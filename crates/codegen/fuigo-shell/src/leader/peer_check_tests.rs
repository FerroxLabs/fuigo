//! U-sock: the leader socket is private to one user account and both sides check who is on the other end.
//! The credential query is injected through `peer_check::seam` (a real second account cannot be made in CI).

use super::seam::{Inject, set};
use super::*;
use crate::leader::client::{ClientError, LeaderClient};
use crate::leader::protocol::{
    ClientCapabilities, ClientMessage, ClientMode, ServerMessage, read_message, write_message,
};
use crate::leader::server::spawn_leader_server;
use crate::leader::transport::LeaderStream;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::AsyncReadExt;


fn mode_of(path: &Path) -> u32 {
    crate::test_support::unix_mode(path)
}

async fn register_frame(stream: &mut LeaderStream) -> std::io::Result<()> {
    write_message(
        stream,
        &ClientMessage::Register {
            client_type: "usock-test".into(),
            mode: ClientMode::Stdio,
            capabilities: ClientCapabilities::default(),
        },
    )
    .await
    .map_err(|e| std::io::Error::other(e.to_string()))
}

/// A fake leader that counts every byte a client sends before closing or timing out.
fn byte_counting_fake(sock: &Path) -> tokio::sync::oneshot::Receiver<usize> {
    let listener = tokio::net::UnixListener::bind(sock).unwrap();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut total = 0usize;
        let mut buf = [0u8; 256];
        loop {
            match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                Ok(Ok(n)) => total += n,
            }
        }
        let _ = tx.send(total);
    });
    rx
}

async fn connect_client(sock: &Path) -> Result<Result<LeaderClient, ClientError>, tokio::time::error::Elapsed> {
    tokio::time::timeout(
        Duration::from_secs(5),
        LeaderClient::connect(sock.to_path_buf(), "usock-test", ClientMode::Stdio, ClientCapabilities::default()),
    )
    .await
}

/// The process umask is NOT changed here (it is process-wide and other tests of this binary create files at the same
/// time). It does not need to be: under any ordinary umask (022, 002, 000) a socket that is only bound is wider than
/// 0600 (0755 under 022), so this fails as soon as the explicit chmod is gone.
#[test]
fn t1_the_socket_is_0600_whatever_the_umask() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap();
    let temp = TempDir::new().unwrap();
    let sock = temp.path().join("leader.sock");
    let handle = rt.block_on(async {
        let handle = spawn_leader_server(sock.clone()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(150)).await;
        handle
    });
    assert_eq!(mode_of(&sock), 0o600, "the leader socket must be owner-only whatever the umask");
    let leftovers: Vec<_> = std::fs::read_dir(temp.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(leftovers, vec![std::ffi::OsString::from("leader.sock")], "no bind scratch dir left behind");
    handle.cancel.cancel();
}

#[tokio::test]
async fn t2_same_uid_client_registers_with_the_product_server() {
    let temp = TempDir::new().unwrap();
    let sock = temp.path().join("leader.sock");
    let handle = spawn_leader_server(sock.clone()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let client = connect_client(&sock).await.expect("no timeout").expect("same user connects");
    drop(client);
    handle.cancel.cancel();
}

#[tokio::test]
async fn t3_client_refuses_a_foreign_peer_and_sends_nothing() {
    let temp = TempDir::new().unwrap();
    let sock = temp.path().join("fake.sock");
    let received = byte_counting_fake(&sock);
    set(Side::Client, &sock, Inject::ForeignUid);
    let result = connect_client(&sock).await.expect("no timeout");
    assert!(matches!(result, Err(ClientError::PeerRefused)), "client must refuse");
    assert_eq!(received.await.unwrap(), 0, "the fake server must have received zero bytes");
}

#[tokio::test]
async fn t4_server_drops_a_foreign_peer_without_entering_the_handler() {
    let temp = TempDir::new().unwrap();
    let sock = temp.path().join("leader.sock");
    let handle = spawn_leader_server(sock.clone()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    set(Side::Server, &sock, Inject::ForeignUid);
    let mut stream = LeaderStream::connect(&sock).await.unwrap();
    let _ = register_frame(&mut stream).await;
    let reply = tokio::time::timeout(Duration::from_secs(3), read_message::<_, ServerMessage>(&mut stream)).await;
    assert!(matches!(reply, Ok(Err(_))), "the server must close without a reply, got {reply:?}");
    assert_eq!(handle.client_count.load(Ordering::Relaxed), 0);
    handle.cancel.cancel();
}

#[tokio::test]
async fn t5_a_failed_credential_query_refuses_on_both_sides() {
    let temp = TempDir::new().unwrap();
    // Client side.
    let fake = temp.path().join("fake.sock");
    let received = byte_counting_fake(&fake);
    set(Side::Client, &fake, Inject::QueryError);
    let result = connect_client(&fake).await.expect("no timeout");
    assert!(matches!(result, Err(ClientError::PeerRefused)));
    assert_eq!(received.await.unwrap(), 0);
    // Server side.
    let sock = temp.path().join("leader.sock");
    let handle = spawn_leader_server(sock.clone()).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    set(Side::Server, &sock, Inject::QueryError);
    let mut stream = LeaderStream::connect(&sock).await.unwrap();
    let _ = register_frame(&mut stream).await;
    let reply = tokio::time::timeout(Duration::from_secs(3), read_message::<_, ServerMessage>(&mut stream)).await;
    assert!(matches!(reply, Ok(Err(_))), "got {reply:?}");
    handle.cancel.cancel();
}

#[test]
fn t6_decision_table() {
    use PeerVerdict::{Accept, Refuse};
    assert_eq!(peer_is_same_user::<()>(1000, Ok(1000)), Accept);
    assert_eq!(peer_is_same_user::<()>(1000, Ok(1001)), Refuse);
    assert_eq!(peer_is_same_user::<()>(1000, Ok(0)), Refuse);
    assert_eq!(peer_is_same_user::<()>(0, Ok(1000)), Refuse);
    assert_eq!(peer_is_same_user::<()>(0, Ok(0)), Accept);
    assert_eq!(peer_is_same_user(1000, Err("no credentials")), Refuse);
    assert_eq!(peer_is_same_user(0, Err(std::io::Error::other("x"))), Refuse);
}

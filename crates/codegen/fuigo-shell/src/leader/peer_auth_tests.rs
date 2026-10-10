//! W-pipe tests on real Windows pipes (unique test-only names; nothing touches the real Fuigo home or its leader pipe).
use super::client::{ClientError, LeaderClient};
use super::peer_auth::{PEER_REFUSED_MESSAGE, PeerFacts, verdict_to_result, win};
use super::protocol::{ClientCapabilities, ClientMode};
use super::transport::LeaderListener;
use std::os::windows::io::{AsRawHandle, RawHandle};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use windows::Win32::Foundation::{HANDLE, HLOCAL, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1, SE_KERNEL_OBJECT,
};
use windows::Win32::Security::{DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};
use windows::core::PWSTR;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn unique_name() -> String {
    format!(r"\\.\pipe\fuigo-test-wpipe-{}-{}", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst))
}

fn unique_socket_path() -> PathBuf {
    std::env::temp_dir().join(format!("fuigo-test-wpipe-{}-{}.sock", std::process::id(), COUNTER.fetch_add(1, Ordering::SeqCst)))
}

/// Owner and DACL of a kernel object as an SDDL string.
fn owner_and_dacl(handle: RawHandle) -> String {
    let mut sd = PSECURITY_DESCRIPTOR::default();
    let info = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    let status = unsafe { GetSecurityInfo(HANDLE(handle), SE_KERNEL_OBJECT, info, None, None, None, None, Some(&mut sd)) };
    assert_eq!(status.0, 0, "GetSecurityInfo failed");
    let mut text = PWSTR::null();
    unsafe { ConvertSecurityDescriptorToStringSecurityDescriptorW(sd, SDDL_REVISION_1, info, &mut text, None) }.unwrap();
    let s = unsafe { text.to_string() }.unwrap();
    unsafe {
        let _ = LocalFree(Some(HLOCAL(text.0.cast())));
        let _ = LocalFree(Some(HLOCAL(sd.0)));
    }
    s
}

fn assert_restricted(sddl: &str, me: &str) {
    assert!(sddl.starts_with(&format!("O:{me}")), "owner is the current user: {sddl}");
    let dacl = &sddl[sddl.find("D:").expect("a DACL")..];
    assert_eq!(dacl.matches("(A;").count(), 2, "exactly two allow entries: {dacl}");
    assert_eq!(dacl.matches('(').count(), 2, "no other entry kinds: {dacl}");
    assert!(dacl.contains(";;;SY)"), "SYSTEM is allowed: {dacl}");
    assert!(dacl.contains(&format!(";;;{me})")), "the current user is allowed: {dacl}");
    for other in [";;;WD)", ";;;AN)", ";;;BA)", ";;;AU)", ";;;BU)", ";;;IU)", ";;;NU)"] {
        assert!(!dacl.contains(other), "no entry for {other}: {dacl}");
    }
}

/// T1: the product function creates every instance with owner = this user and an allow list of this user and SYSTEM only.
#[tokio::test]
async fn t1_the_pipe_is_created_with_a_restricted_descriptor() {
    let me = win::own_sid().expect("own sid");
    let name = unique_name();
    let first = win::create_secure_server(name.as_ref(), true).unwrap();
    assert_restricted(&owner_and_dacl(first.as_raw_handle()), &me);
    let second = win::create_secure_server(name.as_ref(), false).unwrap();
    assert_restricted(&owner_and_dacl(second.as_raw_handle()), &me);
}

/// T1b: the listener (the product path every leader uses) hands out restricted instances, first and re-created.
#[tokio::test]
async fn t1b_the_listener_pipe_and_the_instance_it_re_creates_are_restricted() {
    let me = win::own_sid().unwrap();
    let path = unique_socket_path();
    let listener = Arc::new(LeaderListener::bind(&path).unwrap());
    let l = listener.clone();
    let accept = tokio::spawn(async move { l.accept().await.map(|(s, ())| s) });
    let client = tokio::time::timeout(
        Duration::from_secs(5),
        super::transport::LeaderStream::connect(&path),
    )
    .await
    .unwrap()
    .unwrap();
    let served = accept.await.unwrap().unwrap();
    // The accepted instance (first) and the successor created by accept() both carry the descriptor.
    let first = served.server_raw_handle().expect("server side");
    assert_restricted(&owner_and_dacl(first), &me);
    let successor = listener.pending_raw_handle_for_test().await.expect("successor instance");
    assert_restricted(&owner_and_dacl(successor), &me);
    drop(client);
}

/// A server that counts every byte it receives and never answers.
async fn silent_counting_server(path: &std::path::Path) -> (Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = LeaderListener::bind(path).unwrap();
    let bytes = Arc::new(AtomicUsize::new(0));
    let counter = bytes.clone();
    let task = tokio::spawn(async move {
        let Ok((mut stream, ())) = listener.accept().await else { return };
        let mut buf = [0u8; 4096];
        while let Ok(n) = stream.read(&mut buf).await {
            if n == 0 {
                break;
            }
            counter.fetch_add(n, Ordering::SeqCst);
        }
    });
    (bytes, task)
}

fn other_user_facts() -> PeerFacts {
    PeerFacts {
        ours: Ok("S-1-5-21-111-222-333-1001".into()),
        peer_token: Ok("S-1-5-21-1-2-3-1001".into()),
        pipe_owner: Ok("S-1-5-21-1-2-3-1001".into()),
    }
}

/// T2: same user, same integrity: the real check accepts, and the registration reaches the server only after the check returned.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t2_same_user_is_accepted_and_nothing_is_written_before_the_check() {
    let path = unique_socket_path();
    let (bytes, server) = silent_counting_server(&path).await;
    let bytes_at_check = Arc::new(AtomicUsize::new(usize::MAX));
    let accepted = Arc::new(AtomicUsize::new(0));
    let (b, at, acc) = (bytes.clone(), bytes_at_check.clone(), accepted.clone());
    let connect = LeaderClient::connect_checked(path.clone(), "test", ClientMode::Stdio, ClientCapabilities::default(), move |stream| {
        let verdict = super::peer_auth::verify_connected(stream);
        // Give a (wrongly early) write ample time to arrive at the server while the check is still running.
        std::thread::sleep(Duration::from_millis(400));
        at.store(b.load(Ordering::SeqCst), Ordering::SeqCst);
        acc.store(verdict.is_ok() as usize, Ordering::SeqCst);
        verdict
    });
    // The silent server never answers, so connect itself does not finish; the check and the registration have happened.
    let _ = tokio::time::timeout(Duration::from_millis(1500), connect).await;
    assert_eq!(accepted.load(Ordering::SeqCst), 1, "a leader of the same user is accepted");
    assert_eq!(bytes_at_check.load(Ordering::SeqCst), 0, "nothing was written before the check returned");
    assert!(bytes.load(Ordering::SeqCst) > 0, "after Accept the registration is sent");
    server.abort();
}

/// T3: a peer judged to be another account is refused and the server receives ZERO bytes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t3_a_leader_of_another_account_is_refused_before_anything_is_sent() {
    let path = unique_socket_path();
    let (bytes, server) = silent_counting_server(&path).await;
    let result = LeaderClient::connect_checked(path.clone(), "test", ClientMode::Stdio, ClientCapabilities::default(), |_| {
        verdict_to_result(&other_user_facts())
    })
    .await;
    let err = result.err().expect("must be refused");
    assert!(matches!(err, ClientError::PeerRefused), "{err:?}");
    assert_eq!(err.to_string(), PEER_REFUSED_MESSAGE);
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(bytes.load(Ordering::SeqCst), 0, "zero bytes reached the server");
    server.abort();
}

/// T4: when the OS queries fail, the client refuses and sends nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn t4_failing_os_queries_refuse_and_send_nothing() {
    let path = unique_socket_path();
    let (bytes, server) = silent_counting_server(&path).await;
    let result = LeaderClient::connect_checked(path.clone(), "test", ClientMode::Stdio, ClientCapabilities::default(), |_| {
        verdict_to_result(&PeerFacts { ours: Ok("S-1-5-21-1-2-3-1001".into()), peer_token: Err(5), pipe_owner: Err(5) })
    })
    .await;
    assert!(matches!(result.err(), Some(ClientError::PeerRefused)));
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(bytes.load(Ordering::SeqCst), 0);
    server.abort();
}

/// T4b: the real queries on a handle that is not a pipe fail, and the decision over those real failures is Refuse.
#[test]
fn t4b_real_queries_that_fail_give_refuse() {
    let facts = win::gather_facts(std::ptr::null_mut());
    assert!(facts.peer_token.is_err() && facts.pipe_owner.is_err(), "{facts:?}");
    assert!(verdict_to_result(&facts).is_err());
}

/// The real check on a real connection reads the real account of this process and the pipe owner (informational: both
/// equal ours for a pipe this process created through the product function).
#[tokio::test]
async fn t2b_real_facts_of_a_product_pipe_equal_our_account() {
    let path = unique_socket_path();
    let listener = LeaderListener::bind(&path).unwrap();
    let accept = tokio::spawn(async move { listener.accept().await.map(|(s, ())| s) });
    let client = super::transport::LeaderStream::connect(&path).await.unwrap();
    let _served = accept.await.unwrap().unwrap();
    let facts = win::gather_facts(client.client_raw_handle().unwrap());
    let me = win::own_sid().unwrap();
    assert_eq!(facts.ours, Ok(me.clone()));
    assert_eq!(facts.peer_token, Ok(me.clone()), "token of the serving process is readable at the same integrity level");
    assert_eq!(facts.pipe_owner, Ok(me));
}

/// Item (h): the kept duplicate of the pipe handle reports the same serving pid as the connection itself.
#[tokio::test]
async fn h_the_duplicate_handle_reports_the_serving_pid_now() {
    let path = unique_socket_path();
    let listener = LeaderListener::bind(&path).unwrap();
    let accept = tokio::spawn(async move { listener.accept().await.map(|(s, ())| s) });
    let client = super::transport::LeaderStream::connect(&path).await.unwrap();
    let _served = accept.await.unwrap().unwrap();
    let probe = win::DupHandle::of(client.client_raw_handle().unwrap()).expect("duplicate");
    assert_eq!(probe.server_pid_now(), Some(std::process::id()));
    assert_eq!(client.os_server_pid(), probe.server_pid_now());
}

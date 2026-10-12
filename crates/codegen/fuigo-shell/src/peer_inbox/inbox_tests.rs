//! Packet 8d tests. Every test that opens a socket must run inside an empty network namespace (`unshare -n`);
//! unix sockets live in each test's own `tempfile::tempdir()` under `/tmp` (default temp path, short enough:
//! `/tmp/.tmpXXXXXX/home/peers/<32 hex>.sock` is well under 103 bytes). Nothing touches `$HOME/.fuigo` or
//! `$XDG_RUNTIME_DIR`: the runtime directory is always passed in explicitly.

use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use fuigo_peer::{
    Address, BoundedId, DeliveryOutcome, Envelope, Hello, HostDir, HostId, HostRow, NoticeKind, Op, OperatorKind, PeerBase,
    PeerMode, RejectReason, Reply, SessionRow, TryResult, parse_rows,
};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::{UnixListener, UnixStream};

use super::conn::{ConnError, InboxHost, serve_one};
use super::dial::{DialError, Locations, dial, try_hello};
use super::directory::{ConnHost, PeerDirectory};
use super::inbox::{PeerInbox, StartOptions};
use super::reap::{LOCATOR_NAME, remove_row};
use super::{CheckedDir, Disabled, read_locator, update_locator};
use crate::session::message_delivery::peer_test_session;
use crate::session::peer_admission::PeerSubmit;
use crate::session::peer_message::force_peer_messaging_for_test;

pub(super) fn hid(s: &str) -> HostId {
    HostId::new(s).unwrap()
}

pub(super) fn tmp() -> TempDir {
    tempfile::tempdir().unwrap()
}

/// A 0755 home inside `t` (the home must not be writable by others; 0755 lets a second uid reach `peers`).
pub(super) fn home_in(t: &TempDir, name: &str) -> PathBuf {
    let h = t.path().join(name);
    std::fs::create_dir_all(&h).unwrap();
    std::fs::set_permissions(&h, std::fs::Permissions::from_mode(0o755)).unwrap();
    h
}

pub(super) fn on() -> StartOptions {
    StartOptions { enabled: true, runtime_dir: None }
}

pub(super) fn envelope(from: &Address, id: &str) -> Envelope {
    Envelope {
        message_id: id.into(),
        seq: 1,
        from: from.clone(),
        from_name: "lane a".into(),
        from_auto_title: None,
        from_ref: "3f2a9c10".into(),
        from_mode: PeerMode::new(false, PeerBase::AcceptEdits, false),
        from_operator: OperatorKind::Human,
        conversation_id: "c-1".into(),
        hop: 0,
        denied_recently: vec![],
        body: "hi".into(),
    }
}

fn delivered() -> Option<PeerSubmit> {
    Some(PeerSubmit::Outcome(DeliveryOutcome::Delivered {}))
}

fn rows_of(home: &Path) -> Vec<HostRow> {
    let d = CheckedDir::open(home).unwrap();
    parse_rows(&read_locator(&d, LOCATOR_NAME).unwrap().unwrap_or_default()).unwrap()
}

fn unavailable(o: &DeliveryOutcome) -> bool {
    matches!(o, DeliveryOutcome::Rejected { reason: RejectReason::Unavailable })
}

async fn send_op(loc: &Locations, from: &PeerInbox, to: &Address, env: Envelope) -> Result<Reply, DialError> {
    let op = Op::Send { to: to.clone(), envelope: env, watch: false };
    dial(loc, from.host_id(), &HostId::of(to), HostDir::Home, op).await
}

// ---------------------------------------------------------------------------------------------------------------
// start / modes / flag

#[tokio::test]
async fn flag_off_leaves_no_peers_dir_and_spawns_no_task() {
    let t = tmp();
    let home = home_in(&t, "home");
    let before = tokio::runtime::Handle::current().metrics().num_alive_tasks();
    let r = PeerInbox::start_with(&home, StartOptions { enabled: false, runtime_dir: Some(t.path().join("rt")) }).await;
    assert_eq!(r.err(), Some(Disabled::FeatureOff));
    assert!(!home.join("peers").exists(), "no peers directory");
    assert!(!t.path().join("rt").exists(), "no runtime directory");
    assert_eq!(std::fs::read_dir(&home).unwrap().count(), 0, "nothing at all in the home");
    assert_eq!(tokio::runtime::Handle::current().metrics().num_alive_tasks(), before, "no task");
    // `start` follows the process flag (off by default, forced here).
    let _off = force_peer_messaging_for_test(false);
    assert_eq!(PeerInbox::start(&home).await.err(), Some(Disabled::FeatureOff));
    assert!(!home.join("peers").exists());
}

#[tokio::test]
async fn socket_mode_0600_and_directory_mode_0700_at_first_visibility() {
    let t = tmp();
    let home = home_in(&t, "home");
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = Arc::new(std::sync::Mutex::new((None::<u32>, None::<u32>)));
    let (s2, seen2, peers) = (stop.clone(), seen.clone(), home.join("peers"));
    let watcher = std::thread::spawn(move || {
        while !s2.load(Ordering::Relaxed) {
            let mut g = seen2.lock().unwrap();
            if g.0.is_none() {
                g.0 = std::fs::symlink_metadata(&peers).ok().map(|m| m.mode() & 0o7777);
            }
            if g.1.is_none()
                && g.0.is_some()
                && let Ok(rd) = std::fs::read_dir(&peers)
            {
                for e in rd.flatten() {
                    if e.file_name().to_string_lossy().ends_with(".sock") {
                        g.1 = std::fs::symlink_metadata(e.path()).ok().map(|m| m.mode() & 0o7777);
                    }
                }
            }
            drop(g);
            std::hint::spin_loop();
        }
    });
    let inbox = PeerInbox::start_with(&home, on()).await.unwrap();
    stop.store(true, Ordering::Relaxed);
    watcher.join().unwrap();
    let (dir_mode, sock_mode) = *seen.lock().unwrap();
    assert_eq!(dir_mode, Some(0o700), "peers directory at first sight");
    if let Some(m) = sock_mode {
        assert_eq!(m, 0o600, "socket at first visibility");
    }
    let sock = home.join("peers").join(format!("{}.sock", inbox.host_id()));
    let m = std::fs::symlink_metadata(&sock).unwrap();
    assert!(std::os::unix::fs::FileTypeExt::is_socket(&m.file_type()));
    assert_eq!(m.mode() & 0o7777, 0o600);
    assert_eq!(std::fs::metadata(home.join("peers")).unwrap().mode() & 0o7777, 0o700);
    // No leftover bind scratch directory.
    let names: Vec<_> = std::fs::read_dir(home.join("peers")).unwrap().flatten().map(|e| e.file_name()).collect();
    assert!(!names.iter().any(|n| n.to_string_lossy().starts_with(".l") && n != ".lock"), "{names:?}");
}

#[tokio::test]
async fn row_is_written_and_removed_with_the_socket_on_drop() {
    let t = tmp();
    let home = home_in(&t, "home");
    let a = PeerInbox::start_with(&home, on()).await.unwrap();
    let b = PeerInbox::start_with(&home, on()).await.unwrap();
    let rows = rows_of(&home);
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r.dir == HostDir::Home && r.pid == std::process::id()));
    let (sa, sb) = (
        home.join("peers").join(format!("{}.sock", a.host_id())),
        home.join("peers").join(format!("{}.sock", b.host_id())),
    );
    a.shutdown().await;
    assert!(!sa.exists() && sb.exists());
    let rows = rows_of(&home);
    assert_eq!(rows.len(), 1);
    assert_eq!(&rows[0].host_id, b.host_id());
    b.shutdown().await;
    b.shutdown().await;
    assert!(!sb.exists());
    let d = CheckedDir::open(&home).unwrap();
    assert!(read_locator(&d, LOCATOR_NAME).unwrap().is_none(), "last row gone: file removed");
}

#[tokio::test]
async fn drop_does_not_unlink_something_that_is_no_longer_our_socket() {
    let t = tmp();
    let home = home_in(&t, "home");
    let a = PeerInbox::start_with(&home, on()).await.unwrap();
    let sock = home.join("peers").join(format!("{}.sock", a.host_id()));
    std::fs::remove_file(&sock).unwrap();
    std::fs::write(&sock, b"not a socket").unwrap();
    drop(a);
    assert_eq!(std::fs::read(&sock).unwrap(), b"not a socket");
}

#[tokio::test]
async fn a_preexisting_file_or_link_at_the_socket_path_makes_start_fail_closed() {
    let t = tmp();
    let home = home_in(&t, "home");
    drop(CheckedDir::create_or_open(&home).unwrap());
    let id = hid("00112233445566778899aabbccddeeff");
    let path = home.join("peers").join(format!("{id}.sock"));
    std::fs::write(&path, b"planted").unwrap();
    let r = PeerInbox::start_inner(&home, on(), id.clone()).await;
    assert_eq!(r.err(), Some(Disabled::SocketPathExists));
    assert_eq!(std::fs::read(&path).unwrap(), b"planted", "untouched");
    assert!(rows_of_or_empty(&home).is_empty(), "no row");
    std::fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink("/nonexistent-target", &path).unwrap();
    let r = PeerInbox::start_inner(&home, on(), id).await;
    assert_eq!(r.err(), Some(Disabled::SocketPathExists));
    assert!(std::fs::symlink_metadata(&path).unwrap().file_type().is_symlink());
}

fn rows_of_or_empty(home: &Path) -> Vec<HostRow> {
    let d = CheckedDir::open(home).unwrap();
    match read_locator(&d, LOCATOR_NAME).unwrap() {
        Some(b) => parse_rows(&b).unwrap(),
        None => vec![],
    }
}

#[tokio::test]
async fn a_symlinked_home_gives_the_typed_reason_and_creates_nothing() {
    let t = tmp();
    let real = home_in(&t, "real");
    let link = t.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let r = PeerInbox::start_with(&link, StartOptions { enabled: true, runtime_dir: Some(t.path().join("rt")) }).await;
    assert_eq!(r.err(), Some(Disabled::SymlinkedHome));
    assert_eq!(std::fs::read_dir(&real).unwrap().count(), 0);
    assert!(!t.path().join("rt").exists());
}

#[tokio::test]
async fn an_oversized_and_a_hard_linked_locator_file_are_ignored_and_rewritten() {
    let t = tmp();
    let home = home_in(&t, "home");
    drop(CheckedDir::create_or_open(&home).unwrap());
    let loc = home.join("peers").join(LOCATOR_NAME);
    std::fs::write(&loc, vec![b' '; 70 * 1024]).unwrap();
    std::fs::set_permissions(&loc, std::fs::Permissions::from_mode(0o600)).unwrap();
    let a = PeerInbox::start_with(&home, on()).await.unwrap();
    assert!(std::fs::metadata(&loc).unwrap().len() < 1024);
    assert_eq!(rows_of(&home).len(), 1);
    a.shutdown().await;
    // Hard-linked: the second name keeps the old bytes; ours is replaced by a fresh single-link file.
    std::fs::write(&loc, b"[]").unwrap();
    std::fs::set_permissions(&loc, std::fs::Permissions::from_mode(0o600)).unwrap();
    let other = home.join("peers").join("other-name");
    std::fs::hard_link(&loc, &other).unwrap();
    let b = PeerInbox::start_with(&home, on()).await.unwrap();
    assert_eq!(std::fs::metadata(&loc).unwrap().nlink(), 1);
    assert_eq!(std::fs::read(&other).unwrap(), b"[]", "the other link was not written through");
    assert_eq!(rows_of(&home).len(), 1);
    drop(b);
}

#[tokio::test]
async fn a_home_path_of_120_bytes_selects_the_runtime_directory_and_still_works() {
    let _on = force_peer_messaging_for_test(true);
    let t = tmp();
    let rt = tmp();
    let mut home = t.path().to_path_buf();
    while home.as_os_str().len() < 100 {
        home.push("nested-component");
    }
    let want = 120usize.saturating_sub(home.as_os_str().len() + 1);
    home.push("x".repeat(want.max(1)));
    assert_eq!(home.as_os_str().len(), 120, "{home:?}");
    std::fs::create_dir_all(&home).unwrap();
    let a = PeerInbox::start_with(&home, StartOptions { enabled: true, runtime_dir: Some(rt.path().to_path_buf()) })
        .await
        .unwrap();
    assert_eq!(a.row().dir, HostDir::Runtime);
    let rt_peers = a.locations().peers_path(HostDir::Runtime).unwrap();
    assert!(rt_peers.starts_with(rt.path().join("fuigo")));
    let hash_dir = rt_peers.parent().unwrap().file_name().unwrap().to_string_lossy().into_owned();
    assert_eq!(hash_dir.len(), 16);
    assert!(hash_dir.bytes().all(|b| b.is_ascii_hexdigit()));
    let sock = rt_peers.join(format!("{}.sock", a.host_id()));
    assert!(sock.exists() && sock.as_os_str().len() <= 103);
    assert!(!home.join("peers").join(format!("{}.sock", a.host_id())).exists());
    for d in [rt.path().join("fuigo"), rt_peers.parent().unwrap().to_path_buf(), rt_peers.clone()] {
        assert_eq!(std::fs::metadata(&d).unwrap().mode() & 0o7777, 0o700, "{d:?}");
    }
    let (h, _rx) = peer_test_session("sess-1", delivered());
    let addr = a.directory().register("sess-1", h, "", "3f2a9c10").unwrap();
    // A second inbox of the same home finds it through the row's `runtime` tag.
    let b = PeerInbox::start_with(&home, StartOptions { enabled: true, runtime_dir: Some(rt.path().to_path_buf()) })
        .await
        .unwrap();
    let r = dial(b.locations(), b.host_id(), a.host_id(), HostDir::Runtime, Op::List { page: 0 }).await.unwrap();
    assert!(matches!(&r, Reply::List { rows, .. } if rows.len() == 1 && rows[0].address == addr));
    // Pointed at "Home" for that host the path is over the socket limit: no connect is even attempted.
    let wrong = dial(b.locations(), b.host_id(), a.host_id(), HostDir::Home, Op::List { page: 0 }).await;
    assert_eq!(wrong.err(), Some(DialError::Other));
    drop((a, b));
    assert!(std::fs::read_dir(&rt_peers).unwrap().next().is_none(), "socket unlinked on drop");
}

#[tokio::test]
async fn no_usable_directory_for_a_long_home_is_a_typed_reason() {
    let t = tmp();
    let mut home = t.path().to_path_buf();
    while home.as_os_str().len() < 110 {
        home.push("nested-component");
    }
    std::fs::create_dir_all(&home).unwrap();
    let r = PeerInbox::start_with(&home, on()).await;
    assert_eq!(r.err(), Some(Disabled::SocketDirUnavailable));
}

// ---------------------------------------------------------------------------------------------------------------
// list / send end to end

#[tokio::test]
async fn start_list_and_send_end_to_end_and_two_homes_never_list_each_other() {
    let _on = force_peer_messaging_for_test(true);
    let t = tmp();
    let (h1, h2) = (home_in(&t, "h1"), home_in(&t, "h2"));
    let a = PeerInbox::start_with(&h1, on()).await.unwrap();
    let b = PeerInbox::start_with(&h1, on()).await.unwrap();
    let c = PeerInbox::start_with(&h2, on()).await.unwrap();
    let (hb, mut seen_b) = peer_test_session("sess-b", delivered());
    let (hc, mut seen_c) = peer_test_session("sess-c", delivered());
    let addr_b = b.directory().register("sess-b", hb, "worker", "3f2a9c10").unwrap();
    let addr_c = c.directory().register("sess-c", hc, "", "3f2a9c11").unwrap();
    let addr_a = a.directory().register("sess-a", peer_test_session("sess-a", delivered()).0, "", "3f2a9c12").unwrap();

    let r = dial(a.locations(), a.host_id(), b.host_id(), HostDir::Home, Op::List { page: 0 }).await.unwrap();
    match r {
        Reply::List { rows, more } => {
            assert!(!more);
            assert_eq!(rows, vec![SessionRow { address: addr_b.clone(), name: "worker".into(), session_ref: "3f2a9c10".into() }]);
        }
        other => panic!("{other:?}"),
    }
    let r = send_op(a.locations(), &a, &addr_b, envelope(&addr_a, "m-1")).await.unwrap();
    assert_eq!(r, Reply::Send { outcome: DeliveryOutcome::Delivered {} });
    let got = seen_b.try_recv().expect("the session got exactly the envelope");
    assert_eq!(got.message_id, "m-1");
    assert!(seen_b.try_recv().is_err());

    // Home 2 is a different world: A (home 1) cannot dial C, and the locator files differ.
    let r = dial(a.locations(), a.host_id(), c.host_id(), HostDir::Home, Op::List { page: 0 }).await;
    assert_eq!(r.err(), Some(DialError::NoSuchFile));
    let h1_ids: Vec<_> = rows_of(&h1).into_iter().map(|r| r.host_id).collect();
    let h2_ids: Vec<_> = rows_of(&h2).into_iter().map(|r| r.host_id).collect();
    assert!(h1_ids.contains(a.host_id()) && h1_ids.contains(b.host_id()) && !h1_ids.contains(c.host_id()));
    assert_eq!(h2_ids, vec![c.host_id().clone()]);
    assert!(seen_c.try_recv().is_err());
    let _ = addr_c;
}

#[tokio::test]
async fn send_to_another_host_unknown_session_or_old_incarnation_is_unavailable_and_delivers_nothing() {
    let _on = force_peer_messaging_for_test(true);
    let t = tmp();
    let home = home_in(&t, "home");
    let a = PeerInbox::start_with(&home, on()).await.unwrap();
    let b = PeerInbox::start_with(&home, on()).await.unwrap();
    let (hb, mut seen) = peer_test_session("sess-b", delivered());
    let old = b.directory().register("sess-b", hb, "", "3f2a9c10").unwrap();
    b.directory().unregister("sess-b");
    let (hb2, mut seen2) = peer_test_session("sess-b", delivered());
    let cur = b.directory().register("sess-b", hb2, "", "3f2a9c10").unwrap();
    assert_eq!(cur.incarnation(), old.incarnation() + 1);
    let from = Address::new(a.host_id().as_str(), "sess-a", 1).unwrap();
    let ours = |addr: Address| {
        let (a, from) = (&a, &from);
        async move { send_op(a.locations(), a, &addr, envelope(from, "m-x")).await }
    };

    // Old incarnation.
    let r = ours(old.clone()).await.unwrap();
    assert!(matches!(&r, Reply::Send { outcome } if unavailable(outcome)), "{r:?}");
    // Unknown session.
    let unknown = Address::new(b.host_id().as_str(), "nope", 1).unwrap();
    let r = ours(unknown).await.unwrap();
    assert!(matches!(&r, Reply::Send { outcome } if unavailable(outcome)), "{r:?}");
    // `to` names another host, dialled at B's socket.
    let other = Address::new("ffffffffffffffffffffffffffffffff", "sess-b", cur.incarnation()).unwrap();
    let op = Op::Send { to: other, envelope: envelope(&from, "m-y"), watch: false };
    let r = dial(a.locations(), a.host_id(), b.host_id(), HostDir::Home, op).await.unwrap();
    assert!(matches!(&r, Reply::Send { outcome } if unavailable(outcome)), "{r:?}");
    // `from` names another host than the hello (consistency check).
    let liar = Address::new("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "sess-a", 1).unwrap();
    let r = ours(cur.clone()).await;
    assert!(matches!(&r, Ok(Reply::Send { outcome: DeliveryOutcome::Delivered {} })), "{r:?}");
    assert!(seen2.try_recv().is_ok());
    let op = Op::Send { to: cur.clone(), envelope: envelope(&liar, "m-z"), watch: false };
    let r = dial(a.locations(), a.host_id(), b.host_id(), HostDir::Home, op).await.unwrap();
    assert!(matches!(&r, Reply::Send { outcome } if unavailable(outcome)), "{r:?}");
    assert!(seen.try_recv().is_err(), "the old session got nothing");
    assert!(seen2.try_recv().is_err(), "nothing but the one good message");
}

#[tokio::test]
async fn list_pages_are_bounded() {
    let _on = force_peer_messaging_for_test(true);
    let t = tmp();
    let home = home_in(&t, "home");
    let a = PeerInbox::start_with(&home, on()).await.unwrap();
    let b = PeerInbox::start_with(&home, on()).await.unwrap();
    for i in 0..70 {
        let id = format!("s{i:03}");
        b.directory().register(&id, peer_test_session(&id, delivered()).0, "", "ref").unwrap();
    }
    let p0 = dial(a.locations(), a.host_id(), b.host_id(), HostDir::Home, Op::List { page: 0 }).await.unwrap();
    let p1 = dial(a.locations(), a.host_id(), b.host_id(), HostDir::Home, Op::List { page: 1 }).await.unwrap();
    assert!(matches!(&p0, Reply::List { rows, more: true } if rows.len() == 64));
    assert!(matches!(&p1, Reply::List { rows, more: false } if rows.len() == 6));
}

#[tokio::test]
async fn notices_reach_only_the_sink_and_a_panicking_connection_does_not_stop_the_loop() {
    let t = tmp();
    let home = home_in(&t, "home");
    let a = PeerInbox::start_with(&home, on()).await.unwrap();
    let b = PeerInbox::start_with(&home, on()).await.unwrap();
    let hits = Arc::new(AtomicUsize::new(0));
    let (h2, a_id) = (hits.clone(), a.host_id().clone());
    b.directory().set_notice_sink(Arc::new(move |peer, _id, kind| {
        assert_eq!(peer, &a_id);
        assert_eq!(kind, NoticeKind::Released);
        h2.fetch_add(1, Ordering::SeqCst);
    }));
    let op = || Op::Notice { message_id: fuigo_peer::BoundedId::new("m-1").unwrap(), kind: NoticeKind::Released };
    let r = dial(a.locations(), a.host_id(), b.host_id(), HostDir::Home, op()).await.unwrap();
    assert_eq!(r, Reply::Notice {});
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    // Now every notice panics inside its connection task. More than 32 of them: permits must come back.
    b.directory().set_notice_sink(Arc::new(|_, _, _| panic!("test panic inside a connection task")));
    for _ in 0..40 {
        let r = dial(a.locations(), a.host_id(), b.host_id(), HostDir::Home, op()).await;
        assert!(r.is_err(), "the connection died with its task");
    }
    let r = dial(a.locations(), a.host_id(), b.host_id(), HostDir::Home, Op::List { page: 0 }).await.unwrap();
    assert!(matches!(r, Reply::List { .. }), "the loop is alive");
}

#[tokio::test]
async fn the_33rd_connection_is_closed_at_once_and_a_freed_permit_is_reused() {
    let t = tmp();
    let home = home_in(&t, "home");
    let a = PeerInbox::start_with(&home, on()).await.unwrap();
    let b = PeerInbox::start_with(&home, on()).await.unwrap();
    let path = b.locations().socket(b.host_id(), HostDir::Home).unwrap();
    let mut held = Vec::new();
    for _ in 0..32 {
        held.push(UnixStream::connect(&path).await.unwrap());
    }
    let mut extra = UnixStream::connect(&path).await.unwrap();
    let mut buf = [0u8; 1];
    let n = tokio::time::timeout(Duration::from_secs(3), extra.read(&mut buf))
        .await
        .expect("closed at once, not left waiting");
    assert!(matches!(n, Ok(0) | Err(_)), "{n:?}");
    // The 32 held ones are still being served (waiting for a hello), not closed.
    let r = tokio::time::timeout(Duration::from_millis(300), held[0].read(&mut buf)).await;
    assert!(r.is_err(), "still open");
    held.pop();
    held.pop();
    tokio::time::sleep(Duration::from_millis(300)).await;
    let r = dial(a.locations(), a.host_id(), b.host_id(), HostDir::Home, Op::List { page: 0 }).await;
    assert!(r.is_ok(), "{r:?}");
}

// ---------------------------------------------------------------------------------------------------------------
// reaping

/// A fake host answering the hello with `announce` (and nothing else), for as long as the returned guard lives.
struct Fake {
    _task: tokio::task::JoinHandle<()>,
}
fn serve_hello(path: &Path, announce: Hello) -> Fake {
    let l = UnixListener::bind(path).unwrap();
    let t = tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = l.accept().await else { return };
            let a = announce.clone();
            tokio::spawn(async move {
                let mut len = [0u8; 4];
                if s.read_exact(&mut len).await.is_err() {
                    return;
                }
                let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
                let _ = s.read_exact(&mut body).await;
                let out = serde_json::to_vec(&a).unwrap();
                let _ = s.write_all(&(out.len() as u32).to_be_bytes()).await;
                let _ = s.write_all(&out).await;
                let _ = s.read(&mut [0u8; 1]).await;
            });
        }
    });
    Fake { _task: t }
}

fn add_row(home: &Path, row: HostRow) {
    let d = CheckedDir::open(home).unwrap();
    update_locator(&d, LOCATOR_NAME, |cur| {
        let mut rows = cur.map(|b| parse_rows(b).unwrap()).unwrap_or_default();
        rows.push(row);
        Some(serde_json::to_vec(&rows).unwrap())
    })
    .unwrap();
}

fn row(id: &HostId, dir: HostDir) -> HostRow {
    HostRow { host_id: id.clone(), pid: 1, started: 1, dir }
}

const GAP: Duration = Duration::from_millis(250);

#[tokio::test]
async fn a_stale_socket_file_with_no_listener_is_reaped_with_its_row_after_two_tries() {
    let t = tmp();
    let home = home_in(&t, "home");
    let a = PeerInbox::start_with(&home, on()).await.unwrap();
    let dead = hid("dead0000dead0000dead0000dead0000");
    let sock = home.join("peers").join(format!("{dead}.sock"));
    drop(std::os::unix::net::UnixListener::bind(&sock).unwrap()); // file stays, nobody listens
    assert!(sock.exists());
    add_row(&home, row(&dead, HostDir::Home));
    let started = std::time::Instant::now();
    let rep = a.reap(GAP).await.unwrap();
    assert!(started.elapsed() >= GAP, "two tries, one gap apart");
    assert_eq!(rep.reaped, vec![dead.clone()]);
    assert!(!sock.exists(), "socket unlinked with the row");
    let ids: Vec<_> = rows_of(&home).into_iter().map(|r| r.host_id).collect();
    assert_eq!(ids, vec![a.host_id().clone()], "our own row is never judged");
}

#[tokio::test]
async fn a_row_without_a_socket_file_is_reaped_when_home_and_kept_when_runtime() {
    let t = tmp();
    let rt = tmp();
    let home = home_in(&t, "home");
    let a = PeerInbox::start_with(&home, StartOptions { enabled: true, runtime_dir: Some(rt.path().to_path_buf()) })
        .await
        .unwrap();
    let (h, r) = (hid("aaaa0000aaaa0000aaaa0000aaaa0000"), hid("bbbb0000bbbb0000bbbb0000bbbb0000"));
    add_row(&home, row(&h, HostDir::Home));
    add_row(&home, row(&r, HostDir::Runtime));
    // The runtime directory exists so that "no such file" is a real observation, not "no directory".
    std::fs::create_dir_all(a.locations().peers_path(HostDir::Runtime).unwrap()).unwrap();
    let rep = a.reap(Duration::from_millis(50)).await.unwrap();
    assert_eq!(rep.reaped, vec![h]);
    assert!(rows_of(&home).iter().any(|x| x.host_id == r), "a runtime row is never reaped on no such file");
}

#[tokio::test]
async fn a_replaced_socket_is_reaped_only_after_two_tries_and_only_if_the_row_is_unchanged() {
    let t = tmp();
    let home = home_in(&t, "home");
    let a = PeerInbox::start_with(&home, on()).await.unwrap();
    let imposter = PeerInbox::start_with(&home, on()).await.unwrap();
    // The row names X; the socket at X.sock answers as the imposter's host id.
    let x = hid("c0de0000c0de0000c0de0000c0de0000");
    let peers = home.join("peers");
    std::fs::rename(peers.join(format!("{}.sock", imposter.host_id())), peers.join(format!("{x}.sock"))).unwrap();
    let r0 = row(&x, HostDir::Home);
    add_row(&home, r0.clone());
    assert_eq!(try_hello(a.locations(), a.host_id(), &x, HostDir::Home).await, TryResult::Hello(imposter.host_id().clone()));

    // The row changed between our read and the removal: nothing is removed.
    let mut changed = r0.clone();
    changed.pid = 99;
    let d = CheckedDir::open(&home).unwrap();
    update_locator(&d, LOCATOR_NAME, |cur| {
        let mut rows = parse_rows(cur.unwrap()).unwrap();
        for r in &mut rows {
            if r.host_id == x {
                *r = changed.clone();
            }
        }
        Some(serde_json::to_vec(&rows).unwrap())
    })
    .unwrap();
    let dir = Arc::new(d);
    assert!(!remove_row(a.locations(), &dir, &r0).await.unwrap(), "stale copy of the row: kept");
    assert!(rows_of(&home).iter().any(|r| r.host_id == x));
    assert!(peers.join(format!("{x}.sock")).exists());

    // A full pass with the row unchanged: two tries (one gap), then the row and the file go.
    let started = std::time::Instant::now();
    let rep = a.reap(GAP).await.unwrap();
    assert!(started.elapsed() >= GAP);
    // (The imposter's own row is dead too: its socket file was renamed away, so it is reaped as no-such-file.)
    assert!(rep.reaped.contains(&x));
    assert!(!peers.join(format!("{x}.sock")).exists());
    assert!(!rows_of(&home).iter().any(|r| r.host_id == x));
}

#[tokio::test]
async fn a_version_mismatch_never_reaps() {
    let t = tmp();
    let home = home_in(&t, "home");
    let a = PeerInbox::start_with(&home, on()).await.unwrap();
    let old = hid("01d00000010000000100000001000000");
    let sock = home.join("peers").join(format!("{old}.sock"));
    let _fake = serve_hello(&sock, Hello { version: 2, host_id: old.clone() });
    add_row(&home, row(&old, HostDir::Home));
    assert_eq!(try_hello(a.locations(), a.host_id(), &old, HostDir::Home).await, TryResult::VersionMismatch);
    let rep = a.reap(Duration::from_millis(50)).await.unwrap();
    assert!(rep.reaped.is_empty());
    assert!(sock.exists() && rows_of(&home).iter().any(|r| r.host_id == old));
    // And a normal dial reports the mismatch as such.
    let r = dial(a.locations(), a.host_id(), &old, HostDir::Home, Op::List { page: 0 }).await;
    assert_eq!(r.err(), Some(DialError::VersionMismatch));
}

#[tokio::test]
async fn a_timeout_does_not_reap() {
    // A peer that accepts and never answers. The probe gives up after the 10 s exchange deadline (real time).
    let t = tmp();
    let home = home_in(&t, "home");
    let a = PeerInbox::start_with(&home, on()).await.unwrap();
    let slow = hid("51000000510000005100000051000000");
    let sock = home.join("peers").join(format!("{slow}.sock"));
    let l = UnixListener::bind(&sock).unwrap();
    let hold = tokio::spawn(async move {
        let mut keep = Vec::new();
        while let Ok((s, _)) = l.accept().await {
            keep.push(s);
        }
    });
    add_row(&home, row(&slow, HostDir::Home));
    let started = std::time::Instant::now();
    let rep = a.reap(Duration::from_millis(50)).await.unwrap();
    assert!(rep.reaped.is_empty());
    assert!(started.elapsed() >= Duration::from_millis(2900), "it really waited the 3 s probe cap");
    assert!(started.elapsed() < Duration::from_secs(5), "cut at the cap (not the 10 s exchange deadline), ONE try");
    assert!(sock.exists() && rows_of(&home).iter().any(|r| r.host_id == slow));
    hold.abort();
}

#[tokio::test]
async fn dial_errors_map_onto_the_reap_inputs() {
    let t = tmp();
    let home = home_in(&t, "home");
    let a = PeerInbox::start_with(&home, on()).await.unwrap();
    let nope = hid("99000000990000009900000099000000");
    let r = dial(a.locations(), a.host_id(), &nope, HostDir::Home, Op::List { page: 0 }).await;
    assert_eq!(r.as_ref().err(), Some(&DialError::NoSuchFile));
    assert_eq!(r.unwrap_err().try_result(), TryResult::NoSuchFile);
    let sock = home.join("peers").join(format!("{nope}.sock"));
    drop(std::os::unix::net::UnixListener::bind(&sock).unwrap());
    let r = dial(a.locations(), a.host_id(), &nope, HostDir::Home, Op::List { page: 0 }).await.unwrap_err();
    assert_eq!((r, r.try_result()), (DialError::Refused, TryResult::Refused));
    // A runtime row with no runtime directory configured: no directory, no evidence.
    let r = dial(a.locations(), a.host_id(), &nope, HostDir::Runtime, Op::List { page: 0 }).await.unwrap_err();
    assert_eq!((r, r.try_result()), (DialError::NoDirectory, TryResult::Other));
    // A server that announces another host id.
    let other = hid("77000000770000007700000077000000");
    let _f = serve_hello(&home.join("peers").join(format!("{other}.sock")), Hello::new(nope.clone()));
    let r = dial(a.locations(), a.host_id(), &other, HostDir::Home, Op::List { page: 0 }).await.unwrap_err();
    assert_eq!(r, DialError::ForeignHello);
}

// ---------------------------------------------------------------------------------------------------------------
// cancellation (8c audit): host call inside the deadline, mid-frame close

#[derive(Default)]
struct Probe {
    entered: AtomicUsize,
    dropped: AtomicUsize,
}
struct DropCount<'a>(&'a AtomicUsize);
impl Drop for DropCount<'_> {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}
impl InboxHost for Probe {
    async fn list(&self, _page: u32) -> (Vec<SessionRow>, bool) {
        self.entered.fetch_add(1, Ordering::SeqCst);
        (vec![], false)
    }
    async fn send_watched(&self, to: Address, e: Envelope, _watch: bool) -> DeliveryOutcome {
        self.send(to, e).await
    }
    async fn send(&self, _to: Address, _e: Envelope) -> DeliveryOutcome {
        self.entered.fetch_add(1, Ordering::SeqCst);
        let _g = DropCount(&self.dropped);
        std::future::pending::<()>().await;
        DeliveryOutcome::Delivered {}
    }
    async fn notice(&self, _m: BoundedId, _k: NoticeKind) {
        self.entered.fetch_add(1, Ordering::SeqCst);
    }
}

fn frame<T: serde::Serialize>(v: &T) -> Vec<u8> {
    let b = serde_json::to_vec(v).unwrap();
    let mut out = (b.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(&b);
    out
}

#[tokio::test(start_paused = true)]
async fn a_host_call_that_never_returns_is_cancelled_by_the_exchange_deadline() {
    let host = Probe::default();
    let a = Address::new("0123456789abcdef0123456789abcdef", "s", 1).unwrap();
    let (mut peer, server) = duplex(1 << 20);
    let hello = Hello::new(hid("fedcba9876543210fedcba9876543210"));
    peer.write_all(&frame(&hello)).await.unwrap();
    peer.write_all(&frame(&Op::Send { to: a.clone(), envelope: envelope(&a, "m-1"), watch: false })).await.unwrap();
    let r = serve_one(server, Hello::new(hid("0123456789abcdef0123456789abcdef")), &host).await;
    assert_eq!(r, Err(ConnError::ExchangeTimeout));
    assert_eq!(host.entered.load(Ordering::SeqCst), 1);
    assert_eq!(host.dropped.load(Ordering::SeqCst), 1, "the host future was dropped when the deadline fired");
}

#[tokio::test(start_paused = true)]
async fn a_close_in_the_middle_of_a_frame_never_calls_the_host() {
    let host = Probe::default();
    let (mut peer, server) = duplex(1 << 20);
    peer.write_all(&frame(&Hello::new(hid("fedcba9876543210fedcba9876543210")))).await.unwrap();
    // The operation frame announces 400 bytes and delivers 10, then the peer goes away.
    peer.write_all(&400u32.to_be_bytes()).await.unwrap();
    peer.write_all(b"{\"op\":\"lis").await.unwrap();
    drop(peer);
    let r = serve_one(server, Hello::new(hid("0123456789abcdef0123456789abcdef")), &host).await;
    assert!(matches!(r, Err(ConnError::Closed | ConnError::Io(_))), "{r:?}");
    assert_eq!(host.entered.load(Ordering::SeqCst), 0);
}

#[tokio::test(start_paused = true)]
async fn a_delivery_is_one_channel_send_so_a_cancelled_send_is_whole_or_absent() {
    let _on = force_peer_messaging_for_test(true);
    let dir = PeerDirectory::new(hid("0123456789abcdef0123456789abcdef"));
    // The "session" takes the command but never answers: the delivery call waits, then the deadline drops it.
    let (h, mut seen) = peer_test_session("sess", None);
    let to = dir.register("sess", h, "", "3f2a9c10").unwrap();
    let peer = hid("fedcba9876543210fedcba9876543210");
    let from = Address::new(peer.as_str(), "x", 1).unwrap();
    let (mut p, server) = duplex(1 << 20);
    p.write_all(&frame(&Hello::new(peer))).await.unwrap();
    p.write_all(&frame(&Op::Send { to, envelope: envelope(&from, "m-1"), watch: false })).await.unwrap();
    let host = ConnHost::new(dir);
    let r = serve_one(server, Hello::new(hid("0123456789abcdef0123456789abcdef")), &host).await;
    assert_eq!(r, Err(ConnError::ExchangeTimeout));
    assert_eq!(seen.try_recv().map(|e| e.message_id), Ok("m-1".to_owned()), "handed over whole, exactly once");
    assert!(seen.try_recv().is_err());
}

// ---------------------------------------------------------------------------------------------------------------
// source pin

#[test]
fn peer_inbox_sources_never_name_the_session_command_path() {
    // Built at run time so this file does not contain the words it forbids.
    let forbidden = [
        ["Session", "Command"].concat(),
        ["cmd", "_tx"].concat(),
        [".sub", "mit("].concat(),
        ["host", "_ingress"].concat(),
    ];
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/peer_inbox");
    let mut checked = 0;
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "rs") {
            let text = std::fs::read_to_string(&p).unwrap();
            for f in &forbidden {
                assert!(!text.contains(f.as_str()), "{} contains {f}", p.display());
            }
            checked += 1;
        }
    }
    assert!(checked >= 10, "scanned only {checked} files");
}


// ---------------------------------------------------------------------------------------------------------------
// Round 2

use super::inbox::fault::{self, Fault};

/// Entries of `<home>/peers` other than the lock file, the locator and `keep`.
fn stray_entries(peers: &Path, keep: &[String]) -> Vec<String> {
    std::fs::read_dir(peers)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n != ".lock" && n != LOCATOR_NAME && !keep.contains(n))
        .collect()
}

/// Another fd of this process takes the directory lock (flock conflicts between open file descriptions).
fn hold_lock(peers: &Path) -> std::fs::File {
    use std::os::fd::AsRawFd;
    let f = std::fs::OpenOptions::new().read(true).write(true).open(peers.join(".lock")).unwrap();
    assert_eq!(unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX) }, 0);
    f
}

#[tokio::test]
async fn r2_a_held_lock_makes_start_fail_closed_and_shutdown_bounded() {
    let t = tmp();
    let home = home_in(&t, "home");
    let peers = home.join("peers");
    let a = PeerInbox::start_with(&home, on()).await.unwrap();
    let a_sock = format!("{}.sock", a.host_id());
    let lock = hold_lock(&peers);
    let t0 = std::time::Instant::now();
    let r = tokio::time::timeout(Duration::from_secs(8), PeerInbox::start_with(&home, on())).await;
    let r = r.expect("start must not wait forever for a held lock");
    assert!(matches!(r.err(), Some(Disabled::LockBusy)));
    assert!(t0.elapsed() < Duration::from_secs(5), "{:?}", t0.elapsed());
    assert!(stray_entries(&peers, std::slice::from_ref(&a_sock)).is_empty(), "start undid its socket and temp dir");
    let t0 = std::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(8), a.shutdown()).await.expect("shutdown is bounded");
    assert!(t0.elapsed() < Duration::from_secs(5));
    assert!(!peers.join(&a_sock).exists(), "our socket is gone even though the row could not be removed");
    drop(lock);
}

#[tokio::test]
async fn r2_from_std_failure_undoes_the_socket_and_the_row() {
    let t = tmp();
    let home = home_in(&t, "home");
    let id = hid(&"ab".repeat(16));
    fault::set(&id, Fault::FromStd);
    let r = PeerInbox::start_inner(&home, on(), id).await;
    assert!(matches!(r.err(), Some(Disabled::Io(_))));
    assert!(stray_entries(&home.join("peers"), &[]).is_empty());
    assert!(rows_of_or_empty(&home).is_empty());
}

#[tokio::test]
async fn r2_a_path_swapped_between_bind_and_check_fails_closed() {
    let t = tmp();
    let home = home_in(&t, "home");
    let id = hid(&"cd".repeat(16));
    fault::set(&id, Fault::SwapAfterBind);
    let r = PeerInbox::start_inner(&home, on(), id).await;
    assert!(matches!(r.err(), Some(Disabled::SocketCheckFailed)));
    // The socket that took the path is NOT ours (different device/inode than the one we bound): the undo leaves it.
    let planted = home.join("peers").join(format!("{}.sock", "cd".repeat(16)));
    assert!(std::fs::symlink_metadata(&planted).is_ok(), "the undo must not remove a socket it did not bind");
    assert!(rows_of_or_empty(&home).is_empty());
}

#[tokio::test]
async fn r2_no_usable_directory_creates_no_peers_dir() {
    let t = tmp();
    let mut home = t.path().to_path_buf();
    while home.as_os_str().len() < 110 {
        home.push("nested-component");
    }
    std::fs::create_dir_all(&home).unwrap();
    let r = PeerInbox::start_with(&home, on()).await;
    assert!(matches!(r.err(), Some(Disabled::SocketDirUnavailable)));
    assert!(!home.join("peers").exists());
}

fn private_dir(p: &Path) {
    std::fs::create_dir_all(p).unwrap();
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn r2_a_symlink_at_each_runtime_level_is_refused_and_nothing_is_created_through_it() {
    for level in 0..3usize {
        let t = tmp();
        let rt = t.path().join("rt");
        private_dir(&rt);
        let target = t.path().join("target");
        private_dir(&target);
        let names = ["fuigo", "0123456789abcdef", "peers"];
        let mut cur = rt.clone();
        for (i, n) in names.iter().enumerate() {
            if i == level {
                std::os::unix::fs::symlink(&target, cur.join(n)).unwrap();
                break;
            }
            private_dir(&cur.join(n));
            cur = cur.join(n);
        }
        let r = CheckedDir::create_under(&rt, &names[..2]);
        let want = if level == 2 { Disabled::PeersSymlink } else { Disabled::AncestorSymlink };
        assert_eq!(r.err(), Some(want), "level {level}");
        assert!(std::fs::read_dir(&target).unwrap().next().is_none(), "nothing created through the link at {level}");
    }
}

#[test]
fn r2_the_runtime_directory_itself_must_be_absolute_ours_and_private() {
    let t = tmp();
    let rt = t.path().join("rt");
    private_dir(&rt);
    std::fs::set_permissions(&rt, std::fs::Permissions::from_mode(0o770)).unwrap();
    assert_eq!(CheckedDir::create_under(&rt, &["fuigo", "x"]).err(), Some(Disabled::RuntimeDirUnavailable));
    assert!(std::fs::read_dir(&rt).unwrap().next().is_none());
    assert_eq!(
        CheckedDir::create_under(Path::new("relative/rt"), &["fuigo", "x"]).err(),
        Some(Disabled::RuntimeDirUnavailable)
    );
    std::fs::set_permissions(&rt, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(CheckedDir::create_under(&rt, &["fuigo", "x"]).is_ok());
    // peers must be exactly 0700
    std::fs::set_permissions(rt.join("fuigo/x/peers"), std::fs::Permissions::from_mode(0o750)).unwrap();
    assert_eq!(CheckedDir::create_under(&rt, &["fuigo", "x"]).err(), Some(Disabled::PeersWrongMode));
}

#[tokio::test]
async fn r2_start_through_a_symlinked_runtime_level_is_refused() {
    let t = tmp();
    let mut home = t.path().to_path_buf();
    while home.as_os_str().len() < 110 {
        home.push("nested-component");
    }
    std::fs::create_dir_all(&home).unwrap();
    let rt = t.path().join("rt");
    private_dir(&rt);
    let target = t.path().join("target");
    private_dir(&target);
    std::os::unix::fs::symlink(&target, rt.join("fuigo")).unwrap();
    let r = PeerInbox::start_with(&home, StartOptions { enabled: true, runtime_dir: Some(rt) }).await;
    assert_eq!(r.err(), Some(Disabled::AncestorSymlink));
    assert!(std::fs::read_dir(&target).unwrap().next().is_none());
}

#[tokio::test]
async fn r2_drop_unlinks_the_socket_at_once_without_taking_the_lock() {
    let t = tmp();
    let home = home_in(&t, "home");
    let peers = home.join("peers");
    let a = PeerInbox::start_with(&home, on()).await.unwrap();
    let sock = peers.join(format!("{}.sock", a.host_id()));
    let lock = hold_lock(&peers);
    let t0 = std::time::Instant::now();
    drop(a);
    assert!(t0.elapsed() < Duration::from_millis(500), "drop never waits for the lock");
    assert!(!sock.exists());
    drop(lock);
}

#[tokio::test]
async fn r2_a_dead_pid_beside_a_live_socket_is_never_reaped() {
    let t = tmp();
    let home = home_in(&t, "home");
    let a = PeerInbox::start_with(&home, on()).await.unwrap();
    let b = PeerInbox::start_with(&home, on()).await.unwrap();
    let d = CheckedDir::open(&home).unwrap();
    let aid = a.host_id().clone();
    update_locator(&d, LOCATOR_NAME, |cur| {
        let mut rows = super::reap::decode_rows(cur);
        for r in &mut rows {
            if r.host_id == aid {
                r.pid = 4_000_000;
            }
        }
        super::reap::encode_rows(&rows)
    })
    .unwrap();
    b.reap(Duration::from_millis(50)).await.unwrap();
    assert!(rows_of(&home).iter().any(|r| r.host_id == aid && r.pid == 4_000_000), "the pid is not consulted");
    assert!(home.join("peers").join(format!("{}.sock", a.host_id())).exists());
}

#[test]
fn r2_the_notice_sink_carries_only_a_typed_kind_and_a_bounded_id() {
    // Compile-time shape: a closure of exactly (host, bounded id, kind) is a sink; a free-text `&str` is not.
    let _sink: super::directory::NoticeSink = Arc::new(|_h: &HostId, _i: &BoundedId, _k: NoticeKind| {});
}

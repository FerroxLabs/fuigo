//! Sub-packet 8f tests (hardening after the Opus review). Every test that opens a socket runs inside `unshare -n`. Each has its
//! own temp home and temp runtime directory, passed as a parameter; the process environment is never touched.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use fuigo_peer::{Address, DeliveryOutcome, Hello, HostDir, HostId, HostRow, NoticeKind, RejectReason, parse_rows};
use tokio::net::UnixListener;

use super::conn::InboxHost;
use super::directory::{ConnHost, PeerDirectory};
use super::host::{PeerHost, PeerInboxStatus};
use super::inbox::{PeerInbox, StartOptions, fault};
use super::inbox_tests::{envelope, hid, home_in, on, tmp};
use super::reap::LOCATOR_NAME;
use super::{CheckedDir, Disabled, read_locator, update_locator};
use crate::session::message_delivery::{PeerGate, peer_test_notice_session, peer_test_session};
use crate::session::peer_message::force_peer_messaging_for_test;

fn rows(home: &Path) -> Vec<HostRow> {
    let Ok(d) = CheckedDir::open(home) else { return vec![] };
    parse_rows(&read_locator(&d, LOCATOR_NAME).ok().flatten().unwrap_or_default()).unwrap_or_default()
}

fn plant(home: &Path, planted: &[HostRow]) {
    let d = CheckedDir::open(home).unwrap();
    update_locator(&d, LOCATOR_NAME, |_| Some(serde_json::to_vec(planted).unwrap())).unwrap();
}

fn row(id: &HostId, dir: HostDir) -> HostRow {
    HostRow { host_id: id.clone(), pid: 1, started: 1, dir }
}

fn socks(home: &Path) -> Vec<String> {
    std::fs::read_dir(home.join("peers"))
        .map(|d| d.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| n.ends_with(".sock")).collect())
        .unwrap_or_default()
}

/// A listener that accepts and never answers, and the connections it keeps open.
fn stuck_listener(path: &Path) -> tokio::task::JoinHandle<()> {
    let l = UnixListener::bind(path).unwrap();
    tokio::spawn(async move {
        let mut keep = Vec::new();
        while let Ok((s, _)) = l.accept().await {
            keep.push(s);
        }
    })
}

// ---- finding 1

#[tokio::test]
async fn xs_p8f_a_session_that_is_not_opted_in_is_neither_listed_nor_addressable() {
    let _on = force_peer_messaging_for_test(true);
    let host = hid("11111111111111111111111111111111");
    let dir = PeerDirectory::new(host.clone());
    let (handle, mut seen) = peer_test_session("s1", Some(crate::session::peer_admission::PeerSubmit::Outcome(DeliveryOutcome::Delivered {})));
    let gate: Arc<PeerGate> = handle.peer_gate().clone();
    gate.set_opted_in(false);
    let addr = dir.register("s1", handle, "", "ref").unwrap();
    let conn = ConnHost::new(dir.clone());
    let from = Address::new("22222222222222222222222222222222", "o", 1).unwrap();
    conn.peer_hello(&HostId::of(&from));
    assert!(conn.list(0).await.0.is_empty(), "registered, not opted in: absent from list");
    let unknown = Address::new(host.as_str(), "nope", 1).unwrap();
    let to_hidden = conn.send(addr.clone(), envelope(&from, "m1")).await;
    let to_unknown = conn.send(unknown, envelope(&from, "m2")).await;
    assert_eq!(to_hidden, DeliveryOutcome::Rejected { reason: RejectReason::Unavailable });
    assert_eq!(to_hidden, to_unknown, "the same reply as an unknown session");
    assert!(seen.try_recv().is_err(), "nothing reached the session");
    gate.set_opted_in(true);
    assert_eq!(conn.list(0).await.0.len(), 1, "opted in: listed");
    assert_eq!(conn.send(addr, envelope(&from, "m3")).await, DeliveryOutcome::Delivered {});
    gate.set_opted_in(false);
    assert!(conn.list(0).await.0.is_empty(), "opted out again: gone");
}

// ---- finding 2

#[tokio::test]
async fn xs_p8f_a_host_that_never_answers_does_not_stop_the_dead_rows_being_reaped() {
    let _on = force_peer_messaging_for_test(true);
    let t = tmp();
    let home = home_in(&t, "home");
    drop(PeerInbox::start_with(&home, on()).await.unwrap());
    let stuck = hid("51000000510000005100000051000000");
    let mut planted: Vec<HostRow> = (0..63).map(|i| row(&hid(&format!("{i:032x}")), HostDir::Home)).collect();
    planted.push(row(&stuck, HostDir::Home));
    plant(&home, &planted);
    let hold = stuck_listener(&home.join("peers").join(format!("{stuck}.sock")));
    let started = std::time::Instant::now();
    let inbox = PeerInbox::start_with(&home, on()).await.expect("start succeeds");
    assert!(started.elapsed() < Duration::from_secs(5) + Duration::from_secs(2), "{:?}", started.elapsed());
    let ids: Vec<HostId> = rows(&home).into_iter().map(|r| r.host_id).collect();
    assert_eq!(ids.len(), 2, "63 dead rows reaped: {ids:?}");
    assert!(ids.contains(&stuck) && ids.contains(inbox.host_id()));
    inbox.shutdown().await;
    hold.abort();
}

#[tokio::test]
async fn xs_p8f_a_full_locator_is_not_terminal_and_the_retry_is_bounded() {
    let _on = force_peer_messaging_for_test(true);
    let t = tmp();
    let home = home_in(&t, "home");
    drop(PeerInbox::start_with(&home, on()).await.unwrap());
    // 64 live hosts (each answers a hello naming itself): nothing can be reaped.
    let mut fakes = Vec::new();
    let mut planted = Vec::new();
    for i in 0..64 {
        let id = hid(&format!("{:032x}", i + 1000));
        let l = UnixListener::bind(home.join("peers").join(format!("{id}.sock"))).unwrap();
        let hello = Hello::new(id.clone());
        fakes.push(tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            while let Ok((mut s, _)) = l.accept().await {
                let h = hello.clone();
                tokio::spawn(async move {
                    let mut len = [0u8; 4];
                    if s.read_exact(&mut len).await.is_err() {
                        return;
                    }
                    let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
                    let _ = s.read_exact(&mut body).await;
                    let out = serde_json::to_vec(&h).unwrap();
                    let _ = s.write_all(&(out.len() as u32).to_be_bytes()).await;
                    let _ = s.write_all(&out).await;
                    let _ = s.read(&mut [0u8; 1]).await;
                });
            }
        }));
        planted.push(row(&id, HostDir::Home));
    }
    plant(&home, &planted);
    let r = PeerInbox::start_with(&home, on()).await;
    assert_eq!(r.err(), Some(Disabled::LocatorFull));
    // Host level: default gap (60 s) means a later registration does NOT start again.
    let (h1, _s1) = peer_test_session("s1", None);
    let slow = Arc::new(PeerHost::with_options(StartOptions { enabled: true, runtime_dir: None }));
    slow.arm(home.clone());
    slow.session_started("s1", h1.clone());
    for _ in 0..400 {
        if slow.status() != PeerInboxStatus::NotStarted {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(slow.status(), PeerInboxStatus::Unavailable { reason: Disabled::LocatorFull });
    plant(&home, &planted[..10]);
    slow.session_started("s2", h1.clone());
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(slow.status(), PeerInboxStatus::Unavailable { reason: Disabled::LocatorFull }, "within 60 s: no new attempt");
    // A short gap: the next registration retries once and now succeeds.
    let quick = Arc::new(PeerHost::with_options(StartOptions { enabled: true, runtime_dir: None }).with_retry_gap(Duration::ZERO));
    quick.arm(home.clone());
    plant(&home, &planted);
    quick.session_started("s1", h1.clone());
    for _ in 0..400 {
        if quick.status() != PeerInboxStatus::NotStarted {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(quick.status(), PeerInboxStatus::Unavailable { reason: Disabled::LocatorFull });
    plant(&home, &planted[..10]);
    quick.session_started("s2", h1);
    for _ in 0..400 {
        if matches!(quick.status(), PeerInboxStatus::Available { .. }) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(matches!(quick.status(), PeerInboxStatus::Available { .. }), "{:?}", quick.status());
    quick.shutdown().await;
    for f in fakes {
        f.abort();
    }
}

// ---- finding 3

#[tokio::test]
async fn xs_p8f_a_runtime_row_is_reaped_only_when_our_own_runtime_directory_verifies() {
    let _on = force_peer_messaging_for_test(true);
    let t = tmp();
    let rt = tmp();
    std::fs::set_permissions(rt.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let home = home_in(&t, "home");
    let a = PeerInbox::start_with(&home, StartOptions { enabled: true, runtime_dir: Some(rt.path().to_path_buf()) })
        .await
        .unwrap();
    let r = hid("bbbb0000bbbb0000bbbb0000bbbb0000");
    let mut all = rows(&home);
    all.push(row(&r, HostDir::Runtime));
    plant(&home, &all);
    // Our runtime peers directory does not exist: not the same directory the row's host used. Kept.
    let rep = a.reap(Duration::from_millis(50)).await.unwrap();
    assert!(rep.reaped.is_empty() && rows(&home).iter().any(|x| x.host_id == r), "kept");
    // Now it exists, ours and 0700: absent twice reaps.
    let rt_home = a.locations().runtime_home().unwrap();
    CheckedDir::create_under(rt.path(), &["fuigo", rt_home.file_name().unwrap().to_str().unwrap()]).unwrap();
    let rep = a.reap(Duration::from_millis(50)).await.unwrap();
    assert_eq!(rep.reaped, vec![r.clone()]);
    assert!(!rows(&home).iter().any(|x| x.host_id == r));
}

// ---- finding 4

#[tokio::test]
async fn xs_p8f_a_start_cancelled_after_bind_leaves_no_socket() {
    let _on = force_peer_messaging_for_test(true);
    let t = tmp();
    let home = home_in(&t, "home");
    let id = hid("cafe0000cafe0000cafe0000cafe0000");
    fault::set(&id, fault::Fault::PauseAfterBind);
    let mut fut = Box::pin(PeerInbox::start_inner(&home, on(), id));
    loop {
        tokio::select! {
            _ = &mut fut => panic!("the start must be paused"),
            () = tokio::time::sleep(Duration::from_millis(20)) => {
                if !socks(&home).is_empty() { break; }
            }
        }
    }
    assert_eq!(socks(&home).len(), 1, "bound");
    drop(fut);
    assert!(socks(&home).is_empty(), "the guard unlinked the orphan");
}

#[tokio::test]
async fn xs_p8f_shutdown_during_a_start_leaves_no_socket_and_no_row() {
    let _on = force_peer_messaging_for_test(true);
    let t = tmp();
    let home = home_in(&t, "home");
    let h = Arc::new(PeerHost::with_options(StartOptions { enabled: true, runtime_dir: None }));
    h.arm(home.clone());
    let (handle, _s) = peer_test_session("s1", None);
    h.session_started("s1", handle);
    h.shutdown().await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(socks(&home).is_empty());
    assert!(rows(&home).is_empty());
}

// ---- finding 9 and smaller points

#[tokio::test]
async fn xs_p8f_a_known_id_cannot_evict_the_ring_and_a_notice_consumes_it() {
    let _on = force_peer_messaging_for_test(true);
    let dir = PeerDirectory::new(hid("11111111111111111111111111111111"));
    let (h, mut seen) = peer_test_notice_session("s1");
    dir.register("s1", h, "", "r").unwrap();
    dir.note_sent("s1", "keep");
    for _ in 0..200 {
        dir.note_sent("s1", "keep");
    }
    for i in 0..63 {
        dir.note_sent("s1", &format!("m{i}"));
    }
    let conn = ConnHost::new(dir.clone());
    let id = fuigo_peer::BoundedId::new("keep").unwrap();
    for _ in 0..5 {
        conn.notice(id.clone(), NoticeKind::Released).await;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(seen.try_recv().unwrap(), ("keep".to_owned(), NoticeKind::Released));
    assert!(seen.try_recv().is_err(), "the replays were dropped");
}

#[tokio::test]
async fn xs_p8f_a_re_registered_session_starts_with_no_sent_ids() {
    let _on = force_peer_messaging_for_test(true);
    let dir = PeerDirectory::new(hid("11111111111111111111111111111111"));
    let (h, mut seen) = peer_test_notice_session("s1");
    dir.register("s1", h.clone(), "", "r").unwrap();
    dir.note_sent("s1", "old");
    dir.register("s1", h, "", "r").unwrap();
    ConnHost::new(dir).notice(fuigo_peer::BoundedId::new("old").unwrap(), NoticeKind::Expired).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(seen.try_recv().is_err());
}

#[tokio::test]
async fn remote_attached_a_notice_is_dropped_not_delivered_and_the_id_survives_for_after_detach() {
    let _on = force_peer_messaging_for_test(true);
    let dir = PeerDirectory::new(hid("11111111111111111111111111111111"));
    let (h, mut seen) = peer_test_notice_session("s1");
    dir.register("s1", h, "", "r").unwrap();
    dir.note_sent("s1", "m1");
    let conn = ConnHost::new(dir);
    let id = fuigo_peer::BoundedId::new("m1").unwrap();
    let g = crate::peer_inbox::driver::attach_remote();
    conn.notice(id.clone(), NoticeKind::Released).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(seen.try_recv().is_err(), "nothing delivered while attached");
    drop(g);
    conn.notice(id, NoticeKind::Released).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(seen.try_recv().unwrap(), ("m1".to_owned(), NoticeKind::Released), "the id was kept");
}

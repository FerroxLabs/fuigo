//! Packet 8e tests: the host wiring over the real inbox. Every test opens sockets, so they run inside an empty network
//! namespace (`unshare -n`). Each has its own temp home; nothing touches `$HOME/.fuigo` or `$XDG_RUNTIME_DIR`
//! (the runtime directory is passed explicitly or left unset).

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use fuigo_peer::{Address, DeliveryOutcome, HostDir, HostId, HostRow, NoticeKind, Op, RejectReason, Reply, parse_rows};

use super::dial::dial;
use super::host::{PeerHost, PeerInboxStatus};
use super::inbox::{PeerInbox, StartOptions};
use super::inbox_tests::{envelope, home_in, hid, on, tmp};
use super::reap::LOCATOR_NAME;
use super::{CheckedDir, Disabled, read_locator, update_locator};
use crate::session::message_delivery::{peer_test_notice_session, peer_test_session};
use crate::session::peer_admission::PeerSubmit;
use crate::session::peer_message::force_peer_messaging_for_test;

fn host(enabled: bool) -> Arc<PeerHost> {
    Arc::new(PeerHost::with_options(StartOptions { enabled, runtime_dir: None }))
}

fn delivered() -> Option<PeerSubmit> {
    Some(PeerSubmit::Outcome(DeliveryOutcome::Delivered {}))
}

async fn wait_for_status(h: &PeerHost) -> PeerInboxStatus {
    for _ in 0..400 {
        let s = h.status();
        if s != PeerInboxStatus::NotStarted {
            return s;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("the host never left NotStarted");
}

fn entries(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> =
        std::fs::read_dir(dir).unwrap().map(|e| e.unwrap().file_name().to_string_lossy().into_owned()).collect();
    v.sort();
    v
}

fn rows(home: &Path) -> Vec<HostRow> {
    let Ok(d) = CheckedDir::open(home) else { return vec![] };
    parse_rows(&read_locator(&d, LOCATOR_NAME).ok().flatten().unwrap_or_default()).unwrap_or_default()
}

/// An observer inbox in the same home: lists and sends to the host under test.
async fn observer(home: &Path) -> PeerInbox {
    PeerInbox::start_with(home, on()).await.unwrap()
}

async fn list(obs: &PeerInbox, target: &HostId) -> Vec<fuigo_peer::SessionRow> {
    match dial(obs.locations(), obs.host_id(), target, HostDir::Home, Op::List { page: 0 }).await.unwrap() {
        Reply::List { rows, .. } => rows,
        other => panic!("{other:?}"),
    }
}

async fn send(obs: &PeerInbox, to: &Address, id: &str) -> DeliveryOutcome {
    let from = Address::new(obs.host_id().as_str(), "obs", 1).unwrap();
    let op = Op::Send { to: to.clone(), envelope: envelope(&from, id), watch: false };
    match dial(obs.locations(), obs.host_id(), &HostId::of(to), HostDir::Home, op).await.unwrap() {
        Reply::Send { outcome } => outcome,
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn flag_off_arm_and_session_start_create_nothing() {
    let t = tmp();
    let home = home_in(&t, "home");
    let before = tokio::runtime::Handle::current().metrics().num_alive_tasks();
    let h = host(false);
    h.arm(home.clone());
    let (handle, _rx) = peer_test_session("s1", delivered());
    let tasks_with_session_helper = tokio::runtime::Handle::current().metrics().num_alive_tasks();
    let _keep_session_alive = handle.clone();
    h.session_started("s1", handle);
    h.session_ended("s1");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(tokio::runtime::Handle::current().metrics().num_alive_tasks(), tasks_with_session_helper, "no task spawned");
    let _ = before;
    assert!(entries(&home).is_empty(), "no peers/, no socket, no file in the home");
    assert_eq!(h.status(), PeerInboxStatus::Unavailable { reason: Disabled::FeatureOff });
    h.shutdown().await;
    assert!(entries(&home).is_empty());
}

#[tokio::test]
async fn the_inbox_starts_lazily_at_the_first_session_and_serves_list_and_send() {
    let _on = force_peer_messaging_for_test(true);
    let t = tmp();
    let home = home_in(&t, "home");
    let h = host(true);
    h.arm(home.clone());
    assert_eq!(h.status(), PeerInboxStatus::NotStarted);
    assert!(entries(&home).is_empty(), "arming alone creates nothing");
    let (handle, mut seen) = peer_test_session("s1", delivered());
    h.session_started("s1", handle);
    let PeerInboxStatus::Available { host_id } = wait_for_status(&h).await else { panic!("not available") };
    let obs = observer(&home).await;
    let rows = list(&obs, &host_id).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].address.session_id(), "s1");
    // Delivered only through the delivery handle: the session saw exactly the envelope.
    assert_eq!(send(&obs, &rows[0].address, "m-1").await, DeliveryOutcome::Delivered {});
    assert_eq!(seen.try_recv().unwrap().message_id, "m-1");
    // A second session on the same host does not start a second inbox.
    let (h2, _rx2) = peer_test_session("s2", delivered());
    h.session_started("s2", h2);
    assert_eq!(list(&obs, &host_id).await.len(), 2);
    assert_eq!(rows_in(&home, &host_id), 1);
    h.shutdown().await;
}

fn rows_in(home: &Path, id: &HostId) -> usize {
    rows(home).iter().filter(|r| &r.host_id == id).count()
}

#[tokio::test]
async fn a_restarted_session_gets_a_new_incarnation_and_the_old_address_is_refused() {
    let _on = force_peer_messaging_for_test(true);
    let t = tmp();
    let home = home_in(&t, "home");
    let h = host(true);
    h.arm(home.clone());
    let (old_handle, mut old_seen) = peer_test_session("s1", delivered());
    h.session_started("s1", old_handle);
    let PeerInboxStatus::Available { host_id } = wait_for_status(&h).await else { panic!() };
    let obs = observer(&home).await;
    let old = list(&obs, &host_id).await.remove(0).address;
    // Replaced resident: registering again raises the incarnation.
    let (new_handle, mut new_seen) = peer_test_session("s1", delivered());
    h.session_started("s1", new_handle);
    let new = list(&obs, &host_id).await.remove(0).address;
    assert!(new.incarnation() > old.incarnation());
    assert_eq!(send(&obs, &old, "m-old").await, DeliveryOutcome::Rejected { reason: RejectReason::Unavailable });
    assert!(old_seen.try_recv().is_err() && new_seen.try_recv().is_err(), "nothing was delivered to either");
    assert_eq!(send(&obs, &new, "m-new").await, DeliveryOutcome::Delivered {});
    // Ended: not listed, and an ended-then-restarted id never revives an old address either.
    h.session_ended("s1");
    assert!(list(&obs, &host_id).await.is_empty());
    let (again, _rx) = peer_test_session("s1", delivered());
    h.session_started("s1", again);
    assert!(list(&obs, &host_id).await.remove(0).address.incarnation() > new.incarnation());
    assert_eq!(send(&obs, &new, "m-stale").await, DeliveryOutcome::Rejected { reason: RejectReason::Unavailable });
    h.shutdown().await;
}

#[tokio::test]
async fn shutdown_removes_the_socket_and_the_row() {
    let _on = force_peer_messaging_for_test(true);
    let t = tmp();
    let home = home_in(&t, "home");
    let h = host(true);
    h.arm(home.clone());
    let (handle, _rx) = peer_test_session("s1", delivered());
    h.session_started("s1", handle);
    let PeerInboxStatus::Available { host_id } = wait_for_status(&h).await else { panic!() };
    assert!(home.join("peers").join(format!("{host_id}.sock")).exists());
    assert_eq!(rows_in(&home, &host_id), 1);
    h.shutdown().await;
    assert!(!home.join("peers").join(format!("{host_id}.sock")).exists());
    assert_eq!(rows_in(&home, &host_id), 0);
    // After shutdown a late session start does nothing.
    let (late, _rx) = peer_test_session("s9", delivered());
    h.session_started("s9", late);
    assert_eq!(h.status(), PeerInboxStatus::NotStarted);
}

#[tokio::test]
async fn a_symlinked_home_starts_normally_reports_unavailable_and_is_not_retried() {
    let _on = force_peer_messaging_for_test(true);
    let t = tmp();
    let real = home_in(&t, "real");
    let link = t.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let h = host(true);
    h.arm(link.clone());
    let (handle, _rx) = peer_test_session("s1", delivered());
    h.session_started("s1", handle);
    assert_eq!(wait_for_status(&h).await, PeerInboxStatus::Unavailable { reason: Disabled::SymlinkedHome });
    // The host carries on: later sessions come and go, nothing is created through the link, the reason stays.
    let (h2, _rx2) = peer_test_session("s2", delivered());
    h.session_started("s2", h2);
    h.session_ended("s2");
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(entries(&real).is_empty());
    assert_eq!(h.status(), PeerInboxStatus::Unavailable { reason: Disabled::SymlinkedHome });
    h.shutdown().await;
}

#[tokio::test]
async fn a_crashed_hosts_row_is_reaped_by_the_next_start_even_when_the_locator_is_full() {
    let _on = force_peer_messaging_for_test(true);
    let t = tmp();
    let home = home_in(&t, "home");
    // Create `<home>/peers` through an inbox that is then dropped, and plant 64 rows of hosts that no longer exist.
    drop(observer(&home).await);
    let dir = CheckedDir::open(&home).unwrap();
    let planted: Vec<HostRow> = (0..64)
        .map(|i| HostRow { host_id: hid(&format!("{i:032x}")), pid: 1, started: 1, dir: HostDir::Home })
        .collect();
    update_locator(&dir, LOCATOR_NAME, |_| Some(serde_json::to_vec(&planted).unwrap())).unwrap();
    assert_eq!(rows(&home).len(), 64);
    // Without the reap pass this start would fail with OutputTooLarge.
    let started = std::time::Instant::now();
    let inbox = PeerInbox::start_with(&home, on()).await.unwrap();
    assert!(started.elapsed() < Duration::from_secs(5), "the pass is bounded");
    let ids: Vec<HostId> = rows(&home).into_iter().map(|r| r.host_id).collect();
    assert_eq!(ids, vec![inbox.host_id().clone()], "all 64 dead rows reaped, ours written");
    inbox.shutdown().await;
}

#[tokio::test]
async fn a_live_hosts_row_is_not_reaped_and_costs_no_second_try() {
    let _on = force_peer_messaging_for_test(true);
    let t = tmp();
    let home = home_in(&t, "home");
    let a = observer(&home).await;
    let started = std::time::Instant::now();
    let b = PeerInbox::start_with(&home, on()).await.unwrap();
    assert!(started.elapsed() < Duration::from_millis(900), "a live row is probed once");
    let ids: Vec<HostId> = rows(&home).into_iter().map(|r| r.host_id).collect();
    assert!(ids.contains(a.host_id()) && ids.contains(b.host_id()));
}

#[tokio::test]
async fn a_runtime_directory_failure_leaves_no_peers_directory_in_the_home() {
    let _on = force_peer_messaging_for_test(true);
    let t = tmp();
    let mut home = t.path().to_path_buf();
    while home.as_os_str().len() < 100 {
        home.push("nested-component");
    }
    std::fs::create_dir_all(&home).unwrap();
    let rt = t.path().join("rt");
    std::fs::create_dir_all(&rt).unwrap();
    std::fs::set_permissions(&rt, std::os::unix::fs::PermissionsExt::from_mode(0o777)).unwrap();
    let r = PeerInbox::start_with(&home, StartOptions { enabled: true, runtime_dir: Some(rt.clone()) }).await;
    assert_eq!(r.err(), Some(Disabled::RuntimeDirUnavailable));
    assert!(!home.join("peers").exists(), "no <home>/peers left behind");
    assert!(entries(&rt).is_empty());
}

#[tokio::test]
async fn a_notice_reaches_only_the_session_that_sent_that_message_id() {
    let _on = force_peer_messaging_for_test(true);
    let t = tmp();
    let home = home_in(&t, "home");
    let inbox = PeerInbox::start_with(&home, on()).await.unwrap();
    let (ia, mut ia_seen) = peer_test_notice_session("sa");
    let (ib, mut ib_seen) = peer_test_notice_session("sb");
    inbox.directory().register("sa", ia, "", "r1").unwrap();
    inbox.directory().register("sb", ib, "", "r2").unwrap();
    inbox.directory().note_sent("sa", "msg-a");
    inbox.directory().note_sent("sb", "msg-b");
    let other = observer(&home).await;
    for (id, kind) in [("msg-a", NoticeKind::Released), ("unknown", NoticeKind::Refused), ("msg-b", NoticeKind::Expired)] {
        let op = Op::Notice { message_id: fuigo_peer::BoundedId::new(id).unwrap(), kind };
        let r = dial(other.locations(), other.host_id(), inbox.host_id(), HostDir::Home, op).await.unwrap();
        assert_eq!(r, Reply::Notice {});
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(ia_seen.try_recv().unwrap(), ("msg-a".to_owned(), NoticeKind::Released));
    assert!(ia_seen.try_recv().is_err(), "sa got nothing for msg-b or the unknown id");
    assert_eq!(ib_seen.try_recv().unwrap(), ("msg-b".to_owned(), NoticeKind::Expired));
    assert!(ib_seen.try_recv().is_err());
    // The ring is bounded.
    for i in 0..200 {
        inbox.directory().note_sent("sa", &format!("m{i}"));
    }
}

/// The real path: a group-writable home makes the started host `Unavailable { HomeWritableByOthers }`, and the message built
/// from that host's own status names the armed home (never an empty path, never a command without one).
#[tokio::test]
async fn status_of_a_group_writable_home_yields_the_message_with_the_armed_home() {
    use std::os::unix::fs::PermissionsExt;
    let _on = force_peer_messaging_for_test(true);
    let t = tmp();
    let home = t.path().join("fuigo-home");
    std::fs::create_dir(&home).unwrap();
    std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o775)).unwrap();
    let h = host(true);
    h.arm(home.clone());
    let (handle, _rx) = peer_test_session("s1", delivered());
    h.session_started("s1", handle);
    let PeerInboxStatus::Unavailable { reason } = wait_for_status(&h).await else { panic!("expected Unavailable") };
    assert_eq!(reason, Disabled::HomeWritableByOthers);
    let msg = h.reason_message(reason);
    assert!(msg.ends_with(&format!("(run: chmod go-w {})", home.display())), "{msg}");
    // A host with no recorded home falls back to the generic text.
    assert_eq!(host(true).reason_message(Disabled::HomeWritableByOthers), Disabled::HomeWritableByOthers.reason_text());
    h.shutdown().await;
}

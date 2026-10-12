//! Packet 15c, group C: the Windows inbox over REAL named pipes. They run ONLY on the Windows test box, under a BATCH logon
//! as a normal user (a network logon such as ssh is refused by design and the desktop is off limits). Each test builds its own
//! Fuigo home with an owner-only DACL under a temp root; the root's ancestors are trusted through `trusted_ancestors`
//! (the machine's shared temp directories are what the real ancestor rule refuses).

use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use fuigo_peer::{
    Address, DeliveryOutcome, Envelope, HostDir, HostId, HostRow, NoticeKind, Op, OperatorKind, PeerBase, PeerMode, Reply,
};
use windows::Win32::Security::SECURITY_ATTRIBUTES;
use windows::Win32::Storage::FileSystem::CreateDirectoryW;
use windows::core::PCWSTR;

use super::*;
use crate::leader::peer_auth::win as auth;
use crate::peer_inbox::host::{PeerHost, PeerInboxStatus};
use crate::peer_inbox::rows::{decode_rows, encode_rows};
use crate::peer_inbox::win_policy::{WinDialError, parse_home_path};
use crate::session::message_delivery::{peer_test_notice_session, peer_test_session};
use crate::session::peer_admission::PeerSubmit;
use crate::session::peer_message::force_peer_messaging_for_test;

struct TestHome {
    _root: tempfile::TempDir,
    home: PathBuf,
    depth: usize,
}

fn test_home() -> TestHome {
    let root = tempfile::tempdir().expect("temp root");
    let home = root.path().join("home");
    let me = auth::own_sid().expect("own sid");
    let mut sec = auth::PipeSecurity::from_sddl(&format!("D:P(A;OICI;FA;;;{me})")).expect("sddl");
    let w: Vec<u16> = home.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: NUL-terminated name; the descriptor lives in `sec` across the call.
    unsafe { CreateDirectoryW(PCWSTR(w.as_ptr()), Some(sec.as_raw().cast::<SECURITY_ATTRIBUTES>().cast_const())) }
        .expect("CreateDirectoryW");
    let depth = parse_home_path(root.path().to_str().unwrap()).unwrap().len();
    TestHome { _root: root, home, depth }
}

fn opts(h: &TestHome) -> StartOptions {
    StartOptions { enabled: true, trusted_ancestors: h.depth }
}

async fn start(h: &TestHome) -> PeerInbox {
    PeerInbox::start_with(&h.home, opts(h)).await.expect("start")
}

fn rows_of(home: &Path) -> Vec<HostRow> {
    let d = CheckedDir::create_or_open_trusting(home, parse_home_path(home.parent().unwrap().to_str().unwrap()).unwrap().len())
        .expect("reopen");
    decode_rows(read_locator(&d, LOCATOR_NAME).unwrap().as_deref())
}

fn envelope(from: &Address, id: &str) -> Envelope {
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

fn ghost(c: char) -> HostRow {
    HostRow { host_id: HostId::new(&c.to_string().repeat(32)).unwrap(), pid: 4242, started: 7, dir: HostDir::Home }
}

async fn plant(inbox: &PeerInbox, row: HostRow) {
    let (d, r) = (inbox.peers_dir().clone(), row);
    tokio::task::spawn_blocking(move || {
        update_locator(&d, LOCATOR_NAME, |cur| {
            let mut rows = decode_rows(cur);
            rows.push(r);
            encode_rows(&rows)
        })
        .unwrap();
    })
    .await
    .unwrap();
}

async fn pipe_gone(our: &HostId, host: &HostId) -> bool {
    for _ in 0..40 {
        if matches!(win_pipe::dial(our, host, Op::List { page: 0 }).await, Err(WinDialError::NoServer)) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test]
async fn c1_start_publishes_our_row_the_pipe_answers_and_shutdown_removes_row_and_pipe() {
    let _on = force_peer_messaging_for_test(true);
    let h = test_home();
    let a = start(&h).await;
    let mine = rows_of(&h.home);
    assert_eq!(mine.len(), 1);
    assert_eq!(&mine[0].host_id, a.host_id());
    assert_eq!(mine[0].pid, std::process::id());
    assert!(h.home.join("peers").is_dir());
    let probe = HostId::new(&"e".repeat(32)).unwrap();
    assert!(matches!(win_pipe::dial(&probe, a.host_id(), Op::List { page: 0 }).await, Ok(Reply::List { .. })), "the pipe exists");
    a.shutdown().await;
    a.shutdown().await;
    assert!(rows_of(&h.home).is_empty(), "our row is gone");
    assert!(pipe_gone(&probe, a.host_id()).await, "the pipe is gone");
}

#[tokio::test]
async fn c1_status_through_the_host_is_available_once_started() {
    let _on = force_peer_messaging_for_test(true);
    let h = test_home();
    let host = Arc::new(PeerHost::with_options(opts(&h)));
    host.arm(h.home.clone());
    let (handle, _seen) = peer_test_session("s1", delivered());
    host.session_started("s1", handle);
    let mut status = host.status();
    for _ in 0..200 {
        if !matches!(status, PeerInboxStatus::NotStarted) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        status = host.status();
    }
    let id = match status {
        PeerInboxStatus::Available { host_id } => host_id,
        other => panic!("{other:?}"),
    };
    assert_eq!(rows_of(&h.home).iter().map(|r| r.host_id.clone()).collect::<Vec<_>>(), vec![id]);
    host.shutdown().await;
    assert!(rows_of(&h.home).is_empty());
}

#[tokio::test]
async fn c2_a_lists_b_sends_to_its_session_and_a_watch_notice_comes_back() {
    let _on = force_peer_messaging_for_test(true);
    let h = test_home();
    let a = start(&h).await;
    let b = start(&h).await;
    assert_ne!(a.host_id(), b.host_id());
    let (ha, mut a_seen) = peer_test_notice_session("sa");
    let from = a.directory().register("sa", ha, "", "r1").unwrap();
    let (hb, mut b_envelopes) = peer_test_session("sb", delivered());
    let to = b.directory().register("sb", hb.clone(), "worker", "r2").unwrap();

    // The rows of other hosts, minus ours.
    let others = a.other_hosts(8).await;
    assert_eq!(others.iter().map(|r| r.host_id.clone()).collect::<Vec<_>>(), vec![b.host_id().clone()]);
    // List through the pipe.
    match a.dial(b.host_id(), Op::List { page: 0 }).await.unwrap() {
        Reply::List { rows, more } => {
            assert!(!more);
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].address, to);
            assert_eq!(rows[0].name, "worker");
        }
        other => panic!("{other:?}"),
    }
    // A plain send is delivered.
    let r = a.dial(b.host_id(), Op::Send { to: to.clone(), envelope: envelope(&from, "m-1"), watch: false }).await.unwrap();
    assert_eq!(r, Reply::Send { outcome: DeliveryOutcome::Delivered {} });
    assert_eq!(b_envelopes.try_recv().expect("the session got the envelope").message_id, "m-1");

    // A watched send: B arms the watch; when B's turn ends the notice travels B's pump -> A's pipe -> A's session.
    a.directory().note_sent_to("sa", "w-1", &to, true);
    let r = a.dial(b.host_id(), Op::Send { to: to.clone(), envelope: envelope(&from, "w-1"), watch: true }).await.unwrap();
    assert_eq!(r, Reply::Send { outcome: DeliveryOutcome::Watching {} });
    let book = &hb.peer_gate().watches;
    book.turn_started();
    book.bind_turn("w-1");
    book.turn_ended();
    let got = tokio::time::timeout(Duration::from_secs(8), a_seen.recv()).await.expect("a notice").expect("open");
    assert_eq!(got, ("w-1".to_owned(), NoticeKind::Idle));

    // A host that is not in the locator, and one whose pipe does not exist, are classified.
    let nobody = HostId::new(&"9".repeat(32)).unwrap();
    assert_eq!(a.dial(&nobody, Op::List { page: 0 }).await.err(), Some(DialClass::Gone));
    b.shutdown().await;
    a.shutdown().await;
}

#[tokio::test]
async fn c3_a_row_without_a_pipe_is_reaped_after_two_tries_not_after_one_and_a_live_host_never() {
    let _on = force_peer_messaging_for_test(true);
    let h = test_home();
    let a = start(&h).await;
    let b = start(&h).await;
    plant(&a, ghost('d')).await;
    assert_eq!(rows_of(&h.home).len(), 3);
    // One try only: the pass is cut off during the gap between the two tries.
    let cut = tokio::time::timeout(Duration::from_millis(400), a.reap(Duration::from_secs(5))).await;
    assert!(cut.is_err(), "the pass was cut short");
    let ids: Vec<HostId> = rows_of(&h.home).into_iter().map(|r| r.host_id).collect();
    assert!(ids.contains(&ghost('d').host_id), "one failed try never reaps");
    // Two tries: reaped. B answers both times and stays; our own row is never judged.
    let report = a.reap(Duration::from_millis(100)).await.unwrap();
    assert_eq!(report.reaped, vec![ghost('d').host_id]);
    let ids: Vec<HostId> = rows_of(&h.home).into_iter().map(|r| r.host_id).collect();
    assert_eq!(ids.len(), 2);
    assert!(ids.contains(a.host_id()) && ids.contains(b.host_id()));
    // A row that was replaced between the read and the removal (another pid) is not removed by a stale judgement.
    let (d, stale, fresh) = (a.peers_dir().clone(), ghost('f'), HostRow { pid: 1, ..ghost('f') });
    plant(&a, fresh.clone()).await;
    let removed = remove_rows(&d, &[stale]).await.unwrap();
    assert!(removed.is_empty());
    assert!(rows_of(&h.home).iter().any(|r| r == &fresh));
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn c3_the_start_reaps_dead_rows_before_writing_ours() {
    let _on = force_peer_messaging_for_test(true);
    let h = test_home();
    let a = start(&h).await;
    plant(&a, ghost('d')).await;
    let b = start(&h).await;
    let ids: Vec<HostId> = rows_of(&h.home).into_iter().map(|r| r.host_id).collect();
    assert!(!ids.contains(&ghost('d').host_id), "the start's reap pass removed the dead row");
    assert!(ids.contains(a.host_id()) && ids.contains(b.host_id()));
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn c4_flag_off_is_feature_off_with_no_pipe_and_no_file() {
    let h = test_home();
    let r = PeerInbox::start_with(&h.home, StartOptions { enabled: false, trusted_ancestors: h.depth }).await;
    assert_eq!(r.err(), Some(Disabled::FeatureOff));
    assert!(!h.home.join("peers").exists(), "no directory was created");
}

#[tokio::test]
async fn c5_a_start_cancelled_after_the_row_was_written_leaves_no_row_and_no_pipe() {
    let _on = force_peer_messaging_for_test(true);
    let h = test_home();
    let id = HostId::new(&"c".repeat(32)).unwrap();
    super::fault::set(&id, super::fault::Fault::PauseAfterPublish);
    let attempt = tokio::time::timeout(Duration::from_millis(1500), PeerInbox::start_inner(&h.home, opts(&h), id.clone())).await;
    assert!(attempt.is_err(), "the start was cancelled while paused");
    let probe = HostId::new(&"e".repeat(32)).unwrap();
    assert!(pipe_gone(&probe, &id).await, "no pipe");
    let mut empty = false;
    for _ in 0..40 {
        if rows_of(&h.home).is_empty() {
            empty = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(empty, "no row");
}

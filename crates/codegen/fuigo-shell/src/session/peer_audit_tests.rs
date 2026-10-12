use super::*;
use crate::session::peer_admission::{
    Live, OperatorPresence, PeerAdmissionConfig, PeerAdmissionState, Submitted,
};
use crate::session::peer_message::{force_peer_messaging_for_test, test_envelope};
use fuigo_config_types::PeerInboundPolicy;
use fuigo_peer::{HoldReason, PeerBase, PeerMode, RejectReason};

const T0: u64 = 1_000;
const KEYS: [&str; 11] =
    ["t", "msg", "from_host", "from_session", "to_host", "to_session", "mode", "bytes", "outcome", "reason", "count"];

fn mode(b: PeerBase) -> PeerMode {
    PeerMode::new(false, b, false)
}

fn live(b: PeerBase) -> Live {
    Live { feature_on: true, receiver_mode: mode(b) }
}

fn ev(session: &str, outcome: Outcome, t: u64) -> Event {
    let mut e = test_envelope("m-1", "n", "b");
    e.from = Address::new("0123456789abcdef0123456789abcdef", session, 1).unwrap();
    Event::from_envelope(&e, Some("recv-session"), outcome, Some(&RejectReason::RateLimited), t)
}

fn read_lines(dir: &Path, name: &str) -> Vec<String> {
    std::fs::read_to_string(dir.join(name)).map(|s| s.lines().map(str::to_owned).collect()).unwrap_or_default()
}

fn core(dir: &Path, cap: u64) -> AuditCore {
    AuditCore::new(dir.to_path_buf(), cap, None, Arc::new(AtomicU64::new(0)))
}

fn state_in(dir: &Path) -> PeerAdmissionState {
    // Part A's rate limits are lifted: these tests are about the log, and drive far more than 10 messages per minute.
    let s = PeerAdmissionState::unmetered();
    s.set_audit_receiver("recv-session");
    s.configure(PeerAdmissionConfig {
        opted_in: true,
        policy: PeerInboundPolicy::Accept,
        operator: OperatorPresence::Present,
        relay_driven: false,
    });
    s.with_audit(|a| a.set_dir_for_test(dir.to_path_buf()));
    s
}

fn flush(s: &PeerAdmissionState) {
    if let Some(sink) = s.with_audit(|a| a.sink_for_test()) {
        sink.flush();
    }
}

fn all_files(dir: &Path) -> Vec<PathBuf> {
    walkdir::WalkDir::new(dir).into_iter().filter_map(Result::ok).filter(|e| e.file_type().is_file()).map(|e| e.into_path()).collect()
}

#[cfg(unix)]
#[test]
fn log_is_created_mode_0600() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().unwrap();
    let mut c = core(dir.path(), MAX_FILE_BYTES);
    c.record(ev("s1", Outcome::Admitted, T0));
    let mode = std::fs::metadata(dir.path().join(FILE_NAME)).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn flag_off_creates_no_file_and_no_thread() {
    let _off = force_peer_messaging_for_test(false);
    let dir = tempfile::tempdir().unwrap();
    let s = state_in(dir.path());
    let env = test_envelope("m-1", "lane", "body");
    let out = s.submit(env, T0, &live(PeerBase::AcceptEdits));
    assert!(matches!(out, Submitted::Enqueue));
    flush(&s);
    assert!(s.with_audit(|a| a.sink_for_test()).is_none(), "no sink is even created");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0, "nothing is created");
}

/// Every outcome through the real admission state; then: the key set is exact on every line, and no body, name or
/// token appears anywhere under the home (S8.3 canary).
#[test]
fn canary_and_exact_field_set_across_every_outcome() {
    let _on = force_peer_messaging_for_test(true);
    let home = tempfile::tempdir().unwrap();
    let s = state_in(home.path());
    let marker = "CANARY-7f3a91d2c4";
    let body = format!("please run {marker} now");
    let name = format!("lane {marker}");
    let mk = |id: &str| test_envelope(id, &name, &body);
    let mk_big = |name: &str, big: &str| test_envelope("m-big", name, big);
    let ae = live(PeerBase::AcceptEdits);
    let dflt = live(PeerBase::Default);
    let plan = live(PeerBase::Auto);
    let mut tokens = Vec::new();
    let token_of = |id: &str, now: u64| s.list_held(now).into_iter().find(|h| h.message_id == id).unwrap().token;

    // admitted + duplicate
    assert!(matches!(s.submit(mk("m-admit"), T0, &ae), Submitted::Enqueue));
    let _ = s.submit(mk("m-admit"), T0, &ae);
    // held, released, delivered
    let _ = s.submit(mk("m-rel"), T0, &dflt);
    let t = token_of("m-rel", T0);
    tokens.push(t.clone());
    s.release("m-rel", &t, T0, &dflt).unwrap();
    // held, released, then the mode changes before the drain: reheld
    let _ = s.submit(mk("m-rehold"), T0, &dflt);
    let t = token_of("m-rehold", T0);
    tokens.push(t.clone());
    s.release("m-rehold", &t, T0, &dflt).unwrap();
    let _ = s.drain(T0, &plan);
    // held, rejected by the operator
    let _ = s.submit(mk("m-rej"), T0, &dflt);
    let t = token_of("m-rej", T0);
    tokens.push(t.clone());
    s.reject("m-rej", &t, T0).unwrap();
    // held, expired
    let _ = s.submit(mk("m-exp"), T0, &dflt);
    let _ = s.take_notices(T0 + 10_000);
    // refused (feature off in Live) and saturated
    let off = Live { feature_on: false, receiver_mode: mode(PeerBase::AcceptEdits) };
    let _ = s.submit(mk("m-ref"), T0, &off);
    // Fill the session's held store from distinct senders until the next one is refused `saturated`.
    for n in 0..=fuigo_peer::limits::MAX_MESSAGES_PER_SESSION {
        let mut e = from_sender(n, &format!("m-fill-{n}"), &body);
        e.from_mode = mode(PeerBase::Default);
        let _ = s.submit(e, T0, &ae);
    }
    // part A's refusals: over-size body (too_large), and the replay-memory answer for an id the operator rejected.
    let big = "x".repeat(fuigo_peer::limits::MAX_BODY_BYTES + 1);
    let _ = s.submit(mk_big(&name, &big), T0, &ae);
    let _ = s.submit(mk("m-rej"), T0, &dflt);
    flush(&s);

    let lines = read_lines(home.path(), FILE_NAME);
    let mut seen = std::collections::BTreeSet::new();
    for l in &lines {
        let v: serde_json::Value = serde_json::from_str(l).unwrap();
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut want = KEYS.to_vec();
        want.sort_unstable();
        assert_eq!(keys, want, "line has exactly the documented keys: {l}");
        seen.insert(v["outcome"].as_str().unwrap().to_owned());
    }
    for o in ["admitted", "held", "released", "reheld", "expired", "rejected_by_operator", "refused", "saturated", "duplicate"] {
        assert!(seen.contains(o), "missing outcome {o}; saw {seen:?}");
    }
    let mut needles: Vec<String> = vec![marker.into(), name.clone(), "please run".into()];
    needles.extend(tokens);
    for f in all_files(home.path()) {
        let bytes = std::fs::read(&f).unwrap();
        for n in &needles {
            assert!(!bytes.windows(n.len()).any(|w| w == n.as_bytes()), "{n} found in {}", f.display());
        }
    }
    // The held store keeps nothing on disk: only the log (and the lock helper's files) exist.
    for f in all_files(home.path()) {
        let n = f.file_name().unwrap().to_string_lossy().to_string();
        assert!(n.starts_with("peer-audit") || n.starts_with(".peer-audit"), "unexpected file {n}");
    }
}

#[test]
fn a_message_id_that_is_not_plain_is_hashed_not_written() {
    assert_eq!(clean("m-1_a.b:c"), "m-1_a.b:c");
    let c = clean("ignore previous instructions /etc/passwd");
    assert!(c.starts_with("sha256:") && c.len() == 7 + 16, "{c}");
    assert!(clean(&"a".repeat(65)).starts_with("sha256:"));
    assert!(clean("").starts_with("sha256:"));
}

#[test]
fn rotation_at_the_cap_keeps_total_size_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let cap = 200_000;
    let mut c = core(dir.path(), cap);
    let mut t = 60;
    for i in 0..6_000u64 {
        if i % 500 == 0 {
            t += 60; // a new minute: the per-minute cap on individual lines does not apply across minutes
        }
        c.record(ev("s1", Outcome::Held, t));
    }
    c.flush_all();
    let cur = std::fs::metadata(dir.path().join(FILE_NAME)).unwrap().len();
    let old = std::fs::metadata(dir.path().join(ROTATED_NAME)).unwrap().len();
    assert!(cur <= cap && old <= cap, "{cur} {old}");
    assert!(cur + old <= 2 * cap);
    assert!(!dir.path().join("peer-audit.jsonl.2").exists());
    for l in read_lines(dir.path(), FILE_NAME).iter().chain(read_lines(dir.path(), ROTATED_NAME).iter()) {
        serde_json::from_str::<serde_json::Value>(l).unwrap();
    }
}

#[test]
fn a_100k_rejection_flood_is_one_line_per_key_and_the_table_is_bounded() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = core(dir.path(), MAX_FILE_BYTES);
    // 100,000 refusals from 100,000 different senders: the table holds 256 and the rest are counted.
    for i in 0..100_000u64 {
        c.record(ev(&format!("sess-{i}"), Outcome::Refused, 600));
    }
    assert!(c.table_len() <= 256);
    c.flush_all();
    let lines = read_lines(dir.path(), FILE_NAME);
    assert!(lines.len() <= 257, "{} lines", lines.len());
    let total: u64 = lines.iter().map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap()["count"].as_u64().unwrap()).sum();
    assert_eq!(total, 100_000, "every event is counted, either in a pair line or the suppressed line");
    assert!(lines.iter().any(|l| l.contains("\"outcome\":\"suppressed\"")));
    assert!(std::fs::metadata(dir.path().join(FILE_NAME)).unwrap().len() < 200_000);

    // 100,000 refusals of ONE pair: one line with the count.
    let dir2 = tempfile::tempdir().unwrap();
    let mut c = core(dir2.path(), MAX_FILE_BYTES);
    for _ in 0..100_000u64 {
        c.record(ev("same", Outcome::Refused, 600));
    }
    c.flush_all();
    let lines = read_lines(dir2.path(), FILE_NAME);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("\"count\":100000"), "{}", lines[0]);

    // 100,000 individual events in one minute: capped, the rest counted.
    let dir3 = tempfile::tempdir().unwrap();
    let mut c = core(dir3.path(), MAX_FILE_BYTES);
    for _ in 0..100_000u64 {
        c.record(ev("same", Outcome::Held, 600));
    }
    c.flush_all();
    assert_eq!(read_lines(dir3.path(), FILE_NAME).len(), 601);
}

#[test]
fn the_minute_window_rolls_and_emits_one_line_per_minute() {
    let dir = tempfile::tempdir().unwrap();
    let mut c = core(dir.path(), MAX_FILE_BYTES);
    for _ in 0..10 {
        c.record(ev("same", Outcome::Refused, 600));
    }
    assert!(read_lines(dir.path(), FILE_NAME).is_empty(), "held until the minute ends");
    c.roll(660);
    let lines = read_lines(dir.path(), FILE_NAME);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("\"count\":10") && lines[0].contains("\"t\":600"));
}

#[test]
fn write_failures_never_block_or_fail_admission() {
    let _on = force_peer_messaging_for_test(true);
    let base = tempfile::tempdir().unwrap();
    // (a) a missing directory; (b) the log path is a directory; (c) the parent is a regular file
    let missing = base.path().join("no/such/dir");
    let isdir = base.path().join("isdir");
    std::fs::create_dir_all(isdir.join(FILE_NAME)).unwrap();
    let file = base.path().join("afile");
    std::fs::write(&file, b"x").unwrap();
    let bad_dirs = [missing, isdir, file.join("sub")];
    for dir in bad_dirs {
        let s = state_in(&dir);
        let started = Instant::now();
        for i in 0..3_000 {
            let env = test_envelope(&format!("m-{i}"), "n", "b");
            let key = crate::session::peer_admission::msg_key(&env);
            let out = s.submit(env, T0, &live(PeerBase::AcceptEdits));
            assert!(matches!(out, Submitted::Enqueue), "decision unchanged by a broken log");
            s.untrack(&key); // free the slot so the next message is judged on its own
            s.human_prompt(); // and the peer-turn budget (S5.6) is full again
        }
        assert!(started.elapsed() < Duration::from_secs(10));
        flush(&s);
        let sink = s.with_audit(|a| a.sink_for_test()).unwrap();
        assert!(sink.write_errors() > 0, "errors are counted, not raised");
    }
}

#[test]
fn a_full_disk_is_swallowed_and_logging_resumes() {
    let dir = tempfile::tempdir().unwrap();
    let fail = Arc::new(AtomicBool::new(true));
    let sink = Sink::spawn(dir.path().to_path_buf(), MAX_FILE_BYTES, Some(fail.clone())).unwrap();
    sink.submit(ev("s1", Outcome::Held, T0));
    sink.flush();
    assert_eq!(sink.write_errors(), 1);
    assert!(read_lines(dir.path(), FILE_NAME).is_empty());
    fail.store(false, Ordering::Relaxed);
    sink.submit(ev("s1", Outcome::Held, T0));
    sink.flush();
    assert_eq!(read_lines(dir.path(), FILE_NAME).len(), 1);
}

#[test]
fn a_full_queue_drops_with_a_counter_and_does_not_block() {
    let (tx, _rx) = sync_channel::<Msg>(1);
    let sink = Sink { tx, dropped: AtomicU64::new(0), errors: Arc::new(AtomicU64::new(0)) };
    for _ in 0..5 {
        sink.submit(ev("s1", Outcome::Held, T0));
    }
    assert_eq!(sink.dropped(), 4);
}

const CHILD_ENV: &str = "FUIGO_TEST_PEER_AUDIT_CHILD_DIR";

/// Helper process body (re-executed by the test below): append 100 lines through a core with a small cap.
#[test]
fn peer_audit_child_writer() {
    let Some(dir) = std::env::var_os(CHILD_ENV) else {
        return;
    };
    let dir = PathBuf::from(dir);
    while !dir.join("go").exists() {
        std::thread::sleep(Duration::from_millis(1));
    }
    let mut c = core(&dir, 64 * 1024);
    let pid = std::process::id();
    for i in 0..100 {
        let mut e = test_envelope(&format!("p{pid}-{i}"), "n", "b");
        e.from = Address::new("0123456789abcdef0123456789abcdef", "child", 1).unwrap();
        c.record(Event::from_envelope(&e, Some("recv"), Outcome::Held, Some(&HoldReason::ModeMismatch), 6_000));
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn two_processes_append_and_rotate_without_losing_a_line() {
    let dir = tempfile::tempdir().unwrap();
    let exe = std::env::current_exe().unwrap();
    let run = || {
        let (exe, home) = (exe.clone(), dir.path().to_path_buf());
        std::thread::spawn(move || {
            std::process::Command::new(&exe)
                .args(["--exact", "session::peer_audit::tests::peer_audit_child_writer", "--test-threads=1"])
                .env(CHILD_ENV, &home)
                .env("HOME", &home)
                .stdout(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
        })
    };
    let (a, b) = (run(), run());
    std::fs::write(dir.path().join("go"), b"").unwrap();
    assert!(a.join().unwrap() && b.join().unwrap());
    let cur = read_lines(dir.path(), FILE_NAME);
    let old = read_lines(dir.path(), ROTATED_NAME);
    assert!(!old.is_empty(), "the cap forced a rotation");
    let mut ids: Vec<String> = cur
        .iter()
        .chain(old.iter())
        .map(|l| serde_json::from_str::<serde_json::Value>(l).expect("no torn line")["msg"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids.len(), 200, "no line lost: a second rotation would have dropped the first rotated file");
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 200, "no line written twice");
}

// ---- Merge of packet 5 parts A and B: every part-A outcome is audited ----

fn audited(s: PeerAdmissionState, dir: &Path) -> PeerAdmissionState {
    s.configure(PeerAdmissionConfig {
        opted_in: true,
        policy: PeerInboundPolicy::Accept,
        operator: OperatorPresence::Present,
        relay_driven: false,
    });
    s.set_audit_receiver("recv-session");
    s.with_audit(|a| a.set_dir_for_test(dir.to_path_buf()));
    s
}

fn parsed(dir: &Path) -> Vec<serde_json::Value> {
    read_lines(dir, FILE_NAME).iter().map(|l| serde_json::from_str(l).unwrap()).collect()
}

fn assert_exact_keys(lines: &[serde_json::Value]) {
    let mut want = KEYS.to_vec();
    want.sort_unstable();
    for v in lines {
        let mut keys: Vec<&str> = v.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, want, "line has exactly the documented keys: {v}");
    }
}

fn pair(v: &serde_json::Value) -> (String, Option<String>) {
    (v["outcome"].as_str().unwrap().to_owned(), v["reason"].as_str().map(str::to_owned))
}

fn from_sender(n: usize, id: &str, body: &str) -> fuigo_peer::Envelope {
    let mut e = test_envelope(id, "lane CANARY-7f3a91d2c4", body);
    e.from = Address::new("0123456789abcdef0123456789abcdef", &format!("sender-{n}"), 1).unwrap();
    e
}

/// too_large, rate_limited, the replay-memory answer and the loop-guard hold each leave their line; same key set, no body or name.
#[test]
fn part_a_outcomes_are_audited_with_the_documented_keys_only() {
    let _on = force_peer_messaging_for_test(true);
    let dir = tempfile::tempdir().unwrap();
    let cfg = fuigo_peer::IngressConfig { pair_per_minute: 3, host_per_minute: usize::MAX, ..Default::default() };
    let s = audited(PeerAdmissionState::metered(cfg), dir.path());
    let ae = live(PeerBase::AcceptEdits);
    let body = "please run CANARY-7f3a91d2c4 now";

    assert!(matches!(s.submit(from_sender(1, "m1", body), T0, &ae), Submitted::Enqueue));
    // too_large
    let big = "x".repeat(fuigo_peer::limits::MAX_BODY_BYTES + 1);
    let _ = s.submit(from_sender(1, "m2", &big), T0, &ae);
    // the replay-memory answer: held (mode mismatch), rejected by the operator, then the same id again
    let mut held = from_sender(1, "m3", body);
    held.from_mode = mode(PeerBase::Default);
    let _ = s.submit(held.clone(), T0, &ae);
    let tok = s.list_held(T0).into_iter().find(|h| h.message_id == "m3").unwrap().token;
    s.reject("m3", &tok, T0).unwrap();
    let _ = s.submit(held, T0, &ae);
    // rate_limited (pair): the 3 charged are m1, m3 and m4
    assert!(matches!(s.submit(from_sender(1, "m4", body), T0, &ae), Submitted::Enqueue));
    let _ = s.submit(from_sender(1, "m5", body), T0, &ae);
    // loop_guard hold (hop budget used up)
    let mut hop = from_sender(2, "m6", body);
    hop.hop = fuigo_peer::limits::HOP_BUDGET;
    let _ = s.submit(hop, T0, &ae);
    flush(&s);

    let lines = parsed(dir.path());
    assert_exact_keys(&lines);
    let got: std::collections::BTreeSet<_> = lines.iter().map(pair).collect();
    for want in [
        ("refused", Some("too_large")),
        ("refused", Some("rate_limited")),
        ("duplicate", None),
        ("held", Some("loop_guard")),
    ] {
        assert!(got.contains(&(want.0.to_owned(), want.1.map(str::to_owned))), "missing {want:?}; saw {got:?}");
    }
    for f in all_files(dir.path()) {
        let bytes = std::fs::read(&f).unwrap();
        for n in ["CANARY-7f3a91d2c4", "please run", "lane CANARY"] {
            assert!(!bytes.windows(n.len()).any(|w| w == n.as_bytes()), "{n} found in {}", f.display());
        }
    }
}

/// The host-total refusal is a `saturated` line, on the session that was refused.
#[test]
fn host_total_saturation_is_audited() {
    use fuigo_peer::limits::{MAX_MESSAGES_PER_HOST, MAX_MESSAGES_PER_SESSION};
    let _on = force_peer_messaging_for_test(true);
    let dir = tempfile::tempdir().unwrap();
    let cfg = fuigo_peer::IngressConfig { pair_per_minute: usize::MAX, host_per_minute: usize::MAX, ..Default::default() };
    let host = Arc::new(Mutex::new(fuigo_peer::PeerIngress::new(cfg, Arc::new(fuigo_peer::HostLedger::default()))));
    let ae = live(PeerBase::AcceptEdits);
    let mismatch = |n: usize, id: &str| {
        let mut e = from_sender(n, id, "b");
        e.from_mode = mode(PeerBase::Default);
        e
    };
    let sessions: Vec<_> = (0..4).map(|_| PeerAdmissionState::with_host(host.clone())).collect();
    for (si, s) in sessions.iter().enumerate() {
        s.configure(PeerAdmissionConfig {
            opted_in: true,
            policy: PeerInboundPolicy::Accept,
            operator: OperatorPresence::Present,
            relay_driven: false,
        });
        for n in 0..MAX_MESSAGES_PER_SESSION {
            let _ = s.submit(mismatch(si, &format!("m{n}")), T0, &ae);
        }
    }
    assert_eq!(sessions[0].host_usage().0, MAX_MESSAGES_PER_HOST);
    let fifth = audited(PeerAdmissionState::with_host(host), dir.path());
    let _ = fifth.submit(mismatch(9, "over"), T0, &ae);
    flush(&fifth);
    let lines = parsed(dir.path());
    assert_exact_keys(&lines);
    assert!(lines.iter().any(|v| pair(v) == ("saturated".to_owned(), Some("saturated".to_owned()))), "{lines:?}");
}

/// 100,000 envelopes refused as rate-limited: part A's tables stay bounded and the audit file stays small (aggregated lines).
#[test]
fn flood_100k_rate_limited_bounds_tables_and_audit_file() {
    use fuigo_peer::limits::*;
    let _on = force_peer_messaging_for_test(true);
    let dir = tempfile::tempdir().unwrap();
    let s = audited(PeerAdmissionState::metered(fuigo_peer::IngressConfig::default()), dir.path());
    let ae = live(PeerBase::AcceptEdits);
    let mut max = s.ingress_sizes();
    let mut limited = 0usize;
    for n in 0..100_000usize {
        // 3000 distinct senders over ~100 s: the pair and host windows refuse nearly everything.
        let out = s.submit(from_sender(n % 3000, &format!("m{n}"), "b"), T0 + (n / 1000) as u64, &ae);
        if matches!(out, Submitted::Done(fuigo_peer::DeliveryOutcome::Rejected { reason: RejectReason::RateLimited })) {
            limited += 1;
        }
        let z = s.ingress_sizes();
        max.pairs = max.pairs.max(z.pairs);
        max.host_log = max.host_log.max(z.host_log);
        max.replay = max.replay.max(z.replay);
        max.replay_order = max.replay_order.max(z.replay_order);
    }
    flush(&s);
    assert!(limited > 90_000, "{limited}");
    assert!(max.pairs <= RATE_TABLE_ENTRIES && max.host_log <= RATE_PER_HOST_PER_MINUTE as usize);
    assert!(max.replay <= REMEMBERED_MESSAGE_IDS && max.replay_order <= 4 * REMEMBERED_MESSAGE_IDS);
    let size: u64 = all_files(dir.path()).iter().map(|f| std::fs::metadata(f).unwrap().len()).sum();
    let lines: usize = all_files(dir.path()).iter().map(|f| std::fs::read_to_string(f).unwrap().lines().count()).sum();
    assert!(lines < 5_000, "aggregated, not one line per envelope: {lines} lines");
    assert!(size < 2 * 1024 * 1024, "{size} bytes");
}

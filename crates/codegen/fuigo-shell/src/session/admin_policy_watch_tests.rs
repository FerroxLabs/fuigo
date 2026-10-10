//! P186c condition 1: the session's turn-start check, driven over real admin files (the same loader entries a tool call uses).
//! Unverified: a live TUI/ACP session; these tests call the same `AdminPolicyWatch` the turn start calls.
use super::AdminPolicyWatch;
use std::path::Path;

const LAX: &str = "[ui]\nyolo = true\n";
const BROKEN: &str = "[ui]\nyolo = \"yes\"\n[sandbox]\nprofile = \"strict\"\n";
const FIXED: &str = "[sandbox]\nprofile = \"strict\"\n";

fn turn(w: &mut AdminPolicyWatch, dir: &Path) -> Vec<String> {
    // P186f: the process uid stands in for root only while the admin-root override is set
    let _root = fuigo_config::admin_root_override::set(dir.to_path_buf());
    w.notices(&fuigo_config::admin_policy_states_at(Some(dir), None))
}

/// Like `turn`, for the Claude `managed-settings.json` (no TOML files in the directory).
fn turn_claude(w: &mut AdminPolicyWatch, dir: &Path, claude: &Path) -> Vec<String> {
    let _root = fuigo_config::admin_root_override::set(dir.to_path_buf());
    w.notices(&fuigo_config::admin_policy_states_at(None, Some(claude)))
}

/// What enforcement does with the Claude file now (a tool call loads it through this entry; it also keeps or forgets the copy).
fn claude_enforced(dir: &Path, claude: &Path) -> fuigo_config::ManagedSettingsJson {
    let _root = fuigo_config::admin_root_override::set(dir.to_path_buf());
    fuigo_config::managed_settings_json(claude)
}

const CLAUDE_OK: &str = r#"{"permissions":{"deny":["Bash(rm:*)"]}}"#;
const CLAUDE_WRONG: &str = r#"{"permissions":{"deny":"Bash(rm:*)"}}"#;

#[test]
fn a_session_is_told_once_per_broken_version_and_when_it_lifts_p186c() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("requirements.toml");
    std::fs::write(&f, LAX).unwrap();
    let mut w = AdminPolicyWatch::default();
    assert!(turn(&mut w, dir.path()).is_empty(), "valid copy: nothing to say");
    // (i) the new version is broken: exactly one notice naming file and key
    std::fs::write(&f, BROKEN).unwrap();
    let n = turn(&mut w, dir.path());
    assert_eq!(n.len(), 1, "{n:?}");
    assert!(n[0].contains(&f.display().to_string()) && n[0].contains("ui.yolo"), "{n:?}");
    assert!(n[0].contains("All tools are denied until an administrator fixes this file."), "{n:?}");
    // (ii) two more turns on the same version: nothing
    assert!(turn(&mut w, dir.path()).is_empty());
    assert!(turn(&mut w, dir.path()).is_empty());
    // (iii) valid again: one lifted notice, then silence
    std::fs::write(&f, FIXED).unwrap();
    let n = turn(&mut w, dir.path());
    assert_eq!(n, vec![format!("Admin policy file {} is valid again. The lock-down is lifted.", f.display())]);
    assert!(turn(&mut w, dir.path()).is_empty());
    // (iv) broken again: told again
    std::fs::write(&f, BROKEN).unwrap();
    assert_eq!(turn(&mut w, dir.path()).len(), 1);
}

#[test]
fn two_sessions_in_one_process_are_each_told_once_p186c() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("managed_config.toml");
    std::fs::write(&f, LAX).unwrap();
    let (mut a, mut b) = (AdminPolicyWatch::default(), AdminPolicyWatch::default());
    assert!(turn(&mut a, dir.path()).is_empty() && turn(&mut b, dir.path()).is_empty());
    std::fs::write(&f, BROKEN).unwrap();
    assert_eq!(turn(&mut a, dir.path()).len(), 1);
    // session a's check did not consume anything for session b
    assert_eq!(turn(&mut b, dir.path()).len(), 1);
    assert!(turn(&mut a, dir.path()).is_empty() && turn(&mut b, dir.path()).is_empty());
}

#[test]
fn a_key_with_a_newline_and_escape_gives_a_one_line_notice_p186c() {
    let l = fuigo_config::AdminLockdown {
        path: "/etc/fuigo/req\nuirements.toml".into(),
        detail: "policy keys of the wrong type: ui.\n\u{1b}[31myolo".into(),
        version: 1,
    };
    let n = l.entered_notice();
    assert!(!n.contains('\n') && !n.contains('\u{1b}') && !n.contains('\r'), "{n:?}");
    assert!(n.contains("yolo"), "{n:?}");
    let lifted = fuigo_config::admin_lockdown_lifted_notice(&l.path);
    assert!(!lifted.contains('\n') && !lifted.contains('\u{1b}'), "{lifted:?}");
}

const STILL_NOT_VALID: &str = "changed and is still not valid. The lock-down has ended and the last valid policy is in force again.";

#[test]
fn a_wrong_typed_version_replaced_by_an_unparseable_one_is_not_called_valid_p186f() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("requirements.toml");
    std::fs::write(&f, LAX).unwrap();
    let mut w = AdminPolicyWatch::default();
    assert!(turn(&mut w, dir.path()).is_empty());
    std::fs::write(&f, BROKEN).unwrap();
    assert_eq!(turn(&mut w, dir.path()).len(), 1, "one entering notice");
    // wrong-typed -> unparseable: enforcement is back on the last valid copy, but the file is NOT valid
    std::fs::write(&f, "[ui\nyolo = ").unwrap();
    let n = turn(&mut w, dir.path());
    assert_eq!(n, vec![format!("Admin policy file {} {STILL_NOT_VALID}", f.display())]);
    assert!(!n[0].contains("is valid again"), "{n:?}");
    assert!(turn(&mut w, dir.path()).is_empty(), "same unparseable version: silent");
    // P186f round 2: the user was told "still not valid"; when it becomes valid they are told so once
    std::fs::write(&f, FIXED).unwrap();
    assert_eq!(turn(&mut w, dir.path()), vec![format!("Admin policy file {} is valid again and is in force.", f.display())]);
    assert!(turn(&mut w, dir.path()).is_empty(), "a second valid read says nothing more");
}

#[test]
fn a_wrong_typed_version_replaced_by_a_missing_file_is_not_called_valid_p186f() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("requirements.toml");
    std::fs::write(&f, LAX).unwrap();
    let mut w = AdminPolicyWatch::default();
    assert!(turn(&mut w, dir.path()).is_empty());
    std::fs::write(&f, BROKEN).unwrap();
    assert_eq!(turn(&mut w, dir.path()).len(), 1);
    std::fs::remove_file(&f).unwrap();
    let n = turn(&mut w, dir.path());
    assert_eq!(n, vec![format!("Admin policy file {} {STILL_NOT_VALID}", f.display())]);
    // P186f round 2: the file comes back valid: told once, then silent
    std::fs::write(&f, FIXED).unwrap();
    assert_eq!(turn(&mut w, dir.path()), vec![format!("Admin policy file {} is valid again and is in force.", f.display())]);
    assert!(turn(&mut w, dir.path()).is_empty());
}

const NOW_EMPTY: &str = "is now empty. The lock-down has ended and this file sets no policy.";

#[test]
fn claude_file_wrong_typed_then_stable_blank_says_now_empty_p186f() {
    let dir = tempfile::tempdir().unwrap();
    let c = dir.path().join("managed-settings.json");
    std::fs::write(&c, CLAUDE_OK).unwrap();
    assert!(matches!(claude_enforced(dir.path(), &c), fuigo_config::ManagedSettingsJson::Loaded(_)));
    let mut w = AdminPolicyWatch::default();
    assert!(turn_claude(&mut w, dir.path(), &c).is_empty());
    std::fs::write(&c, CLAUDE_WRONG).unwrap();
    assert_eq!(turn_claude(&mut w, dir.path(), &c).len(), 1, "one entering notice");
    std::fs::write(&c, "   \n").unwrap();
    let n = turn_claude(&mut w, dir.path(), &c);
    assert_eq!(n, vec![format!("Admin policy file {} {NOW_EMPTY}", c.display())]);
    assert!(!n[0].contains("last valid policy"), "{n:?}");
    // enforcement agrees: the kept copy is forgotten, the policy is absent
    assert!(matches!(claude_enforced(dir.path(), &c), fuigo_config::ManagedSettingsJson::Absent));
    assert!(turn_claude(&mut w, dir.path(), &c).is_empty());
}

#[test]
fn toml_file_wrong_typed_then_stable_blank_says_now_empty_p186f() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("requirements.toml");
    std::fs::write(&f, LAX).unwrap();
    let mut w = AdminPolicyWatch::default();
    assert!(turn(&mut w, dir.path()).is_empty());
    std::fs::write(&f, BROKEN).unwrap();
    assert_eq!(turn(&mut w, dir.path()).len(), 1);
    std::fs::write(&f, "\n\n").unwrap();
    assert_eq!(turn(&mut w, dir.path()), vec![format!("Admin policy file {} {NOW_EMPTY}", f.display())]);
    assert!(turn(&mut w, dir.path()).is_empty());
}

#[test]
fn claude_file_wrong_typed_then_unparseable_says_still_not_valid_p186f() {
    let dir = tempfile::tempdir().unwrap();
    let c = dir.path().join("managed-settings.json");
    std::fs::write(&c, CLAUDE_OK).unwrap();
    assert!(matches!(claude_enforced(dir.path(), &c), fuigo_config::ManagedSettingsJson::Loaded(_)));
    let mut w = AdminPolicyWatch::default();
    assert!(turn_claude(&mut w, dir.path(), &c).is_empty());
    std::fs::write(&c, CLAUDE_WRONG).unwrap();
    assert_eq!(turn_claude(&mut w, dir.path(), &c).len(), 1);
    std::fs::write(&c, "{not json").unwrap();
    assert_eq!(turn_claude(&mut w, dir.path(), &c), vec![format!("Admin policy file {} {STILL_NOT_VALID}", c.display())]);
    assert!(turn_claude(&mut w, dir.path(), &c).is_empty());
    // round 2: valid again after "still not valid": told once
    std::fs::write(&c, CLAUDE_OK).unwrap();
    assert_eq!(turn_claude(&mut w, dir.path(), &c), vec![format!("Admin policy file {} is valid again and is in force.", c.display())]);
    assert!(turn_claude(&mut w, dir.path(), &c).is_empty());
}

#[test]
fn a_stable_blank_after_still_not_valid_says_now_empty_once_p186f() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("requirements.toml");
    std::fs::write(&f, LAX).unwrap();
    let mut w = AdminPolicyWatch::default();
    assert!(turn(&mut w, dir.path()).is_empty());
    std::fs::write(&f, BROKEN).unwrap();
    assert_eq!(turn(&mut w, dir.path()).len(), 1);
    std::fs::write(&f, "[ui\nyolo = ").unwrap();
    assert_eq!(turn(&mut w, dir.path()), vec![format!("Admin policy file {} {STILL_NOT_VALID}", f.display())]);
    std::fs::write(&f, "").unwrap();
    assert_eq!(turn(&mut w, dir.path()), vec![format!("Admin policy file {} {NOW_EMPTY}", f.display())]);
    assert!(turn(&mut w, dir.path()).is_empty());
}

#[test]
fn a_file_told_now_empty_that_turns_valid_says_valid_again_once_followups2() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("requirements.toml");
    std::fs::write(&f, LAX).unwrap();
    let mut w = AdminPolicyWatch::default();
    assert!(turn(&mut w, dir.path()).is_empty());
    std::fs::write(&f, BROKEN).unwrap();
    assert_eq!(turn(&mut w, dir.path()).len(), 1);
    std::fs::write(&f, "").unwrap();
    assert_eq!(turn(&mut w, dir.path()), vec![format!("Admin policy file {} {NOW_EMPTY}", f.display())]);
    assert!(turn(&mut w, dir.path()).is_empty(), "a second blank read stays silent");
    std::fs::write(&f, FIXED).unwrap();
    assert_eq!(turn(&mut w, dir.path()), vec![format!("Admin policy file {} is valid again and is in force.", f.display())]);
    assert!(turn(&mut w, dir.path()).is_empty(), "said once");
}

#[test]
fn a_file_told_now_empty_that_goes_wrong_typed_never_says_valid_again_followups2() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("requirements.toml");
    std::fs::write(&f, LAX).unwrap();
    let mut w = AdminPolicyWatch::default();
    assert!(turn(&mut w, dir.path()).is_empty());
    std::fs::write(&f, BROKEN).unwrap();
    assert_eq!(turn(&mut w, dir.path()).len(), 1);
    std::fs::write(&f, "").unwrap();
    assert_eq!(turn(&mut w, dir.path()).len(), 1);
    std::fs::write(&f, "[ui]\nyolo = \"no\"\n").unwrap();
    let n = turn(&mut w, dir.path());
    // round 2: the copy is gone (the file stayed empty), so enforcement IS the full lock-down and the session says so
    assert!(enforced_broken(dir.path(), &f), "enforcement is the no-copy lock-down");
    assert_eq!(n.len(), 1, "{n:?}");
    assert!(n[0].contains(&f.display().to_string()) && n[0].contains("ui.yolo") && n[0].contains(DENIED), "{n:?}");
    assert!(!n[0].contains("valid again") && !n[0].contains("last valid policy"), "{n:?}");
    assert!(turn(&mut w, dir.path()).is_empty(), "same broken version: silent");
}

const DENIED: &str = "All tools are denied until an administrator fixes this file.";

/// Whether the loaders treat `f` as broken with no validated copy (the lock-down), read through the public loader entry.
fn enforced_broken(dir: &Path, f: &Path) -> bool {
    let _root = fuigo_config::admin_root_override::set(dir.to_path_buf());
    fuigo_config::broken_admin_files().iter().any(|b| b.path == f)
}

#[test]
fn a_file_that_stays_empty_then_breaks_with_no_copy_says_all_tools_denied_once_round2() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("requirements.toml");
    std::fs::write(&f, LAX).unwrap();
    let mut w = AdminPolicyWatch::default();
    assert!(turn(&mut w, dir.path()).is_empty());
    std::fs::write(&f, BROKEN).unwrap();
    assert_eq!(turn(&mut w, dir.path()).len(), 1, "typed-pin enter");
    std::fs::write(&f, "").unwrap();
    assert_eq!(turn(&mut w, dir.path()), vec![format!("Admin policy file {} {NOW_EMPTY}", f.display())]);
    // (a) now unparseable, and no copy is held
    std::fs::write(&f, "[ui\nyolo = ").unwrap();
    let n = turn(&mut w, dir.path());
    assert!(enforced_broken(dir.path(), &f), "enforcement is the no-copy lock-down, so the notice is true");
    assert_eq!(n.len(), 1, "{n:?}");
    assert!(n[0].contains(&f.display().to_string()) && n[0].contains("could not be loaded") && n[0].contains(DENIED), "{n:?}");
    assert!(!n[0].contains("last valid policy") && !n[0].contains("valid again"), "{n:?}");
    assert!(!n[0].contains('\n'), "one line: {n:?}");
    assert!(turn(&mut w, dir.path()).is_empty(), "same broken text: silent");
    assert!(turn(&mut w, dir.path()).is_empty());
    // a different broken version is announced again
    std::fs::write(&f, "[ui\nyolo2 = ").unwrap();
    assert_eq!(turn(&mut w, dir.path()).len(), 1);
    // (b) valid: lifted, once
    std::fs::write(&f, FIXED).unwrap();
    assert_eq!(turn(&mut w, dir.path()), vec![format!("Admin policy file {} is valid again. The lock-down is lifted.", f.display())]);
    assert!(turn(&mut w, dir.path()).is_empty());
}

#[test]
fn a_no_copy_lockdown_that_becomes_blank_says_now_empty_once_round2() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("requirements.toml");
    std::fs::write(&f, LAX).unwrap();
    let mut w = AdminPolicyWatch::default();
    assert!(turn(&mut w, dir.path()).is_empty());
    std::fs::write(&f, BROKEN).unwrap();
    turn(&mut w, dir.path());
    std::fs::write(&f, "").unwrap();
    turn(&mut w, dir.path());
    std::fs::write(&f, "[ui\nyolo = ").unwrap();
    assert_eq!(turn(&mut w, dir.path()).len(), 1);
    std::fs::write(&f, "").unwrap();
    assert_eq!(turn(&mut w, dir.path()), vec![format!("Admin policy file {} {NOW_EMPTY}", f.display())]);
    assert!(turn(&mut w, dir.path()).is_empty());
}

#[test]
fn a_file_broken_while_the_copy_is_held_says_no_deny_notice_round2() {
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("requirements.toml");
    std::fs::write(&f, LAX).unwrap();
    let mut w = AdminPolicyWatch::default();
    assert!(turn(&mut w, dir.path()).is_empty());
    std::fs::write(&f, "[ui\nyolo = ").unwrap();
    // (d) the copy is in force: nothing to announce
    assert!(turn(&mut w, dir.path()).is_empty());
    assert!(!enforced_broken(dir.path(), &f), "enforcement is the kept copy");
    assert!(turn(&mut w, dir.path()).is_empty());
}

#[test]
fn claude_file_that_stays_empty_then_breaks_with_no_copy_says_all_tools_denied_once_round2() {
    let dir = tempfile::tempdir().unwrap();
    let c = dir.path().join("managed-settings.json");
    std::fs::write(&c, CLAUDE_OK).unwrap();
    assert!(matches!(claude_enforced(dir.path(), &c), fuigo_config::ManagedSettingsJson::Loaded(_)));
    let mut w = AdminPolicyWatch::default();
    assert!(turn_claude(&mut w, dir.path(), &c).is_empty());
    std::fs::write(&c, CLAUDE_WRONG).unwrap();
    assert_eq!(turn_claude(&mut w, dir.path(), &c).len(), 1);
    std::fs::write(&c, "").unwrap();
    assert_eq!(turn_claude(&mut w, dir.path(), &c), vec![format!("Admin policy file {} {NOW_EMPTY}", c.display())]);
    // a tool call loads the file: the stable blank forgets the copy
    assert!(matches!(claude_enforced(dir.path(), &c), fuigo_config::ManagedSettingsJson::Absent));
    std::fs::write(&c, "{not json").unwrap();
    let n = turn_claude(&mut w, dir.path(), &c);
    assert!(matches!(claude_enforced(dir.path(), &c), fuigo_config::ManagedSettingsJson::Broken(_)), "lock-down");
    assert_eq!(n.len(), 1, "{n:?}");
    assert!(n[0].contains(&c.display().to_string()) && n[0].contains(DENIED), "{n:?}");
    assert!(!n[0].contains("last valid policy"), "{n:?}");
    assert!(turn_claude(&mut w, dir.path(), &c).is_empty());
    std::fs::write(&c, CLAUDE_OK).unwrap();
    assert_eq!(turn_claude(&mut w, dir.path(), &c), vec![format!("Admin policy file {} is valid again. The lock-down is lifted.", c.display())]);
}

#[test]
fn claude_file_broken_while_the_copy_is_held_says_no_deny_notice_round2() {
    let dir = tempfile::tempdir().unwrap();
    let c = dir.path().join("managed-settings.json");
    std::fs::write(&c, CLAUDE_OK).unwrap();
    assert!(matches!(claude_enforced(dir.path(), &c), fuigo_config::ManagedSettingsJson::Loaded(_)));
    let mut w = AdminPolicyWatch::default();
    assert!(turn_claude(&mut w, dir.path(), &c).is_empty());
    std::fs::write(&c, "{not json").unwrap();
    assert!(turn_claude(&mut w, dir.path(), &c).is_empty());
    assert!(matches!(claude_enforced(dir.path(), &c), fuigo_config::ManagedSettingsJson::Loaded(_)), "the copy");
}

// ---- P186f item 2: the turn-start read is bounded ----

mod bounded {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, mpsc};
    use std::time::{Duration, Instant};

    const BUDGET: Duration = Duration::from_millis(150);

    fn locked(path: &str) -> Vec<fuigo_config::AdminFileState> {
        let path = std::path::PathBuf::from(path);
        vec![fuigo_config::AdminFileState {
            path: path.clone(),
            class: fuigo_config::AdminFileClass::Locked(fuigo_config::AdminLockdown {
                path,
                detail: "policy keys of the wrong type: ui.yolo".into(),
                version: 7,
            }),
        }]
    }

    /// A reader whose FIRST run blocks until released (3 s safety stop), counting every run it starts.
    fn blocking_watch() -> (AdminPolicyWatch, Arc<AtomicUsize>, mpsc::Sender<()>) {
        let runs = Arc::new(AtomicUsize::new(0));
        let (tx, rx) = mpsc::channel::<()>();
        let rx = Arc::new(std::sync::Mutex::new(rx));
        let r = runs.clone();
        let w = AdminPolicyWatch::with_reader(Arc::new(move || {
            let (r, rx) = (r.clone(), rx.clone());
            Box::new(move || {
                if r.fetch_add(1, Ordering::SeqCst) == 0 {
                    let _ = rx.lock().unwrap().recv_timeout(Duration::from_secs(3));
                }
                locked("/etc/fuigo/requirements.toml")
            })
        }));
        (w, runs, tx)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_stuck_read_costs_one_budget_then_nothing_and_starts_no_second_reader_p186f() {
        let (w, runs, release) = blocking_watch();
        let t = Instant::now();
        assert!(w.check(BUDGET).await.is_empty(), "no notice while the read has not returned");
        let took = t.elapsed();
        assert!(took >= BUDGET && took < Duration::from_millis(1500), "bounded by the budget: {took:?}");
        assert_eq!(runs.load(Ordering::SeqCst), 1);
        // a second turn while the first read is still stuck: at once, and no second reader
        let t = Instant::now();
        assert!(w.check(BUDGET).await.is_empty());
        assert!(t.elapsed() < Duration::from_millis(100), "{:?}", t.elapsed());
        assert_eq!(runs.load(Ordering::SeqCst), 1, "at most one outstanding read");
        // released: the next turns report normally, once
        release.send(()).unwrap();
        let mut got = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        while got.is_empty() && Instant::now() < deadline {
            got = w.check(BUDGET).await;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(got.len(), 1, "{got:?}");
        assert!(got[0].contains("/etc/fuigo/requirements.toml") && got[0].contains("ui.yolo"), "{got:?}");
        assert!(w.check(BUDGET).await.is_empty(), "told once");
    }
}

// Unix only: the test is about file owner uids.
#[cfg(unix)]
#[test]
fn a_user_owned_file_is_admin_policy_only_while_the_admin_root_override_is_set_p186f() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("requirements.toml"), LAX).unwrap();
    {
        use std::os::unix::fs::MetadataExt;
        if std::fs::metadata(dir.path().join("requirements.toml")).unwrap().uid() == 0 {
            // run as root, the process uid IS the real admin uid: the two cases cannot differ. Needs a non-root run.
            return;
        }
    }
    let class = || {
        fuigo_config::admin_policy_states_at(Some(dir.path()), None)
            .into_iter()
            .find(|s| s.path.ends_with("requirements.toml"))
            .map(|s| s.class)
    };
    // the feature alone (a `--all-features` binary): a file owned by this user is not root's policy
    // (round 2: with no copy held that is the broken-no-copy class, what the loaders enforce as a lock-down; was `Other`)
    assert!(matches!(class(), Some(fuigo_config::AdminFileClass::BrokenNoCopy(_))));
    // a test that set the override: the process uid stands in for root
    let _root = fuigo_config::admin_root_override::set(dir.path().to_path_buf());
    assert!(matches!(class(), Some(fuigo_config::AdminFileClass::Valid)));
}

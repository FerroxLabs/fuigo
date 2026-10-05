use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::{Mutex, mpsc};
use std::time::{Duration, Instant};

use super::transaction::{TransactionObserver, TransactionPhase};
use super::*;

fn request(path: &Path, items: &[(&str, &str)]) -> ManagedConfigRequest {
    ManagedConfigRequest {
        path: path.to_path_buf(),
        namespace: "fuigo doctor".to_owned(),
        owned_item_prefix: "terminal.".to_owned(),
        items: items
            .iter()
            .map(|(name, body)| {
                let name = if name.starts_with("terminal.") {
                    (*name).to_owned()
                } else {
                    format!("terminal.{name}")
                };
                ManagedItem::new(name, *body)
            })
            .collect(),
        comments: CommentSyntax::hash(),
        validator: None,
    }
}

fn expected(body: &str, newline: &str) -> String {
    [
        "# >>> fuigo doctor >>>",
        "# >>> terminal.ssh-wrap >>>",
        body,
        "# <<< terminal.ssh-wrap <<<",
        "# <<< fuigo doctor <<<",
    ]
    .join(newline)
}

fn artifacts(directory: &Path) -> HashSet<String> {
    fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.contains(".fuigo-"))
        .collect()
}

#[test]
fn missing_empty_normal_no_final_newline_and_crlf_are_preserved() {
    let temp = tempfile::tempdir().unwrap();
    let missing = temp.path().join("missing.rc");
    let plan = ManagedConfig::plan(request(
        &missing,
        &[("terminal.ssh-wrap", "alias ssh='fuigo wrap ssh'")],
    ))
    .unwrap();
    assert_eq!(
        plan.updated_bytes(),
        expected("alias ssh='fuigo wrap ssh'", "\n").as_bytes()
    );
    assert!(plan.backup_path_hint().is_none());
    ManagedConfig::apply(plan).unwrap();
    assert_eq!(
        fs::read_to_string(&missing).unwrap(),
        expected("alias ssh='fuigo wrap ssh'", "\n")
    );

    let empty = temp.path().join("empty.rc");
    fs::write(&empty, "").unwrap();
    let plan = ManagedConfig::plan(request(
        &empty,
        &[("terminal.ssh-wrap", "alias ssh='fuigo wrap ssh'")],
    ))
    .unwrap();
    assert!(plan.backup_path_hint().is_some());
    ManagedConfig::apply(plan).unwrap();

    let normal = temp.path().join("normal.rc");
    fs::write(&normal, "export KEEP=1\n").unwrap();
    let plan = ManagedConfig::plan(request(
        &normal,
        &[("terminal.ssh-wrap", "alias ssh='fuigo wrap ssh'")],
    ))
    .unwrap();
    assert_eq!(
        String::from_utf8(plan.updated_bytes().to_vec()).unwrap(),
        format!(
            "export KEEP=1\n{}\n",
            expected("alias ssh='fuigo wrap ssh'", "\n")
        )
    );

    let no_final = temp.path().join("no-final.rc");
    fs::write(&no_final, "export KEEP=1").unwrap();
    let plan = ManagedConfig::plan(request(&no_final, &[("item", "body")])).unwrap();
    assert!(
        !String::from_utf8(plan.updated_bytes().to_vec())
            .unwrap()
            .ends_with('\n')
    );

    let crlf = temp.path().join("crlf.rc");
    fs::write(&crlf, b"set -x KEEP 1\r\n").unwrap();
    let plan = ManagedConfig::plan(request(&crlf, &[("item", "body")])).unwrap();
    let rendered = String::from_utf8(plan.updated_bytes().to_vec()).unwrap();
    assert!(!rendered.replace("\r\n", "").contains('\n'));
}

#[test]
fn typed_inspection_and_item_updates_share_one_validated_parse() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.rc");
    fs::write(
        &path,
        "before\n# >>> fuigo doctor >>>\n# >>> terminal.old >>>\nold\n# <<< terminal.old <<<\n# <<< fuigo doctor <<<\nafter\n",
    )
    .unwrap();
    let plan = ManagedConfig::plan(request(&path, &[("new", "new body")])).unwrap();
    let original = fs::read_to_string(&path).unwrap();
    assert_eq!(plan.inspection().original_text(), Some(original.as_str()));
    assert_eq!(plan.inspection().unmanaged_text(), "before\nafter\n");
    let block = plan.managed_block().unwrap();
    assert!(block.contains("# >>> terminal.old >>>\nold\n# <<< terminal.old <<<"));
    assert!(block.contains("# >>> terminal.new >>>\nnew body\n# <<< terminal.new <<<"));
    ManagedConfig::apply(plan).unwrap();

    let plan = ManagedConfig::plan(request(&path, &[("old", "replaced")])).unwrap();
    let rendered = String::from_utf8(plan.updated_bytes().to_vec()).unwrap();
    assert!(rendered.contains("# >>> terminal.old >>>\nreplaced\n# <<< terminal.old <<<"));
    assert!(rendered.starts_with("before\n"));
    assert!(rendered.ends_with("after\n"));
}

#[test]
fn prose_and_exports_with_owned_words_and_chevrons_are_inert() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("inert");
    let content = [
        "# Terminal.app note: terminal. support >>> may vary <<< by host",
        "# fuigo doctor docs say >>> run this later <<<",
        "export NOTE='terminal.ssh-wrap >>> not a marker'",
        "printf '%s\\n' 'fuigo doctor <<< prose >>>'",
        "#terminal.future prose >>> lacks marker grammar",
        "echo '# >>> terminal.future >>> embedded text'",
    ]
    .join("\n");
    fs::write(&path, &content).unwrap();
    let plan = ManagedConfig::plan(request(&path, &[("terminal.current", "body")])).unwrap();
    assert!(String::from_utf8_lossy(plan.updated_bytes()).starts_with(&content));
}

#[test]
fn malformed_structural_owned_near_markers_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    for (index, content) in [
        "# >>> terminal.future >>\n",
        "# <<< terminal.future <<\n",
        "#   >>> terminal.future >> extra\n",
        "#\t<<< terminal.future <<< extra\n",
        "# >>> fuigo doctor >>\n",
    ]
    .iter()
    .enumerate()
    {
        let path = temp.path().join(format!("near-{index}"));
        fs::write(&path, content).unwrap();
        assert!(matches!(
            ManagedConfig::plan(request(&path, &[("terminal.current", "body")])),
            Err(ManagedConfigError::InvalidMarkers { .. })
        ));
    }
}

#[test]
fn owned_future_markers_are_rejected_independent_of_requested_items() {
    let temp = tempfile::tempdir().unwrap();
    for (index, content) in [
        "# >>> terminal.future >>>\nbody\n# <<< terminal.future <<<\n",
        "# >>> fuigo doctor >>>\n# >>> terminal.current >>>\nbody\n# <<< terminal.current <<<\n# <<< fuigo doctor <<<\n# >>> terminal.future >>>\nbody\n# <<< terminal.future <<<\n",
    ]
    .iter()
    .enumerate()
    {
        let path = temp.path().join(format!("future-{index}"));
        fs::write(&path, content).unwrap();
        assert!(matches!(
            ManagedConfig::plan(request(&path, &[("terminal.current", "body")])),
            Err(ManagedConfigError::InvalidMarkers { .. })
        ));
    }

    let unrelated = temp.path().join("unrelated");
    fs::write(
        &unrelated,
        "# >>> user custom >>>\nnot ours\n# <<< user custom <<<\n",
    )
    .unwrap();
    assert!(ManagedConfig::plan(request(&unrelated, &[("terminal.current", "body")])).is_ok());
}

#[test]
fn exact_noop_creates_no_transaction_artifacts_or_rewrite() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.rc");
    let content = expected("body", "\n");
    fs::write(&path, &content).unwrap();
    let before = fs::metadata(&path).unwrap().modified().unwrap();
    let outcome = ManagedConfig::apply(
        ManagedConfig::plan(request(&path, &[("terminal.ssh-wrap", "body")])).unwrap(),
    )
    .unwrap();
    assert_eq!(outcome.status, ManagedConfigStatus::NoChange);
    assert_eq!(fs::read_to_string(&path).unwrap(), content);
    assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), before);
    assert!(artifacts(temp.path()).is_empty());
}

#[test]
fn invalid_inputs_and_all_marker_shapes_are_refused() {
    let temp = tempfile::tempdir().unwrap();
    let oversize = temp.path().join("oversize");
    fs::write(
        &oversize,
        vec![b'x'; super::source::MAX_CONFIG_BYTES as usize + 1],
    )
    .unwrap();
    // Not named `nul`: on Windows that is the NUL device in every directory,
    // so no such file is ever created and the plan fails on the device instead.
    let nul = temp.path().join("nul-byte");
    fs::write(&nul, b"a\0b").unwrap();
    let non_utf8 = temp.path().join("non-utf8");
    fs::write(&non_utf8, [0xff]).unwrap();
    for path in [&oversize, &nul, &non_utf8] {
        let refused = ManagedConfig::plan(request(path, &[("item", "body")])).map(|_| ());
        assert!(
            matches!(refused, Err(ManagedConfigError::UnsafePath { .. })),
            "{}: {refused:?}",
            path.display()
        );
    }

    let cases = [
        "# >>> fuigo doctor >>>\n",
        "# <<< fuigo doctor <<<\n# >>> fuigo doctor >>>\n",
        "# >>> fuigo doctor >>\n",
        "# >>> fuigo doctor >>>\nraw\n# <<< fuigo doctor <<<\n",
        "# >>> fuigo doctor >>>\n# <<< terminal.item <<<\n# <<< fuigo doctor <<<\n",
        "# >>> fuigo doctor >>>\n# >>> terminal.item >>>\nbody\n# <<< terminal.other <<<\n# <<< fuigo doctor <<<\n",
        "# >>> fuigo doctor >>>\n# >>> terminal.item >>>\nbody\n# <<< terminal.item <<<\n# >>> terminal.item >>>\nbody\n# <<< terminal.item <<<\n# <<< fuigo doctor <<<\n",
        "# >>> terminal.item >>>\nbody\n# <<< terminal.item <<<\n",
    ];
    for (index, content) in cases.iter().enumerate() {
        let path = temp.path().join(format!("marker-{index}"));
        fs::write(&path, content).unwrap();
        assert!(matches!(
            ManagedConfig::plan(request(&path, &[("item", "new")])),
            Err(ManagedConfigError::InvalidMarkers { .. })
        ));
    }
}

#[cfg(unix)]
#[test]
fn symlink_resolution_depth_cycles_and_parent_symlinks_are_refused() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let physical = temp.path().join("physical");
    fs::write(&physical, "keep\n").unwrap();
    let relative = temp.path().join("relative");
    symlink("physical", &relative).unwrap();
    let plan = ManagedConfig::plan(request(&relative, &[("item", "body")])).unwrap();
    assert_eq!(
        plan.target_path(),
        fs::canonicalize(&physical).unwrap().as_path()
    );
    ManagedConfig::apply(plan).unwrap();
    assert!(
        fs::symlink_metadata(&relative)
            .unwrap()
            .file_type()
            .is_symlink()
    );

    let cycle_a = temp.path().join("cycle-a");
    let cycle_b = temp.path().join("cycle-b");
    symlink("cycle-b", &cycle_a).unwrap();
    symlink("cycle-a", &cycle_b).unwrap();
    assert!(ManagedConfig::plan(request(&cycle_a, &[("item", "body")])).is_err());

    let mut last = temp.path().join("depth-target");
    fs::write(&last, "body").unwrap();
    for index in 0..=super::source::MAX_SYMLINKS {
        let next = temp.path().join(format!("depth-{index}"));
        symlink(&last, &next).unwrap();
        last = next;
    }
    assert!(ManagedConfig::plan(request(&last, &[("item", "body")])).is_err());

    let real_parent = temp.path().join("real-parent");
    fs::create_dir(&real_parent).unwrap();
    let linked_parent = temp.path().join("linked-parent");
    symlink(&real_parent, &linked_parent).unwrap();
    let plan =
        ManagedConfig::plan(request(&linked_parent.join("rc"), &[("item", "body")])).unwrap();
    assert_eq!(
        plan.target_path().parent(),
        Some(fs::canonicalize(&real_parent).unwrap().as_path())
    );
}

#[cfg(unix)]
#[test]
fn bytes_mode_and_actual_backup_are_exact() {
    use std::os::unix::fs::PermissionsExt as _;

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.rc");
    let original = b"export KEEP=1\r\n";
    fs::write(&path, original).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    let plan = ManagedConfig::plan(request(&path, &[("item", "body")])).unwrap();
    let hint = plan.backup_path_hint().unwrap().to_path_buf();
    let outcome = ManagedConfig::apply(plan).unwrap();
    let backup = outcome.backup_path.unwrap();
    assert_eq!(backup, hint);
    assert_eq!(fs::read(&backup).unwrap(), original);
    assert_eq!(
        fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
        0o640
    );
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o640
    );
}

#[test]
fn stale_source_and_parent_swap_are_rejected_before_publication() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("parent/config.rc");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "before\n").unwrap();
    let plan = ManagedConfig::plan(request(&path, &[("item", "body")])).unwrap();
    fs::write(&path, "changed\n").unwrap();
    assert!(matches!(
        ManagedConfig::apply(plan),
        Err(ManagedConfigError::StalePlan(_))
    ));

    let plan = ManagedConfig::plan(request(&path, &[("item", "body")])).unwrap();
    let old_parent = temp.path().join("old-parent");
    fs::rename(path.parent().unwrap(), &old_parent).unwrap();
    fs::create_dir(path.parent().unwrap()).unwrap();
    assert!(matches!(
        ManagedConfig::apply(plan),
        Err(ManagedConfigError::ParentChanged(_))
    ));
    assert!(!path.exists());
}

#[cfg(unix)]
#[test]
fn missing_parent_revalidation_rejects_new_symlink_component() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(temp.path()).unwrap();
    let path = root.join("missing/child/config.rc");
    let parent_plan = super::source::ParentPlan::capture(path.parent().unwrap()).unwrap();
    let target = root.join("redirected");
    fs::create_dir(&target).unwrap();
    fs::create_dir(root.join("missing")).unwrap();
    symlink(&target, root.join("missing/child")).unwrap();

    assert!(matches!(
        parent_plan.ensure_and_anchor(),
        Err(ManagedConfigError::UnsafePath { .. })
    ));
}

#[test]
fn backup_and_temp_hint_collisions_retry_under_lock() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.rc");
    fs::write(&path, "original\n").unwrap();
    let plan = ManagedConfig::plan(request(&path, &[("item", "body")])).unwrap();
    let backup_hint = plan.backup_path_hint().unwrap().to_path_buf();
    let temp_hint = plan.temp_path_hint.as_ref().unwrap().clone();
    fs::write(&backup_hint, "unrelated backup").unwrap();
    fs::write(&temp_hint, "unrelated temp").unwrap();
    let outcome = ManagedConfig::apply(plan).unwrap();
    assert_ne!(outcome.backup_path.as_deref(), Some(backup_hint.as_path()));
    assert_eq!(
        fs::read_to_string(&backup_hint).unwrap(),
        "unrelated backup"
    );
    assert_eq!(fs::read_to_string(&temp_hint).unwrap(), "unrelated temp");
}

struct FailAt(TransactionPhase);
impl TransactionObserver for FailAt {
    fn phase(&self, phase: TransactionPhase, _: &ManagedConfigPlan) -> io::Result<()> {
        if phase == self.0 {
            Err(io::Error::other(format!("injected {}", phase.name())))
        } else {
            Ok(())
        }
    }
}

struct CorruptTemp;
impl TransactionObserver for CorruptTemp {
    fn mutate_written_temp(&self, path: &Path, _: &ManagedConfigPlan) -> io::Result<()> {
        fs::write(path, "corrupt")
    }
}

#[test]
fn all_precommit_phase_failures_cleanup_and_preserve_original() {
    let phases = [
        TransactionPhase::BeforeBackupReserve,
        TransactionPhase::AfterBackupReserved,
        TransactionPhase::BeforeTempReserve,
        TransactionPhase::BeforeTempWrite,
        TransactionPhase::AfterTempWritten,
        TransactionPhase::AfterValidation,
        TransactionPhase::BeforePublish,
    ];
    for phase in phases {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.rc");
        fs::write(&path, "original\n").unwrap();
        let plan = ManagedConfig::plan(request(&path, &[("item", "body")])).unwrap();
        assert!(matches!(
            ManagedConfig::apply_with_observer(plan, &FailAt(phase)),
            Err(ManagedConfigError::Phase { .. })
        ));
        assert_eq!(fs::read_to_string(&path).unwrap(), "original\n");
        assert!(artifacts(temp.path()).is_empty());
    }
}

#[test]
fn post_publish_failures_rollback_existing_and_remove_new_target() {
    let phases = [
        TransactionPhase::AfterPublish,
        TransactionPhase::BeforeParentSync,
        TransactionPhase::AfterParentSync,
        TransactionPhase::BeforeVerify,
    ];
    for phase in phases {
        for existing in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("config.rc");
            if existing {
                fs::write(&path, "original\n").unwrap();
            }
            let plan = ManagedConfig::plan(request(&path, &[("item", "body")])).unwrap();
            assert!(ManagedConfig::apply_with_observer(plan, &FailAt(phase)).is_err());
            if existing {
                assert_eq!(fs::read_to_string(&path).unwrap(), "original\n");
            } else {
                assert!(!path.exists());
            }
            assert!(artifacts(temp.path()).is_empty());
        }
    }
}

#[test]
fn verification_failure_rolls_back_exact_original() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.rc");
    fs::write(&path, "original\n").unwrap();
    let plan = ManagedConfig::plan(request(&path, &[("item", "body")])).unwrap();
    let error = ManagedConfig::apply_with_observer(plan, &CorruptTemp).unwrap_err();
    assert!(matches!(error, ManagedConfigError::Verification { .. }));
    assert_eq!(fs::read_to_string(&path).unwrap(), "original\n");
    assert!(artifacts(temp.path()).is_empty());
}

#[test]
fn primary_and_rollback_errors_are_both_reported() {
    struct FailBoth;
    impl TransactionObserver for FailBoth {
        fn phase(&self, phase: TransactionPhase, _: &ManagedConfigPlan) -> io::Result<()> {
            if matches!(
                phase,
                TransactionPhase::AfterPublish | TransactionPhase::BeforeRollback
            ) {
                Err(io::Error::other("injected failure"))
            } else {
                Ok(())
            }
        }
    }

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.rc");
    fs::write(&path, "original\n").unwrap();
    let plan = ManagedConfig::plan(request(&path, &[("item", "body")])).unwrap();
    assert!(matches!(
        ManagedConfig::apply_with_observer(plan, &FailBoth),
        Err(ManagedConfigError::Recovery { .. })
    ));
}

#[test]
fn publish_and_parent_sync_failures_are_injected_at_the_real_operations() {
    struct PublishFailure;
    impl TransactionObserver for PublishFailure {
        fn publish(&self, _: &Path, _: &Path) -> io::Result<()> {
            Err(io::Error::other("injected publish failure"))
        }
    }
    struct SyncFailure;
    impl TransactionObserver for SyncFailure {
        fn sync_parent(
            &self,
            parent: &super::source::ParentAnchor,
            rollback: bool,
        ) -> Result<(), ManagedConfigError> {
            if rollback {
                parent.sync()
            } else {
                Err(ManagedConfigError::Sync {
                    path: Path::new("injected-parent").to_path_buf(),
                    source: io::Error::other("injected sync failure"),
                })
            }
        }
    }

    for observer in [
        &PublishFailure as &dyn TransactionObserver,
        &SyncFailure as &dyn TransactionObserver,
    ] {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("config.rc");
        fs::write(&path, "original\n").unwrap();
        let plan = ManagedConfig::plan(request(&path, &[("item", "body")])).unwrap();
        assert!(ManagedConfig::apply_with_observer(plan, observer).is_err());
        assert_eq!(fs::read_to_string(&path).unwrap(), "original\n");
        assert!(artifacts(temp.path()).is_empty());
    }
}

#[test]
fn failed_validator_cleans_reserved_backup_and_temp() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.rc");
    fs::write(&path, "original\n").unwrap();
    let mut request = request(&path, &[("item", "body")]);
    request.validator = Some(SyntaxValidator {
        program: "/bin/sh".into(),
        args: vec!["-c".into(), "exit 7".into()],
        timeout: Duration::from_secs(1),
    });
    assert!(matches!(
        ManagedConfig::apply(ManagedConfig::plan(request).unwrap()),
        Err(ManagedConfigError::Validation { .. })
    ));
    assert_eq!(fs::read_to_string(&path).unwrap(), "original\n");
    assert!(artifacts(temp.path()).is_empty());
}

#[test]
fn transaction_lock_blocks_second_apply_then_stale_revalidation_wins() {
    // Every wait on the applies is bounded and a thread that ends early
    // disconnects its channel, so a first apply that never reaches the lock
    // (on Windows it once failed to open the parent directory, long before)
    // fails this test at once instead of leaving it waiting forever on a
    // barrier. The threads are joined only after both results are in.
    const WAIT: Duration = Duration::from_secs(60);

    struct BlockAfterLock {
        reached: mpsc::Sender<()>,
        release: Mutex<mpsc::Receiver<()>>,
    }
    impl TransactionObserver for BlockAfterLock {
        fn phase(&self, phase: TransactionPhase, _: &ManagedConfigPlan) -> io::Result<()> {
            if phase == TransactionPhase::AfterLock {
                self.reached.send(()).map_err(io::Error::other)?;
                self.release
                    .lock()
                    .unwrap()
                    .recv_timeout(WAIT)
                    .map_err(io::Error::other)?;
            }
            Ok(())
        }
    }

    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.rc");
    fs::write(&path, "original\n").unwrap();
    let first = ManagedConfig::plan(request(&path, &[("one", "one")])).unwrap();
    let second = ManagedConfig::plan(request(&path, &[("two", "two")])).unwrap();
    let (reached, reached_here) = mpsc::channel();
    let (release, release_there) = mpsc::channel();
    let observer = BlockAfterLock {
        reached,
        release: Mutex::new(release_there),
    };
    let (first_result, first_result_here) = mpsc::channel();
    let first_thread = std::thread::spawn(move || {
        let _ = first_result.send(ManagedConfig::apply_with_observer(first, &observer));
    });
    match reached_here.recv_timeout(WAIT) {
        Ok(()) => {}
        // The observer (and its sender) is gone: the apply returned early, and
        // its result is already in the channel.
        Err(mpsc::RecvTimeoutError::Disconnected) => panic!(
            "first apply ended before it held the lock: {:?}",
            first_result_here.recv_timeout(WAIT)
        ),
        Err(mpsc::RecvTimeoutError::Timeout) => {
            panic!("first apply did not reach the lock within {WAIT:?}")
        }
    }

    let (started, started_here) = mpsc::channel();
    let (result, result_here) = mpsc::channel();
    let second_thread = std::thread::spawn(move || {
        let _ = started.send(());
        let _ = result.send(ManagedConfig::apply(second));
    });
    // The 50 ms are counted from when the second thread is running, so a
    // slow thread start cannot stand in for a held lock.
    started_here
        .recv_timeout(WAIT)
        .expect("second apply did not start");
    match result_here.recv_timeout(Duration::from_millis(50)) {
        Err(mpsc::RecvTimeoutError::Timeout) => {}
        early => panic!("second apply must block on lock, got {early:?}"),
    }
    release.send(()).unwrap();
    let first_result = first_result_here
        .recv_timeout(WAIT)
        .expect("first apply did not finish after it was released");
    assert!(first_result.is_ok(), "{first_result:?}");
    let second_result = result_here
        .recv_timeout(WAIT)
        .expect("second apply did not finish after the lock was released");
    first_thread.join().unwrap();
    second_thread.join().unwrap();
    assert!(
        matches!(second_result, Err(ManagedConfigError::StalePlan(_))),
        "{second_result:?}"
    );
}

/// Other writers create entries beside the file and in the directories above
/// it all the time (the transaction's own backup and temp files among them).
/// That is not a changed parent: the plan stays valid and applies.
#[test]
fn new_entries_in_the_parent_directories_do_not_change_the_parent() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("outer/inner/config.rc");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "original\n").unwrap();
    let plan = ManagedConfig::plan(request(&path, &[("item", "body")])).unwrap();

    // A directory's modified time moves with each of these.
    fs::write(temp.path().join("beside-outer"), "x").unwrap();
    fs::create_dir(temp.path().join("outer/beside-inner")).unwrap();
    fs::write(temp.path().join("outer/inner/beside-config"), "x").unwrap();
    fs::remove_file(temp.path().join("outer/inner/beside-config")).unwrap();

    ManagedConfig::verify_unchanged(&plan).unwrap();
    let outcome = ManagedConfig::apply(plan).unwrap();
    assert_eq!(outcome.status, ManagedConfigStatus::Applied);
    assert!(fs::read_to_string(&path).unwrap().starts_with("original\n"));
}

fn set_directory_modified(directory: &Path, modified: std::time::SystemTime) {
    #[cfg(windows)]
    let handle = {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        fs::OpenOptions::new()
            .access_mode(FILE_WRITE_ATTRIBUTES)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(directory)
            .unwrap()
    };
    #[cfg(not(windows))]
    let handle = fs::File::open(directory).unwrap();
    handle.set_modified(modified).unwrap();
}

/// The plan names the file it read, not one that merely looks the same: a
/// replacement with the same bytes, length and modified time is stale, and so
/// is a parent directory replaced by an empty one made in the same instant.
#[test]
fn a_look_alike_replacement_of_the_file_or_its_parent_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("parent/config.rc");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(&path, "original\n").unwrap();
    let modified = fs::metadata(&path).unwrap().modified().unwrap();
    let plan = ManagedConfig::plan(request(&path, &[("item", "body")])).unwrap();

    let twin = temp.path().join("parent/twin");
    fs::write(&twin, "original\n").unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&twin)
        .unwrap()
        .set_modified(modified)
        .unwrap();
    // The original stays on disk (renamed), so its identity cannot be reused.
    fs::rename(&path, temp.path().join("parent/moved-away")).unwrap();
    fs::rename(&twin, &path).unwrap();
    assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), modified);
    assert_eq!(fs::read(&path).unwrap(), b"original\n");
    assert!(matches!(
        ManagedConfig::verify_unchanged(&plan),
        Err(ManagedConfigError::StalePlan(_))
    ));
    assert!(matches!(
        ManagedConfig::apply(plan),
        Err(ManagedConfigError::StalePlan(_))
    ));
    assert_eq!(fs::read(&path).unwrap(), b"original\n");

    // The parent: a missing target in a directory that is swapped for a twin.
    let missing = temp.path().join("swapped/config.rc");
    let parent = missing.parent().unwrap();
    fs::create_dir(parent).unwrap();
    let parent_modified = fs::metadata(parent).unwrap().modified().unwrap();
    let plan = ManagedConfig::plan(request(&missing, &[("item", "body")])).unwrap();
    fs::rename(parent, temp.path().join("swapped-away")).unwrap();
    fs::create_dir(parent).unwrap();
    set_directory_modified(parent, parent_modified);
    assert_eq!(
        fs::metadata(parent).unwrap().modified().unwrap(),
        parent_modified
    );
    assert!(matches!(
        ManagedConfig::verify_unchanged(&plan),
        Err(ManagedConfigError::ParentChanged(_))
    ));
    assert!(matches!(
        ManagedConfig::apply(plan),
        Err(ManagedConfigError::ParentChanged(_))
    ));
    assert!(!missing.exists());
}

/// `nul` (like `con`, `aux`, ...) names a device in every directory. Such a
/// path is refused at plan time; nothing is planned for a device.
#[cfg(windows)]
#[test]
fn a_reserved_device_name_is_refused_at_plan_time() {
    let temp = tempfile::tempdir().unwrap();
    let refused = ManagedConfig::plan(request(&temp.path().join("nul"), &[("item", "body")]));
    assert!(refused.is_err(), "{refused:?}");
    assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 0);
}

/// Windows has two kinds of directory link. A junction needs no privilege to
/// create, so it is the one this test can always make; both are refused as a
/// parent the same way a Unix symlink is.
#[cfg(windows)]
#[test]
fn a_junction_parent_is_resolved_at_plan_time_and_refused_when_swapped_in() {
    use super::source::windows_tests::junction;

    let temp = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(temp.path()).unwrap();
    let real_parent = root.join("real-parent");
    fs::create_dir(&real_parent).unwrap();
    let linked_parent = root.join("linked-parent");
    junction(&linked_parent, &real_parent);
    assert!(
        fs::symlink_metadata(&linked_parent)
            .unwrap()
            .file_type()
            .is_symlink()
    );

    // Planned through the junction: the plan is for the real directory.
    let plan =
        ManagedConfig::plan(request(&linked_parent.join("rc"), &[("item", "body")])).unwrap();
    assert_eq!(plan.target_path().parent(), Some(real_parent.as_path()));
    ManagedConfig::apply(plan).unwrap();
    assert!(real_parent.join("rc").exists());

    // The captured chain refuses a junction outright.
    assert!(matches!(
        super::source::ParentPlan::capture(&linked_parent),
        Err(ManagedConfigError::UnsafePath { .. })
    ));

    // Planned on a real directory that is then swapped for a junction to the
    // very same directory: same files behind the path, still a changed parent.
    let path = root.join("swap/config.rc");
    fs::create_dir(path.parent().unwrap()).unwrap();
    fs::write(&path, "original\n").unwrap();
    let plan = ManagedConfig::plan(request(&path, &[("item", "body")])).unwrap();
    let moved = root.join("swap-moved");
    fs::rename(path.parent().unwrap(), &moved).unwrap();
    junction(path.parent().unwrap(), &moved);
    assert_eq!(fs::read_to_string(&path).unwrap(), "original\n");
    assert!(matches!(
        ManagedConfig::apply(plan),
        Err(ManagedConfigError::ParentChanged(_))
    ));
    assert_eq!(fs::read_to_string(&path).unwrap(), "original\n");
}

#[test]
fn validator_timeout_is_bounded() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("config.rc");
    fs::write(&path, "original\n").unwrap();
    let mut request = request(&path, &[("item", "body")]);
    request.validator = Some(SyntaxValidator {
        program: "/bin/sh".into(),
        args: vec!["-c".into(), "sleep 60".into()],
        timeout: Duration::from_millis(20),
    });
    let started = Instant::now();
    assert!(ManagedConfig::apply(ManagedConfig::plan(request).unwrap()).is_err());
    // "Bounded" means cut off at the timeout rather than waited out: the validator would run 60 s,
    // so any bound below that discriminates. 1 s (against a 5 s sleep) failed on a loaded host,
    // where spawning `sh` and tearing its group down alone can take longer.
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(30),
        "validator was not cut off: {elapsed:?}"
    );
    assert_eq!(fs::read_to_string(&path).unwrap(), "original\n");
}

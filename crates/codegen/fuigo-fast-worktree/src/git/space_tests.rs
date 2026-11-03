//! BF-2, BF-3, BF-3a and BF-7 tests. Fixtures are the BF-8 recordings (git 2.43.0, `LC_ALL=C`).

use super::*;
use std::path::{Path, PathBuf};

const C1: &str = "Preparing worktree (detached HEAD eaf3ff1)\nerror: unable to write file big.bin\nerror: unable to write file s0.txt\nerror: unable to write file s1.txt\nerror: unable to write file s10.txt\nerror: unable to write file s11.txt\nerror: unable to write file s12.txt\nerror: unable to write file s13.txt\nerror: unable to write file s14.txt\nerror: unable to write file s15.txt\nerror: unable to write file s16.txt\nerror: unable to write file s17.txt\nerror: unable to write file s18.txt\nerror: unable to write file s19.txt\nerror: unable to write file s2.txt\nerror: unable to write file s3.txt\nerror: unable to write file s4.txt\nerror: unable to write file s5.txt\nerror: unable to write file s6.txt\nerror: unable to write file s7.txt\nerror: unable to write file s8.txt\nerror: unable to write file s9.txt\nfatal: Could not reset index file to revision 'HEAD'.\n";
const C2: &str = "Preparing worktree (detached HEAD eaf3ff1)\nerror: unable to write file 'big.bin'\nfatal: Could not reset index file to revision 'HEAD'.\n";
const C3A: &str = "Preparing worktree (detached HEAD 2f8b6eb)\nerror: unable to create file d1/f15: No space left on device\nerror: unable to create file d1/f9: No space left on device\nfatal: cannot create directory at 'd2': No space left on device\n";
const C3B: &str = "Preparing worktree (detached HEAD 2f8b6eb)\nerror: failed to open file 'd0/f18': No space left on device\nerror: failed to open file 'd0/f13': No space left on device\nfatal: Could not reset index file to revision 'HEAD'.\n";
const C4: &str = "Preparing worktree (detached HEAD 1d00efd)\nfatal: could not write to '<MNT>/c4/wt/.git': No space left on device\n";
const C4B: &str = "Preparing worktree (detached HEAD 1d00efd)\nfatal: could not create leading directories of '<MNT>/c4b/wt/.git': No space left on device\n";
/// C5 (`reset --hard`): C1 without the `Preparing worktree` line.
fn c5() -> &'static str {
    C1.split_once('\n').unwrap().1
}
const C5B: &str = "error: unable to create file d1/f5: No space left on device\nerror: unable to create file d1/f9: No space left on device\nfatal: cannot create directory at 'd2': No space left on device\n";
const C6: &str = "Preparing worktree (detached HEAD 1d00efd)\nfatal: could not write to '.git/worktrees/wt/locked': No space left on device\n";

const MIB: u64 = 1024 * 1024;

fn failed() -> ExitStatus {
    #[cfg(unix)]
    {
        std::os::unix::process::ExitStatusExt::from_raw(128 << 8)
    }
    #[cfg(windows)]
    {
        std::os::windows::process::ExitStatusExt::from_raw(128)
    }
}

fn paths() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/fs/dest-parent"),
        PathBuf::from("/fs/common"),
    ]
}

fn low_bytes() -> Avail {
    Avail {
        bytes: MIB,
        inodes: Some(10_000),
    }
}
fn ample() -> Avail {
    Avail {
        bytes: 10_000 * MIB,
        inodes: Some(1_000_000),
    }
}

fn with_probe(a: io::Result<Avail>) -> seam::SeamGuard {
    let r = a.map_err(|e| e.kind());
    seam::install(
        Some(Box::new(move |_: &Path| r.map_err(io::Error::from))),
        None,
    )
}

fn by(err: &anyhow::Error) -> Option<StorageFullBy> {
    err.downcast_ref::<GitStorageFull>().map(|g| g.by)
}

fn today(what: &str, stderr: &str) -> String {
    format!("{what} failed: {stderr}")
}

fn classify(stderr: &str, fit: bool) -> anyhow::Error {
    let repo = Path::new("/repo");
    git_write_failure(
        "git worktree add",
        &failed(),
        stderr,
        &paths(),
        fit.then_some(FitCheck {
            repo,
            git_ref: "HEAD",
        }),
    )
}

// ---- BF-3 rules ----

#[test]
fn bf3_rule_table() {
    let q = "fatal: cannot create directory at '/x': No space left on device";
    assert_eq!(line_rule(q), Some(LineRule::Q));
    assert_eq!(line_rule(&format!("{q}\r")), Some(LineRule::Q));
    let u = "error: unable to create file a: No space left on device";
    assert_eq!(line_rule(u), Some(LineRule::U));
    assert_eq!(line_rule(&format!("{u}\r")), Some(LineRule::U));
    for none in [
        "error: unable to create file a: No space left on device: Permission denied",
        "warning: unable to create file a: No space left on device",
        "error: unable to write file a",
        "fatal: invalid path 'x: No space left on device'",
        "fatal: '/a': No space left on device: Permission denied",
        "fatal: cannot create directory at '/x': Aucun espace disponible sur le périphérique",
        "error: unable to create file a: Kein Speicherplatz mehr verfügbar",
    ] {
        assert_eq!(line_rule(none), None, "{none}");
    }
    // Every recorded ENOSPC line matches.
    for (fx, rule) in [
        (C3A, None),
        (C3B, Some(LineRule::Q)),
        (C4, Some(LineRule::Q)),
        (C4B, Some(LineRule::Q)),
        (C5B, None),
        (C6, Some(LineRule::Q)),
    ] {
        let s: Vec<_> = classify_lines(fx)
            .into_iter()
            .filter(|(_, c)| *c == LineClass::S)
            .collect();
        assert!(!s.is_empty(), "{fx}");
        if let Some(rule) = rule {
            assert!(s.iter().all(|(l, _)| line_rule(l) == Some(rule)), "{fx}");
        }
    }
    assert!(
        classify_lines(C3A)
            .iter()
            .any(|(l, _)| line_rule(l) == Some(LineRule::U))
    );
    assert!(
        classify_lines(C5B)
            .iter()
            .any(|(l, _)| line_rule(l) == Some(LineRule::U))
    );
}

// ---- BF-3a classes ----

#[test]
fn bf3a_class_table() {
    use LineClass::*;
    for (line, class) in [
        ("error: unable to write file big.bin", W),
        ("error: unable to write file 'big.bin'", W),
        ("fatal: Could not reset index file to revision 'HEAD'.", R),
        ("Preparing worktree (detached HEAD eaf3ff1)", I),
        ("error: unable to create file a: No space left on device", S),
        ("warning: unable to write file a", O),
        ("fatal: unable to write new index file", O),
        ("HEAD is now at 1a2b3c msg", O),
        ("Updating files: 100% (2/2), done.", O),
        ("fatal: unable to checkout working tree", O),
        ("hint: Use 'git worktree prune'", O),
        ("my-hook: refusing this checkout", O),
        ("fatal: Could not reset index file to revision 'HEAD'", O),
        (
            "error: unable to write file 'big.bin': Permission denied",
            O,
        ),
        ("error: unable to write file big.bin: Permission denied", O),
        ("error: unable to write file 'big.bin' ", O),
        ("error: unable to write file ''", O),
        ("error: unable to write file ", O),
        ("error: unable to write file s0.txt\r", W),
    ] {
        assert_eq!(line_class(line), class, "{line}");
    }
    assert!(
        classify_lines("\n\r\n\nPreparing worktree (x)\n").len() == 1,
        "empty lines are skipped"
    );
    let c1 = classify_lines(C1);
    assert_eq!(c1.iter().filter(|(_, c)| *c == W).count(), 21);
    assert_eq!(c1.iter().filter(|(_, c)| *c == R).count(), 1);
    assert_eq!(c1.iter().filter(|(_, c)| *c == I).count(), 1);
    assert!(
        classify_lines(C2)
            .iter()
            .all(|(_, c)| matches!(c, I | W | R))
    );
}

// ---- BF-2 ----

/// A single recorded errno-less write line (the C2 shape without its summary).
const W_ONLY: &str = "error: unable to write file 'big.bin'\n";
/// git's reset summary alone: R never classifies on its own (BF-3a).
const R_ONLY: &str = "fatal: Could not reset index file to revision 'HEAD'.\n";

#[test]
fn bf2_floor_by_bytes_and_by_inodes_beside_a_write_failure_line() {
    for stderr in [c5(), C2, W_ONLY] {
        let _g = with_probe(Ok(low_bytes()));
        let e = classify(stderr, false);
        assert_eq!(by(&e), Some(StorageFullBy::Floor), "{e}");
        let _g = with_probe(Ok(Avail {
            bytes: 10_000 * MIB,
            inodes: Some(3),
        }));
        assert_eq!(by(&classify(stderr, false)), Some(StorageFullBy::Floor));
    }
}

/// A failure git explains with nothing (a silent hook) or only an informational line is not a full disk, whatever
/// the probe says: it keeps the 1.0.38 error, so the caller's fallback still applies.
#[test]
fn bf2_empty_or_informational_stderr_under_a_low_probe_is_today() {
    for stderr in ["", "Preparing worktree (detached HEAD eaf3ff1)\n"] {
        for low in [
            low_bytes(),
            Avail {
                bytes: 10_000 * MIB,
                inodes: Some(3),
            },
            Avail {
                bytes: 0,
                inodes: Some(0),
            },
        ] {
            let _g = with_probe(Ok(low));
            let e = classify(stderr, true);
            assert!(by(&e).is_none(), "{stderr:?}: {e}");
            assert_eq!(e.to_string(), today("git worktree add", stderr));
            let e = reset_failure(stderr);
            assert!(by(&e).is_none(), "{stderr:?}: {e}");
            assert_eq!(e.to_string(), today("git reset --hard HEAD", stderr));
        }
    }
}

#[test]
fn bf2_ample_probe_is_byte_identical_to_today() {
    let _g = with_probe(Ok(ample()));
    for stderr in ["", C2, "fatal: invalid reference: nope\n"] {
        let e = classify(stderr, false);
        assert!(by(&e).is_none());
        assert_eq!(e.to_string(), today("git worktree add", stderr));
        assert_eq!(format!("{e:#}"), today("git worktree add", stderr));
    }
}

#[test]
fn bf2_probe_error_never_classifies() {
    let _g = with_probe(Err(io::Error::other("statvfs failed")));
    for stderr in ["", C1, C2, c5(), "Preparing worktree (x)\n"] {
        let e = classify(stderr, true);
        assert!(by(&e).is_none(), "{stderr}");
        assert_eq!(e.to_string(), today("git worktree add", stderr));
    }
}

#[test]
fn bf2_unknown_inodes_classify_by_bytes_only() {
    let _g = with_probe(Ok(Avail {
        bytes: MIB,
        inodes: None,
    }));
    assert_eq!(by(&classify(W_ONLY, false)), Some(StorageFullBy::Floor));
    let _g = with_probe(Ok(Avail {
        bytes: 10_000 * MIB,
        inodes: None,
    }));
    assert!(by(&classify(W_ONLY, false)).is_none());
}

#[test]
fn bf2_low_probe_with_a_named_cause_is_today() {
    let _g = with_probe(Ok(Avail {
        bytes: 0,
        inodes: Some(0),
    }));
    for stderr in [
        "fatal: invalid reference: nope\n",
        "Preparing worktree (detached HEAD 1)\nfatal: '/x/dest' already exists\n",
        "error: cannot lock ref 'refs/heads/x': Unable to create '/r/.git/refs/heads/x.lock': Permission denied\n",
        "Preparing worktree (detached HEAD 1)\nhook says no\n",
        "error: unable to write file 'big.bin': Permission denied\n",
        "Preparing worktree (detached HEAD 1)\nerror: unable to write file 'big.bin': Permission denied\nfatal: Could not reset index file to revision 'HEAD'.\n",
        R_ONLY,
        "Preparing worktree (detached HEAD 1)\nfatal: Could not reset index file to revision 'HEAD'.\n",
    ] {
        let e = classify(stderr, true);
        assert!(by(&e).is_none(), "{stderr}");
        assert_eq!(e.to_string(), today("git worktree add", stderr));
    }
}

/// The allow-list, end to end under a zero probe: every distinct line shape in the BF-8 recordings keeps its class
/// and still classifies, and the same write lines with any other errno are class O and stay the 1.0.38 error.
#[test]
fn bf3a_recorded_shapes_classify_and_errno_variants_are_today() {
    use LineClass::*;
    let _g = with_probe(Ok(Avail {
        bytes: 0,
        inodes: Some(0),
    }));
    for (line, class) in [
        ("error: unable to write file s0.txt", W),
        ("error: unable to write file big.bin", W),
        ("error: unable to write file 'big.bin'", W),
        ("fatal: Could not reset index file to revision 'HEAD'.", R),
        ("Preparing worktree (detached HEAD eaf3ff1)", I),
        (
            "error: unable to create file d1/f15: No space left on device",
            S,
        ),
        (
            "error: failed to open file 'd0/f18': No space left on device",
            S,
        ),
        (
            "fatal: cannot create directory at 'd2': No space left on device",
            S,
        ),
        (
            "fatal: could not write to '.git/worktrees/wt/locked': No space left on device",
            S,
        ),
        (
            "fatal: could not write to '/m/c4/wt/.git': No space left on device",
            S,
        ),
        (
            "fatal: could not create leading directories of '/m/c4b/wt/.git': No space left on device",
            S,
        ),
    ] {
        assert_eq!(line_class(line), class, "{line}");
        if class != I && class != R {
            let stderr = format!("{line}\n");
            assert!(by(&classify(&stderr, true)).is_some(), "{line}");
            assert!(by(&reset_failure(&stderr)).is_some(), "{line}");
        }
    }
    for fx in [C1, C2, C3A, C3B, C4, C4B, c5(), C5B, C6] {
        assert!(by(&classify(fx, true)).is_some(), "{fx}");
    }
    for errno in [
        "Permission denied",
        "Read-only file system",
        "Input/output error",
        "File exists",
        "Is a directory",
    ] {
        for line in [
            format!("error: unable to write file 'big.bin': {errno}"),
            format!("error: unable to write file big.bin: {errno}"),
            format!("error: unable to create file d1/f15: {errno}"),
            format!("fatal: could not write to '.git/worktrees/wt/locked': {errno}"),
        ] {
            assert_eq!(line_class(&line), O, "{line}");
            for stderr in [
                format!("{line}\n"),
                format!(
                    "Preparing worktree (detached HEAD 1)\n{line}\nfatal: Could not reset index file to revision 'HEAD'.\n"
                ),
            ] {
                let e = classify(&stderr, true);
                assert!(by(&e).is_none(), "{stderr}");
                assert_eq!(e.to_string(), today("git worktree add", &stderr));
                let e = reset_failure(&stderr);
                assert!(by(&e).is_none(), "{stderr}");
                assert_eq!(e.to_string(), today("git reset --hard HEAD", &stderr));
            }
        }
    }
}

#[test]
fn bf2_s_line_wins_beside_a_summary() {
    let _g = with_probe(Err(io::Error::other("no probe")));
    for fx in [C3A, C3B, C4, C4B, C5B, C6] {
        let e = classify(fx, false);
        assert_eq!(by(&e), Some(StorageFullBy::Line), "{fx}");
        assert!(
            e.to_string()
                .ends_with("(git reported no space left on the device)"),
            "{e}"
        );
    }
    let _g = with_probe(Ok(low_bytes()));
    let e = classify(
        "fatal: could not write to '/x': No space left on device\nfatal: something else\n",
        false,
    );
    assert_eq!(by(&e), Some(StorageFullBy::Line));
}

#[test]
fn typed_error_carries_a_storage_full_source_and_the_space_note() {
    let _g = with_probe(Ok(low_bytes()));
    let e = classify(W_ONLY, false);
    let io = e
        .chain()
        .find_map(|c| c.downcast_ref::<io::Error>())
        .expect("io source");
    assert_eq!(io.kind(), io::ErrorKind::StorageFull);
    assert_eq!(
        e.to_string(),
        "git worktree add failed: error: unable to write file 'big.bin' (only 1024 KiB free on /fs/dest-parent)"
    );
}

#[test]
fn floor_checks_every_fs_path() {
    let _g = seam::install(
        Some(Box::new(|p: &Path| {
            Ok(if p.ends_with("common") {
                Avail {
                    bytes: 0,
                    inodes: Some(0),
                }
            } else {
                ample()
            })
        })),
        None,
    );
    let e = classify(
        "Preparing worktree (x)\nerror: unable to write file a\n",
        false,
    );
    let g = e.downcast_ref::<GitStorageFull>().unwrap();
    assert_eq!(
        (g.by, g.path.as_path()),
        (StorageFullBy::Floor, Path::new("/fs/common"))
    );
}

// ---- BF-7 ----

fn fit_seam(avail: Avail, need: anyhow::Result<Need>) -> seam::SeamGuard {
    let need = std::cell::RefCell::new(Some(need));
    seam::install(
        Some(Box::new(move |_: &Path| Ok(avail))),
        Some(Box::new(move || {
            need.borrow_mut()
                .take()
                .unwrap_or_else(|| anyhow::bail!("walked twice"))
        })),
    )
}

const TREE: Need = Need {
    bytes: 24 * MIB,
    entries: 21,
};

#[test]
fn bf7_recorded_c1_and_c2_classify_by_fit() {
    for fx in [C1, C2] {
        let _g = fit_seam(
            Avail {
                bytes: 16 * MIB,
                inodes: Some(4000),
            },
            Ok(TREE),
        );
        let e = classify(fx, true);
        assert_eq!(by(&e), Some(StorageFullBy::Fit), "{e}");
        assert!(
            e.to_string().ends_with(
                "(the checkout needs 24576 KiB; only 16384 KiB free on /fs/dest-parent)"
            ),
            "{e}"
        );
        assert_eq!(seam::need_calls(), 1);
    }
}

#[test]
fn bf7_tree_that_fits_or_walk_error_is_today() {
    let _g = fit_seam(
        Avail {
            bytes: 100 * MIB,
            inodes: Some(4000),
        },
        Ok(TREE),
    );
    assert_eq!(
        classify(C1, true).to_string(),
        today("git worktree add", C1)
    );
    let _g = fit_seam(
        Avail {
            bytes: 16 * MIB,
            inodes: Some(4000),
        },
        Err(anyhow::anyhow!("gix: odb broken")),
    );
    assert_eq!(
        classify(C2, true).to_string(),
        today("git worktree add", C2)
    );
}

#[test]
fn bf7_inode_shortfall_is_fit() {
    let _g = fit_seam(
        Avail {
            bytes: 100 * MIB,
            inodes: Some(70),
        },
        Ok(TREE),
    );
    assert_eq!(by(&classify(C2, true)), Some(StorageFullBy::Fit));
}

#[test]
fn bf7_never_walks_with_a_named_cause_or_without_a_w_line() {
    let named = format!("{C1}fatal: unable to checkout working tree\n");
    let _g = fit_seam(
        Avail {
            bytes: 16 * MIB,
            inodes: Some(4000),
        },
        Ok(TREE),
    );
    assert_eq!(
        classify(&named, true).to_string(),
        today("git worktree add", &named)
    );
    assert_eq!(
        seam::need_calls(),
        0,
        "the walk never runs beside a class O line"
    );
    let ir = "Preparing worktree (detached HEAD eaf3ff1)\nfatal: Could not reset index file to revision 'HEAD'.\n";
    let _g = fit_seam(
        Avail {
            bytes: 16 * MIB,
            inodes: Some(4000),
        },
        Ok(TREE),
    );
    assert!(by(&classify(ir, true)).is_none());
    assert_eq!(
        seam::need_calls(),
        0,
        "the walk never runs without a W line"
    );
}

// ---- C5: reset --hard by the probe ----

fn reset_failure(stderr: &str) -> anyhow::Error {
    git_write_failure(
        "git reset --hard HEAD",
        &failed(),
        stderr,
        &[PathBuf::from("/fs/wt")],
        None,
    )
}

#[test]
fn c5_reset_classifies_by_floor_never_by_fit() {
    let _g = fit_seam(
        Avail {
            bytes: 12 * 1024,
            inodes: Some(4000),
        },
        Ok(TREE),
    );
    assert_eq!(by(&reset_failure(c5())), Some(StorageFullBy::Floor));
    let _g = fit_seam(
        Avail {
            bytes: 100 * MIB,
            inodes: Some(4000),
        },
        Ok(TREE),
    );
    let e = reset_failure(c5());
    assert_eq!(e.to_string(), today("git reset --hard HEAD", c5()));
    assert_eq!(seam::need_calls(), 0, "BF-7 never runs for the reset step");
    let named = format!("{}error: some other cause\n", c5());
    let _g = fit_seam(
        Avail {
            bytes: 0,
            inodes: Some(0),
        },
        Ok(TREE),
    );
    assert_eq!(
        reset_failure(&named).to_string(),
        today("git reset --hard HEAD", &named)
    );
}

// ---- real git: tree walk and a real refusal under a low probe ----

fn repo_with_files() -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    std::fs::create_dir_all(repo.join("d")).unwrap();
    fuigo_test_utils::git::init_git_repo(&repo);
    std::fs::write(repo.join("a.txt"), vec![b'x'; 1000]).unwrap();
    std::fs::write(repo.join("d/b.txt"), vec![b'y'; 234]).unwrap();
    fuigo_test_utils::git::git_commit_all(&repo, "init");
    (tmp, repo)
}

#[test]
fn tree_need_counts_entries_and_blob_bytes() {
    fuigo_test_utils::require_git!();
    let (_tmp, repo) = repo_with_files();
    let need = tree_need(&repo, "HEAD").unwrap();
    assert_eq!(
        need,
        Need {
            bytes: 1234,
            entries: 3
        }
    );
}

#[test]
fn real_refusal_under_low_probe_is_today() {
    fuigo_test_utils::require_git!();
    let (tmp, repo) = repo_with_files();
    let dest = tmp.path().join("busy");
    std::fs::create_dir(&dest).unwrap();
    std::fs::write(dest.join("x"), "x").unwrap();
    for low in [true, false] {
        let _g = low.then(|| {
            with_probe(Ok(Avail {
                bytes: 0,
                inodes: Some(0),
            }))
        });
        let e = crate::git::worktree_add_no_checkout(&repo, dest.to_str().unwrap(), "HEAD")
            .unwrap_err();
        assert!(by(&e).is_none(), "{e}");
        let s = e.to_string();
        assert!(
            s.starts_with("git worktree add failed: ") && s.contains("already exists"),
            "{s}"
        );
        assert!(!s.contains("free on"), "{s}");
    }
}

#[test]
fn success_never_probes() {
    fuigo_test_utils::require_git!();
    let (tmp, repo) = repo_with_files();
    let _g = with_probe(Ok(Avail {
        bytes: 0,
        inodes: Some(0),
    }));
    crate::git::worktree_add_no_checkout(&repo, tmp.path().join("wt").to_str().unwrap(), "HEAD")
        .unwrap();
    crate::git::git_reset_hard_command(&tmp.path().join("wt"), None).unwrap();
    assert_eq!(seam::probe_calls(), 0);
    assert_eq!(seam::need_calls(), 0);
}

//! BF-8: the disk-full classifier against a real full filesystem (1.0.39 item 7 merge gate).
//!
//! Every test is `#[ignore]` and returns early unless `FUIGO_ENOSPC_MNT` is set. The run is root inside
//! `unshare -n -m --propagation private`: each case mounts its own tmpfs under `$FUIGO_ENOSPC_MNT/<case>`
//! (private to the namespace), runs git with the production arguments, records git's exact stderr, every
//! line's rule and class, the probe on every `fs_paths` entry after the exit, BF-7's `need`/`avail` when
//! it runs, and the verdict to `$FUIGO_ENOSPC_OUT/<case>.txt`, then unmounts. Run with `LC_ALL=C`.
#![cfg(target_os = "linux")]
// The box test prints each case record as it runs (`--nocapture`).
#![allow(clippy::print_stderr)]

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use fuigo_fast_worktree::enospc_box as bx;
use fuigo_fast_worktree::{
    CreationMode, GitStorageFull, LineClass, StorageFullBy, WorkingTreeMode, WorktreeBuilder,
};

const MIB: usize = 1024 * 1024;

struct Env {
    mnt: PathBuf,
    out: PathBuf,
}

fn env() -> Option<Env> {
    let mnt = std::env::var_os("FUIGO_ENOSPC_MNT")?;
    let out = std::env::var_os("FUIGO_ENOSPC_OUT").unwrap_or_else(|| mnt.clone());
    std::fs::create_dir_all(&out).unwrap();
    Some(Env {
        mnt: mnt.into(),
        out: out.into(),
    })
}

/// A namespace-private tmpfs, unmounted on drop (also on a failed assertion).
struct Tmpfs(PathBuf);
impl Tmpfs {
    fn mount(e: &Env, case: &str, opts: &str) -> Tmpfs {
        let dir = e.mnt.join(case);
        std::fs::create_dir_all(&dir).unwrap();
        let st = Command::new("mount")
            .args(["-t", "tmpfs", "-o", &format!("{opts},mode=0700")])
            .arg(format!("fuigo-enospc-{case}"))
            .arg(&dir)
            .status()
            .unwrap();
        assert!(st.success(), "mount tmpfs for {case}");
        Tmpfs(dir)
    }
}
impl Drop for Tmpfs {
    fn drop(&mut self) {
        let _ = Command::new("umount").arg(&self.0).status();
        let _ = std::fs::remove_dir(&self.0);
    }
}

fn git(dir: &Path, args: &[&str]) -> Output {
    Command::new("git")
        .args([
            "-c",
            "user.name=box",
            "-c",
            "user.email=box@example.invalid",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap()
}

fn git_ok(dir: &Path, args: &[&str]) {
    let o = git(dir, args);
    assert!(
        o.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut v = Vec::with_capacity(len);
    while v.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.truncate(len);
    v
}

fn init(repo: &Path) {
    std::fs::create_dir_all(repo).unwrap();
    git_ok(repo, &["init", "-q", "-b", "master"]);
}

fn commit(repo: &Path) {
    git_ok(repo, &["add", "-A"]);
    git_ok(repo, &["commit", "-q", "-m", "box"]);
}

/// One 24 MiB random tracked file plus 20 small files (C1, C2, C5).
fn bytes_repo(repo: &Path) {
    init(repo);
    std::fs::write(repo.join("big.bin"), random_bytes(24 * MIB)).unwrap();
    for i in 0..20 {
        std::fs::write(repo.join(format!("s{i}.txt")), format!("small {i}\n")).unwrap();
    }
    commit(repo);
}

/// 200 small tracked files in 10 directories (C3, C5b).
fn inode_repo(repo: &Path) {
    init(repo);
    for d in 0..10 {
        std::fs::create_dir_all(repo.join(format!("d{d}"))).unwrap();
        for f in 0..20 {
            std::fs::write(repo.join(format!("d{d}/f{f}")), format!("{d}/{f}\n")).unwrap();
        }
    }
    commit(repo);
}

fn small_repo(repo: &Path) {
    init(repo);
    std::fs::write(repo.join("a.txt"), "a\n").unwrap();
    std::fs::write(repo.join("b.txt"), "b\n").unwrap();
    commit(repo);
}

/// Fill a filesystem to ENOSPC with one filler file (kept in place).
fn fill_bytes(dir: &Path) {
    let mut f = std::fs::File::create(dir.join("filler")).unwrap();
    let chunk = vec![0u8; 64 * 1024];
    loop {
        if let Err(e) = f.write_all(&chunk) {
            assert_eq!(e.kind(), std::io::ErrorKind::StorageFull, "filler: {e}");
            break;
        }
    }
    let _ = f.sync_all();
}

/// Fill a filesystem's inode table with empty files.
fn fill_inodes(dir: &Path) {
    for i in 0.. {
        if let Err(e) = std::fs::File::create(dir.join(format!("e{i}"))) {
            assert_eq!(
                e.kind(),
                std::io::ErrorKind::StorageFull,
                "inode filler: {e}"
            );
            break;
        }
    }
}

fn stderr_text(o: &Output) -> String {
    match std::str::from_utf8(&o.stderr) {
        Ok(s) => s.to_string(),
        Err(_) => o.stderr.escape_ascii().to_string(),
    }
}

enum Step<'a> {
    AddWithCheckout {
        source: &'a Path,
        dest: &'a Path,
        workers: usize,
    },
    AddNoCheckout {
        source: &'a Path,
        dest: &'a Path,
    },
    ResetHard {
        worktree: &'a Path,
    },
}

/// Run one step with the production arguments, record everything, return the verdict.
fn run_case(e: &Env, case: &str, step: Step<'_>, allowed: &[LineClass], expected: StorageFullBy) {
    let mut rec = String::new();
    let (what, out, fs_paths, fit_repo) = match &step {
        Step::AddWithCheckout {
            source,
            dest,
            workers,
        } => {
            let d = dest.to_string_lossy().to_string();
            let workers = format!("checkout.workers={workers}");
            writeln!(
                rec,
                "command: git -c {workers} worktree add --detach -- {d} HEAD"
            )
            .unwrap();
            let o = git(
                source,
                &[
                    "-c", &workers, "worktree", "add", "--detach", "--", &d, "HEAD",
                ],
            );
            (
                "git worktree add",
                o,
                bx::add_fs_paths(dest, source),
                Some(source.to_path_buf()),
            )
        }
        Step::AddNoCheckout { source, dest } => {
            let d = dest.to_string_lossy().to_string();
            writeln!(
                rec,
                "command: git worktree add --detach --no-checkout -- {d} HEAD"
            )
            .unwrap();
            let o = git(
                source,
                &[
                    "worktree",
                    "add",
                    "--detach",
                    "--no-checkout",
                    "--",
                    &d,
                    "HEAD",
                ],
            );
            ("git worktree add", o, bx::add_fs_paths(dest, source), None)
        }
        Step::ResetHard { worktree } => {
            writeln!(
                rec,
                "command: git -C {} reset --hard HEAD",
                worktree.display()
            )
            .unwrap();
            let o = git(worktree, &["reset", "--hard", "HEAD"]);
            (
                "git reset --hard HEAD",
                o,
                vec![worktree.to_path_buf()],
                None,
            )
        }
    };
    let stderr = stderr_text(&out);
    writeln!(rec, "exit: {:?}", out.status.code()).unwrap();
    writeln!(rec, "stderr (verbatim):\n{stderr}--- end stderr").unwrap();
    let lines = bx::classify_lines(&stderr);
    writeln!(rec, "lines:").unwrap();
    for (l, c) in &lines {
        writeln!(rec, "  rule={:?} class={c:?} | {l}", bx::line_rule(l)).unwrap();
    }
    writeln!(rec, "probe after exit:").unwrap();
    for p in &fs_paths {
        writeln!(rec, "  {} -> {:?}", p.display(), bx::probe(p)).unwrap();
    }
    let no_o = !lines
        .iter()
        .any(|(_, c)| matches!(c, LineClass::O | LineClass::S));
    let has_w = lines.iter().any(|(_, c)| *c == LineClass::W);
    if let Some(repo) = &fit_repo
        && no_o
        && has_w
    {
        writeln!(
            rec,
            "bf7: need={:?} avail={:?}",
            bx::tree_need(repo, "HEAD"),
            bx::probe(&fs_paths[0])
        )
        .unwrap();
    }
    assert!(
        !out.status.success(),
        "{case}: git must fail on the full filesystem\n{rec}"
    );
    let fit = fit_repo.as_deref().map(|repo| bx::FitCheck {
        repo,
        git_ref: "HEAD",
    });
    let err = bx::git_write_failure(what, &out.status, &stderr, &fs_paths, fit);
    let verdict = err.downcast_ref::<GitStorageFull>().map(|g| g.by);
    match err.downcast_ref::<GitStorageFull>() {
        Some(g) => writeln!(
            rec,
            "verdict: GitStorageFull {{ by: {:?} }}\ndisplay: {err}",
            g.by
        )
        .unwrap(),
        None => writeln!(rec, "verdict: 1.0.38 error\ndisplay: {err}").unwrap(),
    }
    std::fs::write(e.out.join(format!("{case}.txt")), &rec).unwrap();
    eprintln!("==== {case}\n{rec}");
    for (l, c) in &lines {
        assert!(
            allowed.contains(c),
            "{case}: line class {c:?} not in the appendix for: {l}\n{rec}"
        );
    }
    assert_eq!(verdict, Some(expected), "{case}\n{rec}");
}

use LineClass::{I, R, S, W};

fn workers_n() -> usize {
    let n = num_cpus::get();
    eprintln!("effective_parallelism (num_cpus) = {n}");
    n
}

#[test]
#[ignore = "BF-8 box test: needs root in a private mount namespace and FUIGO_ENOSPC_MNT"]
fn c1_bytes_workers_1_by_fit() {
    let Some(e) = env() else { return };
    let src = tempfile::TempDir::new().unwrap();
    bytes_repo(&src.path().join("r"));
    let m = Tmpfs::mount(&e, "c1", "size=16m,nr_inodes=4096");
    let dest = m.0.join("wt");
    run_case(
        &e,
        "c1",
        Step::AddWithCheckout {
            source: &src.path().join("r"),
            dest: &dest,
            workers: 1,
        },
        &[I, W, R],
        StorageFullBy::Fit,
    );
}

#[test]
#[ignore = "BF-8 box test"]
fn c2_bytes_workers_n_by_fit() {
    let Some(e) = env() else { return };
    let src = tempfile::TempDir::new().unwrap();
    bytes_repo(&src.path().join("r"));
    let m = Tmpfs::mount(&e, "c2", "size=16m,nr_inodes=4096");
    let dest = m.0.join("wt");
    let workers = workers_n();
    run_case(
        &e,
        "c2",
        Step::AddWithCheckout {
            source: &src.path().join("r"),
            dest: &dest,
            workers,
        },
        &[I, W, R],
        StorageFullBy::Fit,
    );
}

#[test]
#[ignore = "BF-8 box test"]
fn c3a_inodes_workers_1_by_line() {
    let Some(e) = env() else { return };
    let src = tempfile::TempDir::new().unwrap();
    inode_repo(&src.path().join("r"));
    let m = Tmpfs::mount(&e, "c3a", "size=64m,nr_inodes=32");
    run_case(
        &e,
        "c3a",
        Step::AddWithCheckout {
            source: &src.path().join("r"),
            dest: &m.0.join("wt"),
            workers: 1,
        },
        &[I, S, R],
        StorageFullBy::Line,
    );
}

#[test]
#[ignore = "BF-8 box test"]
fn c3b_inodes_workers_n_by_line() {
    let Some(e) = env() else { return };
    let src = tempfile::TempDir::new().unwrap();
    inode_repo(&src.path().join("r"));
    let m = Tmpfs::mount(&e, "c3b", "size=64m,nr_inodes=32");
    let workers = workers_n();
    run_case(
        &e,
        "c3b",
        Step::AddWithCheckout {
            source: &src.path().join("r"),
            dest: &m.0.join("wt"),
            workers,
        },
        &[I, S, R],
        StorageFullBy::Line,
    );
}

#[test]
#[ignore = "BF-8 box test"]
fn c4_prefilled_bytes_no_checkout_by_line() {
    let Some(e) = env() else { return };
    let src = tempfile::TempDir::new().unwrap();
    small_repo(&src.path().join("r"));
    let m = Tmpfs::mount(&e, "c4", "size=1m");
    fill_bytes(&m.0);
    run_case(
        &e,
        "c4",
        Step::AddNoCheckout {
            source: &src.path().join("r"),
            dest: &m.0.join("wt"),
        },
        &[I, S],
        StorageFullBy::Line,
    );
}

#[test]
#[ignore = "BF-8 box test"]
fn c4b_prefilled_inodes_no_checkout_by_line() {
    let Some(e) = env() else { return };
    let src = tempfile::TempDir::new().unwrap();
    small_repo(&src.path().join("r"));
    let m = Tmpfs::mount(&e, "c4b", "size=1m,nr_inodes=64");
    fill_inodes(&m.0);
    run_case(
        &e,
        "c4b",
        Step::AddNoCheckout {
            source: &src.path().join("r"),
            dest: &m.0.join("wt"),
        },
        &[I, S],
        StorageFullBy::Line,
    );
}

#[test]
#[ignore = "BF-8 box test"]
fn c5_reset_bytes_by_floor() {
    let Some(e) = env() else { return };
    let src = tempfile::TempDir::new().unwrap();
    let repo = src.path().join("r");
    bytes_repo(&repo);
    let m = Tmpfs::mount(&e, "c5", "size=16m");
    let wt = m.0.join("wt");
    git_ok(
        &repo,
        &[
            "worktree",
            "add",
            "--detach",
            "--no-checkout",
            "--",
            wt.to_str().unwrap(),
            "HEAD",
        ],
    );
    run_case(
        &e,
        "c5",
        Step::ResetHard { worktree: &wt },
        &[W, R],
        StorageFullBy::Floor,
    );
}

#[test]
#[ignore = "BF-8 box test"]
fn c5b_reset_inodes_by_line() {
    let Some(e) = env() else { return };
    let src = tempfile::TempDir::new().unwrap();
    let repo = src.path().join("r");
    inode_repo(&repo);
    let m = Tmpfs::mount(&e, "c5b", "size=64m,nr_inodes=40");
    let wt = m.0.join("wt");
    git_ok(
        &repo,
        &[
            "worktree",
            "add",
            "--detach",
            "--no-checkout",
            "--",
            wt.to_str().unwrap(),
            "HEAD",
        ],
    );
    run_case(
        &e,
        "c5b",
        Step::ResetHard { worktree: &wt },
        &[S, R],
        StorageFullBy::Line,
    );
}

#[test]
#[ignore = "BF-8 box test"]
fn c6_common_dir_full_by_line() {
    let Some(e) = env() else { return };
    let srcfs = Tmpfs::mount(&e, "c6src", "size=1m");
    let repo = srcfs.0.join("r");
    small_repo(&repo);
    fill_bytes(&srcfs.0);
    let m = Tmpfs::mount(&e, "c6", "size=64m");
    run_case(
        &e,
        "c6",
        Step::AddNoCheckout {
            source: &repo,
            dest: &m.0.join("wt"),
        },
        &[I, S],
        StorageFullBy::Line,
    );
}

/// C7: the real `create()` path a subagent uses, with handle_request's B2-2 ownership rule replayed
/// (stat before, reclaim on a typed abort), on each fill and both strategies it can choose.
fn c7_one(e: &Env, case: &str, repo: &Path, dest: &Path, mode: CreationMode, workers: usize) {
    let dest_absent = matches!(dest.try_exists(), Ok(false));
    let mode_name = format!("{mode:?}");
    let res = WorktreeBuilder::new(repo, dest)
        .working_tree_mode(WorkingTreeMode::PreserveWorkingTree)
        .creation_mode(mode)
        .parallelism(workers)
        .create();
    let err = res
        .err()
        .unwrap_or_else(|| panic!("{case}: create must fail on the full filesystem"));
    let abort = fuigo_fast_worktree::is_copy_abort(&err);
    if abort && dest_absent {
        let _ = fuigo_fast_worktree::remove_worktree(dest);
        fuigo_fast_worktree::remove_stale_worktree_registration(repo, dest);
    }
    let by = err
        .chain()
        .find_map(|c| c.downcast_ref::<GitStorageFull>())
        .map(|g| g.by);
    let tracked = err.chain().any(|c| {
        c.downcast_ref::<fuigo_fast_worktree::TrackedCopyError>()
            .is_some()
    });
    let list = git(repo, &["worktree", "list", "--porcelain"]);
    let entries = String::from_utf8_lossy(&list.stdout)
        .matches("worktree ")
        .count();
    let reg = repo.join(".git/worktrees").join(dest.file_name().unwrap());
    let rec = format!(
        "mode: {mode_name}\nerror: {err:#}\nis_copy_abort: {abort}\nGitStorageFull.by: {by:?}\nTrackedCopyError: {tracked}\n\
         dest exists after: {}\nworktree list entries: {entries}\n.git/worktrees/<id> exists: {}\n",
        dest.exists(),
        reg.exists()
    );
    std::fs::write(e.out.join(format!("{case}.txt")), &rec).unwrap();
    eprintln!("==== {case}\n{rec}");
    assert!(abort, "{case}: the failure must be a typed abort\n{rec}");
    assert!(
        !dest.exists() && entries == 1 && !reg.exists(),
        "{case}: nothing may be left\n{rec}"
    );
}

#[test]
#[ignore = "BF-8 box test"]
fn c7_fuigo_api_create_path() {
    let Some(e) = env() else { return };
    let src = tempfile::TempDir::new().unwrap();
    let bytes = src.path().join("bytes");
    bytes_repo(&bytes);
    let inodes = src.path().join("inodes");
    inode_repo(&inodes);
    let small = src.path().join("small");
    small_repo(&small);
    let n = workers_n();
    {
        let m = Tmpfs::mount(&e, "c7-checkout-bytes", "size=16m,nr_inodes=4096");
        c7_one(
            &e,
            "c7-checkout-bytes",
            &bytes,
            &m.0.join("wt"),
            CreationMode::GitCheckout,
            1,
        );
    }
    {
        let m = Tmpfs::mount(&e, "c7-checkout-inodes", "size=64m,nr_inodes=32");
        c7_one(
            &e,
            "c7-checkout-inodes",
            &inodes,
            &m.0.join("wt"),
            CreationMode::GitCheckout,
            n,
        );
    }
    {
        let m = Tmpfs::mount(&e, "c7-copy-bytes", "size=16m,nr_inodes=4096");
        c7_one(
            &e,
            "c7-copy-bytes",
            &bytes,
            &m.0.join("wt"),
            CreationMode::Linked,
            1,
        );
    }
    {
        let m = Tmpfs::mount(&e, "c7-copy-prefilled", "size=1m");
        fill_bytes(&m.0);
        c7_one(
            &e,
            "c7-copy-prefilled",
            &small,
            &m.0.join("wt"),
            CreationMode::Linked,
            1,
        );
    }
}

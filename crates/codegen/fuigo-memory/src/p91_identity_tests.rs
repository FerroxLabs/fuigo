//! P91 R2: workspace memory identity includes the remote HOST.
use crate::storage::MemoryStorage;

pub(crate) fn git_repo_with_origin(dir: &std::path::Path, origin: &str) {
    std::fs::create_dir_all(dir).unwrap();
    let repo = git2::Repository::init(dir).unwrap();
    repo.remote("origin", origin).unwrap();
}

/// Audit probe `probe_workspace_identity_ignores_host_and_is_attacker_choosable`,
/// inverted: the same `org/repo` on another host is a different memory directory.
#[test]
fn same_org_repo_on_another_host_never_shares_memory() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    let attacker = temp.path().join("cloned-from-evil");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    git_repo_with_origin(&attacker, "https://evil.example/victimcorp/secret-app");
    let a = MemoryStorage::new(&victim, Some(&root));
    let b = MemoryStorage::new(&attacker, Some(&root));
    assert_ne!(a.workspace_dir(), b.workspace_dir());
}

/// ssh, https, scheme-ssh-with-port, user info, host case and `.git` forms of ONE
/// host still share a directory.
#[test]
fn forms_of_the_same_host_share_memory() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let mut dirs = Vec::new();
    for (i, origin) in [
        "git@github.com:acme/widgets.git",
        "https://github.com/acme/widgets",
        "https://user@GitHub.com/acme/widgets.git/",
        "ssh://git@github.com:22/acme/widgets.git",
        "http://github.com:80/acme/widgets",
    ]
    .into_iter()
    .enumerate()
    {
        let clone = temp.path().join(format!("clone{i}"));
        git_repo_with_origin(&clone, origin);
        dirs.push(MemoryStorage::new(&clone, Some(&root)).workspace_dir().to_path_buf());
    }
    assert!(dirs.windows(2).all(|w| w[0] == w[1]), "{dirs:?}");
    for (host, origin) in [
        ("gitlab", "git@gitlab.com:acme/widgets.git"),
        ("subdomain", "https://evil.github.com/acme/widgets"),
        ("lookalike", "https://github.com.evil.example/acme/widgets"),
    ] {
        let clone = temp.path().join(host);
        git_repo_with_origin(&clone, origin);
        assert_ne!(MemoryStorage::new(&clone, Some(&root)).workspace_dir(), dirs[0], "{origin}");
    }
}

/// Name of the pre-P91 directory for `org/repo` (slug + blake3 of `org/repo`).
fn legacy_dir(root: &std::path::Path, org_repo: &str) -> std::path::PathBuf {
    let slug = org_repo.rsplit('/').next().unwrap();
    root.join(format!("{slug}-{}", &blake3::hash(org_repo.as_bytes()).to_hex()[..8]))
}

/// A legacy directory as the old code left it: the `MEMORY.md` header names the
/// clone that created it, a session log carries a provenance record, and there is
/// an index whose rows point at the old location.
fn seed_legacy(dir: &std::path::Path, creator: &std::path::Path, provenance: Option<&std::path::Path>) {
    std::fs::create_dir_all(dir.join("sessions")).unwrap();
    std::fs::write(
        dir.join("MEMORY.md"),
        format!(
            "# Project Memory — {}\n\n> Auto-populated by dream consolidation. Edit freely.\n\n## Facts\n\n- VICTIM_CANARY deploy uses make\n",
            creator.display()
        ),
    )
    .unwrap();
    if let Some(workspace) = provenance {
        let record =
            crate::safety::capture_record("Decision: db = SQLite", "s", &workspace.display().to_string(), "user", 1)
                .unwrap();
        std::fs::write(dir.join("sessions/2026-09-01-x-abc.md"), format!("## Session\n\n{record}")).unwrap();
    }
    std::fs::write(dir.join("index.sqlite"), "stale index").unwrap();
}

fn memory_text(storage: &MemoryStorage) -> String {
    std::fs::read_to_string(storage.workspace_memory_file()).unwrap_or_default()
}

/// The user's own clone (same host as the recorded creator) adopts the legacy
/// directory: content moves, the stale index is dropped, the old name is gone.
#[test]
fn legacy_memory_migrates_to_the_proven_host() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    let legacy = legacy_dir(&root, "victimcorp/secret-app");
    seed_legacy(&legacy, &victim, Some(&victim.join("sub")));
    let storage = MemoryStorage::new(&victim, Some(&root));
    assert_ne!(storage.workspace_dir(), legacy.as_path());
    assert!(!legacy.exists(), "legacy directory must have been moved");
    assert!(memory_text(&storage).contains("VICTIM_CANARY"));
    assert!(storage.workspace_dir().join("sessions/2026-09-01-x-abc.md").is_file());
    assert!(!storage.workspace_dir().join("index.sqlite").exists());
    // A second clone over https of the same host now finds the migrated directory.
    let other = temp.path().join("victim-https");
    git_repo_with_origin(&other, "https://github.com/victimcorp/secret-app");
    assert_eq!(MemoryStorage::new(&other, Some(&root)).workspace_dir(), storage.workspace_dir());
}

/// The hostile clone opened FIRST still cannot take the legacy directory: its
/// recorded creator is a clone of a different host. Nothing is moved or deleted,
/// and the genuine clone can still adopt it afterwards.
#[test]
fn hostile_host_opened_first_cannot_adopt_legacy_memory() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    let attacker = temp.path().join("cloned-from-evil");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    git_repo_with_origin(&attacker, "https://evil.example/victimcorp/secret-app");
    let legacy = legacy_dir(&root, "victimcorp/secret-app");
    seed_legacy(&legacy, &victim, None);
    let hostile = MemoryStorage::new(&attacker, Some(&root));
    assert!(legacy.join("MEMORY.md").is_file(), "legacy directory must be untouched");
    assert!(!memory_text(&hostile).contains("VICTIM_CANARY"));
    let genuine = MemoryStorage::new(&victim, Some(&root));
    assert!(memory_text(&genuine).contains("VICTIM_CANARY"));
    assert_ne!(genuine.workspace_dir(), hostile.workspace_dir());
}

/// Unknown provenance (header edited away, recorded clone deleted) or mixed
/// provenance (both hosts wrote to it) is never adopted automatically.
#[test]
fn unprovable_or_mixed_legacy_memory_is_left_in_place() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    let attacker = temp.path().join("cloned-from-evil");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    git_repo_with_origin(&attacker, "https://evil.example/victimcorp/secret-app");
    let legacy = legacy_dir(&root, "victimcorp/secret-app");

    // Recorded creator no longer exists.
    seed_legacy(&legacy, &temp.path().join("deleted-clone"), None);
    let storage = MemoryStorage::new(&victim, Some(&root));
    assert!(legacy.join("MEMORY.md").is_file());
    assert!(!memory_text(&storage).contains("VICTIM_CANARY"));
    std::fs::remove_dir_all(storage.workspace_dir()).ok();

    // Both hosts recorded: the folder may already be poisoned; the user decides.
    seed_legacy(&legacy, &victim, Some(&attacker));
    for clone in [&victim, &attacker] {
        let storage = MemoryStorage::new(clone, Some(&root));
        assert!(legacy.join("MEMORY.md").is_file());
        assert!(!memory_text(&storage).contains("VICTIM_CANARY"));
    }
}

/// Astra P91 r1 #2: evidence that cannot be read completely never proves
/// ownership. A small hostile-host capture next to an oversized victim header must
/// not migrate the directory to the hostile host.
#[test]
fn incomplete_evidence_never_authorizes_adoption() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    let attacker = temp.path().join("cloned-from-evil");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    git_repo_with_origin(&attacker, "https://evil.example/victimcorp/secret-app");
    let legacy = legacy_dir(&root, "victimcorp/secret-app");
    seed_legacy(&legacy, &victim, Some(&attacker));
    // The victim header becomes unreadable evidence (oversized); only the hostile capture is small.
    let mut big = std::fs::read_to_string(legacy.join("MEMORY.md")).unwrap();
    big.push_str(&"x".repeat(9 << 20));
    std::fs::write(legacy.join("MEMORY.md"), big).unwrap();
    let hostile = MemoryStorage::new(&attacker, Some(&root));
    assert!(legacy.join("MEMORY.md").is_file(), "legacy directory must be untouched");
    assert!(!hostile.workspace_dir().join("MEMORY.md").exists());
    // A provenance record that cannot be parsed is incomplete evidence too.
    let clone = temp.path().join("victim-other");
    git_repo_with_origin(&clone, "git@github.com:victimcorp/other-app.git");
    let legacy2 = legacy_dir(&root, "victimcorp/other-app");
    seed_legacy(&legacy2, &clone, None);
    std::fs::write(
        legacy2.join("sessions/2026-09-02-x-def.md"),
        "<!-- fuigo-memory-provenance {not json -->",
    )
    .unwrap();
    let other = MemoryStorage::new(&clone, Some(&root));
    assert!(legacy2.join("MEMORY.md").is_file());
    assert!(!memory_text(&other).contains("VICTIM_CANARY"));
}

/// Astra P91 r1 #6/#5: only the index database and its sidecars are moved aside
/// (never deleted, never a user note), before the directory gets its new name.
#[test]
fn migration_moves_only_index_files_aside() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    let legacy = legacy_dir(&root, "victimcorp/secret-app");
    seed_legacy(&legacy, &victim, None);
    let index_files = ["index.sqlite-wal", "index.sqlite-shm", "index.h-box1.sqlite", "index.h-box1.sqlite-journal"];
    let user_files = ["index.sqlite-notes.md", "index.sqlite.backup", "index.h-.sqlite", "myindex.sqlite"];
    for name in index_files.iter().chain(&user_files) {
        std::fs::write(legacy.join(name), name).unwrap();
    }
    let storage = MemoryStorage::new(&victim, Some(&root));
    let dir = storage.workspace_dir();
    assert!(memory_text(&storage).contains("VICTIM_CANARY"));
    let asides: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with(".pre-p91-index-"))
        .collect();
    assert_eq!(asides.len(), 1, "{asides:?}");
    for name in index_files.iter().chain(&["index.sqlite"]) {
        assert!(!dir.join(name).exists(), "{name} left in place");
        assert!(asides[0].join(name).is_file(), "{name} not kept aside");
    }
    for name in user_files {
        assert_eq!(std::fs::read_to_string(dir.join(name)).unwrap(), name, "{name} touched");
    }
    assert!(storage.list_memory_files().unwrap().iter().all(|p| !p.to_string_lossy().contains(".pre-p91-index")));
}

/// Astra P91 r1 #7: the legacy name is found with the pre-P91 slug, which for an
/// origin ending in `.git/` was `repo-git`.
#[test]
fn legacy_name_uses_the_old_slug_for_dot_git_slash_origins() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    git_repo_with_origin(&victim, "https://github.com/acme/widgets.git/");
    let legacy = root.join(format!(
        "widgets-git-{}",
        &blake3::hash(b"acme/widgets.git").to_hex()[..8]
    ));
    seed_legacy(&legacy, &victim, None);
    let storage = MemoryStorage::new(&victim, Some(&root));
    assert!(!legacy.exists());
    assert!(memory_text(&storage).contains("VICTIM_CANARY"));
}

/// Astra P91 r1 #4: a remote identity's directory name carries 64 bits of hash.
#[test]
fn remote_identity_directory_has_a_64_bit_suffix() {
    let temp = tempfile::tempdir().unwrap();
    let clone = temp.path().join("c");
    git_repo_with_origin(&clone, "git@github.com:acme/widgets.git");
    let storage = MemoryStorage::new(&clone, Some(&temp.path().join("memroot")));
    let name = storage.workspace_dir().file_name().unwrap().to_string_lossy().into_owned();
    let (slug, hash) = name.rsplit_once('-').unwrap();
    assert_eq!(slug, "widgets");
    assert_eq!(hash, &blake3::hash(b"github.com/acme/widgets").to_hex()[..16]);
}

/// Astra P91 r2 #3: a provenance record that is valid JSON but does not name its
/// workspace is unreadable evidence, so ownership is unproven.
#[test]
fn provenance_without_a_workspace_makes_ownership_unproven() {
    for record in ["{}", "null", "{\"session\":\"s\"}", "{\"workspace\":7}"] {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("memroot");
        let victim = temp.path().join("victim");
        git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
        let legacy = legacy_dir(&root, "victimcorp/secret-app");
        seed_legacy(&legacy, &victim, None);
        std::fs::write(
            legacy.join("sessions/2026-09-03-x-ghi.md"),
            format!("Decision: x\n\n<!-- fuigo-memory-provenance {record} -->\n"),
        )
        .unwrap();
        let storage = MemoryStorage::new(&victim, Some(&root));
        assert!(legacy.join("MEMORY.md").is_file(), "{record}: adopted");
        assert!(!memory_text(&storage).contains("VICTIM_CANARY"), "{record}");
    }
}

/// Astra P91 r2 #4: an existing `.pre-p91-index*` entry (here a symlink to
/// another workspace) is never followed or overwritten.
#[cfg(unix)]
#[test]
fn quarantine_never_follows_an_existing_link() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    let legacy = legacy_dir(&root, "victimcorp/secret-app");
    seed_legacy(&legacy, &victim, None);
    let elsewhere = temp.path().join("other-workspace");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::write(elsewhere.join("index.sqlite"), "OTHER_DB").unwrap();
    std::os::unix::fs::symlink(&elsewhere, legacy.join(".pre-p91-index")).unwrap();
    let storage = MemoryStorage::new(&victim, Some(&root));
    assert!(memory_text(&storage).contains("VICTIM_CANARY"));
    assert_eq!(std::fs::read_to_string(elsewhere.join("index.sqlite")).unwrap(), "OTHER_DB");
}

/// Astra P91 r2 #5 / r3 #3: a starter waits for the migration lock before it
/// decides anything, so it can never publish an empty destination while another
/// starter is moving the legacy directory there. Deterministic: the test holds the
/// lock itself.
#[test]
fn migration_waits_for_the_lock() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    let legacy = legacy_dir(&root, "victimcorp/secret-app");
    seed_legacy(&legacy, &victim, None);
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(root.join(".memory-migrate.lock"))
        .unwrap();
    lock.lock().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let (v, r) = (victim.clone(), root.clone());
    let starter = std::thread::spawn(move || {
        let storage = MemoryStorage::new(&v, Some(&r));
        tx.send(()).unwrap();
        storage
    });
    assert!(
        rx.recv_timeout(std::time::Duration::from_millis(500)).is_err(),
        "migration ran without the lock"
    );
    assert!(legacy.join("MEMORY.md").is_file());
    lock.unlock().unwrap();
    let storage = starter.join().unwrap();
    assert!(!legacy.exists());
    assert!(memory_text(&storage).contains("VICTIM_CANARY"));
}

/// Astra P91 r3 #3: clones whose origins differ only by a trailing `.git/` share
/// the new directory AND both consider either pre-P91 name.
#[test]
fn equivalent_origins_consider_both_legacy_names() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let slash = temp.path().join("clone-slash");
    let plain = temp.path().join("clone-plain");
    git_repo_with_origin(&slash, "https://github.com/acme/widgets.git/");
    git_repo_with_origin(&plain, "git@github.com:acme/widgets.git");
    let legacy = root.join(format!(
        "widgets-git-{}",
        &blake3::hash(b"acme/widgets.git").to_hex()[..8]
    ));
    seed_legacy(&legacy, &slash, None);
    let storage = MemoryStorage::new(&plain, Some(&root));
    assert!(!legacy.exists());
    assert!(memory_text(&storage).contains("VICTIM_CANARY"));
    assert_eq!(MemoryStorage::new(&slash, Some(&root)).workspace_dir(), storage.workspace_dir());
}

/// P97: a legacy folder that is not adopted produces a visible one-time notice naming both folders.
#[test]
fn not_adopted_legacy_memory_yields_a_notice_naming_both_folders() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    let attacker = temp.path().join("cloned-from-evil");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    git_repo_with_origin(&attacker, "https://evil.example/victimcorp/secret-app");
    let legacy = legacy_dir(&root, "victimcorp/secret-app");
    seed_legacy(&legacy, &victim, None);
    let hostile = MemoryStorage::new(&attacker, Some(&root));
    let [notice] = hostile.legacy_notices() else {
        panic!("expected one notice, got {:?}", hostile.legacy_notices());
    };
    assert_eq!(notice.legacy, legacy);
    assert_eq!(notice.new, hostile.workspace_dir());
    let text = notice.message();
    assert!(text.contains(&legacy.display().to_string()), "{text}");
    assert!(text.contains(&hostile.workspace_dir().display().to_string()), "{text}");
    assert!(text.contains("by hand") && text.contains("user guide"), "{text}");
    assert!(!text.contains('\u{2014}'));
    // It also went through the startup notice queue the shell and pager already replay.
    assert!(fuigo_file_utils::destination_gate::withheld_notices().contains(&text));
    assert!(legacy.join("MEMORY.md").is_file(), "legacy directory must be untouched");
}

/// P97: a second start (same legacy folder, same destination) says nothing again.
#[test]
fn second_start_produces_no_notice() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    let attacker = temp.path().join("cloned-from-evil");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    git_repo_with_origin(&attacker, "https://evil.example/victimcorp/secret-app");
    seed_legacy(&legacy_dir(&root, "victimcorp/secret-app"), &victim, None);
    assert_eq!(MemoryStorage::new(&attacker, Some(&root)).legacy_notices().len(), 1);
    assert!(MemoryStorage::new(&attacker, Some(&root)).legacy_notices().is_empty());
    assert!(MemoryStorage::new(&attacker, Some(&root)).legacy_notices().is_empty());
}

/// P97: an adopted folder and a start with no legacy folder produce no notice.
#[test]
fn adopted_or_absent_legacy_memory_yields_no_notice() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    assert!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().is_empty(), "no legacy folder");
    let other = temp.path().join("other");
    git_repo_with_origin(&other, "git@github.com:acme/widgets.git");
    let legacy = legacy_dir(&root, "acme/widgets");
    seed_legacy(&legacy, &other, Some(&other.join("sub")));
    let adopted = MemoryStorage::new(&other, Some(&root));
    assert!(!legacy.exists(), "legacy directory must have been moved");
    assert!(adopted.legacy_notices().is_empty(), "{:?}", adopted.legacy_notices());
}

/// What a 1.0.20 binary does in this repository after 1.0.21 adopted its folder: it recomputes the
/// old `org/repo` name, recreates the folder with its `MEMORY.md` template, and writes there.
fn old_version_recreates_legacy(legacy: &std::path::Path, workspace: &std::path::Path, note: Option<&str>) {
    std::fs::create_dir_all(legacy.join("sessions")).unwrap();
    std::fs::write(
        legacy.join("MEMORY.md"),
        format!(
            "# Project Memory \u{2014} {}\n\n> Auto-populated by dream consolidation. Edit freely.\n",
            workspace.display()
        ),
    )
    .unwrap();
    std::fs::write(legacy.join("index.sqlite"), "index of the old version").unwrap();
    std::fs::write(legacy.join(".memory-write.lock"), "").unwrap();
    if let Some(note) = note {
        std::fs::write(legacy.join("sessions/2026-10-03-x-abc.md"), format!("## Session\n\n- {note}\n")).unwrap();
    }
}

/// R110 (M1): 1.0.21 adopts the legacy folder, 1.0.20 then recreates it and writes there, and the
/// next 1.0.21 start says so once, naming both folders. Nothing is moved, merged or deleted.
#[test]
fn downgrade_round_trip_notices_the_recreated_legacy_folder_once() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    let legacy = legacy_dir(&root, "victimcorp/secret-app");
    seed_legacy(&legacy, &victim, Some(&victim.join("sub")));
    let adopted = MemoryStorage::new(&victim, Some(&root));
    assert!(adopted.legacy_notices().is_empty(), "{:?}", adopted.legacy_notices());
    assert!(!legacy.exists(), "1.0.21 must have adopted the legacy folder");
    let new_dir = adopted.workspace_dir().to_path_buf();

    old_version_recreates_legacy(&legacy, &victim, Some("DOWNGRADE_NOTE written by 1.0.20"));

    let back = MemoryStorage::new(&victim, Some(&root));
    assert_eq!(back.workspace_dir(), new_dir.as_path());
    let [notice] = back.legacy_notices() else {
        panic!("expected one notice, got {:?}", back.legacy_notices());
    };
    assert_eq!(notice.legacy, legacy);
    assert_eq!(notice.new, new_dir);
    let text = notice.message();
    assert!(text.contains(&legacy.display().to_string()), "{text}");
    assert!(text.contains(&new_dir.display().to_string()), "{text}");
    assert!(text.contains("by hand") && text.contains("user guide"), "{text}");
    assert!(!text.contains('\u{2014}'), "{text}");
    assert!(fuigo_file_utils::destination_gate::withheld_notices().contains(&text));
    // Nothing merged, moved or deleted.
    let old_note = std::fs::read_to_string(legacy.join("sessions/2026-10-03-x-abc.md")).unwrap();
    assert!(old_note.contains("DOWNGRADE_NOTE"));
    assert!(memory_text(&back).contains("VICTIM_CANARY"));
    assert!(!memory_text(&back).contains("DOWNGRADE_NOTE"));
    // Once only.
    assert!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().is_empty());
    assert!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().is_empty());
}

/// R110 (M1): a legacy folder the old version only initialised (template, index, lock, empty
/// sessions) holds no notes, so it is not worth a notice.
#[test]
fn recreated_legacy_folder_without_notes_yields_no_notice() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    let legacy = legacy_dir(&root, "victimcorp/secret-app");
    seed_legacy(&legacy, &victim, Some(&victim.join("sub")));
    assert!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().is_empty());
    old_version_recreates_legacy(&legacy, &victim, None);
    assert!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().is_empty());
    // Once the old version writes a note, the next start says so.
    std::fs::write(legacy.join("sessions/2026-10-04-y-def.md"), "## Session\n\n- LATER_NOTE\n").unwrap();
    assert_eq!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().len(), 1);
}

/// R110 (M1): after the user merges by hand and removes the legacy folder, a later recreation by
/// the old version is news again and produces a new notice.
#[test]
fn legacy_folder_recreated_after_a_manual_merge_is_noticed_again() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    let legacy = legacy_dir(&root, "victimcorp/secret-app");
    seed_legacy(&legacy, &victim, Some(&victim.join("sub")));
    assert!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().is_empty());
    old_version_recreates_legacy(&legacy, &victim, Some("FIRST_DOWNGRADE"));
    assert_eq!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().len(), 1);
    std::fs::remove_dir_all(&legacy).unwrap();
    assert!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().is_empty());
    old_version_recreates_legacy(&legacy, &victim, Some("SECOND_DOWNGRADE"));
    assert_eq!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().len(), 1);
}

/// R110 (M1): a legacy folder that P97 already announced as not adopted is not announced a
/// second time once the new folder exists.
#[test]
fn not_adopted_legacy_folder_is_not_announced_twice() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    let attacker = temp.path().join("cloned-from-evil");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    git_repo_with_origin(&attacker, "https://evil.example/victimcorp/secret-app");
    seed_legacy(&legacy_dir(&root, "victimcorp/secret-app"), &victim, None);
    let first = MemoryStorage::new(&attacker, Some(&root));
    assert_eq!(first.legacy_notices().len(), 1);
    // The new folder now exists (a temp-dir cwd is ephemeral, so `ensure_initialized` would skip it).
    std::fs::create_dir_all(first.workspace_dir()).unwrap();
    std::fs::write(first.workspace_dir().join("MEMORY.md"), "# Project Memory\n").unwrap();
    let second = MemoryStorage::new(&attacker, Some(&root));
    assert!(second.legacy_notices().is_empty(), "{:?}", second.legacy_notices());
}

/// Astra P110 r1 #3: a folder P97 announced before this version existed (only the P97 marker is
/// there) is not announced again once the new folder exists.
#[test]
fn folder_announced_by_an_earlier_version_is_not_announced_again() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    let attacker = temp.path().join("cloned-from-evil");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    git_repo_with_origin(&attacker, "https://evil.example/victimcorp/secret-app");
    seed_legacy(&legacy_dir(&root, "victimcorp/secret-app"), &victim, None);
    let first = MemoryStorage::new(&attacker, Some(&root));
    assert_eq!(first.legacy_notices().len(), 1);
    // What a P97-only binary leaves behind: its own marker, none of this version's.
    let mut removed = 0;
    for entry in std::fs::read_dir(&root).unwrap().flatten() {
        if entry.file_name().to_string_lossy().starts_with(".legacy-stranded-notice-") {
            std::fs::remove_file(entry.path()).unwrap();
            removed += 1;
        }
    }
    assert_eq!(removed, 1);
    std::fs::create_dir_all(first.workspace_dir()).unwrap();
    std::fs::write(first.workspace_dir().join("MEMORY.md"), "# Project Memory\n").unwrap();
    let second = MemoryStorage::new(&attacker, Some(&root));
    assert!(second.legacy_notices().is_empty(), "{:?}", second.legacy_notices());
}

/// Astra P110 r1 #4: after a notice, the user removes the legacy folder AND clears the new one;
/// the start that finds both absent still forgets the notice, so a later recreation is announced.
#[test]
fn recreation_after_both_folders_were_removed_is_noticed_again() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    let legacy = legacy_dir(&root, "victimcorp/secret-app");
    seed_legacy(&legacy, &victim, Some(&victim.join("sub")));
    let adopted = MemoryStorage::new(&victim, Some(&root));
    let new_dir = adopted.workspace_dir().to_path_buf();
    old_version_recreates_legacy(&legacy, &victim, Some("FIRST_DOWNGRADE"));
    assert_eq!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().len(), 1);
    std::fs::remove_dir_all(&legacy).unwrap();
    std::fs::remove_dir_all(&new_dir).unwrap();
    assert!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().is_empty());
    std::fs::create_dir_all(&new_dir).unwrap();
    std::fs::write(new_dir.join("MEMORY.md"), "# Project Memory\n").unwrap();
    old_version_recreates_legacy(&legacy, &victim, Some("SECOND_DOWNGRADE"));
    assert_eq!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().len(), 1);
}

/// Astra P110 r2 #3: P97 refuses a folder whose recorded clone is missing; once that clone exists
/// the folder is adopted; if an old version then recreates it with notes, that is announced.
#[test]
fn adoption_after_an_earlier_refusal_forgets_the_old_notice() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    let second = temp.path().join("victim-second-clone");
    git_repo_with_origin(&second, "git@github.com:victimcorp/secret-app.git");
    let legacy = legacy_dir(&root, "victimcorp/secret-app");
    seed_legacy(&legacy, &victim, None);
    // The recorded clone does not exist yet: not adopted, P97 notice.
    assert_eq!(MemoryStorage::new(&second, Some(&root)).legacy_notices().len(), 1);
    assert!(legacy.exists());
    // It appears: the next start adopts the folder.
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    let adopted = MemoryStorage::new(&second, Some(&root));
    assert!(adopted.legacy_notices().is_empty(), "{:?}", adopted.legacy_notices());
    assert!(!legacy.exists(), "the folder must have been adopted");
    // 1.0.20 recreates it and writes there: announced.
    old_version_recreates_legacy(&legacy, &second, Some("AFTER_ADOPTION"));
    assert_eq!(MemoryStorage::new(&second, Some(&root)).legacy_notices().len(), 1);
}

/// Astra P110 r4 #1: with the new folder published, a start that finds a recreated legacy folder
/// decides about its notice under the migration lock, the same lock an adopter holds while it
/// retires both markers. Deterministic: the test holds the lock itself.
#[test]
fn stranded_notice_waits_for_the_migration_lock() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    let legacy = legacy_dir(&root, "victimcorp/secret-app");
    seed_legacy(&legacy, &victim, None);
    assert!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().is_empty());
    assert!(!legacy.exists(), "the folder must have been adopted");
    old_version_recreates_legacy(&legacy, &victim, Some("WAITS_FOR_LOCK"));
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(root.join(".memory-migrate.lock"))
        .unwrap();
    lock.lock().unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let (v, r) = (victim.clone(), root.clone());
    let starter = std::thread::spawn(move || {
        let notices = MemoryStorage::new(&v, Some(&r)).legacy_notices().len();
        tx.send(()).unwrap();
        notices
    });
    assert!(
        rx.recv_timeout(std::time::Duration::from_millis(500)).is_err(),
        "the stranded-folder notice was decided without the migration lock"
    );
    lock.unlock().unwrap();
    assert_eq!(starter.join().unwrap(), 1);
}

/// Astra P110 r5 #1 #2: suppression is never written on the strength of another marker. A start
/// that stays silent only because P97 already announced the folder leaves no marker of its own, so
/// when an interleaved cleanup (or a start that could not take the lock) retires the P97 marker,
/// the recreated folder is announced instead of silenced for good. Replays that end state.
#[test]
fn silence_from_the_p97_marker_writes_no_marker_of_its_own() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    let attacker = temp.path().join("cloned-from-evil");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    git_repo_with_origin(&attacker, "https://evil.example/victimcorp/secret-app");
    let legacy = legacy_dir(&root, "victimcorp/secret-app");
    seed_legacy(&legacy, &victim, None);
    let markers = |prefix: &str| {
        std::fs::read_dir(&root)
            .unwrap()
            .flatten()
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(prefix))
            .map(|entry| entry.path())
            .collect::<Vec<_>>()
    };
    let first = MemoryStorage::new(&attacker, Some(&root));
    assert_eq!(first.legacy_notices().len(), 1);
    // Start again before the new folder exists: P97 says it was announced, so no marker is added.
    for stranded in markers(".legacy-stranded-notice-") {
        std::fs::remove_file(stranded).unwrap();
    }
    assert!(MemoryStorage::new(&attacker, Some(&root)).legacy_notices().is_empty());
    assert!(markers(".legacy-stranded-notice-").is_empty(), "silence wrote a marker before the move");
    // And again once the new folder exists.
    std::fs::create_dir_all(first.workspace_dir()).unwrap();
    std::fs::write(first.workspace_dir().join("MEMORY.md"), "# Project Memory\n").unwrap();
    assert!(MemoryStorage::new(&attacker, Some(&root)).legacy_notices().is_empty());
    assert!(markers(".legacy-stranded-notice-").is_empty(), "silence wrote a marker after the move");
    // A delayed cleanup retires the P97 marker while the folder holds notes: announced, not lost.
    for p97 in markers(".legacy-notice-") {
        std::fs::remove_file(p97).unwrap();
    }
    old_version_recreates_legacy(&legacy, &attacker, Some("AFTER_RETIREMENT"));
    assert_eq!(MemoryStorage::new(&attacker, Some(&root)).legacy_notices().len(), 1);
}

/// Astra P110 r6: a start for one clone announces a legacy folder it may not adopt; another host's
/// clone then adopts that folder (retiring only its own markers), and an older version recreates it
/// with new notes. The first clone's markers are about the folder that moved away, so the recreated
/// one is announced, not silenced for good.
#[test]
fn recreated_legacy_folder_is_announced_despite_another_destinations_markers() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    let attacker = temp.path().join("cloned-from-evil");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    git_repo_with_origin(&attacker, "https://evil.example/victimcorp/secret-app");
    let legacy = legacy_dir(&root, "victimcorp/secret-app");
    seed_legacy(&legacy, &victim, None);
    let first = MemoryStorage::new(&attacker, Some(&root));
    assert_eq!(first.legacy_notices().len(), 1);
    std::fs::create_dir_all(first.workspace_dir()).unwrap();
    std::fs::write(first.workspace_dir().join("MEMORY.md"), "# Project Memory\n").unwrap();
    // The victim's clone adopts the folder; no start of the attacker's clone sees it absent.
    let adopted = MemoryStorage::new(&victim, Some(&root));
    assert!(adopted.legacy_notices().is_empty(), "{:?}", adopted.legacy_notices());
    assert!(!legacy.exists(), "the folder must have been adopted");
    old_version_recreates_legacy(&legacy, &attacker, Some("NEW_GENERATION"));
    assert_eq!(MemoryStorage::new(&attacker, Some(&root)).legacy_notices().len(), 1);
    assert!(MemoryStorage::new(&attacker, Some(&root)).legacy_notices().is_empty());
}

fn notice_markers(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    std::fs::read_dir(root)
        .unwrap()
        .flatten()
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(".legacy-"))
        .map(|entry| entry.path())
        .collect()
}

/// Astra P110 r7 #2: the same legacy folder (same inode) gains notes after it was announced, as when
/// an older version recreates it and the filesystem reuses the inode. Those notes were never
/// announced, so they are; unchanged notes stay quiet.
#[test]
fn new_notes_in_an_announced_legacy_folder_are_announced() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    let legacy = legacy_dir(&root, "victimcorp/secret-app");
    seed_legacy(&legacy, &victim, None);
    assert!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().is_empty());
    old_version_recreates_legacy(&legacy, &victim, Some("FIRST_NOTE"));
    assert_eq!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().len(), 1);
    assert!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().is_empty());
    std::fs::write(legacy.join("sessions/2026-10-04-y-def.md"), "## Session\n\n- SECOND_NOTE\n").unwrap();
    assert_eq!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().len(), 1);
    assert!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().is_empty());
    // An older version re-indexing or taking its write lock is not a new note.
    std::fs::write(legacy.join("index.sqlite"), "re-indexed").unwrap();
    assert!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().is_empty());
}

/// Astra P110 r7 #1 #3: a marker that records nothing (a write cut short, a pre-release build, or a
/// folder identity the filesystem cannot give) never silences a notice on its own.
#[test]
fn an_empty_marker_does_not_silence_a_notice() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    let attacker = temp.path().join("cloned-from-evil");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    git_repo_with_origin(&attacker, "https://evil.example/victimcorp/secret-app");
    seed_legacy(&legacy_dir(&root, "victimcorp/secret-app"), &victim, None);
    let first = MemoryStorage::new(&attacker, Some(&root));
    assert_eq!(first.legacy_notices().len(), 1);
    std::fs::create_dir_all(first.workspace_dir()).unwrap();
    std::fs::write(first.workspace_dir().join("MEMORY.md"), "# Project Memory\n").unwrap();
    assert!(MemoryStorage::new(&attacker, Some(&root)).legacy_notices().is_empty());
    let markers = notice_markers(&root);
    assert!(!markers.is_empty());
    for marker in &markers {
        std::fs::write(marker, "").unwrap();
    }
    assert_eq!(MemoryStorage::new(&attacker, Some(&root)).legacy_notices().len(), 1);
    assert!(MemoryStorage::new(&attacker, Some(&root)).legacy_notices().is_empty());
}

/// Astra P110 r8 #1: a failed P91 index move leaves a fresh `.pre-p91-index-*` folder each attempt;
/// that is not a new note, so the notes already announced stay quiet.
#[test]
fn index_moved_aside_is_not_a_new_note() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    let legacy = legacy_dir(&root, "victimcorp/secret-app");
    seed_legacy(&legacy, &victim, None);
    assert!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().is_empty());
    old_version_recreates_legacy(&legacy, &victim, Some("ASIDE_NOTE"));
    assert_eq!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().len(), 1);
    std::fs::create_dir_all(legacy.join(".pre-p91-index-4242-1791046258")).unwrap();
    std::fs::write(legacy.join(".pre-p91-index-4242-1791046258/index.sqlite"), "old index").unwrap();
    assert!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().is_empty());
}

/// Astra P110 r8 #2: a FIFO left in a legacy folder is never opened, so start-up cannot block on it.
#[cfg(unix)]
#[test]
fn a_fifo_in_a_legacy_folder_does_not_block_start_up() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    let legacy = legacy_dir(&root, "victimcorp/secret-app");
    seed_legacy(&legacy, &victim, None);
    assert!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().is_empty());
    old_version_recreates_legacy(&legacy, &victim, Some("FIFO_NOTE"));
    let made = std::process::Command::new("mkfifo")
        .arg(legacy.join("sessions/capture.pipe"))
        .status()
        .unwrap();
    assert!(made.success());
    let (tx, rx) = std::sync::mpsc::channel();
    let (v, r) = (victim.clone(), root.clone());
    std::thread::spawn(move || {
        let _ = tx.send(MemoryStorage::new(&v, Some(&r)).legacy_notices().len());
    });
    let notices = rx
        .recv_timeout(std::time::Duration::from_secs(20))
        .expect("start-up blocked on a FIFO in the legacy folder");
    assert_eq!(notices, 1);
}

/// Astra P110 r8 #3: link targets are compared byte for byte, so retargeting an announced symlink
/// between two names that differ only in invalid UTF-8 is a change.
#[cfg(unix)]
#[test]
fn retargeting_a_symlink_between_non_utf8_names_is_a_change() {
    use std::os::unix::ffi::OsStrExt;
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    let legacy = legacy_dir(&root, "victimcorp/secret-app");
    seed_legacy(&legacy, &victim, None);
    assert!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().is_empty());
    old_version_recreates_legacy(&legacy, &victim, Some("LINK_NOTE"));
    let link = legacy.join("sessions/linked.md");
    std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(b"/archive/\x80.md"), &link).unwrap();
    assert_eq!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().len(), 1);
    std::fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink(std::ffi::OsStr::from_bytes(b"/archive/\x81.md"), &link).unwrap();
    assert_eq!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().len(), 1);
}

/// P124 (R110 proposal, Fable phase 7 round 2 F3): a legacy folder that stays forever but holds no
/// notes (template, index, lock, empty sessions) is not hashed on every start.
#[test]
fn a_lingering_legacy_folder_without_notes_is_not_hashed_on_start() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    let legacy = legacy_dir(&root, "victimcorp/secret-app");
    seed_legacy(&legacy, &victim, Some(&victim.join("sub")));
    assert!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().is_empty());
    old_version_recreates_legacy(&legacy, &victim, None);
    crate::storage::FINGERPRINT_CALLS.with(|calls| calls.set(0));
    for _ in 0..3 {
        assert!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().is_empty());
    }
    assert_eq!(
        crate::storage::FINGERPRINT_CALLS.with(|calls| calls.get()),
        0,
        "a folder without notes must be recognised by the cheap check, not read and hashed"
    );
}

/// P124: the cheap check changes nothing a user can see: notes still produce one notice, and the
/// hash is only taken for a folder that holds notes.
#[test]
fn a_legacy_folder_with_notes_is_still_noticed_once_after_the_cheap_check() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    let legacy = legacy_dir(&root, "victimcorp/secret-app");
    seed_legacy(&legacy, &victim, Some(&victim.join("sub")));
    assert!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().is_empty());
    old_version_recreates_legacy(&legacy, &victim, Some("CHEAP_CHECK_NOTE"));
    assert_eq!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().len(), 1);
    assert!(MemoryStorage::new(&victim, Some(&root)).legacy_notices().is_empty());
}

/// P124: `fuigo memory clear` lists a stranded legacy folder as not cleared, with its path and how
/// to remove it, and never touches it.
#[test]
fn a_stranded_legacy_folder_is_listed_for_memory_clear() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    let legacy = legacy_dir(&root, "victimcorp/secret-app");
    seed_legacy(&legacy, &victim, Some(&victim.join("sub")));
    let adopted = MemoryStorage::new(&victim, Some(&root));
    assert!(adopted.stranded_legacy_folders().is_empty());
    assert_eq!(adopted.stranded_legacy_clear_notice(), None);
    old_version_recreates_legacy(&legacy, &victim, Some("STRANDED_NOTE"));
    let storage = MemoryStorage::new(&victim, Some(&root));
    assert_eq!(storage.stranded_legacy_folders(), vec![legacy.clone()]);
    let text = storage.stranded_legacy_clear_notice().expect("a notice");
    assert!(text.contains(&legacy.display().to_string()), "{text}");
    assert!(text.to_lowercase().contains("not cleared"), "{text}");
    assert!(text.contains("older version"), "{text}");
    assert!(text.contains("remove") || text.contains("delete"), "{text}");
    assert!(!text.contains('\u{2014}'), "{text}");
    // The listing is read-only and does not depend on the one-time notice having been shown.
    assert_eq!(MemoryStorage::new(&victim, Some(&root)).stranded_legacy_folders(), vec![legacy.clone()]);
    assert!(legacy.join("sessions/2026-10-03-x-abc.md").exists());
}

/// P124: a legacy folder an older version only initialised holds no notes, and clearing says
/// nothing about it; the same once the folder is gone.
#[test]
fn an_empty_or_absent_legacy_folder_is_not_listed_for_memory_clear() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    let legacy = legacy_dir(&root, "victimcorp/secret-app");
    seed_legacy(&legacy, &victim, Some(&victim.join("sub")));
    assert!(MemoryStorage::new(&victim, Some(&root)).stranded_legacy_folders().is_empty());
    old_version_recreates_legacy(&legacy, &victim, None);
    let storage = MemoryStorage::new(&victim, Some(&root));
    assert!(storage.stranded_legacy_folders().is_empty());
    assert_eq!(storage.stranded_legacy_clear_notice(), None);
    std::fs::remove_dir_all(&legacy).unwrap();
    assert!(MemoryStorage::new(&victim, Some(&root)).stranded_legacy_folders().is_empty());
}

/// P124: a legacy folder that was never adopted (P97, unprovable host) also still holds the user's
/// notes outside the new folder, so clear lists it too.
#[test]
fn a_never_adopted_legacy_folder_is_listed_for_memory_clear() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().join("memroot");
    let victim = temp.path().join("victim");
    git_repo_with_origin(&victim, "git@github.com:victimcorp/secret-app.git");
    let other = temp.path().join("other");
    git_repo_with_origin(&other, "git@evil.example:victimcorp/secret-app.git");
    let legacy = legacy_dir(&root, "victimcorp/secret-app");
    seed_legacy(&legacy, &other, Some(&other.join("sub")));
    let storage = MemoryStorage::new(&victim, Some(&root));
    assert!(legacy.exists(), "not adopted");
    assert_eq!(storage.stranded_legacy_folders(), vec![legacy]);
}

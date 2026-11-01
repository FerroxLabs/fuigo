//! P167 (S9): the `--trust` grant path. Kept in its own file so the presence-check tests in `folder_trust.rs` stay
//! untouched by this packet.

use std::path::{Path, PathBuf};

use super::*;
use crate::ENV_TEST_LOCK as ENV_LOCK;
use crate::TestEnvGuard as EnvVarGuard;
use crate::trust::workspace_key;

/// Whether `key` is trusted by the live decision.
fn trusted_now(key: &Path) -> bool {
    !folder_trust_inert() && decide_key(key, false).is_trusted()
}

fn repo_tmp() -> tempfile::TempDir {
    let tmp = tempfile::tempdir().unwrap();
    git2::Repository::init(tmp.path()).unwrap();
    tmp
}

/// Simulate a release-stamped build so store I/O runs (a local/dev build makes grant/revoke no-ops).
fn simulate_release_build() -> EnvVarGuard {
    EnvVarGuard::set(fuigo_version::TEST_VERSION_ENV, Path::new("0.0.0-sim"))
}

/// `--trust` over a corrupt store must leave the user's file byte-for-byte and record no trust, durable or
/// process-local: an unread store is not an empty allow-list to grant into.
#[test]
fn p167_grant_over_corrupt_store_keeps_file_and_grants_nothing() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _sim = simulate_release_build();
    let home = tempfile::tempdir().unwrap();
    let _home = EnvVarGuard::set("FUIGO_HOME", home.path());
    let store_path: PathBuf = TrustStore::default_path().expect("FUIGO_HOME is set");
    // Not valid TOML (the unclosed table header is on its own line, not in a comment).
    let before = b"[folders.\"/srv/kept-grant\"]\ntrusted = true\n[[[ truncated by a crash\n".to_vec();
    std::fs::create_dir_all(store_path.parent().unwrap()).unwrap();
    std::fs::write(&store_path, &before).unwrap();

    let repo = repo_tmp();
    let key = workspace_key(repo.path());
    let _ = grant_folder_trust(repo.path());

    assert_eq!(
        std::fs::read(&store_path).unwrap(),
        before,
        "a grant must never rewrite an unreadable store from an empty document"
    );
    assert!(!trusted_now(&key), "an unread store must not make the folder trusted");
}

// ── Ported from upstream (75810042 / a28ee2b2), adapted to Fuigo's paths and wording ──

#[test]
fn p167_resolution_classifies_each_grant_outcome() {
    let key = PathBuf::from("/tmp/x");
    assert_eq!(
        GrantResolution::Trusted,
        GrantOutcome::Granted {
            key: key.clone(),
            persist: PersistStatus::Durable,
        }
        .resolution()
    );
    assert_eq!(
        GrantResolution::Trusted,
        GrantOutcome::AlreadyDurable { key: key.clone() }.resolution()
    );
    assert_eq!(
        GrantResolution::Unrecorded,
        GrantOutcome::Granted {
            key,
            persist: PersistStatus::NotSaved {
                error: std::io::Error::other("denied"),
            },
        }
        .resolution()
    );
    let inert = GrantOutcome::Refused { reason: GrantRefuse::InertBuild };
    assert_eq!(GrantResolution::Trusted, inert.resolution());
    assert!(inert.dismisses_gate());
    // u35 t1: home and root folders are never trusted, so a grant there answers nothing.
    for reason in [GrantRefuse::UnsafeRoot, GrantRefuse::NoHome, GrantRefuse::Unreadable, GrantRefuse::KeyMoved] {
        let outcome = GrantOutcome::Refused { reason };
        assert_eq!(GrantResolution::Unrecorded, outcome.resolution());
        assert!(!outcome.dismisses_gate());
    }
}

#[test]
fn p167_refuse_display_names_the_next_step_in_fuigo_terms() {
    let text = GrantOutcome::Refused {
        reason: GrantRefuse::Unreadable,
    }
    .to_string();
    assert!(text.contains("trust store could not be read"), "{text}");
    assert!(text.contains("Fix or delete trusted_folders.toml in your Fuigo home ($FUIGO_HOME"), "{text}");
    let no_home = GrantOutcome::Refused {
        reason: GrantRefuse::NoHome,
    }
    .to_string();
    assert!(no_home.contains("no home directory") && no_home.contains("FUIGO_HOME"), "{no_home}");
    let local = GrantOutcome::Granted {
        key: PathBuf::from("/tmp/x"),
        persist: PersistStatus::NotSaved {
            error: std::io::Error::other("denied"),
        },
    }
    .to_string();
    assert!(local.contains("stays untrusted") && local.contains("fuigo --trust"), "{local}");
    for text in [text, no_home, local] {
        assert!(!text.to_ascii_lowercase().contains("grok"), "no upstream branding: {text}");
    }
}

#[test]
fn p167_workspace_key_is_canonical_so_a_live_grant_is_not_key_moved() {
    let tmp = repo_tmp();
    let key = workspace_key(tmp.path());
    assert_eq!(key, dunce::canonicalize(&key).expect("existing key canonicalizes"));
}

#[test]
fn p167_directory_at_the_store_path_is_unreadable_not_process_local() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _sim = simulate_release_build();
    let home = tempfile::tempdir().unwrap();
    let fixture = dunce::canonicalize(home.path()).unwrap();
    std::fs::create_dir_all(fixture.join(crate::trust::TRUST_FILE_NAME)).unwrap();
    let tmp = repo_tmp();
    let key = workspace_key(tmp.path());
    let outcome = grant_folder_trust_key_in(&fixture, &key);
    assert!(
        matches!(outcome, GrantOutcome::Refused { reason: GrantRefuse::Unreadable }),
        "a directory at the store path is not an empty document: {outcome:?}"
    );
    assert!(!trusted_now(&key), "an unread store must not trust the folder");
}

#[test]
fn p167_publish_failure_after_a_missing_store_stays_untrusted() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _sim = simulate_release_build();
    let home = tempfile::tempdir().unwrap();
    let fixture = dunce::canonicalize(home.path()).unwrap();
    // The store "home" is a regular file: the store is Missing (ENOTDIR) and creating its directory fails.
    let blocker = fixture.join("not-a-dir");
    std::fs::write(&blocker, b"x").unwrap();
    let tmp = repo_tmp();
    let key = workspace_key(tmp.path());
    let outcome = grant_folder_trust_key_in(&blocker, &key);
    assert!(
        matches!(
            outcome,
            GrantOutcome::Granted {
                persist: PersistStatus::NotSaved { .. },
                ..
            }
        ),
        "{outcome:?}"
    );
    assert!(!trusted_now(&key), "u35 t1: an unsaved grant leaves the folder untrusted");
    assert_eq!(std::fs::read(&blocker).unwrap(), b"x", "nothing written over the blocker");
}

#[test]
fn p167_grant_key_uses_the_shown_path_not_a_rederived_root() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _sim = simulate_release_build();
    let home = tempfile::tempdir().unwrap();
    let fixture = dunce::canonicalize(home.path()).unwrap();
    // `shown` is a subdir of a git repo: re-deriving `workspace_key` from it would yield the repo root `other`.
    let other = fixture.join("outer-repo");
    std::fs::create_dir_all(&other).unwrap();
    git2::Repository::init(&other).unwrap();
    let shown = other.join("shown-sub");
    std::fs::create_dir_all(&shown).unwrap();
    assert_eq!(workspace_key(&shown), dunce::canonicalize(&other).unwrap(), "fixture: rederiving would widen");

    let outcome = grant_folder_trust_key_in(&fixture, &shown);
    assert!(
        matches!(outcome, GrantOutcome::Granted { persist: PersistStatus::Durable, .. }),
        "{outcome:?}"
    );
    let store = TrustStore::load_from(fixture.join(crate::trust::TRUST_FILE_NAME));
    assert!(store.has_decision(&shown), "the shown key is the stored key");
    assert!(!store.has_decision(&other), "the rederived repo root is not written");
}

#[test]
fn p167_unreadable_store_grant_keeps_bytes_and_records_nothing() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _sim = simulate_release_build();
    let home = tempfile::tempdir().unwrap();
    let fixture = dunce::canonicalize(home.path()).unwrap();
    let store_path = fixture.join(crate::trust::TRUST_FILE_NAME);
    let before = b"folders = not-a-table\n";
    std::fs::write(&store_path, before).unwrap();
    let key_dir = fixture.join("repo");
    std::fs::create_dir_all(&key_dir).unwrap();
    let key = dunce::canonicalize(&key_dir).unwrap();

    let outcome = grant_folder_trust_key_in(&fixture, &key);
    assert!(matches!(outcome, GrantOutcome::Refused { reason: GrantRefuse::Unreadable }), "{outcome:?}");
    assert_eq!(std::fs::read(&store_path).unwrap(), before);
    assert!(!trusted_now(&key), "no trust either");
}

/// The pre-check: a key that no longer resolves to itself (deleted, or a non-canonical spelling) is refused before
/// any store I/O.
#[test]
fn p167_moved_or_noncanonical_key_is_refused_before_any_write() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _sim = simulate_release_build();
    let home = tempfile::tempdir().unwrap();
    let fixture = dunce::canonicalize(home.path()).unwrap();
    let gone = fixture.join("deleted-repo");
    let dotted_gone = fixture.join("x").join("..").join("deleted-repo");
    let outcome = grant_folder_trust_key_in(&fixture, &dotted_gone);
    assert!(matches!(outcome, GrantOutcome::Refused { reason: GrantRefuse::KeyMoved }), "{outcome:?}");
    let live = fixture.join("live");
    std::fs::create_dir_all(&live).unwrap();
    let dotted = live.join("..").join("live");
    let outcome = grant_folder_trust_key_in(&fixture, &dotted);
    assert!(matches!(outcome, GrantOutcome::Refused { reason: GrantRefuse::KeyMoved }), "{outcome:?}");
    assert!(!fixture.join(crate::trust::TRUST_FILE_NAME).exists(), "nothing written for a refused key");
    #[cfg(unix)]
    {
        let alias = fixture.join("alias");
        std::os::unix::fs::symlink(&live, &alias).unwrap();
        let outcome = grant_folder_trust_key_in(&fixture, &alias);
        assert!(matches!(outcome, GrantOutcome::Refused { reason: GrantRefuse::KeyMoved }), "{outcome:?}");
    }
    // Astra r1 #3: a missing but absolute, normal key (a standalone worktree whose recorded source repo is gone) is
    // still grantable as written, as before P167.
    let outcome = grant_folder_trust_key_in(&fixture, &gone);
    assert!(matches!(outcome, GrantOutcome::Granted { persist: PersistStatus::Durable, .. }), "{outcome:?}");
    assert!(TrustStore::load_from(fixture.join(crate::trust::TRUST_FILE_NAME)).has_decision(&gone));
}

#[test]
fn p167_relative_store_home_is_no_home() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _sim = simulate_release_build();
    let tmp = repo_tmp();
    let key = workspace_key(tmp.path());
    let outcome = grant_folder_trust_key_in(Path::new(".fuigo"), &key);
    assert!(matches!(outcome, GrantOutcome::Refused { reason: GrantRefuse::NoHome }), "{outcome:?}");
}

/// An already durably trusted key is reported as such and the file (owner-only) is not rewritten.
#[test]
fn p167_already_durable_grant_does_not_rewrite_and_store_stays_owner_only() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _sim = simulate_release_build();
    let home = tempfile::tempdir().unwrap();
    let fixture = dunce::canonicalize(home.path()).unwrap();
    let tmp = repo_tmp();
    let key = workspace_key(tmp.path());
    let first = grant_folder_trust_key_in(&fixture, &key);
    assert!(matches!(first, GrantOutcome::Granted { persist: PersistStatus::Durable, .. }), "{first:?}");
    let store_path = fixture.join(crate::trust::TRUST_FILE_NAME);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&store_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the store is owner-only");
    }
    let mut marked = std::fs::read(&store_path).unwrap();
    marked.extend_from_slice(b"\n# keep-me\n");
    std::fs::write(&store_path, &marked).unwrap();
    let again = grant_folder_trust_key_in(&fixture, &key);
    assert!(matches!(again, GrantOutcome::AlreadyDurable { .. }), "{again:?}");
    assert_eq!(std::fs::read(&store_path).unwrap(), marked, "not rewritten");
}

/// The interactive (stderr) prompt path reports the same outcome and grants nothing over an unreadable store.
#[test]
fn p167_persist_trust_over_unreadable_store_is_refused() {
    let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let home = tempfile::tempdir().unwrap();
    let fixture = dunce::canonicalize(home.path()).unwrap();
    let store_path = fixture.join(crate::trust::TRUST_FILE_NAME);
    std::fs::write(&store_path, b"[[[").unwrap();
    let key_dir = fixture.join("repo-prompt");
    std::fs::create_dir_all(&key_dir).unwrap();
    let key = dunce::canonicalize(&key_dir).unwrap();
    let mut store = TrustStore::load_from(store_path.clone());
    let outcome = persist_trust(&mut store, &key);
    assert!(matches!(outcome, GrantOutcome::Refused { reason: GrantRefuse::Unreadable }), "{outcome:?}");
    assert_eq!(std::fs::read(&store_path).unwrap(), b"[[[");
    assert!(!trusted_now(&key));
}

// ── u38 F5: the process-only grant ───────────────────────────────────────────────────────────────

/// Own process (the grant is a process static), a release-stamped build, an empty absolute home, a git repo.
struct ProcessGrantWorld {
    _lock: std::sync::MutexGuard<'static, ()>,
    _sim: EnvVarGuard,
    _home_guard: EnvVarGuard,
    _real: TestFolderTrust,
    home: tempfile::TempDir,
    repo: tempfile::TempDir,
    key: PathBuf,
}

fn process_grant_world() -> ProcessGrantWorld {
    let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let sim = simulate_release_build();
    let home = tempfile::tempdir().unwrap();
    let home_guard = EnvVarGuard::set("FUIGO_HOME", home.path());
    let repo = repo_tmp();
    let key = workspace_key(repo.path());
    let real = TestFolderTrust::real();
    ProcessGrantWorld { _lock: lock, _sim: sim, _home_guard: home_guard, _real: real, home, repo, key }
}

fn home_entries(home: &Path) -> Vec<PathBuf> {
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(home).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            entries.extend(home_entries(&path));
        }
        entries.push(path);
    }
    entries.sort();
    entries
}

#[test]
fn u38_f5_process_grant_trusts_now_and_writes_nothing() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = process_grant_world();
    assert!(!trusted_now(&w.key), "premise: undecided");
    let before = home_entries(w.home.path());
    let generation = trust_generation();

    let outcome = grant_folder_trust_key_for_process(&w.key);

    assert!(
        matches!(outcome, GrantOutcome::Granted { persist: PersistStatus::ProcessOnly, .. }),
        "{outcome:?}"
    );
    assert!(outcome.dismisses_gate(), "settle_gui_grant lets a process grant through");
    assert!(trusted_now(&w.key));
    assert!(dir_trust(w.repo.path()).is_trusted(), "commands follow the one decision");
    assert_ne!(trust_generation(), generation, "cached verdicts are re-derived");
    assert_eq!(home_entries(w.home.path()), before, "nothing is written to disk");
}

#[test]
fn u38_f5_process_grant_covers_exactly_what_a_durable_grant_refuses_not() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = process_grant_world();
    // The same pre-check as a durable grant: a key that is not its own canonical form is refused.
    let alias = w.key.join("..").join(w.key.file_name().unwrap());
    let moved = grant_folder_trust_key_for_process(&alias);
    assert!(matches!(moved, GrantOutcome::Refused { reason: GrantRefuse::KeyMoved }), "{moved:?}");
    let root = grant_folder_trust_key_for_process(Path::new("/"));
    assert!(matches!(root, GrantOutcome::Refused { reason: GrantRefuse::UnsafeRoot }), "{root:?}");
    assert!(PROCESS_GRANTS.lock().is_empty(), "a refused grant records nothing");
}

/// An unread store keeps the folder untrusted whatever is held here, so the grant says so instead of reporting a
/// success the decision would not honour (the session is told, as for a durable grant).
#[test]
fn u38_f5_process_grant_over_an_unreadable_store_is_refused() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = process_grant_world();
    let store_path = TrustStore::default_path().expect("FUIGO_HOME is set");
    std::fs::create_dir_all(store_path.parent().unwrap()).unwrap();
    std::fs::write(&store_path, b"[[[ truncated by a crash\n").unwrap();

    let outcome = grant_folder_trust_key_for_process(&w.key);

    assert!(matches!(outcome, GrantOutcome::Refused { reason: GrantRefuse::Unreadable }), "{outcome:?}");
    assert!(PROCESS_GRANTS.lock().is_empty());
    assert!(!trusted_now(&w.key));
}

#[test]
fn u38_f5_a_stored_no_beats_a_process_grant() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = process_grant_world();
    TrustStore::load().set_untrusted(&w.key).unwrap();
    let store_path = TrustStore::default_path().expect("FUIGO_HOME is set");
    let stored = std::fs::read(&store_path).unwrap();

    let _ = grant_folder_trust_key_for_process(&w.key);

    assert!(!trusted_now(&w.key), "a stored no outranks a process yes");
    assert!(!dir_trust(w.repo.path()).is_trusted());
    assert_eq!(std::fs::read(&store_path).unwrap(), stored, "the stored no is untouched");
}

#[test]
fn u38_f5_a_stored_no_for_a_subfolder_beats_a_process_grant_of_the_repo() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = process_grant_world();
    let sub = w.key.join("vendor");
    std::fs::create_dir_all(&sub).unwrap();
    TrustStore::load().set_untrusted(&sub).unwrap();

    assert!(grant_folder_trust_key_for_process(&w.key).dismisses_gate());

    assert!(trusted_now(&w.key), "premise: the repo itself is granted");
    assert!(!decide(&sub, false).is_trusted(), "the most specific no wins");
}

#[test]
fn u38_f5_a_process_no_beats_a_process_grant() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = process_grant_world();
    set_process_decline(&w.key, true);

    let _ = grant_folder_trust_key_for_process(&w.key);

    assert!(!trusted_now(&w.key), "a no held in this process outranks a process yes");
    assert!(PROCESS_DECLINES.lock().contains(&w.key), "the grant does not lift the no");
}

#[test]
fn u38_f5_untrust_clears_a_process_grant() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = process_grant_world();
    assert!(grant_folder_trust_key_for_process(&w.key).dismisses_gate());

    let RevokeOutcome::Revoked { was_trusted, saved, .. } = revoke_folder_trust_store(w.repo.path()) else {
        panic!("a release-stamped build revokes");
    };

    assert!(was_trusted, "/untrust reports what the process grant had trusted");
    assert!(saved.is_ok());
    assert!(!trusted_now(&w.key));
    assert!(PROCESS_GRANTS.lock().is_empty(), "cleared, not only outranked");
}

/// `U38_F5_PROBE_KEY` turns the re-run into the new process: same home, same key, none of the parent's memory.
#[test]
fn u38_f5_process_grant_is_gone_in_a_new_process() {
    const TEST: &str = "folder_trust::grant_tests::u38_f5_process_grant_is_gone_in_a_new_process";
    const PROBE: &str = "U38_F5_PROBE_KEY";
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    if let Some(key) = std::env::var_os(PROBE) {
        assert!(!trusted_now(Path::new(&key)), "a new process must not inherit the grant");
        return;
    }
    let w = process_grant_world();
    assert!(grant_folder_trust_key_for_process(&w.key).dismisses_gate());
    assert!(trusted_now(&w.key), "premise: trusted in the granting process");

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", TEST, "--include-ignored", "--test-threads=1"])
        .env(PROBE, &w.key)
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    assert!(stdout.contains("1 passed"), "the probe must really have run: {stdout}");
}

/// A durable grant that can't be saved never falls back to a process grant.
#[test]
fn u38_f5_a_durable_grant_that_cannot_be_saved_stays_gated() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = process_grant_world();
    let blocker = w.home.path().join("not-a-dir");
    std::fs::write(&blocker, b"x").unwrap();

    let outcome = grant_folder_trust_key_in(&dunce::canonicalize(&blocker).unwrap(), &w.key);

    assert!(
        matches!(outcome, GrantOutcome::Granted { persist: PersistStatus::NotSaved { .. }, .. }),
        "{outcome:?}"
    );
    assert!(!outcome.dismisses_gate());
    assert!(PROCESS_GRANTS.lock().is_empty(), "no process grant appears behind a failed save");
    assert!(!trusted_now(&w.key));
}

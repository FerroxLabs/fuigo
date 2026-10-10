//! P167 (S9): the `--trust` grant path. Kept in its own file so the presence-check tests in `folder_trust.rs` stay
//! untouched by this packet.

use std::path::{Path, PathBuf};

use super::*;
use crate::ENV_TEST_LOCK as ENV_LOCK;
use crate::TestEnvGuard as EnvVarGuard;

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
    assert!(
        !is_trusted_this_process(&key),
        "an unread store must not become process-local trusted"
    );
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
        GrantResolution::SessionLocal,
        GrantOutcome::Granted {
            key,
            persist: PersistStatus::ProcessLocalOnly {
                error: std::io::Error::other("denied"),
            },
        }
        .resolution()
    );
    for reason in [GrantRefuse::InertBuild, GrantRefuse::UnsafeRoot] {
        let outcome = GrantOutcome::Refused { reason };
        assert_eq!(GrantResolution::Trusted, outcome.resolution());
        assert!(outcome.dismisses_gate());
    }
    for reason in [GrantRefuse::NoHome, GrantRefuse::Unreadable, GrantRefuse::KeyMoved] {
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
        persist: PersistStatus::ProcessLocalOnly {
            error: std::io::Error::other("denied"),
        },
    }
    .to_string();
    assert!(local.contains("this session only") && local.contains("fuigo --trust"), "{local}");
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
    assert!(!is_trusted_this_process(&key), "an unread store must not record process-local trust");
}

#[test]
fn p167_publish_failure_after_a_missing_store_is_process_local() {
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
                persist: PersistStatus::ProcessLocalOnly { .. },
                ..
            }
        ),
        "{outcome:?}"
    );
    assert!(is_trusted_this_process(&key), "the explicit grant holds for this process");
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
    assert!(!PROCESS_DECISIONS.lock().contains_key(&key), "no process-local trust either");
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
    assert!(!PROCESS_DECISIONS.lock().contains_key(&key));
}

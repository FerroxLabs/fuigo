//! Mutation-pass tests (1.0.46, lane `mut`) for the peer denial ring: each pins behaviour that `cargo mutants` showed
//! no other test pinned.

use super::peer_denials::*;

fn key(hash: &str) -> DenialKey {
    DenialKey {
        kind: "edit".into(),
        hash: hash.into(),
    }
}

fn hashes(keys: &[DenialKey]) -> Vec<&str> {
    keys.iter().map(|k| k.hash.as_str()).collect()
}

fn plain(n: usize) -> Vec<DenialKey> {
    (0..n).map(|i| key(&format!("h{i}"))).collect()
}

#[test]
fn peer_cap_keys_leaves_a_set_at_the_cap_untouched_even_with_a_marker_first() {
    let mut keys = vec![key(MANY_TARGETS_HASH)];
    keys.extend(plain(MAX_KEYS_PER_DENIAL - 1));
    assert_eq!(keys.len(), MAX_KEYS_PER_DENIAL);
    // At the cap nothing is reordered: the marker stays first.
    assert_eq!(cap_keys(keys.clone()), keys);
    assert_eq!(cap_keys(Vec::new()), Vec::new());
    assert_eq!(cap_keys(plain(3)), plain(3));
}

#[test]
fn peer_cap_keys_truncates_plain_keys_to_the_cap() {
    let out = cap_keys(plain(MAX_KEYS_PER_DENIAL + 3));
    assert_eq!(out, plain(MAX_KEYS_PER_DENIAL));
}

#[test]
fn peer_cap_keys_never_drops_the_many_targets_marker() {
    // One marker among eleven keys: seven plain keys, then the marker.
    let mut keys = plain(5);
    keys.push(key(MANY_TARGETS_HASH));
    keys.extend((5..10).map(|i| key(&format!("h{i}"))));
    assert_eq!(keys.len(), 11);
    let out = cap_keys(keys);
    assert_eq!(out.len(), MAX_KEYS_PER_DENIAL);
    assert_eq!(
        hashes(&out),
        ["h0", "h1", "h2", "h3", "h4", "h5", "h6", MANY_TARGETS_HASH]
    );

    // Two markers: six plain keys and both markers.
    let mut keys = plain(10);
    keys.insert(2, key(MANY_TARGETS_HASH));
    keys.insert(4, key(MANY_TARGETS_HASH));
    let out = cap_keys(keys);
    assert_eq!(out.len(), MAX_KEYS_PER_DENIAL);
    assert_eq!(
        hashes(&out),
        [
            "h0",
            "h1",
            "h2",
            "h3",
            "h4",
            "h5",
            MANY_TARGETS_HASH,
            MANY_TARGETS_HASH
        ]
    );

    // More markers than the cap: only markers remain, still at the cap.
    let keys = (0..MAX_KEYS_PER_DENIAL + 2)
        .map(|_| key(MANY_TARGETS_HASH))
        .collect();
    let out = cap_keys(keys);
    assert_eq!(out.len(), MAX_KEYS_PER_DENIAL);
    assert!(out.iter().all(|k| k.hash == MANY_TARGETS_HASH));
}

#[test]
fn peer_mono_secs_advances_with_real_time() {
    let a = mono_secs();
    std::thread::sleep(std::time::Duration::from_millis(1100));
    let b = mono_secs();
    assert!(b > a, "mono_secs did not advance: {a} then {b}");
}

#[test]
fn peer_canonical_json_integral_float_spelling_stops_at_the_threshold() {
    use crate::permission::types::AccessKind;
    let k = |v: serde_json::Value| {
        denial_keys_for(
            &AccessKind::MCPTool {
                name: "srv__t".into(),
                input: v,
            },
            None,
            None,
            std::path::Path::new("/"),
            None,
        )
    };
    // An integral float under the threshold is spelled like the integer ...
    assert_eq!(
        k(serde_json::json!({"n": 8.0e15})),
        k(serde_json::json!({"n": 8_000_000_000_000_000_i64}))
    );
    // ... at the threshold it keeps its float spelling.
    assert_ne!(
        k(serde_json::json!({"n": 9.0e15})),
        k(serde_json::json!({"n": 9_000_000_000_000_000_i64}))
    );
}

fn keys_of(
    access: &crate::permission::types::AccessKind,
    read: Option<&crate::permission::types::ReadTargets>,
) -> Vec<DenialKey> {
    denial_keys_for(
        access,
        None,
        read,
        std::path::Path::new("/peer-test-cwd"),
        None,
    )
}

#[test]
fn peer_mcp_tool_name_outside_the_safe_alphabet_or_empty_is_hashed() {
    use crate::permission::types::AccessKind;
    let kind_of = |name: &str| {
        let k = keys_of(
            &AccessKind::MCPTool {
                name: name.into(),
                input: serde_json::json!({"a": 1}),
            },
            None,
        );
        assert_eq!(k.len(), 1);
        k[0].kind.clone()
    };
    assert_eq!(kind_of("srv__tool-1.x:y"), "mcp:srv__tool-1.x:y");
    let spaced = kind_of("a b");
    assert!(
        spaced.starts_with("mcp:") && !spaced.contains(" "),
        "{spaced}"
    );
    assert_ne!(
        spaced,
        kind_of("a c"),
        "hashed, so distinct names stay distinct"
    );
    let empty = kind_of("");
    assert!(
        empty.len() > "mcp:".len(),
        "an empty name is hashed: {empty}"
    );
}

#[test]
fn peer_read_with_an_empty_target_list_falls_back_to_the_single_path() {
    use crate::permission::types::{AccessKind, ReadResolution, ReadTargets};
    let empty = ReadTargets {
        paths: Vec::new(),
        resolution: ReadResolution::ModelPath,
    };
    let with_fallback = keys_of(
        &AccessKind::Read(Some("/peer-test-cwd/f.txt".into())),
        Some(&empty),
    );
    assert_eq!(with_fallback.len(), 1, "{with_fallback:?}");
    assert_eq!(
        with_fallback,
        keys_of(&AccessKind::Read(Some("/peer-test-cwd/f.txt".into())), None)
    );
    assert!(keys_of(&AccessKind::Read(None), Some(&empty)).is_empty());
}

#[test]
fn peer_read_literal_resolution_does_not_expand_a_tilde() {
    use crate::permission::types::{AccessKind, ReadResolution, ReadTargets};
    let targets = |resolution| ReadTargets {
        paths: vec!["~/peer-f".to_owned()],
        resolution,
    };
    let access = AccessKind::Read(None);
    let literal = keys_of(&access, Some(&targets(ReadResolution::Literal)));
    let model = keys_of(&access, Some(&targets(ReadResolution::ModelPath)));
    // Literal: opened as spelled, so a relative spelling is joined to the cwd as is.
    assert_eq!(
        literal,
        keys_of(
            &AccessKind::Read(Some("/peer-test-cwd/~/peer-f".into())),
            None
        )
    );
    assert_ne!(literal, model, "the model path reader expands the tilde");
}

#[test]
fn peer_grep_without_a_path_needs_a_glob_to_have_a_target() {
    use crate::permission::types::AccessKind;
    let grep = |glob: Option<&str>| {
        keys_of(
            &AccessKind::Grep {
                path: None,
                glob: glob.map(str::to_owned),
            },
            None,
        )
    };
    assert!(grep(None).is_empty());
    assert!(grep(Some("")).is_empty());
    assert_eq!(grep(Some("*.rs")).len(), 1);
}

fn edit_keys(paths: &[String], both: bool, cwd: &std::path::Path) -> Vec<DenialKey> {
    use crate::permission::types::{AccessKind, EditTargets};
    let access = AccessKind::Edit("edit".into());
    let targets = EditTargets::Paths(paths.to_vec());
    if both {
        match_keys_for(&access, Some(&targets), None, cwd, None)
    } else {
        denial_keys_for(&access, Some(&targets), None, cwd, None)
    }
}

#[test]
fn peer_task_pseudo_path_and_apply_patch_are_keyed_as_themselves_or_not_at_all() {
    use crate::permission::types::AccessKind;
    let task = keys_of(&AccessKind::Edit("task:explore".into()), None);
    assert_eq!(task.len(), 1);
    // Not a file: it is NOT the key of the path `<cwd>/task:explore`.
    let as_path = keys_of(
        &AccessKind::Edit("/peer-test-cwd/task:explore".into()),
        None,
    );
    assert_eq!(as_path.len(), 1);
    assert_ne!(task, as_path);
    // `apply_patch` and an empty name have no target of their own.
    assert!(keys_of(&AccessKind::Edit("apply_patch".into()), None).is_empty());
    assert!(keys_of(&AccessKind::Edit(String::new()), None).is_empty());
    assert_eq!(keys_of(&AccessKind::Edit("a.txt".into()), None).len(), 1);
}

#[test]
fn peer_recording_many_targets_keeps_the_first_seven_and_a_marker() {
    let cwd = std::path::Path::new("/peer-test-cwd");
    let one = |p: &str| edit_keys(&[p.to_owned()], false, cwd);
    for n in [9usize, 12] {
        let paths: Vec<String> = (0..n).map(|i| format!("/peer-test-cwd/f{i}")).collect();
        let keys = edit_keys(&paths, false, cwd);
        assert_eq!(keys.len(), MAX_KEYS_PER_DENIAL, "{n} targets");
        for (i, p) in paths.iter().take(MAX_KEYS_PER_DENIAL - 1).enumerate() {
            assert_eq!(keys[i..=i], one(p)[..], "target {i} of {n}");
        }
        assert_eq!(keys[MAX_KEYS_PER_DENIAL - 1].hash, MANY_TARGETS_HASH);
    }
    // At the cap exactly there is no marker.
    let paths: Vec<String> = (0..MAX_KEYS_PER_DENIAL)
        .map(|i| format!("/peer-test-cwd/f{i}"))
        .collect();
    let keys = edit_keys(&paths, false, cwd);
    assert_eq!(keys.len(), MAX_KEYS_PER_DENIAL);
    assert!(keys.iter().all(|k| k.hash != MANY_TARGETS_HASH));
}

/// Matching keys (both spellings of a symlinked target) are not capped to the recording bound.
#[cfg(unix)]
#[test]
fn peer_matching_keys_hold_both_spellings_and_are_not_capped() {
    let tmp = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(tmp.path()).unwrap();
    std::fs::create_dir(root.join("real")).unwrap();
    std::os::unix::fs::symlink(root.join("real"), root.join("link")).unwrap();
    for i in 0..12 {
        std::fs::write(root.join("real").join(format!("f{i}")), "x").unwrap();
    }
    let paths = |n: usize| -> Vec<String> { (0..n).map(|i| format!("link/f{i}")).collect() };
    // Few targets: both spellings of each, no cut.
    assert_eq!(edit_keys(&paths(5), true, &root).len(), 10);
    // Recording keeps one spelling per target.
    assert_eq!(edit_keys(&paths(5), false, &root).len(), 5);
    // Many targets: the first seven targets with both spellings, then the marker.
    let keys = edit_keys(&paths(12), true, &root);
    assert_eq!(keys.len(), 2 * (MAX_KEYS_PER_DENIAL - 1) + 1);
    assert_eq!(keys.last().unwrap().hash, MANY_TARGETS_HASH);
}

#[test]
fn peer_denial_log_entries_are_the_key_sets_oldest_first() {
    let log = DenialLog::default();
    assert!(log.entries().is_empty());
    log.record_keys(vec![key("a1"), key("a2")], 10);
    log.record_keys(vec![key("b1")], 11);
    assert_eq!(
        log.entries(),
        vec![vec![key("a1"), key("a2")], vec![key("b1")]]
    );
    // A repeat refreshes the entry and moves it to the newest place.
    log.record_keys(vec![key("a2"), key("a1")], 12);
    assert_eq!(log.entries().len(), 2);
    assert_eq!(log.entries()[0], vec![key("b1")]);
}

#[test]
fn peer_laundering_hit_queue_keeps_the_newest_sixty_four() {
    let log = DenialLog::default();
    let stamps: Vec<_> = (0..70)
        .map(|i| fuigo_peer::DenialStamp {
            tool_kind: "edit".into(),
            target_hash: format!("h{i:03}"),
        })
        .collect();
    for (i, s) in stamps.iter().enumerate() {
        log.carry(&format!("m{i:03}"), std::slice::from_ref(s));
    }
    for i in 0..70 {
        assert!(log.match_carried(&key(&format!("h{i:03}"))).is_some());
    }
    let hits = log.take_hits();
    assert_eq!(hits.len(), 64);
    assert_eq!(hits[0].message_id, "m006", "the six oldest were dropped");
    assert_eq!(hits[63].message_id, "m069");
    assert!(log.take_hits().is_empty());
}

// ---- peer_guard.rs ----

#[test]
fn peer_git_config_names_are_protected_only_where_git_reads_them() {
    use super::peer_guard::is_peer_protected_lexical as lex;
    use std::path::Path;
    let p = |s: &str| lex(Path::new(s));
    // Repo, worktree, submodule and the user-level files.
    assert!(p("/work/r/.git/config"));
    assert!(p("/work/r/.git/modules/sub/config"));
    assert!(p("/work/r/.git/config.worktree"));
    assert!(p("/work/r/.git/worktrees/w/config.worktree"));
    assert!(p("/work/home/.gitconfig"));
    assert!(p("/work/home/.config/git/config"));
    // Look-alikes are free: a file named config elsewhere, other files in .git, modules without the config.
    assert!(!p("/work/app/config"));
    assert!(!p("/work/r/config"));
    assert!(!p("/work/r/.git/HEAD"));
    assert!(!p("/work/r/.git/modules/sub/HEAD"));
    assert!(!p("/work/r/modules/sub/config"));
    assert!(!p("/work/r/config.worktree"));
    assert!(!p("/work/r/.git"));
    assert!(!p("/work/home/.config/other/config"));
}

#[test]
fn peer_bare_container_is_the_directory_itself_by_spelling_or_after_symlinks() {
    use super::peer_guard::is_peer_bare_container as bare;
    use std::path::Path;
    for name in [".claude", ".fuigo", ".cursor", ".CLAUDE", ".Fuigo"] {
        assert!(bare(Path::new(&format!("/work/p/{name}"))), "{name}");
    }
    assert!(!bare(Path::new("/work/p/.claude/rules")));
    assert!(!bare(Path::new("/work/p/claude")));
    assert!(!bare(Path::new("/work/p/.git")));
    assert!(!bare(Path::new("/")));
    #[cfg(unix)]
    {
        let tmp = tempfile::tempdir().unwrap();
        let root = dunce::canonicalize(tmp.path()).unwrap();
        std::fs::create_dir(root.join(".claude")).unwrap();
        std::fs::create_dir(root.join("other")).unwrap();
        // A link spelled innocently that lands on the container ...
        std::os::unix::fs::symlink(root.join(".claude"), root.join("link")).unwrap();
        assert!(bare(&root.join("link")), "resolved spelling");
        // ... and a container name that is really a link to somewhere else counts by its own spelling.
        std::os::unix::fs::symlink(root.join("other"), root.join(".cursor")).unwrap();
        assert!(bare(&root.join(".cursor")), "lexical spelling");
        assert!(!bare(&root.join("other")));
    }
}

#[test]
fn peer_holds_protected_needs_a_real_git_dir_or_a_directory_with_a_protected_name() {
    use super::peer_guard::peer_holds_protected as holds;
    let tmp = tempfile::tempdir().unwrap();
    let root = dunce::canonicalize(tmp.path()).unwrap();
    std::fs::write(root.join("plain.txt"), "x").unwrap();
    assert!(
        !holds(&root.join("plain.txt")),
        "an existing file is not a holder"
    );
    assert!(!holds(&root.join(".git")), "a missing .git holds nothing");
    assert!(!holds(&root), "an empty directory holds nothing");
    std::fs::create_dir(root.join(".git")).unwrap();
    assert!(holds(&root.join(".git")), "a .git directory");
    assert!(holds(&root), "a directory with a .git in it");
    let other = root.join("other");
    std::fs::create_dir(&other).unwrap();
    std::fs::write(other.join("CLAUDE.md"), "x").unwrap();
    assert!(holds(&other), "a directory with CLAUDE.md in it");
    assert!(
        !holds(&other.join("CLAUDE.md")),
        "the file itself is not a directory"
    );
}

//! P124: `fuigo memory clear` lists a stranded legacy memory folder as not cleared (own binary: `FUIGO_HOME` is read once).

use std::path::Path;
use std::process::Command;

use fuigo_pager::memory_cmd::{MemoryArgs, MemoryCommand, not_cleared_lines, run};
use fuigo_shell::session::memory::storage::MemoryStorage;

fn git_repo_with_origin(dir: &Path, origin: &str) {
    std::fs::create_dir_all(dir).unwrap();
    for args in [vec!["init", "-q"], vec!["remote", "add", "origin", origin]] {
        let status = Command::new("git").args(&args).current_dir(dir).status().unwrap();
        assert!(status.success(), "git {args:?}");
    }
}

#[test]
#[serial_test::serial(FUIGO_HOME)]
fn memory_clear_lists_a_stranded_legacy_folder_and_leaves_it_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    // SAFETY: serialised on FUIGO_HOME; this binary reads it once, here first.
    unsafe { std::env::set_var("FUIGO_HOME", &home) };
    let repo = tmp.path().join("widgets");
    git_repo_with_origin(&repo, "git@github.com:acme/widgets.git");

    // 1.0.21 state: the new folder exists with notes of its own.
    let storage = MemoryStorage::new(&repo, None);
    std::fs::create_dir_all(storage.workspace_dir()).unwrap();
    std::fs::write(storage.workspace_dir().join("MEMORY.md"), "# Project Memory\n\n- NEW_NOTE\n").unwrap();
    assert!(not_cleared_lines(&storage).is_empty(), "no legacy folder yet");

    // An older Fuigo recreates the old `org/repo` folder and writes a note there.
    let legacy = home.join("memory").join(format!("widgets-{}", &blake3::hash(b"acme/widgets").to_hex()[..8]));
    std::fs::create_dir_all(legacy.join("sessions")).unwrap();
    std::fs::write(legacy.join("sessions/2026-10-03-x-abc.md"), "## Session\n\n- OLD_NOTE\n").unwrap();

    let storage = MemoryStorage::new(&repo, None);
    let lines = not_cleared_lines(&storage);
    let text = lines.join("\n");
    assert!(text.contains(&legacy.display().to_string()), "{text}");
    assert!(text.to_lowercase().contains("not cleared"), "{text}");
    assert!(text.contains("older version"), "{text}");

    std::env::set_current_dir(&repo).unwrap();
    run(MemoryArgs { command: MemoryCommand::Clear { workspace: true, global: false, all: false, yes: true } }).unwrap();
    assert!(
        !storage.workspace_dir().join("MEMORY.md").exists(),
        "the workspace memory was cleared"
    );
    assert!(legacy.join("sessions/2026-10-03-x-abc.md").exists(), "clear must not delete the legacy folder");
}

//! u35: an installed hook that denies the folder keeps project agent files out, and is consulted with the cwd.
//! Its own test binary, so it owns the set-once hook.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

static CALLS: AtomicUsize = AtomicUsize::new(0);
static SEEN: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

fn deny(cwd: &Path) -> bool {
    CALLS.fetch_add(1, Ordering::SeqCst);
    SEEN.lock().unwrap().push(cwd.to_path_buf());
    false
}

#[test]
fn a_denying_hook_keeps_project_agents_out() {
    let fuigo_home = tempfile::tempdir().unwrap();
    // SAFETY: the only test in this binary, so no other thread reads the environment.
    unsafe { std::env::set_var("FUIGO_HOME", fuigo_home.path()) };
    fuigo_agent::discovery::install_project_agent_trust(deny);
    let repo = tempfile::tempdir().unwrap();
    let agents = repo.path().join(".fuigo").join("agents");
    fs::create_dir_all(&agents).unwrap();
    fs::write(
        agents.join("reviewer.md"),
        "---\nname: reviewer\ndescription: Project reviewer\n---\nbody\n",
    )
    .unwrap();

    assert!(fuigo_agent::discovery::by_name_in_cwd("reviewer", repo.path()).is_none());
    assert!(
        !fuigo_agent::discovery::discover(repo.path())
            .iter()
            .any(|d| d.name == "reviewer")
    );
    assert!(
        !fuigo_agent::discovery::all_subagents(repo.path(), &HashMap::new())
            .iter()
            .any(|e| e.name == "reviewer")
    );
    assert!(CALLS.load(Ordering::SeqCst) >= 1, "the hook must be consulted");
    assert!(
        SEEN.lock().unwrap().iter().any(|p| p == repo.path()),
        "the hook must be asked about the lookup's cwd"
    );
}

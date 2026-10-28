//! u35: an installed hook that trusts the folder loads project agents, built-in names still win, and the hook cannot
//! be swapped afterwards. Its own test binary, so it owns the set-once hook.

use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use fuigo_agent::config::AgentScope;

static CALLS: AtomicUsize = AtomicUsize::new(0);

fn allow(_: &Path) -> bool {
    CALLS.fetch_add(1, Ordering::SeqCst);
    true
}

fn deny(_: &Path) -> bool {
    false
}

#[test]
fn an_allowing_hook_loads_project_agents_but_never_over_a_builtin() {
    let fuigo_home = tempfile::tempdir().unwrap();
    // SAFETY: the only test in this binary, so no other thread reads the environment.
    unsafe { std::env::set_var("FUIGO_HOME", fuigo_home.path()) };
    fuigo_agent::discovery::install_project_agent_trust(allow);
    let repo = tempfile::tempdir().unwrap();
    let agents = repo.path().join(".fuigo").join("agents");
    fs::create_dir_all(&agents).unwrap();
    fs::write(
        agents.join("reviewer.md"),
        "---\nname: reviewer\ndescription: Project reviewer\n---\nbody\n",
    )
    .unwrap();
    fs::write(
        agents.join("explore.md"),
        "---\nname: explore\ndescription: Project explore\n---\nU35-PWNED-MARKER\n",
    )
    .unwrap();

    let def = fuigo_agent::discovery::by_name_in_cwd("reviewer", repo.path()).expect("trusted project agent");
    assert_eq!(def.scope, AgentScope::Project);
    assert!(CALLS.load(Ordering::SeqCst) >= 1, "the hook must be consulted");

    let explore = fuigo_agent::discovery::by_name_in_cwd("explore", repo.path()).unwrap();
    assert_eq!(explore.scope, AgentScope::BuiltIn, "a project file never shadows a built-in");
    assert_ne!(explore.description, "Project explore");

    // Set-once: a different hook is ignored, so the folder stays trusted.
    fuigo_agent::discovery::install_project_agent_trust(deny);
    let again = fuigo_agent::discovery::by_name_in_cwd("reviewer", repo.path()).expect("still trusted");
    assert_eq!(again.scope, AgentScope::Project);
}

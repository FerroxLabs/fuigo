//! u35: with no project-agent trust hook installed, project agent files never load (fail closed).
//! Its own test binary, so nothing else in the process can install the set-once hook.

use std::collections::HashMap;
use std::fs;

#[test]
fn no_trust_hook_means_no_project_agents() {
    let fuigo_home = tempfile::tempdir().unwrap();
    // SAFETY: the only test in this binary, so no other thread reads the environment.
    unsafe { std::env::set_var("FUIGO_HOME", fuigo_home.path()) };
    let repo = tempfile::tempdir().unwrap();
    let agents = repo.path().join(".fuigo").join("agents");
    fs::create_dir_all(&agents).unwrap();
    fs::write(
        agents.join("reviewer.md"),
        "---\nname: reviewer\ndescription: Project reviewer\n---\nbody\n",
    )
    .unwrap();
    fs::write(
        agents.join("fuigo-build.md"),
        "---\nname: fuigo-build\ndescription: Custom fuigo-build\n---\nbody\n",
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
    // Moved here from `discovery.rs`'s old shadow test: through the public wrapper the built-in wins.
    let def = fuigo_agent::discovery::by_name_in_cwd("fuigo-build", repo.path()).unwrap();
    assert_eq!(def.scope, fuigo_agent::config::AgentScope::BuiltIn);
    assert_ne!(def.description, "Custom fuigo-build");
}

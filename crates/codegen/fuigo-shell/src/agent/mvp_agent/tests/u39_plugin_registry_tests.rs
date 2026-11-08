//! Items 4 and 4b (E2, E3): a child's own plugin registry is built for its cwd on its own verdict, and Task validation and
//! `inherit_skills` read the parent's own session registry (the source of its Task enum), not the process snapshot.
use super::{build_minimal_agent_for_tests, make_test_handle};
use crate::agent::subagent::{build_child_plugin_registry, validate_subagent_type};
use agent_client_protocol as acp;
use fuigo_agent::plugins::{PluginRegistry, PluginScope, SharedPluginRegistryHandle};
use fuigo_tools::implementations::fuigo_build::task::types::SubagentValidateTypeOutcome;
use std::path::Path;
use std::sync::Arc;

/// A project plugin `<repo>/.fuigo/plugins/<name>` with one agent `<name>-agent` and one skill `<name>-skill`.
#[allow(clippy::disallowed_methods, reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there")]
fn project_plugin(repo: &Path, name: &str) {
    let root = repo.join(".fuigo").join("plugins").join(name);
    std::fs::create_dir_all(root.join("agents")).unwrap();
    let skill = root.join("skills").join(format!("{name}-skill"));
    std::fs::create_dir_all(&skill).unwrap();
    std::fs::write(
        skill.join("SKILL.md"),
        format!(
            "---\nname: {name}-skill\ndescription: u39 fixture skill\n---\n{name} skill body\n"
        ),
    )
    .unwrap();
    std::fs::write(root.join("plugin.json"), format!(r#"{{"name":"{name}"}}"#)).unwrap();
    std::fs::write(
        root.join("agents").join(format!("{name}-agent.md")),
        format!("---\nname: {name}-agent\ndescription: u39 fixture\n---\n{name} agent body\n"),
    )
    .unwrap();
}

fn repo_with_plugin(name: &str) -> tempfile::TempDir {
    let repo = tempfile::tempdir().unwrap();
    git2::Repository::init(repo.path()).unwrap();
    project_plugin(repo.path(), name);
    repo
}

/// The user config enables the fixture plugins by name, so only the folder verdict decides project scope.
#[allow(clippy::disallowed_methods, reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there")]
fn enable_in_user_config(home: &Path, names: &[&str]) {
    let list = names
        .iter()
        .map(|n| format!("\"{n}\""))
        .collect::<Vec<_>>()
        .join(", ");
    std::fs::write(
        home.join("config.toml"),
        format!("[plugins]\nenabled = [{list}]\n"),
    )
    .unwrap();
}

fn active_names(registry: &Option<Arc<PluginRegistry>>) -> Vec<String> {
    let mut names: Vec<String> = registry
        .as_ref()
        .map(|r| r.active_plugins().iter().map(|p| p.name.clone()).collect())
        .unwrap_or_default();
    names.sort();
    names
}

fn snapshot_for(handle: &SharedPluginRegistryHandle, cwd: &Path) {
    let cfg = crate::config::resolve_effective_plugins_config(cwd).to_discovery_config();
    handle.reload(
        Some(cwd),
        &cfg,
        crate::agent::folder_trust::project_scope_allowed(cwd),
        false,
    );
}

#[allow(clippy::disallowed_methods, reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there")]
#[test]
fn child_registry_is_built_for_the_child_folder_on_its_own_verdict() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    enable_in_user_config(home.path(), &["px", "py", "pu"]);
    let user_plugin = home.path().join("plugins").join("pu");
    std::fs::create_dir_all(&user_plugin).unwrap();
    std::fs::write(user_plugin.join("plugin.json"), r#"{"name":"pu"}"#).unwrap();
    let x = repo_with_plugin("px");
    let y = repo_with_plugin("py");
    crate::agent::folder_trust::record_for_test(x.path(), true);
    crate::agent::folder_trust::record_for_test(y.path(), true);
    let handle = SharedPluginRegistryHandle::new(None, vec![]);
    snapshot_for(&handle, x.path());
    let snapshot = handle.snapshot();
    assert!(
        active_names(&snapshot).contains(&"px".to_string()),
        "fixture: the snapshot holds X's px"
    );

    let in_y = build_child_plugin_registry(&handle, y.path());
    assert!(active_names(&in_y).contains(&"py".to_string()));
    assert!(
        !active_names(&in_y).contains(&"px".to_string()),
        "a trusted child in Y does not get X's plugin"
    );

    let in_x = build_child_plugin_registry(&handle, x.path());
    assert_eq!(
        active_names(&in_x),
        active_names(&snapshot),
        "a trusted child in X gets the snapshot's set"
    );

    crate::agent::folder_trust::record_for_test(y.path(), false);
    let untrusted_y = build_child_plugin_registry(&handle, y.path());
    let project_active = untrusted_y
        .as_ref()
        .map(|r| {
            r.active_plugins()
                .iter()
                .filter(|p| p.scope == PluginScope::Project)
                .count()
        })
        .unwrap_or(0);
    assert_eq!(
        project_active, 0,
        "an untrusted child in Y gets no project plugin"
    );
    assert!(
        untrusted_y
            .as_ref()
            .is_some_and(|r| r.list().iter().any(|p| p.name == "pu")),
        "an untrusted child in Y keeps its user plugins"
    );
}

fn unknown_available(outcome: SubagentValidateTypeOutcome) -> Vec<String> {
    match outcome {
        SubagentValidateTypeOutcome::Unknown { available } => available,
        other => panic!("expected Unknown, got {other:?}"),
    }
}

#[tokio::test(flavor = "current_thread")]
async fn task_validation_and_inherit_skills_read_the_parent_registry() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    enable_in_user_config(home.path(), &["px", "py"]);
    let x = repo_with_plugin("px");
    let y = repo_with_plugin("py");
    crate::agent::folder_trust::record_for_test(x.path(), true);
    crate::agent::folder_trust::record_for_test(y.path(), true);
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async {
            let agent = build_minimal_agent_for_tests();
            snapshot_for(&agent.plugin_registry_handle, x.path());
            let snapshot = agent.plugin_registry_handle.snapshot();
            assert!(
                active_names(&snapshot).contains(&"px".to_string()),
                "fixture: snapshot is X's"
            );
            let registry_y = build_child_plugin_registry(&agent.plugin_registry_handle, y.path());
            assert!(
                active_names(&registry_y).contains(&"py".to_string()),
                "fixture: Y's registry"
            );

            // A trusted parent in Y.
            let sid = acp::SessionId::new("u39-parent-y");
            let mut handle = make_test_handle("test-model", false, None);
            handle.info.cwd = y.path().display().to_string();
            handle.plugin_registry.set(registry_y.clone());
            let live = handle.plugin_registry.clone();
            agent.insert_resident(&sid, handle);
            let ctx = agent.build_subagent_validation_context(sid.0.as_ref());
            assert!(matches!(
                validate_subagent_type("py-agent", &ctx),
                SubagentValidateTypeOutcome::Ok
            ));
            let available = unknown_available(validate_subagent_type("px-agent", &ctx));
            assert!(
                available.iter().any(|name| name.contains("py-agent")),
                "{available:?}"
            );
            assert!(
                !available.iter().any(|name| name.contains("px-agent")),
                "{available:?}"
            );

            // inherit_skills lists the Y parent's plugin skills, not the launch folder's.
            let spawn_ctx = agent.build_subagent_spawn_context(sid.0.as_ref());
            let inherited: Vec<String> = crate::agent::subagent::list_parent_skills(
                &spawn_ctx.parent_cwd,
                &spawn_ctx.parent_skills_config,
                spawn_ctx.plugin_registry.as_deref(),
                spawn_ctx.parent_compat,
            )
            .await
            .into_iter()
            .map(|skill| skill.name)
            .collect();
            assert!(
                inherited.iter().any(|name| name.contains("py-skill")),
                "{inherited:?}"
            );
            assert!(
                !inherited.iter().any(|name| name.contains("px-skill")),
                "{inherited:?}"
            );

            // A later publish (a reload, or the actor literal of a re-open) is followed at once.
            live.set(None);
            let ctx = agent.build_subagent_validation_context(sid.0.as_ref());
            assert!(!matches!(
                validate_subagent_type("py-agent", &ctx),
                SubagentValidateTypeOutcome::Ok
            ));
            live.set(registry_y.clone());
            let ctx = agent.build_subagent_validation_context(sid.0.as_ref());
            assert!(matches!(
                validate_subagent_type("py-agent", &ctx),
                SubagentValidateTypeOutcome::Ok
            ));

            // A parent whose registry is the launch folder's snapshot sees today's set.
            let sid_x = acp::SessionId::new("u39-parent-x");
            let mut handle_x = make_test_handle("test-model", false, None);
            handle_x.info.cwd = x.path().display().to_string();
            handle_x.plugin_registry.set(snapshot.clone());
            agent.insert_resident(&sid_x, handle_x);
            let ctx_x = agent.build_subagent_validation_context(sid_x.0.as_ref());
            let today = crate::agent::subagent::SubagentValidationContext {
                parent_cwd: x.path().to_path_buf(),
                plugin_registry: snapshot.clone(),
                ..Default::default()
            };
            assert!(matches!(
                validate_subagent_type("px-agent", &ctx_x),
                SubagentValidateTypeOutcome::Ok
            ));
            assert_eq!(
                unknown_available(validate_subagent_type("no-such-agent", &ctx_x)),
                unknown_available(validate_subagent_type("no-such-agent", &today)),
            );

            // An evicted parent falls back to the process snapshot.
            let evicted = agent.build_subagent_validation_context("u39-evicted");
            assert!(matches!(
                (&evicted.plugin_registry, &snapshot),
                (Some(a), Some(b)) if Arc::ptr_eq(a, b)
            ));
        })
        .await;
    drop(home);
}

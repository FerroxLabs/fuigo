use std::path::PathBuf;

use super::*;
use crate::config_values::{ImportPatternMode, ImportPermission, ImportRuleAction, ImportTool};

fn server(command: &str) -> McpServerConfig {
    toml::from_str(&format!("command = \"{command}\"")).unwrap()
}

fn snapshot(permission_pattern: &str, env: &[(&str, &str)]) -> ClaudeSettingsSnapshot {
    ClaudeSettingsSnapshot {
        permissions: vec![ImportPermission {
            action: ImportRuleAction::Allow,
            tool: ImportTool::Bash,
            pattern: Some(permission_pattern.to_string()),
            pattern_mode: ImportPatternMode::Glob,
        }],
        env: env
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
    }
}

/// A snapshot per file, a skipped file, hooks read from the JSON, and the MCP lists, with the global/project split
/// decided by where the path is. A path is global only under the OS home's `.claude`, and the OS home is the
/// real one here, so the fixture paths are all project paths.
#[test]
fn scan_builds_a_plan_from_snapshots_hooks_and_server_lists() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path();
    git2::Repository::init(repo).unwrap();
    let with_hooks = repo.join("settings.json");
    std::fs::write(
        &with_hooks,
        r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo done"}]}]}}"#,
    )
    .unwrap();
    let skipped = repo.join("skipped.json");
    let paths: Vec<PathBuf> = vec![with_hooks.clone(), skipped.clone()];

    let plan = scan_importable_settings(
        repo,
        &paths,
        |path| (path == with_hooks).then(|| snapshot("ls", &[("A", "1"), ("B", "2")])),
        vec![("claude-json-srv".into(), server("one"))],
        vec![("mcp-json-srv".into(), server("two"))],
    );

    let kinds = |items: &[ImportableItem]| {
        items
            .iter()
            .map(|i| match i {
                ImportableItem::Permission(_) => "permission",
                ImportableItem::EnvVar { .. } => "env",
                ImportableItem::McpServer { .. } => "mcp",
                ImportableItem::Hook { .. } => "hook",
                ImportableItem::PathEntry { .. } => "path",
            })
            .collect::<Vec<_>>()
    };
    // The temp dir is not under the OS home's `.claude`, so its settings are project settings; the
    // ~/.claude.json servers are always global.
    let project = kinds(&plan.project_items);
    assert_eq!(
        project.get(..4),
        Some(["permission", "env", "env", "hook"].as_slice()),
        "{project:?}"
    );
    assert!(project.contains(&"mcp"), "the .mcp.json server is project-scoped");
    assert!(kinds(&plan.global_items).contains(&"mcp"), "the ~/.claude.json server is global");
    let env: Vec<_> = plan
        .project_items
        .iter()
        .filter_map(|i| match i {
            ImportableItem::EnvVar { key, .. } => Some(key.as_str()),
            _ => None,
        })
        .collect();
    assert_eq!(env, ["A", "B"], "the snapshot's order is kept");
}

#[test]
fn an_empty_scan_is_an_empty_plan() {
    let dir = tempfile::tempdir().unwrap();
    let plan = scan_importable_settings(dir.path(), &[], |_| None, vec![], vec![]);
    assert!(plan.global_items.iter().all(|i| matches!(i, ImportableItem::PathEntry { .. })),
        "only a real ~/.claude/{{skills,rules}} on this machine could appear");
    assert!(plan.project_items.is_empty());
}

#[test]
fn summary_redacts_env_values_and_lists_each_kind() {
    let dir = tempfile::tempdir().unwrap();
    let plan = ImportPlan {
        global_items: vec![
            ImportableItem::Permission(ImportPermission {
                action: ImportRuleAction::Deny,
                tool: ImportTool::Bash,
                pattern: Some("rm -rf *".into()),
                pattern_mode: ImportPatternMode::Glob,
            }),
            ImportableItem::EnvVar {
                key: "TOKEN".into(),
                value: "abcdef123".into(),
            },
        ],
        project_items: vec![
            ImportableItem::Hook {
                event: "Stop".into(),
                matcher: None,
                command: "echo done".into(),
                timeout: Some(3),
            },
            ImportableItem::PathEntry {
                kind: PathKind::Rule,
                path: "/r".into(),
            },
        ],
    };
    let text = plan.summary(dir.path());
    assert!(text.contains("Global (~/.fuigo/config.toml):"), "{text}");
    assert!(text.contains("1 permission rule(s) (1 deny)"), "{text}");
    assert!(text.contains("deny Bash(rm -rf *)"), "{text}");
    assert!(text.contains("TOKEN = <redacted, 9 chars>"), "{text}");
    assert!(!text.contains("abcdef123"), "{text}");
    assert!(text.contains("Stop [*] echo done (timeout: 3s)"), "{text}");
    assert!(text.contains("1 extra rule dir(s)"), "{text}");
    assert_eq!(ImportPlan::default().summary(dir.path()), "No Claude settings found to import.");
}

use std::path::Path;

use super::*;
use crate::config_values::{ImportPatternMode, ImportTool};

fn rule(action: ImportRuleAction, tool: ImportTool, pattern: Option<&str>) -> ImportableItem {
    ImportableItem::Permission(ImportPermission {
        action,
        tool,
        pattern: pattern.map(str::to_string),
        pattern_mode: ImportPatternMode::Glob,
    })
}

fn env(key: &str, value: &str) -> ImportableItem {
    ImportableItem::EnvVar {
        key: key.to_string(),
        value: value.to_string(),
    }
}

fn server(command: &str) -> Box<McpServerConfig> {
    Box::new(toml::from_str(&format!("command = \"{command}\"\nargs = [\"-y\"]")).unwrap())
}

fn patch(current: Option<&str>, items: &[ImportableItem]) -> (TomlValue, usize) {
    let patch = merge_items_into_config(Path::new("config.toml"), current, items).unwrap();
    let text = patch.contents.expect("the merge added something");
    (toml::from_str(&text).unwrap(), patch.count)
}

fn strings(value: &TomlValue) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect()
}

#[test]
fn permissions_are_appended_and_deduped_against_the_file() {
    let current = "[permission]\nallow = [\"Bash(npm test)\"]\n";
    let (parsed, count) = patch(
        Some(current),
        &[
            rule(ImportRuleAction::Allow, ImportTool::Bash, Some("npm test")),
            rule(ImportRuleAction::Allow, ImportTool::Bash, Some("npm run build")),
            rule(ImportRuleAction::Deny, ImportTool::Bash, Some("rm -rf *")),
            rule(ImportRuleAction::Ask, ImportTool::Any, None),
        ],
    );
    assert_eq!(count, 3);
    assert_eq!(strings(&parsed["permission"]["allow"]), ["Bash(npm test)", "Bash(npm run build)"]);
    assert_eq!(strings(&parsed["permission"]["deny"]), ["Bash(rm -rf *)"]);
    assert_eq!(strings(&parsed["permission"]["ask"]), ["*"]);
}

/// The same rule found in two source files is written once.
#[test]
fn a_rule_repeated_within_one_import_is_written_once() {
    let (parsed, count) = patch(
        None,
        &[
            rule(ImportRuleAction::Allow, ImportTool::Read, Some("src/**")),
            rule(ImportRuleAction::Allow, ImportTool::Read, Some("src/**")),
        ],
    );
    assert_eq!(count, 1);
    assert_eq!(strings(&parsed["permission"]["allow"]), ["Read(src/**)"]);
}

#[test]
fn env_vars_never_overwrite_and_create_the_section() {
    let (parsed, count) = patch(
        Some("[env]\nEXISTING = \"old\"\n"),
        &[env("EXISTING", "new"), env("NEW_VAR", "value")],
    );
    assert_eq!(count, 1);
    assert_eq!(parsed["env"]["EXISTING"].as_str(), Some("old"));
    assert_eq!(parsed["env"]["NEW_VAR"].as_str(), Some("value"));

    let (parsed, count) = patch(None, &[env("FOO", "bar")]);
    assert_eq!(count, 1);
    assert_eq!(parsed["env"]["FOO"].as_str(), Some("bar"));
}

#[test]
fn mcp_servers_never_overwrite_an_existing_name() {
    let items = [
        ImportableItem::McpServer {
            name: "mine".into(),
            config: server("replacement"),
        },
        ImportableItem::McpServer {
            name: "fresh".into(),
            config: server("npx"),
        },
    ];
    let (parsed, count) = patch(Some("[mcp_servers.mine]\ncommand = \"kept\"\n"), &items);
    assert_eq!(count, 1);
    assert_eq!(parsed["mcp_servers"]["mine"]["command"].as_str(), Some("kept"));
    assert_eq!(parsed["mcp_servers"]["fresh"]["command"].as_str(), Some("npx"));
}

#[test]
fn path_entries_fill_the_right_arrays_and_dedup() {
    let items = [
        ImportableItem::PathEntry {
            kind: PathKind::Skill,
            path: "/foo/skills".into(),
        },
        ImportableItem::PathEntry {
            kind: PathKind::Rule,
            path: "/bar/rules".into(),
        },
    ];
    let (parsed, count) = patch(None, &items);
    assert_eq!(count, 2);
    assert_eq!(strings(&parsed["paths"]["extra_skill_dirs"]), ["/foo/skills"]);
    assert_eq!(strings(&parsed["paths"]["extra_rule_dirs"]), ["/bar/rules"]);

    let again = merge_items_into_config(
        Path::new("config.toml"),
        Some("[paths]\nextra_skill_dirs = [\"/foo/skills\"]\nextra_rule_dirs = [\"/bar/rules\"]\n"),
        &items,
    )
    .unwrap();
    assert_eq!(again.count, 0);
    assert!(again.contents.is_none(), "nothing added, nothing to write");
}

#[test]
fn unrelated_sections_survive_and_hooks_are_not_written_here() {
    let current = "[ui]\ntheme = \"dark\"\n";
    let hook = ImportableItem::Hook {
        event: "Stop".into(),
        matcher: None,
        command: "true".into(),
        timeout: None,
    };
    let none = merge_items_into_config(Path::new("c.toml"), Some(current), std::slice::from_ref(&hook)).unwrap();
    assert!(none.contents.is_none());
    let (parsed, _) = patch(Some(current), &[hook, env("K", "v")]);
    assert_eq!(parsed["ui"]["theme"].as_str(), Some("dark"));
}

#[test]
fn a_config_that_does_not_parse_is_refused() {
    let err = merge_items_into_config(Path::new("/x/config.toml"), Some("[ui\nbroken"), &[env("K", "v")])
        .unwrap_err()
        .to_string();
    assert!(err.starts_with("refusing to import: existing config at /x/config.toml is not valid TOML"), "{err}");
    let err = marker_config_text(Path::new("/x/config.toml"), Some("[ui\nbroken"))
        .unwrap_err()
        .to_string();
    assert!(err.starts_with("refusing to write import marker: existing config at /x/config.toml"), "{err}");
}

#[test]
fn a_section_of_the_wrong_type_is_refused_not_overwritten() {
    for (current, items, want) in [
        ("permission = 1\n", vec![rule(ImportRuleAction::Allow, ImportTool::Bash, None)], "[permission] is not a table"),
        ("[permission]\nallow = \"x\"\n", vec![rule(ImportRuleAction::Allow, ImportTool::Bash, None)], "permission.allow is not an array"),
        ("paths = 1\n", vec![ImportableItem::PathEntry { kind: PathKind::Skill, path: "p".into() }], "[paths] is not a table"),
        ("mcp_servers = 1\n", vec![ImportableItem::McpServer { name: "n".into(), config: server("c") }], "[mcp_servers] is not a table"),
    ] {
        let err = merge_items_into_config(Path::new("c.toml"), Some(current), &items)
            .unwrap_err()
            .to_string();
        assert_eq!(err, want);
    }
    // An `[env]` that is not a table is skipped with a warning, not an error: the other items still import.
    let patch = merge_items_into_config(Path::new("c.toml"), Some("env = 1\n"), &[env("A", "b")]).unwrap();
    assert_eq!(patch.count, 0);
}

#[test]
fn the_marker_is_added_and_everything_else_kept() {
    let text = marker_config_text(Path::new("c.toml"), Some("[ui]\ntheme = \"dark\"\n")).unwrap();
    let parsed: TomlValue = toml::from_str(&text).unwrap();
    assert_eq!(parsed["claude_compat"]["imported"].as_bool(), Some(true));
    assert_eq!(parsed["ui"]["theme"].as_str(), Some("dark"));

    let fresh: TomlValue = toml::from_str(&marker_config_text(Path::new("c.toml"), None).unwrap()).unwrap();
    assert_eq!(fresh["claude_compat"]["imported"].as_bool(), Some(true));

    let again = marker_config_text(Path::new("c.toml"), Some(&text)).unwrap();
    assert_eq!(toml::from_str::<TomlValue>(&again).unwrap(), parsed, "idempotent");
}

#[test]
fn rules_format_back_to_the_compact_string() {
    let f = |tool, pattern: Option<&str>, mode| {
        format_rule_string(&ImportPermission {
            action: ImportRuleAction::Allow,
            tool,
            pattern: pattern.map(str::to_string),
            pattern_mode: mode,
        })
    };
    use ImportPatternMode::{Domain, Glob};
    assert_eq!(f(ImportTool::Bash, Some("npm run build"), Glob), "Bash(npm run build)");
    assert_eq!(f(ImportTool::Bash, None, Glob), "Bash");
    assert_eq!(f(ImportTool::Any, None, Glob), "*");
    assert_eq!(f(ImportTool::Any, Some("src/**"), Glob), "src/**");
    assert_eq!(f(ImportTool::WebFetch, Some("example.com"), Domain), "WebFetch(domain:example.com)");
    assert_eq!(f(ImportTool::Mcp, Some("srv"), Glob), "MCPTool(srv)");
}

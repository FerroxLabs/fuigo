//! One end-to-end regression test per Claude source format the importer reads, pinned through the public
//! surface only (`scan_importable_settings`, `apply_import`, `mark_claude_imported`, `ImportPlan::summary`):
//! what is found, which scope it lands in, and what is written where.
//!
//! Each test builds a private `HOME` (the OS home the scanner reads `~/.claude*` from) and a private
//! `FUIGO_HOME`, in a process of its own (`rerun_in_own_process`), holding ONE source format, so a break in one
//! reader fails exactly that reader's test.

use std::path::{Path, PathBuf};

use fuigo_test_support::EnvGuard;
use toml::Value as TomlValue;

use super::*;

struct World {
    _home_env: EnvGuard,
    _fuigo_env: EnvGuard,
    _dir: tempfile::TempDir,
    home: PathBuf,
    fuigo_home: PathBuf,
    proj: PathBuf,
}

impl World {
    /// A fake OS home, a git repo `proj` inside it, and a private fuigo home.
    fn new() -> World {
        let dir = tempfile::tempdir().unwrap();
        let home = dunce::canonicalize(dir.path()).unwrap();
        let fuigo_home = home.join("fuigo-home");
        let proj = home.join("proj");
        std::fs::create_dir_all(&fuigo_home).unwrap();
        std::fs::create_dir_all(&proj).unwrap();
        git2::Repository::init(&proj).unwrap();
        let _home_env = EnvGuard::set("HOME", &home);
        let _fuigo_env = EnvGuard::set("FUIGO_HOME", &fuigo_home);
        World {
            _home_env,
            _fuigo_env,
            _dir: dir,
            home,
            fuigo_home,
            proj,
        }
    }

    fn write(&self, path: &Path, contents: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    fn scan(&self) -> ImportPlan {
        scan_importable_settings(&self.proj)
    }

    fn apply(&self, plan: &ImportPlan) -> ImportResult {
        apply_import(plan, &self.proj).unwrap()
    }

    fn global_config(&self) -> TomlValue {
        read_toml(&self.fuigo_home.join("config.toml"))
    }

    fn project_config(&self) -> TomlValue {
        read_toml(&self.proj.join(".fuigo").join("config.toml"))
    }
}

fn read_toml(path: &Path) -> TomlValue {
    toml::from_str(&std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display())))
        .unwrap()
}

fn read_json(path: &Path) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display())))
        .unwrap()
}

fn strings(v: &TomlValue) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_owned())
        .collect()
}

fn permissions(items: &[ImportableItem]) -> usize {
    items
        .iter()
        .filter(|i| matches!(i, ImportableItem::Permission(_)))
        .count()
}

fn env_vars(items: &[ImportableItem]) -> Vec<(String, String)> {
    let mut v: Vec<_> = items
        .iter()
        .filter_map(|i| match i {
            ImportableItem::EnvVar { key, value } => Some((key.clone(), value.clone())),
            _ => None,
        })
        .collect();
    v.sort();
    v
}

fn hooks(items: &[ImportableItem]) -> Vec<(String, Option<String>, String, Option<u64>)> {
    items
        .iter()
        .filter_map(|i| match i {
            ImportableItem::Hook {
                event,
                matcher,
                command,
                timeout,
            } => Some((event.clone(), matcher.clone(), command.clone(), *timeout)),
            _ => None,
        })
        .collect()
}

fn mcp_names(items: &[ImportableItem]) -> Vec<String> {
    let mut v: Vec<_> = items
        .iter()
        .filter_map(|i| match i {
            ImportableItem::McpServer { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect();
    v.sort();
    v
}

fn path_entries(items: &[ImportableItem]) -> Vec<(PathKind, String)> {
    items
        .iter()
        .filter_map(|i| match i {
            ImportableItem::PathEntry { kind, path } => Some((*kind, path.clone())),
            _ => None,
        })
        .collect()
}

#[cfg(unix)]
fn assert_owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode & 0o077, 0, "{} is {mode:o}: imported settings may carry credentials", path.display());
}

#[cfg(not(unix))]
fn assert_owner_only(_path: &Path) {}

// ---- ~/.claude/settings.json and the project's .claude/settings.json: permissions ----

#[test]
fn format_settings_permissions() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = World::new();
    w.write(
        &w.home.join(".claude/settings.json"),
        r#"{"permissions":{
            "allow":["Bash(npm run build)","Read(src/*.rs)","Bash(git status:*)"],
            "deny":["Bash(rm -rf *)"],
            "ask":["WebFetch(domain:example.com)","Edit"]}}"#,
    );
    w.write(
        &w.proj.join(".claude/settings.local.json"),
        r#"{"permissions":{"allow":["Edit(docs/**)"],"deny":["NotARealTool(x)"]}}"#,
    );
    let plan = w.scan();
    assert_eq!(permissions(&plan.global_items), 6, "user-tier rules land in the global scope");
    assert_eq!(permissions(&plan.project_items), 1, "an unparseable rule is skipped, the rest kept");
    assert_eq!(plan.total_items(), 7);

    let result = w.apply(&plan);
    assert_eq!((result.global_count, result.project_count), (6, 1));
    let global = w.global_config();
    assert_eq!(
        strings(&global["permission"]["allow"]),
        ["Bash(npm run build)", "Read(src/*.rs)", "Bash(git status)"]
    );
    assert_eq!(strings(&global["permission"]["deny"]), ["Bash(rm -rf *)"]);
    assert_eq!(strings(&global["permission"]["ask"]), ["WebFetch(domain:example.com)", "Edit"]);
    assert_eq!(strings(&w.project_config()["permission"]["allow"]), ["Edit(docs/**)"]);
    assert_owner_only(&w.fuigo_home.join("config.toml"));
    assert_owner_only(&w.proj.join(".fuigo/config.toml"));
}

// ---- the same files' `env` blocks (settings.json and settings.local.json) ----

#[test]
fn format_settings_env() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = World::new();
    w.write(&w.home.join(".claude/settings.json"), r#"{"env":{"G_KEY":"g-value-1"}}"#);
    w.write(&w.home.join(".claude/settings.local.json"), r#"{"env":{"L_KEY":"local-value"}}"#);
    w.write(&w.proj.join(".claude/settings.json"), r#"{"env":{"P_KEY":"proj-value"}}"#);
    let plan = w.scan();
    assert_eq!(
        env_vars(&plan.global_items),
        [("G_KEY".into(), "g-value-1".into()), ("L_KEY".into(), "local-value".into())]
    );
    assert_eq!(env_vars(&plan.project_items), [("P_KEY".into(), "proj-value".into())]);

    // The human-facing summary shows the length, never the value.
    let summary = plan.summary(&w.proj);
    assert!(summary.contains("G_KEY = <redacted, 9 chars>"), "{summary}");
    for secret in ["g-value-1", "local-value", "proj-value"] {
        assert!(!summary.contains(secret), "summary leaked {secret}: {summary}");
    }

    let result = w.apply(&plan);
    assert_eq!((result.global_count, result.project_count), (2, 1));
    let global = w.global_config();
    assert_eq!(global["env"]["G_KEY"].as_str(), Some("g-value-1"));
    assert_eq!(global["env"]["L_KEY"].as_str(), Some("local-value"));
    assert_eq!(w.project_config()["env"]["P_KEY"].as_str(), Some("proj-value"));

    // Additive only: a value already in config.toml is never overwritten.
    w.write(
        &w.fuigo_home.join("config.toml"),
        "[env]\nG_KEY = \"mine\"\n",
    );
    let again = w.apply(&plan);
    assert_eq!(again.global_count, 1, "only L_KEY is new");
    let global = w.global_config();
    assert_eq!(global["env"]["G_KEY"].as_str(), Some("mine"));
    assert_eq!(global["env"]["L_KEY"].as_str(), Some("local-value"));
}

/// Environment variables come out of a scan in key order, not in the order a hash map happens to yield them,
/// so the summary, the import modal and the written `[env]` table read the same every run.
#[test]
fn format_settings_env_order_is_stable() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = World::new();
    let keys = ["K8", "K3", "K6", "K1", "K7", "K2", "K5", "K4"];
    let body = keys
        .iter()
        .map(|k| format!("\"{k}\":\"v\""))
        .collect::<Vec<_>>()
        .join(",");
    w.write(&w.home.join(".claude/settings.json"), &format!("{{\"env\":{{{body}}}}}"));
    let plan = w.scan();
    let order: Vec<String> = plan
        .global_items
        .iter()
        .filter_map(|i| match i {
            ImportableItem::EnvVar { key, .. } => Some(key.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(order, ["K1", "K2", "K3", "K4", "K5", "K6", "K7", "K8"]);
}

// ---- the `hooks` blocks: command handlers only, written to imported-from-claude.json ----

#[test]
fn format_settings_hooks() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = World::new();
    w.write(
        &w.home.join(".claude/settings.json"),
        r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[
            {"type":"command","command":"echo global-hook","timeout":5},
            {"type":"http","url":"http://127.0.0.1:9/ignored"}]}]}}"#,
    );
    w.write(
        &w.proj.join(".claude/settings.json"),
        r#"{"hooks":{"Stop":[{"hooks":[{"type":"command","command":"echo proj-stop"}]}]}}"#,
    );
    let plan = w.scan();
    assert_eq!(
        hooks(&plan.global_items),
        [("PreToolUse".into(), Some("Bash".into()), "echo global-hook".into(), Some(5))],
        "the http handler is not imported"
    );
    assert_eq!(
        hooks(&plan.project_items),
        [("Stop".into(), None, "echo proj-stop".into(), None)]
    );
    let summary = plan.summary(&w.proj);
    assert!(summary.contains("PreToolUse [Bash] echo global-hook (timeout: 5s)"), "{summary}");

    let result = w.apply(&plan);
    assert_eq!((result.global_count, result.project_count), (1, 1));
    let g = read_json(&w.fuigo_home.join("hooks/imported-from-claude.json"));
    let group = &g["hooks"]["PreToolUse"][0];
    assert_eq!(group["matcher"], "Bash");
    assert_eq!(group["hooks"][0]["type"], "command");
    assert_eq!(group["hooks"][0]["command"], "echo global-hook");
    assert_eq!(group["hooks"][0]["timeout"], 5);
    let p = read_json(&w.proj.join(".fuigo/hooks/imported-from-claude.json"));
    assert_eq!(p["hooks"]["Stop"][0]["hooks"][0]["command"], "echo proj-stop");
    assert!(p["hooks"]["Stop"][0].get("matcher").is_none());

    // Re-importing adds nothing, and a changed timeout is refreshed in place.
    assert_eq!(w.apply(&plan).total(), 0);
    w.write(
        &w.home.join(".claude/settings.json"),
        r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"echo global-hook","timeout":9}]}]}}"#,
    );
    let replan = w.scan();
    assert_eq!(w.apply(&replan).total(), 0, "a refresh is not a new hook");
    let g = read_json(&w.fuigo_home.join("hooks/imported-from-claude.json"));
    assert_eq!(g["hooks"]["PreToolUse"][0]["hooks"][0]["timeout"], 9);
    assert_eq!(g["hooks"]["PreToolUse"].as_array().unwrap().len(), 1);
}

// ---- ~/.claude.json: user-level servers and this project's entry ----

#[test]
fn format_claude_json_mcp_servers() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = World::new();
    let claude_json = serde_json::json!({
        "mcpServers": {"user-srv": {"command": "npx", "args": ["-y", "user-mcp"]}},
        "projects": {
            w.proj.to_string_lossy(): {"mcpServers": {
                "proj-local-srv": {"type": "http", "url": "https://example.com/mcp"}}},
            "/somewhere/else": {"mcpServers": {"other-srv": {"command": "no"}}}
        }
    });
    w.write(&w.home.join(".claude.json"), &claude_json.to_string());
    let plan = w.scan();
    assert_eq!(mcp_names(&plan.global_items), ["proj-local-srv", "user-srv"]);
    assert!(mcp_names(&plan.project_items).is_empty());

    let result = w.apply(&plan);
    assert_eq!(result.global_count, 2);
    let global = w.global_config();
    assert_eq!(global["mcp_servers"]["user-srv"]["command"].as_str(), Some("npx"));
    assert_eq!(
        global["mcp_servers"]["proj-local-srv"]["url"].as_str(),
        Some("https://example.com/mcp")
    );
    assert!(global["mcp_servers"].get("other-srv").is_none());
    assert_owner_only(&w.fuigo_home.join("config.toml"));
}

// ---- <repo>/.mcp.json ----

#[test]
fn format_mcp_json_servers() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = World::new();
    w.write(
        &w.proj.join(".mcp.json"),
        r#"{"mcpServers":{"repo-srv":{"command":"node","args":["srv.js"],"env":{"TOKEN":"abc"}}}}"#,
    );
    let plan = w.scan();
    assert_eq!(mcp_names(&plan.project_items), ["repo-srv"]);
    assert!(mcp_names(&plan.global_items).is_empty());

    let result = w.apply(&plan);
    assert_eq!((result.global_count, result.project_count), (0, 1));
    let project = w.project_config();
    assert_eq!(project["mcp_servers"]["repo-srv"]["command"].as_str(), Some("node"));
    assert_eq!(project["mcp_servers"]["repo-srv"]["args"][0].as_str(), Some("srv.js"));
    assert_owner_only(&w.proj.join(".fuigo/config.toml"));

    // Additive only: a server already configured under that name is kept as it is.
    w.write(
        &w.proj.join(".fuigo/config.toml"),
        "[mcp_servers.repo-srv]\ncommand = \"mine\"\n",
    );
    assert_eq!(w.apply(&plan).total(), 0);
    assert_eq!(w.project_config()["mcp_servers"]["repo-srv"]["command"].as_str(), Some("mine"));
}

// ---- ~/.claude/{skills,rules} and <repo>/.claude/{skills,rules} directories ----

#[test]
fn format_claude_skill_and_rule_dirs() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = World::new();
    std::fs::create_dir_all(w.home.join(".claude/skills")).unwrap();
    std::fs::create_dir_all(w.proj.join(".claude/skills")).unwrap();
    std::fs::create_dir_all(w.proj.join(".claude/rules")).unwrap();
    let plan = w.scan();
    let s = |p: PathBuf| p.to_string_lossy().into_owned();
    assert_eq!(
        path_entries(&plan.global_items),
        [(PathKind::Skill, s(w.home.join(".claude/skills")))]
    );
    let mut project = path_entries(&plan.project_items);
    project.sort_by_key(|(_, p)| p.clone());
    assert_eq!(
        project,
        [
            (PathKind::Rule, s(w.proj.join(".claude/rules"))),
            (PathKind::Skill, s(w.proj.join(".claude/skills"))),
        ]
    );

    let result = w.apply(&plan);
    assert_eq!((result.global_count, result.project_count), (1, 2));
    assert_eq!(
        strings(&w.global_config()["paths"]["extra_skill_dirs"]),
        [s(w.home.join(".claude/skills"))]
    );
    let project = w.project_config();
    assert_eq!(strings(&project["paths"]["extra_skill_dirs"]), [s(w.proj.join(".claude/skills"))]);
    assert_eq!(strings(&project["paths"]["extra_rule_dirs"]), [s(w.proj.join(".claude/rules"))]);
}

// ---- the opt-in marker, and a config.toml that is not valid TOML ----

#[test]
fn format_import_marker_and_refusal_to_clobber() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let w = World::new();
    let config = w.fuigo_home.join("config.toml");
    w.write(&config, "[ui]\ntheme = \"dark\"\n");
    reset_marker_cache_for_test();
    assert!(!is_claude_import_marked_at(&config));
    mark_claude_imported().unwrap();
    assert!(is_claude_import_marked(), "the in-process cache reflects the marker at once");
    let parsed = read_toml(&config);
    assert_eq!(parsed["claude_compat"]["imported"].as_bool(), Some(true));
    assert_eq!(parsed["ui"]["theme"].as_str(), Some("dark"), "other sections survive");
    assert_owner_only(&config);
    reset_marker_cache_for_test();

    // A config.toml that does not parse is never rewritten, by the marker or by an import.
    w.write(&config, "[ui\nbroken");
    let before = std::fs::read_to_string(&config).unwrap();
    let err = mark_claude_imported().unwrap_err().to_string();
    assert!(err.contains("not valid TOML"), "{err}");
    let plan = ImportPlan {
        global_items: vec![ImportableItem::EnvVar {
            key: "K".into(),
            value: "v".into(),
        }],
        project_items: vec![],
    };
    let err = apply_import(&plan, &w.proj).unwrap_err().to_string();
    assert!(err.contains("not valid TOML"), "{err}");
    assert_eq!(std::fs::read_to_string(&config).unwrap(), before);
}

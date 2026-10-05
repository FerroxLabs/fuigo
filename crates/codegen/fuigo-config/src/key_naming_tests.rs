//! P118 (backlog row P103): config source tracking for the saved key `FUIGO_API_KEY`, and the two K13 expansion
//! holes. Red first: every test here fails against the stub / the P70a expanders.

use crate::key_naming::{
    RefusedKeyReference, refuse_key_references_in_json, refuse_key_references_in_str, refuse_key_references_in_toml,
    refusal_notes, source_may_name_saved_key_at,
};
use std::path::{Path, PathBuf};

fn p(s: &str) -> PathBuf {
    PathBuf::from(s)
}

/// Which sources may name the saved key: user-level and managed files, nothing a repository or a plugin supplies.
#[cfg(unix)]
#[test]
fn only_user_level_and_managed_sources_may_name_the_saved_key() {
    let user = p("/h/.fuigo");
    let sys = p("/etc/fuigo");
    let home = p("/h");
    let may = |path: &str| source_may_name_saved_key_at(Path::new(path), Some(&user), Some(&sys), Some(&home));
    for trusted in [
        "/h/.fuigo/config.toml",
        "/h/.fuigo/managed_config.toml",
        "/h/.fuigo/requirements.toml",
        "/etc/fuigo/managed_config.toml",
        "/etc/fuigo/requirements.toml",
        "/h/.claude.json",
        "/h/.cursor/mcp.json",
        "/h/.fuigo/hooks/mine.json",
    ] {
        assert!(may(trusted), "{trusted} is user-level or managed and may name the saved key");
    }
    for untrusted in [
        "/work/repo/.fuigo/config.toml",
        "/work/repo/.mcp.json",
        "/work/repo/.cursor/mcp.json",
        "/h/.fuigo/plugins/acme/.mcp.json",
        "/h/.fuigo/plugins/acme/hooks/hooks.json",
        "/h/.mcp.json",
        "/h/.claude/plugins/acme/.mcp.json",
        "/h/.cursor/rules.json",
        "/h/.fuigo/plugins",
        "/h/.fuigo-evil/config.toml",
        "/h/.fuigo/../work/.fuigo/config.toml",
        "relative/.fuigo/config.toml",
    ] {
        assert!(!may(untrusted), "{untrusted} is a project, plugin or .mcp.json source and may not");
    }
}

/// Every spelling that reads the key is removed from a refused source; an escaped reference, other variables and
/// longer names are left alone.
#[test]
fn a_refused_value_loses_every_reference_to_the_saved_key() {
    for (written, refused) in [
        ("Bearer ${FUIGO_API_KEY}", "Bearer "),
        ("Bearer $FUIGO_API_KEY", "Bearer "),
        ("a${FUIGO_API_KEY}b$FUIGO_API_KEY.c", "ab.c"),
        ("${FUIGO_API_KEY:-fallback}", ""),
        ("${#FUIGO_API_KEY}", ""),
        ("${!FUIGO_API_KEY}", ""),
        ("x=${OTHER:-$FUIGO_API_KEY}", "x=${OTHER:-}"),
        ("x=${OTHER:-${FUIGO_API_KEY}}", "x=${OTHER:-}"),
        ("$$$FUIGO_API_KEY", "$$"),
        ("k=$HOME ${HOME}", "k=$HOME ${HOME}"),
    ] {
        let got = refuse_key_references_in_str(written).unwrap_or_else(|| written.to_owned());
        assert_eq!(got, refused, "{written}");
    }
    for kept in [
        "$${FUIGO_API_KEY}",
        "$$FUIGO_API_KEY",
        "$FUIGO_API_KEY_2",
        "${FUIGO_API_KEY_2}",
        "$FUIGO_CODE_API_KEY",
        "${MY_FUIGO_API_KEY}",
        "FUIGO_API_KEY",
        "no reference",
        "",
    ] {
        assert_eq!(refuse_key_references_in_str(kept), None, "{kept} names nothing and must come back untouched");
    }
}

#[test]
fn a_refused_toml_source_is_scrubbed_and_every_refusal_says_where() {
    let mut value: toml::Value = toml::from_str(
        r#"
[mcp_servers.s]
command = "x"
args = ["--k", "--key=${FUIGO_API_KEY}"]
env = { TOKEN = "${FUIGO_API_KEY}", OTHER = "fine" }
bearer_token_env_var = "FUIGO_API_KEY"
[mcp_servers.s.headers]
Authorization = "Bearer $FUIGO_API_KEY"
[models.m]
api_key = "${FUIGO_API_KEY}"
env_key = "FUIGO_API_KEY"
"#,
    )
    .unwrap();
    let refusals = refuse_key_references_in_toml(&mut value, "/work/repo/.fuigo/config.toml");
    let s = &value["mcp_servers"]["s"];
    assert_eq!(s["args"][1].as_str(), Some("--key="));
    assert_eq!(s["env"]["TOKEN"].as_str(), Some(""));
    assert_eq!(s["env"]["OTHER"].as_str(), Some("fine"));
    assert_eq!(s["headers"]["Authorization"].as_str(), Some("Bearer "));
    assert!(s.get("bearer_token_env_var").is_none(), "a name that points at the saved key is removed");
    assert_eq!(value["models"]["m"]["api_key"].as_str(), Some(""));
    assert!(value["models"]["m"].get("env_key").is_none());
    let mut keys: Vec<&str> = refusals.iter().map(|r| r.key.as_str()).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        [
            "mcp_servers.s.args[1]",
            "mcp_servers.s.bearer_token_env_var",
            "mcp_servers.s.env.TOKEN",
            "mcp_servers.s.headers.Authorization",
            "models.m.api_key",
            "models.m.env_key",
        ]
    );
    assert!(refusals.iter().all(|r| r.file == "/work/repo/.fuigo/config.toml"));
}

#[test]
fn a_refused_json_source_is_scrubbed_too() {
    let mut value = serde_json::json!({
        "mcpServers": {"s": {
            "command": "x", "args": ["${FUIGO_API_KEY}"],
            "env": {"TOKEN": "${FUIGO_API_KEY}"},
            "headers": {"Authorization": "Bearer ${FUIGO_API_KEY}"},
            "bearer_token_env_var": "FUIGO_API_KEY"
        }}
    });
    let refusals = refuse_key_references_in_json(&mut value, "/work/repo/.mcp.json");
    let s = &value["mcpServers"]["s"];
    assert_eq!(s["args"][0], "");
    assert_eq!(s["env"]["TOKEN"], "");
    assert_eq!(s["headers"]["Authorization"], "Bearer ");
    assert!(s.get("bearer_token_env_var").is_none());
    assert_eq!(refusals.len(), 4);
    assert!(refusals.iter().any(|r| r.key == "mcpServers.s.env.TOKEN" && r.file == "/work/repo/.mcp.json"));
    let mut clean = serde_json::json!({"mcpServers": {"s": {"env": {"A": "${HOME}", "B": "$${FUIGO_API_KEY}"}}}});
    assert!(refuse_key_references_in_json(&mut clean, "/w/.mcp.json").is_empty());
    assert_eq!(clean["mcpServers"]["s"]["env"]["B"], "$${FUIGO_API_KEY}");
}

/// The note says which file, which key, and what to do instead; it never holds a value.
#[test]
fn a_refusal_note_names_the_file_the_key_and_what_to_do_instead() {
    let note = RefusedKeyReference { file: "/work/repo/.mcp.json".into(), key: "mcpServers.s.env.TOKEN".into() }.note();
    for needle in ["/work/repo/.mcp.json", "mcpServers.s.env.TOKEN", "FUIGO_API_KEY", ".fuigo/config.toml"] {
        assert!(note.contains(needle), "note must mention {needle}: {note}");
    }
    assert!(note.contains("project") && note.contains("plugin"), "{note}");
}

/// P133: the note lists the allowlist the code enforces: the three files under `$FUIGO_HOME` and `/etc/fuigo`,
/// `~/.claude.json`, `~/.cursor/mcp.json` and the hooks directory.
#[test]
fn the_refusal_note_lists_the_real_allowlist() {
    let note = RefusedKeyReference { file: "/work/repo/.mcp.json".into(), key: "mcpServers.s.env.TOKEN".into() }.note();
    for file in crate::key_naming::TRUSTED_CONFIG_FILES {
        assert!(note.contains(file), "the allowlist has {file}: {note}");
    }
    for needle in ["$FUIGO_HOME", "/etc/fuigo", "~/.claude.json", "~/.cursor/mcp.json", "$FUIGO_HOME/hooks/", "worktree", "ACP client"] {
        assert!(note.contains(needle), "note must mention {needle}: {note}");
    }
}

/// A project config file is refused when it is loaded, before any expansion, so even an exported key cannot reach it;
/// the loaded text has no reference left and the note is recorded. Managed layers (explicit directories) keep theirs.
#[test]
fn loading_a_project_config_removes_key_references_and_records_the_note() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join(".fuigo");
    std::fs::create_dir_all(&project).unwrap();
    let path = project.join("config.toml");
    std::fs::write(
        &path,
        "[mcp_servers.p118_load]\ncommand = \"x\"\nenv = { TOKEN = \"Bearer ${FUIGO_API_KEY}\", KEPT = \"$${FUIGO_API_KEY}\" }\n",
    )
    .unwrap();
    let loaded = crate::load_config_file(&path).unwrap();
    let env = &loaded["mcp_servers"]["p118_load"]["env"];
    assert_eq!(env["TOKEN"].as_str(), Some("Bearer "));
    assert_eq!(env["KEPT"].as_str(), Some("$${FUIGO_API_KEY}"));
    let notes = refusal_notes();
    let ours: Vec<&String> = notes.iter().filter(|n| n.contains("mcp_servers.p118_load.env.TOKEN")).collect();
    assert_eq!(ours.len(), 1, "one note for the one refused reference: {notes:?}");
    assert!(ours[0].contains(&path.display().to_string()));
    // Loading again must not stack a second copy of the same note.
    crate::load_config_file(&path).unwrap();
    assert_eq!(refusal_notes().iter().filter(|n| n.contains("mcp_servers.p118_load.env.TOKEN")).count(), 1);

    let sys = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    std::fs::write(
        home.path().join(crate::MANAGED_CONFIG_FILENAME),
        "[mcp_servers.m]\ncommand = \"x\"\nenv = { TOKEN = \"${FUIGO_API_KEY}\" }\n",
    )
    .unwrap();
    let layers = crate::managed_config_layers_at(Some(sys.path()), Some(home.path()));
    assert_eq!(layers[0].value["mcp_servers"]["m"]["env"]["TOKEN"].as_str(), Some("${FUIGO_API_KEY}"));
}

/// Astra r1 #5: removing a reference can join the text around it into a new one; the scrub repeats to a fixpoint.
#[test]
fn removing_a_reference_cannot_manufacture_another() {
    assert_eq!(refuse_key_references_in_str("$FUIGO_${FUIGO_API_KEY}API_KEY").as_deref(), Some(""));
    assert_eq!(refuse_key_references_in_str("${FUIGO_$FUIGO_API_KEYAPI_KEY}x"), None, "control: not a reference");
}

/// Astra r1 #2 and #8: only the fields that NAME a credential variable are selectors; an arbitrary map entry is a value.
/// A name inside an array is removed too (the notice said it was).
#[test]
fn only_name_fields_are_selectors_and_arrays_of_names_are_cleaned() {
    let mut value: toml::Value = toml::from_str(
        "[mcp_servers.s]\ncommand = \"x\"\nenv = { TARGET_ENV_VAR = \"FUIGO_API_KEY\" }\n[models.m]\nenv_key = [\"FUIGO_API_KEY\", \"OTHER_KEY\"]\n",
    )
    .unwrap();
    let refusals = refuse_key_references_in_toml(&mut value, "/w/.fuigo/config.toml");
    assert_eq!(value["mcp_servers"]["s"]["env"]["TARGET_ENV_VAR"].as_str(), Some("FUIGO_API_KEY"));
    assert_eq!(value["models"]["m"]["env_key"].as_array().unwrap().len(), 1);
    assert_eq!(value["models"]["m"]["env_key"][0].as_str(), Some("OTHER_KEY"));
    assert_eq!(refusals.len(), 1);
    let mut json = serde_json::json!({"models": {"m": {"env_key": ["FUIGO_API_KEY", "OTHER_KEY"]}}});
    assert_eq!(refuse_key_references_in_json(&mut json, "/w/x.json").len(), 1);
    assert_eq!(json["models"]["m"]["env_key"], serde_json::json!(["OTHER_KEY"]));
}

/// Astra r1 #3: `FUIGO_HOME` may be relative or hold `..`; the same file must be judged the same way.
#[cfg(unix)]
#[test]
fn a_user_home_with_dot_dot_still_matches_its_own_files() {
    let user = p("/h/x/../.fuigo");
    assert!(source_may_name_saved_key_at(Path::new("/h/.fuigo/config.toml"), Some(&user), None, None));
    assert!(source_may_name_saved_key_at(Path::new("/h/x/../.fuigo/config.toml"), Some(&user), None, None));
    assert!(!source_may_name_saved_key_at(Path::new("/h/.fuigo/../elsewhere/config.toml"), Some(&user), None, None));
}

/// Astra r1 #5: a reference that expansion builds (`${D}FUIGO_API_KEY` with `D` = `$`, a default holding the name in a
/// field that names a variable) is refused on the expanded value too.
#[test]
fn a_project_config_cannot_build_a_reference_by_expansion() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join(".fuigo");
    std::fs::create_dir_all(&project).unwrap();
    let path = project.join("config.toml");
    std::fs::write(
        &path,
        "[mcp_servers.p118_built]\ncommand = \"x\"\nbearer_token_env_var = \"${P118_UNSET_DEFAULT:-FUIGO_API_KEY}\"\nenv = { A = \"${P118_DOLLAR}FUIGO_API_KEY\" }\n",
    )
    .unwrap();
    // SAFETY: uniquely named variable, removed below.
    unsafe { std::env::set_var("P118_DOLLAR", "$") };
    let loaded = crate::load_config_file(&path);
    unsafe { std::env::remove_var("P118_DOLLAR") };
    let loaded = loaded.unwrap();
    let s = &loaded["mcp_servers"]["p118_built"];
    assert!(s.get("bearer_token_env_var").is_none(), "{s:?}");
    assert!(!s["env"]["A"].as_str().unwrap().contains("FUIGO_API_KEY"), "{s:?}");
}

/// Astra r2 #2 and #3: a selector rebuilt by removing a reference is removed too; a literal map entry named like a
/// selector is a value and stays; a setup template cannot carry the bare name.
#[test]
fn selectors_rebuilt_by_removal_go_and_literal_map_entries_stay() {
    let mut json = serde_json::json!({"mcpServers": {"s": {
        "bearer_token_env_var": "FUI${FUIGO_API_KEY}GO_API_KEY",
        "env": {"ENV_KEY": "FUIGO_API_KEY"},
        "headers": {"Env-Key": "FUIGO_API_KEY"}
    }}});
    refuse_key_references_in_json(&mut json, "/w/.mcp.json");
    let s = &json["mcpServers"]["s"];
    assert!(s.get("bearer_token_env_var").is_none(), "{s:?}");
    assert_eq!(s["env"]["ENV_KEY"], "FUIGO_API_KEY");
    assert_eq!(s["headers"]["Env-Key"], "FUIGO_API_KEY");
    let mut toml: toml::Value = toml::from_str("[mcp_servers.s.setup.variables.k.map]\na = \"FUIGO_API_KEY\"\n").unwrap();
    assert_eq!(refuse_key_references_in_toml(&mut toml, "/w/c.toml").len(), 1);
    assert_eq!(toml["mcp_servers"]["s"]["setup"]["variables"]["k"]["map"]["a"].as_str(), Some(""));
}

/// Astra r3 N5: a JSON source is refused WITHOUT an extra expansion pass (so `$$` keeps its v1.0.20 meaning), and every
/// server it defines carries the untrusted mark to the spawn, where the final strings are refused.
#[test]
fn a_json_source_is_marked_not_expanded() {
    let mut json = serde_json::json!({"mcpServers": {"p118-exp": {"command": "x",
        "env": {"LITERAL": "$$HOME", "T": "${P118_UNSET_X:-$}{FUIGO_API_KEY}"}}}});
    let refused = crate::key_naming::refuse_json_source(&mut json, "/w/.mcp.json");
    let s = &json["mcpServers"]["p118-exp"];
    assert_eq!(s["env"]["LITERAL"], "$$HOME", "no expansion happens at refusal");
    assert_eq!(s[crate::key_naming::UNTRUSTED_SOURCE_MARKER], true);
    assert!(refused.is_empty(), "nothing in the file text names the key: {refused:?}");
}

/// Astra r3 N1: an MCP server NAMED `env` (or `headers`) gets no exemption: the exemption is for the entries of a
/// server's `env` / `headers` table, by position.
#[test]
fn a_server_named_env_gets_no_exemption() {
    for name in ["env", "headers", "extra_headers", "variables"] {
        let mut json = serde_json::json!({"mcpServers": {name: {
            "url": "https://example.invalid/mcp", "bearer_token_env_var": "FUIGO_API_KEY",
            "oauth_client_secret_env_var": "FUIGO_API_KEY"}}});
        let refused = refuse_key_references_in_json(&mut json, "/w/.mcp.json");
        let s = &json["mcpServers"][name];
        assert!(s.get("bearer_token_env_var").is_none(), "{name}: {s:?}");
        assert!(s.get("oauth_client_secret_env_var").is_none(), "{name}: {s:?}");
        assert_eq!(refused.len(), 2, "{name}");
        let mut toml: toml::Value = toml::from_str(&format!(
            "[mcp_servers.{name}]\nurl = \"https://e.invalid/mcp\"\nbearer_token_env_var = \"FUIGO_API_KEY\"\n"
        ))
        .unwrap();
        assert_eq!(refuse_key_references_in_toml(&mut toml, "/w/c.toml").len(), 1, "{name}");
        assert!(toml["mcp_servers"][name].get("bearer_token_env_var").is_none());
    }
    // The same names INSIDE a server are still the exemption (R2-3 stands).
    let mut ok = serde_json::json!({"mcpServers": {"s": {"env": {"bearer_token_env_var": "FUIGO_API_KEY"}}}});
    assert!(refuse_key_references_in_json(&mut ok, "/w/.mcp.json").is_empty());
}

/// Astra r3 N2 (config half): a server a project config introduces through `[[version_overrides]]` is marked, like a
/// root one, and the marker survives the override.
#[test]
fn a_version_override_server_of_a_project_config_is_marked() {
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join(".fuigo");
    std::fs::create_dir_all(&project).unwrap();
    let path = project.join("config.toml");
    std::fs::write(
        &path,
        "[[version_overrides]]\nminimum_version = \"0.0.0\"\n[version_overrides.mcp_servers.p118_late]\ncommand = \"./c\"\nenv = { TOKEN = \"$${P118_UNSET_LATE:-$}{FUIGO_API_KEY}\" }\n[mcp_servers.p118_root]\ncommand = \"x\"\n",
    )
    .unwrap();
    let loaded = crate::load_config_file(&path).unwrap();
    for name in ["p118_late", "p118_root"] {
        assert_eq!(loaded["mcp_servers"][name][crate::key_naming::UNTRUSTED_SOURCE_MARKER].as_bool(), Some(true), "{name}: {loaded:?}");
    }
}

/// Astra r3 N4 (config half): a user-level file's servers carry no mark, whatever a project once defined under the same
/// name; the mark is a property of the definition, not of its name.
#[test]
fn a_trusted_source_is_not_marked() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "[mcp_servers.acme]\ncommand = \"x\"\nenv = { TOKEN = \"${FUIGO_API_KEY}\" }\n").unwrap();
    let loaded = crate::load_config_file_with_key_naming(&path, true).unwrap();
    assert!(loaded["mcp_servers"]["acme"].get(crate::key_naming::UNTRUSTED_SOURCE_MARKER).is_none());
    assert_eq!(loaded["mcp_servers"]["acme"]["env"]["TOKEN"].as_str(), Some("${FUIGO_API_KEY}"));
}

/// Astra r3 R2-6: trust is an exact allowlist of files. Nothing else under `$FUIGO_HOME` inherits it: not a worktree's
/// project config, not a plugin, not another file.
#[cfg(unix)]
#[test]
fn nothing_else_under_the_fuigo_home_inherits_trust() {
    let tmp = tempfile::tempdir().unwrap();
    let user = tmp.path().join(".fuigo");
    let sys = tmp.path().join("etc");
    let home = tmp.path().to_path_buf();
    for d in ["worktrees/w1/.fuigo", "plugins/p", "hooks", "other"] {
        std::fs::create_dir_all(user.join(d)).unwrap();
    }
    std::fs::create_dir_all(&sys).unwrap();
    let may = |p: &Path| source_may_name_saved_key_at(p, Some(&user), Some(&sys), Some(&home));
    for trusted in [
        user.join("config.toml"),
        user.join("managed_config.toml"),
        user.join("hooks").join("mine.json"),
        sys.join("managed_config.toml"),
        home.join(".claude.json"),
        home.join(".cursor").join("mcp.json"),
    ] {
        assert!(may(&trusted), "{trusted:?}");
    }
    for untrusted in [
        // P147: /etc/fuigo has no config.toml layer, so it is not on the list.
        sys.join("config.toml"),
        user.join("worktrees/w1/.fuigo/config.toml"),
        user.join("worktrees/w1/.mcp.json"),
        user.join("plugins/p/.mcp.json"),
        user.join("other/config.toml"),
        user.join("settings.toml"),
        user.join("hooks"),
        user.join("config.toml.d/x.toml"),
    ] {
        assert!(!may(&untrusted), "{untrusted:?}");
    }
}

/// Astra r3 N3: a symlink or alias spelling of an untrusted file is untrusted; a symlinked `~/.fuigo` (and a link to a
/// trusted file) is still trusted. Paths are resolved with realpath before they are compared.
#[cfg(unix)]
#[test]
fn aliases_are_resolved_before_trust_is_decided() {
    use std::os::unix::fs::symlink;
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("dotfiles").join("fuigo");
    std::fs::create_dir_all(real.join("plugins/p")).unwrap();
    std::fs::create_dir_all(real.join("worktrees/w")).unwrap();
    std::fs::write(real.join("config.toml"), "").unwrap();
    std::fs::write(real.join("plugins/p/.mcp.json"), "{}").unwrap();
    // The user's `~/.fuigo` is itself a symlink.
    let user = tmp.path().join(".fuigo");
    symlink(&real, &user).unwrap();
    let home = tmp.path().to_path_buf();
    let may = |p: &Path| source_may_name_saved_key_at(p, Some(&user), None, Some(&home));
    assert!(may(&user.join("config.toml")), "a symlinked ~/.fuigo keeps working");
    assert!(may(&real.join("config.toml")), "the real spelling is the same file");
    // An alias into the plugins directory is a plugin file, wherever it is spelled.
    symlink(real.join("plugins/p"), user.join("alias")).unwrap();
    assert!(!may(&user.join("alias").join(".mcp.json")));
    assert!(!may(&user.join("plugins/p/.mcp.json")));
    // A link in a project that points at a trusted file IS that file; any other project file is not.
    let proj = tmp.path().join("proj");
    std::fs::create_dir_all(&proj).unwrap();
    symlink(real.join("config.toml"), proj.join("link.toml")).unwrap();
    assert!(may(&proj.join("link.toml")));
    assert!(!may(&proj.join("other.toml")));
    // Worktrees under a symlinked home stay untrusted.
    assert!(!may(&user.join("worktrees/w/.fuigo/config.toml")));
}

/// A hook file may name the saved key only when its real path is under `$FUIGO_HOME/hooks/` (P147, S16/B32; this
/// replaces P118's "anything outside worktrees/ and plugins/"): worktrees, plugins, aliases into them, a user-configured
/// hooks path elsewhere and a symlink out of the hooks directory are all refused.
#[cfg(unix)]
#[test]
fn only_hook_files_under_the_hooks_dir_may_name_the_saved_key() {
    use crate::key_naming::hook_file_may_name_saved_key_in as may;
    let tmp = tempfile::tempdir().unwrap();
    let user = tmp.path().join(".fuigo");
    for d in ["worktrees/w/.fuigo/hooks", "plugins/p/hooks", "hooks/sub", "elsewhere"] {
        std::fs::create_dir_all(user.join(d)).unwrap();
    }
    std::os::unix::fs::symlink(user.join("worktrees/w"), tmp.path().join("alias")).unwrap();
    std::fs::write(tmp.path().join("out.json"), "{}").unwrap();
    std::os::unix::fs::symlink(tmp.path().join("out.json"), user.join("hooks/link.json")).unwrap();
    // A plugin or a worktree aliased in as the hooks directory itself, or reached through `..` after a link, is not.
    std::fs::create_dir_all(tmp.path().join("outside/child")).unwrap();
    std::fs::write(tmp.path().join("outside/x.json"), "{}").unwrap();
    std::os::unix::fs::symlink(tmp.path().join("outside/child"), user.join("hooks/jump")).unwrap();
    assert!(!may(&user.join("hooks/jump/../x.json"), Some(&user)), "`..` after a link leaves the hooks dir");
    let aliased = tmp.path().join("aliased/.fuigo");
    std::fs::create_dir_all(&aliased).unwrap();
    std::fs::write(user.join("plugins/p/hooks/h.json"), "{}").unwrap();
    std::os::unix::fs::symlink(user.join("plugins/p/hooks"), aliased.join("hooks")).unwrap();
    std::os::unix::fs::symlink(user.join("plugins"), aliased.join("plugins")).unwrap();
    assert!(!may(&aliased.join("hooks/h.json"), Some(&aliased)), "a hooks dir aliased onto a plugin");
    assert!(may(&user.join("hooks/h.json"), Some(&user)));
    assert!(may(&user.join("hooks/sub/h.json"), Some(&user)));
    assert!(!may(&user.join("hooks"), Some(&user)), "the directory itself is not a hook file");
    assert!(!may(&user.join("hooks/link.json"), Some(&user)), "a symlink out of the hooks dir");
    assert!(!may(&tmp.path().join("elsewhere/hooks/h.json"), Some(&user)), "a hooks-paths target elsewhere");
    assert!(!may(&tmp.path().join(".claude/settings.json"), Some(&user)));
    assert!(!may(&user.join("worktrees/w/.fuigo/hooks/h.json"), Some(&user)));
    assert!(!may(&user.join("plugins/p/hooks/h.json"), Some(&user)));
    assert!(!may(&tmp.path().join("alias/.fuigo/hooks/h.json"), Some(&user)), "an alias into a worktree is a worktree");
    assert!(!may(&user.join("hooks/h.json"), None), "no fuigo home, no trusted hooks dir");
}

/// P133: a value that only becomes a reference over several expansions is refused; a map entry merely named like a
/// selector is a value and stays.
#[test]
fn composed_references_are_refused_over_several_expansions() {
    // A stand-in for the loader's expander, one step per call: `$$` becomes `$`, `@@` becomes the key's name.
    let expand = |s: &str| s.replace("$$", "$").replace("@@", "FUIGO_API_KEY");
    let mut v = serde_json::json!({
        "env": { "A": "$$$${FUIGO_API_KEY}", "ENV_KEY": "FUIGO_API_KEY", "OK": "fine" },
        "bearer_token_env_var": "@@"
    });
    let refused = crate::key_naming::refuse_composed_key_references_in_server_json(&mut v, "/x", &expand);
    assert!(refused.iter().any(|r| r.key == "env.A"), "{refused:?}");
    assert_eq!(v["env"]["A"], "");
    assert_eq!(v["env"]["ENV_KEY"], "FUIGO_API_KEY");
    assert_eq!(v["env"]["OK"], "fine");
    assert!(v.get("bearer_token_env_var").is_none(), "{v}");
}


fn p136_refusal(file: &str) -> RefusedKeyReference {
    RefusedKeyReference { file: file.into(), key: "mcp_servers.s.env.T".into() }
}

/// P136 (Astra r3 #4): a notice scope holds exactly the refusals recorded inside it, tagged when they were recorded; a
/// refusal recorded outside every scope belongs to no session; the innermost scope owns a refusal, and leaving it
/// gives the outer one back.
#[test]
fn a_notice_scope_holds_only_its_own_refusals() {
    use crate::key_naming::{NoticeScope, report_refusals};
    let a = NoticeScope::new();
    let b = NoticeScope::new();
    report_refusals(&[p136_refusal("/p136s/outside/config.toml")]);
    a.run(|| report_refusals(&[p136_refusal("/p136s/a/config.toml"), p136_refusal("/p136s/a/config.toml")]));
    b.run(|| {
        report_refusals(&[p136_refusal("MCP server `s` supplied by the ACP client")]);
        a.run(|| report_refusals(&[p136_refusal("/p136s/a/nested.toml")]));
        report_refusals(&[p136_refusal("/p136s/b/after.toml")]);
    });
    let na = a.notes();
    assert_eq!(na.len(), 2, "each note once, only a's: {na:?}");
    assert!(na[0].starts_with("/p136s/a/config.toml") && na[1].starts_with("/p136s/a/nested.toml"), "{na:?}");
    let nb = b.notes();
    assert_eq!(nb.len(), 2, "{nb:?}");
    assert!(nb[0].starts_with("MCP server `s` supplied by the ACP client"), "a label that is not a path is b's only: {nb:?}");
    assert!(nb[1].starts_with("/p136s/b/after.toml"), "{nb:?}");
    assert!(NoticeScope::new().notes().is_empty(), "a fresh scope holds nothing, not the unscoped refusal");
}

/// A setup that records a refusal, waits (another session's setup runs on the same thread meanwhile), and records one more.
struct P136Setup {
    file: &'static str,
    step: u8,
}

impl std::future::Future for P136Setup {
    type Output = ();
    fn poll(mut self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<()> {
        let file = format!("{}/{}.toml", self.file, self.step);
        crate::key_naming::report_refusals(&[p136_refusal(&file)]);
        if self.step < 2 {
            self.step += 1;
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    }
}

/// P136 (Astra r3 #4): two sessions set up at the same time, interleaved on one thread and on two threads, are each
/// told only their own refusals.
#[test]
fn overlapping_session_setups_are_told_only_their_own_refusals() {
    use crate::key_naming::NoticeScope;
    let (a, b) = (NoticeScope::new(), NoticeScope::new());
    let mut fa = std::pin::pin!(a.scoped(P136Setup { file: "/p136o/a", step: 0 }));
    let mut fb = std::pin::pin!(b.scoped(P136Setup { file: "/p136o/b", step: 0 }));
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    let (mut done_a, mut done_b) = (false, false);
    while !(done_a && done_b) {
        if !done_a {
            done_a = fa.as_mut().poll(&mut cx).is_ready();
        }
        if !done_b {
            done_b = fb.as_mut().poll(&mut cx).is_ready();
        }
    }
    let other = std::thread::spawn(|| {
        let c = NoticeScope::new();
        c.run(|| crate::key_naming::report_refusals(&[p136_refusal("/p136o/c/thread.toml")]));
        c
    });
    let c = other.join().unwrap();
    for (scope, own, label) in [(a, "/p136o/a/", "a"), (b, "/p136o/b/", "b")] {
        let notes = scope.notes();
        assert_eq!(notes.len(), 3, "{label}: {notes:?}");
        assert!(notes.iter().all(|n| n.starts_with(own)), "{label} was told another session's refusal: {notes:?}");
    }
    let nc = c.notes();
    assert_eq!(nc.len(), 1, "{nc:?}");
    assert!(nc[0].starts_with("/p136o/c/thread.toml"));
}

/// Astra P136 r1 #5: another session cannot push this session's undelivered notes out by flooding refusals of its own;
/// a flooded scope keeps a bounded number and sums up the rest. A collected scope is closed.
#[test]
fn a_flood_of_refusals_in_one_scope_does_not_evict_another_scopes_notes() {
    use crate::key_naming::{MAX_NOTES_PER_SCOPE, NoticeScope, report_refusals};
    let a = NoticeScope::new();
    a.run(|| report_refusals(&[p136_refusal("/p136e/a/config.toml")]));
    let b = NoticeScope::new();
    let flood: Vec<RefusedKeyReference> = (0..5000)
        .map(|i| RefusedKeyReference { file: "/p136e/b/flood.toml".into(), key: format!("mcp_servers.s.args[{i}]") })
        .collect();
    b.run(|| report_refusals(&flood));
    let na = a.notes();
    assert_eq!(na.len(), 1, "{na:?}");
    assert!(na[0].starts_with("/p136e/a/config.toml"));
    let nb = b.notes();
    assert_eq!(nb.len(), MAX_NOTES_PER_SCOPE + 1, "bounded, plus one summary");
    assert!(nb.last().unwrap().starts_with(&format!("{} more references", 5000 - MAX_NOTES_PER_SCOPE)), "{:?}", nb.last());
    // Collected: closed, later refusals in it are only logged.
    a.run(|| report_refusals(&[p136_refusal("/p136e/a/late.toml")]));
    assert!(a.notes().is_empty());
}

/// P138 d-2 (Astra r1 #4): a scope whose setup is dropped before it announces (a cancelled request) is closed by its guard,
/// so it cannot stay open and count against the cap; a refusal recorded after that is only logged.
#[test]
fn a_dropped_setup_closes_its_scope() {
    use crate::key_naming::{NoticeScope, report_refusals};
    let scope = NoticeScope::new();
    scope.run(|| report_refusals(&[p136_refusal("/p138s/dropped.toml")]));
    drop(scope.close_on_drop());
    scope.run(|| report_refusals(&[p136_refusal("/p138s/after.toml")]));
    assert!(scope.notes().is_empty(), "the scope stayed open after its guard was dropped");
    // And collecting first is fine.
    let other = NoticeScope::new();
    let closer = other.close_on_drop();
    other.run(|| report_refusals(&[p136_refusal("/p138s/other.toml")]));
    assert_eq!(other.notes().len(), 1);
    drop(closer);
}

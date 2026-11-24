//! MC-03 gate tests: real config loading (a test FUIGO_HOME) through the gate.

use super::*;
use crate::util::config::{
    CampaignApproval, campaign_approval_shown, disabled_mcp_server_names, load_mcp_servers,
    save_mcp_server_enabled_in,
};
use fuigo_tools::types::compat::CompatConfig;

fn write(path: &std::path::Path, s: &str) {
    std::fs::write(path, s).unwrap();
}

fn load(cwd: &std::path::Path) -> Vec<acp::McpServer> {
    load_mcp_servers(cwd, &CompatConfig::default())
}

fn http_oauth(client: &str, port: u16) -> String {
    format!(
        "[mcp_servers.h]\nurl = \"https://h.invalid/mcp\"\n[mcp_servers.h.oauth]\nclientId = \"{client}\"\ncallbackPort = {port}\n"
    )
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

#[test]
fn first_sight_is_silent_a_change_is_held_once_and_approval_admits_it() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    let config = home.path().join("config.toml");
    write(&config, &http_oauth("one", 4100));

    let first = admit_mcp_launch(load(cwd.path()));
    assert_eq!(first.admitted.len(), 1);
    assert!(
        first.held.is_empty() && first.notices.is_empty(),
        "{:?}",
        first.notices
    );

    // Port-only change: held once (plan test changed per Fable r2), approved, then it starts.
    write(&config, &http_oauth("one", 4101));
    let changed = load(cwd.path());
    let held = admit_mcp_launch(changed.clone());
    assert!(held.admitted.is_empty());
    assert_eq!(held.held.len(), 1);
    assert_eq!(held.notices.len(), 1);
    assert!(
        held.notices[0].contains("changed since you approved it")
            || held.notices[0].contains("`h`"),
        "{}",
        held.notices[0]
    );
    assert_eq!(
        held_mcp_server("", &held.held[0].key).unwrap().digest,
        held.held[0].digest
    );
    assert!(approve_stamped(&changed[0]).unwrap());
    let again = admit_mcp_launch(load(cwd.path()));
    assert_eq!(again.admitted.len(), 1, "{:?}", again.notices);
    assert!(held_mcp_servers().iter().all(|h| h.name != "h"));

    // Going back to an approved definition needs nothing.
    write(&config, &http_oauth("one", 4100));
    assert_eq!(admit_mcp_launch(load(cwd.path())).admitted.len(), 1);
}

#[test]
fn oauth_changed_after_admission_is_held_and_the_admitted_object_keeps_its_own_oauth() {
    // Mandatory fix 1.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    let config = home.path().join("config.toml");
    write(&config, &http_oauth("admitted", 4100));
    let mut admitted = admit_mcp_launch(load(cwd.path())).admitted;
    let installed = admitted.pop().unwrap();
    assert_eq!(
        installed.oauth(None).unwrap().client_id.as_deref(),
        Some("admitted")
    );

    write(&config, &http_oauth("attacker", 4100));
    // A fresh read is held, never launched under the old admission.
    let fresh = admit_mcp_launch(load(cwd.path()));
    assert!(fresh.admitted.is_empty());
    assert_eq!(fresh.held.len(), 1);
    // The installed object re-gated for a restart/OAuth rebuild connects with what was admitted, not disk; a
    // fallback map read from disk is ignored for a covered server.
    let disk =
        crate::util::config::load_mcp_servers_with_oauth(cwd.path(), &CompatConfig::default()).1;
    let regated = admit_installed(std::slice::from_ref(installed.server()))
        .pop()
        .expect("the installed object is still approved");
    assert!(regated.is_covered());
    assert_eq!(
        regated.oauth(disk.get("h")).unwrap().client_id.as_deref(),
        Some("admitted")
    );
}

#[test]
fn unstamped_servers_are_admitted_with_the_callers_oauth() {
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("approvals.json");
    write(&store, "{broken");
    let mut client = acp::McpServer::Stdio(acp::McpServerStdio::new(
        "c",
        std::path::PathBuf::from("/bin/c"),
    ));
    // Coordinator (stamp fail-closed scope): an object with neither a stamp nor an uncovered mark is held.
    let bare = admit_with_store(vec![client.clone()], &store);
    assert!(bare.admitted.is_empty());
    assert!(
        bare.notices[0].contains("missing or could not be read"),
        "{:?}",
        bare.notices
    );
    ap::mark_uncovered(&mut client, "client");
    let a = admit_with_store(vec![client], &store);
    assert_eq!(a.admitted.len(), 1, "client/plugin servers are not covered");
    assert!(!a.admitted[0].is_covered());
    assert!(a.notices.is_empty());
}

#[test]
fn an_unreadable_store_holds_every_covered_server_with_one_notice_and_reset_recovers() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    write(
        &home.path().join("config.toml"),
        "[mcp_servers.a]\ncommand = \"/bin/a\"\n[mcp_servers.b]\ncommand = \"/bin/b\"\n",
    );
    let store = crate::util::config::mcp_approvals::store_path();
    write(&store, "{\"version\":1,");
    let a = admit_mcp_launch(load(cwd.path()));
    assert!(a.admitted.is_empty());
    assert_eq!(a.held.len(), 2);
    assert!(a.held.iter().all(|h| h.store_unavailable));
    assert_eq!(a.notices.len(), 1, "{:?}", a.notices);
    assert!(a.notices[0].contains("fuigo mcp approvals reset"));
    // Approving cannot overwrite it.
    assert!(approve_stamped(&load(cwd.path())[0]).is_err());

    crate::util::config::reset_mcp_approvals().unwrap().unwrap();
    let b = admit_mcp_launch(load(cwd.path()));
    assert_eq!(b.admitted.len(), 2);
    assert!(b.notices.is_empty());
}

#[test]
fn removing_a_server_keeps_its_record_so_re_adding_a_different_command_is_held() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    let config = home.path().join("config.toml");
    write(&config, "[mcp_servers.x]\ncommand = \"/bin/old\"\n");
    assert_eq!(admit_mcp_launch(load(cwd.path())).admitted.len(), 1);
    write(&config, "");
    assert!(admit_mcp_launch(load(cwd.path())).admitted.is_empty());
    write(&config, "[mcp_servers.x]\ncommand = \"/bin/new\"\n");
    assert_eq!(admit_mcp_launch(load(cwd.path())).held.len(), 1);
}

#[test]
fn user_servers_are_keyed_by_scope_not_file() {
    // Fable r2 M1 (the file-to-file move itself is covered by `keys_follow_the_scope_directory_not_the_file`).
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    write(
        &home.path().join("config.toml"),
        "[mcp_servers.m]\ncommand = \"/bin/m\"\n",
    );
    let first = admit_mcp_launch(load(cwd.path()));
    assert_eq!(read_stamp_key(&first.admitted[0]), "user\0m");
}

fn read_stamp_key(a: &AdmittedMcpLaunch) -> String {
    ap::read_stamp(a.server()).unwrap().key
}

#[test]
fn a_delayed_enable_save_keeps_the_approval_of_the_command_the_user_was_shown() {
    // Mandatory fix 3 (Grok r2 A3): the run loop's delayed save passes Keep, so an edit made between the notice and the
    // save is not approved; a campaign server dropped before the gate is recorded, so a changed command is held later.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    let config = home.path().join("config.toml");
    let campaign = |arg: &str| {
        format!(
            "[[campaigns]]\nid = \"race\"\n[campaigns.mcp_servers.fresh]\ncommand = \"race-srv\"\nargs = [\"{arg}\"]\n"
        )
    };
    write(&config, &campaign("--a"));
    // First launch: held by C7-02 (unapproved, dropped before the gate) and recorded as first seen.
    assert!(disabled_mcp_server_names(cwd.path()).contains("fresh"));
    let launched = crate::session::managed_mcp::merge_managed_mcp_servers(
        Vec::new(),
        cwd.path(),
        None,
        &CompatConfig::default(),
    );
    assert!(launched.iter().all(|s| mcp_server_name(s) != "fresh"));
    let store = crate::util::config::mcp_approvals::load_store();
    assert_eq!(
        store.digests("campaign\0fresh").map(<[String]>::len),
        Some(1),
        "a campaign server dropped before the gate is recorded"
    );

    // The user is shown --a and turns it on; the campaign changes it to --b before the delayed save.
    let (shown, _) = campaign_approval_shown("fresh", cwd.path());
    assert!(matches!(shown, CampaignApproval::Set(..)));
    block_on(save_mcp_server_enabled_in("fresh", true, cwd.path(), shown)).unwrap();
    let approved = std::fs::read_to_string(&config).unwrap();
    write(&config, &approved.replace("\"--a\"", "\"--b\""));
    block_on(save_mcp_server_enabled_in(
        "fresh",
        true,
        cwd.path(),
        CampaignApproval::Keep,
    ))
    .unwrap();
    assert!(
        disabled_mcp_server_names(cwd.path()).contains("fresh"),
        "the delayed save must not approve the edited command"
    );

    // Review Fable M3: --a was recorded first, but the user now turns on exactly --b (shown) in /mcp: that approves --b
    // for the gate too, so it starts.
    let (shown_b, _) = campaign_approval_shown("fresh", cwd.path());
    block_on(save_mcp_server_enabled_in(
        "fresh",
        true,
        cwd.path(),
        shown_b,
    ))
    .unwrap();
    let gated = admit_mcp_launch(load(cwd.path()));
    assert_eq!(gated.admitted.len(), 1, "{:?}", gated.notices);
    assert!(gated.held.is_empty());
    // A later campaign change to --c is not covered by that approval.
    let text = std::fs::read_to_string(&config).unwrap();
    write(&config, &text.replace("\"--b\"", "\"--c\""));
    let (shown_c, _) = campaign_approval_shown("fresh", cwd.path());
    assert!(matches!(shown_c, CampaignApproval::Set(..)));
    let config_c = std::fs::read_to_string(&config).unwrap();
    // Only the C7-02 fingerprint of --b is recorded, so --c is dropped before the gate; nothing starts it silently.
    assert!(config_c.contains("--c"));
    assert!(disabled_mcp_server_names(cwd.path()).contains("fresh"));
}

#[test]
fn a_user_override_of_a_managed_server_is_covered_and_a_managed_only_server_is_not() {
    // Fable r2 M3: provenance from the one layered read; a name the user layer touches is the user's definition.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    write(
        &home.path().join(fuigo_config::MANAGED_CONFIG_FILENAME),
        "[mcp_servers.mm]\ncommand = \"/bin/managed\"\n[mcp_servers.only]\ncommand = \"/bin/only\"\n",
    );
    let user = home.path().join("config.toml");
    write(&user, "[mcp_servers.mm]\nargs = [\"one\"]\n");
    let first = admit_mcp_launch(load(cwd.path()));
    let stamped: Vec<_> = first
        .admitted
        .iter()
        .filter(|a| a.is_covered())
        .map(|a| a.name().to_owned())
        .collect();
    assert_eq!(stamped, ["mm"], "managed-only servers are uncovered");
    write(&user, "[mcp_servers.mm]\nargs = [\"two\"]\n");
    let second = admit_mcp_launch(load(cwd.path()));
    assert_eq!(
        second
            .held
            .iter()
            .map(|h| h.name.as_str())
            .collect::<Vec<_>>(),
        ["mm"]
    );
}

#[test]
fn always_allow_grant_fingerprints_ignore_the_admission_stamp() {
    // 1.0.45/1.0.46 "Always allow" grants keep matching after upgrade, with no new warning.
    let dir = tempfile::tempdir().unwrap();
    let store = dir.path().join("approvals.json");
    for plain in [
        acp::McpServer::Stdio(
            acp::McpServerStdio::new("g", std::path::PathBuf::from("/bin/g"))
                .args(vec!["--port=1".into()]),
        ),
        acp::McpServer::Http(acp::McpServerHttp::new("g", "https://g.invalid/mcp")),
    ] {
        let mut stamped = plain.clone();
        let digest = ap::mcpdef_v1_acp(&plain).unwrap();
        ap::set_stamp(
            &mut stamped,
            &ap::AdmissionStamp {
                key: format!("user\0g-{}", digest),
                digest,
                origin: "cfg".into(),
                oauth: None,
            },
        );
        use crate::session::managed_mcp::{
            mcp_definition_fingerprint, mcp_definition_fingerprint_1045,
        };
        assert_eq!(
            mcp_definition_fingerprint(&plain),
            mcp_definition_fingerprint(&stamped)
        );
        assert_eq!(
            mcp_definition_fingerprint_1045(&plain),
            mcp_definition_fingerprint_1045(&stamped)
        );
        // And the admitted object is the stamped one, unchanged for the grant check.
        let admitted = admit_with_store(vec![stamped.clone()], &store).admitted;
        assert_eq!(
            mcp_definition_fingerprint(admitted[0].server()),
            mcp_definition_fingerprint(&plain)
        );
    }
}

fn trusted_repo() -> tempfile::TempDir {
    let cwd = tempfile::tempdir().unwrap();
    git2::Repository::init(cwd.path()).unwrap();
    crate::agent::folder_trust::record_for_test(cwd.path(), true);
    cwd
}

fn stdio_toml(name: &str, arg: &str) -> String {
    format!("[mcp_servers.{name}]\ncommand = \"srv-{name}\"\nargs = [\"{arg}\"]\n")
}

fn stdio_json(name: &str, arg: &str) -> String {
    format!(r#"{{"command":"srv-{name}","args":["{arg}"]}}"#)
}

fn bump(path: &std::path::Path) {
    let text = std::fs::read_to_string(path).unwrap();
    assert!(text.contains("\"v1\""), "{}: {text}", path.display());
    write(path, &text.replace("\"v1\"", "\"v2\""));
}

fn sorted_names<'a>(names: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut v: Vec<String> = names.map(str::to_owned).collect();
    v.sort();
    v
}

#[test]
fn every_covered_source_is_stamped_unchanged_is_silent_and_a_change_is_held() {
    // Design test 6 (review Fable M4/M5): one changed-and-held case per covered source, each with an identical-bytes
    // control, and every loaded object carries a stamp.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _key = fuigo_test_support::EnvGuard::unset("FUIGO_API_KEY");
    let _flag = fuigo_test_support::EnvGuard::unset("FUIGO_FOLDER_TRUST");
    let fuigo = fuigo_test_support::FuigoHome::new();
    let home = tempfile::tempdir().unwrap();
    let _home = fuigo_test_support::EnvGuard::set("HOME", home.path());
    let cwd = trusted_repo();
    let c = cwd.path();
    std::fs::create_dir_all(c.join(".fuigo")).unwrap();
    std::fs::create_dir_all(c.join(".cursor")).unwrap();
    std::fs::create_dir_all(home.path().join(".cursor")).unwrap();
    let json_file = |name: &str| {
        format!(
            r#"{{"mcpServers":{{"{name}":{}}}}}"#,
            stdio_json(name, "v1")
        )
    };
    let files = [
        (fuigo.path().join("config.toml"), stdio_toml("s_user", "v1")),
        (c.join(".fuigo/config.toml"), stdio_toml("s_project", "v1")),
        (c.join(".mcp.json"), json_file("s_mcpjson")),
        (c.join(".cursor/mcp.json"), json_file("s_cursor_project")),
        (
            home.path().join(".cursor/mcp.json"),
            json_file("s_cursor_user"),
        ),
        (
            home.path().join(".claude.json"),
            format!(
                r#"{{"mcpServers":{{"s_claude_user":{}}},"projects":{{{}:{{"mcpServers":{{"s_claude_project":{}}}}}}}}}"#,
                stdio_json("s_claude_user", "v1"),
                serde_json::to_string(&c.display().to_string()).unwrap(),
                stdio_json("s_claude_project", "v1")
            ),
        ),
    ];
    for (path, text) in &files {
        write(path, text);
    }
    let expected = sorted_names(
        [
            "s_user",
            "s_project",
            "s_mcpjson",
            "s_cursor_project",
            "s_cursor_user",
            "s_claude_user",
            "s_claude_project",
        ]
        .into_iter(),
    );
    let loaded = load(c);
    assert_eq!(
        sorted_names(loaded.iter().map(mcp_server_name)),
        expected,
        "every source loads"
    );
    for s in &loaded {
        assert!(
            ap::read_stamp(s).is_some(),
            "{} is stamped",
            mcp_server_name(s)
        );
    }
    let first = admit_mcp_launch(loaded);
    assert_eq!(first.admitted.len(), 7, "{:?}", first.notices);
    // Identical bytes: silent.
    let again = admit_mcp_launch(load(c));
    assert!(
        again.held.is_empty() && again.notices.is_empty(),
        "{:?}",
        again.notices
    );
    for (path, _) in &files {
        bump(path);
    }
    let changed = admit_mcp_launch(load(c));
    assert!(changed.admitted.is_empty(), "{:?}", changed.notices);
    assert_eq!(
        sorted_names(changed.held.iter().map(|h| h.name.as_str())),
        expected
    );
    assert_eq!(changed.notices.len(), 7);
}

#[test]
fn agent_and_subagent_inline_servers_replacing_a_covered_one_are_held_until_approved() {
    // Design test 9 (review Fable M1): the main-session overlay and the subagent path both re-key an inline server that
    // replaces a covered one onto that server's key; a new inline name is first seen, and held after a change.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    write(
        &home.path().join("config.toml"),
        &stdio_toml("notes", "disk"),
    );
    let parent = admit_mcp_launch(load(cwd.path())).servers();
    assert_eq!(parent.len(), 1);
    let definition = |arg: &str| {
        let mut d = fuigo_agent::config::AgentDefinition::parse(&format!(
            "---\nname: seat\ndescription: d\nmcpServers:\n  - notes: {{command: srv-notes, args: [\"{arg}\"]}}\n  - extra: {{command: srv-extra, args: [\"{arg}\"]}}\n---\nbody\n"
        ))
        .unwrap();
        d.scope = fuigo_agent::config::AgentScope::User;
        d.source_path = Some(home.path().join("agents/seat.md"));
        d
    };
    let held_names = |a: &Admission| sorted_names(a.held.iter().map(|h| h.name.as_str()));

    // Main session overlay.
    let mut merged = load(cwd.path());
    crate::session::agent_mcp::apply_agent_mcp_overlay(&mut merged, &definition("a"), cwd.path());
    let main = admit_mcp_launch(merged);
    assert_eq!(
        held_names(&main),
        vec!["notes".to_owned()],
        "{:?}",
        main.notices
    );
    assert_eq!(main.admitted.len(), 1, "a new inline name is first seen");

    // Subagent path: the call handle_request makes.
    let sub = crate::session::agent_mcp::materialize_subagent_mcp_servers(
        &definition("a"),
        &parent,
        "",
        cwd.path(),
        fuigo_config::key_naming::NoticeScope::new(),
    );
    let child = admit_mcp_launch(sub.clone());
    assert_eq!(
        held_names(&child),
        vec!["notes".to_owned()],
        "{:?}",
        child.notices
    );

    // Approved: both paths start it, and the disk definition still starts (the key keeps both digests).
    let notes = sub.iter().find(|s| mcp_server_name(s) == "notes").unwrap();
    assert!(approve_stamped(notes).unwrap());
    assert!(admit_mcp_launch(sub).held.is_empty());
    assert!(admit_mcp_launch(load(cwd.path())).held.is_empty());

    // A later change to the new inline name is held.
    let mut changed = load(cwd.path());
    crate::session::agent_mcp::apply_agent_mcp_overlay(&mut changed, &definition("b"), cwd.path());
    let names = held_names(&admit_mcp_launch(changed));
    assert!(names.contains(&"extra".to_owned()), "{names:?}");
}

#[test]
fn fuigos_own_saves_are_not_held() {
    // Design test 15 (review Fable M6): what Fuigo saves records the digest the next read computes.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    let path = home.path().join("config.toml");
    let configs = [
        (
            "own_stdio",
            "command = \"srv\"\nargs = [\"--a\", \"b\"]\nenv = { B = \"2\", A = \"1\" }\n",
        ),
        (
            "own_http",
            "url = \"https://own.invalid/mcp\"\nheaders = { X-Two = \"2\", X-One = \"1\" }\n[oauth]\nclientId = \"cid\"\ncallbackPort = 4300\n",
        ),
        ("own_stdio", "command = \"srv\"\nargs = [\"--c\"]\n"),
    ];
    for (name, text) in configs {
        let config: crate::util::config::McpServerConfig = toml::from_str(text).unwrap();
        block_on(crate::util::config::save_mcp_server_config_at(
            &path, name, &config,
        ))
        .unwrap();
    }
    let gated = admit_mcp_launch(load(cwd.path()));
    assert_eq!(gated.admitted.len(), 2, "{:?}", gated.notices);
    assert!(
        gated.held.is_empty() && gated.notices.is_empty(),
        "{:?}",
        gated.notices
    );
}

#[test]
fn the_held_registry_is_keyed_by_scope_so_one_projects_toggle_cannot_approve_anothers() {
    // Review Fable M2: two projects hold a same-named `db`; each entry is found only by its own key.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _flag = fuigo_test_support::EnvGuard::unset("FUIGO_FOLDER_TRUST");
    let _home = fuigo_test_support::FuigoHome::new();
    let (a, b) = (trusted_repo(), trusted_repo());
    let db = |dir: &tempfile::TempDir, arg: &str| {
        write(
            &dir.path().join(".mcp.json"),
            &format!(r#"{{"mcpServers":{{"db":{}}}}}"#, stdio_json("db", arg)),
        );
    };
    db(&a, "a1");
    db(&b, "b1");
    assert_eq!(admit_mcp_launch(load(a.path())).admitted.len(), 1);
    assert_eq!(admit_mcp_launch(load(b.path())).admitted.len(), 1);
    db(&a, "a2");
    db(&b, "b2");
    let held_a = admit_mcp_launch(load(a.path())).held.remove(0);
    let held_b = admit_mcp_launch(load(b.path())).held.remove(0);
    assert_ne!(held_a.key, held_b.key);
    assert_eq!(
        held_mcp_server("", &held_b.key).unwrap().digest,
        held_b.digest
    );
    assert_eq!(
        held_mcp_server("", &held_a.key).unwrap().digest,
        held_a.digest
    );
    // Approving and starting A's leaves B's held entry alone.
    ap::approve_mcp_definition(&held_a.key, &held_a.digest).unwrap();
    assert_eq!(admit_mcp_launch(load(a.path())).admitted.len(), 1);
    assert!(held_mcp_server("", &held_a.key).is_none());
    assert_eq!(
        held_mcp_server("", &held_b.key).unwrap().digest,
        held_b.digest
    );
    assert!(admit_mcp_launch(load(b.path())).admitted.is_empty());
}

#[test]
fn a_stamp_that_does_not_parse_is_held_not_treated_as_uncovered() {
    // Review Fable M4: fail closed.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _home = fuigo_test_support::FuigoHome::new();
    let mut meta = serde_json::Map::new();
    meta.insert(
        ap::ADMISSION_META_KEY.to_owned(),
        serde_json::json!("not a stamp"),
    );
    let bad = acp::McpServer::Stdio(acp::McpServerStdio::new("bad", "srv").meta(meta));
    let mut plain = acp::McpServer::Stdio(acp::McpServerStdio::new("plain", "srv"));
    ap::mark_uncovered(&mut plain, "plugin");
    let gated = admit_mcp_launch(vec![bad, plain]);
    assert_eq!(gated.admitted.len(), 1);
    assert_eq!(
        gated.admitted[0].name(),
        "plain",
        "a server marked uncovered still starts"
    );
    assert_eq!(gated.notices.len(), 1);
    assert!(
        gated.notices[0].contains("`bad` was not started"),
        "{}",
        gated.notices[0]
    );
}

#[test]
fn enable_agent_approves_exactly_the_held_inline_server_of_that_agent() {
    // `fuigo mcp enable <name> --agent <agent>`: the CLI lookup gates like a session running that agent.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    use crate::util::config::{approve_held_mcp_definition, held_agent_mcp_definition};
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    let agents = home.path().join("agents");
    std::fs::create_dir_all(&agents).unwrap();
    let seat = |arg: &str| {
        write(
            &agents.join("seat.md"),
            &format!(
                "---\nname: seat\ndescription: d\nmcpServers:\n  - adder: {{command: srv-adder, args: [\"{arg}\"]}}\n---\nbody\n"
            ),
        );
    };
    let launch = || {
        let def = fuigo_agent::discovery::by_name_in_cwd("seat", cwd.path()).expect("agent found");
        let mut merged = load(cwd.path());
        crate::session::agent_mcp::apply_agent_mcp_overlay(&mut merged, &def, cwd.path());
        admit_mcp_launch(merged)
    };
    seat("v1");
    assert_eq!(launch().admitted.len(), 1, "first seen");
    assert!(
        held_agent_mcp_definition(cwd.path(), "seat", "adder")
            .unwrap()
            .is_none()
    );
    seat("v2");
    let held = held_agent_mcp_definition(cwd.path(), "seat", "adder")
        .unwrap()
        .expect("held");
    assert!(held.display.contains("srv-adder v2"), "{}", held.display);
    assert_eq!(launch().held.len(), 1);
    approve_held_mcp_definition(&held).unwrap();
    assert!(launch().held.is_empty());
    assert!(
        held_agent_mcp_definition(cwd.path(), "seat", "adder")
            .unwrap()
            .is_none()
    );
    assert!(held_agent_mcp_definition(cwd.path(), "nobody", "adder").is_err());
    assert!(held_agent_mcp_definition(cwd.path(), "seat", "other").is_err());
}

#[test]
fn reformatting_and_env_reference_rotation_start_and_an_unchanged_start_writes_nothing() {
    // Design tests 2, 4 (reference rotation, for a JSON source: its strings are expanded after the digest) and 20.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _key = fuigo_test_support::EnvGuard::unset("FUIGO_API_KEY");
    let _flag = fuigo_test_support::EnvGuard::unset("FUIGO_FOLDER_TRUST");
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = trusted_repo();
    let config = home.path().join("config.toml");
    let _t = fuigo_test_support::EnvGuard::set("MC03_ROTATING", "one");
    write(
        &config,
        "[mcp_servers.r]\ncommand = \"srv-r\"\nargs = [\"--a\"]\nenv = { M = \"z\", L = \"x\" }\n",
    );
    let mcp = cwd.path().join(".mcp.json");
    write(
        &mcp,
        r#"{"mcpServers":{"j":{"command":"srv-j","env":{"T":"${MC03_ROTATING}"}}}}"#,
    );
    assert_eq!(admit_mcp_launch(load(cwd.path())).admitted.len(), 2);
    let store = ap::store_path();
    let bytes = std::fs::read(&store).unwrap();
    let mtime = std::fs::metadata(&store).unwrap().modified().unwrap();

    // Reformatted, re-commented and reordered: same definition.
    write(
        &config,
        "# my servers\n[mcp_servers.r]\nenv = { L = \"x\", M = \"z\" } # vars\nargs = [ \"--a\" ]\ncommand = \"srv-r\"\n",
    );
    let again = admit_mcp_launch(load(cwd.path()));
    assert!(
        again.held.is_empty() && again.notices.is_empty(),
        "{:?}",
        again.notices
    );
    // The referenced value rotates: the definition (before expansion) is unchanged.
    let _t2 = fuigo_test_support::EnvGuard::set("MC03_ROTATING", "two");
    let rotated = admit_mcp_launch(load(cwd.path()));
    assert!(rotated.held.is_empty(), "{:?}", rotated.notices);
    assert_eq!(
        std::fs::read(&store).unwrap(),
        bytes,
        "an unchanged start writes nothing"
    );
    assert_eq!(
        std::fs::metadata(&store).unwrap().modified().unwrap(),
        mtime
    );

    // A literal env value change is held.
    let text = std::fs::read_to_string(&config).unwrap();
    write(&config, &text.replace("L = \"x\"", "L = \"y\""));
    assert_eq!(admit_mcp_launch(load(cwd.path())).held.len(), 1);
}

#[test]
fn monorepo_siblings_with_the_same_server_name_never_hold_each_other() {
    // Design test 7.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _flag = fuigo_test_support::EnvGuard::unset("FUIGO_FOLDER_TRUST");
    let _home = fuigo_test_support::FuigoHome::new();
    let repo = trusted_repo();
    let (pa, pb) = (repo.path().join("pkg/a"), repo.path().join("pkg/b"));
    for (dir, arg) in [(&pa, "a"), (&pb, "b")] {
        std::fs::create_dir_all(dir).unwrap();
        crate::agent::folder_trust::record_for_test(dir, true);
        write(
            &dir.join(".mcp.json"),
            &format!(r#"{{"mcpServers":{{"db":{}}}}}"#, stdio_json("db", arg)),
        );
    }
    for _ in 0..2 {
        for dir in [&pa, &pb] {
            let gated = admit_mcp_launch(load(dir));
            assert_eq!(
                gated.admitted.len(),
                1,
                "{}: {:?}",
                dir.display(),
                gated.notices
            );
            assert!(gated.notices.is_empty());
        }
    }
}

#[test]
fn an_untrusted_folders_changed_server_is_never_recorded_and_after_trust_a_change_is_held() {
    // Design test 17.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _flag = fuigo_test_support::EnvGuard::unset("FUIGO_FOLDER_TRUST");
    let _home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    git2::Repository::init(cwd.path()).unwrap();
    crate::agent::folder_trust::record_for_test(cwd.path(), false);
    let mcp = cwd.path().join(".mcp.json");
    write(
        &mcp,
        &format!(r#"{{"mcpServers":{{"u":{}}}}}"#, stdio_json("u", "v1")),
    );
    // The launch merge (folder trust applies there).
    let merged = |cwd: &std::path::Path| {
        crate::session::managed_mcp::merge_managed_mcp_servers(
            Vec::new(),
            cwd,
            None,
            &CompatConfig::default(),
        )
    };
    let gated = admit_mcp_launch(merged(cwd.path()));
    assert!(
        gated.admitted.iter().all(|a| a.name() != "u"),
        "untrusted: dropped"
    );
    assert!(
        !ap::store_path().exists(),
        "nothing recorded from an untrusted folder"
    );
    crate::agent::folder_trust::record_for_test(cwd.path(), true);
    let trusted = admit_mcp_launch(merged(cwd.path()));
    assert_eq!(
        trusted.admitted.len(),
        1,
        "first launch after trust is silent"
    );
    assert!(trusted.notices.is_empty());
    bump(&mcp);
    assert_eq!(admit_mcp_launch(merged(cwd.path())).held.len(), 1);
}

#[test]
fn installed_servers_launch_from_their_admitted_snapshot_without_store_io() {
    // Review Astra M4: init/restart/retry/OAuth rebuild re-use the snapshot admitted at install. They read and write no
    // store (they run on the reactor, some under the state lock), so even an unreadable store does not stop a server
    // the gate already admitted, and the file is left untouched.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    write(
        &home.path().join("config.toml"),
        &http_oauth("admitted", 4100),
    );
    let installed = admit_mcp_launch(load(cwd.path())).servers();
    assert_eq!(installed.len(), 1);

    let store = crate::util::config::mcp_approvals::store_path();
    write(&store, "{unreadable");
    let relaunch = admit_installed(&installed);
    assert_eq!(relaunch.len(), 1, "the admitted snapshot launches");
    assert!(relaunch[0].is_covered());
    assert_eq!(
        relaunch[0].oauth(None).unwrap().client_id.as_deref(),
        Some("admitted")
    );
    assert_eq!(std::fs::read_to_string(&store).unwrap(), "{unreadable");

    // Still fail closed for an object the gate never stamped or marked.
    let mut bare = installed[0].clone();
    crate::util::config::mcp_approvals::strip_stamp(&mut bare);
    assert!(admit_installed(&[bare]).is_empty());
}

/// Review Astra M4 timing: the gate work of an unchanged session start (8 approved servers: the spawn admission plus
/// the init launch of the installed list). Run with `--ignored --nocapture`.
#[test]
#[ignore = "timing probe, run by hand"]
fn unchanged_start_gate_timing() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    let config: String = (0..8)
        .map(|i| format!("[mcp_servers.s{i}]\ncommand = \"srv{i}\"\nargs = [\"--n\", \"{i}\"]\n"))
        .collect();
    write(&home.path().join("config.toml"), &config);
    let servers = load(cwd.path());
    assert_eq!(admit_mcp_launch(servers.clone()).admitted.len(), 8);
    let rounds = 2000;
    let start = std::time::Instant::now();
    for _ in 0..rounds {
        let installed = admit_for_session("T", servers.clone()).servers();
        assert_eq!(admit_installed(&installed).len(), 8);
    }
    let per = start.elapsed() / rounds;
    let line = format!("M4_TIMING unchanged start gate: {per:?} per start ({rounds} rounds)\n");
    print!("{line}");
    // The test runs in its own process, whose stdout the harness keeps; `M4_TIMING_OUT` collects the number.
    if let Ok(out) = std::env::var("M4_TIMING_OUT") {
        use std::io::Write as _;
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(out)
            .unwrap();
        f.write_all(line.as_bytes()).unwrap();
    }
}

#[test]
fn a_child_inline_server_replacing_a_held_or_disabled_parent_server_never_starts_unapproved() {
    // Review Astra/Fable confirm H2: the parent's admitted list lacks a server it holds, so the child keys its
    // same-named inline server to the parent's held identity; a parent server switched off drops the child's.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    let config = home.path().join("config.toml");
    write(&config, &stdio_toml("notes", "a"));
    assert_eq!(admit_for_session("P", load(cwd.path())).admitted.len(), 1);
    // The parent's own `notes` changes: held in session P, so it is not in P's admitted list.
    write(&config, &stdio_toml("notes", "a2"));
    let parent = admit_for_session("P", load(cwd.path()));
    assert_eq!(
        sorted_names(parent.held.iter().map(|h| h.name.as_str())),
        ["notes"]
    );
    let parent = parent.servers();
    assert!(parent.is_empty());

    let mut definition = fuigo_agent::config::AgentDefinition::parse(
        "---\nname: kid\ndescription: d\nmcpServers:\n  - notes: {command: srv-notes, args: [\"b\"]}\n---\nbody\n",
    )
    .unwrap();
    definition.scope = fuigo_agent::config::AgentScope::User;
    definition.source_path = Some(home.path().join("agents/kid.md"));
    let child = |parent_session: &str| {
        crate::session::agent_mcp::materialize_subagent_mcp_servers(
            &definition,
            &parent,
            parent_session,
            cwd.path(),
            fuigo_config::key_naming::NoticeScope::new(),
        )
    };
    let sub = child("P");
    let first = admit_for_session("C", sub.clone());
    assert!(first.admitted.is_empty(), "the child's B does not start");
    assert_eq!(
        sorted_names(first.held.iter().map(|h| h.name.as_str())),
        ["notes"]
    );
    // Approving the parent's A2 does not start B; approving exactly B does.
    let a2 = load(cwd.path());
    assert!(approve_stamped(&a2[0]).unwrap());
    assert!(admit_for_session("C", sub.clone()).admitted.is_empty());
    assert!(approve_stamped(&sub[0]).unwrap());
    assert_eq!(admit_for_session("C", sub).admitted.len(), 1);

    // The parent's `notes` switched off: the child's same-named inline server is dropped before any gate.
    write(
        &config,
        &format!("{}enabled = false\n", stdio_toml("notes", "a2")),
    );
    assert!(child("P").is_empty());
}

#[test]
fn a_toggle_that_leaves_its_server_held_is_an_error_saying_why() {
    // Review Fable confirm 2: the run loop answers a toggle with this; turned on but still held is never ok.
    let held = |store_unavailable| HeldMcpServer {
        name: "notes".to_owned(),
        key: "user\0notes".to_owned(),
        digest: "mcpdef.v1:00".to_owned(),
        origin: "config.toml".to_owned(),
        display: "runs: srv".to_owned(),
        store_unavailable,
    };
    let mut admission = Admission::default();
    assert_eq!(toggle_outcome(&admission, "notes", true), Ok(()));
    admission.held.push(held(false));
    let err = toggle_outcome(&admission, "notes", true).unwrap_err();
    assert!(
        err.contains("`notes` is still not started") && err.contains("not the one approved"),
        "{err}"
    );
    assert_eq!(
        toggle_outcome(&admission, "notes", false),
        Ok(()),
        "turning off is not refused"
    );
    assert_eq!(toggle_outcome(&admission, "other", true), Ok(()));
    admission.held[0] = held(true);
    let err = toggle_outcome(&admission, "notes", true).unwrap_err();
    assert!(err.contains("approvals file could not be read"), "{err}");
}

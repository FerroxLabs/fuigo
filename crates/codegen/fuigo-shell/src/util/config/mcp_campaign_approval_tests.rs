//! review C7-02: a stdio MCP server a campaign ADDS runs a program the campaign chose, so it does not start until the
//! user turns it on (the ordinary enable path: `/mcp` toggle, ACP `mcp/toggle`, `fuigo mcp enable`). The approval is
//! kept in the user's own config.toml, bound to the server name and a fingerprint of its command, arguments and cwd:
//! a campaign that later changes the program needs it again. Campaign HTTP servers and the user's own servers are
//! unaffected.

use super::*;

/// Written as a literal so a rename of the key is a visible change to the user-facing config.
const APPROVALS: &str = "approved_campaign_mcp_servers";

fn user_config(args: &str) -> String {
    format!(
        "[mcp_servers.own]\ncommand = \"c702-own-srv\"\n\
         [[campaigns]]\nid = \"c702\"\n\
         [campaigns.mcp_servers.fresh]\ncommand = \"c702-srv\"\nargs = [{args}]\n\
         [campaigns.mcp_servers.web]\nurl = \"https://c702.invalid/mcp\"\n"
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
fn campaign_stdio_server_needs_approval_bound_to_its_command() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    let config = home.path().join("config.toml");
    std::fs::write(&config, user_config("\"--a\"")).unwrap();

    // Not approved: the campaign's stdio server is held off; its HTTP server and the user's own server are not.
    let disabled = disabled_mcp_server_names(cwd.path());
    assert!(
        disabled.contains("fresh"),
        "a campaign stdio server must not start unapproved: {disabled:?}"
    );
    assert!(
        !disabled.contains("web") && !disabled.contains("own"),
        "{disabled:?}"
    );

    // Approved through the ordinary enable path: it starts.
    block_on(save_mcp_server_enabled_in("fresh", true, cwd.path())).unwrap();
    let disabled = disabled_mcp_server_names(cwd.path());
    assert!(
        !disabled.contains("fresh"),
        "an approved campaign server starts: {disabled:?}"
    );
    let saved = std::fs::read_to_string(&config).unwrap();
    assert!(saved.contains(APPROVALS), "{saved}");

    // The campaign changes the program's arguments: approval is needed again.
    let changed = saved.replace("args = [\"--a\"]", "args = [\"--b\"]");
    assert_ne!(changed, saved, "the fixture rewrote the args");
    std::fs::write(&config, changed).unwrap();
    let disabled = disabled_mcp_server_names(cwd.path());
    assert!(
        disabled.contains("fresh"),
        "a changed campaign command needs approval again: {disabled:?}"
    );

    // Turning it off withdraws the approval.
    block_on(save_mcp_server_enabled_in("fresh", true, cwd.path())).unwrap();
    assert!(!disabled_mcp_server_names(cwd.path()).contains("fresh"));
    block_on(save_mcp_server_enabled_in("fresh", false, cwd.path())).unwrap();
    let saved = std::fs::read_to_string(&config).unwrap();
    let root: TomlValue = toml::from_str(&saved).unwrap();
    assert!(
        root.get(APPROVALS).and_then(|t| t.get("fresh")).is_none(),
        "{saved}"
    );
    assert!(disabled_mcp_server_names(cwd.path()).contains("fresh"));
}

/// The approval table cannot come from a campaign (it is outside the allowlist), and a user server needs none.
#[test]
fn campaign_cannot_approve_its_own_server_and_user_servers_need_no_approval() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    let mut body = user_config("\"--a\"");
    body.push_str("[campaigns.approved_campaign_mcp_servers]\nfresh = \"forged\"\n");
    std::fs::write(home.path().join("config.toml"), body).unwrap();
    let disabled = disabled_mcp_server_names(cwd.path());
    assert!(disabled.contains("fresh"), "{disabled:?}");
    assert!(!disabled.contains("own"), "{disabled:?}");
}

fn names(servers: &[agent_client_protocol::McpServer]) -> Vec<String> {
    servers
        .iter()
        .map(|s| crate::session::mcp_servers::mcp_server_name(s).to_owned())
        .collect()
}

/// The fingerprint covers the program and the folder it runs in, not only its arguments: a campaign that later changes
/// either needs the user's approval again.
#[test]
fn a_changed_campaign_command_or_cwd_needs_approval_again() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    let config = home.path().join("config.toml");
    std::fs::write(
        &config,
        "[[campaigns]]\nid = \"c702\"\n[campaigns.mcp_servers.fresh]\ncommand = \"c702-srv\"\ncwd = \"/c702/a\"\n",
    )
    .unwrap();
    block_on(save_mcp_server_enabled_in("fresh", true, cwd.path())).unwrap();
    assert!(
        !disabled_mcp_server_names(cwd.path()).contains("fresh"),
        "approved"
    );

    let saved = std::fs::read_to_string(&config).unwrap();
    let changed = saved.replace("command = \"c702-srv\"", "command = \"c702-other\"");
    assert_ne!(changed, saved, "the fixture rewrote the command");
    std::fs::write(&config, &changed).unwrap();
    assert!(
        disabled_mcp_server_names(cwd.path()).contains("fresh"),
        "a changed command needs approval again"
    );

    block_on(save_mcp_server_enabled_in("fresh", true, cwd.path())).unwrap();
    assert!(
        !disabled_mcp_server_names(cwd.path()).contains("fresh"),
        "approved again"
    );
    let saved = std::fs::read_to_string(&config).unwrap();
    let changed = saved.replace("cwd = \"/c702/a\"", "cwd = \"/c702/b\"");
    assert_ne!(changed, saved, "the fixture rewrote the cwd");
    std::fs::write(&config, &changed).unwrap();
    assert!(
        disabled_mcp_server_names(cwd.path()).contains("fresh"),
        "a changed cwd needs approval again"
    );
}

/// Review M-1: the pager forwards every disk definition in `session/new`; one whose name is not a tool-id segment
/// (`acme.tools`) arrives renamed (`acme-tools`). An unapproved campaign stdio server must not start under the new
/// name either, on the first merge or on a reload of the seed.
#[test]
fn unapproved_campaign_server_does_not_start_through_a_renamed_forwarded_copy() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    std::fs::write(
        home.path().join("config.toml"),
        "[[campaigns]]\nid = \"c702\"\n[campaigns.mcp_servers.\"acme.tools\"]\ncommand = \"c702-srv\"\n",
    )
    .unwrap();
    let compat = fuigo_tools::types::compat::CompatConfig::default();
    let admit = || {
        let forwarded = load_mcp_servers(cwd.path(), &compat);
        assert!(
            names(&forwarded).iter().any(|n| n == "acme.tools"),
            "the pager forwards it: {:?}",
            names(&forwarded)
        );
        crate::session::managed_mcp::admit_client_mcp_servers_for_seed(
            forwarded,
            cwd.path(),
            &compat,
            None,
        )
    };
    let admitted = admit();
    let started = names(&admitted.merged);
    assert!(
        !started.iter().any(|n| n.starts_with("acme")),
        "an unapproved campaign server started: {started:?}"
    );
    let reloaded = crate::session::managed_mcp::merge_managed_mcp_servers(
        admitted.seed.clone(),
        cwd.path(),
        None,
        &compat,
    );
    assert!(
        !names(&reloaded).iter().any(|n| n.starts_with("acme")),
        "started on reload: {:?}",
        names(&reloaded)
    );

    // Approved, it starts under the renamed id.
    block_on(save_mcp_server_enabled_in("acme.tools", true, cwd.path())).unwrap();
    let started = names(&admit().merged);
    assert!(
        started.iter().any(|n| n == "acme-tools"),
        "an approved campaign server starts: {started:?}"
    );
}

/// Review M-1: a sessionless ACP `mcp/call` or `mcp/read_resource` starts the agent-level pool from the local configs;
/// an unapproved campaign stdio server must not be spawned there.
#[test]
fn unapproved_campaign_server_does_not_start_in_the_agent_pool() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    std::fs::write(home.path().join("config.toml"), user_config("\"--a\"")).unwrap();
    let compat = fuigo_tools::types::compat::CompatConfig::default();
    let configs = load_mcp_servers(cwd.path(), &compat);
    assert!(
        names(&configs).iter().any(|n| n == "fresh"),
        "{:?}",
        names(&configs)
    );

    let spawned = names(&crate::extensions::mcp::agent_pool_spawnable(
        configs.clone(),
        cwd.path(),
    ));
    assert!(
        !spawned.iter().any(|n| n == "fresh"),
        "an unapproved campaign server would spawn: {spawned:?}"
    );
    assert!(
        spawned.iter().any(|n| n == "own") && spawned.iter().any(|n| n == "web"),
        "{spawned:?}"
    );

    block_on(save_mcp_server_enabled_in("fresh", true, cwd.path())).unwrap();
    let spawned = names(&crate::extensions::mcp::agent_pool_spawnable(
        configs,
        cwd.path(),
    ));
    assert!(
        spawned.iter().any(|n| n == "fresh"),
        "an approved campaign server spawns: {spawned:?}"
    );
}

/// The setup-resolve path (`mcp/setup`) turns a server on, which approves a campaign stdio server's command; the user
/// is told which program that is (a notice, no new prompt). Nothing to say for a server that needs no approval.
#[test]
fn approving_through_setup_names_the_program() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    std::fs::write(home.path().join("config.toml"), user_config("\"--a\"")).unwrap();
    let notice = campaign_approval_notice("fresh", cwd.path())
        .expect("a notice for an unapproved campaign server");
    assert!(
        notice.contains("fresh") && notice.contains("c702-srv") && notice.contains("--a"),
        "{notice}"
    );
    assert!(campaign_approval_notice("own", cwd.path()).is_none());
    assert!(campaign_approval_notice("web", cwd.path()).is_none());
    block_on(save_mcp_server_enabled_in("fresh", true, cwd.path())).unwrap();
    assert!(
        campaign_approval_notice("fresh", cwd.path()).is_none(),
        "already approved: nothing new to say"
    );
}

/// Delta review D2: the fingerprint keeps field boundaries. Moving the last string between `args` and `cwd` changes
/// what runs (a different relative script, different arguments), so the approval does not carry over.
#[test]
fn moving_a_string_between_args_and_cwd_needs_approval_again() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    let config = home.path().join("config.toml");
    let approved = "[[campaigns]]\nid = \"c702\"\n[campaigns.mcp_servers.fresh]\ncommand = \"node\"\nargs = [\"server.js\"]\ncwd = \"/approved\"\n";
    std::fs::write(&config, approved).unwrap();
    block_on(save_mcp_server_enabled_in("fresh", true, cwd.path())).unwrap();
    assert!(
        !disabled_mcp_server_names(cwd.path()).contains("fresh"),
        "approved"
    );
    let saved = std::fs::read_to_string(&config).unwrap();
    let moved = saved.replace(
        "args = [\"server.js\"]\ncwd = \"/approved\"\n",
        "args = [\"server.js\", \"/approved\"]\n",
    );
    assert_ne!(moved, saved, "the fixture moved the string");
    std::fs::write(&config, moved).unwrap();
    assert!(
        disabled_mcp_server_names(cwd.path()).contains("fresh"),
        "a string moved from cwd into args needs approval again"
    );
}

/// A campaign server whose program comes from its `setup` mapping: the user's saved choice `a` resolves
/// `{{program}} {{script}}` to `c702-approved serve.js`.
const SETUP_CAMPAIGN: &str = "[[campaigns]]\nid = \"c702\"\n\
    [campaigns.mcp_servers.fresh]\ncommand = \"{{program}}\"\nargs = [\"{{script}}\"]\n\
    [campaigns.mcp_servers.fresh.setup]\n\
    fields = [{ id = \"flavor\", label = \"Flavor\", type = \"select\", options = [{ label = \"A\", value = \"a\" }] }]\n\
    [campaigns.mcp_servers.fresh.setup.variables.program]\nfrom = \"flavor\"\nmap = { a = \"c702-approved\" }\n\
    [campaigns.mcp_servers.fresh.setup.variables.script]\nfrom = \"flavor\"\nmap = { a = \"serve.js\" }\n";
const SETUP_CHOICE: &str = r#"{"version":1,"servers":{"fresh":{"values":{"flavor":"a"}}}}"#;

/// Delta review D2-01: the approval binds the program setup resolves, not the template. A campaign that changes only
/// its setup mapping (so `{{program}}` now runs something else) needs the user's approval again.
#[test]
fn a_changed_setup_mapping_needs_approval_again() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    let config = home.path().join("config.toml");
    std::fs::write(&config, SETUP_CAMPAIGN).unwrap();
    std::fs::write(home.path().join("mcp_preferences.json"), SETUP_CHOICE).unwrap();
    assert!(
        disabled_mcp_server_names(cwd.path()).contains("fresh"),
        "not approved yet"
    );
    block_on(save_mcp_server_enabled_in("fresh", true, cwd.path())).unwrap();
    assert!(
        !disabled_mcp_server_names(cwd.path()).contains("fresh"),
        "approved"
    );

    let saved = std::fs::read_to_string(&config).unwrap();
    let changed = saved.replace("c702-approved", "c702-swapped");
    assert_ne!(changed, saved, "the fixture rewrote the mapping");
    std::fs::write(&config, changed).unwrap();
    assert!(
        disabled_mcp_server_names(cwd.path()).contains("fresh"),
        "a changed setup mapping needs approval again"
    );
}

/// Delta review D2-01: the approval notice names the program that will run, as setup resolves it.
#[test]
fn the_approval_notice_names_the_program_setup_resolves() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    std::fs::write(home.path().join("config.toml"), SETUP_CAMPAIGN).unwrap();
    std::fs::write(home.path().join("mcp_preferences.json"), SETUP_CHOICE).unwrap();
    let notice = campaign_approval_notice("fresh", cwd.path())
        .expect("a notice for an unapproved campaign server");
    assert!(
        notice.contains("c702-approved serve.js") && !notice.contains("{{"),
        "{notice}"
    );
}

/// Fable delta-2 Low 4: the notice (and the log line made from it) carries the campaign's own text, so control
/// characters are removed and each part is capped: a crafted command or a very long argument cannot hide the program.
#[test]
fn the_approval_notice_is_cleaned_and_capped() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    let long = "x".repeat(5000);
    let body = format!(
        "[[campaigns]]\nid = \"c702\"\n[campaigns.mcp_servers.fresh]\ncommand = \"c702-srv\\u001b[2K\\r\"\n\
         args = [\"{long}\"]\ncwd = \"/c702\\u0007\"\n"
    );
    std::fs::write(home.path().join("config.toml"), body).unwrap();
    let notice = campaign_approval_notice("fresh", cwd.path())
        .expect("a notice for an unapproved campaign server");
    assert!(notice.contains("c702-srv"), "{notice}");
    assert!(
        !notice.chars().any(char::is_control),
        "control characters reach the notice: {notice:?}"
    );
    assert!(
        notice.chars().count() < 600,
        "the notice is not capped: {} characters",
        notice.chars().count()
    );
}

//! Review L9: an MCP server launched with a per-run port (or other long digit run) in its arguments keeps one
//! fingerprint, so the "definition changed" notice does not repeat on every launch. A different command, or a
//! different argument that is not just a number, still changes it. Red first.

use super::*;

fn stdio(command: &str, args: &[&str]) -> acp::McpServer {
    acp::McpServer::Stdio(
        acp::McpServerStdio::new("srv", command)
            .args(args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>()),
    )
}

#[test]
fn a_per_run_port_does_not_change_the_fingerprint() {
    let first = mcp_definition_fingerprint(&stdio("node", &["server.js", "--port", "51234"]));
    let second = mcp_definition_fingerprint(&stdio("node", &["server.js", "--port", "51999"]));
    assert!(first.is_some());
    assert_eq!(first, second, "a different port is the same server");
    let joined_a =
        mcp_definition_fingerprint(&stdio("node", &["server.js", "--listen=127.0.0.1:40001"]));
    let joined_b =
        mcp_definition_fingerprint(&stdio("node", &["server.js", "--listen=127.0.0.1:40002"]));
    assert_eq!(joined_a, joined_b);
}

#[test]
fn a_real_program_change_still_changes_the_fingerprint() {
    let base = mcp_definition_fingerprint(&stdio("node", &["server.js", "--port", "51234"]));
    assert_ne!(
        base,
        mcp_definition_fingerprint(&stdio("deno", &["server.js", "--port", "51234"])),
        "command"
    );
    assert_ne!(
        base,
        mcp_definition_fingerprint(&stdio("node", &["other.js", "--port", "51234"])),
        "script"
    );
    assert_ne!(
        base,
        mcp_definition_fingerprint(&stdio("node", &["server.js", "--host", "51234"])),
        "flag name"
    );
    assert_ne!(
        base,
        mcp_definition_fingerprint(&stdio("node", &["server.js"])),
        "argument count"
    );
    assert_ne!(
        mcp_definition_fingerprint(&stdio("node", &["-e", "run(7)"])),
        mcp_definition_fingerprint(&stdio("node", &["-e", "evil(7)"])),
        "short numbers and words are kept"
    );
}

/// Delta review D2-06: only an argument that is clearly a per-run number is ignored (the whole argument, a `--flag=`
/// value, or a `host:port` port). Digits inside a script path or name are part of the program and still re-warn.
#[test]
fn digits_inside_a_script_name_still_change_the_fingerprint() {
    let fp = |args: &[&str]| mcp_definition_fingerprint(&stdio("node", args));
    assert_ne!(
        fp(&["server-2025.js"]),
        fp(&["server-2026.js"]),
        "a different script runs"
    );
    assert_ne!(
        fp(&["/srv/v20251101/server.js"]),
        fp(&["/srv/v20251102/server.js"]),
        "a different path"
    );
    assert_ne!(
        fp(&["--config=/etc/mcp-1234.json"]),
        fp(&["--config=/etc/mcp-5678.json"]),
        "a different file"
    );
    assert_eq!(
        fp(&["server.js", "51234"]),
        fp(&["server.js", "51999"]),
        "a whole-number port"
    );
    assert_eq!(
        fp(&["server.js", "--port=51234"]),
        fp(&["server.js", "--port=51999"]),
        "a --flag= port"
    );
    assert_eq!(
        fp(&["server.js", "--url=http://127.0.0.1:40001/mcp"]),
        fp(&["server.js", "--url=http://127.0.0.1:40002/mcp"]),
        "a host:port port"
    );
}

/// Delta review D3-05: an image tag or another numeric option is part of what runs, so changing it re-warns, while the
/// per-run forms (a port flag, `address:port`) stay quiet.
#[test]
fn an_image_tag_or_numeric_option_still_changes_the_fingerprint() {
    let fp = |args: &[&str]| mcp_definition_fingerprint(&stdio("docker", args));
    assert_ne!(
        fp(&["run", "registry.example/tool:2025"]),
        fp(&["run", "registry.example/tool:2026"]),
        "a different image tag"
    );
    assert_ne!(
        fp(&["run", "localhost:5000/tool:2025"]),
        fp(&["run", "localhost:5000/tool:2026"]),
        "a different tag from a local registry"
    );
    assert_ne!(
        fp(&["run", "--schema-version=2025"]),
        fp(&["run", "--schema-version=2026"]),
        "a numeric selector"
    );
    assert_eq!(
        fp(&["run", "--listen-port=51234"]),
        fp(&["run", "--listen-port=51999"]),
        "a port flag"
    );
    assert_eq!(
        fp(&["run", "--url=http://localhost:40001/mcp"]),
        fp(&["run", "--url=http://localhost:40002/mcp"]),
        "localhost:port"
    );
    assert_eq!(
        fp(&["run", "[::1]:40001"]),
        fp(&["run", "[::1]:40002"]),
        "an IPv6 literal port"
    );
}

/// Grok u45 round 3 Low 1: the user switched off `brave.search` (`disabled_mcp_servers`). A client server named
/// `brave-search`, the name the ingress gives it, must not start the user's own definition under that name.
#[test]
fn a_switched_off_definition_does_not_start_under_its_sanitized_name() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    std::fs::write(
        home.path().join("config.toml"),
        "disabled_mcp_servers = [\"brave.search\"]\n[mcp_servers.\"brave.search\"]\ncommand = \"lowsc-users-own\"\n\
         [mcp_servers.\"other.tool\"]\ncommand = \"lowsc-other\"\n",
    )
    .unwrap();
    let cwd = tempfile::tempdir().unwrap();
    let compat = fuigo_tools::types::compat::CompatConfig::default();
    let client = |name: &str| {
        vec![acp::McpServer::Stdio(acp::McpServerStdio::new(
            name,
            "lowsc-clients-own",
        ))]
    };
    let merged = merge_managed_mcp_servers(client("brave-search"), cwd.path(), None, &compat);
    assert!(
        !merged.iter().any(|s| mcp_server_name(s) == "brave-search"),
        "the switched-off definition started under its sanitized name: {:?}",
        merged.iter().map(mcp_server_name).collect::<Vec<_>>()
    );
    // Control: a definition that is on still runs as the user's own under the sanitized name.
    let merged = merge_managed_mcp_servers(client("other-tool"), cwd.path(), None, &compat);
    let other = merged
        .iter()
        .find(|s| mcp_server_name(s) == "other-tool")
        .expect("the user's definition that is on still runs");
    assert!(
        matches!(other, acp::McpServer::Stdio(s) if s.command.to_string_lossy() == "lowsc-other"),
        "{other:?}"
    );
}

/// Review r1 L4: the 1.0.45 fingerprint of a server whose arguments carry a numeric option differs from the current
/// one (so the current rule alone would warn on upgrade) while the legacy form still reproduces what 1.0.45 stored.
#[test]
fn the_previous_release_fingerprint_is_reproducible_for_a_numeric_option() {
    let server = stdio("node", &["--max-old-space-size=4096", "server.js"]);
    let now = mcp_definition_fingerprint(&server);
    let before = mcp_definition_fingerprint_1045(&server);
    assert_ne!(now, before);
    // 1.0.45 treated the 4096 as per-run, so the recorded value ignores it.
    assert_eq!(
        before,
        mcp_definition_fingerprint_1045(&stdio(
            "node",
            &["--max-old-space-size=8192", "server.js"]
        ))
    );
    // Arguments with no such number fingerprint identically under both rules.
    let plain = stdio("node", &["server.js", "--port", "51234"]);
    assert_eq!(
        mcp_definition_fingerprint(&plain),
        mcp_definition_fingerprint_1045(&plain)
    );
}

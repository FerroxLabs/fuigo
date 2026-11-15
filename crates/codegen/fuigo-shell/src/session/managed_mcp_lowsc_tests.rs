//! Review L9: an MCP server launched with a per-run port (or other long digit run) in its arguments keeps one
//! fingerprint, so the "definition changed" notice does not repeat on every launch. A different command, or a
//! different argument that is not just a number, still changes it. Red first.

use super::*;

fn stdio(command: &str, args: &[&str]) -> acp::McpServer {
    acp::McpServer::Stdio(acp::McpServerStdio::new("srv", command).args(args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>()))
}

#[test]
fn a_per_run_port_does_not_change_the_fingerprint() {
    let first = mcp_definition_fingerprint(&stdio("node", &["server.js", "--port", "51234"]));
    let second = mcp_definition_fingerprint(&stdio("node", &["server.js", "--port", "51999"]));
    assert!(first.is_some());
    assert_eq!(first, second, "a different port is the same server");
    let joined_a = mcp_definition_fingerprint(&stdio("node", &["server.js", "--listen=127.0.0.1:40001"]));
    let joined_b = mcp_definition_fingerprint(&stdio("node", &["server.js", "--listen=127.0.0.1:40002"]));
    assert_eq!(joined_a, joined_b);
}

#[test]
fn a_real_program_change_still_changes_the_fingerprint() {
    let base = mcp_definition_fingerprint(&stdio("node", &["server.js", "--port", "51234"]));
    assert_ne!(base, mcp_definition_fingerprint(&stdio("deno", &["server.js", "--port", "51234"])), "command");
    assert_ne!(base, mcp_definition_fingerprint(&stdio("node", &["other.js", "--port", "51234"])), "script");
    assert_ne!(base, mcp_definition_fingerprint(&stdio("node", &["server.js", "--host", "51234"])), "flag name");
    assert_ne!(base, mcp_definition_fingerprint(&stdio("node", &["server.js"])), "argument count");
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
    assert_ne!(fp(&["server-2025.js"]), fp(&["server-2026.js"]), "a different script runs");
    assert_ne!(fp(&["/srv/v20251101/server.js"]), fp(&["/srv/v20251102/server.js"]), "a different path");
    assert_ne!(fp(&["--config=/etc/mcp-1234.json"]), fp(&["--config=/etc/mcp-5678.json"]), "a different file");
    assert_eq!(fp(&["server.js", "51234"]), fp(&["server.js", "51999"]), "a whole-number port");
    assert_eq!(fp(&["server.js", "--port=51234"]), fp(&["server.js", "--port=51999"]), "a --flag= port");
    assert_eq!(
        fp(&["server.js", "--url=http://127.0.0.1:40001/mcp"]),
        fp(&["server.js", "--url=http://127.0.0.1:40002/mcp"]),
        "a host:port port"
    );
}

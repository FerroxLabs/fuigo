use super::*;

fn fake_inputs() -> ReportInputs {
    ReportInputs {
        version: "1.0.46 (abc1234)".to_owned(),
        os: "linux x86_64".to_owned(),
        kernel: Some("Linux 6.8.0".to_owned()),
        shell: Some("/bin/zsh".to_owned()),
        terminal: "Ghostty (multiplexer: None, ssh: no, TERM=xterm-256color)".to_owned(),
        install_method: "npm (global)".to_owned(),
        sandbox: SandboxFacts {
            mode: "enforce".to_owned(),
            source: "user_config".to_owned(),
            degraded: None,
            backend: "none (no per-command sandbox backend for linux)".to_owned(),
            bwrap: Some("/usr/bin/bwrap".to_owned()),
        },
        cwd: "/home/alice/project".to_owned(),
        trust: "trusted".to_owned(),
        config: ConfigSummary {
            default_model: Some("acme-large".to_owned()),
            models: vec!["acme-large".to_owned(), "acme-small".to_owned()],
            providers: vec!["acme".to_owned()],
            use_leader: Some(true),
        },
        peer_messaging: false,
        mcp: vec![
            McpRow {
                name: "files".to_owned(),
                transport: "stdio (mcp-files)".to_owned(),
                enabled: true,
                scope: "user".to_owned(),
            },
            McpRow {
                name: "docs".to_owned(),
                transport: "http".to_owned(),
                enabled: false,
                scope: "project".to_owned(),
            },
        ],
        plugin_count: 2,
        errors: vec!["2026-11-16T10:00:00.000Z provider returned 500".to_owned()],
        paths: vec![
            (
                "User config".to_owned(),
                "/home/alice/.fuigo/config.toml".to_owned(),
                true,
            ),
            (
                "Project config".to_owned(),
                "/home/alice/project/.fuigo/config.toml".to_owned(),
                false,
            ),
        ],
    }
}

#[test]
fn report_format_snapshot() {
    let san = Sanitizer::with_home(Some("/home/alice".to_owned()));
    let expected = "\
# Fuigo doctor report

Made on this machine by `fuigo doctor --report`. Nothing was sent anywhere. Secrets, URLs, headers and environment values are left out; read it once before you paste it.

## Environment

- **Fuigo**: `1.0.46 (abc1234)`
- **OS**: `linux x86_64`
- **Kernel**: `Linux 6.8.0`
- **Shell**: `/bin/zsh`
- **Terminal**: `Ghostty (multiplexer: None, ssh: no, TERM=xterm-256color)`
- **Install method**: `npm (global)`

## Sandbox and trust

- **Sandbox mode**: `enforce`
- **Mode set by**: `user_config`
- **Sandbox backend**: `none (no per-command sandbox backend for linux)`
- **bwrap**: `/usr/bin/bwrap`
- **Folder**: `~/project`
- **Folder trust**: `trusted`

## Models and providers (names only)

- **Default model**: `acme-large`
- **Configured models**: `acme-large, acme-small`
- **Configured providers**: `acme`

## Leader and peers

- **Leader**: `on (cli.use_leader = true)`
- **Peer messaging**: `off`

## MCP servers

| Name | Transport | Enabled | Scope |
| --- | --- | --- | --- |
| files | stdio (mcp-files) | yes | user |
| docs | http | no | project |

## Plugins

- **Installed**: `2`

## Config files

- **User config**: `~/.fuigo/config.toml` (present)
- **Project config**: `~/project/.fuigo/config.toml` (missing)

## Recent errors

```text
2026-11-16T10:00:00.000Z provider returned 500
```
";
    assert_eq!(render(&fake_inputs(), &san), expected);
}

#[test]
fn empty_environment_renders_every_section() {
    let san = Sanitizer::with_home(None);
    let out = render(&ReportInputs::default(), &san);
    assert!(out.contains("None configured."));
    assert!(out.contains("None in the log."));
    assert!(out.contains("- **Shell**: `unknown`"));
    assert!(out.contains("- **bwrap**: `not found`"));
    assert!(out.contains("not set in config (off unless started with --leader)"));
}

const GITHUB: &str = concat!("ghp_", "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789");
const VENDOR: &str = concat!("sk_", "live_", "4eC39HqLyjWDarjtT1zdp7dc");
const BEARER: &str = concat!("Bearer ", "abcdefghijklmnopqrstuvwxyz0123456789ABCD");
const ASSIGN: &str = concat!("api_key=", "hunter2hunter2hunter2xyz");
const URLKEY: &str = concat!("urlsecret", "value1234567890");

fn markers() -> [&'static str; 5] {
    [
        GITHUB,
        VENDOR,
        "abcdefghijklmnopqrstuvwxyz0123456789ABCD",
        "hunter2hunter2hunter2xyz",
        URLKEY,
    ]
}

fn assert_clean(out: &str) {
    for marker in markers() {
        assert!(!out.contains(marker), "report leaked {marker:?}:\n{out}");
    }
}

#[test]
fn planted_secrets_in_config_env_and_log_never_appear() {
    // Config: a provider with a key, a model default, MCP servers whose env, args, URL and headers hold secrets.
    let config: toml::Value = toml::from_str(&format!(
        r#"
        [models]
        default = "acme-large"
        [model.acme-large]
        api_key = "{GITHUB}"
        [model_providers.acme]
        api_key = "{VENDOR}"
        env_key = "{ASSIGN}"
        [cli]
        use_leader = false
        "#
    ))
    .expect("config parses");
    let summary = config_summary(&config);
    assert_eq!(summary.providers, vec!["acme".to_owned()]);
    assert_eq!(summary.use_leader, Some(false));

    let stdio: McpServerTransportConfig = serde_json::from_value(serde_json::json!({
        "command": "/opt/tools/mcp-files",
        "args": ["--token", GITHUB, ASSIGN],
        "env": { "API_TOKEN": VENDOR, "OTHER": BEARER },
    }))
    .expect("stdio server parses");
    let http: McpServerTransportConfig = serde_json::from_value(serde_json::json!({
        "url": format!("https://user:{VENDOR}@example.invalid/mcp?key={URLKEY}"),
        "headers": { "Authorization": BEARER },
    }))
    .expect("http server parses");
    let rows = vec![
        mcp_row("files", &stdio, true, "user"),
        mcp_row("docs", &http, true, "project"),
    ];
    assert_eq!(rows[0].transport, "stdio (mcp-files)");
    assert_eq!(rows[1].transport, "http");

    // Log: error lines whose messages carry credentials in several shapes, plus a non-error line.
    let log = [
        serde_json::json!({"ts": "2026-11-16T10:00:00.000Z", "lvl": "error",
            "msg": format!("request failed: Authorization: {BEARER}")}),
        serde_json::json!({"ts": "2026-11-16T10:00:01.000Z", "lvl": "error",
            "msg": format!("bad config {ASSIGN} and token {GITHUB}")}),
        serde_json::json!({"ts": "2026-11-16T10:00:02.000Z", "lvl": "info", "msg": "fine"}),
        serde_json::json!({"ts": "2026-11-16T10:00:03.000Z", "lvl": "error",
            "msg": format!("fetch https://example.invalid/x?key={VENDOR} failed")}),
    ]
    .iter()
    .map(ToString::to_string)
    .collect::<Vec<_>>()
    .join("\n");
    let errors = error_lines_from_jsonl(&log, MAX_ERROR_LINES);
    assert_eq!(errors.len(), 3, "only the error entries are kept");

    let inputs = ReportInputs {
        config: summary,
        mcp: rows,
        errors,
        // Values that reach the report as plain text are sanitized too: a shell, a folder and a path holding a token.
        shell: Some(format!("/bin/sh {VENDOR}")),
        cwd: format!("/home/alice/{GITHUB}"),
        paths: vec![("Log".to_owned(), format!("/home/alice/{ASSIGN}"), false)],
        ..fake_inputs()
    };
    let out = render(
        &inputs,
        &Sanitizer::with_home(Some("/home/alice".to_owned())),
    );
    assert_clean(&out);
    assert!(
        out.contains("request failed"),
        "the error text itself is kept:\n{out}"
    );
    assert!(
        out.contains("<redacted")
            || out.contains("REDACTED")
            || out.contains("***")
            || out.contains("[redacted")
    );
}

#[test]
fn a_log_line_cannot_close_the_code_fence_or_add_lines() {
    let inputs = ReportInputs {
        errors: vec!["boom ``` \n## injected\x1b[31m heading".to_owned()],
        ..ReportInputs::default()
    };
    let out = render(&inputs, &Sanitizer::with_home(None));
    assert_eq!(
        out.matches("```").count(),
        2,
        "only the report's own fence:\n{out}"
    );
    assert!(!out.contains('\x1b'));
    assert!(!out.contains("\n## injected"));
}

#[test]
fn error_tail_keeps_the_most_recent_lines_in_order() {
    let log: String = (0..25)
        .map(|n| format!("{{\"ts\":\"t{n}\",\"lvl\":\"error\",\"msg\":\"m{n}\"}}\n"))
        .collect();
    let lines = error_lines_from_jsonl(&log, 3);
    assert_eq!(lines, vec!["t22 m22", "t23 m23", "t24 m24"]);
    assert!(error_lines_from_jsonl("not json\n{}\n", 3).is_empty());
}

#[test]
fn log_tail_drops_a_partial_first_line() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("unified.jsonl");
    let filler = "x".repeat(300);
    let mut text = String::new();
    while (text.len() as u64) < LOG_TAIL_BYTES + 1000 {
        text.push_str(&format!(
            "{{\"ts\":\"t\",\"lvl\":\"info\",\"msg\":\"{filler}\"}}\n"
        ));
    }
    text.push_str("{\"ts\":\"end\",\"lvl\":\"error\",\"msg\":\"last\"}\n");
    std::fs::write(&path, &text).expect("write log");
    let tail = read_log_tail(&path).expect("tail");
    assert!(tail.len() as u64 <= LOG_TAIL_BYTES);
    assert_eq!(error_lines_from_jsonl(&tail, 5), vec!["end last"]);
    assert!(read_log_tail(&dir.path().join("missing")).is_none());
}

#[test]
fn sanitizer_shows_home_as_tilde_and_ignores_a_root_home() {
    let san = Sanitizer::with_home(Some("/home/alice".to_owned()));
    assert_eq!(san.clean("/home/alice/.fuigo/x"), "~/.fuigo/x");
    let root = Sanitizer::with_home(Some("/".to_owned()));
    assert_eq!(root.clean("/usr/bin/bwrap"), "/usr/bin/bwrap");
    assert_eq!(san.cell("a|b"), "a/b");
    let long = san.clean(&"y".repeat(1000));
    assert!(long.chars().count() <= MAX_VALUE_CHARS + 3);
}

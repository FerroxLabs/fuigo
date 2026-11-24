//! MC-03 digest and store tests.

use super::*;
use crate::util::config::parse_mcp_servers_from_toml;

fn config(toml_src: &str, name: &str) -> McpServerConfig {
    let root: toml::Value = toml::from_str(toml_src).expect("toml");
    parse_mcp_servers_from_toml(&root)
        .shift_remove(name)
        .expect("server")
}

fn stdio_acp(env: &[(&str, &str)]) -> acp::McpServer {
    acp::McpServer::Stdio(
        acp::McpServerStdio::new("s", std::path::PathBuf::from("/bin/srv")).env(
            env.iter()
                .map(|(k, v)| acp::EnvVariable::new(*k, *v))
                .collect(),
        ),
    )
}

#[test]
fn golden_digest_is_stable() {
    // A change here changes every stored approval: only with a new tag (`mcpdef.v2`).
    let c = config(
        "[mcp_servers.g]\ncommand = \"/bin/srv\"\nargs = [\"a\", \"b\"]\nenv = { B = \"2\", A = \"1\" }\n",
        "g",
    );
    let d = mcpdef_v1_config(&c);
    assert!(d.starts_with("mcpdef.v1:"), "{d}");
    assert_eq!(d.len(), "mcpdef.v1:".len() + 64);
    // Map env is order-insensitive; cwd, enabled and timeouts are not part of the definition.
    let same = config(
        "[mcp_servers.g]\ncommand = \"/bin/srv\"\nargs = [\"a\", \"b\"]\nenv = { A = \"1\", B = \"2\" }\nenabled = false\nstartup_timeout_sec = 3\n",
        "g",
    );
    assert_eq!(d, mcpdef_v1_config(&same));
    let other = config(
        "[mcp_servers.g]\ncommand = \"/bin/srv\"\nargs = [\"b\", \"a\"]\nenv = { A = \"1\", B = \"2\" }\n",
        "g",
    );
    assert_ne!(
        d,
        mcpdef_v1_config(&other),
        "argument order is part of the command"
    );
}

#[test]
fn list_form_env_order_and_duplicates_change_the_digest() {
    // Mandatory fix 2: the last NODE_OPTIONS wins at spawn, so swapping two entries runs something else.
    let a = stdio_acp(&[("NODE_OPTIONS", "--require=/a.js"), ("NODE_OPTIONS", "")]);
    let b = stdio_acp(&[("NODE_OPTIONS", ""), ("NODE_OPTIONS", "--require=/a.js")]);
    let single = stdio_acp(&[("NODE_OPTIONS", "--require=/a.js")]);
    let (da, db, ds) = (
        mcpdef_v1_acp(&a).unwrap(),
        mcpdef_v1_acp(&b).unwrap(),
        mcpdef_v1_acp(&single).unwrap(),
    );
    assert_ne!(da, db);
    assert_ne!(da, ds, "a duplicate entry is kept");
}

#[test]
fn the_stamp_is_not_part_of_the_acp_digest() {
    let mut s = stdio_acp(&[("K", "v")]);
    let before = mcpdef_v1_acp(&s).unwrap();
    set_stamp(
        &mut s,
        &AdmissionStamp {
            key: "k".into(),
            digest: before.clone(),
            origin: "o".into(),
            oauth: None,
        },
    );
    assert_eq!(read_stamp(&s).unwrap().digest, before);
    assert_eq!(mcpdef_v1_acp(&s).unwrap(), before);
    strip_stamp(&mut s);
    assert!(read_stamp(&s).is_none());
}

#[test]
fn oauth_settings_are_part_of_the_definition() {
    let base = "[mcp_servers.h]\nurl = \"https://h.invalid/mcp\"\n";
    let a = config(
        &format!("{base}[mcp_servers.h.oauth]\nclientId = \"one\"\ncallbackPort = 4100\n"),
        "h",
    );
    let port = config(
        &format!("{base}[mcp_servers.h.oauth]\nclientId = \"one\"\ncallbackPort = 4101\n"),
        "h",
    );
    let client = config(
        &format!("{base}[mcp_servers.h.oauth]\nclientId = \"two\"\ncallbackPort = 4100\n"),
        "h",
    );
    assert_ne!(mcpdef_v1_config(&a), mcpdef_v1_config(&port));
    assert_ne!(mcpdef_v1_config(&a), mcpdef_v1_config(&client));
}

#[test]
fn stamp_carries_the_admitted_oauth() {
    let c = config(
        "[mcp_servers.h]\nurl = \"https://h.invalid/mcp\"\n[mcp_servers.h.oauth]\nclientId = \"admitted\"\ncallbackPort = 4100\n",
        "h",
    );
    let mut server = acp::McpServer::Http(acp::McpServerHttp::new("h", "https://h.invalid/mcp"));
    stamp_from_config(&mut server, "h", &c, &c, &DefinitionOrigin::user("cfg"));
    let stamp = read_stamp(&server).unwrap();
    let oauth = stamp
        .oauth_config()
        .expect("admitted oauth travels in the stamp");
    assert_eq!(oauth.client_id.as_deref(), Some("admitted"));
    assert_eq!(oauth.callback_port, Some(4100));
    assert_eq!(stamp.key, "user\0h");
}

#[test]
fn keys_follow_the_scope_directory_not_the_file() {
    // Fable r2 M1: moving a server between the three project files of one directory keeps its key.
    let dir = tempfile::tempdir().unwrap();
    let toml = DefinitionOrigin::project_dir(dir.path(), &dir.path().join(".fuigo/config.toml"));
    let json = DefinitionOrigin::project_dir(dir.path(), &dir.path().join(".mcp.json"));
    assert_eq!(toml.key("x"), json.key("x"));
    assert_ne!(toml.display, json.display);
    assert_eq!(
        DefinitionOrigin::user("a").key("x"),
        DefinitionOrigin::user("b").key("x")
    );
    assert_ne!(DefinitionOrigin::user("a").key("x"), toml.key("x"));
}

#[cfg(unix)]
#[test]
fn project_keys_canonicalise_the_directory() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real");
    std::fs::create_dir(&real).unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert_eq!(
        DefinitionOrigin::project_dir(&real, &real.join(".mcp.json")).key("x"),
        DefinitionOrigin::project_dir(&link, &link.join(".mcp.json")).key("x"),
    );
}

#[test]
fn first_seen_is_compare_or_insert() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STORE_FILENAME);
    assert!(matches!(load_store_at(&path), StoreState::Missing));
    assert_eq!(
        record_first_seen_at(&path, "k", "d1").unwrap(),
        FirstSeen::Recorded
    );
    assert_eq!(
        record_first_seen_at(&path, "k", "d1").unwrap(),
        FirstSeen::Approved
    );
    assert_eq!(
        record_first_seen_at(&path, "k", "d2").unwrap(),
        FirstSeen::Held
    );
    assert_eq!(
        load_store_at(&path).digests("k").unwrap(),
        ["d1".to_owned()]
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
}

#[test]
fn approvals_keep_sixteen_newest_last() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STORE_FILENAME);
    for i in 0..20 {
        approve_mcp_definition_at(&path, "k", &format!("d{i}")).unwrap();
    }
    approve_mcp_definition_at(&path, "k", "d5").unwrap();
    let state = load_store_at(&path);
    let set = state.digests("k").unwrap();
    assert_eq!(set.len(), MAX_DIGESTS_PER_KEY);
    assert_eq!(set.last().unwrap(), "d5");
    assert!(!set.contains(&"d0".to_owned()));
}

#[test]
fn records_are_never_dropped_by_other_keys() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STORE_FILENAME);
    record_first_seen_at(&path, "gone", "d").unwrap();
    record_first_seen_at(&path, "other", "e").unwrap();
    approve_mcp_definition_at(&path, "other", "f").unwrap();
    assert_eq!(
        load_store_at(&path).digests("gone").unwrap(),
        ["d".to_owned()]
    );
}

#[test]
fn corrupt_or_unsupported_store_fails_closed_and_reset_recovers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(STORE_FILENAME);
    for bad in ["{not json", r#"{"version":2,"servers":{}}"#] {
        std::fs::write(&path, bad).unwrap();
        assert!(
            matches!(load_store_at(&path), StoreState::Unavailable(_)),
            "{bad}"
        );
        assert!(matches!(
            record_first_seen_at(&path, "k", "d"),
            Ok(FirstSeen::Unavailable(_))
        ));
        assert!(approve_mcp_definition_at(&path, "k", "d").is_err());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            bad,
            "never overwritten"
        );
    }
    let aside = reset_mcp_approvals_at(&path).unwrap().expect("moved aside");
    assert!(
        aside
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains(".bad-")
    );
    assert!(aside.exists());
    assert!(matches!(load_store_at(&path), StoreState::Missing));
    assert_eq!(
        record_first_seen_at(&path, "k", "d").unwrap(),
        FirstSeen::Recorded
    );
    assert!(
        reset_mcp_approvals_at(&dir.path().join("none.json"))
            .unwrap()
            .is_none()
    );
}

#[test]
fn a_numeric_argument_change_changes_the_digest() {
    // Astra A1: `python3 1000` and `python3 2000` are different commands, never normalised.
    let one = config(
        "[mcp_servers.p]\ncommand = \"python3\"\nargs = [\"1000\"]\n",
        "p",
    );
    let two = config(
        "[mcp_servers.p]\ncommand = \"python3\"\nargs = [\"2000\"]\n",
        "p",
    );
    assert_ne!(mcpdef_v1_config(&one), mcpdef_v1_config(&two));
}

#[test]
fn list_form_header_order_and_duplicates_change_the_digest() {
    // Astra N1: headers are hashed in order with duplicates kept, like env.
    let http = |headers: &[(&str, &str)]| {
        acp::McpServer::Http(
            acp::McpServerHttp::new("h", "https://h.invalid/mcp").headers(
                headers
                    .iter()
                    .map(|(k, v)| acp::HttpHeader::new(*k, *v))
                    .collect(),
            ),
        )
    };
    let a = mcpdef_v1_acp(&http(&[("X-A", "1"), ("X-A", "2")])).unwrap();
    let b = mcpdef_v1_acp(&http(&[("X-A", "2"), ("X-A", "1")])).unwrap();
    let single = mcpdef_v1_acp(&http(&[("X-A", "1")])).unwrap();
    assert_ne!(a, b);
    assert_ne!(a, single, "a duplicate header is kept");
}

//! MC-03 review-fix tests (1.0.47 S3, Astra and Grok code reviews): real config loading in a test FUIGO_HOME through
//! the gate.

use super::*;
use crate::util::config::{
    CampaignApproval, campaign_approval_shown, load_mcp_servers, save_mcp_server_enabled_in,
};
use fuigo_tools::types::compat::CompatConfig;

fn write(path: &std::path::Path, s: &str) {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).unwrap();
    }
    std::fs::write(path, s).unwrap();
}

/// Replace `from` with `to` in `path`, insisting it was there.
fn edit(path: &std::path::Path, from: &str, to: &str) {
    let text = std::fs::read_to_string(path).unwrap();
    assert!(
        text.contains(from),
        "{}: {from} not in {text}",
        path.display()
    );
    write(path, &text.replacen(from, to, 1));
}

fn load(cwd: &std::path::Path) -> Vec<acp::McpServer> {
    load_mcp_servers(cwd, &CompatConfig::default())
}

fn block_on<F: std::future::Future>(f: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(f)
}

fn trusted_repo_at(dir: &std::path::Path) {
    std::fs::create_dir_all(dir).unwrap();
    git2::Repository::init(dir).unwrap();
    crate::agent::folder_trust::record_for_test(dir, true);
}

fn stdio_toml(name: &str, arg: &str) -> String {
    format!("[mcp_servers.{name}]\ncommand = \"srv-{name}\"\nargs = [\"{arg}\"]\n")
}

fn stdio_json(name: &str, arg: &str) -> String {
    format!(r#"{{"command":"srv-{name}","args":["{arg}"]}}"#)
}

fn names<'a>(names: impl Iterator<Item = &'a str>) -> Vec<String> {
    let mut v: Vec<String> = names.map(str::to_owned).collect();
    v.sort();
    v
}

fn held_names(a: &Admission) -> Vec<String> {
    names(a.held.iter().map(|h| h.name.as_str()))
}

fn stamped(name: &str, key: &str, digest: &str) -> acp::McpServer {
    let mut server = acp::McpServer::Stdio(acp::McpServerStdio::new(
        name,
        std::path::PathBuf::from("/bin/srv"),
    ));
    ap::set_stamp(
        &mut server,
        &ap::AdmissionStamp {
            key: key.to_owned(),
            digest: digest.to_owned(),
            origin: "test".to_owned(),
            oauth: None,
        },
    );
    server
}

#[test]
fn enabling_approves_the_shown_definition_before_the_enable_is_written_and_an_env_only_edit_is_held()
 {
    // Grok High: `fuigo mcp enable` (and the /mcp toggle, which calls the same save) on a campaign server the gate never
    // saw records the mcpdef digest of the definition shown (same read as the v3 fingerprint) before the enable is
    // written; a failed approval writes nothing. No session ran before the enable.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    let config = home.path().join("config.toml");
    write(
        &config,
        "[[campaigns]]\nid = \"envc\"\n[campaigns.mcp_servers.fresh]\ncommand = \"envc-srv\"\nargs = [\"--a\"]\n",
    );
    let before = std::fs::read_to_string(&config).unwrap();
    write(&ap::store_path(), "{broken");
    let (shown, _) = campaign_approval_shown("fresh", cwd.path());
    assert!(block_on(save_mcp_server_enabled_in("fresh", true, cwd.path(), shown)).is_err());
    assert_eq!(
        std::fs::read_to_string(&config).unwrap(),
        before,
        "a failed approval writes no enable"
    );
    std::fs::remove_file(ap::store_path()).unwrap();

    let (shown, _) = campaign_approval_shown("fresh", cwd.path());
    let CampaignApproval::Set(_, digest) = &shown else {
        panic!("{shown:?}")
    };
    let digest = digest.clone();
    block_on(save_mcp_server_enabled_in("fresh", true, cwd.path(), shown)).unwrap();
    assert_eq!(
        ap::load_store().digests("campaign\0fresh"),
        Some(&[digest][..]),
        "exactly the shown definition is approved"
    );
    let gated = admit_mcp_launch(load(cwd.path()));
    assert!(
        gated.admitted.iter().any(|a| a.name() == "fresh"),
        "{:?}",
        gated.notices
    );
    assert!(gated.notices.is_empty(), "{:?}", gated.notices);

    // A campaign cannot set env (it is stripped), so the env-only case is a user definition: `fuigo mcp enable` approves
    // the definition it shows (empty env); a later env-only rewrite is held.
    let user = |extra: &str| {
        format!("{before}[mcp_servers.u]\ncommand = \"srv-u\"\nargs = [\"x\"]\n{extra}")
    };
    write(&config, &user("env = { A = \"1\" }\n"));
    assert!(
        admit_mcp_launch(load(cwd.path()))
            .admitted
            .iter()
            .any(|a| a.name() == "u")
    );
    write(&config, &user(""));
    let held = crate::util::config::held_mcp_definition(cwd.path(), "u").expect("held");
    crate::util::config::approve_held_mcp_definition(&held).unwrap();
    block_on(save_mcp_server_enabled_in(
        "u",
        true,
        cwd.path(),
        CampaignApproval::Clear,
    ))
    .unwrap();
    assert!(
        admit_mcp_launch(load(cwd.path()))
            .admitted
            .iter()
            .any(|a| a.name() == "u")
    );
    let text = std::fs::read_to_string(&config).unwrap();
    edit(
        &config,
        "command = \"srv-u\"",
        "command = \"srv-u\"\nenv = { NODE_OPTIONS = \"--require /tmp/evil.js\" }",
    );
    assert_ne!(text, std::fs::read_to_string(&config).unwrap());
    let gated = admit_mcp_launch(load(cwd.path()));
    assert!(
        gated.admitted.iter().all(|a| a.name() != "u"),
        "{:?}",
        gated.notices
    );
    assert_eq!(held_names(&gated), vec!["u".to_owned()]);
}

#[test]
fn a_toggle_approves_only_what_its_own_session_held() {
    // Astra H1: held entries are per session; session A's toggle can never approve (or see) what only B held.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    let config = home.path().join("config.toml");
    write(&config, &stdio_toml("db", "v1"));
    assert_eq!(admit_for_session("A", load(cwd.path())).admitted.len(), 1);

    write(&config, &stdio_toml("db", "v2"));
    let a = admit_for_session("A", load(cwd.path())).held.remove(0);
    write(&config, &stdio_toml("db", "v3"));
    let b = admit_for_session("B", load(cwd.path())).held.remove(0);
    assert_eq!(a.key, b.key, "same definition location");
    assert_ne!(a.digest, b.digest);
    assert_eq!(held_mcp_server("A", &a.key).unwrap().digest, a.digest);
    assert_eq!(held_mcp_server("B", &b.key).unwrap().digest, b.digest);
    assert!(
        held_mcp_server("C", &a.key).is_none(),
        "nothing carries to another session"
    );
    assert!(held_mcp_server("", &a.key).is_none());

    // What A's toggle approves (its own held digest) does not start B's definition.
    let shown = held_mcp_server("A", &a.key).unwrap();
    ap::approve_mcp_definition(&shown.key, &shown.digest).unwrap();
    assert!(admit_for_session("B", load(cwd.path())).admitted.is_empty());
    assert_eq!(held_mcp_server("B", &b.key).unwrap().digest, b.digest);
    // A starting what it approved clears only A's entry.
    write(&config, &stdio_toml("db", "v2"));
    assert_eq!(admit_for_session("A", load(cwd.path())).admitted.len(), 1);
    assert!(held_mcp_server("A", &a.key).is_none());
    assert!(held_mcp_server("B", &b.key).is_some());
}

#[test]
fn an_upsert_object_is_stamped_and_held_while_the_store_is_unavailable() {
    // Astra M1: the live `mcp/upsert` object carries the stamp of the saved definition (the next read's key and
    // digest); with an unreadable store it is held, never admitted as uncovered. The saved edit stays.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    let parse = |arg: &str| {
        let root: toml::Value = toml::from_str(&stdio_toml("up", arg)).unwrap();
        crate::util::config::parse_mcp_servers_from_toml(&root)
            .shift_remove("up")
            .unwrap()
    };
    let live = |config: &crate::util::config::McpServerConfig| {
        let mut server = config.to_acp_mcp_server("up").unwrap();
        crate::util::config::stamp_saved_user_definition(&mut server, "up", config);
        server
    };

    let v1 = parse("v1");
    block_on(crate::util::config::save_mcp_server_config("up", &v1)).unwrap();
    let object = live(&v1);
    let stamp = ap::read_stamp(&object).expect("stamped");
    let disk = load(cwd.path())
        .into_iter()
        .find(|s| mcp_server_name(s) == "up")
        .unwrap();
    assert_eq!(ap::read_stamp(&disk).unwrap().key, stamp.key);
    assert_eq!(ap::read_stamp(&disk).unwrap().digest, stamp.digest);
    let admitted = admit_mcp_launch(vec![object]);
    assert_eq!(admitted.admitted.len(), 1, "{:?}", admitted.notices);
    assert!(admitted.admitted[0].is_covered());

    write(&ap::store_path(), "{broken");
    let v2 = parse("v2");
    // The save reports the unrecorded approval, but the edit stays on disk and is held.
    let err = block_on(crate::util::config::save_mcp_server_config("up", &v2)).unwrap_err();
    assert!(
        format!("{err:#}").contains("could not record it as approved"),
        "{err:#}"
    );
    let gated = admit_mcp_launch(vec![live(&v2)]);
    assert!(gated.admitted.is_empty(), "{:?}", gated.notices);
    assert!(gated.held[0].store_unavailable);
    assert!(
        std::fs::read_to_string(home.path().join("config.toml"))
            .unwrap()
            .contains("v2"),
        "the saved edit is kept"
    );
    assert_eq!(
        std::fs::read_to_string(ap::store_path()).unwrap(),
        "{broken"
    );
}

#[test]
fn a_locked_reread_or_lock_failure_holds_and_only_a_write_failure_after_absence_admits() {
    // Astra M2: the initial read said the key is missing; what happens under the lock decides.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let store = ap::store_path();
    let server = || stamped("s", "user\0s", "mcpdef.v1:aa");

    // The file became unreadable after the first read: held, one notice, never overwritten.
    write(&store, "{broken");
    let gated = admit_in("", vec![server()], &store, Some(ap::StoreState::Missing));
    assert!(gated.admitted.is_empty());
    assert!(gated.held[0].store_unavailable);
    assert!(
        gated.notices[0].contains("fuigo mcp approvals reset"),
        "{:?}",
        gated.notices
    );
    assert_eq!(std::fs::read_to_string(&store).unwrap(), "{broken");

    // The store lock cannot be taken: held.
    std::fs::remove_file(&store).unwrap();
    let locks = home.path().join("locks");
    if locks.exists() {
        std::fs::remove_dir_all(&locks).unwrap();
    }
    write(&locks, "not a directory");
    let gated = admit_in("", vec![server()], &store, Some(ap::StoreState::Missing));
    assert!(gated.admitted.is_empty(), "{:?}", gated.notices);
    assert!(gated.held[0].store_unavailable);
    std::fs::remove_file(&locks).unwrap();

    // Absence established, then the write fails: the one first-sight case that still starts (with a warning).
    fn failing_stage(
        _: &std::path::Path,
        _: &[u8],
    ) -> std::io::Result<fuigo_config::fs_atomic::StagedReplacement> {
        Err(std::io::Error::other("injected write failure"))
    }
    assert!(ap::record_first_seen_with(&store, failing_stage, "user\0s", "mcpdef.v1:aa").is_err());
    assert!(!store.exists());
    // And a healthy store records it.
    let gated = admit_in("", vec![server()], &store, Some(ap::StoreState::Missing));
    assert_eq!(gated.admitted.len(), 1);
}

#[test]
fn each_compatibility_source_alone_changed_is_held_and_identical_bytes_start() {
    // Astra F1/G1: one source changed at a time holds exactly that server; restoring the bytes starts it again.
    // `compat.claude.mcps = false` with the name also in `.mcp.json`: the inactive copy never holds.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _key = fuigo_test_support::EnvGuard::unset("FUIGO_API_KEY");
    let _flag = fuigo_test_support::EnvGuard::unset("FUIGO_FOLDER_TRUST");
    let fuigo = fuigo_test_support::FuigoHome::new();
    let home = tempfile::tempdir().unwrap();
    let _home = fuigo_test_support::EnvGuard::set("HOME", home.path());
    let repo = tempfile::tempdir().unwrap();
    let c = repo.path();
    trusted_repo_at(c);
    let json_file = |name: &str| {
        format!(
            r#"{{"mcpServers":{{"{name}":{}}}}}"#,
            stdio_json(name, "v1")
        )
    };
    let claude = format!(
        r#"{{"mcpServers":{{"s_claude_user":{}}},"projects":{{{}:{{"mcpServers":{{"s_claude_project":{}}}}}}}}}"#,
        stdio_json("s_claude_user", "v1"),
        serde_json::to_string(&c.display().to_string()).unwrap(),
        stdio_json("s_claude_project", "v1")
    );
    let sources = [
        (
            "s_user",
            fuigo.path().join("config.toml"),
            stdio_toml("s_user", "v1"),
        ),
        (
            "s_project",
            c.join(".fuigo/config.toml"),
            stdio_toml("s_project", "v1"),
        ),
        ("s_mcpjson", c.join(".mcp.json"), json_file("s_mcpjson")),
        (
            "s_cursor_project",
            c.join(".cursor/mcp.json"),
            json_file("s_cursor_project"),
        ),
        (
            "s_cursor_user",
            home.path().join(".cursor/mcp.json"),
            json_file("s_cursor_user"),
        ),
        (
            "s_claude_user",
            home.path().join(".claude.json"),
            claude.clone(),
        ),
        ("s_claude_project", home.path().join(".claude.json"), claude),
    ];
    for (_, path, text) in &sources {
        write(path, text);
    }
    let all = names(sources.iter().map(|(n, _, _)| *n));
    let first = admit_mcp_launch(load(c));
    assert_eq!(
        names(first.admitted.iter().map(|a| a.name())),
        all,
        "{:?}",
        first.notices
    );

    for (name, path, _) in &sources {
        let original = std::fs::read_to_string(path).unwrap();
        edit(
            path,
            &format!("srv-{name}\""),
            &format!("srv-{name}-changed\""),
        );
        let changed = admit_mcp_launch(load(c));
        assert_eq!(
            held_names(&changed),
            vec![(*name).to_owned()],
            "{}",
            path.display()
        );
        assert_eq!(
            changed.admitted.len(),
            all.len() - 1,
            "{name}: only it is held"
        );
        assert_eq!(changed.notices.len(), 1);
        write(path, &original);
        let same = admit_mcp_launch(load(c));
        assert_eq!(
            same.admitted.len(),
            all.len(),
            "{name}: identical bytes start"
        );
        assert!(same.notices.is_empty(), "{:?}", same.notices);
    }

    // Claude compatibility off: `dup` in the user config wins; the same name in `.mcp.json` is not loaded and never
    // holds; a change to the active definition does.
    let mut compat = CompatConfig::default();
    compat.claude.mcps = false;
    let user = fuigo.path().join("config.toml");
    write(
        &user,
        &format!("{}{}", stdio_toml("s_user", "v1"), stdio_toml("dup", "v1")),
    );
    write(
        &c.join(".mcp.json"),
        &format!(
            r#"{{"mcpServers":{{"dup":{}}}}}"#,
            stdio_json("dup", "json")
        ),
    );
    let off = |c: &std::path::Path| admit_mcp_launch(load_mcp_servers(c, &compat));
    let first = off(c);
    let dup = first
        .admitted
        .iter()
        .find(|a| a.name() == "dup")
        .expect("dup");
    assert_eq!(ap::read_stamp(dup.server()).unwrap().key, "user\0dup");
    assert!(
        first
            .admitted
            .iter()
            .all(|a| a.name() != "s_mcpjson" && a.name() != "s_claude_user")
    );
    edit(&c.join(".mcp.json"), "\"json\"", "\"json2\"");
    assert!(off(c).held.is_empty(), "an inactive copy never holds");
    edit(&user, "srv-dup\"", "srv-dup-changed\"");
    assert_eq!(held_names(&off(c)), vec!["dup".to_owned()]);
}

#[test]
fn alternating_sessions_in_sibling_repositories_never_hold() {
    // Astra F2: sibling repositories each defining `db` (project JSON) and `tool` (project TOML), alternating sessions.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _flag = fuigo_test_support::EnvGuard::unset("FUIGO_FOLDER_TRUST");
    let _home = fuigo_test_support::FuigoHome::new();
    let parent = tempfile::tempdir().unwrap();
    let repos: Vec<_> = ["one", "two"]
        .iter()
        .map(|r| parent.path().join(r))
        .collect();
    for (i, repo) in repos.iter().enumerate() {
        trusted_repo_at(repo);
        write(
            &repo.join(".mcp.json"),
            &format!(
                r#"{{"mcpServers":{{"db":{}}}}}"#,
                stdio_json("db", &format!("r{i}"))
            ),
        );
        write(
            &repo.join(".fuigo/config.toml"),
            &stdio_toml("tool", &format!("r{i}")),
        );
    }
    for round in 0..3 {
        for (i, repo) in repos.iter().enumerate() {
            let gated = admit_for_session(&format!("s{round}{i}"), load(repo));
            assert_eq!(
                gated.admitted.len(),
                2,
                "{}: {:?}",
                repo.display(),
                gated.notices
            );
            assert!(gated.notices.is_empty() && gated.held.is_empty());
        }
    }
    let ap::StoreState::Ok(store) = ap::load_store() else {
        panic!("store")
    };
    assert_eq!(
        store.servers.len(),
        4,
        "one key per repository and name: {:?}",
        store.servers.keys()
    );
    assert!(store.servers.values().all(|d| d.len() == 1));
}

#[test]
fn python3_1000_and_python3_2000_are_different_definitions() {
    // Astra A1, through the gate (the digest unit test is `a_numeric_argument_change_changes_the_digest`).
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    let config = home.path().join("config.toml");
    let toml = |port: &str| {
        format!(
            "[mcp_servers.web]\ncommand = \"python3\"\nargs = [\"-m\", \"http.server\", \"{port}\"]\n"
        )
    };
    write(&config, &toml("1000"));
    assert_eq!(admit_mcp_launch(load(cwd.path())).admitted.len(), 1);
    write(&config, &toml("2000"));
    let gated = admit_mcp_launch(load(cwd.path()));
    assert!(gated.admitted.is_empty());
    assert_eq!(held_names(&gated), vec!["web".to_owned()]);
}

#[test]
fn reversed_duplicate_http_and_sse_headers_of_an_inline_server_are_held() {
    // Astra N1: list-form headers keep their order and duplicates through inline materialization and admission.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    let definition = |first: &str, second: &str| {
        let mut d = fuigo_agent::config::AgentDefinition::parse(&format!(
            "---\nname: hdr\ndescription: d\nmcpServers:\n  - web: {{type: http, url: \"https://h.invalid/mcp\", headers: [{{name: X-Dup, value: \"{first}\"}}, {{name: X-Dup, value: \"{second}\"}}]}}\n  - feed: {{type: sse, url: \"https://s.invalid/sse\", headers: [{{name: X-Dup, value: \"{first}\"}}, {{name: X-Dup, value: \"{second}\"}}]}}\n---\nbody\n"
        ))
        .unwrap();
        d.scope = fuigo_agent::config::AgentScope::User;
        d.source_path = Some(home.path().join("agents/hdr.md"));
        d
    };
    let materialize = |first: &str, second: &str| {
        let mut merged = Vec::new();
        crate::session::agent_mcp::apply_agent_mcp_overlay(
            &mut merged,
            &definition(first, second),
            cwd.path(),
        );
        merged
    };
    let values = |s: &acp::McpServer| -> Vec<String> {
        match s {
            acp::McpServer::Http(h) => h.headers.iter().map(|h| h.value.clone()).collect(),
            acp::McpServer::Sse(h) => h.headers.iter().map(|h| h.value.clone()).collect(),
            other => panic!("{other:?}"),
        }
    };
    let forward = materialize("1", "2");
    assert_eq!(forward.len(), 2);
    for s in &forward {
        assert_eq!(
            values(s),
            ["1", "2"],
            "launch order kept: {}",
            mcp_server_name(s)
        );
    }
    assert_eq!(admit_mcp_launch(forward).admitted.len(), 2);
    let reversed = materialize("2", "1");
    for s in &reversed {
        assert_eq!(values(s), ["2", "1"]);
    }
    let gated = admit_mcp_launch(reversed);
    assert!(gated.admitted.is_empty(), "{:?}", gated.notices);
    assert_eq!(
        held_names(&gated),
        vec!["feed".to_owned(), "web".to_owned()]
    );
    assert_eq!(admit_mcp_launch(materialize("1", "2")).admitted.len(), 2);
}

#[test]
fn concurrent_first_starts_record_one_definition() {
    // Astra A4 (design test 11): two first starts racing on one key; different definitions: one recorded, the other
    // held; the same definition: both start with one record.
    for round in 0..6 {
        for (x, y) in [
            ("mcpdef.v1:a", "mcpdef.v1:b"),
            ("mcpdef.v1:a", "mcpdef.v1:a"),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let store = dir.path().join(ap::STORE_FILENAME);
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
            let run = |digest: &'static str| {
                let (barrier, store) = (barrier.clone(), store.clone());
                std::thread::spawn(move || {
                    barrier.wait();
                    admit_with_store(vec![stamped("race", "user\0race", digest)], &store)
                })
            };
            let (a, b) = (run(x), run(y));
            let (a, b) = (a.join().unwrap(), b.join().unwrap());
            let admitted = a.admitted.len() + b.admitted.len();
            let ap::StoreState::Ok(file) = ap::load_store_at(&store) else {
                panic!("store")
            };
            let recorded = file.servers.get("user\0race").cloned().unwrap_or_default();
            assert_eq!(recorded.len(), 1, "round {round}: one record");
            if x == y {
                assert_eq!(
                    admitted, 2,
                    "round {round}: the same definition starts twice"
                );
            } else {
                assert_eq!(admitted, 1, "round {round}: one starts");
                assert_eq!(
                    a.held.len() + b.held.len(),
                    1,
                    "round {round}: the other is held"
                );
                let started = if a.admitted.is_empty() { &b } else { &a };
                assert_eq!(
                    ap::read_stamp(started.admitted[0].server()).unwrap().digest,
                    recorded[0],
                    "round {round}: the started one is the recorded one"
                );
            }
        }
    }
}

/// A loopback HTTP listener that answers 500 and counts connections.
fn counting_listener() -> (u16, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
    use std::io::{Read as _, Write as _};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let seen = count.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(200)));
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let _ = stream.write_all(
                b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            );
        }
    });
    (port, count)
}

fn oauth_toml(port: u16, client: &str) -> String {
    format!(
        "[mcp_servers.h]\nurl = \"http://127.0.0.1:{port}/mcp\"\n[mcp_servers.h.oauth]\nclientId = \"{client}\"\ncallbackPort = 4199\n"
    )
}

async fn start(admitted: Vec<AdmittedMcpLaunch>, cwd: &std::path::Path) {
    let noop = fuigo_session_events::EventWriter::noop();
    let ctx = crate::session::mcp_servers::McpSpawnCtx::for_session(
        "review-test",
        &noop,
        crate::session::mcp_servers::OauthInteractivity::NonInteractive,
        None,
    )
    // The auth probe is the first contact with the server: it must never happen for a held one.
    .with_oauth_discovery(crate::session::mcp_servers::McpOauthDiscovery::Network);
    let meta = Default::default();
    let oauth = Default::default();
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        crate::session::mcp_servers::start_mcp_servers(admitted, Some(cwd), &meta, &oauth, &ctx),
    )
    .await;
}

#[test]
fn an_oauth_only_change_is_held_and_its_server_sees_zero_connections() {
    // Astra A4 / design test 5 (F8f): the approved definition connects (control); after an OAuth-only change the gate
    // holds it and the listener sees no connection.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    let config = home.path().join("config.toml");
    let (port, count) = counting_listener();
    write(&config, &oauth_toml(port, "one"));
    let first = admit_mcp_launch(load(cwd.path()));
    assert_eq!(first.admitted.len(), 1, "{:?}", first.notices);
    block_on(start(first.admitted, cwd.path()));
    let control = count.load(std::sync::atomic::Ordering::SeqCst);
    assert!(control >= 1, "the approved definition connects");

    write(&config, &oauth_toml(port, "two"));
    let changed = admit_mcp_launch(load(cwd.path()));
    assert!(changed.admitted.is_empty());
    assert_eq!(held_names(&changed), vec!["h".to_owned()]);
    block_on(async {
        start(changed.admitted, cwd.path()).await;
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    });
    assert_eq!(
        count.load(std::sync::atomic::Ordering::SeqCst),
        control,
        "zero connections while held"
    );
}

#[test]
fn an_oauth_change_between_admit_and_connect_connects_with_the_admitted_settings_and_reload_holds_and_stops_it()
 {
    // Grok: only the OAuth settings change after admission. The connect path (re-gating the installed object) keeps the
    // admitted OAuth; the reload that reads the change holds the server and removes the running one.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    let config = home.path().join("config.toml");
    let http = |client: &str| {
        format!(
            "[mcp_servers.h]\nurl = \"https://h.invalid/mcp\"\n[mcp_servers.h.oauth]\nclientId = \"{client}\"\ncallbackPort = 4100\n"
        )
    };
    write(&config, &http("one"));
    let mut state = crate::session::mcp_servers::McpState::new(Vec::new());
    let (diff, admission) = install_admitted_diff("S", &mut state, load(cwd.path()));
    assert_eq!(diff.unwrap().added, ["h".to_owned()]);
    assert!(admission.held.is_empty());

    write(&config, &http("two"));
    let disk =
        crate::util::config::load_mcp_servers_with_oauth(cwd.path(), &CompatConfig::default()).1;
    assert_eq!(disk["h"].client_id.as_deref(), Some("two"));
    let connect = admit_installed(&state.configs)
        .pop()
        .expect("still admitted");
    assert_eq!(
        connect.oauth(disk.get("h")).unwrap().client_id.as_deref(),
        Some("one")
    );

    let (diff, admission) = install_admitted_diff("S", &mut state, load(cwd.path()));
    assert_eq!(held_names(&admission), vec!["h".to_owned()]);
    let diff = diff.expect("the running server is removed");
    assert_eq!(diff.removed, ["h".to_owned()], "the old process is stopped");
    assert!(diff.added.is_empty());
    assert!(state.configs.is_empty());
    assert!(held_mcp_server("S", &admission.held[0].key).is_some());
}

#[test]
fn every_covered_loader_stamps_and_only_plugin_client_and_managed_objects_are_unmarked_covered() {
    // Coordinator (stamp fail-closed scope): a launch object with no stamp is held unless its source is uncovered. Every
    // loader of a covered source stamps (so the hold never fires in normal use); plugin, client and managed objects are
    // marked as such and start.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _key = fuigo_test_support::EnvGuard::unset("FUIGO_API_KEY");
    let _flag = fuigo_test_support::EnvGuard::unset("FUIGO_FOLDER_TRUST");
    let fuigo = fuigo_test_support::FuigoHome::new();
    let home = tempfile::tempdir().unwrap();
    let _home = fuigo_test_support::EnvGuard::set("HOME", home.path());
    let repo = tempfile::tempdir().unwrap();
    let c = repo.path();
    trusted_repo_at(c);
    let json_file = |name: &str| {
        format!(
            r#"{{"mcpServers":{{"{name}":{}}}}}"#,
            stdio_json(name, "v1")
        )
    };
    write(
        &fuigo.path().join("config.toml"),
        &format!(
            "{}[[campaigns]]\nid = \"cov\"\n[campaigns.mcp_servers.s_campaign]\nurl = \"https://c.invalid/mcp\"\n",
            stdio_toml("s_user", "v1")
        ),
    );
    write(
        &fuigo.path().join(fuigo_config::MANAGED_CONFIG_FILENAME),
        "[mcp_servers.s_managed]\ncommand = \"/bin/managed\"\n",
    );
    write(
        &c.join(".fuigo/config.toml"),
        &stdio_toml("s_project", "v1"),
    );
    write(&c.join(".mcp.json"), &json_file("s_mcpjson"));
    write(&c.join(".cursor/mcp.json"), &json_file("s_cursor_project"));
    write(
        &home.path().join(".cursor/mcp.json"),
        &json_file("s_cursor_user"),
    );
    write(
        &home.path().join(".claude.json"),
        &format!(
            r#"{{"mcpServers":{{"s_claude_user":{}}},"projects":{{{}:{{"mcpServers":{{"s_claude_project":{}}}}}}}}}"#,
            stdio_json("s_claude_user", "v1"),
            serde_json::to_string(&c.display().to_string()).unwrap(),
            stdio_json("s_claude_project", "v1")
        ),
    );
    let covered = names(
        [
            "s_user",
            "s_campaign",
            "s_project",
            "s_mcpjson",
            "s_cursor_project",
            "s_cursor_user",
            "s_claude_user",
            "s_claude_project",
        ]
        .into_iter(),
    );
    let check = |label: &str, servers: &[acp::McpServer], with_client: bool| {
        let stamped = names(
            servers
                .iter()
                .filter(|s| ap::read_stamp(s).is_some())
                .map(mcp_server_name),
        );
        assert_eq!(stamped, covered, "{label}: every covered source stamps");
        for s in servers.iter().filter(|s| ap::read_stamp(s).is_none()) {
            let expected = match mcp_server_name(s) {
                "s_managed" => "managed",
                "client_own" if with_client => "client",
                other => panic!("{label}: `{other}` has no stamp"),
            };
            assert_eq!(ap::uncovered_source(s), Some(expected), "{label}");
        }
        let gated = admit_mcp_launch(servers.to_vec());
        assert!(
            gated.held.is_empty() && gated.notices.is_empty(),
            "{label}: {:?}",
            gated.notices
        );
        assert_eq!(gated.admitted.len(), servers.len(), "{label}");
    };
    let compat = CompatConfig::default();
    check("load", &load(c), false);
    let client = acp::McpServer::Stdio(acp::McpServerStdio::new(
        "client_own",
        std::path::PathBuf::from("/bin/client"),
    ));
    check(
        "session merge",
        &crate::session::managed_mcp::merge_managed_mcp_servers(vec![client], c, None, &compat),
        true,
    );
    let (global, user) = crate::util::config::load_effective_config_and_user_layer().unwrap();
    check(
        "hot reload",
        &crate::util::config::reload_mcp_servers_merged(&global, &user, c, &compat),
        false,
    );
    let discovered: Vec<_> =
        crate::session::managed_mcp::discover_mcp_definitions_ignoring_disable(
            &crate::session::managed_mcp::McpDiscoveryInputs {
                cwd: c,
                plugin_registry: None,
                compat: &compat,
            },
        )
        .into_values()
        .collect();
    check("CLI discovery", &discovered, false);

    // Plugins are marked at their one loader.
    let (plugin, _) = crate::session::managed_mcp::load_plugin_mcp_servers_from_value_labelled(
        &serde_json::json!({"mcpServers": {"p": {"command": "/bin/p"}}}),
        "plugin.json",
        "p",
        "/tmp/p",
        "/tmp/pd",
    );
    assert_eq!(ap::uncovered_source(&plugin[0]), Some("plugin"));
    assert_eq!(admit_mcp_launch(plugin).admitted.len(), 1);
    // An agent's inline server is stamped too.
    let mut def = fuigo_agent::config::AgentDefinition::parse(
        "---\nname: inl\ndescription: d\nmcpServers:\n  - inl: {command: srv-inl}\n---\nbody\n",
    )
    .unwrap();
    def.scope = fuigo_agent::config::AgentScope::User;
    def.source_path = Some(fuigo.path().join("agents/inl.md"));
    let mut merged = Vec::new();
    crate::session::agent_mcp::apply_agent_mcp_overlay(&mut merged, &def, c);
    assert!(ap::read_stamp(&merged[0]).is_some());
}

#[test]
fn rotating_a_referenced_user_config_value_starts_and_changing_the_reference_is_held() {
    // Coordinator (token rotation): config.toml MCP launch strings are expanded when the launch object is built, after
    // the digest, as for `.mcp.json`. The launched object still carries the expanded values.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    let config = home.path().join("config.toml");
    let _t = fuigo_test_support::EnvGuard::set("MC03_TOKEN", "one");
    let _h = fuigo_test_support::EnvGuard::set("MC03_HOST", "h1.invalid");
    write(
        &config,
        "[mcp_servers.s]\ncommand = \"srv-s\"\nargs = [\"--token=${MC03_TOKEN}\"]\nenv = { TOKEN = \"${MC03_TOKEN}\" }\n\
         [mcp_servers.h]\nurl = \"https://${MC03_HOST}/mcp\"\nheaders = { Authorization = \"Bearer ${MC03_TOKEN}\" }\n",
    );
    let launched = |cwd: &std::path::Path| {
        let servers = load(cwd);
        let s = servers
            .iter()
            .find(|s| mcp_server_name(s) == "s")
            .cloned()
            .unwrap();
        let h = servers
            .iter()
            .find(|s| mcp_server_name(s) == "h")
            .cloned()
            .unwrap();
        (servers, s, h)
    };
    let (servers, s, h) = launched(cwd.path());
    let acp::McpServer::Stdio(stdio) = &s else {
        panic!("{s:?}")
    };
    assert_eq!(
        stdio.args,
        ["--token=one"],
        "the process receives the expanded value"
    );
    assert_eq!(stdio.env[0].value, "one");
    let acp::McpServer::Http(http) = &h else {
        panic!("{h:?}")
    };
    assert_eq!(http.url, "https://h1.invalid/mcp");
    assert_eq!(http.headers[0].value, "Bearer one");
    assert_eq!(admit_mcp_launch(servers).admitted.len(), 2);

    // The values rotate: same definition, starts, with the new values.
    let _t2 = fuigo_test_support::EnvGuard::set("MC03_TOKEN", "two");
    let _h2 = fuigo_test_support::EnvGuard::set("MC03_HOST", "h2.invalid");
    let (servers, s, h) = launched(cwd.path());
    let acp::McpServer::Stdio(stdio) = &s else {
        panic!()
    };
    assert_eq!(stdio.env[0].value, "two");
    let acp::McpServer::Http(http) = &h else {
        panic!()
    };
    assert_eq!(http.url, "https://h2.invalid/mcp");
    let rotated = admit_mcp_launch(servers);
    assert!(
        rotated.held.is_empty() && rotated.notices.is_empty(),
        "{:?}",
        rotated.notices
    );

    // Changing the reference itself is a definition change.
    edit(
        &config,
        "TOKEN = \"${MC03_TOKEN}\"",
        "TOKEN = \"${MC03_OTHER}\"",
    );
    edit(
        &config,
        "https://${MC03_HOST}/mcp",
        "https://${MC03_HOST2}/mcp",
    );
    let changed = admit_mcp_launch(load(cwd.path()));
    assert_eq!(held_names(&changed), vec!["h".to_owned(), "s".to_owned()]);
}

fn merged(client: Vec<acp::McpServer>, cwd: &std::path::Path) -> Vec<acp::McpServer> {
    crate::session::managed_mcp::merge_managed_mcp_servers(
        client,
        cwd,
        None,
        &CompatConfig::default(),
    )
}

fn store_bytes() -> Vec<u8> {
    std::fs::read(ap::store_path()).unwrap_or_default()
}

#[test]
fn a_non_copy_client_server_displacing_an_approved_disk_server_always_starts_and_is_never_recorded()
{
    // Coordinator (Murage, an ACP host): its per-thread mounts (`browser`, ...) arrive through `session/new` with new
    // ports, env and args every run, and may share a name with the owner's own disk servers. A non-copy client server
    // wins the name (P141) and is ungated: started every time, nothing stored, nothing held.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _key = fuigo_test_support::EnvGuard::unset("FUIGO_API_KEY");
    let _flag = fuigo_test_support::EnvGuard::unset("FUIGO_FOLDER_TRUST");
    let _home = fuigo_test_support::FuigoHome::new();
    let repo = tempfile::tempdir().unwrap();
    trusted_repo_at(repo.path());
    write(
        &repo.path().join(".mcp.json"),
        &format!(
            r#"{{"mcpServers":{{"browser":{}}}}}"#,
            stdio_json("browser", "disk")
        ),
    );
    // The owner's disk `browser` is approved (first seen).
    assert_eq!(
        admit_mcp_launch(merged(Vec::new(), repo.path()))
            .admitted
            .len(),
        1
    );
    let before = store_bytes();
    for (session, port) in [("murage-1", "41001"), ("murage-2", "41002")] {
        let mount = acp::McpServer::Stdio(
            acp::McpServerStdio::new("browser", "/opt/murage/browser")
                .args(vec!["--port".to_owned(), port.to_owned()])
                .env(vec![acp::EnvVariable::new(
                    "MOUNT_TOKEN",
                    format!("tok-{port}"),
                )]),
        );
        let gated = admit_for_session(session, merged(vec![mount], repo.path()));
        assert!(
            gated.held.is_empty() && gated.notices.is_empty(),
            "{session}: {:?}",
            gated.notices
        );
        assert_eq!(gated.admitted.len(), 1);
        let started = gated.admitted[0].server();
        let acp::McpServer::Stdio(stdio) = started else {
            panic!("{started:?}")
        };
        assert_eq!(
            stdio.args[1], port,
            "{session}: the client's mount wins the name"
        );
        assert!(!gated.admitted[0].is_covered(), "{session}: ungated");
        assert_eq!(ap::uncovered_source(started), Some("client"));
        assert_eq!(store_bytes(), before, "{session}: nothing is stored");
    }
}

#[test]
fn a_client_copy_of_a_changed_disk_definition_is_held() {
    // A client forwarding the owner's disk server (the pager's copy) cannot carry a changed definition past the gate:
    // the copy is the disk definition, under its disk key.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _key = fuigo_test_support::EnvGuard::unset("FUIGO_API_KEY");
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    let config = home.path().join("config.toml");
    write(&config, &stdio_toml("notes", "v1"));
    let copy_of_disk = |cwd: &std::path::Path| {
        let mut copy = load(cwd).pop().unwrap();
        ap::strip_stamp(&mut copy);
        copy
    };
    assert_eq!(
        admit_mcp_launch(merged(vec![copy_of_disk(cwd.path())], cwd.path()))
            .admitted
            .len(),
        1
    );
    write(&config, &stdio_toml("notes", "v2"));
    let gated = admit_mcp_launch(merged(vec![copy_of_disk(cwd.path())], cwd.path()));
    assert!(gated.admitted.is_empty(), "{:?}", gated.notices);
    assert_eq!(held_names(&gated), vec!["notes".to_owned()]);
    assert_eq!(gated.held[0].key, "user\0notes", "held under the disk key");
}

#[test]
fn a_disk_only_change_with_no_client_server_is_held() {
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    let config = home.path().join("config.toml");
    write(&config, &stdio_toml("browser", "v1"));
    assert_eq!(
        admit_mcp_launch(merged(Vec::new(), cwd.path()))
            .admitted
            .len(),
        1
    );
    write(&config, &stdio_toml("browser", "v2"));
    let gated = admit_mcp_launch(merged(Vec::new(), cwd.path()));
    assert_eq!(held_names(&gated), vec!["browser".to_owned()]);
}

#[test]
fn a_client_server_named_like_a_user_config_server_still_runs_the_users_definition() {
    // P136 unchanged (coordinator): a client server never overwrites a TRUSTED disk definition of its name; the user's
    // own definition runs, gated under its own key.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    write(
        &home.path().join("config.toml"),
        &stdio_toml("browser", "v1"),
    );
    let mount = acp::McpServer::Stdio(
        acp::McpServerStdio::new("browser", "/opt/murage/browser")
            .args(vec!["--port".to_owned(), "41001".to_owned()]),
    );
    let gated = admit_mcp_launch(merged(vec![mount], cwd.path()));
    assert_eq!(gated.admitted.len(), 1, "{:?}", gated.notices);
    let acp::McpServer::Stdio(stdio) = gated.admitted[0].server() else {
        panic!()
    };
    assert_ne!(
        stdio.command.to_string_lossy(),
        "/opt/murage/browser",
        "the user's definition runs"
    );
    assert!(gated.admitted[0].is_covered());
    assert_eq!(
        ap::read_stamp(gated.admitted[0].server()).unwrap().key,
        "user\0browser"
    );
}

#[test]
fn rotating_a_value_in_a_partial_user_override_of_a_managed_server_starts() {
    // Review Astra confirm M3: the user table sets only `args` over a managed `command`; it does not parse alone, so the
    // raw definition is recovered at the merged layer. Rotating the value starts; changing the reference is held.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let home = fuigo_test_support::FuigoHome::new();
    let cwd = tempfile::tempdir().unwrap();
    write(
        &home.path().join(fuigo_config::MANAGED_CONFIG_FILENAME),
        "[mcp_servers.mm]\ncommand = \"/bin/managed\"\n",
    );
    let user = home.path().join("config.toml");
    write(
        &user,
        "[mcp_servers.mm]\nargs = [\"--token=${MC03_PTOKEN}\"]\n",
    );
    let _t = fuigo_test_support::EnvGuard::set("MC03_PTOKEN", "one");
    let first = admit_mcp_launch(load(cwd.path()));
    assert_eq!(first.admitted.len(), 1);
    assert!(
        first.admitted[0].is_covered(),
        "the user override is covered"
    );

    let _t2 = fuigo_test_support::EnvGuard::set("MC03_PTOKEN", "two");
    let servers = load(cwd.path());
    let acp::McpServer::Stdio(stdio) = &servers[0] else {
        panic!("{servers:?}")
    };
    assert_eq!(stdio.args, ["--token=two"]);
    let rotated = admit_mcp_launch(servers);
    assert!(
        rotated.held.is_empty() && rotated.notices.is_empty(),
        "{:?}",
        rotated.notices
    );

    write(
        &user,
        "[mcp_servers.mm]\nargs = [\"--token=${MC03_OTHER}\"]\n",
    );
    assert_eq!(admit_mcp_launch(load(cwd.path())).held.len(), 1);
}

#[test]
fn a_client_copy_of_a_changed_project_definition_is_held() {
    // Review Fable confirm 4: the pager forwards project-scope servers too (`.mcp.json`, `.fuigo/config.toml`). Through
    // the real forward path (the pager's load, the session's seed at ingress, the hot reload re-merging that seed), the
    // copy is recognised as the disk definition: a changed definition is held under the project key, both for a new
    // session's fresh forward and for an open session's stale seed.
    if fuigo_test_support::env::rerun_in_own_process() {
        return;
    }
    let _key = fuigo_test_support::EnvGuard::unset("FUIGO_API_KEY");
    let _flag = fuigo_test_support::EnvGuard::unset("FUIGO_FOLDER_TRUST");
    let _home = fuigo_test_support::FuigoHome::new();
    let compat = CompatConfig::default();
    for source in [".mcp.json", ".fuigo/config.toml"] {
        let repo = tempfile::tempdir().unwrap();
        trusted_repo_at(repo.path());
        let file = repo.path().join(source);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        let define = |arg: &str| {
            if source == ".mcp.json" {
                format!(
                    r#"{{"mcpServers":{{"notes":{}}}}}"#,
                    stdio_json("notes", arg)
                )
            } else {
                stdio_toml("notes", arg)
            }
        };
        // The pager's forward of what it loads, as the session's ingress keeps it.
        let forward = |cwd: &std::path::Path| {
            crate::session::managed_mcp::admit_client_mcp_servers_for_seed(
                load_mcp_servers(cwd, &compat),
                cwd,
                &compat,
                None,
            )
            .seed
        };
        let gate = |seed: crate::session::managed_mcp::ClientMcpSeed, cwd: &std::path::Path| {
            admit_mcp_launch(crate::session::managed_mcp::merge_managed_mcp_servers(
                seed, cwd, None, &compat,
            ))
        };
        write(&file, &define("v1"));
        let seed_v1 = forward(repo.path());
        let first = gate(seed_v1.clone(), repo.path());
        assert_eq!(first.admitted.len(), 1, "{source}: {:?}", first.notices);
        assert!(
            first.admitted[0].is_covered(),
            "{source}: the copy is the disk definition"
        );

        write(&file, &define("v2"));
        let disk_key = ap::read_stamp(
            &merged(Vec::new(), repo.path())
                .into_iter()
                .find(|s| mcp_server_name(s) == "notes")
                .unwrap(),
        )
        .unwrap()
        .key;
        assert!(disk_key.starts_with("project:"), "{source}: {disk_key:?}");
        for (label, seed) in [
            ("fresh forward", forward(repo.path())),
            ("stale seed", seed_v1),
        ] {
            let gated = gate(seed, repo.path());
            assert!(
                gated.admitted.is_empty(),
                "{source} {label}: {:?}",
                gated.notices
            );
            assert_eq!(
                held_names(&gated),
                vec!["notes".to_owned()],
                "{source} {label}"
            );
            assert_eq!(
                gated.held[0].key, disk_key,
                "{source} {label}: held under the project key"
            );
        }
    }
}

//! P148 item 2 (e2e C1, B18/B28): a key an ACP client passes in `authenticate` (`_meta["fuigo/apiKey"].key`) is the
//! key this process runs with, so a `${FUIGO_API_KEY}` reference in a file allowed to name it (`~/.fuigo/config.toml`)
//! resolves to it in the same process, exactly as a `fuigo/setApiKey` key does. It is still not saved (B18: no
//! persistence unless the client sends `persist: true`).
//!
//! Real path: `initialize` + `authenticate` with the key over ACP, `FUIGO_API_KEY` unset and no `auth.json`, then
//! `session/new`; the user's stdio MCP server writes the `TOKEN` its spawn received. Red before the fix: the reference
//! stayed unresolved (the config credential resolver never saw the authenticated key, and was not even installed).
#![cfg(unix)]

#[allow(dead_code)]
mod acp_harness;
#[allow(dead_code)]
mod p148_support;

use std::time::{Duration, Instant};

use acp_harness::{AutoApproveClient, new_session, run_agent_test, spawn_agent_local_with_config};
use serde_json::json;

const AUTH_KEY: &str = "p148-authenticate-key-FAKE";

#[test]
fn an_authenticated_key_resolves_trusted_key_references_in_the_same_process() {
    run_agent_test(|cwd, _mock| async move {
        // The harness exports a key; this case is "no exported key, no saved key, only the authenticated one".
        // SAFETY: the only other live threads are the mock's HTTP workers, which never read env.
        unsafe {
            std::env::remove_var("FUIGO_API_KEY");
            std::env::remove_var("FUIGO_CODE_API_KEY");
        }
        let fuigo_home = std::path::PathBuf::from(std::env::var("FUIGO_HOME").expect("FUIGO_HOME"));
        let out = fuigo_home.join("p148-token.txt");
        let script = fuigo_home.join("p148-cap.sh");
        std::fs::write(
            &script,
            format!("#!/bin/sh\nprintf '%s' \"$TOKEN\" > '{}'\nexec cat > /dev/null\n", out.display()),
        )
        .expect("capture script");
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .expect("chmod");
        std::fs::write(
            fuigo_home.join("config.toml"),
            format!(
                "[mcp_servers.p148cap]\ncommand = \"/bin/sh\"\nargs = [\"{}\"]\nenv = {{ TOKEN = \"${{FUIGO_API_KEY}}\" }}\nstartup_timeout_sec = 2\n",
                script.display()
            ),
        )
        .expect("config.toml");
        assert!(!fuigo_home.join("auth.json").exists(), "precondition: no saved key");

        let mut config = fuigo_shell::agent::config::Config::default();
        config.session.title_policy = Some(fuigo_shell::agent::config::TitlePolicy::Local);
        let (conn, auth) = p148_support::connect_with_meta(
            AutoApproveClient,
            "p148-authenticated-key",
            spawn_agent_local_with_config(config),
            None,
            json!({ "headless": true, "fuigo/apiKey": { "key": AUTH_KEY } }),
        )
        .await;
        auth.expect("authenticate with a runtime key");
        let _session = new_session(&conn, &cwd).await;

        let deadline = Instant::now() + Duration::from_secs(30);
        let token = loop {
            if let Ok(token) = std::fs::read_to_string(&out) {
                break token;
            }
            assert!(Instant::now() < deadline, "the user's MCP server was never spawned");
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        assert_eq!(
            token, AUTH_KEY,
            "a trusted ${{FUIGO_API_KEY}} reference must resolve to the key this process authenticated with"
        );
        let saved = std::fs::read_to_string(fuigo_home.join("auth.json")).unwrap_or_default();
        assert!(!saved.contains(AUTH_KEY), "B18: an authenticated key is not saved by default");
    });
}

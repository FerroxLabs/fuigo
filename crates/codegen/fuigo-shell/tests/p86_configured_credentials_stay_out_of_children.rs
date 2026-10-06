//! P86 (CB-1): a credential variable a user CONFIGURED -- a `[model.*]` or `[model_providers.*]`
//! `env_key`, or the variable behind an `env_http_headers` entry -- is denied to the agent's child
//! processes exactly like the built-in provider key names.
//!
//! ITS OWN PROCESS. The denylist is process-wide and only grows, so this is an integration test
//! binary with a single test: it plants the credentials in its OWN environment before any thread
//! exists, loads a config through the production parser, and spawns a child through the production
//! entry point the hooks and stdio MCP servers use. The names are made up for this test, so nothing
//! but the config load can put them on the denylist.

#![cfg(unix)]

use fuigo_shell::agent::config::Config;

const MODEL_KEY: &str = "P86_CORP_MODEL_KEY";
const MODEL_KEY_FALLBACK: &str = "P86_CORP_MODEL_KEY_FALLBACK";
const PROVIDER_KEY: &str = "P86_CORP_PROVIDER_KEY";
const HEADER_VAR: &str = "P86_CORP_HEADER_TOKEN";
const PROVIDER_HEADER_VAR: &str = "P86_CORP_PROVIDER_HEADER";

#[test]
fn configured_credential_variables_never_reach_a_child() {
    // SAFETY: the only test in this binary, before any thread is spawned.
    unsafe {
        for name in [
            MODEL_KEY,
            MODEL_KEY_FALLBACK,
            PROVIDER_KEY,
            HEADER_VAR,
            PROVIDER_HEADER_VAR,
        ] {
            std::env::set_var(name, "fake-p86-configured");
        }
        // Named by a header mapping, but a core variable: it must stay visible.
        std::env::set_var("USER", "p86-user");
        std::env::set_var("P86_BENIGN", "kept");
    }

    let probe = || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let mut cmd = tokio::process::Command::new("/bin/sh");
            let check = format!(
                "test \"$P86_BENIGN\" = kept && test \"$USER\" = p86-user && test -z \"${{{MODEL_KEY}+x}}${{{MODEL_KEY_FALLBACK}+x}}${{{PROVIDER_KEY}+x}}${{{HEADER_VAR}+x}}${{{PROVIDER_HEADER_VAR}+x}}\""
            );
            cmd.args(["-c", &format!("{check} && /bin/sh -c '{check}'")]);
            fuigo_tools::util::apply_shell_environment_policy(&mut cmd, None);
            cmd.status().await.unwrap().success()
        })
    };

    // Before any config names them they are ordinary variables, so the child sees them: the
    // probe is not vacuous.
    assert!(
        !probe(),
        "the child must see unconfigured variables, or this test proves nothing"
    );

    let raw: toml::Value = toml::from_str(&format!(
        r#"
[model.corp]
model = "corp-model"
base_url = "https://gateway.corp.example/v1"
env_key = ["{MODEL_KEY}", "{MODEL_KEY_FALLBACK}"]

[model.corp.env_http_headers]
X-Corp-Token = "{HEADER_VAR}"
X-Corp-User = "USER"

[model_providers.corp_gateway]
base_url = "https://gateway2.corp.example/v1"
env_key = "{PROVIDER_KEY}"

[model_providers.corp_gateway.env_http_headers]
X-Gateway-Token = "{PROVIDER_HEADER_VAR}"
"#
    ))
    .unwrap();
    Config::new_from_toml_cfg(&raw).expect("config parses");

    assert!(
        probe(),
        "a configured credential variable reached a child (or USER / P86_BENIGN went missing)"
    );
}

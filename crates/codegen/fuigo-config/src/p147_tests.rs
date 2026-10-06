//! P147 (e2e lane C1, release notes B28/S16): `${FUIGO_API_KEY:-default}` in a trusted config reads the saved key, and
//! the allowlist names exactly the files Fuigo reads. Red first.

use crate::credential_env::read_first_party_key_references;
use crate::expand_env_vars_in_string;
use crate::key_naming::{RefusedKeyReference, source_may_name_saved_key_at};
use std::path::Path;

const KEY: &str = "p147-key-FAKE-3e9a";

fn unexported() {
    assert!(std::env::var_os("FUIGO_API_KEY").is_none(), "these tests need FUIGO_API_KEY unexported");
}

/// A trusted `config.toml` that writes `${FUIGO_API_KEY:-dflt}`, loaded through the real loader with the key saved but
/// not exported: the loaded value keeps the reference (no key, no default baked in), and where it is used it reads the
/// saved key; with no key it reads the default; an empty key counts as none (`:-`).
#[test]
fn a_defaulted_reference_in_a_trusted_config_reads_the_saved_key() {
    unexported();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.toml");
    std::fs::write(
        &path,
        "[mcp_servers.p147]\nurl = \"https://x.invalid/mcp\"\nheaders = { X = \"Bearer ${FUIGO_API_KEY:-dflt}\" }\n",
    )
    .unwrap();
    let v = crate::loader::load_config_file_with_key_naming(&path, true).unwrap();
    let loaded = v["mcp_servers"]["p147"]["headers"]["X"].as_str().unwrap().to_owned();
    assert!(!loaded.contains(KEY));
    assert_eq!(read_first_party_key_references(&loaded, Some(KEY)), format!("Bearer {KEY}"), "loaded as {loaded:?}");
    assert_eq!(read_first_party_key_references(&loaded, None), "Bearer dflt");
    assert_eq!(read_first_party_key_references(&loaded, Some("")), "Bearer dflt");
    assert_eq!(expand_env_vars_in_string(&loaded), loaded, "a second load pass changed it");
}

/// The default is still expanded at load (as the expander always did); escapes, aliases that end in `$` and other
/// variables' defaults keep their P70a/P118 meaning.
#[test]
fn a_defaulted_reference_keeps_the_other_expansion_rules() {
    unexported();
    // SAFETY: uniquely named P147_* variables, set here and removed below; no other test reads them.
    unsafe {
        std::env::set_var("P147_D", "from-env");
        std::env::set_var("P147_DOLLAR", "$");
    }
    let cases = [
        // (written, at destination with the key, at destination without one)
        ("${FUIGO_API_KEY:-$P147_D}", KEY.to_owned(), "from-env".to_owned()),
        ("$${FUIGO_API_KEY:-d}", "${FUIGO_API_KEY:-d}".to_owned(), "${FUIGO_API_KEY:-d}".to_owned()),
        ("${P147_DOLLAR}${FUIGO_API_KEY:-d}", format!("${KEY}"), "$d".to_owned()),
        ("a ${FUIGO_API_KEY} b ${FUIGO_API_KEY:-d} c", format!("a {KEY} b {KEY} c"), "a ${FUIGO_API_KEY} b d c".to_owned()),
        ("${P147_UNSET:-x}${FUIGO_API_KEY:-y}", format!("x{KEY}"), "xy".to_owned()),
    ];
    let mut failures = Vec::new();
    for (written, with_key, without) in &cases {
        let loaded = expand_env_vars_in_string(written);
        let got = (
            read_first_party_key_references(&loaded, Some(KEY)).into_owned(),
            read_first_party_key_references(&loaded, None).into_owned(),
        );
        if (&got.0, &got.1) != (with_key, without) {
            failures.push(format!("{written}: loaded {loaded:?}, got {got:?}, want ({with_key:?}, {without:?})"));
        }
    }
    unsafe {
        std::env::remove_var("P147_D");
        std::env::remove_var("P147_DOLLAR");
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// S16 lists the files Fuigo reads: `/etc/fuigo` has no `config.toml` layer, so that file is not on the allowlist, and
/// the refusal note names the two managed files there and the hook files that are refused.
#[cfg(unix)]
#[test]
fn the_allowlist_names_only_files_fuigo_reads() {
    let user = Path::new("/h/.fuigo");
    let sys = Path::new("/etc/fuigo");
    let home = Path::new("/h");
    let may = |p: &str| source_may_name_saved_key_at(Path::new(p), Some(user), Some(sys), Some(home));
    assert!(!may("/etc/fuigo/config.toml"), "/etc/fuigo/config.toml is not read, so it is not listed");
    assert!(may("/etc/fuigo/managed_config.toml") && may("/etc/fuigo/requirements.toml"));
    assert!(may("/h/.fuigo/config.toml"));
    let note = RefusedKeyReference { file: "/x".into(), key: "k".into() }.note();
    assert!(!note.contains("same three"), "{note}");
    for needle in ["managed_config.toml and requirements.toml under /etc/fuigo", ".claude/settings.json", "hooks-paths"] {
        assert!(note.contains(needle), "note must mention {needle}: {note}");
    }
}

/// Astra r1 #4: in TOML the default is kept only where the key is resolved at use (an MCP server's `env`, `args`,
/// `headers`, a model's `api_key`); a command, URL or any other setting gets its default at load.
#[test]
fn a_defaulted_reference_is_kept_only_where_the_key_is_resolved() {
    unexported();
    let mut v: toml::Value = toml::from_str(
        r#"
        [mcp_servers.s]
        command = "${FUIGO_API_KEY:-npx}"
        url = "https://x.invalid/${FUIGO_API_KEY:-v1}/mcp"
        args = ["${FUIGO_API_KEY:-a}"]
        env = { T = "${FUIGO_API_KEY:-e}" }
        headers = { X = "${FUIGO_API_KEY:-h}" }
        [model.m]
        api_key = "${FUIGO_API_KEY:-k}"
        base_url = "https://m.invalid/${FUIGO_API_KEY:-b}"
        [ui]
        theme = "${FUIGO_API_KEY:-dark}"
        "#,
    )
    .unwrap();
    crate::expand_env_vars_in_toml(&mut v);
    let s = &v["mcp_servers"]["s"];
    assert_eq!(s["command"].as_str(), Some("npx"));
    assert_eq!(s["url"].as_str(), Some("https://x.invalid/v1/mcp"));
    assert_eq!(s["args"][0].as_str(), Some("${FUIGO_API_KEY:-a}"));
    assert_eq!(s["env"]["T"].as_str(), Some("${FUIGO_API_KEY:-e}"));
    assert_eq!(s["headers"]["X"].as_str(), Some("${FUIGO_API_KEY:-h}"));
    assert_eq!(v["model"]["m"]["api_key"].as_str(), Some("${FUIGO_API_KEY:-k}"));
    assert_eq!(v["model"]["m"]["base_url"].as_str(), Some("https://m.invalid/b"));
    assert_eq!(v["ui"]["theme"].as_str(), Some("dark"));
}

/// Astra r1 #3: a kept default is expanded once, like any default: an escaped `$$D` stays the text `$D` however many
/// load passes run, and a default from another variable is read once.
#[test]
fn a_kept_default_is_expanded_exactly_once() {
    unexported();
    // SAFETY: uniquely named P147_* variable, set here and removed below; no other test reads it.
    unsafe { std::env::set_var("P147_ONCE", "expanded") };
    let once = expand_env_vars_in_string("${FUIGO_API_KEY:-$$P147_ONCE}");
    let twice = expand_env_vars_in_string(&once);
    let thrice = expand_env_vars_in_string(&twice);
    let from_var = expand_env_vars_in_string(&expand_env_vars_in_string("${FUIGO_API_KEY:-$P147_ONCE}"));
    unsafe { std::env::remove_var("P147_ONCE") };
    assert_eq!(once, twice);
    assert_eq!(twice, thrice);
    assert_eq!(read_first_party_key_references(&thrice, None), "$P147_ONCE");
    assert_eq!(crate::apply_first_party_key_defaults(&thrice), "$P147_ONCE");
    assert_eq!(read_first_party_key_references(&from_var, None), "expanded");
    assert_eq!(read_first_party_key_references(&from_var, Some(KEY)), KEY);
}

/// Astra r2 N1: only a model's own `api_key` keeps the reference; a map entry merely named `api_key` (a query
/// parameter, an extra header) is an ordinary setting and gets its default. N2: where the default is taken
/// (`apply_first_party_key_defaults`), a `$` that an expansion put before the reference stays one `$`.
#[test]
fn only_a_models_own_api_key_keeps_the_reference_and_defaults_keep_dollar_parity() {
    unexported();
    let mut v: toml::Value = toml::from_str(
        r#"
        [model.x]
        api_key = "${FUIGO_API_KEY:-k}"
        [model.x.query_params]
        api_key = "${FUIGO_API_KEY:-q}"
        [models.extra_headers]
        api_key = "${FUIGO_API_KEY:-h}"
        [model_providers.p]
        api_key = "${FUIGO_API_KEY:-p}"
        "#,
    )
    .unwrap();
    crate::expand_env_vars_in_toml(&mut v);
    assert_eq!(v["model"]["x"]["api_key"].as_str(), Some("${FUIGO_API_KEY:-k}"));
    assert_eq!(v["model"]["x"]["query_params"]["api_key"].as_str(), Some("q"));
    assert_eq!(v["models"]["extra_headers"]["api_key"].as_str(), Some("h"));
    assert_eq!(v["model_providers"]["p"]["api_key"].as_str(), Some("${FUIGO_API_KEY:-p}"), "a provider's own key");
    // SAFETY: uniquely named P147_* variable, set here and removed below; no other test reads it.
    unsafe { std::env::set_var("P147_DOLLAR2", "$") };
    let loaded = expand_env_vars_in_string("https://x.invalid/${P147_DOLLAR2}${FUIGO_API_KEY:-v1}/mcp");
    unsafe { std::env::remove_var("P147_DOLLAR2") };
    assert_eq!(crate::apply_first_party_key_defaults(&loaded), "https://x.invalid/$v1/mcp", "loaded as {loaded:?}");
    assert_eq!(read_first_party_key_references(&loaded, None), "https://x.invalid/$v1/mcp");
}

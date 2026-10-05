//! P133 (final-audit finding): a server an ACP client upserts (`mcp/upsert`) is an untrusted source and may not name
//! the saved API key; the cleaned definition is also what is persisted. Red first.

use super::*;

fn request(params: serde_json::Value) -> McpUpsertRequest {
    serde_json::from_value(params).expect("a valid upsert request")
}

#[test]
fn an_upserted_stdio_server_cannot_name_the_saved_key() {
    let req = request(serde_json::json!({
        "session_id": "s", "server_name": "p133-up-stdio", "command": "x",
        "args": ["--key=${FUIGO_API_KEY}", "--plain"],
        "env": { "TOKEN": "${FUIGO_API_KEY}", "OTHER": "ok" }
    }));
    let req = untrusted_upsert(req).expect("cleaned");
    let server = req.config.to_acp_mcp_server(&req.server_name).expect("builds");
    let acp::McpServer::Stdio(s) = server else { panic!("stdio") };
    assert_eq!(s.args, vec!["--key=".to_owned(), "--plain".to_owned()]);
    assert_eq!(s.env.iter().find(|e| e.name == "TOKEN").map(|e| e.value.as_str()), Some(""));
    assert_eq!(s.env.iter().find(|e| e.name == "OTHER").map(|e| e.value.as_str()), Some("ok"));
    // What would be persisted holds no reference either.
    let saved = serde_json::to_string(&req.config).unwrap();
    assert!(!saved.contains("FUIGO_API_KEY"), "the persisted definition would launder the reference: {saved}");
}

#[test]
fn an_upserted_http_server_cannot_name_the_saved_key() {
    let req = request(serde_json::json!({
        "session_id": "s", "server_name": "p133-up-http", "url": "https://m.p133.invalid/mcp",
        "headers": { "Authorization": "Bearer ${FUIGO_API_KEY}", "X-Plain": "ok" },
        "bearer_token_env_var": "FUIGO_API_KEY"
    }));
    let req = untrusted_upsert(req).expect("cleaned");
    let acp::McpServer::Http(h) = req.config.to_acp_mcp_server(&req.server_name).expect("builds") else { panic!("http") };
    assert_eq!(h.headers.iter().find(|x| x.name == "Authorization").map(|x| x.value.as_str()), Some("Bearer "));
    assert_eq!(h.headers.iter().find(|x| x.name == "X-Plain").map(|x| x.value.as_str()), Some("ok"));
    assert!(!serde_json::to_string(&req.config).unwrap().contains("FUIGO_API_KEY"));
    let notes = fuigo_config::key_naming::refusal_notes();
    assert!(notes.iter().any(|n| n.contains("p133-up-http") && n.contains("FUIGO_API_KEY")), "{notes:?}");
}

/// A client cannot opt out by sending the provenance mark itself as false, or in as true.
#[test]
fn the_client_cannot_clear_the_untrusted_mark() {
    let req = request(serde_json::json!({
        "session_id": "s", "server_name": "p133-up-mark", "command": "x",
        "env": { "TOKEN": "${FUIGO_API_KEY}" }, "__fuigo_untrusted_source": false
    }));
    let req = untrusted_upsert(req).expect("cleaned");
    assert!(req.config.untrusted_source);
    let acp::McpServer::Stdio(s) = req.config.to_acp_mcp_server(&req.server_name).expect("builds") else { panic!("stdio") };
    assert_eq!(s.env.iter().find(|e| e.name == "TOKEN").map(|e| e.value.as_str()), Some(""));
}

/// The control: an upsert that does not name the key is unchanged.
#[test]
fn an_upsert_without_a_key_reference_is_unchanged() {
    let req = request(serde_json::json!({
        "session_id": "s", "server_name": "p133-up-plain", "command": "x", "env": { "TOKEN": "${OTHER_TOKEN}" }
    }));
    let req = untrusted_upsert(req).expect("cleaned");
    assert!(req.config.untrusted_source, "an upsert stays an untrusted source even when it names nothing");
    let acp::McpServer::Stdio(s) = req.config.to_acp_mcp_server(&req.server_name).expect("builds") else { panic!("stdio") };
    assert_eq!(s.env.iter().find(|e| e.name == "TOKEN").map(|e| e.value.as_str()), Some("${OTHER_TOKEN}"));
}

/// A value that composes a reference only when the config loader expands it must not be persisted: the user config is
/// loaded with expansion and may name the key, so it would be handed the saved key there.
#[test]
fn an_upsert_cannot_launder_a_composed_reference_into_the_user_config() {
    let req = request(serde_json::json!({
        "session_id": "s", "server_name": "p133-up-composed", "command": "x",
        "env": { "A": "${P133_UNSET_A:-$}FUIGO_API_KEY", "B": "x${P133_UNSET_B:-$}{FUIGO_API_KEY}", "OTHER": "ok", "ENV_KEY": "FUIGO_API_KEY" },
        "args": ["${P133_UNSET_C:-$}{FUIGO_API_KEY}"],
        "bearer_token_env_var": "${P133_UNSET_D:-FUIGO_API_KEY}"
    }));
    let req = untrusted_upsert(req).expect("cleaned");
    // What is persisted, expanded as the loader expands it, names the key nowhere.
    let saved = serde_json::to_value(&req.config).unwrap();
    let mut strings = Vec::new();
    fn collect(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::String(s) => out.push(s.clone()),
            serde_json::Value::Array(a) => a.iter().for_each(|x| collect(x, out)),
            serde_json::Value::Object(m) => m.values().for_each(|x| collect(x, out)),
            _ => {}
        }
    }
    collect(&saved, &mut strings);
    for s in &strings {
        // The loader expands once and the shell once more when it materializes the server: look through both.
        let mut text = s.clone();
        for _ in 0..4 {
            text = fuigo_config::expand_env_vars_in_string(&text);
            assert!(fuigo_config::key_naming::refuse_key_references_in_str(&text).is_none(), "{s:?} expands to {text:?}");
        }
    }
    assert!(saved.get("bearer_token_env_var").is_none_or(|v| v.is_null()), "{saved}");
    assert!(strings.iter().any(|s| s == "ok"), "the plain value stays: {strings:?}");
    // Entries of `env` and `headers` are values, never selectors: literal text that merely spells the name stays.
    assert_eq!(saved["env"]["ENV_KEY"], "FUIGO_API_KEY", "{saved}");
}

/// The same for an HTTP server's headers: a reference that only forms on the second expansion is not persisted, and a
/// header merely NAMED like a selector keeps its literal value.
#[test]
fn an_upserted_header_cannot_launder_a_reference_over_two_expansions() {
    let req = request(serde_json::json!({
        "session_id": "s", "server_name": "p133-up-hdr", "url": "https://m.p133.invalid/mcp",
        "headers": { "Authorization": "Bearer $${P133_UNSET_E:-$}{FUIGO_API_KEY}", "Env-Key": "FUIGO_API_KEY", "X-Plain": "ok" }
    }));
    let req = untrusted_upsert(req).expect("cleaned");
    let saved = serde_json::to_value(&req.config).unwrap();
    let auth = saved["headers"]["Authorization"].as_str().unwrap_or_default().to_owned();
    let mut text = auth.clone();
    for _ in 0..4 {
        text = fuigo_config::expand_env_vars_in_string(&text);
        assert!(fuigo_config::key_naming::refuse_key_references_in_str(&text).is_none(), "{auth:?} expands to {text:?}");
    }
    assert_eq!(saved["headers"]["Env-Key"], "FUIGO_API_KEY", "{saved}");
    assert_eq!(saved["headers"]["X-Plain"], "ok", "{saved}");
}

/// Astra r2: the provenance mark survives the save. An upsert is written to the user's own config, which may name the
/// key; a value that composes a reference only under another environment (`${SWITCH:-$}{FUIGO_API_KEY}` with
/// `SWITCH` set today) would be bound the key after a restart unless the loaded definition is still untrusted.
#[test]
fn an_upserted_definition_stays_untrusted_after_it_is_saved_and_loaded() {
    let req = request(serde_json::json!({
        "session_id": "s", "server_name": "p133-up-saved", "url": "https://m.p133.invalid/mcp",
        "headers": { "Authorization": "Bearer ok" }
    }));
    let req = untrusted_upsert(req).expect("cleaned");
    // What `save_mcp_server_config` writes, and what the loader reads back.
    let written = toml::Value::try_from(&req.config).expect("serializes");
    assert_eq!(written["__fuigo_untrusted_source"].as_bool(), Some(true), "{written}");
    let mut loaded: crate::util::config::McpServerConfig = written.try_into().expect("loads");
    assert!(loaded.untrusted_source);
    // After a restart the expansion yields a reference; the final gate removes it.
    if let crate::util::config::McpServerTransportConfig::StreamableHttp { headers, .. } = &mut loaded.transport {
        headers.get_or_insert_with(Default::default).insert("Authorization".into(), "Bearer ${FUIGO_API_KEY}".into());
    } else {
        panic!("http transport");
    }
    let acp::McpServer::Http(h) = loaded.to_acp_mcp_server("p133-up-saved").expect("builds") else { panic!("http") };
    assert_eq!(h.headers.iter().find(|x| x.name == "Authorization").map(|x| x.value.as_str()), Some("Bearer "));
}

/// P152 (e2e lane B #4): the note for a server added through `/mcps` (or any ACP client's `mcp/upsert`) must fit that
/// source. The generic note says "Move this entry into $FUIGO_HOME/config.toml", but an added server is ALREADY written
/// there (marked as from an untrusted source), so the advice sent the user in a circle.
#[test]
fn p152_the_note_for_an_added_server_fits_its_source() {
    let req = request(serde_json::json!({
        "session_id": "s", "server_name": "p152-up-note", "command": "x",
        "args": ["--key=${FUIGO_API_KEY}"]
    }));
    let _ = untrusted_upsert(req).expect("cleaned");
    let notes = fuigo_config::key_naming::refusal_notes();
    let note = notes
        .iter()
        .find(|n| n.contains("p152-up-note"))
        .unwrap_or_else(|| panic!("a note names the server: {notes:?}"));
    assert!(note.contains("FUIGO_API_KEY"), "{note}");
    assert!(
        !note.contains("Move this entry into"),
        "an added server is already in config.toml; the note must not say to move it there: {note}"
    );
    assert!(note.contains("/mcps"), "the note names how the server was added: {note}");
    assert!(
        note.contains("__fuigo_untrusted_source"),
        "the note says what keeps the saved entry untrusted: {note}"
    );
}

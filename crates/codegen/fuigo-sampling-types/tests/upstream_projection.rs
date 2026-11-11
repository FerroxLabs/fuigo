use fuigo_sampling_types::error::UpstreamError;
use serde_json::json;
const ECHO: &str = "xk3-9f2a7c1e0b4d6a8f3e5c7b9d1f0a2c4e6b8d";
#[test]
fn p1_unknown_state_is_other() {
    let u = UpstreamError {
        state: Some(ECHO.into()),
        ..Default::default()
    };
    let wire = serde_json::to_value(&u).unwrap();
    assert_eq!(wire["state"], "other");
    let persisted = serde_json::to_string(&u).unwrap();
    assert!(!persisted.contains(ECHO));
    let restored: UpstreamError = serde_json::from_str(&persisted).unwrap();
    assert_eq!(restored.state.as_deref(), Some("other"));
}
#[test]
fn p1_unknown_type_and_codes_are_other() {
    let u = UpstreamError {
        http_status: Some(401),
        error_type: Some(ECHO.into()),
        code: Some(ECHO.into()),
        codes: vec![ECHO.into()],
        ..Default::default()
    };
    let wire = serde_json::to_value(&u).unwrap();
    assert_eq!(
        wire,
        json!({"http_status":401,"type":"other","code":"other","codes":["other"]})
    );
    let read: UpstreamError = serde_json::from_value(json!({"state":ECHO,"type":ECHO})).unwrap();
    assert_eq!(read.state.as_deref(), Some("other"));
    assert_eq!(read.error_type.as_deref(), Some("other"));
}
#[test]
fn p1_known_vocabulary_is_preserved_and_absence_stays_absent() {
    for (code, _) in fuigo_sampling_types::refusal::FINAL_ORDER {
        let u = UpstreamError {
            state: Some((*code).into()),
            ..Default::default()
        };
        assert_eq!(serde_json::to_value(u).unwrap()["state"], *code);
    }
    for typ in fuigo_sampling_types::upstream_vocab::PROVIDER_TYPES
        .iter()
        .chain(fuigo_sampling_types::upstream_vocab::LITELLM_EXCEPTIONS)
    {
        let wire = json!({"type":typ});
        let body = json!({"error":{"type":typ,"message":"refusal"}});
        let parsed = UpstreamError::default().with_body(401, &serde_json::to_vec(&body).unwrap());
        assert_eq!(serde_json::to_value(parsed).unwrap()["type"], *typ);
        let u: UpstreamError = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(u).unwrap(), wire);
    }
    assert_eq!(
        serde_json::to_value(UpstreamError::default()).unwrap(),
        json!({})
    );
}

#[test]
fn p1_unknown_present_strings_outside_slug_grammar_are_other() {
    for field in ["state", "type"] {
        for value in ["", "Unexpected Secret", "A".repeat(256).as_str()] {
            let mut body = json!({"error":{"message":"refusal"}});
            body["error"][field] = json!(value);
            let parsed = UpstreamError::default().with_body(401, &serde_json::to_vec(&body).unwrap());
            assert_eq!(serde_json::to_value(parsed).unwrap()[field], "other");
        }
    }
}

#[test]
fn binding_python_none_marker_is_absent() {
    let body = br#"{"error":{"type":"None","message":"refusal"}}"#;
    let parsed = UpstreamError::default().with_body(402, body);
    assert!(serde_json::to_value(parsed).unwrap().get("type").is_none());
}

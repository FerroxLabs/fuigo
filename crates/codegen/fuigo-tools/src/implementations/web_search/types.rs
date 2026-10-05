use indexmap::IndexMap;

/// Configuration for the web search tool.
///
/// Use `Disabled` when no API key is available or web search should be turned off.
/// Use `Enabled { … }` to provide credentials and endpoint configuration.
// The `Enabled` variant is inherently large (credentials, headers, domain filters) while
// `Disabled` is empty, but this config is built once per session and never stored in bulk
// collections, so boxing would add indirection for no real benefit.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum WebSearchConfig {
    #[default]
    Disabled,
    Enabled {
        api_key: String,
        base_url: String,
        model: String,
        #[serde(default, skip_serializing_if = "IndexMap::is_empty")]
        extra_headers: IndexMap<String, String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        alpha_test_key: Option<String>,
        /// Authoritative domain allowlist from `[toolset.web_search] allowed_domains`.
        /// When set, it governs the client-side web_search tool and the model's
        /// own per-call `allowed_domains` is ignored (see `resolve_filters`), so a
        /// configured policy cannot be bypassed. Mutually exclusive with
        /// `excluded_domains`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        allowed_domains: Option<Vec<String>>,
        /// Authoritative domain blocklist from `[toolset.web_search] excluded_domains`. Like
        /// `allowed_domains` it governs outright: the model cannot un-block a domain by naming it
        /// in its own per-call `allowed_domains`, which is what makes this a real block. Mutually
        /// exclusive with `allowed_domains`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        excluded_domains: Option<Vec<String>>,
    },
}

/// Hand-written `Debug` (P70): credential values print as `<redacted>` (headers and query parameters by name only), so a `{:?}` of this type in a log, panic or error cannot disclose them.
/// The destructures are exhaustive, so a new field fails to compile here until its Debug output is decided.
impl std::fmt::Debug for WebSearchConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => f.write_str("Disabled"),
            Self::Enabled { api_key: _, base_url, model, extra_headers, alpha_test_key, allowed_domains, excluded_domains } => f
                .debug_struct("Enabled")
                .field("api_key", &"<redacted>")
                .field("base_url", &fuigo_auth::redact_url(base_url))
                .field("model", model)
                .field("extra_headers", &extra_headers.iter().map(|(k, _)| (k, "<redacted>")).collect::<Vec<_>>())
                .field("alpha_test_key", &alpha_test_key.as_ref().map(|_| "<redacted>"))
                .field("allowed_domains", allowed_domains)
                .field("excluded_domains", excluded_domains)
                .finish(),
        }
    }
}

impl WebSearchConfig {
    /// Returns `true` when the config is the `Enabled` variant.
    pub fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled { .. })
    }

    /// Return a copy safe for returning to clients.
    ///
    /// The `api_key` is replaced with `"***REDACTED***"` and the optional
    /// extra access key field is stripped.
    pub fn redacted(&self) -> Self {
        match self {
            Self::Disabled => Self::Disabled,
            Self::Enabled {
                base_url,
                model,
                extra_headers,
                allowed_domains,
                excluded_domains,
                ..
            } => Self::Enabled {
                api_key: "***REDACTED***".to_string(),
                base_url: base_url.clone(),
                model: model.clone(),
                extra_headers: extra_headers.clone(),
                alpha_test_key: None,
                allowed_domains: allowed_domains.clone(),
                excluded_domains: excluded_domains.clone(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_default_is_disabled() {
        let config = WebSearchConfig::default();
        assert!(!config.is_enabled());
    }

    #[test]
    fn test_config_redacted() {
        let mut headers = IndexMap::new();
        headers.insert("X-Custom".to_string(), "value".to_string());
        let config = WebSearchConfig::Enabled {
            api_key: "secret-key-12345".to_string(),
            base_url: "https://api.x.ai/v1".to_string(),
            model: "test-web-search-model".to_string(),
            extra_headers: headers,
            alpha_test_key: Some("alpha-secret".to_string()),
            allowed_domains: Some(vec!["docs.x.ai".to_string()]),
            excluded_domains: None,
        };
        let redacted = config.redacted();
        match redacted {
            WebSearchConfig::Enabled {
                api_key,
                base_url,
                model,
                extra_headers,
                alpha_test_key,
                allowed_domains,
                excluded_domains,
            } => {
                assert_eq!(api_key, "***REDACTED***");
                assert_eq!(base_url, "https://api.x.ai/v1");
                assert_eq!(model, "test-web-search-model");
                assert_eq!(extra_headers.get("X-Custom").unwrap(), "value");
                assert!(alpha_test_key.is_none());
                // Domain filters survive redaction (not secrets).
                assert_eq!(allowed_domains, Some(vec!["docs.x.ai".to_string()]));
                assert!(excluded_domains.is_none());
            }
            _ => panic!("Expected Enabled variant"),
        }
    }

    #[test]
    fn test_config_serde_roundtrip() {
        let config = WebSearchConfig::Enabled {
            api_key: "key".to_string(),
            base_url: "https://api.x.ai/v1".to_string(),
            model: "test-web-search-model".to_string(),
            extra_headers: IndexMap::new(),
            alpha_test_key: None,
            allowed_domains: None,
            excluded_domains: None,
        };
        let json = serde_json::to_string(&config).unwrap();
        let parsed: WebSearchConfig = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_enabled());
    }

    #[test]
    fn test_config_deserialize_from_set_options_payload() {
        let json = r#"{
            "status": "enabled",
            "api_key": "fuigo-abc123",
            "base_url": "https://api.x.ai/v1",
            "model": "test-web-search-model"
        }"#;
        let config: WebSearchConfig = serde_json::from_str(json).unwrap();
        assert!(config.is_enabled());
    }
}

#[cfg(test)]
mod p70_redacted_debug {
    use super::*;

    /// `{x:?}` and `{x:#?}` hold `<redacted>` (control) and no fragment of any secret.
    fn assert_redacted(debug: &dyn std::fmt::Debug, secrets: &[&str]) {
        for out in [format!("{debug:?}"), format!("{debug:#?}")] {
            assert!(out.contains("<redacted>"), "control: the secret field is printed as redacted: {out}");
            for secret in secrets {
                let chars: Vec<char> = secret.chars().collect();
                for w in chars.windows(6) {
                    let frag: String = w.iter().collect();
                    assert!(!out.contains(&frag), "Debug output holds {frag:?} of a secret: {out}");
                }
            }
        }
    }

    /// P70 (Astra r1): the tool configs that carry the session key.
    #[test]
    fn tool_configs_debug_redact_keys_and_header_values() {
        let headers: IndexMap<String, String> =
            [("authorization".to_owned(), "Bearer p70th-FAKE-2c3d4e5f".to_owned())].into_iter().collect();
        let web = WebSearchConfig::Enabled {
            api_key: "p70ws-FAKE-6a7b8c9d".into(),
            base_url: "https://p70.invalid/v1?key=p70wu-FAKE-4b5c6d7e".into(),
            model: "m".into(),
            extra_headers: headers.clone(),
            alpha_test_key: Some("p70wa-FAKE-0e1f2a3b".into()),
            allowed_domains: None,
            excluded_domains: None,
        };
        assert_redacted(
            &web,
            &["p70ws-FAKE-6a7b8c9d", "p70th-FAKE-2c3d4e5f", "p70wa-FAKE-0e1f2a3b", "p70wu-FAKE-4b5c6d7e"],
        );
        let image = crate::implementations::fuigo_build::image_gen::ImageGenConfig::Enabled {
            api_key: "p70ig-FAKE-4c5d6e7f".into(),
            base_url: "https://p70.invalid".into(),
            extra_headers: headers.clone(),
            image_gen_enabled: true,
            image_edit_enabled: true,
            model_override: None,
            edit_model_override: None,
            tier_restricted: false,
        };
        assert_redacted(&image, &["p70ig-FAKE-4c5d6e7f", "p70th-FAKE-2c3d4e5f"]);
        let video = crate::implementations::fuigo_build::video_gen::VideoGenConfig::Enabled {
            api_key: "p70vg-FAKE-8a9b0c1d".into(),
            base_url: "https://p70.invalid".into(),
            extra_headers: headers,
            zdr_video_output_s3: None,
            tier_restricted: false,
            zdr_restricted: false,
        };
        assert_redacted(&video, &["p70vg-FAKE-8a9b0c1d", "p70th-FAKE-2c3d4e5f"]);
    }
}

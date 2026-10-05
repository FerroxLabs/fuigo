//! Reads the model list from an OpenAI-compatible `/v1/models`.
use crate::agent::config::EndpointsConfig;
use crate::agent::models::ModelFetchAuth;
use crate::auth::FuigoAuth;
use crate::auth::backend::{ActiveAuthBackend, AuthBackend};
use crate::remote::client::{BackendError, FetchModelsResult, parse_remote_model_value};
use crate::remote::model_source::ModelSource;
use serde::Deserialize;
#[derive(Debug, Deserialize)]
struct ModelsResponse {
    data: Vec<serde_json::Value>,
}
/// Reads `/v1/models` from whichever host the endpoint config resolved to.
pub(crate) struct OaiModelSource {
    endpoint: ListModelsEndpoint,
    inference_base_url: String,
}
impl OaiModelSource {
    pub(crate) fn new(endpoints: &EndpointsConfig, fetch_auth: ModelFetchAuth) -> Self {
        Self {
            endpoint: ListModelsEndpoint::from_endpoints(endpoints, fetch_auth),
            inference_base_url: endpoints.resolve_inference_base_url(),
        }
    }
}
impl ModelSource for OaiModelSource {
    fn cache_origin(&self) -> String {
        self.endpoint.url.clone()
    }
    fn fetch(&self, auth: Option<&FuigoAuth>) -> Result<FetchModelsResult, BackendError> {
        let client = crate::http::shared_startup_blocking_client();
        tracing::info!("Fetching models from {}", self.endpoint.url);
        let mut request = client.get(&self.endpoint.url);
        match self.endpoint.auth {
            EndpointAuth::ApiKey => {
                // P42: the session-token fallback is a session delivery, so it asks the one predicate.
                let api_key = crate::agent::auth_method::read_fuigo_api_key_env()
                    .or_else(|_| {
                        auth.filter(|a| {
                            !crate::auth::session_delivery::is_session_credential(a)
                                || crate::auth::session_delivery::session_may_reach(&self.endpoint.url)
                        })
                        .map(|a| a.key.clone())
                        .ok_or(std::env::VarError::NotPresent)
                    })
                    .map_err(|_| {
                        BackendError::Auth(
                            "No API key for custom models endpoint. Set FUIGO_API_KEY.".into(),
                        )
                    })?;
                // P70b: a failed fetch logs the response body; record the bearer so a log sink can scrub an echo.
                fuigo_telemetry::sent_credentials::record(&api_key);
                request = request.header("Authorization", format!("Bearer {}", api_key));
            }
            EndpointAuth::Session => {
                let auth = auth
                    .filter(|_| ActiveAuthBackend::default().is_fuigo_authority())
                    // P42: one session-delivery predicate for the catalogue URL too.
                    .filter(|a| {
                        !crate::auth::session_delivery::is_session_credential(a)
                            || crate::auth::session_delivery::session_may_reach(&self.endpoint.url)
                    })
                    .ok_or_else(|| {
                        BackendError::Auth("No auth credentials for cli-chat-proxy".into())
                    })?;
                request = apply_session_headers(request, auth, &self.endpoint.url);
            }
        }
        let response = fuigo_extra_ca::dispatch::send_blocking(request)?;
        if !response.status().is_success() {
            let status = response.status().as_u16();
            let body = response.text().unwrap_or_default();
            tracing::warn!("Failed to fetch models: {} - {}", status, body);
            return Err(BackendError::RequestFailed { status, body });
        }
        let etag = response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let models_response: ModelsResponse = response.json()?;
        tracing::info!(
            "Fetched {} models from {}",
            models_response.data.len(),
            self.endpoint.url
        );
        let mut models = Vec::with_capacity(models_response.data.len());
        for (idx, value) in models_response.data.into_iter().enumerate() {
            match parse_remote_model_value(&value, &self.inference_base_url) {
                Some(model) => models.push(model),
                None => {
                    tracing::warn!(
                        "Skipping model at index {}: missing required field ('model' or 'context_window') or invalid types",
                        idx
                    )
                }
            }
        }
        Ok(FetchModelsResult { models, etag })
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndpointAuth {
    ApiKey,
    Session,
}
struct ListModelsEndpoint {
    url: String,
    auth: EndpointAuth,
}
impl ListModelsEndpoint {
    fn from_endpoints(endpoints: &EndpointsConfig, fetch_auth: ModelFetchAuth) -> Self {
        if endpoints.has_custom_endpoint() {
            Self {
                url: endpoints.resolve_models_list_url(),
                auth: EndpointAuth::ApiKey,
            }
        } else if fetch_auth == ModelFetchAuth::ApiKey {
            Self {
                url: format!("{}/models", endpoints.fuigo_api_base_url),
                auth: EndpointAuth::ApiKey,
            }
        } else {
            Self {
                url: endpoints.resolve_models_list_url(),
                auth: EndpointAuth::Session,
            }
        }
    }
}
/// The session-auth headers on a models fetch. P43: the account id, e-mail and client version
/// go only to a FluxRouter-operated models endpoint; a configured models host (`[endpoints]
/// models_base_url`, any gateway) gets the bearer and none of them.
fn apply_session_headers(
    request: reqwest::blocking::RequestBuilder,
    auth: &crate::auth::FuigoAuth,
    url: &str,
) -> reqwest::blocking::RequestBuilder {
    let identity = fuigo_extra_ca::fluxrouter::IdentityDisclosure::for_destination(url);
    let mut pairs = vec![
        ("x-userid", auth.user_id.as_str()),
        ("x-fuigo-client-version", fuigo_version::VERSION),
    ];
    if let Some(email) = &auth.email {
        pairs.push(("x-email", email.as_str()));
    }
    // P70b: a failed fetch logs the response body; record the bearer so a log sink can scrub an echo.
    fuigo_telemetry::sent_credentials::record(&auth.key);
    request
        .header("Authorization", format!("Bearer {}", &auth.key))
        .header("X-XAI-Token-Auth", "xai-grok-cli")
        .headers(identity.header_map(pairs))
        .header(
            crate::http::CLIENT_MODE_HEADER,
            crate::http::process_client_mode(),
        )
}
#[cfg(test)]
mod tests {
    /// P43. Both sides of the models-fetch session headers, on the request that is sent.
    #[test]
    fn session_model_fetch_carries_identity_only_to_fluxrouter() {
        let auth = crate::auth::FuigoAuth {
            key: "token".into(),
            user_id: "acct-1".into(),
            email: Some("a@b.example".into()),
            ..Default::default()
        };
        let client = fuigo_extra_ca::build_blocking_reqwest_client(|builder| builder).unwrap();
        let url = "https://api.fluxrouter.ai/v1/models";
        let request = super::apply_session_headers(client.get(url), &auth, url).build().unwrap();
        assert_eq!(request.headers()["x-userid"], "acct-1");
        assert_eq!(request.headers()["x-email"], "a@b.example");
        assert!(request.headers().contains_key("x-fuigo-client-version"));
        for url in [
            "https://gateway.example/v1/models",
            "http://127.0.0.1:8080/v1/models",
            "http://api.fluxrouter.ai/v1/models",
        ] {
            let request = super::apply_session_headers(client.get(url), &auth, url).build().unwrap();
            for name in fuigo_extra_ca::fluxrouter::IDENTITY_HEADER_NAMES {
                assert!(!request.headers().contains_key(name), "{url} got {name}");
            }
            assert_eq!(request.headers()["authorization"], "Bearer token");
        }
    }
    use super::*;
    #[test]
    #[serial_test::serial]
    fn models_fetch_endpoint_matches_auth_mode() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        use crate::agent::config::EndpointsConfig;
        use crate::agent::models::ModelFetchAuth;
        for k in [
            "FUIGO_CLI_CHAT_PROXY_BASE_URL",
            "FUIGO_API_BASE_URL",
            "FUIGO_MODELS_LIST_URL",
        ] {
            unsafe { std::env::remove_var(k) };
        }
        let cfg = EndpointsConfig::from_config_value(
            &toml::from_str(
                r#"[endpoints]
                    fuigo_api_base_url = "https://inference.acme-corp.example/fuigo/v1""#,
            )
            .unwrap(),
        );
        // Session and deployment fetches go through the AUXILIARY proxy, which
        // Fuigo leaves unset -- so these resolve to a bare path and reach
        // nothing. The invariant that still matters is the one below: neither
        // may follow `fuigo_api_base_url`, or a session/deployment credential
        // would be presented to the inference host.
        let session = ListModelsEndpoint::from_endpoints(&cfg, ModelFetchAuth::Session);
        assert_eq!(session.url, "/models");
        assert_eq!(session.auth, EndpointAuth::Session);
        let deployment = ListModelsEndpoint::from_endpoints(&cfg, ModelFetchAuth::Deployment);
        assert_eq!(deployment.url, "/models");
        assert_eq!(deployment.auth, EndpointAuth::Session);
        for u in [&session.url, &deployment.url] {
            assert!(!u.contains("acme-corp"), "must not follow inference: {u}");
        }
        let api = ListModelsEndpoint::from_endpoints(&cfg, ModelFetchAuth::ApiKey);
        assert_eq!(
            api.url,
            "https://inference.acme-corp.example/fuigo/v1/models"
        );
        assert_eq!(api.auth, EndpointAuth::ApiKey);
        let default = EndpointsConfig::from_config_value(&toml::Value::Table(Default::default()));
        assert_eq!(
            ListModelsEndpoint::from_endpoints(&default, ModelFetchAuth::ApiKey).url,
            format!(
                "{}/models",
                crate::agent::config::FUIGO_API_BASE_URL_DEFAULT
            )
        );
        let custom = EndpointsConfig::from_config_value(
            &toml::from_str(
                r#"[endpoints]
                    models_base_url = "https://models.acme.com/v1""#,
            )
            .unwrap(),
        );
        let ep = ListModelsEndpoint::from_endpoints(&custom, ModelFetchAuth::Session);
        assert_eq!(ep.url, "https://models.acme.com/v1/models");
        assert_eq!(ep.auth, EndpointAuth::ApiKey);
    }
}

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
                let api_key = crate::agent::auth_method::read_fuigo_api_key_env()
                    .or_else(|_| {
                        auth.map(|a| a.key.clone())
                            .ok_or(std::env::VarError::NotPresent)
                    })
                    .map_err(|_| {
                        BackendError::Auth(
                            "No API key for custom models endpoint. Set FUIGO_API_KEY.".into(),
                        )
                    })?;
                request = request.header("Authorization", format!("Bearer {}", api_key));
            }
            EndpointAuth::Session => {
                let auth = auth
                    .filter(|_| ActiveAuthBackend::default().is_fuigo_authority())
                    .ok_or_else(|| {
                        BackendError::Auth("No auth credentials for cli-chat-proxy".into())
                    })?;
                request = request
                    .header("Authorization", format!("Bearer {}", &auth.key))
                    .header("X-XAI-Token-Auth", "xai-grok-cli")
                    .header("x-userid", &auth.user_id)
                    .header("x-fuigo-client-version", fuigo_version::VERSION)
                    .header(
                        crate::http::CLIENT_MODE_HEADER,
                        crate::http::process_client_mode(),
                    );
                if let Some(email) = &auth.email {
                    request = request.header("x-email", email);
                }
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
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    #[serial_test::serial]
    fn models_fetch_endpoint_matches_auth_mode() {
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

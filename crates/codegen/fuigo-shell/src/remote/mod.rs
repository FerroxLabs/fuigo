//! Remote storage client for the backend.
pub mod agent;
pub(crate) mod chat_models_client;
pub mod client;
pub mod conversations_client;
mod model_source;
pub mod pull;
#[cfg(test)]
mod pull_smoke_test;
pub(crate) mod skills_client;
pub mod sync;
pub mod workspaces_client;
pub use agent::{
    SandboxClient, SandboxCreateEnvironmentRequest, SandboxEnvironment, SandboxEnvironmentResponse,
    SandboxEnvironmentVariable, SandboxEnvironmentWithMetadata, SandboxForkRequest,
    SandboxForkResponse, SandboxForkedSession, SandboxHibernateResponse,
    SandboxListEnvironmentsRequest, SandboxListEnvironmentsResponse,
    SandboxListPreinstalledPackagesResponse, SandboxLogsExitCodes, SandboxLogsResponse,
    SandboxMode, SandboxPreinstalledPackage, SandboxRestoreRequest, SandboxRestoreResponse,
    SandboxSecretInput, SandboxStartRequest, SandboxStartResponse, SandboxStatusResponse,
    SandboxTerminateRequest, SandboxUpdateEnvironmentRequest,
};
pub use chat_models_client::{
    ChatModelsClient, ChatModelsError, ListModesResponse, Mode, ModeAvailability,
};
pub(crate) use client::DEFAULT_CONTEXT_WINDOW;
pub use client::{
    BackendClient, BackendError, FetchModelsResult, FetchedBundle, SettingsFetch, fetch_bundle,
    fetch_login_device_flow, fetch_settings_blocking, fetch_subagent_bundle, share_url,
};
pub use conversations_client::{
    ConvError, ConvQuery, Conversation, ConversationsClient, ListConversationsPage,
    UpdateConversationBody,
};
pub(crate) use model_source::{ModelSource, active_model_source};
pub use pull::{PullResult, pull_session_to_local};
/// P43. The per-account identity every auxiliary-service client attaches: the Ferrox account id
/// (`x-userid`), the account e-mail (`x-email`), and the identity-class client labels
/// (`x-fuigo-client-version`, `x-fuigo-client-identifier`). Empty unless `url` is
/// FluxRouter-operated (`fuigo_extra_ca::fluxrouter::IdentityDisclosure`): these services are
/// operator-configured, and an operator-configured host is not one Fuigo chose to identify the
/// user to. The bearer still authorises the request; identity is attribution.
pub(crate) fn account_identity_headers(
    url: &str,
    user_id: &str,
    email: Option<&str>,
) -> reqwest::header::HeaderMap {
    let client_identifier = crate::http::process_client_identifier();
    let mut pairs = vec![
        ("x-userid", user_id),
        ("x-fuigo-client-version", fuigo_version::VERSION),
        ("x-fuigo-client-identifier", client_identifier.as_str()),
    ];
    if let Some(email) = email {
        pairs.push(("x-email", email));
    }
    fuigo_extra_ca::fluxrouter::IdentityDisclosure::for_destination(url).header_map(pairs)
}
pub use skills_client::{
    BundledSkill, CHAT_PRODUCT_META_KEY, CHAT_PRODUCT_META_VALUE, ListBundledSkillsResponse,
    ListUserSkillsResponse, ProductSkillsCatalog, SkillsClient, SkillsError, UserSkill,
};
pub use sync::RemoteSync;
pub use workspaces_client::{ListWorkspacesPage, Workspace, WorkspacesClient, WsError, WsQuery};
#[cfg(test)]
pub(crate) mod identity_tests {
    use std::sync::{Arc, Mutex};
    /// Every header map a loopback mock received. P43 hostile tests point a real client at it.
    pub(crate) type Seen = Arc<Mutex<Vec<axum::http::HeaderMap>>>;
    /// A loopback mock that answers every method and path with `200 body`, recording the
    /// request headers. Loopback is never FluxRouter-operated, so nothing it records may carry
    /// an identity-class header.
    pub(crate) async fn spawn_recording_mock(
        body: &'static str,
    ) -> (String, Seen, tokio::task::JoinHandle<()>) {
        let seen: Seen = Arc::default();
        let recorder = seen.clone();
        let app = axum::Router::new().fallback(move |headers: axum::http::HeaderMap| {
            let recorder = recorder.clone();
            async move {
                recorder.lock().unwrap().push(headers);
                (
                    [(axum::http::header::CONTENT_TYPE, "application/json")],
                    body,
                )
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let handle = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        (base, seen, handle)
    }
    /// Asserts `seen` recorded at least one request and none carried an identity header.
    pub(crate) fn assert_no_identity(seen: &Seen, path: &str) {
        assert_no_identity_headers(seen, path);
        let seen = seen.lock().unwrap();
        for headers in seen.iter() {
            assert!(
                headers.contains_key("authorization") || headers.contains_key("x-xai-token-auth"),
                "{path}: the request lost its credential, so it is not the authenticated path"
            );
        }
    }
    /// [`assert_no_identity`] for unauthenticated paths (OAuth device code, token exchange).
    pub(crate) fn assert_no_identity_headers(seen: &Seen, path: &str) {
        let seen = seen.lock().unwrap();
        assert!(!seen.is_empty(), "{path}: the mock received no request, so this proves nothing");
        for headers in seen.iter() {
            for name in fuigo_extra_ca::fluxrouter::IDENTITY_HEADER_NAMES {
                assert!(
                    !headers.contains_key(name),
                    "{path}: a non-FluxRouter destination received {name}"
                );
            }
        }
    }
    /// P43. Both sides of the shared auxiliary-service identity decision.
    #[test]
    fn account_identity_headers_go_only_to_fluxrouter() {
        let map = super::account_identity_headers(
            "https://api.fluxrouter.ai/v1/rest/modes",
            "acct-1",
            Some("a@b.example"),
        );
        assert_eq!(map["x-userid"], "acct-1");
        assert_eq!(map["x-email"], "a@b.example");
        assert!(map.contains_key("x-fuigo-client-version"));
        assert!(map.contains_key("x-fuigo-client-identifier"));
        for url in [
            "https://grok-web.example/rest/modes",
            "http://api.fluxrouter.ai/v1/rest/modes",
            "http://127.0.0.1:8080/rest/modes",
            "https://api.fluxrouter.ai.evil.example/rest/modes",
            "",
        ] {
            assert!(
                super::account_identity_headers(url, "acct-1", Some("a@b.example")).is_empty(),
                "{url} must get no identity"
            );
        }
    }
}

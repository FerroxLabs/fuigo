//! Two responsibilities:
//!
//! 1. **Quarantines `rmcp` 2.1 and `reqwest` 0.13.** `rmcp` 2.1 requires
//!    `reqwest >= 0.13.2`. The rest of the workspace consumes `reqwest` 0.12
//!    and a transitive ecosystem (`opentelemetry-otlp`, `oauth2`,
//!    `fuigo-mixpanel`, `fuigo-tools`, ...) also pinned to 0.12. Bumping every
//!    crate to 0.13 to satisfy `rmcp` triggers a cascade — an OpenTelemetry
//!    `HttpClient` adapter and cross-version test breakage when a crate
//!    carries both versions under a renamed `package = "reqwest"` alias.
//!    reqwest 0.13 is now a fully private impl detail of [`servers`]; no
//!    re-export. Consumers reach `rmcp` model types through this namespace
//!    (`fuigo_mcp::rmcp::*`).
//!
//! 2. **Owns MCP-specific integration code**:
//!    - [`credentials`]: on-disk `$FUIGO_HOME/mcp_credentials.json` store and the rmcp `CredentialStore` adapter.
//!    - `auth_status`: decides auth for HTTP servers from what is on disk.
//!    - [`oauth`]: browser-based OAuth flow with cross-process and in-process dedup.
//!    - [`oauth_config`]: BYO OAuth config types parsed out of `config.toml`.
//!    - [`servers`]: MCP transport layer (rmcp's `StreamableHttpClientTransport` and `TokioChildProcess`).
//!      It also owns client lifecycle, tool invocation, error classification, and managed-MCP refresh.
//!    - [`mcp_http_client`]: backoff wrapper around the HTTP client handed to rmcp's streamable-HTTP transport.
//!      It works around rmcp's zero-backoff SSE reconnect loop.

pub use rmcp;

#[doc(hidden)]
pub fn isolate_fuigo_home_for_tests() {
    static HOME: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    HOME.get_or_init(|| {
        let dir = tempfile::TempDir::new().expect("test fuigo home").keep();
        // SAFETY: OnceLock-guarded single set; the concurrent env-read race is accepted in tests.
        unsafe { std::env::set_var("FUIGO_HOME", &dir) };
        let memo = fuigo_config::fuigo_home();
        assert!(
            memo.starts_with(&dir),
            "fuigo-home memo was warmed before test isolation: {}",
            memo.display()
        );
    });
}

pub mod acp_transport;
mod auth_status;
pub mod credentials;
pub mod elicitation;
mod http_policy;
pub mod liveness;
pub mod mcp_http_client;
pub mod oauth;
pub mod oauth_config;
pub mod owned_clients;
pub mod servers;
/// Ported from upstream VERBATIM (module and its tests), so `tool_name.rs` and
/// `tool_name_tests.rs` diff byte-for-byte against upstream's copies bar the crate rename.
///
/// That deliberately carries upstream's `clippy::indexing_slicing` rewrite in
/// `parse_mcp_qualified_name` (`&tool_with_delimiter[..]` → `.get(..)?`, behaviour-identical:
/// the index is a byte boundary the `windows` scan just found). Unrelated same-sync churn
/// belongs to no item in this branch, but keeping the port whole is the better trade than
/// hand-reverting one line and losing the byte-for-byte diff. Conscious acceptance, not an
/// oversight — do not re-raise it.
mod tool_name;
pub mod wire;

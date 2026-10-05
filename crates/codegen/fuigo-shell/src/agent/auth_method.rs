use agent_client_protocol as acp;

use crate::agent::config::ModelEntry;
use crate::auth::PreferredAuthMethod;

/// Shared, live handle to the agent's current ACP auth method id.
///
/// `Arc` so a clone can cross the per-session-thread boundary at spawn.
/// The `ArcSwapOption` interior lets the agent's `authenticate` handler publish a new method without re-spawning sessions.
/// Every running session's per-turn auth gate observes the new method on its next turn.
/// `None` until the first `authenticate`.
/// Auth is process-global (one user, one `AuthManager`), so all sessions sharing one cell is correct.
pub(crate) type SharedAuthMethodId = std::sync::Arc<arc_swap::ArcSwapOption<acp::AuthMethodId>>;

/// Construct a [`SharedAuthMethodId`]. `None` is the pre-`authenticate` state.
pub(crate) fn new_shared_auth_method_id(initial: Option<acp::AuthMethodId>) -> SharedAuthMethodId {
    std::sync::Arc::new(arc_swap::ArcSwapOption::new(
        initial.map(std::sync::Arc::new),
    ))
}

/// Env var that, when set, advertises `fuigo.api_key` as a viable auth method.
///
/// Kept as a constant so test code and the production check stay in sync.
pub const FUIGO_API_KEY_ENV_VAR: &str = "FUIGO_API_KEY";

/// Legacy env var name.
/// Checked as a fallback when `FUIGO_API_KEY` is not set, so existing deployments that use the old name keep working.
pub const LEGACY_FUIGO_API_KEY_ENV_VAR: &str = "FUIGO_CODE_API_KEY";

/// `authenticate` `_meta` key under which an ACP client supplies the first-party API key at runtime (P08).
///
/// Shape: `{"key"?: string, "persist"?: boolean}`. Advertised to clients, before they authenticate, as
/// `agentCapabilities._meta["fuigo/capabilities"].authenticateApiKey.metaKey`. Additive within the `fuigo/*`
/// namespace: no new ACP method, so no Contract E.5a underscore exposure.
pub const RUNTIME_API_KEY_META: &str = "fuigo/apiKey";

/// The first-party API key an ACP client supplied in `authenticate` (`_meta["fuigo/apiKey"].key`), held in this
/// process's memory only (P08).
///
/// It is never written to the process environment, so no child process and no reader of the agent's environment
/// sees it, and it is written to `auth.json` only when the same request opted in with `persist: true`.
/// Process-global, exactly like the `FUIGO_API_KEY` it stands in for: auth is process-global (one user, one
/// `AuthManager`), and in leader mode every attached client shares it just as they share the env key.
/// Not zeroized: the sampler and each session's credentials hold ordinary `String` clones of it.
static RUNTIME_API_KEY: std::sync::RwLock<Option<String>> = std::sync::RwLock::new(None);

/// Replace (or with `None`, clear) the runtime API key, returning the one it replaced. Callers pass a trimmed,
/// non-empty key.
pub(crate) fn set_runtime_api_key(key: Option<String>) -> Option<String> {
    std::mem::replace(
        &mut *RUNTIME_API_KEY
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
        key,
    )
}

/// The first-party key saved in `auth.json` (`fuigo::api_key` scope), held in process memory (P70).
///
/// The agent used to copy it into `FUIGO_API_KEY` (at `initialize`, and in `fuigo/setApiKey`), where every reader of the
/// agent's environment and every child that inherited it could see it. It now lives here and the readers below consult
/// it exactly where they used to find it in the environment:
/// - loaded at `initialize` only when neither a runtime nor an env key is present: the environment wins over it, as the
///   old "set only if unset" copy did (Contract E.2: an injected `FUIGO_API_KEY` is used as before);
/// - set by `fuigo/setApiKey` with `shadows_env`, because the old `set_var` replaced whatever `FUIGO_API_KEY` held.
///
/// It is the user's own saved key, not one a client handed over the wire, so unlike [`RUNTIME_API_KEY`] the readers
/// that return a key to a client (`fuigo/getApiKey`, `getBearerToken`) may return it, as they did from the environment.
static STORED_API_KEY: std::sync::RwLock<Option<StoredApiKey>> = std::sync::RwLock::new(None);

#[derive(Clone)]
struct StoredApiKey {
    key: String,
    /// Read ahead of `FUIGO_API_KEY` / `FUIGO_CODE_API_KEY` (a `setApiKey` key), rather than after them.
    shadows_env: bool,
}

/// `initialize`: when API-key auth is allowed and no runtime or env key is present, hold the key saved in
/// `<fuigo_home>/auth.json` (if any) in memory, after the environment. Returns whether a key was loaded.
///
/// P70: this replaced `set_var("FUIGO_API_KEY", <saved key>)`. The key is read where the env copy used to be found
/// and never placed in the agent's environment (Contract E.2: an injected env key, checked here, still takes
/// precedence, and a later one still outranks it).
pub(crate) fn load_saved_api_key(fuigo_home: &std::path::Path, api_key_auth_disabled: bool) -> bool {
    if api_key_auth_disabled || read_fuigo_api_key_env().is_ok() {
        return false;
    }
    let Some(api_key) = crate::auth::read_api_key(fuigo_home) else {
        return false;
    };
    // A sampler `env_http_headers` entry, an MCP server's `bearer_token_env_var` / OAuth client-secret variable, or an
    // explicit `${FUIGO_API_KEY}` in a config string (MCP `env` / `args` / `url` / `headers`, model fields, a hook's
    // command / `env` / URL) naming FUIGO_API_KEY used to resolve the env copy: route them here.
    fuigo_sampler::client::install_env_header_resolver(read_named_key_env);
    fuigo_config_types::install_credential_env_resolver(read_named_key_env_for_config);
    set_stored_api_key(Some(api_key), false);
    true
}

/// `fuigo/setApiKey`, after `auth.json` was written: hold `key` in memory ahead of the env key (the `set_var` this
/// replaced overwrote `FUIGO_API_KEY`), or with `None` drop the stored key and `FUIGO_API_KEY`, as the clear always did.
pub(crate) fn apply_set_api_key(key: Option<&str>) {
    match key {
        Some(key) => {
            fuigo_sampler::client::install_env_header_resolver(read_named_key_env);
            fuigo_config_types::install_credential_env_resolver(read_named_key_env_for_config);
            set_stored_api_key(Some(key.to_owned()), true);
        }
        None => {
            set_stored_api_key(None, false);
            // SAFETY: ext_method is single-threaded per agent; this only ever removes.
            unsafe { std::env::remove_var(FUIGO_API_KEY_ENV_VAR) };
        }
    }
}

/// The value of a credential variable that a user's config names for a destination OUTSIDE inference: an MCP
/// server's `bearer_token_env_var` or OAuth client-secret variable (P70a, Astra r3, r4), and an explicit
/// `${FUIGO_API_KEY}` / `$FUIGO_API_KEY` in a config string or a hook's config (P70a follow-up, Sean 2026-10-03:
/// writing the reference is the user's consent; the value goes only where it is written, never into this process's
/// environment). `FUIGO_API_KEY` sees the env key and the stored key in the order the old env copy gave them, and,
/// only when neither exists, the key an ACP client supplied in `authenticate` (P148): the key this process runs with
/// then stands in for a saved key, in memory only unless the client asked to persist it (B18). The user's own key keeps
/// priority, so a config value expanded at load from an exported key and one resolved here never disagree, and the
/// value the refusal of untrusted sources protects (`fuigo_config::key_naming`, which reads this resolver) stays the
/// key those sources could otherwise reach. Only a source allowed to name the key resolves it (S16). Any other name,
/// the legacy one included, reads the environment.
pub(crate) fn read_named_key_env_for_config(name: &str) -> Option<String> {
    if name == FUIGO_API_KEY_ENV_VAR {
        first_party_key(false, || std::env::var(name).ok()).or_else(runtime_api_key)
    } else {
        std::env::var(name).ok()
    }
}

/// Replace (or with `None`, clear) the stored key. `shadows_env`: see [`STORED_API_KEY`].
pub(crate) fn set_stored_api_key(key: Option<String>, shadows_env: bool) {
    *STORED_API_KEY
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = key.map(|key| StoredApiKey { key, shadows_env });
}

fn stored_api_key() -> Option<StoredApiKey> {
    STORED_API_KEY
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// The first-party key in precedence order: the runtime key (when `with_runtime`), a stored key that shadows the
/// environment, `env()`, then a stored key that does not.
fn first_party_key(with_runtime: bool, env: impl FnOnce() -> Option<String>) -> Option<String> {
    if with_runtime && let Some(key) = runtime_api_key() {
        return Some(key);
    }
    let stored = stored_api_key();
    if let Some(stored) = stored.as_ref().filter(|s| s.shadows_env) {
        return Some(stored.key.clone());
    }
    env().or_else(|| stored.map(|s| s.key))
}

/// The value a model's `env_key` names, for the env-key resolver in `agent::config`. A mapping to either first-party
/// key name (`env_key = "FUIGO_API_KEY"`) sees the runtime key first, exactly as the unmapped fallback does, so a
/// client's explicit key cannot be bypassed by a config that names the env var. Any other name reads the environment.
/// `FUIGO_API_KEY` also sees the stored key (P70) where it used to find it in the environment; the legacy name never did.
pub(crate) fn read_named_key_env(name: &str) -> Option<String> {
    if name == FUIGO_API_KEY_ENV_VAR {
        first_party_key(true, || std::env::var(name).ok())
    } else if name == LEGACY_FUIGO_API_KEY_ENV_VAR {
        runtime_api_key().or_else(|| std::env::var(name).ok())
    } else {
        std::env::var(name).ok()
    }
}

/// Whether `candidate` is the runtime key a client supplied. For the readers that hand a credential back to a client
/// (`fuigo/auth/getBearerToken`): a runtime key is never echoed back.
pub(crate) fn is_runtime_api_key(candidate: &str) -> bool {
    runtime_api_key().is_some_and(|key| key == candidate.trim())
}

fn runtime_api_key() -> Option<String> {
    RUNTIME_API_KEY
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Read the first-party API key: the runtime key a client supplied over ACP, then `FUIGO_API_KEY`, then the legacy
/// `FUIGO_CODE_API_KEY`.
///
/// The runtime key is consulted first because it is the client's explicit choice for this process; an ambient env
/// key must not silently bill a different account (Contract E.3). With no runtime key this is exactly the env read it
/// always was, so the key an embedder injects into the agent's environment stays a first-class source (Contract E.2).
/// Every consumer of the env key (inference credential resolution, the tool/auxiliary static key, the advert
/// predicates) therefore treats a runtime key as an env key that is not in the environment.
/// The key saved in `auth.json` and held in memory (P70, [`STORED_API_KEY`]) is read where the environment copy of it
/// used to be found: after the environment, or ahead of it for a `setApiKey` key.
pub(crate) fn read_fuigo_api_key_env() -> Result<String, std::env::VarError> {
    first_party_key(true, read_environment_key).ok_or(std::env::VarError::NotPresent)
}

/// `FUIGO_API_KEY`, then legacy, from the process environment.
fn read_environment_key() -> Option<String> {
    std::env::var(FUIGO_API_KEY_ENV_VAR)
        .or_else(|_| std::env::var(LEGACY_FUIGO_API_KEY_ENV_VAR))
        .ok()
}

/// The environment key or the stored key, never the runtime key. For the one reader that hands the key back to a
/// client (`fuigo/getApiKey`): a key a client supplied over ACP is never echoed back (P08), while the user's saved key
/// is returned exactly as when it sat in `FUIGO_API_KEY` (P70).
pub(crate) fn read_fuigo_api_key_echoable() -> Result<String, std::env::VarError> {
    first_party_key(false, read_environment_key).ok_or(std::env::VarError::NotPresent)
}

/// A parsed `authenticate` `_meta["fuigo/apiKey"]`. No `Debug`, `Display` or `Serialize`: it holds the secret.
#[derive(Default)]
pub(crate) struct RuntimeApiKeyRequest {
    /// The key to use for this process, trimmed and non-empty. `None`: use the ambient key (env / BYOK).
    pub key: Option<String>,
    /// Write the key that ends up in use to `auth.json`. Off unless the client asks.
    pub persist: bool,
}

/// Parse `authenticate` `_meta["fuigo/apiKey"]`. Absent is the default (no runtime key, no persistence).
///
/// Errors are fixed text: they never quote the request, because the value a client got wrong may be the key itself.
/// Unknown fields are ignored so a newer client degrades to the safe defaults.
pub(crate) fn parse_runtime_api_key_meta(
    meta: Option<&acp::Meta>,
) -> Result<RuntimeApiKeyRequest, &'static str> {
    const SHAPE: &str = "`_meta[\"fuigo/apiKey\"]` must be an object {\"key\"?: non-empty string, \"persist\"?: boolean}.";
    let Some(carrier) = meta.and_then(|m| m.get(RUNTIME_API_KEY_META)) else {
        return Ok(RuntimeApiKeyRequest::default());
    };
    let Some(fields) = carrier.as_object() else {
        return Err(SHAPE);
    };
    let key = match fields.get("key") {
        None | Some(serde_json::Value::Null) => None,
        Some(serde_json::Value::String(key)) if !key.trim().is_empty() => Some(key.trim().to_owned()),
        Some(_) => return Err(SHAPE),
    };
    let persist = match fields.get("persist") {
        None | Some(serde_json::Value::Null) => false,
        Some(serde_json::Value::Bool(persist)) => *persist,
        Some(_) => return Err(SHAPE),
    };
    Ok(RuntimeApiKeyRequest { key, persist })
}

/// `data.message` of the `-32000` when `fuigo.api_key` has no key to use. Addressed to the ACP client: it names the
/// field to send, rather than telling a human to edit `config.toml`.
pub const API_KEY_REQUIRED_MESSAGE: &str = "fuigo.api_key has no API key. Send one in this request as \
     `_meta[\"fuigo/apiKey\"] = {\"key\": \"<api key>\"}` (add `\"persist\": true` to also save it to auth.json), \
     or start the agent with FUIGO_API_KEY in its environment.";

/// The `agentCapabilities._meta["fuigo/capabilities"].authenticateApiKey` advert. Names the channel; never a key.
pub(crate) fn runtime_api_key_capability() -> serde_json::Value {
    serde_json::json!({ "metaKey": RUNTIME_API_KEY_META, "persistOptIn": true })
}

/// Returns `true` if either `FUIGO_API_KEY` or `FUIGO_CODE_API_KEY` is set.
pub fn has_fuigo_api_key_env() -> bool {
    read_fuigo_api_key_env().is_ok()
}

/// Whether `fuigo.api_key` should be advertised (and pushed FIRST) when building the `auth_methods` list at `initialize()` time.
///
/// Regression: `fuigo.api_key` must stay first when only per-model credentials exist (no global `FUIGO_API_KEY`).
/// Deferring it made BYOK users hit the login screen because the pager uses `auth_methods.first()` for startup metadata.
///
/// [`build_auth_methods`] consumes this predicate and pins the ordering; its tests catch call-site and predicate regressions.
///
/// Probes `std::env` at call time and consults each `ModelEntry` for a resolvable api_key/env_key.
/// Both inputs can change between calls, so the result is not cached.
///
/// `disable_api_key_auth` (`[fuigo_com_config] disable_api_key_auth` / `FUIGO_DISABLE_API_KEY_AUTH`) is the admin kill switch.
/// When true the method is never advertised, regardless of available credentials, so `FUIGO_API_KEY` can't bypass a deployment's forced IdP login.
///
/// Presence-only for the first-party env key (treats it as usable).
/// Login paths that have run the validity probe should call [`should_advertise_fuigo_api_key_with_env_ok`] with the probe result instead.
pub(crate) fn should_advertise_fuigo_api_key<'a, I>(disable_api_key_auth: bool, models: I) -> bool
where
    I: IntoIterator<Item = &'a ModelEntry>,
{
    should_advertise_fuigo_api_key_with_env_ok(disable_api_key_auth, models, true)
}

/// Single advertise policy for `fuigo.api_key`: the kill switch, BYOK, and the first-party env key.
/// The env key is gated by `first_party_env_ok` (probe result, or `true` for presence-only); BYOK still advertises without a probe.
pub(crate) fn should_advertise_fuigo_api_key_with_env_ok<'a, I>(
    disable_api_key_auth: bool,
    models: I,
    first_party_env_ok: bool,
) -> bool
where
    I: IntoIterator<Item = &'a ModelEntry>,
{
    if disable_api_key_auth {
        return false;
    }
    let has_byok = models.into_iter().any(ModelEntry::has_own_credentials);
    has_byok || (has_fuigo_api_key_env() && first_party_env_ok)
}

/// Inputs to [`build_auth_methods`].
///
/// The caller (`MvpAgent::initialize()`) computes the booleans.
/// They depend on async side effects (token refresh) and shared mutable state (`AuthManager`).
/// The list-construction logic itself is pure so it can be unit-tested without any of that machinery.
pub struct AuthMethodsBuildInputs<'a> {
    /// True if `fuigo.api_key` should be advertised AT ALL.
    /// Login/initialize callers compute it via [`should_advertise_fuigo_api_key_with_env_ok`] after the validity probe.
    /// Presence-only paths may use [`should_advertise_fuigo_api_key`].
    /// When `preferred_method` is `Oidc`, this is ignored (API key is never advertised under that pin).
    pub has_external_api_key: bool,
    /// True if a cached session token is available (either present at startup or recovered via silent refresh).
    pub has_cached_token: bool,
    /// True if enterprise OIDC is configured.
    /// Mutually exclusive with the default `grok.com` method.
    pub has_enterprise_oidc: bool,
    /// Required when `has_enterprise_oidc` is true; ignored otherwise.
    pub enterprise_oidc_issuer: Option<&'a str>,
    /// Optional display label for the login method (`grok.com` or `oidc`).
    pub login_label: Option<&'a str>,
    /// True if `fuigo_com_config.auth_provider_command` is configured (sets `meta.external_provider = true` on the `grok.com` method).
    pub has_auth_provider_command: bool,
    /// Config pin (`[auth] preferred_method`).
    /// `None` keeps multi-method fallthrough; `Some` is fail-closed (only that method family).
    pub preferred_method: Option<PreferredAuthMethod>,
}

/// Output of [`build_auth_methods`].
pub struct BuiltAuthMethods {
    /// Auth methods in advertised order.
    /// ORDER IS THE CONTRACT: the pager's `startup_auth_metadata()` reads `methods.first()` to decide whether interactive login is needed.
    pub methods: Vec<acp::AuthMethod>,
    /// The default `auth_method_id` to install on the agent.
    /// When unpinned, `cached_token` wins over `fuigo.api_key` when both are present.
    /// When pinned, only the preferred method may appear; `None` means unavailable (fail auth, no cross-method fallthrough).
    pub default_auth_method_id: Option<acp::AuthMethodId>,
}

/// Build the `auth_methods` list and default `auth_method_id` from pre-computed inputs.
///
/// REGRESSION GUARD: when unpinned and `has_external_api_key` is true, the **first** entry MUST be `fuigo.api_key`.
/// A prior change deferred it to the END for per-model credentials, which made the pager send per-model-key users to the login screen.
/// Unit tests lock this.
///
/// Unpinned ordering (when each method is enabled):
/// 1. `fuigo.api_key`     (if `has_external_api_key`)
/// 2. `cached_token`    (if `has_cached_token`)
/// 3. exactly one of:
///    - `oidc`          (if `has_enterprise_oidc`)
///    - `grok.com`      (otherwise)
///
/// Unpinned `default_auth_method_id`:
/// - `cached_token` if `has_cached_token`
/// - `fuigo.api_key`  else if `has_external_api_key`
/// - `None`         otherwise
///
/// Pinned (`preferred_method`):
/// - `ApiKey`: only `fuigo.api_key` if available; else an empty list and `None` (fail).
/// - `Oidc`: `cached_token` (if any) then interactive login; never `fuigo.api_key`.
///   Default is `cached_token` when present, else `None` (interactive).
pub fn build_auth_methods(inputs: AuthMethodsBuildInputs<'_>) -> BuiltAuthMethods {
    let AuthMethodsBuildInputs {
        has_external_api_key,
        has_cached_token,
        has_enterprise_oidc,
        enterprise_oidc_issuer,
        login_label,
        has_auth_provider_command,
        preferred_method,
    } = inputs;

    match preferred_method {
        Some(PreferredAuthMethod::ApiKey) => build_pinned_api_key(has_external_api_key),
        Some(PreferredAuthMethod::Oidc) => build_pinned_oidc(
            has_cached_token,
            has_enterprise_oidc,
            enterprise_oidc_issuer,
            login_label,
            has_auth_provider_command,
        ),
        None => build_unpinned(
            has_external_api_key,
            has_cached_token,
            has_enterprise_oidc,
            enterprise_oidc_issuer,
            login_label,
            has_auth_provider_command,
        ),
    }
}

fn build_pinned_api_key(has_external_api_key: bool) -> BuiltAuthMethods {
    if !has_external_api_key {
        fuigo_telemetry::unified_log::warn(
            "auth: preferred_method=api_key but no API key credentials available",
            None,
            None,
        );
        return BuiltAuthMethods {
            methods: Vec::new(),
            default_auth_method_id: None,
        };
    }
    BuiltAuthMethods {
        methods: vec![fuigo_api_key_auth_method()],
        default_auth_method_id: Some(acp::AuthMethodId::new(FUIGO_API_KEY_METHOD_ID)),
    }
}

fn build_pinned_oidc(
    has_cached_token: bool,
    has_enterprise_oidc: bool,
    enterprise_oidc_issuer: Option<&str>,
    login_label: Option<&str>,
    has_auth_provider_command: bool,
) -> BuiltAuthMethods {
    let mut methods: Vec<acp::AuthMethod> = Vec::new();
    let mut default_auth_method_id: Option<acp::AuthMethodId> = None;

    if has_cached_token {
        methods.push(cached_token_auth_method());
        default_auth_method_id = Some(acp::AuthMethodId::new(CACHED_TOKEN_AUTH_METHOD_ID));
    }

    push_interactive_login(
        &mut methods,
        has_enterprise_oidc,
        enterprise_oidc_issuer,
        login_label,
        has_auth_provider_command,
    );

    BuiltAuthMethods {
        methods,
        default_auth_method_id,
    }
}

fn build_unpinned(
    has_external_api_key: bool,
    has_cached_token: bool,
    has_enterprise_oidc: bool,
    enterprise_oidc_issuer: Option<&str>,
    login_label: Option<&str>,
    has_auth_provider_command: bool,
) -> BuiltAuthMethods {
    let mut methods: Vec<acp::AuthMethod> = Vec::new();
    let mut default_auth_method_id: Option<acp::AuthMethodId> = None;

    if has_external_api_key {
        methods.push(fuigo_api_key_auth_method());
        default_auth_method_id = Some(acp::AuthMethodId::new(FUIGO_API_KEY_METHOD_ID));
    }

    if has_cached_token {
        methods.push(cached_token_auth_method());
        // cached_token wins over fuigo.api_key for default_auth_method_id so is_session_based_auth() returns true and OIDC refresh stays alive
        let overrode_api_key = default_auth_method_id.is_some();
        default_auth_method_id = Some(acp::AuthMethodId::new(CACHED_TOKEN_AUTH_METHOD_ID));
        if overrode_api_key {
            fuigo_telemetry::unified_log::info(
                "auth method priority: cached_token overrides fuigo.api_key for default_auth_method_id",
                None,
                Some(serde_json::json!({
                    "has_external_api_key": has_external_api_key,
                    "has_cached_token": has_cached_token,
                })),
            );
        }
    }

    push_interactive_login(
        &mut methods,
        has_enterprise_oidc,
        enterprise_oidc_issuer,
        login_label,
        has_auth_provider_command,
    );

    BuiltAuthMethods {
        methods,
        default_auth_method_id,
    }
}

fn push_interactive_login(
    methods: &mut Vec<acp::AuthMethod>,
    has_enterprise_oidc: bool,
    enterprise_oidc_issuer: Option<&str>,
    login_label: Option<&str>,
    has_auth_provider_command: bool,
) {
    if has_enterprise_oidc {
        // Caller invariant: `enterprise_oidc_issuer` MUST be `Some(...)` when `has_enterprise_oidc` is true
        // Production callers derive both from the same `cfg.fuigo_com_config.oidc` Option
        // The inconsistent `(true, None)` combination is a programmer error, so panic loudly
        let issuer = enterprise_oidc_issuer
            .expect("enterprise_oidc_issuer is required when has_enterprise_oidc is true");
        methods.push(oidc_auth_method(issuer, login_label));
    } else if has_auth_provider_command {
        // Only when the operator actually configured an auth provider command.
        //
        // Upstream pushed this UNCONDITIONALLY, and that is the whole reason a
        // fresh Fuigo tried to log in to xAI at boot. With no key on disk the
        // advertised list was `[grok.com]`, the pager read `methods.first()`,
        // saw a method needing interactive login, and dispatched Action::Login
        // before drawing a frame -- straight at a host Fuigo does not use and
        // an account the user does not have.
        //
        // With no provider configured the list is now empty, which the pager
        // already handles: it shows the welcome menu, where "Enter API key" is
        // the first row.
        methods.push(fuigo_com_auth_method(
            login_label,
            has_auth_provider_command,
        ));
    }
}

/// ACP session auth method. Use `is_session_based_method` for classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMethodKind {
    FuigoApiKey,
    CachedToken,
    FuigoCom,
    Oidc,
    Unknown,
}

impl AuthMethodKind {
    pub fn from_id(id: &acp::AuthMethodId) -> Self {
        match id.0.as_ref() {
            FUIGO_API_KEY_METHOD_ID => Self::FuigoApiKey,
            CACHED_TOKEN_AUTH_METHOD_ID => Self::CachedToken,
            FUIGO_COM_METHOD_ID => Self::FuigoCom,
            OIDC_METHOD_ID => Self::Oidc,
            _ => Self::Unknown,
        }
    }

    /// API key auth: no auth.json, no refresh, no user interaction.
    pub fn is_api_key(self) -> bool {
        matches!(self, Self::FuigoApiKey)
    }

    /// `true` for session-based methods (cached_token, grok.com, oidc).
    pub(crate) fn is_session_based(self) -> bool {
        matches!(self, Self::CachedToken | Self::FuigoCom | Self::Oidc)
    }

    /// Requires user interaction (browser, OIDC redirect, or external auth command).
    pub fn needs_interactive_login(self) -> bool {
        matches!(self, Self::FuigoCom | Self::Oidc)
    }
}

/// `true` for session-based ACP methods (cached_token, grok.com, oidc).
pub(crate) fn is_session_based_method(method_id: &acp::AuthMethodId) -> bool {
    AuthMethodKind::from_id(method_id).is_session_based()
}

/// Per-model BYOK status: whether the selected model carries its own `[model.*]` `api_key`/`env_key`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ModelByok {
    /// Model has its own per-model key (not refreshable).
    Byok,
    /// Model has no per-model key (session auth governs).
    NotByok,
    /// Config couldn't be loaded/parsed; BYOK status indeterminate.
    Unknown,
}

impl ModelByok {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Byok => "byok",
            Self::NotByok => "not_byok",
            Self::Unknown => "unknown",
        }
    }
}

/// Whether this session and model combination uses a refreshable session token.
///
/// Gates on stable inputs, not `Credentials.auth_type`.
/// That field collapses to `ApiKey` when the session-token cache is momentarily empty and `FUIGO_API_KEY` is set.
/// The collapse demoted live OIDC sessions to non-refreshable api-key mode and 401'd every prompt until restart.
/// `model_byok` still excludes genuine per-model BYOK, whose keys are not refreshable.
///
/// `Unknown` means BYOK status is indeterminate: config currently unparseable, no sampling config yet, or the per-model memo was cleared.
/// It must **not** demote a live session to non-refreshable api-key mode.
/// That demotion re-sends the stale buffered token on every turn and 401s with `bad-credentials` until restart.
///
/// P42: `model_byok` decides only whether the session token is *wanted*. Where it may go is decided by
/// `destination_may_receive_session`, which every caller must compute with
/// [`crate::auth::session_delivery::session_may_reach`] (`AuthBackend::may_receive_session`), the one
/// session-delivery predicate. `NotByok` used to deliver regardless of the destination, and a model absent
/// from the local catalogue is classed `NotByok`, so a catalogue entry naming `http://localhost:9999` received
/// the session token. A definite `Byok` never uses the session token.
pub(crate) fn session_token_auth_gate(
    is_session_based_method: bool,
    model_byok: ModelByok,
    destination_may_receive_session: bool,
) -> bool {
    is_session_based_method
        && match model_byok {
            ModelByok::NotByok | ModelByok::Unknown => destination_may_receive_session,
            ModelByok::Byok => false,
        }
}

pub const AUTH_ERROR_SESSION_EXPIRED: &str =
    "Session expired. Run `fuigo login` to re-authenticate.";

pub const AUTH_ERROR_API_KEY: &str = "Authentication failed. Run `fuigo login`, set FUIGO_API_KEY, or add api_key to ~/.fuigo/config.toml.";

/// Next ACP method id when `cached_token` cannot proceed (missing / expired / legacy WebLogin), or `None` when fallthrough is forbidden.
///
/// Unpinned: prefer non-interactive `fuigo.api_key` when advertiseable, else interactive `grok.com`.
///
/// Pinned `oidc`: **no** fallthrough to api_key; return `None` so the caller fails auth.
/// Pinned `api_key` should not reach this path (cached_token is not advertised).
pub(crate) fn method_id_after_cached_token_unavailable(
    has_external_api_key: bool,
    preferred_method: Option<PreferredAuthMethod>,
) -> Option<&'static str> {
    match preferred_method {
        Some(PreferredAuthMethod::Oidc) | Some(PreferredAuthMethod::ApiKey) => None,
        None => Some(if has_external_api_key {
            FUIGO_API_KEY_METHOD_ID
        } else {
            FUIGO_COM_METHOD_ID
        }),
    }
}

/// Error when `preferred_method=api_key` but no key/BYOK credentials exist.
pub const PREFERRED_API_KEY_UNAVAILABLE: &str = "preferred_method=api_key but no API key is configured (set FUIGO_API_KEY or model api_key/env_key in config.toml).";

/// Error when `preferred_method=oidc` but the session path cannot proceed.
pub const PREFERRED_OIDC_UNAVAILABLE: &str =
    "preferred_method=oidc but no session is available. Run `fuigo login` to authenticate.";

pub const FUIGO_API_KEY_METHOD_ID: &str = "fuigo.api_key";
pub(crate) fn fuigo_api_key_auth_method() -> acp::AuthMethod {
    acp::AuthMethod::Agent(
        acp::AuthMethodAgent::new(
            acp::AuthMethodId::new(FUIGO_API_KEY_METHOD_ID),
            "fuigo.api_key".to_string(),
        )
        .description(Some(format!(
            "{FUIGO_API_KEY_ENV_VAR} or api_key/env_key in config.toml"
        ))),
    )
}

pub const CACHED_TOKEN_AUTH_METHOD_ID: &str = "cached_token";
pub(crate) fn cached_token_auth_method() -> acp::AuthMethod {
    acp::AuthMethod::Agent(
        acp::AuthMethodAgent::new(
            acp::AuthMethodId::new(CACHED_TOKEN_AUTH_METHOD_ID),
            "cached_token".to_string(),
        )
        .description(Some("Cached token from ~/.fuigo/auth.json".to_string())),
    )
}

pub const FUIGO_COM_METHOD_ID: &str = "grok.com";

/// Ferrox Labs OAuth2/OIDC auth. Method id `"grok.com"` kept for ACP wire compatibility.
pub(crate) fn fuigo_com_auth_method(
    label: Option<&str>,
    has_auth_provider_command: bool,
) -> acp::AuthMethod {
    let name = label.unwrap_or("Fuigo");
    let meta = if has_auth_provider_command {
        let mut m = acp::Meta::new();
        m.insert("external_provider".to_owned(), serde_json::json!(true));
        Some(m)
    } else {
        None
    };
    acp::AuthMethod::Agent(
        acp::AuthMethodAgent::new(
            acp::AuthMethodId::new(FUIGO_COM_METHOD_ID),
            name.to_string(),
        )
        .description(Some(format!("Sign in with {name}")))
        .meta(meta),
    )
}

pub const OIDC_METHOD_ID: &str = "oidc";
pub(crate) fn oidc_auth_method(issuer: &str, label: Option<&str>) -> acp::AuthMethod {
    let name = label
        .map(|l| l.to_string())
        .unwrap_or_else(|| format!("Single sign-on ({})", issuer));
    acp::AuthMethod::Agent(
        acp::AuthMethodAgent::new(acp::AuthMethodId::new(OIDC_METHOD_ID), name.clone())
            .description(Some(format!("Sign in with {name}"))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::config::{Config, resolve_model_list};
    use agent_client_protocol as acp;
    use serial_test::serial;

    const FAKE_RUNTIME_KEY: &str = "p08-unit-runtime-key-FAKE";

    fn meta(value: serde_json::Value) -> acp::Meta {
        serde_json::json!({ RUNTIME_API_KEY_META: value })
            .as_object()
            .cloned()
            .expect("object")
    }

    /// P08: the `_meta["fuigo/apiKey"]` carrier. Absent means no runtime key and no persistence; a key is trimmed.
    #[test]
    fn runtime_api_key_meta_parses_the_documented_shape() {
        let none = parse_runtime_api_key_meta(None).expect("absent meta is fine");
        assert!(none.key.is_none() && !none.persist);
        let unrelated = serde_json::json!({ "headless": true }).as_object().cloned().unwrap();
        let unrelated = parse_runtime_api_key_meta(Some(&unrelated)).expect("other meta keys are ignored");
        assert!(unrelated.key.is_none() && !unrelated.persist);
        let full = parse_runtime_api_key_meta(Some(&meta(
            serde_json::json!({ "key": format!("  {FAKE_RUNTIME_KEY}\n"), "persist": true, "future": 1 }),
        )))
        .expect("full carrier");
        assert_eq!(full.key.as_deref(), Some(FAKE_RUNTIME_KEY));
        assert!(full.persist);
        let persist_only = parse_runtime_api_key_meta(Some(&meta(serde_json::json!({ "persist": true }))))
            .expect("persist without a key adopts the ambient key");
        assert!(persist_only.key.is_none() && persist_only.persist);
    }

    /// P08: every malformed carrier is refused with fixed text that never quotes the request, so a key put in the
    /// wrong place or beside a wrong-typed field cannot come back in the error.
    #[test]
    fn runtime_api_key_meta_errors_never_quote_the_request() {
        for bad in [
            serde_json::json!(FAKE_RUNTIME_KEY),
            serde_json::json!([FAKE_RUNTIME_KEY]),
            serde_json::json!({ "key": "   " }),
            serde_json::json!({ "key": 42, "persist": FAKE_RUNTIME_KEY }),
            serde_json::json!({ "key": FAKE_RUNTIME_KEY, "persist": "yes" }),
            serde_json::json!({ "key": [FAKE_RUNTIME_KEY] }),
        ] {
            let Err(reason) = parse_runtime_api_key_meta(Some(&meta(bad.clone()))) else {
                panic!("accepted a malformed carrier: {bad}");
            };
            assert!(!reason.contains(FAKE_RUNTIME_KEY), "the error quoted the key: {reason}");
            assert!(reason.contains(RUNTIME_API_KEY_META), "the error names the field: {reason}");
        }
    }

    /// P08: a runtime key is read before the environment (the client's explicit choice wins), the environment is
    /// read exactly as before once it is cleared (Contract E.2), and the runtime key never enters the environment.
    #[test]
    #[serial]
    fn runtime_api_key_precedes_the_env_key_without_entering_the_environment() {
        let _env = fuigo_test_support::EnvGuard::set(FUIGO_API_KEY_ENV_VAR, "p08-unit-env-key-FAKE");
        let _legacy = fuigo_test_support::EnvGuard::unset(LEGACY_FUIGO_API_KEY_ENV_VAR);
        let _other = fuigo_test_support::EnvGuard::set("P08_UNIT_PROVIDER_KEY", "p08-unit-provider-FAKE");
        let replaced = set_runtime_api_key(Some(FAKE_RUNTIME_KEY.to_owned()));
        let read = read_fuigo_api_key_env();
        let from_environment = read_fuigo_api_key_echoable();
        let in_environment = std::env::vars().any(|(_, v)| v.contains(FAKE_RUNTIME_KEY));
        // A model `env_key` naming a first-party variable sees the runtime key; any other name reads the env.
        let mapped = crate::agent::config::EnvKeys::single(FUIGO_API_KEY_ENV_VAR).resolve_value();
        let mapped_legacy = read_named_key_env(LEGACY_FUIGO_API_KEY_ENV_VAR);
        let other = crate::agent::config::EnvKeys::single("P08_UNIT_PROVIDER_KEY").resolve_value();
        let is_runtime = is_runtime_api_key(&format!(" {FAKE_RUNTIME_KEY} "));
        let cleared = set_runtime_api_key(None);
        assert!(replaced.is_none(), "precondition: no runtime key before the test");
        assert_eq!(cleared.as_deref(), Some(FAKE_RUNTIME_KEY), "clearing returns the key it replaced");
        assert_eq!(read.as_deref(), Ok(FAKE_RUNTIME_KEY));
        assert_eq!(from_environment.as_deref(), Ok("p08-unit-env-key-FAKE"));
        assert!(!in_environment, "the runtime key was placed in the process environment");
        assert_eq!(mapped.as_deref(), Some(FAKE_RUNTIME_KEY), "env_key = FUIGO_API_KEY bypassed the runtime key");
        assert_eq!(mapped_legacy.as_deref(), Some(FAKE_RUNTIME_KEY));
        assert_eq!(other.as_deref(), Some("p08-unit-provider-FAKE"));
        assert!(is_runtime);
        assert!(!is_runtime_api_key(FAKE_RUNTIME_KEY), "no runtime key once cleared");
        assert_eq!(read_fuigo_api_key_env().as_deref(), Ok("p08-unit-env-key-FAKE"));
        assert_eq!(
            crate::agent::config::EnvKeys::single(FUIGO_API_KEY_ENV_VAR).resolve_value().as_deref(),
            Some("p08-unit-env-key-FAKE")
        );
    }

    /// P70: a key loaded from `auth.json` is held in memory, never in the environment. It ranks after the env key
    /// (the old copy was made only when the env was empty), a `setApiKey` key ranks ahead of it (the old `set_var`
    /// replaced it), the runtime key ranks ahead of both, and only the runtime key is withheld from the echo reader.
    #[test]
    #[serial]
    fn stored_api_key_is_read_in_place_of_the_env_copy_and_never_enters_the_environment() {
        const STORED: &str = "p70-unit-stored-key-FAKE";
        let _env = fuigo_test_support::EnvGuard::unset(FUIGO_API_KEY_ENV_VAR);
        let _legacy = fuigo_test_support::EnvGuard::unset(LEGACY_FUIGO_API_KEY_ENV_VAR);
        assert!(set_runtime_api_key(None).is_none(), "precondition: no runtime key");
        set_stored_api_key(Some(STORED.to_owned()), false);
        let alone = (read_fuigo_api_key_env(), read_fuigo_api_key_echoable(), read_named_key_env(FUIGO_API_KEY_ENV_VAR));
        let legacy_name = read_named_key_env(LEGACY_FUIGO_API_KEY_ENV_VAR);
        let in_environment = std::env::vars().any(|(_, v)| v.contains(STORED));
        let has = has_fuigo_api_key_env();
        // An env key that appears later outranks a loaded key, exactly as an env key already present prevented the copy.
        let env_wins = {
            let _e = fuigo_test_support::EnvGuard::set(FUIGO_API_KEY_ENV_VAR, "p70-unit-env-FAKE");
            read_fuigo_api_key_env()
        };
        // A `setApiKey` key outranks the env key, as the old `set_var` overwrote it.
        set_stored_api_key(Some(STORED.to_owned()), true);
        let shadowing = {
            let _e = fuigo_test_support::EnvGuard::set(FUIGO_API_KEY_ENV_VAR, "p70-unit-env-FAKE");
            (read_fuigo_api_key_env(), read_fuigo_api_key_echoable())
        };
        let _ = set_runtime_api_key(Some(FAKE_RUNTIME_KEY.to_owned()));
        let with_runtime = (read_fuigo_api_key_env(), read_fuigo_api_key_echoable());
        let _ = set_runtime_api_key(None);
        set_stored_api_key(None, false);
        let cleared = read_fuigo_api_key_env();
        assert_eq!(alone.0.as_deref(), Ok(STORED));
        assert_eq!(alone.1.as_deref(), Ok(STORED), "getApiKey returns the saved key, as it did from the env");
        assert_eq!(alone.2.as_deref(), Some(STORED), "env_key = FUIGO_API_KEY saw the env copy");
        assert_eq!(legacy_name, None, "the legacy name never saw the copy");
        assert!(!in_environment, "the stored key was placed in the process environment");
        assert!(has);
        assert_eq!(env_wins.as_deref(), Ok("p70-unit-env-FAKE"));
        assert_eq!(shadowing.0.as_deref(), Ok(STORED));
        assert_eq!(shadowing.1.as_deref(), Ok(STORED));
        assert_eq!(with_runtime.0.as_deref(), Ok(FAKE_RUNTIME_KEY));
        assert_eq!(with_runtime.1.as_deref(), Ok(STORED), "the runtime key is never echoed");
        assert!(cleared.is_err());
    }

    /// No variable of the process environment holds `secret` (under any name).
    fn env_holds(secret: &str) -> Option<String> {
        std::env::vars().find(|(_, v)| v.contains(secret)).map(|(k, _)| k)
    }

    /// P70 (P08 proposal 4): `initialize` loads a key saved in `auth.json` into memory, never into the environment;
    /// it is then the key every env-key reader sees. An env key present at `initialize` (Contract E.2) wins and nothing
    /// is loaded; API-key auth disabled by policy loads nothing.
    #[test]
    #[serial]
    fn saved_api_key_is_loaded_into_memory_not_the_environment() {
        const SAVED: &str = "p70-unit-saved-key-FAKE";
        let home = tempfile::tempdir().expect("tempdir");
        crate::auth::store_api_key(home.path(), SAVED).expect("seed auth.json");
        let _env = fuigo_test_support::EnvGuard::unset(FUIGO_API_KEY_ENV_VAR);
        let _legacy = fuigo_test_support::EnvGuard::unset(LEGACY_FUIGO_API_KEY_ENV_VAR);
        assert!(set_runtime_api_key(None).is_none(), "precondition: no runtime key");
        set_stored_api_key(None, false);

        let disabled = load_saved_api_key(home.path(), true);
        let after_disabled = read_fuigo_api_key_env();
        let loaded = load_saved_api_key(home.path(), false);
        let leaked = env_holds(SAVED);
        let read = (read_fuigo_api_key_env(), read_named_key_env(FUIGO_API_KEY_ENV_VAR));
        set_stored_api_key(None, false);
        let with_env = {
            let _e = fuigo_test_support::EnvGuard::set(FUIGO_API_KEY_ENV_VAR, "p70-unit-injected-FAKE");
            (load_saved_api_key(home.path(), false), read_fuigo_api_key_env())
        };
        let after_env = read_fuigo_api_key_env();
        set_stored_api_key(None, false);

        assert!(!disabled && after_disabled.is_err(), "a disabled policy loads nothing");
        assert!(loaded, "the saved key is loaded");
        assert_eq!(leaked, None, "the saved key entered the process environment");
        assert_eq!(read.0.as_deref(), Ok(SAVED));
        assert_eq!(read.1.as_deref(), Some(SAVED));
        assert!(!with_env.0, "an env key present at initialize means nothing is loaded");
        assert_eq!(with_env.1.as_deref(), Ok("p70-unit-injected-FAKE"));
        assert!(after_env.is_err(), "nothing was stored behind the env key");
    }

    /// P70a (Astra r3): an HTTP MCP server configured with `bearer_token_env_var = "FUIGO_API_KEY"` gets the key the
    /// user saved, as it did when the key sat in the environment, also when a client authenticated with another key
    /// (P148: that key only stands in when the user has none). Loading the saved key installs the resolver.
    #[test]
    #[serial]
    fn mcp_bearer_env_var_naming_the_first_party_key_sees_the_saved_key_ahead_of_the_runtime_key() {
        const SAVED: &str = "p70a-unit-mcp-saved-FAKE";
        let home = tempfile::tempdir().expect("tempdir");
        crate::auth::store_api_key(home.path(), SAVED).expect("seed auth.json");
        let _env = fuigo_test_support::EnvGuard::unset(FUIGO_API_KEY_ENV_VAR);
        let _legacy = fuigo_test_support::EnvGuard::unset(LEGACY_FUIGO_API_KEY_ENV_VAR);
        assert!(set_runtime_api_key(None).is_none(), "precondition: no runtime key");
        set_stored_api_key(None, false);
        assert!(load_saved_api_key(home.path(), false), "the saved key is loaded");
        let server = fuigo_config_types::McpServerConfig {
            transport: fuigo_config_types::McpServerTransportConfig::StreamableHttp {
                url: "https://mcp.p70.invalid/mcp".into(),
                transport_type: None,
                bearer_token_env_var: Some(FUIGO_API_KEY_ENV_VAR.into()),
                headers: None,
                oauth_client_id: None,
                oauth_client_secret_env_var: None,
                oauth_scopes: None,
            },
            enabled: true,
            oauth: None,
            setup: None,
            startup_timeout_sec: None,
            tool_timeout_sec: None,
            tool_timeouts: None,
            expose_image_base64: None,
            untrusted_source: false,
        };
        let bearer = |server: &fuigo_config_types::McpServerConfig| match server.to_acp_mcp_server("p70a") {
            Some(acp::McpServer::Http(http)) => {
                http.headers.iter().find(|h| h.name == "Authorization").map(|h| h.value.clone())
            }
            other => panic!("an HTTP MCP server: {}", other.is_some()),
        };
        let saved = bearer(&server);
        let _ = set_runtime_api_key(Some(FAKE_RUNTIME_KEY.to_owned()));
        let with_runtime = bearer(&server);
        let _ = set_runtime_api_key(None);
        set_stored_api_key(None, false);
        assert_eq!(saved.as_deref(), Some(format!("Bearer {SAVED}").as_str()));
        // P148: the user's saved key keeps priority over a key a client authenticated with.
        assert_eq!(with_runtime.as_deref(), Some(format!("Bearer {SAVED}").as_str()), "the runtime key displaced the saved key");
        assert_eq!(read_named_key_env_for_config(LEGACY_FUIGO_API_KEY_ENV_VAR), None, "the legacy name never saw the copy");
    }

    /// P148: a `${FUIGO_API_KEY}` reference in a trusted config resolves to the key a client authenticated with when the
    /// user has no key of their own (none exported, none saved), and the user's key keeps priority when they have one;
    /// the legacy name never sees the authenticated key; clearing it leaves nothing.
    #[test]
    #[serial]
    fn a_trusted_reference_falls_back_to_the_authenticated_key_only_when_the_user_has_none() {
        let _env = fuigo_test_support::EnvGuard::unset(FUIGO_API_KEY_ENV_VAR);
        let _legacy = fuigo_test_support::EnvGuard::unset(LEGACY_FUIGO_API_KEY_ENV_VAR);
        set_stored_api_key(None, false);
        let _ = set_runtime_api_key(Some(FAKE_RUNTIME_KEY.to_owned()));
        let only_runtime = read_named_key_env_for_config(FUIGO_API_KEY_ENV_VAR);
        let legacy = read_named_key_env_for_config(LEGACY_FUIGO_API_KEY_ENV_VAR);
        let exported = {
            let _e = fuigo_test_support::EnvGuard::set(FUIGO_API_KEY_ENV_VAR, "p148-unit-exported-FAKE");
            read_named_key_env_for_config(FUIGO_API_KEY_ENV_VAR)
        };
        set_stored_api_key(Some("p148-unit-saved-FAKE".to_owned()), false);
        let saved = read_named_key_env_for_config(FUIGO_API_KEY_ENV_VAR);
        set_stored_api_key(None, false);
        let _ = set_runtime_api_key(None);
        let nothing = read_named_key_env_for_config(FUIGO_API_KEY_ENV_VAR);
        assert_eq!(only_runtime.as_deref(), Some(FAKE_RUNTIME_KEY), "no user key: the authenticated key stands in");
        assert_eq!(legacy, None, "the legacy name never sees the authenticated key");
        assert_eq!(exported.as_deref(), Some("p148-unit-exported-FAKE"), "an exported key keeps priority");
        assert_eq!(saved.as_deref(), Some("p148-unit-saved-FAKE"), "a saved key keeps priority");
        assert_eq!(nothing, None);
    }

    /// P70a follow-up (Sean, 2026-10-03), late binding: an explicit `${FUIGO_API_KEY}` / `$FUIGO_API_KEY` in config is
    /// left literal by config loading (the expander every config string goes through) unless the key was exported,
    /// so no record of config holds the saved key; where the value is used it resolves
    /// (`resolve_first_party_key_references`, here also through a model's `api_key`, `first_own_credential`) to the
    /// key the user saved, held in memory: a `setApiKey` key ahead of an exported one, as the old `set_var` made it;
    /// a key a client authenticated with only behind both (P148); the legacy name never did; with no key anywhere the
    /// reference is left as written. Nothing puts the key in the process environment (`std::env::vars`, and
    /// `/proc/self/environ` on Linux).
    #[test]
    #[serial]
    fn explicit_key_reference_in_config_resolves_to_the_saved_key_without_entering_the_environment() {
        const SAVED: &str = "p70a-unit-reference-saved-FAKE";
        const SET: &str = "p70a-unit-reference-set-FAKE";
        let home = tempfile::tempdir().expect("tempdir");
        crate::auth::store_api_key(home.path(), SAVED).expect("seed auth.json");
        let _env = fuigo_test_support::EnvGuard::unset(FUIGO_API_KEY_ENV_VAR);
        let _legacy = fuigo_test_support::EnvGuard::unset(LEGACY_FUIGO_API_KEY_ENV_VAR);
        assert!(set_runtime_api_key(None).is_none(), "precondition: no runtime key");
        set_stored_api_key(None, false);
        let load = crate::config::expand_env_vars_in_string;
        let resolve = |s: &str| fuigo_config::resolve_first_party_key_references(s).into_owned();
        let template = "Bearer ${FUIGO_API_KEY} $FUIGO_API_KEY ${FUIGO_CODE_API_KEY}";

        assert!(load_saved_api_key(home.path(), false), "the saved key is loaded");
        let loaded = load(template);
        let resolved = resolve(&loaded);
        let model_api_key = crate::agent::config::first_own_credential(Some(&loaded), None);
        let _ = set_runtime_api_key(Some(FAKE_RUNTIME_KEY.to_owned()));
        let with_runtime = resolve("${FUIGO_API_KEY}");
        let _ = set_runtime_api_key(None);
        let exported_at_load = {
            let _e = fuigo_test_support::EnvGuard::set(FUIGO_API_KEY_ENV_VAR, "p70a-unit-exported-FAKE");
            load("${FUIGO_API_KEY}")
        };
        let leaked = env_holds(SAVED);
        #[cfg(target_os = "linux")]
        let in_proc_environ = String::from_utf8_lossy(&std::fs::read("/proc/self/environ").expect("environ"))
            .contains(SAVED);
        #[cfg(not(target_os = "linux"))]
        let in_proc_environ = false;
        apply_set_api_key(Some(SET));
        let set_over_exported = {
            let _e = fuigo_test_support::EnvGuard::set(FUIGO_API_KEY_ENV_VAR, "p70a-unit-exported-FAKE");
            resolve("${FUIGO_API_KEY}")
        };
        let set_leaked = env_holds(SET);
        set_stored_api_key(None, false);
        let nothing = resolve("${FUIGO_API_KEY}");

        assert_eq!(loaded, template, "config loading resolved an unexported reference");
        assert_eq!(resolved, format!("Bearer {SAVED} {SAVED} ${{FUIGO_CODE_API_KEY}}"));
        assert_eq!(model_api_key.as_deref(), Some(resolved.as_str()), "a model api_key naming the key");
        assert_eq!(with_runtime, SAVED, "P148: the saved key keeps priority over an authenticated one");
        assert_eq!(exported_at_load, "p70a-unit-exported-FAKE", "an exported key expands at load, as before");
        assert_eq!(set_over_exported, SET, "a setApiKey key wins over an exported one, as the old set_var did");
        assert_eq!(leaked, None, "the saved key entered the process environment");
        assert_eq!(set_leaked, None, "the setApiKey key entered the process environment");
        assert!(!in_proc_environ, "the saved key is in /proc/self/environ");
        assert_eq!(nothing, "${FUIGO_API_KEY}", "with no key the reference is left as written");
    }

    /// P70: `fuigo/setApiKey` holds the key in memory ahead of an env key (the old `set_var` overwrote it) and never
    /// in the environment; a clear drops it and `FUIGO_API_KEY`, as the clear always did.
    #[test]
    #[serial]
    fn set_api_key_holds_the_key_in_memory_ahead_of_the_env_key() {
        const SET: &str = "p70-unit-setapikey-FAKE";
        let _env = fuigo_test_support::EnvGuard::set(FUIGO_API_KEY_ENV_VAR, "p70-unit-injected-FAKE");
        let _legacy = fuigo_test_support::EnvGuard::unset(LEGACY_FUIGO_API_KEY_ENV_VAR);
        assert!(set_runtime_api_key(None).is_none(), "precondition: no runtime key");
        apply_set_api_key(Some(SET));
        let leaked = env_holds(SET);
        let read = (read_fuigo_api_key_env(), read_fuigo_api_key_echoable());
        apply_set_api_key(None);
        let cleared = (read_fuigo_api_key_env(), std::env::var(FUIGO_API_KEY_ENV_VAR));
        assert_eq!(leaked, None, "the setApiKey key entered the process environment");
        assert_eq!(read.0.as_deref(), Ok(SET), "the set key outranks the env key, as the old set_var did");
        assert_eq!(read.1.as_deref(), Ok(SET));
        assert!(cleared.0.is_err() && cleared.1.is_err(), "a clear drops the stored key and FUIGO_API_KEY");
    }

    /// The capability advert names the channel and carries no credential.
    #[test]
    fn runtime_api_key_capability_names_the_meta_key() {
        assert_eq!(
            runtime_api_key_capability(),
            serde_json::json!({ "metaKey": "fuigo/apiKey", "persistOptIn": true })
        );
    }

    /// When API-key credentials are advertiseable, fall through from a dead `cached_token` to non-interactive `fuigo.api_key` (not browser OAuth).
    /// Covers the both-advertised case: `has_cached_token` was true at initialize but the session later went missing/expired/legacy.
    /// Advertise order still puts `fuigo.api_key` first while `default_auth_method_id` prefers session.
    /// After the session fails, this helper must still pick `fuigo.api_key`.
    #[test]
    fn after_cached_token_unavailable_prefers_api_key_when_advertiseable() {
        assert_eq!(
            method_id_after_cached_token_unavailable(true, None),
            Some(FUIGO_API_KEY_METHOD_ID),
        );
    }

    /// With no advertiseable API-key credentials, fall to interactive `grok.com`.
    #[test]
    fn after_cached_token_unavailable_falls_to_fuigo_com_without_api_key() {
        assert_eq!(
            method_id_after_cached_token_unavailable(false, None),
            Some(FUIGO_COM_METHOD_ID),
        );
    }

    /// Pinned methods never fall through between api_key and oidc.
    #[test]
    fn after_cached_token_unavailable_fails_closed_when_pinned() {
        assert_eq!(
            method_id_after_cached_token_unavailable(true, Some(PreferredAuthMethod::Oidc)),
            None,
        );
        assert_eq!(
            method_id_after_cached_token_unavailable(true, Some(PreferredAuthMethod::ApiKey)),
            None,
        );
    }

    /// Classifier matrix for all auth method variants.
    #[test]
    fn auth_method_kind_classifier_matrix() {
        let session_methods = [
            CACHED_TOKEN_AUTH_METHOD_ID,
            FUIGO_COM_METHOD_ID,
            OIDC_METHOD_ID,
        ];
        for method_id in session_methods {
            let id = acp::AuthMethodId::new(method_id);
            let kind = AuthMethodKind::from_id(&id);
            assert!(
                kind.is_session_based(),
                "{method_id}: kind must be session-based"
            );
            assert!(
                is_session_based_method(&id),
                "{method_id}: wrapper must agree"
            );
        }
        let api_id = acp::AuthMethodId::new(FUIGO_API_KEY_METHOD_ID);
        let api_kind = AuthMethodKind::from_id(&api_id);
        assert!(!api_kind.is_session_based());
        assert!(api_kind.is_api_key());
        assert!(!is_session_based_method(&api_id));
        assert!(!is_session_based_method(&acp::AuthMethodId::new(
            "unknown-method"
        )));
    }

    use fuigo_test_support::EnvGuard;

    // ── Helpers ─────────────────────────────────────────────────────────

    /// Default inputs to `build_auth_methods` representing a session-only user with no API key anywhere.
    /// Tests override only the fields they care about.
    fn default_inputs() -> AuthMethodsBuildInputs<'static> {
        AuthMethodsBuildInputs {
            has_external_api_key: false,
            has_cached_token: false,
            has_enterprise_oidc: false,
            enterprise_oidc_issuer: None,
            login_label: None,
            has_auth_provider_command: false,
            preferred_method: None,
        }
    }

    /// `default_inputs` with an interactive auth provider configured.
    ///
    /// Fuigo only advertises the interactive login method when an operator has
    /// actually configured one -- upstream pushed it unconditionally, which is
    /// what made a fresh install try to log in to xAI before its first frame.
    /// Tests about method ORDERING and suppression still need a login method to
    /// exist, so they start from this instead.
    fn inputs_with_login_provider() -> AuthMethodsBuildInputs<'static> {
        AuthMethodsBuildInputs {
            has_auth_provider_command: true,
            ..default_inputs()
        }
    }

    fn method_ids(built: &BuiltAuthMethods) -> Vec<&str> {
        built.methods.iter().map(|m| m.id().0.as_ref()).collect()
    }

    fn default_id(built: &BuiltAuthMethods) -> Option<&str> {
        built
            .default_auth_method_id
            .as_ref()
            .map(|id| id.0.as_ref())
    }

    fn first_kind(methods: &[acp::AuthMethod]) -> Option<AuthMethodKind> {
        methods.first().map(|m| AuthMethodKind::from_id(m.id()))
    }

    // build_auth_methods regression: pin production call-site ordering.
    // Reordering so `fuigo.api_key` is after login methods must fail the tests below.

    /// BYOK with only per-model `env_key` must list `fuigo.api_key` first.
    #[test]
    fn enterprise_byok_first_method_is_fuigo_api_key() {
        let inputs = AuthMethodsBuildInputs {
            has_external_api_key: true, // enterprise user with resolved per-model env_key
            has_cached_token: false,
            ..default_inputs()
        };
        let built = build_auth_methods(inputs);

        assert_eq!(
            first_kind(&built.methods),
            Some(AuthMethodKind::FuigoApiKey),
            "BYOK enterprise-style: auth_methods.first() MUST be fuigo.api_key \
             (deferred-to-last ordering sends users to the login screen)",
        );
        assert_eq!(
            built
                .default_auth_method_id
                .as_ref()
                .map(|id| id.0.as_ref()),
            Some(FUIGO_API_KEY_METHOD_ID),
        );
        // Cross-check with the pager-side predicate: the first method must not require interactive login
        // That is the exact condition the pager's `startup_auth_metadata()` uses
        assert!(
            !AuthMethodKind::from_id(built.methods[0].id()).needs_interactive_login(),
            "first method MUST NOT need interactive login when fuigo.api_key is available",
        );
    }

    /// BYOK plus a cached session token: fuigo.api_key stays first in the methods list, skipping the login screen.
    /// `default_auth_method_id` is still `cached_token`, which keeps OIDC refresh alive.
    #[test]
    fn byok_with_cached_token_keeps_fuigo_api_key_first() {
        let inputs = AuthMethodsBuildInputs {
            has_external_api_key: true,
            has_cached_token: true,
            ..default_inputs()
        };
        let built = build_auth_methods(inputs);

        assert_eq!(
            first_kind(&built.methods),
            Some(AuthMethodKind::FuigoApiKey),
            "fuigo.api_key MUST precede cached_token in advertised order",
        );
        // Sanity: cached_token still appears, just second.
        assert!(
            built
                .methods
                .iter()
                .any(|m| AuthMethodKind::from_id(m.id()) == AuthMethodKind::CachedToken),
            "cached_token must still be advertised when present",
        );
        // cached_token wins for default_auth_method_id (keeps OIDC refresh alive).
        assert_eq!(
            built
                .default_auth_method_id
                .as_ref()
                .map(|id| id.0.as_ref()),
            Some(CACHED_TOKEN_AUTH_METHOD_ID),
        );
    }

    /// Session-only user (no API key anywhere): cached_token first, then `grok.com`.
    /// `auth_methods.first()` does NOT need interactive login, so this user also skips the login screen at startup.
    #[test]
    fn session_only_user_first_method_is_cached_token() {
        let inputs = AuthMethodsBuildInputs {
            has_external_api_key: false,
            has_cached_token: true,
            ..default_inputs()
        };
        let built = build_auth_methods(inputs);

        assert_eq!(
            first_kind(&built.methods),
            Some(AuthMethodKind::CachedToken)
        );
        assert_eq!(
            built
                .default_auth_method_id
                .as_ref()
                .map(|id| id.0.as_ref()),
            Some(CACHED_TOKEN_AUTH_METHOD_ID),
        );
    }

    /// Brand-new user, nothing configured: NOTHING is advertised.
    ///
    /// Upstream advertised `grok.com` here, and the pager reads
    /// `methods.first()` to decide whether to start an interactive login -- so
    /// this one line is what made a fresh install dial xAI at boot. An empty
    /// list is the state the pager renders as the welcome menu, with
    /// "Enter API key" first.
    #[test]
    fn fresh_user_advertises_nothing_and_gets_the_api_key_menu() {
        let built = build_auth_methods(default_inputs());

        assert!(built.methods.is_empty());
        assert!(built.default_auth_method_id.is_none());
    }

    /// ...but an operator who configured an auth provider still gets the login
    /// method, leading, exactly as before.
    #[test]
    fn configured_auth_provider_still_advertises_interactive_login() {
        let built = build_auth_methods(inputs_with_login_provider());

        assert_eq!(first_kind(&built.methods), Some(AuthMethodKind::FuigoCom));
        assert!(built.default_auth_method_id.is_none());
        assert_eq!(built.methods.len(), 1);
    }

    /// Enterprise OIDC replaces `grok.com` (mutually exclusive).
    /// fuigo.api_key, when present, still leads.
    #[test]
    fn enterprise_oidc_replaces_fuigo_com_but_fuigo_api_key_still_first() {
        let inputs = AuthMethodsBuildInputs {
            has_external_api_key: true,
            has_cached_token: false,
            has_enterprise_oidc: true,
            enterprise_oidc_issuer: Some("https://sso.example.com"),
            ..default_inputs()
        };
        let built = build_auth_methods(inputs);

        assert_eq!(
            first_kind(&built.methods),
            Some(AuthMethodKind::FuigoApiKey)
        );
        assert!(
            built
                .methods
                .iter()
                .any(|m| AuthMethodKind::from_id(m.id()) == AuthMethodKind::Oidc),
            "oidc must be advertised when has_enterprise_oidc",
        );
        assert!(
            !built
                .methods
                .iter()
                .any(|m| AuthMethodKind::from_id(m.id()) == AuthMethodKind::FuigoCom),
            "grok.com and oidc are mutually exclusive",
        );
    }

    /// `has_auth_provider_command` reaches the `grok.com` method as `meta.external_provider = true`.
    /// Pinned here so the pager's `AuthStartMode::Command` path keeps working.
    #[test]
    fn auth_provider_command_sets_external_provider_meta() {
        let inputs = AuthMethodsBuildInputs {
            has_auth_provider_command: true,
            login_label: Some("Acme Corp"),
            ..default_inputs()
        };
        let built = build_auth_methods(inputs);

        let fuigo = built
            .methods
            .iter()
            .find(|m| AuthMethodKind::from_id(m.id()) == AuthMethodKind::FuigoCom)
            .expect("grok.com must be advertised");
        assert_eq!(fuigo.name(), "Acme Corp");
        let meta = fuigo.meta().expect("meta should be set");
        assert_eq!(
            meta.get("external_provider").and_then(|v| v.as_bool()),
            Some(true),
        );
    }

    // ── End-to-end: enterprise TOML to resolved models to build_auth_methods ─

    /// END-TO-END REGRESSION TEST: parses the literal enterprise-style
    /// `~/.fuigo/config.toml` skeleton from the bug report, walks it through
    /// the same predicate (`should_advertise_fuigo_api_key`) and the same
    /// list-builder (`build_auth_methods`) that `MvpAgent::initialize()` uses
    /// in production, and asserts that `auth_methods.first()` is `fuigo.api_key`
    /// (which causes the pager to skip the login screen).
    ///
    /// This is the test that *would have caught* that regression.
    /// If the bug returns (fuigo.api_key pushed LAST when only per-model credentials exist), `first_kind` stops being `FuigoApiKey` and this test fails.
    #[test]
    #[serial]
    fn enterprise_byok_config_does_not_require_login() {
        const TEST_ENV_VAR: &str = "TEST_ENTERPRISE_REGRESSION_AUTH_TOKEN";

        // Make sure no global key is masking the per-model path we're trying to exercise
        // Held until end-of-scope so we restore on panic too
        let _global = EnvGuard::unset(FUIGO_API_KEY_ENV_VAR);

        let dm = crate::models::default_model();
        let toml: toml::Value = toml::from_str(&format!(
            r#"
            [model."{dm}"]
            model = "{dm}"
            base_url = "https://inference.example.com/v1"
            context_window = 200000
            env_key = "{TEST_ENV_VAR}"
            "#,
        ))
        .unwrap();
        let cfg = Config::new_from_toml_cfg(&toml).expect("config should parse");
        let models = resolve_model_list(&cfg, None);
        let model = models.get(dm).expect("enterprise-style model should exist");
        assert_eq!(
            model.env_key.as_ref().map(|k| k.names()),
            Some(vec![TEST_ENV_VAR])
        );

        // Without the env var present, has_own_credentials() and the predicate return false, and the builder advertises only the login method
        // Confirms the predicate isn't trivially true
        {
            let _unset = EnvGuard::unset(TEST_ENV_VAR);
            let has_external_api_key = should_advertise_fuigo_api_key(false, models.values());
            assert!(!has_external_api_key);
            let built = build_auth_methods(AuthMethodsBuildInputs {
                has_external_api_key,
                ..default_inputs()
            });
            assert_ne!(
                first_kind(&built.methods),
                Some(AuthMethodKind::FuigoApiKey),
                "without env_key resolved, fuigo.api_key must NOT be advertised first",
            );
        }

        // With the env var present (the actual enterprise scenario), the predicate returns true
        // The builder MUST put `fuigo.api_key` first so the pager's `startup_auth_metadata()` returns `needs_login = false`
        {
            let _set = EnvGuard::set(TEST_ENV_VAR, "enterprise-secret-token");
            let has_external_api_key = should_advertise_fuigo_api_key(false, models.values());
            assert!(has_external_api_key);
            let built = build_auth_methods(AuthMethodsBuildInputs {
                has_external_api_key,
                // Realistic enterprise user: no cached session token, default grok.com login (no enterprise OIDC)
                has_cached_token: false,
                ..default_inputs()
            });
            assert_eq!(
                first_kind(&built.methods),
                Some(AuthMethodKind::FuigoApiKey),
                "BYOK: fuigo.api_key must be auth_methods.first(); deferred-to-last \
                 ordering sends enterprise users to the login screen",
            );
            assert!(
                !AuthMethodKind::from_id(built.methods[0].id()).needs_interactive_login(),
                "auth_methods.first() MUST NOT need interactive login -- this \
                 is the exact predicate the pager's startup_auth_metadata() \
                 uses to decide whether to show the login screen",
            );
        }
    }

    /// `FUIGO_API_KEY` alone (no per-model creds) also triggers advertising `fuigo.api_key` as the first method.
    /// Historical "external key" path; covered here so the predicate keeps treating env-var-only users the same as per-model users.
    #[test]
    #[serial]
    fn global_external_api_key_advertises_fuigo_api_key_first() {
        let _set = EnvGuard::set(FUIGO_API_KEY_ENV_VAR, "fuigo-external-key");
        let cfg = Config::default();
        let models = resolve_model_list(&cfg, None);
        let has_external_api_key = should_advertise_fuigo_api_key(false, models.values());
        assert!(has_external_api_key);
        let built = build_auth_methods(AuthMethodsBuildInputs {
            has_external_api_key,
            ..default_inputs()
        });
        assert_eq!(
            first_kind(&built.methods),
            Some(AuthMethodKind::FuigoApiKey)
        );
    }

    /// Admin kill switch (`disable_api_key_auth`): the predicate must return false even when credentials are available everywhere.
    /// That includes both the global env var and a per-model env_key.
    /// The builder then never advertises `fuigo.api_key`, and the pager sends the user to the deployment's login method instead.
    #[test]
    #[serial]
    fn disable_api_key_auth_suppresses_fuigo_api_key_method() {
        let _set = EnvGuard::set(FUIGO_API_KEY_ENV_VAR, "fuigo-external-key");
        let cfg = Config::default();
        let models = resolve_model_list(&cfg, None);

        // Flag off: today's behavior (advertised first).
        assert!(should_advertise_fuigo_api_key(false, models.values()));

        // Flag on: never advertised, regardless of credentials.
        let has_external_api_key = should_advertise_fuigo_api_key(true, models.values());
        assert!(!has_external_api_key);
        let built = build_auth_methods(AuthMethodsBuildInputs {
            has_external_api_key,
            ..inputs_with_login_provider()
        });
        assert!(
            !built
                .methods
                .iter()
                .any(|m| AuthMethodKind::from_id(m.id()) == AuthMethodKind::FuigoApiKey),
            "fuigo.api_key must not be advertised when disable_api_key_auth is set",
        );
        assert_eq!(
            first_kind(&built.methods),
            Some(AuthMethodKind::FuigoCom),
            "with api-key auth disabled and no cached token, the login method \
             must lead so the pager requires interactive login",
        );
        assert!(built.default_auth_method_id.is_none());
    }

    #[test]
    #[serial]
    fn env_key_probe_unusable_suppresses_advertise_without_byok() {
        let _set = EnvGuard::set(FUIGO_API_KEY_ENV_VAR, "fuigo-dead-key");
        let _legacy = EnvGuard::unset(LEGACY_FUIGO_API_KEY_ENV_VAR);
        let cfg = Config::default();
        let models = resolve_model_list(&cfg, None);
        assert!(
            should_advertise_fuigo_api_key(false, models.values()),
            "presence-only helper still sees the env key"
        );
        assert!(
            !should_advertise_fuigo_api_key_with_env_ok(false, models.values(), false),
            "probe-unusable env key alone must not advertise"
        );
        let built = build_auth_methods(AuthMethodsBuildInputs {
            has_external_api_key: false,
            ..inputs_with_login_provider()
        });
        assert_eq!(first_kind(&built.methods), Some(AuthMethodKind::FuigoCom));
    }

    #[test]
    #[serial]
    fn env_key_probe_ok_still_advertises() {
        let _set = EnvGuard::set(FUIGO_API_KEY_ENV_VAR, "fuigo-live-key");
        let cfg = Config::default();
        let models = resolve_model_list(&cfg, None);
        assert!(should_advertise_fuigo_api_key_with_env_ok(
            false,
            models.values(),
            true
        ));
    }

    #[test]
    #[serial]
    fn byok_advertises_even_when_env_probe_unusable() {
        const TEST_ENV_VAR: &str = "TEST_BYOK_PROBE_INDEPENDENT_TOKEN";
        let _unset = EnvGuard::unset(FUIGO_API_KEY_ENV_VAR);
        let _legacy = EnvGuard::unset(LEGACY_FUIGO_API_KEY_ENV_VAR);
        let _byok = EnvGuard::set(TEST_ENV_VAR, "enterprise-secret-token");

        let dm = crate::models::default_model();
        let toml: toml::Value = toml::from_str(&format!(
            r#"
            [model."{dm}"]
            model = "{dm}"
            base_url = "https://inference.example.com/v1"
            context_window = 200000
            env_key = "{TEST_ENV_VAR}"
            "#,
        ))
        .unwrap();
        let cfg = Config::new_from_toml_cfg(&toml).expect("config should parse");
        let models = resolve_model_list(&cfg, None);
        assert!(
            should_advertise_fuigo_api_key_with_env_ok(false, models.values(), false),
            "BYOK must not depend on the first-party env probe"
        );
    }

    /// Legacy `FUIGO_CODE_API_KEY` env var is accepted as a fallback when `FUIGO_API_KEY` is not set, so existing deployments keep working.
    #[test]
    #[serial]
    fn legacy_env_var_fallback_advertises_fuigo_api_key() {
        let _unset_new = EnvGuard::unset(FUIGO_API_KEY_ENV_VAR);
        let _set_legacy = EnvGuard::set(LEGACY_FUIGO_API_KEY_ENV_VAR, "fuigo-legacy-key");
        assert!(has_fuigo_api_key_env());
        assert_eq!(read_fuigo_api_key_env().unwrap(), "fuigo-legacy-key");

        let cfg = Config::default();
        let models = resolve_model_list(&cfg, None);
        let has_external_api_key = should_advertise_fuigo_api_key(false, models.values());
        assert!(has_external_api_key);
    }

    /// When both `FUIGO_API_KEY` and `FUIGO_CODE_API_KEY` are set, the new name takes precedence.
    #[test]
    #[serial]
    fn new_env_var_takes_precedence_over_legacy() {
        let _new = EnvGuard::set(FUIGO_API_KEY_ENV_VAR, "new-key");
        let _legacy = EnvGuard::set(LEGACY_FUIGO_API_KEY_ENV_VAR, "old-key");
        assert_eq!(read_fuigo_api_key_env().unwrap(), "new-key");
    }

    // -- fuigo login --legacy regression coverage ------------------------
    //
    // `fuigo login --legacy` produces a FuigoAuth with `auth_mode: WebLogin`, `oidc_issuer: None`, and no `expires_at` (30-day hardcoded TTL)
    // When this token is in the `FUIGO_AUTH` env var (or the legacy scope fallback in auth.json), `AuthManager::new` returns it from `current()`
    // That feeds `has_cached_token = true` into `build_auth_methods`, which puts `cached_token` first
    // `startup_auth_metadata()` then returns `needs_login = false`: legacy users get frictionless auth, no login screen
    //
    // This test pins the env-var path (highest priority in AuthManager) end-to-end
    // A regression in FUIGO_AUTH JSON parsing or in auth method ordering would send legacy-token users to the login screen

    /// END-TO-END REGRESSION TEST for a legacy auth token (WebLogin, no expires_at) in the `FUIGO_AUTH` env var with no other auth available.
    /// `AuthManager` MUST load it and `build_auth_methods` must advertise `cached_token` first.
    /// The pager therefore skips the login screen (frictionless legacy auth).
    #[test]
    #[serial]
    fn fuigo_login_legacy_token_does_not_require_login() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        use crate::auth::{AuthManager, AuthMode, FuigoAuth, FuigoComConfig};

        // Ensure clean slate for "no other auth available".
        let _g1 = EnvGuard::unset("FUIGO_AUTH_PATH");
        let _g2 = EnvGuard::unset(FUIGO_API_KEY_ENV_VAR);

        // Construct a legacy-style token exactly as `fuigo login --legacy` produces it
        // That means WebLogin mode, no OIDC fields, no refresh_token, no expires_at (is_expired falls back to the 30-day age check)
        let legacy_token = FuigoAuth {
            key: "legacy-relay-token".into(),
            auth_mode: AuthMode::WebLogin,
            create_time: chrono::Utc::now(),
            user_id: "legacy-user".into(),
            email: Some("legacy@example.com".into()),
            oidc_issuer: None,
            oidc_client_id: None,
            refresh_token: None,
            expires_at: None,
            ..FuigoAuth::test_default()
        };

        // Provide it via the FUIGO_AUTH env var (highest priority code path in AuthManager::new)
        // This is the "legacy auth token exists in the env" case with no other auth
        let legacy_json = serde_json::to_string(&legacy_token).expect("serialize legacy token");
        let _g = EnvGuard::set("FUIGO_AUTH", &legacy_json);

        // AuthManager picks it up from the env var directly (no file needed).
        let dir = tempfile::tempdir().unwrap();
        let cfg = FuigoComConfig::default();
        let mgr = AuthManager::new(dir.path(), cfg);
        let current = mgr.current();
        assert!(
            current.is_some(),
            "legacy token in FUIGO_AUTH env MUST be loaded directly -- if this fails, \
             users with legacy auth in env would be sent to the login screen",
        );
        assert_eq!(
            current.as_ref().unwrap().key,
            "legacy-relay-token",
            "loaded token must match the one injected via env",
        );

        // Derive has_cached_token exactly as initialize() does
        let has_cached_token = mgr.current().is_some();
        assert!(has_cached_token);

        // With only this legacy token (no fuigo api key), the first method must be cached_token so the pager skips the login screen
        let built = build_auth_methods(AuthMethodsBuildInputs {
            has_external_api_key: false,
            has_cached_token,
            ..default_inputs()
        });

        assert_eq!(
            first_kind(&built.methods),
            Some(AuthMethodKind::CachedToken),
            "legacy token in env: cached_token MUST be auth_methods.first() \
             (pager startup_auth_metadata returns needs_login=false)",
        );
        assert!(
            !AuthMethodKind::from_id(built.methods[0].id()).needs_interactive_login(),
            "auth_methods.first() MUST NOT need interactive login when legacy token \
             is in env -- prevents login screen regression",
        );
        assert_eq!(
            built
                .default_auth_method_id
                .as_ref()
                .map(|id| id.0.as_ref()),
            Some(CACHED_TOKEN_AUTH_METHOD_ID),
        );
    }

    /// Negative case for the legacy flow: when auth.json does NOT contain a legacy-scope entry, AuthManager::current() is None.
    /// has_cached_token is then false and build_auth_methods advertises only the login method.
    /// This pins the predicate's "no" answer so the test above isn't trivially passing.
    #[test]
    #[serial]
    fn no_legacy_token_means_no_cached_token_advertised() {
        if fuigo_test_support::env::rerun_in_own_process() {
            return;
        }
        use crate::auth::{AuthManager, FuigoComConfig};

        let _g1 = EnvGuard::unset("FUIGO_AUTH");
        let _g2 = EnvGuard::unset("FUIGO_AUTH_PATH");

        let dir = tempfile::tempdir().unwrap();
        // No auth.json in the tempdir.
        let cfg = FuigoComConfig::default();
        let mgr = AuthManager::new(dir.path(), cfg);
        assert!(mgr.current().is_none());

        let built = build_auth_methods(AuthMethodsBuildInputs {
            has_external_api_key: false,
            has_cached_token: mgr.current().is_some(),
            ..inputs_with_login_provider()
        });
        assert_eq!(
            first_kind(&built.methods),
            Some(AuthMethodKind::FuigoCom),
            "no cached token AND no api key: pager must show login (grok.com first)",
        );
    }

    // ── preferred_method pin (fail-closed) ──────────────────────────────

    #[test]
    fn pin_api_key_with_key_only_advertises_api_key() {
        let built = build_auth_methods(AuthMethodsBuildInputs {
            has_external_api_key: true,
            has_cached_token: true,
            preferred_method: Some(PreferredAuthMethod::ApiKey),
            ..default_inputs()
        });
        assert_eq!(method_ids(&built), vec![FUIGO_API_KEY_METHOD_ID]);
        assert_eq!(default_id(&built), Some(FUIGO_API_KEY_METHOD_ID));
    }

    #[test]
    fn pin_api_key_without_key_fails_closed_even_with_session() {
        let built = build_auth_methods(AuthMethodsBuildInputs {
            has_external_api_key: false,
            has_cached_token: true,
            preferred_method: Some(PreferredAuthMethod::ApiKey),
            ..default_inputs()
        });
        assert!(built.methods.is_empty());
        assert!(built.default_auth_method_id.is_none());
    }

    #[test]
    fn pin_oidc_with_session_hides_api_key() {
        let built = build_auth_methods(AuthMethodsBuildInputs {
            has_external_api_key: true,
            has_cached_token: true,
            preferred_method: Some(PreferredAuthMethod::Oidc),
            ..inputs_with_login_provider()
        });
        assert_eq!(
            method_ids(&built),
            vec![CACHED_TOKEN_AUTH_METHOD_ID, FUIGO_COM_METHOD_ID]
        );
        assert_eq!(default_id(&built), Some(CACHED_TOKEN_AUTH_METHOD_ID));
    }

    #[test]
    fn pin_oidc_without_session_is_interactive_only() {
        let built = build_auth_methods(AuthMethodsBuildInputs {
            has_external_api_key: true,
            has_cached_token: false,
            preferred_method: Some(PreferredAuthMethod::Oidc),
            ..inputs_with_login_provider()
        });
        assert_eq!(method_ids(&built), vec![FUIGO_COM_METHOD_ID]);
        assert!(built.default_auth_method_id.is_none());
    }
}

//! Which environment variables a child process of Fuigo must never inherit: the ONE registry of credential names
//! (moved here from `fuigo-tools`' `shell_env_policy` in P120, which re-exports it, so that `fuigo-tty-utils` and
//! `fuigo-fast-worktree`, which `fuigo-tools` depends on, can apply the same filter to the git they spawn).

use std::sync::LazyLock;

/// The environment variables each provider Fuigo knows reads its key from.
///
/// This module is the ONE registry of these names: `fuigo_shell::agent::key_discovery::PROVIDERS`
/// takes each provider's `env_vars` from here (it cannot be the other way round: `fuigo-shell`
/// depends on this crate, and the hooks and MCP crates that spawn children do not depend on
/// `fuigo-shell`). A test in `key_discovery` fails if a provider there names a variable this
/// denylist does not cover.
pub mod provider_key_env_vars {
    /// FluxRouter, Fuigo's lead provider. `FLUX_API_KEY` is FluxRouter's own name for its key.
    pub const FLUXROUTER: &[&str] = &["FUIGO_API_KEY", "FUIGO_CODE_API_KEY", "FLUX_API_KEY"];
    pub const ANTHROPIC: &[&str] = &["ANTHROPIC_API_KEY"];
    pub const OPENAI: &[&str] = &["OPENAI_API_KEY"];
    pub const GOOGLE: &[&str] = &["GEMINI_API_KEY", "GOOGLE_API_KEY"];
    pub const XAI: &[&str] = &["XAI_API_KEY", "GROK_API_KEY"];
    pub const GROQ: &[&str] = &["GROQ_API_KEY"];
    pub const OPENROUTER: &[&str] = &["OPENROUTER_API_KEY"];
    pub const DEEPSEEK: &[&str] = &["DEEPSEEK_API_KEY"];
    pub const MISTRAL: &[&str] = &["MISTRAL_API_KEY"];
    /// Bearer-token variables the config documentation tells users to name in a model's `env_key`
    /// (`fuigo_shell::agent::config::EnvKeys`), which no provider discovers by itself. A config
    /// that does name them is registered at load too; listing them here covers the process before
    /// any config is read and a config that names them only through a remote catalogue.
    pub const DOCUMENTED_ENV_KEYS: &[&str] = &["ANTHROPIC_AUTH_TOKEN", "LC_ANTHROPIC_AUTH_TOKEN"];

    /// Every group above.
    pub const ALL: &[&[&str]] = &[
        FLUXROUTER,
        ANTHROPIC,
        OPENAI,
        GOOGLE,
        XAI,
        GROQ,
        OPENROUTER,
        DEEPSEEK,
        MISTRAL,
        DOCUMENTED_ENV_KEYS,
    ];
}

/// The variables Fuigo itself reads a secret of its OWN from (P113, CIE-02 / E1): never inherited by a child, like the
/// provider keys. A child that needs one gets it only through an explicit entry (a server's or hook's `env`,
/// `[shell_environment_policy] set`), which is applied after the policy base.
///
/// `fuigo_shell::agent::config::FIRST_PARTY_CREDENTIAL_ENV_VARS` (scrubbed from the auth-provider helper) names
/// first-party credentials too; `fuigo-shell` depends on this crate, not the other way round, so a test there
/// (`p113_every_first_party_credential_variable_is_denied_to_child_processes`) fails if that list names one this one
/// does not cover.
pub const FUIGO_INTERNAL_CREDENTIAL_ENV_VARS: &[&str] = &[
    // The shared secret that authenticates an ACP connection to `fuigo agent serve` (`--secret`).
    "FUIGO_AGENT_SECRET",
    // The saved login as inline JSON (key, user id, e-mail, team ids), and the file that holds it.
    "FUIGO_AUTH",
    "FUIGO_AUTH_PATH",
    // Managed-deployment and extra first-party request credentials.
    "FUIGO_DEPLOYMENT_KEY",
    "FUIGO_EXTRA_AUTH_KEY",
    // The trace-upload credentials file.
    "FUIGO_TRACE_UPLOAD_CREDENTIALS_FILE",
    // OTLP exporter headers (they carry the collector's auth token), Fuigo's internal exporter and the user's.
    "FUIGO_INTERNAL_OTLP_HEADERS",
    "OTEL_EXPORTER_OTLP_HEADERS",
    "OTEL_EXPORTER_OTLP_LOGS_HEADERS",
    "OTEL_EXPORTER_OTLP_METRICS_HEADERS",
    // Telemetry ingestion credentials overridden from the environment.
    "FUIGO_TELEMETRY_EVENTS_API_KEY",
    "FUIGO_TELEMETRY_MIXPANEL_TOKEN",
];

/// Names users configured to hold a credential (`env_key`, `env_http_headers`, ...), registered
/// by the config loader through [`register_credential_env_names`]. Stored upper-cased. Only ever
/// grows: a name that was a credential once in this process stays hidden from its children.
static CONFIGURED_CREDENTIAL_NAMES: LazyLock<
    std::sync::RwLock<std::collections::BTreeSet<String>>,
> = LazyLock::new(Default::default);

/// Names that are never treated as a credential however a config names them: stripping them would
/// break every child (`env_http_headers = { X-User = "USER" }` is plausible), and none is a secret.
/// Covers both platforms' [`CORE_ENV_VARS`] (a test pins that) plus a few shell basics.
const NEVER_CREDENTIAL_NAMES: &[&str] = &[
    "PATH",
    "SHELL",
    "TMPDIR",
    "TEMP",
    "TMP",
    "HOME",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "LOGNAME",
    "USER",
    "TERM",
    "PWD",
    "SHLVL",
    "PATHEXT",
    "COMSPEC",
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "USERNAME",
    "USERDOMAIN",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "PROGRAMFILES",
    "PROGRAMFILES(X86)",
    "PROGRAMW6432",
    "PROGRAMDATA",
    "LOCALAPPDATA",
    "APPDATA",
    "POWERSHELL",
    "PWSH",
];

/// Add configured credential variable names to the denylist for every child spawned from now on
/// (bash tool, hooks, stdio MCP servers, LSP servers, login-shell capture). Empty names, names
/// containing `=` or NUL, and [`NEVER_CREDENTIAL_NAMES`] are ignored. A name is kept EXACTLY as
/// configured (no trimming: `env_key = " K "` reads the variable `" K "`, and `"   "` is a
/// valid variable name on Unix, so those are the ones to deny); matching is case-insensitive
/// like the rest of the policy.
pub fn register_credential_env_names<I, S>(names: I)
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let fresh: Vec<String> = names
        .into_iter()
        .filter_map(|name| {
            let name = name.as_ref();
            let usable = !name.is_empty()
                && !name.contains(['=', '\0'])
                && !NEVER_CREDENTIAL_NAMES
                    .iter()
                    .any(|never| never.eq_ignore_ascii_case(name));
            usable.then(|| name.to_ascii_uppercase())
        })
        // P113 r3 (Astra r3 #1): a built-in provider name a config names (an MCP `bearer_token_env_var =
        // "OPENAI_API_KEY"`) is kept too: children are denied it either way, but `!` commands and client terminals,
        // which keep the user's own provider keys, must lose it ([`is_fuigo_secret`]).
        .collect();
    if fresh.is_empty() {
        return;
    }
    // Waits out a persistent-shell spawn that checked the generation and has not spawned yet.
    let _fence = DENYLIST_FENCE
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let mut set = CONFIGURED_CREDENTIAL_NAMES
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    // Only a real addition to what children are denied moves the generation (two callers racing on the same name add
    // once; a built-in provider name was denied already).
    let denies_more = fresh
        .iter()
        .any(|name| !is_known_credential(name) && !set.contains(name));
    set.extend(fresh);
    if denies_more {
        CREDENTIAL_DENYLIST_GENERATION.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Bumped (under the registry's write lock) every time [`register_credential_env_names`] adds a
/// name. A persistent shell records it with its snapshot: a snapshot taken under an older
/// generation may hold a credential that is denied now, so it is discarded, never replayed.
static CREDENTIAL_DENYLIST_GENERATION: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// The current [`CREDENTIAL_DENYLIST_GENERATION`].
pub fn credential_denylist_generation() -> u64 {
    CREDENTIAL_DENYLIST_GENERATION.load(std::sync::atomic::Ordering::SeqCst)
}

/// Held for reading from a persistent shell's generation check until its spawn returns, and for
/// writing by [`register_credential_env_names`], so no name can be added between the check and
/// the spawn that replays the checked snapshot. A separate lock from the registry itself, which
/// the spawn reads while building the child environment.
static DENYLIST_FENCE: std::sync::RwLock<()> = std::sync::RwLock::new(());

/// See [`DENYLIST_FENCE`]. Never hold it across an `.await`.
pub fn credential_denylist_fence() -> std::sync::RwLockReadGuard<'static, ()> {
    DENYLIST_FENCE
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn is_known_credential(name: &str) -> bool {
    known_credential_names().any(|known| known.eq_ignore_ascii_case(name))
}

/// Every built-in credential name: the provider keys, then Fuigo's own.
fn known_credential_names() -> impl Iterator<Item = &'static str> {
    provider_key_env_vars::ALL
        .iter()
        .flat_map(|group| group.iter())
        .chain(FUIGO_INTERNAL_CREDENTIAL_ENV_VARS)
        .copied()
}

/// Ambient credentials never cross a subprocess boundary implicitly: every provider's key
/// variables ([`provider_key_env_vars`]), Fuigo's own ([`FUIGO_INTERNAL_CREDENTIAL_ENV_VARS`]) and
/// every name a loaded config registered.
pub fn is_provider_credential(name: &str) -> bool {
    is_known_credential(name)
        || CONFIGURED_CREDENTIAL_NAMES
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&name.to_ascii_uppercase())
}

/// Every credential variable name currently denied to children (known, then registered).
pub fn credential_env_names() -> Vec<String> {
    let mut names: Vec<String> = known_credential_names().map(str::to_string).collect();
    names.extend(
        CONFIGURED_CREDENTIAL_NAMES
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|name| !is_known_credential(name))
            .cloned(),
    );
    names
}

/// Whether `name` holds one of FUIGO's OWN secrets (P113 r3): its first-party API key variables
/// ([`provider_key_env_vars::FLUXROUTER`]), the rest of [`FUIGO_INTERNAL_CREDENTIAL_ENV_VARS`], and every name a loaded
/// config registered as a credential (an MCP `bearer_token_env_var` or client secret, a model `env_key`). Narrower than
/// [`is_provider_credential`]: another provider's key (`OPENAI_API_KEY`) is the user's, not Fuigo's. Case-insensitive.
pub fn is_fuigo_secret(name: &str) -> bool {
    provider_key_env_vars::FLUXROUTER
        .iter()
        .chain(FUIGO_INTERNAL_CREDENTIAL_ENV_VARS)
        .any(|known| known.eq_ignore_ascii_case(name))
        || CONFIGURED_CREDENTIAL_NAMES
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains(&name.to_ascii_uppercase())
}

/// The variables of this process's environment, spelled as they are, that hold one of Fuigo's own secrets
/// ([`is_fuigo_secret`]). For a child that otherwise keeps the user's whole environment (a `!` command, a client
/// terminal): remove each of these from it (`env_remove`) before setting any explicit variable, so an explicit entry
/// still arrives.
pub fn inherited_fuigo_secret_names() -> Vec<std::ffi::OsString> {
    std::env::vars_os()
        .map(|(name, _)| name)
        .filter(|name| name.to_str().is_some_and(is_fuigo_secret))
        .collect()
}

/// Remove Fuigo's own secrets ([`is_fuigo_secret`]) from the environment `cmd` will inherit. Call it BEFORE setting
/// any explicit variable: `env_remove` after an `env` would drop the explicit value too.
pub fn remove_fuigo_secrets(cmd: &mut std::process::Command) {
    for name in inherited_fuigo_secret_names() {
        cmd.env_remove(name);
    }
}

/// Whether `name` is one of the secrets FUIGO ITSELF holds or is handed (P120 follow-up): the first-party API key
/// variables ([`provider_key_env_vars::FLUXROUTER`]) and the rest of [`FUIGO_INTERNAL_CREDENTIAL_ENV_VARS`]. Narrower
/// than [`is_fuigo_secret`]: it leaves out the names a loaded config registered ([`config_registered_names`]), which
/// are the USER's own credentials (`GITHUB_TOKEN` named as an MCP `bearer_token_env_var`) and which the user's own
/// tools (git credential helpers, `gh`) read. Used for the children that run the user's own programs on the user's
/// own behalf (git, jj, direnv, `$EDITOR`/`$PAGER`, sign-in and identity commands, the status line, notification
/// hooks, `fuigo wrap`); the bash tool, MCP, hooks, LSP and terminals keep the full filter. Case-insensitive.
pub fn is_fuigo_owned_secret(name: &str) -> bool {
    provider_key_env_vars::FLUXROUTER
        .iter()
        .chain(FUIGO_INTERNAL_CREDENTIAL_ENV_VARS)
        .any(|known| known.eq_ignore_ascii_case(name))
}

/// Every name a loaded config registered as a credential (upper-cased), built-in names excluded: the user-side class
/// that [`is_fuigo_owned_secret`] leaves alone and [`is_fuigo_secret`] strips.
pub fn config_registered_names() -> Vec<String> {
    CONFIGURED_CREDENTIAL_NAMES
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .filter(|name| !is_known_credential(name))
        .cloned()
        .collect()
}

/// [`inherited_fuigo_secret_names`] for [`is_fuigo_owned_secret`] only.
pub fn inherited_fuigo_owned_secret_names() -> Vec<std::ffi::OsString> {
    std::env::vars_os()
        .map(|(name, _)| name)
        .filter(|name| name.to_str().is_some_and(is_fuigo_owned_secret))
        .collect()
}

/// [`remove_fuigo_secrets`] for [`is_fuigo_owned_secret`] only. Call it BEFORE setting any explicit variable.
pub fn remove_fuigo_owned_secrets(cmd: &mut std::process::Command) {
    for name in inherited_fuigo_owned_secret_names() {
        cmd.env_remove(name);
    }
}

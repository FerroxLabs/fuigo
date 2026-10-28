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
    ///
    /// ORDER IS PRECEDENCE: `FUIGO_API_KEY`, then `FUIGO_CODE_API_KEY`, then `FLUX_API_KEY`. Every reader of the Flux
    /// key from the environment (runtime, `fuigo models`, `login --status`, the picker) takes this list; do not
    /// write the names out again elsewhere.
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
///
/// Whether a name IS a never-credential name is decided by the host's real name rules
/// ([`is_never_credential_name`]), never by the wider credential fold: on Unix `\u{17f}HELL` is a
/// different variable from `SHELL`, so it is registered (and removed from children) while `SHELL`
/// itself survives ([`is_configured_credential`] never matches a never-credential name).
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
                && !is_never_credential_name(name);
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
    known_credential_names().any(|known| credential_names_match(known, name))
}

/// Whether `name` is one of [`NEVER_CREDENTIAL_NAMES`] under the HOST's own name rules: ASCII
/// case-insensitive on Unix (what the registry, stored ASCII-upper-cased, always used there) and
/// Windows' ordinal ignore-case equality ([`windows_env_names_equal`]) on Windows. Deliberately
/// NOT [`credential_names_match`]: the wide fold may only ever add a removal, so it must never make a
/// distinct variable count as a never-credential name and escape registration.
fn is_never_credential_name(name: &str) -> bool {
    is_never_credential_name_on(name, cfg!(windows))
}

fn is_never_credential_name_on(name: &str, windows: bool) -> bool {
    NEVER_CREDENTIAL_NAMES.iter().any(|never| {
        if windows {
            windows_env_names_equal(never, name)
        } else {
            never.eq_ignore_ascii_case(name)
        }
    })
}

/// Whether the configured registry holds `name` in any spelling [`credential_names_match`] equates.
/// A never-credential name ([`is_never_credential_name`]) is never one: a registered `\u{17f}HELL`
/// folds to `SHELL` under the wide match, and that fold must strip `\u{17f}HELL`, not `SHELL`.
fn is_configured_credential(name: &str) -> bool {
    if is_never_credential_name(name) {
        return false;
    }
    CONFIGURED_CREDENTIAL_NAMES
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .any(|configured| credential_names_match(configured, name))
}

/// `c`'s simple (one-to-one) uppercase mapping as Windows applies it: per UTF-16 code unit, so a
/// character outside the Basic Multilingual Plane (a surrogate pair) is never mapped, and a
/// character whose uppercase is several characters (`ß` -> `SS`) or lies outside the BMP is left
/// as it is.
fn windows_upcase(c: char) -> char {
    if u32::from(c) > 0xFFFF {
        return c;
    }
    let mut upper = c.to_uppercase();
    match (upper.next(), upper.next()) {
        (Some(u), None) if u32::from(u) <= 0xFFFF => u,
        _ => c,
    }
}

/// `c` lowered (one-to-one only), then [`windows_upcase`]d: equates the characters whose case pair
/// is not symmetric (the Kelvin sign `\u{212A}` and `K`), which [`windows_upcase`] alone keeps apart.
fn fold_lower_then_upcase(c: char) -> char {
    let mut lower = c.to_lowercase();
    match (lower.next(), lower.next()) {
        (Some(l), None) => windows_upcase(l),
        _ => windows_upcase(c),
    }
}

/// Whether Windows treats `a` and `b` as the SAME environment variable. Windows compares variable
/// names with an ordinal ignore-case comparison (`CompareStringOrdinal(.., TRUE)`, which Rust's
/// `std` also uses for `Command`'s environment keys): each UTF-16 unit is mapped through the
/// system's uppercase table and the results compared. The model here is Unicode uppercase per
/// UTF-16 unit, kept only where it is one-to-one ([`windows_upcase`]). For ASCII and Latin-1 names
/// it equates exactly what Windows does; outside them it may differ either way (a character whose
/// full uppercase is several characters but whose simple uppercase is one, such as `\u{1f80}`, is
/// left unmapped here while Windows maps it). Credential matching does not rely on it alone
/// ([`credential_names_match`] adds a wider fold).
pub fn windows_env_names_equal(a: &str, b: &str) -> bool {
    if a.is_ascii() && b.is_ascii() {
        return a.eq_ignore_ascii_case(b);
    }
    a.chars().map(windows_upcase).eq(b.chars().map(windows_upcase))
}

/// `name` mapped through [`windows_upcase`]: equal keys are exactly the names
/// [`windows_env_names_equal`] equates.
pub fn windows_env_name_key(name: &str) -> String {
    name.chars().map(windows_upcase).collect()
}

/// `name` mapped through [`fold_lower_then_upcase`] (the wider fold [`credential_names_match`] adds).
pub fn wide_env_name_key(name: &str) -> String {
    name.chars().map(fold_lower_then_upcase).collect()
}

/// Whether `a` and `b` must be treated as the same CREDENTIAL name on every platform. Deliberately
/// wider than any one platform's rule, so a credential fails toward removal: ASCII case-insensitive
/// (as before), Windows' equality ([`windows_env_names_equal`]), and the lower-then-upper fold
/// ([`wide_env_name_key`]) for the case pairs Windows' table might map differently. On Unix this can
/// strip a distinct variable whose name differs from a credential only by case, never keep one.
pub fn credential_names_match(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
        || windows_env_names_equal(a, b)
        || (!(a.is_ascii() && b.is_ascii())
            && a.chars().map(fold_lower_then_upcase).eq(b.chars().map(fold_lower_then_upcase)))
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
    is_known_credential(name) || is_configured_credential(name)
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
        .any(|known| credential_names_match(known, name))
        || is_configured_credential(name)
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
        .any(|known| credential_names_match(known, name))
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

#[cfg(test)]
mod u35_winenv_tests {
    use super::*;

    /// Windows equates names by uppercasing each UTF-16 unit, so a non-ASCII spelling is the same
    /// variable as its uppercase; ASCII-only folding (the old rule) kept them apart.
    #[test]
    fn windows_env_names_equal_folds_unicode_case() {
        assert!(windows_env_names_equal("Path", "PATH"));
        assert!(windows_env_names_equal("\u{f6}auth", "\u{d6}AUTH"), "\u{f6} uppercases to \u{d6}");
        assert!(windows_env_names_equal("caf\u{e9}_key", "CAF\u{c9}_KEY"));
        assert!(!windows_env_names_equal("PATH", "PATHS"));
        assert!(!windows_env_names_equal("STRASSE", "stra\u{df}e"), "\u{df} has no one-to-one uppercase");
        assert_eq!(windows_env_name_key("\u{f6}auth"), "\u{d6}AUTH");
        // A character outside the BMP is a surrogate pair to Windows and is never case-mapped.
        assert!(!windows_env_names_equal("\u{10428}", "\u{10400}"));
    }

    /// A credential fails toward removal: every spelling any platform could treat as the same name,
    /// including a dotless i (`\u{131}` uppercases to `I`) and the Kelvin sign (`\u{212A}`, whose
    /// lowercase is `k`).
    #[test]
    fn provider_credentials_match_unicode_spellings() {
        assert!(is_provider_credential("openai_api_key"));
        assert!(is_provider_credential("OPENA\u{131}_API_KEY"), "dotless i aliases I");
        assert!(is_provider_credential("GROQ_API_\u{212A}EY"), "Kelvin sign aliases K");
        assert!(is_fuigo_secret("FUIGO_AP\u{131}_KEY"));
        assert!(is_fuigo_owned_secret("flux_ap\u{131}_key"));
        assert!(!is_provider_credential("OPENAI_API_KEYS"));
        assert!(!is_provider_credential("PATH"));
    }

    /// A registered non-ASCII credential is denied in every spelling, not only its upper-ASCII form
    /// (the registry stored `to_ascii_uppercase`, so `\u{d6}AUTH` matched `\u{f6}AUTH` only by luck of
    /// spelling).
    #[test]
    fn registered_credentials_match_unicode_spellings() {
        register_credential_env_names(["\u{d6}AUTH_U35"]);
        assert!(is_provider_credential("\u{d6}AUTH_U35"));
        assert!(is_provider_credential("\u{f6}auth_u35"));
        assert!(is_fuigo_secret("\u{f6}Auth_U35"));
        assert!(!is_provider_credential("OAUTH_U35"), "\u{f6} is not o");
    }

    /// A configured name that folds to a never-credential name (`\u{17f}` uppercases to `S`) can never
    /// strip `SHELL` or `USERNAME` from a child, on any platform.
    #[test]
    fn never_credential_names_ignore_unicode_spellings() {
        register_credential_env_names(["\u{17f}HELL", "U\u{17f}ERNAME"]);
        assert!(!is_provider_credential("SHELL"));
        assert!(!is_provider_credential("USERNAME"));
        assert!(!is_provider_credential("shell"));
    }

    /// u35-winenv r2 (Astra r2 High): on Unix a credential whose name differs from a never-credential
    /// name only by a Unicode case alias (`\u{17f}HELL`, `SHELL`) is a DIFFERENT variable. Registering
    /// it must deny it to children; the wide fold must not make it count as `SHELL` and be dropped
    /// (b62b45bfa dropped it, so the secret reached every child). `SHELL` itself still survives. On
    /// Windows the two are one variable, so the registration is ignored there, as `SHELL` is.
    #[test]
    fn unix_credential_folding_to_a_core_name_is_still_denied() {
        register_credential_env_names(["\u{17f}HELL"]);
        if cfg!(windows) {
            assert!(!is_provider_credential("\u{17f}HELL"));
        } else {
            assert!(is_provider_credential("\u{17f}HELL"), "the credential must be removed from children");
            assert!(is_fuigo_secret("\u{17f}HELL"));
            assert!(
                credential_env_names().iter().any(|name| name == "\u{17f}HELL"),
                "listed as denied"
            );
        }
        assert!(!is_provider_credential("SHELL"), "SHELL itself is never a credential");
        assert!(!is_fuigo_secret("SHELL"));
    }

    /// Whether a name is a never-credential name is the host's own name rule, never the wide fold.
    #[test]
    fn never_credential_rule_is_the_hosts_name_rule() {
        assert!(is_never_credential_name_on("\u{17f}HELL", true), "Windows: one variable with SHELL");
        assert!(!is_never_credential_name_on("\u{17f}HELL", false), "Unix: a distinct variable");
        assert!(is_never_credential_name_on("Shell", false), "Unix registry rule stays ASCII-insensitive");
        assert!(is_never_credential_name_on("Path", true));
    }
}

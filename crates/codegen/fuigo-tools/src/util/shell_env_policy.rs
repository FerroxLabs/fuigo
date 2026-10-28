//! Controls which environment variables agent subprocesses (bash tool,
//! terminals) inherit. Always excludes ambient known provider credentials and Fuigo's own; enforced at the
//! shell spawn sites on macOS, Linux, and Windows.

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::LazyLock;
use wildmatch::WildMatchPattern;

/// Case-insensitive environment-variable-name glob (`*`, `?`).
pub type EnvironmentVariablePattern = WildMatchPattern<'*', '?'>;

fn deserialize_patterns<'de, D>(
    deserializer: D,
) -> Result<Vec<EnvironmentVariablePattern>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let globs = Vec::<String>::deserialize(deserializer)?;
    Ok(globs
        .iter()
        .map(|s| EnvironmentVariablePattern::new_case_insensitive(s))
        .collect())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShellEnvironmentPolicyInherit {
    /// Core platform variables only (PATH, HOME, SHELL, ...).
    Core,
    #[default]
    All,
    None,
}

/// How to build the environment for agent subprocesses. Applied in order: start
/// from `inherit`; if `ignore_default_excludes` is false, drop the secret
/// patterns `*KEY*`/`*SECRET*`/`*TOKEN*`; drop `exclude`; insert `set`; if
/// `include_only` is non-empty, keep only those. Patterns are case-insensitive
/// globs (`*`, `?`).
#[derive(Debug, Clone, PartialEq, serde::Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ShellEnvironmentPolicy {
    pub inherit: ShellEnvironmentPolicyInherit,
    /// Skip the built-in secret excludes (default `true`).
    pub ignore_default_excludes: bool,
    #[serde(deserialize_with = "deserialize_patterns")]
    pub exclude: Vec<EnvironmentVariablePattern>,
    /// Values inserted into the base environment before `include_only` filtering
    /// (an unmatched name is then dropped). These seed the base; request env
    /// layered at spawn can still override them.
    pub set: HashMap<String, String>,
    #[serde(deserialize_with = "deserialize_patterns")]
    pub include_only: Vec<EnvironmentVariablePattern>,
}

impl Default for ShellEnvironmentPolicy {
    fn default() -> Self {
        Self {
            inherit: ShellEnvironmentPolicyInherit::All,
            ignore_default_excludes: true,
            exclude: ["FUIGO_API_KEY", "FUIGO_CODE_API_KEY"]
                .into_iter()
                .map(EnvironmentVariablePattern::new_case_insensitive)
                .collect(),
            set: HashMap::new(),
            include_only: Vec::new(),
        }
    }
}

impl ShellEnvironmentPolicy {
    /// The mandatory credential baseline means no policy is a no-op.
    pub fn is_noop(&self) -> bool {
        false // The mandatory credential baseline always applies.
    }

    /// True if `name` matches a built-in secret exclude and those are enabled.
    fn matches_default_exclude(&self, name: &str, platform: EnvPlatform) -> bool {
        !self.ignore_default_excludes
            && DEFAULT_SECRET_EXCLUDES
                .iter()
                .any(|p| platform.pattern_matches(p, name, PatternUse::Remove))
    }

    fn matches_exclude(&self, name: &str, platform: EnvPlatform) -> bool {
        self.exclude
            .iter()
            .any(|p| platform.pattern_matches(p, name, PatternUse::Remove))
    }

    /// True if `include_only` is empty (all admitted) or `name` matches it.
    fn matches_include_only(&self, name: &str, platform: EnvPlatform) -> bool {
        self.include_only.is_empty()
            || self
                .include_only
                .iter()
                .any(|p| platform.pattern_matches(p, name, PatternUse::Keep))
    }

    /// Whether `name` survives the name filters (default excludes, `exclude`,
    /// `include_only`), ignoring `inherit`/`set`. Used to filter variables layered
    /// in after the policy base, e.g. login-shell capture. Shares its matchers
    /// with [`create_env_for`] so the two cannot drift.
    pub fn allows(&self, name: &str) -> bool {
        self.allows_on(name, EnvPlatform::host())
    }

    /// [`allows`](Self::allows) under `platform`'s name rules.
    pub(crate) fn allows_on(&self, name: &str, platform: EnvPlatform) -> bool {
        !is_provider_credential(name)
            && !self.matches_default_exclude(name, platform)
            && !self.matches_exclude(name, platform)
            && self.matches_include_only(name, platform)
    }

    /// Like [`allows`](Self::allows) but also honors `inherit`: `none` admits
    /// nothing, `core` admits only core names, `all` defers to `allows`.
    pub fn allows_with_inherit(&self, name: &str) -> bool {
        self.allows_with_inherit_on(name, EnvPlatform::host())
    }

    /// [`allows_with_inherit`](Self::allows_with_inherit) under `platform`'s name rules: a core
    /// name matches exactly on Unix (`path` is not `PATH` there) and in any Windows spelling on
    /// Windows.
    pub(crate) fn allows_with_inherit_on(&self, name: &str, platform: EnvPlatform) -> bool {
        match self.inherit {
            ShellEnvironmentPolicyInherit::None => return false,
            ShellEnvironmentPolicyInherit::Core => {
                if !platform.is_core(name) {
                    return false;
                }
            }
            ShellEnvironmentPolicyInherit::All => {}
        }
        self.allows_on(name, platform)
    }
}

// The credential registry lives in `fuigo-secrets` (P120) so the leaf crates that spawn git (`fuigo-tty-utils`,
// `fuigo-fast-worktree`) apply the SAME filter; it is re-exported here under its old path.
pub use fuigo_secrets::child_env::{
    FUIGO_INTERNAL_CREDENTIAL_ENV_VARS, credential_denylist_fence, credential_denylist_generation,
    config_registered_names, credential_env_names, inherited_fuigo_owned_secret_names,
    inherited_fuigo_secret_names, is_fuigo_owned_secret, is_fuigo_secret, is_provider_credential,
    provider_key_env_vars, register_credential_env_names,
};

/// Built-in secret excludes applied when `ignore_default_excludes` is false.
/// Shared by the base-env build and the login-capture filter so they can't drift.
static DEFAULT_SECRET_EXCLUDES: LazyLock<[EnvironmentVariablePattern; 3]> = LazyLock::new(|| {
    [
        EnvironmentVariablePattern::new_case_insensitive("*KEY*"),
        EnvironmentVariablePattern::new_case_insensitive("*SECRET*"),
        EnvironmentVariablePattern::new_case_insensitive("*TOKEN*"),
    ]
});

/// "Core" variables retained under [`ShellEnvironmentPolicyInherit::Core`] on Unix.
const UNIX_CORE_ENV_VARS: &[&str] = &[
    "PATH", "SHELL", "TMPDIR", "TEMP", "TMP", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "LOGNAME",
    "USER",
];
/// "Core" variables retained under [`ShellEnvironmentPolicyInherit::Core`] on Windows.
const WINDOWS_CORE_ENV_VARS: &[&str] = &[
    "PATH",
    "PATHEXT",
    "SHELL",
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
    "TEMP",
    "TMP",
    "TMPDIR",
    "POWERSHELL",
    "PWSH",
];

/// What a policy glob decides: a removal (`exclude`, the default excludes), where a wider match
/// only removes more, or a keep (`include_only`), where it would let more through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PatternUse {
    Remove,
    Keep,
}

/// The environment-name semantics a child environment is built for. Windows names are
/// case-insensitive (`Path` and `PATH` are one variable); Unix names are exact. A parameter rather
/// than a `cfg!` so the Windows rules run under the Linux unit tests too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnvPlatform {
    Unix,
    Windows,
}

impl EnvPlatform {
    /// The platform this process runs on.
    pub(crate) const fn host() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else {
            Self::Unix
        }
    }

    fn core_vars(self) -> &'static [&'static str] {
        match self {
            Self::Unix => UNIX_CORE_ENV_VARS,
            Self::Windows => WINDOWS_CORE_ENV_VARS,
        }
    }

    /// Whether `a` and `b` name the same variable on this platform: byte-exact on Unix; on
    /// Windows the ordinal ignore-case equality Windows itself applies, Unicode case included
    /// ([`fuigo_secrets::child_env::windows_env_names_equal`]), so `\u{f6}auth` is `\u{d6}AUTH`.
    pub(crate) fn same_name(self, a: &str, b: &str) -> bool {
        match self {
            Self::Unix => a == b,
            Self::Windows => fuigo_secrets::child_env::windows_env_names_equal(a, b),
        }
    }

    /// [`same_name`](Self::same_name) for `OsStr` names; a name that is not UTF-8 matches only
    /// itself.
    pub(crate) fn same_os_name(self, a: &std::ffi::OsStr, b: &std::ffi::OsStr) -> bool {
        match (a.to_str(), b.to_str()) {
            (Some(a), Some(b)) => self.same_name(a, b),
            _ => a == b,
        }
    }

    /// Whether `name` is one of this platform's core variables (`inherit = "core"`).
    fn is_core(self, name: &str) -> bool {
        self.core_vars().iter().any(|core| self.same_name(core, name))
    }

    /// Whether the policy glob `pattern` matches `name`. Unix: the glob as compiled (case-
    /// insensitive, as it always was). Windows: also when the pattern's literals and the name agree
    /// under Windows' own name equality, folded on BOTH sides, so `AP\u{131}_*` matches `API_AUTH`
    /// and `API_*` matches `AP\u{131}_AUTH` (the glob's own fold is per-character lowercase, which
    /// misses such aliases). For a REMOVAL filter (`exclude`, the default excludes) the wider
    /// lower-then-upper fold is added too, so an alias Windows' table might map differently fails
    /// toward removal; `include_only` keeps to Windows' equality, so the wide fold can never keep a
    /// variable in.
    fn pattern_matches(self, pattern: &EnvironmentVariablePattern, name: &str, usage: PatternUse) -> bool {
        if pattern.matches(name) {
            return true;
        }
        if self != Self::Windows || (name.is_ascii() && pattern.pattern_chars().iter().all(char::is_ascii)) {
            return false;
        }
        let source = pattern.pattern();
        // Case-SENSITIVE on the folded forms: both sides are already folded, and the glob's own
        // lowercase fold on top would equate more than Windows does (wrong for `include_only`).
        let folded = |key: fn(&str) -> String| EnvironmentVariablePattern::new(&key(&source)).matches(&key(name));
        folded(fuigo_secrets::child_env::windows_env_name_key)
            || (usage == PatternUse::Remove && folded(fuigo_secrets::child_env::wide_env_name_key))
    }

    /// Whether `env` already carries a variable named `name` (in any spelling the platform treats
    /// as the same name).
    pub(crate) fn contains(self, env: &HashMap<String, String>, name: &str) -> bool {
        match self {
            Self::Unix => env.contains_key(name),
            Self::Windows => env.keys().any(|k| self.same_name(k, name)),
        }
    }

    /// Insert `name=value`, first removing every spelling of `name` the platform treats as equal so
    /// the map keeps exactly one entry per variable.
    fn insert(self, env: &mut HashMap<String, String>, name: &str, value: &str) {
        if self == Self::Windows {
            env.retain(|k, _| !self.same_name(k, name));
        }
        env.insert(name.to_string(), value.to_string());
    }
}

/// Collapse `vars` to one entry per variable name under `platform`'s name semantics. Unix keeps
/// every name (they are distinct variables; a repeated exact name keeps its first value). Windows
/// keeps the FIRST spelling seen in the environment block under one key, with the value
/// `resolve(name)` returns for it (the value the process itself reads for that name, i.e.
/// `std::env::var_os` semantics), falling back to that first entry's value. Without this, a block
/// holding both `Path` and `PATH` handed the child whichever one `HashMap` iteration met last, so
/// on some starts the child's `PATH` was the wrong one and every shell spawn failed with "program
/// not found".
pub(crate) fn collapse_env_names<I, R>(vars: I, platform: EnvPlatform, resolve: R) -> Vec<(String, String)>
where
    I: IntoIterator<Item = (String, String)>,
    R: Fn(&str) -> Option<String>,
{
    let mut out: Vec<(String, String)> = Vec::new();
    for (name, value) in vars {
        if out.iter().any(|(seen, _)| platform.same_name(seen, &name)) {
            continue;
        }
        let value = match platform {
            EnvPlatform::Unix => value,
            EnvPlatform::Windows => resolve(&name).unwrap_or(value),
        };
        out.push((name, value));
    }
    out
}

/// Build the child environment from `policy` and the process env. Uses `vars_os`
/// and skips non-UTF-8 entries so a hostile variable cannot panic at spawn time.
pub(crate) fn create_env(policy: &ShellEnvironmentPolicy) -> HashMap<String, String> {
    let vars = std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)));
    let vars = collapse_env_names(vars, EnvPlatform::host(), |name| {
        std::env::var_os(name).and_then(|v| v.into_string().ok())
    });
    create_env_for(vars, policy, EnvPlatform::host())
}

#[cfg(test)]
pub(crate) fn create_env_from_vars<I>(
    vars: I,
    policy: &ShellEnvironmentPolicy,
) -> HashMap<String, String>
where
    I: IntoIterator<Item = (String, String)>,
{
    create_env_for(vars, policy, EnvPlatform::host())
}

/// The platform-parameterised core of [`create_env`]: `vars` is the inherited environment in
/// block order. Case-variant duplicates are collapsed first (first spelling wins, see
/// [`collapse_env_names`]), so the result holds at most one entry per variable on `platform`.
pub(crate) fn create_env_for<I>(
    vars: I,
    policy: &ShellEnvironmentPolicy,
    platform: EnvPlatform,
) -> HashMap<String, String>
where
    I: IntoIterator<Item = (String, String)>,
{
    let vars = collapse_env_names(vars, platform, |_| None);
    let mut env: HashMap<String, String> = match policy.inherit {
        ShellEnvironmentPolicyInherit::All => vars.into_iter().collect(),
        ShellEnvironmentPolicyInherit::None => HashMap::new(),
        ShellEnvironmentPolicyInherit::Core => {
            vars.into_iter().filter(|(k, _)| platform.is_core(k)).collect()
        }
    };

    // Order matters: default excludes, then `exclude`, then `set`, then
    // `include_only`. `set` lands before `include_only` so an unmatched set name
    // is still dropped. The matchers are shared with `allows` (case-insensitive; on Windows every
    // Unicode-case spelling too). Credentials are matched in every spelling on every platform.
    env.retain(|k, _| !is_provider_credential(k) && !policy.matches_default_exclude(k, platform));
    env.retain(|k, _| !policy.matches_exclude(k, platform));
    // Sorted, so two `set` spellings of one Windows name resolve the same way on every run.
    let mut set: Vec<(&String, &String)> = policy.set.iter().collect();
    set.sort();
    for (k, v) in set {
        platform.insert(&mut env, k, v);
    }
    env.retain(|k, _| policy.matches_include_only(k, platform));

    // Windows resolves executables via PATHEXT; keep it present even under a
    // restrictive policy so commands stay runnable.
    if platform == EnvPlatform::Windows && !platform.contains(&env, "PATHEXT") {
        env.insert("PATHEXT".to_string(), ".COM;.EXE;.BAT;.CMD".to_string());
    }

    env
}

/// Names (inherited or already set on the command) that must be removed from the command because
/// `base` does not carry them. On Windows a name is carried when `base` holds it in any spelling:
/// std's `Command` treats `PATH` and `Path` as one key, so the base value replaces it.
pub(crate) fn names_to_remove<I>(
    names: I,
    base: &HashMap<String, String>,
    platform: EnvPlatform,
) -> Vec<std::ffi::OsString>
where
    I: IntoIterator<Item = std::ffi::OsString>,
{
    names
        .into_iter()
        .filter(|name| !name.to_str().is_some_and(|name| platform.contains(base, name)))
        .collect()
}

/// Remove the command's inherited env (by name, see below) and install the policy-derived base env.
/// `active` must already be noop-filtered; `None` leaves the command untouched.
/// The one base-env code path, shared by the public entry point and the spawn
/// sites.
pub(crate) fn install_policy_base_env(
    cmd: &mut tokio::process::Command,
    active: Option<&ShellEnvironmentPolicy>,
) {
    if let Some(policy) = active {
        // Not `env_clear()`: a clear is invisible to `Command::get_envs`, so the per-command
        // sandbox (which rebuilds the command from its program, args, dir and env edits, and
        // reads the environment the child will have through `sandbox_launch::child_env`) would see
        // the whole inherited environment come back. Every inherited name the base does not carry
        // is removed by name instead, which both of them observe; the child's environment is the
        // same set either way.
        let base = create_env(policy);
        install_base_env_for(cmd, std::env::vars_os().map(|(name, _)| name), base, EnvPlatform::host());
    }
}

/// The platform-parameterised core of [`install_policy_base_env`]: remove every name in
/// `inherited` (and every name `cmd` already set) that `base` does not carry, then set `base`.
pub(crate) fn install_base_env_for(
    cmd: &mut tokio::process::Command,
    inherited: impl IntoIterator<Item = std::ffi::OsString>,
    base: HashMap<String, String>,
    platform: EnvPlatform,
) {
    // Inherited names and any the command already set (a clear drops those too)
    let mut names: std::collections::BTreeSet<std::ffi::OsString> = inherited.into_iter().collect();
    names.extend(cmd.as_std().get_envs().map(|(name, _)| name.to_os_string()));
    for name in names_to_remove(names, &base, platform) {
        cmd.env_remove(&name);
    }
    cmd.envs(base);
}

/// Install the policy-derived base env on `cmd` (clearing inherited env first);
/// `None` uses the default policy. Call before any other
/// `.env`/`.envs`.
pub fn apply_shell_environment_policy(
    cmd: &mut tokio::process::Command,
    policy: Option<&ShellEnvironmentPolicy>,
) {
    let default_policy = ShellEnvironmentPolicy::default();
    let policy = policy.unwrap_or(&default_policy);
    install_policy_base_env(cmd, Some(policy).filter(|p| !p.is_noop()));
}

#[cfg(test)]
pub(crate) fn t05_fresh_process(test_name: &str) -> bool {
    if std::env::var("T05_CHILD_TEST").as_deref() == Ok(test_name) {
        return false;
    }
    let home = tempfile::tempdir().unwrap();
    std::fs::write(home.path().join(".bashrc"), "export OpEnAi_ApI_KeY=fake-rc\nexport T05_BENIGN=kept\nalias t05_alias='printf alias-ok'\nt05_fn() { printf function-ok; }\n").unwrap();
    let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
    cmd.arg(test_name)
        .args(["--test-threads=1", "--nocapture"])
        .env("T05_CHILD_TEST", test_name)
        .env("HOME", home.path())
        .env("FUIGO_HOME", home.path().join(".fuigo"))
        .env("SHELL", "/bin/bash")
        .env("FUIGO_LOGIN_ENV", "1");
    for name in credential_env_names() {
        cmd.env(name, "fake-t05-ambient");
    }
    let output = cmd.output().unwrap();
    assert!(
        output.status.success(),
        "isolated T05 child test failed: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    true
}

/// P86: credential names the parent-environment probes plant in the PARENT process. Literal on
/// purpose: a probe that read the denylist to decide what to plant would plant nothing once the
/// denylist was emptied, and pass. `FLUX_API_KEY` (FluxRouter, the lead provider) and
/// `ANTHROPIC_AUTH_TOKEN` are the two CB-1 found missing.
#[cfg(test)]
pub(crate) const P86_PLANTED: &[&str] = &[
    "FLUX_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "FUIGO_API_KEY",
    "OPENAI_API_KEY",
    P86_CONFIGURED,
];

/// A name no provider uses: on the denylist only because the probe child registers it, the way
/// the config loader registers a user's `env_key`.
#[cfg(test)]
pub(crate) const P86_CONFIGURED: &str = "P86_CORP_KEY";

/// Shell test a P86 probe child runs: the benign parent variable arrived (so the probe really
/// inherits the parent environment) and none of [`P86_PLANTED`] did.
#[cfg(test)]
pub(crate) const P86_CHILD_CHECK: &str = "test \"$P86_BENIGN\" = kept && test -z \"${FLUX_API_KEY+x}${ANTHROPIC_AUTH_TOKEN+x}${FUIGO_API_KEY+x}${OPENAI_API_KEY+x}${P86_CORP_KEY+x}\"";

/// Re-run `test_name` in a fresh test process whose OWN environment holds every
/// [`P86_PLANTED`] credential plus `P86_BENIGN=kept` (returns `true` in the parent, which must
/// then return; `false` in the child, which runs the body). The child's `HOME` is a temp dir
/// whose `.bashrc` (sourced by `.bash_profile`) exports `GROQ_API_KEY` and `P86_RC_BENIGN=kept`,
/// so the login-capture and persistent routes see an rc-only credential too.
/// The parent asserts the child ran exactly one test, so a filter that matched nothing cannot
/// pass vacuously.
#[cfg(test)]
pub(crate) fn p86_parent_env(test_name: &str) -> bool {
    if std::env::var("P86_CHILD_TEST").as_deref() == Ok(test_name) {
        register_credential_env_names([P86_CONFIGURED]);
        return false;
    }
    let home = tempfile::tempdir().unwrap();
    // `GROQ_API_KEY` is exported ONLY by the rc file (not planted in the parent), so the
    // login-capture and persistent-shell filters are what must drop it; `P86_RC_BENIGN` proves the
    // rc file was really read. `.bash_profile` because the persistent shell starts as a login shell.
    std::fs::write(
        home.path().join(".bashrc"),
        "export GROQ_API_KEY=fake-p86-rc\nexport P86_RC_BENIGN=kept\n",
    )
    .unwrap();
    std::fs::write(home.path().join(".bash_profile"), ". \"$HOME/.bashrc\"\n").unwrap();
    let mut cmd = std::process::Command::new(std::env::current_exe().unwrap());
    cmd.arg(test_name)
        .args(["--test-threads=1", "--nocapture"])
        .env("P86_CHILD_TEST", test_name)
        .env("HOME", home.path())
        .env("FUIGO_HOME", home.path().join(".fuigo"))
        .env("SHELL", "/bin/bash")
        .env("FUIGO_LOGIN_ENV", "1")
        .env("P86_BENIGN", "kept")
        // In the parent env but registered by no one until a test does so mid-run.
        .env("P86_LATE_KEY", "fake-p86-ambient")
        // Only the rc file may provide these, whatever the runner's environment holds.
        .env_remove("GROQ_API_KEY")
        .env_remove("P86_RC_BENIGN");
    for name in P86_PLANTED {
        cmd.env(name, "fake-p86-ambient");
    }
    let output = cmd.output().unwrap();
    let stdout = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
    .replace("fake-p86-", "[redacted]-");
    assert!(
        output.status.success(),
        "isolated P86 child test failed: {stdout}"
    );
    assert!(
        stdout.contains("test result: ok. 1 passed"),
        "the P86 child must run exactly one test: {stdout}"
    );
    true
}

#[cfg(test)]
#[path = "shell_env_policy_tests.rs"]
mod tests;

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
    fn matches_default_exclude(&self, name: &str) -> bool {
        !self.ignore_default_excludes && DEFAULT_SECRET_EXCLUDES.iter().any(|p| p.matches(name))
    }

    fn matches_exclude(&self, name: &str) -> bool {
        self.exclude.iter().any(|p| p.matches(name))
    }

    /// True if `include_only` is empty (all admitted) or `name` matches it.
    fn matches_include_only(&self, name: &str) -> bool {
        self.include_only.is_empty() || self.include_only.iter().any(|p| p.matches(name))
    }

    /// Whether `name` survives the name filters (default excludes, `exclude`,
    /// `include_only`), ignoring `inherit`/`set`. Used to filter variables layered
    /// in after the policy base, e.g. login-shell capture. Shares its matchers
    /// with [`create_env_from_vars`] so the two cannot drift.
    pub fn allows(&self, name: &str) -> bool {
        !is_provider_credential(name)
            && !self.matches_default_exclude(name)
            && !self.matches_exclude(name)
            && self.matches_include_only(name)
    }

    /// Like [`allows`](Self::allows) but also honors `inherit`: `none` admits
    /// nothing, `core` admits only core names, `all` defers to `allows`.
    pub fn allows_with_inherit(&self, name: &str) -> bool {
        match self.inherit {
            ShellEnvironmentPolicyInherit::None => return false,
            ShellEnvironmentPolicyInherit::Core => {
                if !CORE_ENV_VARS
                    .iter()
                    .any(|core| core.eq_ignore_ascii_case(name))
                {
                    return false;
                }
            }
            ShellEnvironmentPolicyInherit::All => {}
        }
        self.allows(name)
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

/// "Core" variables retained under [`ShellEnvironmentPolicyInherit::Core`].
#[cfg(not(target_os = "windows"))]
const CORE_ENV_VARS: &[&str] = &[
    "PATH", "SHELL", "TMPDIR", "TEMP", "TMP", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "LOGNAME",
    "USER",
];
#[cfg(target_os = "windows")]
const CORE_ENV_VARS: &[&str] = &[
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

/// Build the child environment from `policy` and the process env. Uses `vars_os`
/// and skips non-UTF-8 entries so a hostile variable cannot panic at spawn time.
pub(crate) fn create_env(policy: &ShellEnvironmentPolicy) -> HashMap<String, String> {
    let vars = std::env::vars_os()
        .filter_map(|(k, v)| Some((k.into_string().ok()?, v.into_string().ok()?)));
    create_env_from_vars(vars, policy)
}

pub(crate) fn create_env_from_vars<I>(
    vars: I,
    policy: &ShellEnvironmentPolicy,
) -> HashMap<String, String>
where
    I: IntoIterator<Item = (String, String)>,
{
    let mut env: HashMap<String, String> = match policy.inherit {
        ShellEnvironmentPolicyInherit::All => vars.into_iter().collect(),
        ShellEnvironmentPolicyInherit::None => HashMap::new(),
        ShellEnvironmentPolicyInherit::Core => vars
            .into_iter()
            .filter(|(k, _)| {
                CORE_ENV_VARS
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(k))
            })
            .collect(),
    };

    // Order matters: default excludes, then `exclude`, then `set`, then
    // `include_only`. `set` lands before `include_only` so an unmatched set name
    // is still dropped. The matchers are shared with `allows`.
    env.retain(|k, _| !is_provider_credential(k) && !policy.matches_default_exclude(k));
    env.retain(|k, _| !policy.matches_exclude(k));
    for (k, v) in &policy.set {
        env.insert(k.clone(), v.clone());
    }
    env.retain(|k, _| policy.matches_include_only(k));

    // Windows resolves executables via PATHEXT; keep it present even under a
    // restrictive policy so commands stay runnable.
    if cfg!(target_os = "windows") && !env.keys().any(|k| k.eq_ignore_ascii_case("PATHEXT")) {
        env.insert("PATHEXT".to_string(), ".COM;.EXE;.BAT;.CMD".to_string());
    }

    env
}

/// Clear the command's inherited env and install the policy-derived base env.
/// `active` must already be noop-filtered; `None` leaves the command untouched.
/// The one base-env code path, shared by the public entry point and the spawn
/// sites.
pub(crate) fn install_policy_base_env(
    cmd: &mut tokio::process::Command,
    active: Option<&ShellEnvironmentPolicy>,
) {
    if let Some(policy) = active {
        cmd.env_clear();
        cmd.envs(create_env(policy));
    }
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

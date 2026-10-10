//! Requirements layers and fail-closed enforcement.

use std::path::{Path, PathBuf};

use crate::env_bool;
use crate::loader::{apply_version_overrides_with_registered, load_toml_file};
use crate::paths::{system_config_dir, user_fuigo_home};
use crate::version_overrides::{VersionOverrideError, apply_version_overrides};

use prod_mc_cli_chat_proxy_types::FAIL_CLOSED_KEY;

/// `fail_closed` from a requirements table; a non-bool warns once and is treated as false.
fn fail_closed_flag(requirements: &toml::Value) -> bool {
    use prod_mc_cli_chat_proxy_types::{FailClosedFlag, fail_closed_flag_status_from_value};
    let status = fail_closed_flag_status_from_value(requirements);
    if matches!(status, FailClosedFlag::Invalid) {
        static WARN_ONCE: std::sync::Once = std::sync::Once::new();
        WARN_ONCE.call_once(|| {
            tracing::warn!(
                "requirements fail_closed is present but not a boolean \
                 (e.g. fail_closed = \"true\"); treating as false - use fail_closed = true"
            );
        });
    }
    status.is_enabled()
}

/// Env override for [`FAIL_CLOSED_KEY`]; only applies to `requirements.toml`.
/// The name shares the `FUIGO_MANAGED_CONFIG_URL` prefix.
pub(crate) const FAIL_CLOSED_ENV: &str = "FUIGO_MANAGED_CONFIG_FAIL_CLOSED";

/// Where a requirements layer came from: a file on disk, or the macOS MDM managed-preferences layer (admin-forced, no file).
/// The typed split keeps a caller from calling `exists()` on or reading a layer that has no path.
#[derive(Debug, Clone)]
pub enum RequirementsSource {
    File(PathBuf),
    Mdm,
}

impl RequirementsSource {
    /// The display and provenance label: a file path string, or the synthetic MDM source id (`ai.x.grok:…`).
    /// For diagnostics and matching only; the MDM layer has no file, so this is a label (`Cow<str>`), never a `Path` to open.
    pub fn label(&self) -> std::borrow::Cow<'_, str> {
        match self {
            Self::File(p) => p.to_string_lossy(),
            Self::Mdm => std::borrow::Cow::Borrowed(crate::macos_managed::MDM_REQUIREMENTS_SOURCE),
        }
    }
}

/// One requirements layer: the parsed TOML and where it came from.
#[derive(Debug, Clone)]
pub struct RequirementsLayer {
    pub value: toml::Value,
    pub source: RequirementsSource,
    /// `true` means the root-owned system layer.
    /// Security decisions must trust this flag, not re-derive it from the source, which is `FUIGO_HOME`-influenced and could carry `..`.
    pub is_system: bool,
}

/// A broken admin policy file this process holds no validated copy of (P183 round 8).
#[derive(Debug, Clone)]
pub struct BrokenAdminFile {
    pub path: PathBuf,
    /// Why it cannot be used (parse error, wrong owner, group/other-writable, unreadable); never a file value.
    pub detail: String,
}

/// The requirements layers that did load, plus every admin file that is broken with no validated copy. The layers already
/// carry [`admin_lockdown_requirements`] for each broken file, so a caller that ignores `broken` still enforces the lock-down.
#[derive(Debug, Clone)]
pub struct RequirementsBroken {
    pub layers: Vec<RequirementsLayer>,
    pub broken: Vec<BrokenAdminFile>,
}

impl std::fmt::Display for RequirementsBroken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, b) in self.broken.iter().enumerate() {
            if i > 0 {
                f.write_str("; ")?;
            }
            write!(
                f,
                "{} ({}): {}",
                display_scrub(&b.path.display().to_string()),
                source_kind(&b.path),
                display_scrub(&b.detail)
            )?;
        }
        Ok(())
    }
}

/// P183 round 9 (Grok r5 H3): the ONE lock-down, for an admin policy source that exists but cannot be trusted and has no
/// validated copy. The requirements path ([`requirements_layers_checked`]), the `managed_config.toml` path and the hook
/// loader all take it from here. A deny-every-tool rule (`[[permission.rules]] action = "deny"`, tool `any`, no pattern) means
/// the keys below cannot matter for what the agent can DO; every key with a stricter value is set anyway. MCP servers,
/// marketplaces, non-managed hooks, project MCP and `models.allowed_models` are locked by the policy engine's handling of
/// the same broken source (P169). [`LOCKDOWN_UNSET`] lists, per remaining typed pin, why no value is stricter.
pub fn lockdown_entries() -> Vec<(String, toml::Value)> {
    use toml::Value::{Array, Boolean, String as S, Table};
    let off = || Boolean(false);
    let mut out: Vec<(String, toml::Value)> = Vec::new();
    for key in REQUIREMENTS_BOOL_FEATURES.iter().chain(REQUIREMENTS_RESOLVE_BOOL_FEATURES) {
        out.push((format!("features.{key}"), off()));
    }
    let mut deny_all = toml::map::Map::new();
    deny_all.insert("action".to_owned(), S("deny".to_owned()));
    for (k, v) in [
        ("permission.rules", Array(vec![Table(deny_all)])),
        ("ui.disable_bypass_permissions_mode", Boolean(true)),
        ("ui.yolo", off()),
        ("ui.remember_tool_approvals", off()),
        ("ui.prompt_suggestions", off()),
        ("sandbox.profile", S("strict".to_owned())),
        ("sandbox.auto_allow_bash", off()),
        ("auto_mode.enabled", off()),
        ("features.telemetry", S("off".to_owned())),
        ("features.codebase_indexing", off()),
        ("features.title_refresh", off()),
        ("cli.auto_update", off()),
        ("diagnostics.crash_handler", off()),
        ("diagnostics.error_reporting", off()),
        ("scheduler.background_loops", off()),
        ("memory.enabled", off()),
        ("subagents.enabled", off()),
        ("managed_mcps.enabled", off()),
        ("tools.respect_gitignore", Boolean(true)),
        ("telemetry.trace_upload", off()),
        ("telemetry.mixpanel_enabled", off()),
        ("telemetry.otel_enabled", off()),
        ("telemetry.otel_log_user_prompts", off()),
        ("telemetry.otel_log_tool_details", off()),
        // No model name can match: every model is refused until the file is fixed
        ("models.allowed_models", Array(vec![S(LOCKDOWN_NO_MODEL.to_owned())])),
    ] {
        out.push((k.to_owned(), v));
    }
    out
}

/// The `managed_config.toml` form of the lock-down: the config-level keys of [`lockdown_entries`] (permission, sandbox, auto
/// mode, the always-approve lock), built by the same function so the two cannot drift.
pub fn admin_lockdown_managed_config() -> toml::Value {
    let keep = |p: &str| {
        ["permission.", "sandbox.", "auto_mode.", "ui."]
            .iter()
            .any(|pre| p.starts_with(pre))
    };
    lockdown_document(lockdown_entries().into_iter().filter(|(p, _)| keep(p)))
}

/// A model name no provider has: `models.allowed_models = [this]` allows nothing.
pub const LOCKDOWN_NO_MODEL: &str = "fuigo-admin-policy-unreadable";

/// Typed pins ([`TYPED_PINS`]) with no lock-down value, and why none is stricter than the deny-every-tool rule. The
/// `lockdown_covers_every_typed_pin` test fails for a pin that is in neither this list nor [`lockdown_entries`].
pub const LOCKDOWN_UNSET: &[(&str, &str)] = &[
    (FAIL_CLOSED_KEY, "meta key, stripped from every layer"),
    ("permission.deny", "the deny-every-tool rule in permission.rules already denies everything; nothing is stricter"),
    ("permission.allow", "no allow list is stricter than none; deny outranks allow"),
    ("permission.ask", "the deny-every-tool rule outranks ask"),
    ("auto_mode.prompt_type", "auto mode is off"),
    ("auto_mode.classifier_model", "auto mode is off"),
    ("auto_mode.classify_timeout_ms", "auto mode is off"),
    ("auto_mode.reasoning_effort", "auto mode is off"),
    ("cli.minimum_version", "a version bound set here could only brick the CLI; no tool runs anyway"),
    ("cli.maximum_version", "as cli.minimum_version"),
    ("cli.required_minimum_version", "as cli.minimum_version"),
    ("cli.required_maximum_version", "as cli.minimum_version"),
    ("cli.use_leader", "cosmetic process model; tools are denied"),
    ("cli.show_tips", "cosmetic"),
    ("cli.channel", "update channel; auto_update is off"),
    ("ui.show_thinking_blocks", "cosmetic"),
    ("ui.group_tool_verbs", "cosmetic"),
    ("ui.collapsed_edit_blocks", "cosmetic"),
    ("toolset.bash.login_shell_capture", "Bash is denied"),
    ("toolset.bash.find_bfs", "Bash is denied"),
    ("toolset.bash.grep_ugrep", "Bash is denied"),
    ("toolset.ask_user_question.timeout_enabled", "no stricter value; tools are denied"),
    ("toolset.ask_user_question.timeout_secs", "no stricter value; tools are denied"),
    ("mcp.startup_timeout_sec", "MCP servers are refused by the policy engine"),
    ("mcp.max_output_bytes", "MCP servers are refused by the policy engine"),
    ("hooks.*", "hooks-only-managed with no managed hooks: the policy engine drops every non-managed hook"),
    ("telemetry.events_url", "telemetry is off"),
    ("telemetry.events_api_key", "telemetry is off"),
    ("telemetry.mixpanel_token", "telemetry is off"),
    ("models.default", "models.allowed_models allows no model"),
    ("models.web_search", "models.allowed_models allows no model"),
    ("endpoints.*", "an endpoint override has no stricter value; remote_fetch, telemetry and trace upload are off and tools are denied"),
];

/// What an admin policy that cannot be read enforces when there is no validated copy: [`lockdown_entries`] as a requirements
/// document.
pub fn admin_lockdown_requirements() -> toml::Value {
    lockdown_document(lockdown_entries())
}

fn lockdown_document(entries: impl IntoIterator<Item = (String, toml::Value)>) -> toml::Value {
    let mut root = toml::Value::Table(toml::map::Map::new());
    for (path, value) in entries {
        let mut table = root.as_table_mut().expect("table");
        let mut parts = path.split('.').peekable();
        while let Some(part) = parts.next() {
            if parts.peek().is_none() {
                table.insert(part.to_owned(), value.clone());
            } else {
                table = table
                    .entry(part.to_owned())
                    .or_insert_with(|| toml::Value::Table(Default::default()))
                    .as_table_mut()
                    .expect("table");
            }
        }
    }
    root
}

/// The admin policy sources that are broken with no validated copy: the system `requirements.toml`, the system
/// `managed_config.toml`, the Claude `managed-settings.json`, and a forced MDM payload. ONE notion of "broken admin source",
/// consumed by `requirements_layers_checked`, `ConfigLayers` (through the lock-down layer), the remote-fetch, crash-handler and
/// worktree-hint sites: none of them can read a broken source as "no layer".
pub fn broken_admin_files() -> Vec<BrokenAdminFile> {
    broken_admin_sources_at(
        system_config_dir().as_deref(),
        crate::paths::claude_managed_settings_probe_path().as_deref(),
        crate::macos_managed::forced_requirements(),
    )
}

pub(crate) fn broken_admin_sources_at(
    dir: Option<&Path>,
    claude_file: Option<&Path>,
    forced_mdm: &Result<Option<toml::Value>, String>,
) -> Vec<BrokenAdminFile> {
    let mut out = Vec::new();
    if let Some(dir) = dir {
        for path in [
            dir.join("requirements.toml"),
            dir.join(crate::loader::MANAGED_CONFIG_FILENAME),
        ] {
            if let AdminSource::Broken(detail) | AdminSource::Locked { detail, .. } =
                admin_source_state(&path, &admin_lockdown_requirements)
            {
                out.push(BrokenAdminFile { path, detail });
            }
        }
    }
    if let Some(path) = claude_file
        && let ManagedSettingsJson::Broken(detail) = managed_settings_json(path)
    {
        out.push(BrokenAdminFile { path: path.to_path_buf(), detail });
    }
    if let Err(detail) = mdm_layer_checked(forced_mdm) {
        out.push(BrokenAdminFile {
            path: PathBuf::from(crate::macos_managed::MDM_REQUIREMENTS_SOURCE),
            detail,
        });
    }
    out
}

/// All loaded requirements layers in apply order (user first, system last). A broken system file with no validated copy is
/// carried as an `Err` (with the layers, which include the lock-down layer); it is never "no policy".
pub fn requirements_layers_checked() -> Result<Vec<RequirementsLayer>, RequirementsBroken> {
    let mut out = Vec::new();
    let mut broken = Vec::new();
    if let Some(user_path) = user_fuigo_home().map(|g| g.join("requirements.toml"))
        && let Some(value) = load_requirements_layer(&user_path)
    {
        out.push(RequirementsLayer {
            value,
            source: RequirementsSource::File(user_path),
            is_system: false,
        });
    }
    if let Some(dir) = system_config_dir() {
        let sys_path = dir.join("requirements.toml");
        match admin_source_state(&sys_path, &admin_lockdown_requirements) {
            AdminSource::Text(src) => {
                if let Some(value) = src.and_then(|s| admin_layer_from_source(&sys_path, &s)) {
                    out.push(RequirementsLayer {
                        value,
                        source: RequirementsSource::File(sys_path),
                        is_system: true,
                    });
                }
            }
            AdminSource::Broken(detail) | AdminSource::Locked { detail, .. } => {
                out.push(RequirementsLayer {
                    value: admin_lockdown_requirements(),
                    source: RequirementsSource::File(sys_path.clone()),
                    is_system: true,
                });
                broken.push(BrokenAdminFile { path: sys_path, detail });
            }
        }
    }
    // macOS MDM: OS-protected admin layer (forced values only)
    // It is pushed last so it wins the deep-merge over the system file and cloud cache
    // It is marked `is_system` so security decisions trust it like the root-owned layer
    // P183 round 9 (Grok r5 M4): a forced payload that does not decode is a broken admin source (lock-down), not no layer
    match mdm_layer_checked(crate::macos_managed::forced_requirements()) {
        Ok(Some(value)) => out.push(RequirementsLayer {
            value,
            source: RequirementsSource::Mdm,
            is_system: true,
        }),
        Ok(None) => {}
        Err(detail) => {
            out.push(RequirementsLayer {
                value: admin_lockdown_requirements(),
                source: RequirementsSource::Mdm,
                is_system: true,
            });
            broken.push(BrokenAdminFile {
                path: PathBuf::from(crate::macos_managed::MDM_REQUIREMENTS_SOURCE),
                detail,
            });
        }
    }
    if broken.is_empty() {
        Ok(out)
    } else {
        Err(RequirementsBroken { layers: out, broken })
    }
}

/// [`requirements_layers_checked`] for callers that cannot refuse: a broken admin file is logged and its lock-down layer
/// is in the result. Never drops the file.
pub fn requirements_layers() -> Vec<RequirementsLayer> {
    requirements_layers_checked().unwrap_or_else(|e| {
        tracing::error!(error = %e, "admin requirements file is broken and was never validated; enforcing the lock-down");
        e.layers
    })
}

/// User and system requirements deep-merged; system wins on conflict.
/// Use for read-only consumers so user pins can't bypass system policy.
pub fn load_merged_requirements() -> Option<toml::Value> {
    let mut iter = requirements_layers().into_iter();
    let mut merged = iter.next()?.value;
    for layer in iter {
        // P183 round 4: a wrong-type higher value cannot erase a lower layer's typed pin
        crate::loader::merge_requirements_toml(&mut merged, &layer.value);
    }
    Some(merged)
}

pub(crate) fn load_requirements() -> Option<toml::Value> {
    load_user_requirements(user_fuigo_home().as_deref())
}

/// User requirements layer from `<home>/requirements.toml`, or `None` with no resolvable user home (rather than reading a cwd-relative `.fuigo`).
fn load_user_requirements(home: Option<&Path>) -> Option<toml::Value> {
    load_requirements_layer(&home?.join("requirements.toml"))
}

pub(crate) fn load_system_requirements() -> Option<toml::Value> {
    let dir = system_config_dir()?;
    load_admin_requirements_layer(&dir.join("requirements.toml"))
}

/// The refusal text for malformed security keys; one wording for startup and every runtime load (P183 round 9, Grok r5 M3).
fn wrong_key_detail(wrong: &[String]) -> String {
    format!(
        "security key(s) of the wrong type: {}. Fix: open the file, set each key to the type the docs list \
         (booleans as true/false, lists of strings as [\"a\", \"b\"]), or delete the key",
        wrong.join(", ")
    )
}

fn last_good_user_layers() -> &'static std::sync::Mutex<std::collections::HashMap<PathBuf, toml::Value>> {
    static LAST: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<PathBuf, toml::Value>>> =
        std::sync::OnceLock::new();
    LAST.get_or_init(Default::default)
}

/// Soft-fails on a file that does not parse; fail-closed enforcement of that lives in [`validate_requirements`].
/// P183 round 9 (Grok r5 M3): a parsing USER file with a malformed security key is refused at startup, and now at every
/// later load too (reload, per-session load, subagent, headless, workspace daemon) with the same message (file, key, fix).
/// The rule at runtime: keep the LAST VALID copy of that file, so its other restrictions stay; if this process never saw a
/// valid copy, fail closed with [`admin_lockdown_requirements`] (startup would have refused the file).
pub(crate) fn load_requirements_layer(path: &Path) -> Option<toml::Value> {
    let v = match load_toml_file(path) {
        Ok(v) if v.as_table().is_some_and(|t| !t.is_empty()) => v,
        _ => return None,
    };
    let value = normalize_requirements_value(v, &path.display().to_string())?;
    let wrong = wrong_type_security_keys(&value);
    if wrong.is_empty() {
        if let Ok(mut m) = last_good_user_layers().lock() {
            m.insert(path.to_path_buf(), value.clone());
        }
        return Some(value);
    }
    let kept = last_good_user_layers()
        .lock()
        .ok()
        .and_then(|m| m.get(path).cloned());
    tracing::error!(
        path = %path.display(),
        kept_last_valid_copy = kept.is_some(),
        "requirements file {} could not be loaded: {}",
        path.display(),
        wrong_key_detail(&wrong)
    );
    Some(kept.unwrap_or_else(admin_lockdown_requirements))
}

/// Strip `fail_closed` and apply `[[version_overrides]]` for a parsed requirements layer (file or MDM), so every source is normalized identically.
///
/// P162: an unparseable `[[version_overrides]]` (bad semver bound, wrong shape) must NOT drop the layer.
/// Dropping it whole would silently lift every pin it carries (`yolo = false`, `[sandbox] profile`, `allowed_models`, ...), which is fail-open for managed policy.
/// Instead the section is discarded (no patch from it is applied, so a half-valid list cannot partially tighten or loosen anything) and the layer's own base pins are kept.
/// The error is loud (`tracing::error!`), and [`validate_requirements`] refuses to start on it for admin-owned layers (system file, MDM) and for any layer with `fail_closed = true`; only a user layer without `fail_closed` runs on its base pins.
pub(crate) fn normalize_requirements_value(
    mut v: toml::Value,
    source: &str,
) -> Option<toml::Value> {
    if let Some(table) = v.as_table_mut() {
        table.remove(FAIL_CLOSED_KEY);
    }
    if let Err(e) = apply_version_overrides_with_registered(&mut v) {
        tracing::error!(
            source = %source,
            error = %e,
            "requirements: invalid version_overrides ignored; the layer's base pins stay in force (admin-owned layers and fail_closed layers refuse to start instead)"
        );
        if let Some(table) = v.as_table_mut() {
            table.remove(crate::version_overrides::VERSION_OVERRIDES_KEY);
        }
    }
    Some(v)
}

/// The MDM layer from the cached forced read: normalized, `None` when nothing is forced, `Err` when a forced payload does
/// not decode (P183 round 9, Grok r5 M4). The seam the tests drive.
pub(crate) fn mdm_layer_checked(
    forced: &Result<Option<toml::Value>, String>,
) -> Result<Option<toml::Value>, String> {
    match forced {
        // P183 round 10 (Grok r6 M): invalid `[[version_overrides]]` in a forced payload are as broken as an undecodable one
        Ok(Some(v)) => mdm_verdict(v.clone()).map(Some),
        Ok(None) => Ok(None),
        Err(e) => Err(e.clone()),
    }
}

/// P183 round 12 (Grok r8): the ONE judgement of an MDM payload, shared by the requirements and policy-sources readers:
/// normalized, then the same wrong-type security-key check the admin files get. `Err` is broken (lock-down).
pub(crate) fn mdm_verdict(v: toml::Value) -> Result<toml::Value, String> {
    let v = normalize_admin_requirements_value(v)?;
    let wrong = wrong_type_security_keys(&v);
    if !wrong.is_empty() {
        return Err(format!("security keys of the wrong type: {}", wrong.join(", ")));
    }
    Ok(v)
}

/// Strict [`normalize_requirements_value`] for ADMIN sources (system file, MDM): invalid `[[version_overrides]]` is an
/// error, not "keep the base pins" (P183 round 9, Grok r5 H1).
pub(crate) fn normalize_admin_requirements_value(
    mut v: toml::Value,
) -> Result<toml::Value, String> {
    if let Some(table) = v.as_table_mut() {
        table.remove(FAIL_CLOSED_KEY);
    }
    apply_version_overrides_with_registered(&mut v)
        .map_err(|e| format!("invalid version_overrides: {e}"))?;
    Ok(v)
}

/// The MDM requirements layer (read and normalized), or `None`. A forced payload that is broken (undecodable, or invalid
/// `[[version_overrides]]`) is the lock-down document, never `None` (P183 round 10, Grok r6 M).
/// Shared so the enforced view and the effective-config view agree.
pub(crate) fn mdm_requirements_value() -> Option<toml::Value> {
    mdm_value_from(crate::macos_managed::forced_requirements())
}

pub(crate) fn mdm_value_from(forced: &Result<Option<toml::Value>, String>) -> Option<toml::Value> {
    match mdm_layer_checked(forced) {
        Ok(v) => v,
        Err(_) => Some(admin_lockdown_requirements()),
    }
}

/// Errors from validating requirements layers at startup.
#[derive(Debug, thiserror::Error)]
pub enum RequirementsError {
    // P183 round 4: the redacted form (index and field only); the Display of the source echoes the raw bound
    #[error(
        "requirements at {} has invalid version_overrides: {}",
        display_scrub(&path.display().to_string()),
        source.redacted()
    )]
    InvalidVersionOverrides {
        path: PathBuf,
        #[source]
        source: VersionOverrideError,
    },
    /// P183: the layer exists but could not be read or parsed at all, so none of its policy can be applied.
    /// `detail` is redacted (location and parser kind, never the offending line).
    #[error(
        "requirements at {} ({}) could not be loaded: {}; refusing to start without its policy",
        display_scrub(&path.display().to_string()),
        source_kind(path),
        display_scrub(detail)
    )]
    Unloadable { path: PathBuf, detail: String },
}

/// P183 round 10: who owns a policy source, for messages. A user must be able to tell "the administrator's file is broken"
/// (not theirs to fix; ask the administrator) from "my own file has a typo".
pub(crate) fn source_kind(path: &Path) -> &'static str {
    let admin = path == Path::new(crate::macos_managed::MDM_REQUIREMENTS_SOURCE)
        || system_config_dir().is_some_and(|d| path.starts_with(d))
        || crate::paths::claude_managed_settings_probe_path().is_some_and(|p| p == path);
    if admin {
        "the administrator's policy file; ask your administrator, you cannot fix it yourself"
    } else {
        "your own file"
    }
}

#[cfg(test)] // P183: startup goes through `validate_requirements_from`; kept for the P162 tests
/// `Ok(())` unless the layer is refused: invalid `[[version_overrides]]` under fail_closed or in an admin-owned layer (P162), or
/// (P183) a file that exists but cannot be read or parsed, when admin-owned or fail_closed. A user layer that is merely broken
/// warns instead; see [`validate_requirements_file`].
pub(crate) fn validate_requirements_layer(
    path: &Path,
    admin_owned: bool,
) -> Result<(), RequirementsError> {
    validate_requirements_file(path, admin_owned, env_bool(FAIL_CLOSED_ENV)).map(|_| ())
}

/// Fail-closed `[[version_overrides]]` validation for a parsed requirements layer (file or MDM).
/// P162: an admin-owned layer is refused on invalid overrides even without `fail_closed`.
/// Evaluating only its base could be LESS strict than the policy the admin wrote (a version patch may be the tightening one), so no safe partial policy exists; the loader's keep-base fallback is for non-startup consumers only.
/// Reads `fail_closed` before applying overrides so a broken patch can't disable enforcement mid-load.
/// `source` is the provenance label in the error.
fn validate_requirements_value(
    mut v: toml::Value,
    source: &RequirementsSource,
    admin_owned: bool,
) -> Result<(), RequirementsError> {
    if v.as_table().is_none_or(|t| t.is_empty()) {
        return Ok(());
    }
    let fail_closed = admin_owned || resolve_fail_closed_mode(&v);
    // P183: `policy_semver`, not `installed_semver`: a garbage FUIGO_TEST_VERSION used to return Ok here and skip validation
    let version = match crate::loader::policy_semver() {
        Ok(v) => v,
        Err(e) if fail_closed => {
            return Err(RequirementsError::Unloadable {
                path: PathBuf::from(source.label().as_ref()),
                detail: format!(
                    "this build's version is not semver ({e}), so version_overrides cannot be checked"
                ),
            });
        }
        Err(_) => return Ok(()),
    };
    if let Err(e) = apply_version_overrides(&mut v, &version)
        && fail_closed
    {
        return Err(RequirementsError::InvalidVersionOverrides {
            path: PathBuf::from(source.label().as_ref()),
            source: e,
        });
    }
    // P183 round 4: an admin-owned security key of the wrong type would be ignored by its reader, lifting the pin.
    // Round 8 (Sean, 2026-10-08): a user file that parses but has a malformed key refuses too, whether or not it sets
    // fail_closed; the message names the file and each key and says how to fix it
    let wrong = wrong_type_security_keys(&v);
    if !wrong.is_empty() {
        return Err(RequirementsError::Unloadable {
            path: PathBuf::from(source.label().as_ref()),
            detail: format!(
                "{}",
                wrong_key_detail(&wrong)
            ),
        });
    }
    Ok(())
}

/// The `[features]` keys requirements pin as booleans: the feature registry (`fuigo_config_types::registry::FEATURES`, which
/// depends on this crate, so a test there keeps this list in step) plus the media pins read by `apply_requirements`.
pub const REQUIREMENTS_BOOL_FEATURES: &[&str] = &[
    "session_search",
    "lsp_tools",
    "web_fetch",
    "session_recap",
    "ask_user_question",
    "voice_mode",
    "write_file",
    "feedback",
    "feedback_trace_card",
    "turn_summary",
    "cancel_rewind",
    "compaction_verbatim_input",
    "two_pass_compaction",
    "backend_tools",
    "auto_wake",
    "subagent_worktree_snapshot",
    "active_agent_messages",
    "repo_status_in_system_prompt",
    "terminal_theme",
    "image_gen",
    "image_edit",
    "video_gen",
];

/// P183 round 6: the `[features]` bools read from requirements outside the feature registry, by fuigo-shell `resolve/*`
/// (`remote_fetch` in `features.rs` defaults ON when its pin is dropped, so it matters most).
pub const REQUIREMENTS_RESOLVE_BOOL_FEATURES: &[&str] = &[
    "remote_fetch",
    "zdr_access_enabled",
    "turn_transient_retry",
    "mcp_liveness_watchers",
    "mcp_auto_restart",
    "mcp_push_server_status",
    "mcp_recursive_config_watch",
];

/// The type a typed requirements pin must have ([`TYPED_PINS`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PinType {
    Bool,
    Str,
    Int,
    Table,
    /// An array of strings (`permission.{deny,allow,ask}`).
    StrArray,
    /// `features.telemetry`: a bool, a mode string `TelemetryMode::parse` accepts ([`TELEMETRY_MODE_STRINGS`]), or a table
    /// (the `version_overrides` patch shape, round 5).
    Telemetry,
    /// `features.codebase_indexing`: a bool or an array of glob strings (`CodebaseIndexingSetting` in fuigo-shell).
    CodebaseIndexing,
    /// `permission.rules`: an array of [`permission_rule_shape_ok`] tables.
    PermissionRules,
    /// One `[hooks]` event: [`hook_event_shape_ok`].
    HookEvent,
}

impl PinType {
    fn accepts(self, value: &toml::Value) -> bool {
        let strings = |v: &toml::Value| {
            v.as_array()
                .is_some_and(|a| a.iter().all(toml::Value::is_str))
        };
        match self {
            Self::Bool => value.is_bool(),
            Self::Str => value.is_str(),
            Self::Int => value.is_integer(),
            Self::Table => value.is_table(),
            Self::StrArray => strings(value),
            Self::Telemetry => {
                value.is_bool()
                    || value.is_table()
                    || value.as_str().is_some_and(|s| {
                        TELEMETRY_MODE_STRINGS.contains(&s.trim().to_ascii_lowercase().as_str())
                    })
            }
            Self::CodebaseIndexing => value.is_bool() || strings(value),
            Self::PermissionRules => value
                .as_array()
                .is_some_and(|a| a.iter().all(permission_rule_shape_ok)),
            Self::HookEvent => hook_event_shape_ok(value),
        }
    }
}

/// The `features.telemetry` strings `fuigo_telemetry::TelemetryMode::parse` accepts (after trim and lowercase); a test in
/// fuigo-shell keeps this list in step. An unknown string was a silently ignored pin (env could turn telemetry back on).
pub const TELEMETRY_MODE_STRINGS: &[&str] = &[
    "1",
    "true",
    "yes",
    "on",
    "enabled",
    "full",
    "0",
    "false",
    "no",
    "off",
    "disabled",
    "session-metrics",
    "session_metrics",
];

/// P183 rounds 4-7: every typed requirements pin, by dotted path (`*` matches any one key), with the type its reader takes.
/// A pin of the wrong type would be skipped by that reader, lifting the pin; so an admin-owned layer (system file, MDM, the
/// system `managed_config.toml`) or a fail_closed layer refuses to start on one, a rewrite after startup keeps the last
/// validated copy, and among requirements layers a wrong-type higher value never erases a lower typed pin. The
/// `[features]` bools from [`REQUIREMENTS_BOOL_FEATURES`] and [`REQUIREMENTS_RESOLVE_BOOL_FEATURES`] are pins too.
/// Round 7 sweep: the readers are fuigo-shell `config::apply_requirements` (`req_bool`/`req_str`), `util/config/resolve/*`,
/// `agent::config` (`SyncBoolFlag`, external OTEL), fuigo-workspace `permission::resolution` (`[permission]`, the
/// always-approve lock), fuigo-hooks (`[hooks]`), and `VersionPolicy` (`cli` bounds). The receipt has the full table, with
/// the keys judged not to be pins and why (`ui.display_refresh`: tolerant reader, redraw cadence only).
pub(crate) const TYPED_PINS: &[(&str, PinType)] = &[
    (FAIL_CLOSED_KEY, PinType::Bool),
    // Sections
    ("ui", PinType::Table),
    ("features", PinType::Table),
    ("sandbox", PinType::Table),
    ("auto_mode", PinType::Table),
    ("cli", PinType::Table),
    ("mcp", PinType::Table),
    ("diagnostics", PinType::Table),
    ("scheduler", PinType::Table),
    ("toolset", PinType::Table),
    ("permission", PinType::Table),
    ("hooks", PinType::Table),
    ("telemetry", PinType::Table),
    ("models", PinType::Table),
    ("memory", PinType::Table),
    ("subagents", PinType::Table),
    ("managed_mcps", PinType::Table),
    ("tools", PinType::Table),
    ("endpoints", PinType::Table),
    // Round 4: the always-approve lock, sandbox and auto mode
    ("ui.disable_bypass_permissions_mode", PinType::Bool),
    ("ui.yolo", PinType::Bool),
    ("sandbox.auto_allow_bash", PinType::Bool),
    ("sandbox.profile", PinType::Str),
    ("auto_mode.enabled", PinType::Bool),
    // Round 7 sweep: the classifier settings; one wrong-type field dropped the whole `[auto_mode]` table to defaults
    ("auto_mode.prompt_type", PinType::Str),
    ("auto_mode.classifier_model", PinType::Str),
    ("auto_mode.classify_timeout_ms", PinType::Int),
    ("auto_mode.reasoning_effort", PinType::Str),
    // Round 5
    ("features.telemetry", PinType::Telemetry),
    ("features.codebase_indexing", PinType::CodebaseIndexing),
    // Round 6 (resolve/*)
    ("cli.minimum_version", PinType::Str),
    ("cli.maximum_version", PinType::Str),
    ("cli.required_minimum_version", PinType::Str),
    ("cli.required_maximum_version", PinType::Str),
    ("diagnostics.crash_handler", PinType::Bool),
    ("scheduler.background_loops", PinType::Bool),
    ("ui.remember_tool_approvals", PinType::Bool),
    ("ui.prompt_suggestions", PinType::Bool),
    ("ui.show_thinking_blocks", PinType::Bool),
    ("ui.group_tool_verbs", PinType::Bool),
    ("ui.collapsed_edit_blocks", PinType::Bool),
    ("toolset.bash.login_shell_capture", PinType::Bool),
    ("toolset.bash.find_bfs", PinType::Bool),
    ("toolset.bash.grep_ugrep", PinType::Bool),
    ("toolset.ask_user_question.timeout_enabled", PinType::Bool),
    ("toolset.ask_user_question.timeout_secs", PinType::Int),
    ("mcp.startup_timeout_sec", PinType::Int),
    ("mcp.max_output_bytes", PinType::Int),
    // Round 7 (Grok r4 H1): `[permission]` as fuigo-workspace reads it
    ("permission.deny", PinType::StrArray),
    ("permission.allow", PinType::StrArray),
    ("permission.ask", PinType::StrArray),
    ("permission.rules", PinType::PermissionRules),
    // Round 7 (Grok r4 H2, M4): `[hooks]` events as fuigo-hooks decodes them
    ("hooks.*", PinType::HookEvent),
    // Round 7 (Grok r4 M5): Sentry is initialized from this flag
    ("diagnostics.error_reporting", PinType::Bool),
    // Round 7 sweep: `apply_requirements` (`req_bool` / `req_str`) and the external OTEL pins
    ("features.title_refresh", PinType::Bool),
    ("telemetry.trace_upload", PinType::Bool),
    ("telemetry.mixpanel_enabled", PinType::Bool),
    ("telemetry.otel_enabled", PinType::Bool),
    ("telemetry.otel_log_user_prompts", PinType::Bool),
    ("telemetry.otel_log_tool_details", PinType::Bool),
    ("telemetry.events_url", PinType::Str),
    ("telemetry.events_api_key", PinType::Str),
    ("telemetry.mixpanel_token", PinType::Str),
    ("cli.auto_update", PinType::Bool),
    ("cli.use_leader", PinType::Bool),
    ("cli.show_tips", PinType::Bool),
    ("cli.channel", PinType::Str),
    ("memory.enabled", PinType::Bool),
    ("subagents.enabled", PinType::Bool),
    ("managed_mcps.enabled", PinType::Bool),
    ("tools.respect_gitignore", PinType::Bool),
    ("models.default", PinType::Str),
    ("models.web_search", PinType::Str),
    ("endpoints.fuigo_api_base_url", PinType::Str),
    ("endpoints.cli_chat_proxy_base_url", PinType::Str),
    ("endpoints.models_base_url", PinType::Str),
    ("endpoints.models_list_url", PinType::Str),
    ("endpoints.trace_upload_url", PinType::Str),
    ("endpoints.feedback_base_url", PinType::Str),
    ("endpoints.deployment_key", PinType::Str),
    ("endpoints.trace_upload_bucket", PinType::Str),
    ("endpoints.trace_upload_region", PinType::Str),
    ("endpoints.trace_upload_credentials_file", PinType::Str),
    ("endpoints.trace_upload_endpoint_url", PinType::Str),
    ("endpoints.trace_upload_credentials", PinType::Str),
];

/// The pin type of the key at `path` ([`TYPED_PINS`] and the `[features]` bool lists), or `None` if it is not a pin.
pub(crate) fn pin_type(path: &[String]) -> Option<PinType> {
    let pin = TYPED_PINS.iter().find(|(pattern, _)| {
        let mut parts = pattern.split('.');
        let matched = path
            .iter()
            .all(|key| parts.next().is_some_and(|p| p == "*" || p == key));
        matched && parts.next().is_none()
    });
    if let Some((_, ty)) = pin {
        return Some(*ty);
    }
    match path {
        [section, key]
            if section == "features"
                && (REQUIREMENTS_BOOL_FEATURES.contains(&key.as_str())
                    || REQUIREMENTS_RESOLVE_BOOL_FEATURES.contains(&key.as_str())) =>
        {
            Some(PinType::Bool)
        }
        _ => None,
    }
}

/// Whether `value` has a type the requirements reader of the key at `path` accepts; `None` for keys that are not pins.
pub(crate) fn security_key_type_ok(path: &[String], value: &toml::Value) -> Option<bool> {
    pin_type(path).map(|ty| ty.accepts(value))
}

/// P183 round 7: the `[permission]` rule fields fuigo-workspace decodes (`RuleAction`, `ToolFilter`, `PatternMode`, all
/// `rename_all = "lowercase"`); a test there decodes every name here, so the lists cannot drift.
pub const PERMISSION_RULE_ACTIONS: &[&str] = &["allow", "deny", "ask"];
pub const PERMISSION_RULE_TOOLS: &[&str] = &[
    "any",
    "bash",
    "edit",
    "read",
    "grep",
    "mcp",
    "webfetch",
    "websearch",
    "agent_message",
    "agentmessage",
];
pub const PERMISSION_PATTERN_MODES: &[&str] = &["glob", "domain"];

/// One `[[permission.rules]]` entry in the shape fuigo-workspace's `PermissionRule` decodes: `action` required; `tool`,
/// `pattern` and `pattern_mode` optional; each a string (the enums from the lists above). One bad entry fails the whole
/// `rules` decode, which dropped every rule of that layer.
pub fn permission_rule_shape_ok(rule: &toml::Value) -> bool {
    let one_of =
        |v: &toml::Value, names: &[&str]| v.as_str().is_some_and(|s| names.contains(&s));
    rule.as_table().is_some_and(|t| {
        t.get("action")
            .is_some_and(|v| one_of(v, PERMISSION_RULE_ACTIONS))
            && t.get("tool")
                .is_none_or(|v| one_of(v, PERMISSION_RULE_TOOLS))
            && t.get("pattern").is_none_or(toml::Value::is_str)
            && t.get("pattern_mode")
                .is_none_or(|v| one_of(v, PERMISSION_PATTERN_MODES))
    })
}

/// P183 round 7 (Grok r4 M4): the shape fuigo-hooks decodes one `[hooks]` event into (`Vec<MatcherGroup>`): an array of
/// tables, each with an optional string `matcher` and a `hooks` array of handler tables (`type` a string; `command` and `url`
/// strings, `timeout` a non-negative integer, `env` a table of strings, all optional). fuigo-config cannot depend on
/// fuigo-hooks; the test `config_hook_shape_matches_strict_parse_p183r7` there keeps the two in step.
pub fn hook_event_shape_ok(value: &toml::Value) -> bool {
    type Table = toml::map::Map<String, toml::Value>;
    fn opt(t: &Table, key: &str, ok: impl Fn(&toml::Value) -> bool) -> bool {
        t.get(key).is_none_or(ok)
    }
    let handler_ok = |h: &toml::Value| {
        h.as_table().is_some_and(|h| {
            h.get("type").is_some_and(toml::Value::is_str)
                && opt(h, "command", toml::Value::is_str)
                && opt(h, "url", toml::Value::is_str)
                && opt(h, "timeout", |v| v.as_integer().is_some_and(|n| n >= 0))
                && opt(h, "env", |v| {
                    v.as_table()
                        .is_some_and(|e| e.values().all(toml::Value::is_str))
                })
        })
    };
    value.as_array().is_some_and(|groups| {
        groups.iter().all(|g| {
            g.as_table().is_some_and(|g| {
                opt(g, "matcher", toml::Value::is_str)
                    && g.get("hooks")
                        .and_then(toml::Value::as_array)
                        .is_some_and(|hs| hs.iter().all(handler_ok))
            })
        })
    })
}

/// The dotted names of the type-checked keys in `v` whose type is wrong ([`security_key_type_ok`]); values are never echoed.
fn wrong_type_security_keys(v: &toml::Value) -> Vec<String> {
    fn walk(v: &toml::Value, path: &mut Vec<String>, wrong: &mut Vec<String>) {
        let Some(table) = v.as_table() else {
            return;
        };
        for (key, value) in table {
            path.push(key.clone());
            match security_key_type_ok(path, value) {
                Some(false) => wrong.push(path.join(".")),
                // P183 round 6: every table is descended into at any depth (`toolset.bash.*` is three deep, under an
                // unchecked `toolset.bash` table); checked keys exist only under the checked sections
                Some(true) | None if value.is_table() => walk(value, path, wrong),
                _ => {}
            }
            path.pop();
        }
    }
    let mut wrong = Vec::new();
    walk(v, &mut Vec::new(), &mut wrong);
    wrong
}

/// P183 round 7 (Grok r4 H3): the policy keys of Claude's `managed-settings.json` that Fuigo reads, checked by type. Before,
/// a present key of the wrong type was read as absent: an object `deniedMcpServers` or `strictKnownMarketplaces` lifted the
/// restriction, and a `permissions` object that failed its decode dropped every rule. Returns the dotted names of the wrong
/// keys (values are never echoed).
/// - root: an object;
/// - `env`: an object whose values are strings, booleans or numbers (`json_env_flag` reads `DISABLE_*` flags from it);
/// - `permissions`: an object; `permissions.{allow,deny,ask}` arrays of strings; `permissions.defaultMode`,
///   `permissions.disableBypassPermissionsMode` and the legacy root `defaultMode` strings;
/// - `allowedMcpServers`, `deniedMcpServers`: arrays of objects, each with at least one of `serverUrl`, `command`,
///   `serverName` (strings) or `serverCommand` (a non-empty array of strings), and each of those it has of that type;
/// - `strictKnownMarketplaces`: an array of objects with a string `source`; a `git` source also needs a string `url`.
///
/// Other keys (Claude settings Fuigo does not read) are not checked.
pub fn managed_settings_policy_errors(json: &serde_json::Value) -> Vec<String> {
    use serde_json::Value;
    let Some(root) = json.as_object() else {
        return vec!["<root>".to_owned()];
    };
    let strings = |v: &Value| v.as_array().is_some_and(|a| a.iter().all(Value::is_string));
    let mut wrong = Vec::new();
    if let Some(env) = root.get("env") {
        match env.as_object() {
            None => wrong.push("env".to_owned()),
            Some(env) => wrong.extend(
                env.iter()
                    .filter(|(_, v)| !(v.is_string() || v.is_boolean() || v.is_number()))
                    .map(|(k, _)| format!("env.{k}")),
            ),
        }
    }
    if let Some(perms) = root.get("permissions") {
        match perms.as_object() {
            None => wrong.push("permissions".to_owned()),
            Some(perms) => {
                for key in ["allow", "deny", "ask"] {
                    if perms.get(key).is_some_and(|v| !strings(v)) {
                        wrong.push(format!("permissions.{key}"));
                    }
                }
                for key in ["defaultMode", "disableBypassPermissionsMode"] {
                    if perms.get(key).is_some_and(|v| !v.is_string()) {
                        wrong.push(format!("permissions.{key}"));
                    }
                }
            }
        }
    }
    if root.get("defaultMode").is_some_and(|v| !v.is_string()) {
        wrong.push("defaultMode".to_owned());
    }
    let mcp_entry_ok = |e: &Value| {
        e.as_object().is_some_and(|e| {
            let mut known = 0;
            let mut ok = true;
            for key in ["serverUrl", "command", "serverName"] {
                if let Some(v) = e.get(key) {
                    known += 1;
                    ok &= v.is_string();
                }
            }
            if let Some(v) = e.get("serverCommand") {
                known += 1;
                ok &= strings(v) && v.as_array().is_some_and(|a| !a.is_empty());
            }
            ok && known > 0
        })
    };
    for key in ["allowedMcpServers", "deniedMcpServers"] {
        if root
            .get(key)
            .is_some_and(|v| !v.as_array().is_some_and(|a| a.iter().all(mcp_entry_ok)))
        {
            wrong.push(key.to_owned());
        }
    }
    let marketplace_ok = |e: &Value| {
        e.get("source")
            .and_then(Value::as_str)
            .is_some_and(|source| source != "git" || e.get("url").is_some_and(Value::is_string))
    };
    if root
        .get("strictKnownMarketplaces")
        .is_some_and(|v| !v.as_array().is_some_and(|a| a.iter().all(marketplace_ok)))
    {
        wrong.push("strictKnownMarketplaces".to_owned());
    }
    wrong
}

/// What [`managed_settings_json`] found.
#[derive(Debug, Clone)]
pub enum ManagedSettingsJson {
    /// No file (or a stable blank): no managed settings.
    Absent,
    /// The file as it is now, or (when it broke after it validated) its last validated copy.
    Loaded(serde_json::Value),
    /// Present but unreadable, not JSON, or a policy key of the wrong type, and never validated in this process. Callers
    /// fail closed: startup refuses this case, so only a process that skipped the startup gate gets here.
    Broken(String),
}

/// P183 round 11 (Grok r7 H1): the strict check of the Claude file's text, shared by every reader. `Ok` text is remembered by
/// the caller through [`remember_admin_source`].
fn strict_managed_settings(src: &str) -> Result<serde_json::Value, StrictFail> {
    // serde_json's error names the line and column only, never the text
    let json: serde_json::Value = serde_json::from_str(src)
        .map_err(|e| StrictFail::other(format!("it is not valid JSON ({e})")))?;
    let wrong = managed_settings_policy_errors(&json);
    if !wrong.is_empty() {
        // `<root>` (the document is not an object) is not a wrong-typed KEY: it keeps the copy
        let typed_pins = !wrong.iter().any(|k| k == "<root>");
        return Err(StrictFail {
            detail: format!("policy keys of the wrong type: {}", wrong.join(", ")),
            typed_pins,
        });
    }
    Ok(json)
}

/// P186c (owner decision 24): why an admin policy text failed the strict check, with the error CLASS as a field (never
/// recovered from the text). `typed_pins` is true only when the text was read completely and parsed and failed ONLY because
/// pinned keys have the wrong type; a running process that holds a validated copy then applies the lock-down instead of the
/// copy. Every other failure (unparseable, bad `[[version_overrides]]`) keeps the copy.
#[derive(Debug, Clone)]
pub(crate) struct StrictFail {
    pub(crate) detail: String,
    pub(crate) typed_pins: bool,
}

impl StrictFail {
    fn other(detail: String) -> Self {
        Self { detail, typed_pins: false }
    }
}

impl From<StrictFail> for String {
    fn from(f: StrictFail) -> Self {
        f.detail
    }
}

/// P186c: the broken versions of an admin file already announced (file -> hash of the text), so the lock-down message shows
/// once per broken version, not on every load. A valid version, or a stable blank, forgets the entry (a later break is a
/// new episode and is announced again).
fn announced_lockdowns() -> &'static std::sync::Mutex<std::collections::HashMap<PathBuf, u64>> {
    static A: std::sync::OnceLock<std::sync::Mutex<std::collections::HashMap<PathBuf, u64>>> =
        std::sync::OnceLock::new();
    A.get_or_init(Default::default)
}

fn text_version(src: &str) -> u64 {
    use std::hash::{Hash as _, Hasher as _};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    src.hash(&mut h);
    h.finish()
}

/// P186c: one admin policy file whose NEW version has a wrong-typed pinned key while this process holds a validated copy, so the
/// lock-down is enforced instead of the copy. `version` identifies the broken text (a different broken text is a new entry).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdminLockdown {
    pub path: PathBuf,
    /// Names the wrong-typed keys (from the file, so outside text); never a value.
    pub detail: String,
    pub version: u64,
}

fn one_line(s: String) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

impl AdminLockdown {
    /// What the session shows when the lock-down starts: the fresh-start wording (`RequirementsError::Unloadable`) without
    /// "refusing to start", then what it means. File and keys come from outside, so they pass through `untrusted` (one line).
    pub fn entered_notice(&self) -> String {
        one_line(format!(
            "requirements at {} ({}) could not be loaded: {}. All tools are denied until an administrator fixes this file.",
            fuigo_tty_utils::untrusted(self.path.display()),
            source_kind(&self.path),
            fuigo_tty_utils::untrusted(&self.detail),
        ))
    }
}

/// P186f: how ONE admin file reads now. Only `Locked` is a lock-down; `Valid` is a valid document; `Other` is anything else
/// (unparseable, half-written, missing, not admin-owned), where enforcement keeps the last valid copy. `Blank` is a stable
/// blank, where enforcement forgets the copy (all three files: `accept_admin_toml_classified` and `managed_settings_json`).
pub enum AdminFileClass {
    Locked(AdminLockdown),
    Valid,
    /// A STABLE blank (or, for a TOML file, no content): enforcement forgets any kept copy and the file sets no policy.
    Blank,
    /// Followups2 round 2: broken (unparseable, wrong-typed, unreadable, not admin-owned) and this process holds NO validated
    /// copy, so the loaders apply the full lock-down (`AdminSource::Broken`, `ManagedSettingsJson::Broken`). Same payload as
    /// `Locked` (`detail` is outside text; `version` identifies the broken text).
    BrokenNoCopy(AdminLockdown),
    Other,
}

pub struct AdminFileState {
    pub path: PathBuf,
    pub class: AdminFileClass,
}

/// Followups2 round 2: identifies a broken version for the once-per-version notice: the text as it is now (read again, read-only),
/// else the failure detail (an unreadable file has no text).
fn broken_version(path: &Path, detail: &str) -> u64 {
    match read_requirements_source(path, true) {
        Ok(Some(src)) => text_version(&src),
        _ => text_version(detail),
    }
}

/// Followups2 round 2: the notice for a lock-down that ended because the file is gone and no validated copy was ever held.
pub fn admin_lockdown_gone_notice(path: &Path) -> String {
    one_line(format!(
        "Admin policy file {} is no longer there. The lock-down has ended and this file sets no policy.",
        fuigo_tty_utils::untrusted(path.display())
    ))
}

/// P186f: the notice for a lock-down that ended because the file became unparseable or went missing, not because it is valid.
pub fn admin_lockdown_ended_invalid_notice(path: &Path) -> String {
    one_line(format!(
        "Admin policy file {} changed and is still not valid. The lock-down has ended and the last valid policy is in force again.",
        fuigo_tty_utils::untrusted(path.display())
    ))
}

/// P186f round 2: the notice for a lock-down that ended because the file is now (stably) empty: it sets no policy.
pub fn admin_lockdown_emptied_notice(path: &Path) -> String {
    one_line(format!(
        "Admin policy file {} is now empty. The lock-down has ended and this file sets no policy.",
        fuigo_tty_utils::untrusted(path.display())
    ))
}

/// P186f round 2: said once when a file the user was told is "still not valid" reads as a valid document again.
pub fn admin_policy_valid_in_force_notice(path: &Path) -> String {
    one_line(format!(
        "Admin policy file {} is valid again and is in force.",
        fuigo_tty_utils::untrusted(path.display())
    ))
}

/// The short notice for the end of a lock-down.
pub fn admin_lockdown_lifted_notice(path: &Path) -> String {
    one_line(format!(
        "Admin policy file {} is valid again. The lock-down is lifted.",
        fuigo_tty_utils::untrusted(path.display())
    ))
}

/// P186c: every admin file currently in the typed-pin lock-down (empty: none). A PURE read of the current state with no
/// once-key: it reads the files again through the same loader entries a tool call uses (a few small files; `admin_source_state`
/// for the two TOML files, `read_managed_settings` for Claude's), so a session can compare it with what it has already shown.
pub fn admin_lockdowns() -> Vec<AdminLockdown> {
    admin_lockdowns_at(system_config_dir().as_deref(), crate::paths::claude_managed_settings_probe_path().as_deref())
}

#[doc(hidden)]
pub fn admin_lockdowns_at(dir: Option<&Path>, claude_file: Option<&Path>) -> Vec<AdminLockdown> {
    admin_policy_states_at(dir, claude_file)
        .into_iter()
        .filter_map(|s| match s.class {
            AdminFileClass::Locked(l) => Some(l),
            _ => None,
        })
        .collect()
}

/// P186f: [`admin_lockdowns_at`] with the class of every admin file (same reads, same judgement).
#[doc(hidden)]
pub fn admin_policy_states_at(dir: Option<&Path>, claude_file: Option<&Path>) -> Vec<AdminFileState> {
    let mut out = Vec::new();
    if let Some(dir) = dir {
        for path in [dir.join("requirements.toml"), dir.join(crate::loader::MANAGED_CONFIG_FILENAME)] {
            let (state, read) = admin_source_state_read(&path, &admin_lockdown_requirements);
            let class = match state {
                AdminSource::Locked { detail, version, .. } => {
                    AdminFileClass::Locked(AdminLockdown { path: path.clone(), detail, version })
                }
                // no content (a stable blank or comments only): `accept_admin_toml_classified` forgot the copy
                AdminSource::Text(None) if read == SourceRead::Valid => AdminFileClass::Blank,
                AdminSource::Text(_) if read == SourceRead::Valid => AdminFileClass::Valid,
                // followups2 round 2: `Broken` is exactly "broken and no copy" (the callers apply the lock-down)
                AdminSource::Broken(detail) => {
                    let version = broken_version(&path, &detail);
                    AdminFileClass::BrokenNoCopy(AdminLockdown { path: path.clone(), detail, version })
                }
                AdminSource::Text(_) => AdminFileClass::Other,
            };
            out.push(AdminFileState { path, class });
        }
    }
    if let Some(path) = claude_file {
        let class = match read_managed_settings(path) {
            Ok(ClaudeFile::WrongTyped(src, detail)) if admin_requirements_copy_exists(path) => {
                AdminFileClass::Locked(AdminLockdown { path: path.to_path_buf(), detail, version: text_version(&src) })
            }
            Ok(ClaudeFile::Text(..)) => AdminFileClass::Valid,
            Ok(ClaudeFile::Blank) => AdminFileClass::Blank,
            // followups2 round 2: wrong-typed without a copy, or unusable without a copy: `managed_settings_json` is `Broken`
            Ok(ClaudeFile::WrongTyped(src, detail)) => AdminFileClass::BrokenNoCopy(AdminLockdown {
                path: path.to_path_buf(),
                detail,
                version: text_version(&src),
            }),
            Err(detail) if !admin_requirements_copy_exists(path) => {
                let version = broken_version(path, &detail);
                AdminFileClass::BrokenNoCopy(AdminLockdown { path: path.to_path_buf(), detail, version })
            }
            _ => AdminFileClass::Other,
        };
        out.push(AdminFileState { path: path.to_path_buf(), class });
    }
    out
}

/// P186f: the turn-start read as a closure that can run on another thread. The paths (and, under the `test-seams` feature, the
/// per-thread admin-root override) are captured HERE, on the calling thread; the closure does all the file reading.
pub fn admin_policy_reader() -> impl FnOnce() -> Vec<AdminFileState> + Send + 'static {
    let dir = system_config_dir();
    let claude = crate::paths::claude_managed_settings_probe_path();
    #[cfg(feature = "test-seams")]
    let carried = crate::paths::admin_root_override::current();
    move || {
        #[cfg(feature = "test-seams")]
        let _guard = carried.map(crate::paths::admin_root_override::set);
        admin_policy_states_at(dir.as_deref(), claude.as_deref())
    }
}

/// P186c: the same clear message for a running process as a fresh start gives (file and key), once per broken version.
fn announce_typed_pin_lockdown(path: &Path, src: &str, detail: &str) {
    use std::hash::{Hash as _, Hasher as _};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    src.hash(&mut h);
    let id = h.finish();
    let first = announced_lockdowns()
        .lock()
        .map(|mut m| m.insert(path.to_path_buf(), id) != Some(id))
        .unwrap_or(false);
    if first {
        let msg = display_scrub(&format!(
            "administrator policy file {}: a new version has a setting of the wrong type ({detail}); every tool is locked \
             down until the file is fixed",
            path.display()
        ));
        tracing::error!("{msg}");
        #[cfg(test)]
        test_notices().lock().unwrap().push((path.to_path_buf(), msg));
    }
}

#[cfg(test)]
fn test_notices() -> &'static std::sync::Mutex<Vec<(PathBuf, String)>> {
    static N: std::sync::OnceLock<std::sync::Mutex<Vec<(PathBuf, String)>>> = std::sync::OnceLock::new();
    N.get_or_init(Default::default)
}

/// P183 round 11 (Grok r7 H1): the policy-sources reader's successful read of the Claude file (`content` is the text of its
/// one trusted read): the same check, and the text becomes the validated copy.
/// P183 round 12 (Grok r8): it also RETURNS the verdict, which the policy-sources reader must use: `Err` is a broken source
/// (copy plus lock-down), never a partly enforced document. `Ok(None)`: blank file (absent, as `managed_settings_json`).
pub(crate) fn accept_managed_settings_text(
    path: &Path,
    content: &str,
) -> Result<Option<serde_json::Value>, String> {
    // P183 round 13 (Grok r9 M1): `content` is blank only after the caller's stability re-check
    // ([`confirm_admin_blank`]): a stable trusted blank is the owner clearing the policy, so the copy goes.
    if content.trim().is_empty() {
        forget_admin_source(path);
        return Ok(None);
    }
    let json = strict_managed_settings(content)?;
    remember_admin_source(path, content);
    Ok(Some(json))
}

/// P183 round 13 (Grok r9 M1, M2): the policy-sources reader's handling of an admin file that read BLANK: the same stable-blank
/// re-check as [`read_requirements_source`] (re-reads go through the ownership check again). `Ok(Some(text))`: the text to
/// judge (the blank, now stable, or content a writer finished); `Ok(None)`: the file vanished during the wait; `Err`: it
/// keeps changing or cannot be trusted, so the caller reports a broken source and the copy stays.
pub(crate) fn confirm_admin_blank(path: &Path, admin_uid: u32) -> Result<Option<String>, String> {
    let recheck = |p: &Path| {
        read_admin_bytes(p, admin_uid).and_then(|b| {
            String::from_utf8(b).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })
    };
    match crate::loader::confirm_blank_with(path, recheck) {
        Ok(text) => Ok(Some(text)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => absent_unless_dangling(path),
        Err(e) => Err(e.to_string()),
    }
}

/// P186 A3: a path the blank wait found `NotFound` is absent only if nothing is there. A dangling symlink (an entry that
/// `symlink_metadata` sees but whose target cannot be opened) is a broken source, as it is on the first open.
fn absent_unless_dangling(path: &Path) -> Result<Option<String>, String> {
    if std::fs::symlink_metadata(path).is_ok() {
        return Err(format!("{} is a symlink whose target cannot be opened", path.display()));
    }
    Ok(None)
}

/// P183 round 13 (Grok r9 M2): the validated copy of an admin file that is now ABSENT, if this process holds one. One rule for
/// every admin source and both readers: the copy stays in force (a process that never saw the file has none).
pub(crate) fn kept_copy_of_absent_admin_file(path: &Path) -> Option<String> {
    let kept = last_good_admin_sources().lock().ok().and_then(|m| m.get(path).cloned());
    if kept.is_some() {
        tracing::error!(path = %path.display(), "admin policy file disappeared; keeping the last validated copy");
    }
    kept
}

/// What one read of `managed-settings.json` found.
enum ClaudeFile {
    Absent,
    /// A STABLE blank (comments do not exist in JSON): the owner emptied it.
    Blank,
    Text(String, serde_json::Value),
    /// P186c: read completely and parsed as JSON, failing ONLY on policy keys of the wrong type (text, detail).
    WrongTyped(String, String),
}

/// One read of `managed-settings.json`, classified like startup's: why it cannot be used, or what it holds.
fn read_managed_settings(path: &Path) -> Result<ClaudeFile, String> {
    let src = match read_requirements_source(path, true) {
        Ok(Some(src)) if !src.trim().is_empty() => src,
        Ok(Some(_)) => return Ok(ClaudeFile::Blank),
        Ok(None) => return Ok(ClaudeFile::Absent),
        Err(failure) => return Err(failure.detail),
    };
    match strict_managed_settings(&src) {
        Ok(json) => Ok(ClaudeFile::Text(src, json)),
        Err(f) if f.typed_pins => Ok(ClaudeFile::WrongTyped(src, f.detail)),
        Err(f) => Err(f.detail),
    }
}

/// P183 round 7 (Grok r4 H3): Claude's `managed-settings.json` for a load (Fuigo's MCP, marketplace and permission policy
/// from it), read the way startup validated it. A file that breaks after it validated keeps its last validated copy (like
/// the system requirements file); a deleted file keeps it too, and only a stable blank clears it (round 13).
pub fn managed_settings_json(path: &Path) -> ManagedSettingsJson {
    match read_managed_settings(path) {
        Ok(ClaudeFile::Blank) => {
            forget_admin_source(path);
            ManagedSettingsJson::Absent
        }
        // P183 round 13 (Grok r9 M2): a deleted file keeps the copy this process validated (as the TOML requirements reader)
        Ok(ClaudeFile::Absent) => match kept_copy_of_absent_admin_file(path)
            .and_then(|src| serde_json::from_str(&src).ok())
        {
            Some(json) => ManagedSettingsJson::Loaded(json),
            None => ManagedSettingsJson::Absent,
        },
        Ok(ClaudeFile::Text(src, json)) => {
            remember_admin_source(path, &src);
            ManagedSettingsJson::Loaded(json)
        }
        // P186c (decision 24): a wrong-typed policy key is the lock-down whether or not a copy exists, announced once
        Ok(ClaudeFile::WrongTyped(src, detail)) => {
            if admin_requirements_copy_exists(path) {
                announce_typed_pin_lockdown(path, &src, &detail);
            }
            ManagedSettingsJson::Broken(detail)
        }
        Err(detail) => {
            let kept = last_good_admin_sources()
                .lock()
                .ok()
                .and_then(|m| m.get(path).cloned())
                .and_then(|src| serde_json::from_str(&src).ok());
            tracing::error!(
                path = %path.display(),
                error = %detail,
                kept_last_good = kept.is_some(),
                "managed-settings.json can no longer be loaded; keeping its last validated copy"
            );
            match kept {
                Some(json) => ManagedSettingsJson::Loaded(json),
                None => ManagedSettingsJson::Broken(detail),
            }
        }
    }
}

/// Startup check of `managed-settings.json` (admin-owned, like the system requirements file): present but unreadable, not
/// JSON, or with a policy key of the wrong type refuses to start; a valid file becomes the last good copy.
fn validate_managed_settings_file(path: Option<&Path>) -> Result<(), RequirementsError> {
    let Some(path) = path else {
        return Ok(());
    };
    match read_managed_settings(path) {
        Ok(ClaudeFile::Blank) => forget_admin_source(path),
        Ok(ClaudeFile::Absent) => {}
        Ok(ClaudeFile::Text(src, _)) => remember_admin_source(path, &src),
        Ok(ClaudeFile::WrongTyped(_, detail)) | Err(detail) => {
            return Err(RequirementsError::Unloadable {
                path: path.to_path_buf(),
                detail,
            });
        }
    }
    Ok(())
}

/// Validates all requirements layers (user and system files, and macOS MDM).
/// Call once at startup from the binary's `main()`; exit on `Err`.
pub fn validate_requirements() -> Result<(), RequirementsError> {
    for warning in validate_requirements_with_warnings()? {
        tracing::error!("{warning}");
    }
    Ok(())
}

/// [`validate_requirements`] that hands back the warnings for the caller to show (P183).
/// Startup runs before tracing is set up, so a `tracing` line alone would never reach the user.
pub fn validate_requirements_with_warnings() -> Result<Vec<String>, RequirementsError> {
    let warnings = validate_requirements_from(
        system_config_dir().as_deref(),
        user_fuigo_home().as_deref(),
        crate::macos_managed::forced_requirements().clone(),
        env_bool(FAIL_CLOSED_ENV),
    )?;
    // P183 round 7: the probe path, not `claude_managed_settings_path` (its `exists()` reads a dangling symlink as absent)
    validate_managed_settings_file(crate::paths::claude_managed_settings_probe_path().as_deref())?;
    Ok(warnings)
}

/// [`validate_requirements_with_warnings`] for explicit directories and no MDM layer, with the live environment.
/// For tests that must not depend on the host's `/etc/fuigo` or MDM profile. Not a policy bypass: it only changes what THIS
/// call checks, and startup never calls it.
#[doc(hidden)]
pub fn validate_requirements_for_dirs(
    system_dir: Option<&Path>,
    user_home: Option<&Path>,
) -> Result<Vec<String>, RequirementsError> {
    validate_requirements_from(system_dir, user_home, Ok(None), env_bool(FAIL_CLOSED_ENV))
}

/// Every requirements layer, admin-owned first. `Ok` carries the warnings to show (a broken user-home file that does not refuse).
/// `mdm` is the forced MDM payload: `Err` when forced but undecodable (P183), `Ok(None)` when nothing is forced.
fn validate_requirements_from(
    system_dir: Option<&Path>,
    user_home: Option<&Path>,
    mdm: Result<Option<toml::Value>, String>,
    env_fail_closed: Option<bool>,
) -> Result<Vec<String>, RequirementsError> {
    let mut warnings = Vec::new();
    if let Some(dir) = system_dir {
        warnings.extend(validate_requirements_file(
            &dir.join(crate::loader::REQUIREMENTS_FILENAME),
            true,
            env_fail_closed,
        )?);
        // P183 round 7 (sweep): the root-owned `managed_config.toml` is admin policy too (its `[permission]` denies and
        // `[hooks]` cannot be removed by the user, and some of its keys win over user config), so it is checked the same way
        warnings.extend(validate_requirements_file(
            &dir.join(crate::loader::MANAGED_CONFIG_FILENAME),
            true,
            env_fail_closed,
        )?);
    }
    // MDM uses the raw value (fail_closed intact) so it's enforced like the files.
    match mdm {
        Err(detail) => {
            return Err(RequirementsError::Unloadable {
                path: PathBuf::from(crate::macos_managed::MDM_REQUIREMENTS_SOURCE),
                detail,
            });
        }
        Ok(Some(v)) => validate_requirements_value(v, &RequirementsSource::Mdm, true)?,
        Ok(None) => {}
    }
    if let Some(home) = user_home {
        warnings.extend(validate_requirements_file(
            &home.join(crate::loader::REQUIREMENTS_FILENAME),
            false,
            env_fail_closed,
        )?);
    }
    Ok(warnings)
}

#[cfg(test)] // P183: startup goes through `validate_requirements_from`; kept for the P162 tests
/// Validate the user requirements layer if a user home resolves; otherwise a no-op (no cwd-relative `.fuigo/requirements.toml` is read or enforced).
fn validate_user_requirements(home: Option<&Path>) -> Result<(), RequirementsError> {
    match home {
        Some(g) => validate_requirements_layer(&g.join("requirements.toml"), false),
        None => Ok(()),
    }
}

/// `fail_closed` for [`validate_requirements`]'s version check.
/// The admin file flag is authoritative; the env can only TIGHTEN it (force-on), never loosen.
fn resolve_fail_closed_mode(requirements: &toml::Value) -> bool {
    resolve_fail_closed_mode_for(env_bool(FAIL_CLOSED_ENV), requirements)
}

/// [`resolve_fail_closed_mode`] with the parsed env value passed in, so the rule is testable
/// without writing the process environment that `validate_requirements` callers also read.
fn resolve_fail_closed_mode_for(env: Option<bool>, requirements: &toml::Value) -> bool {
    fail_closed_flag(requirements) || env == Some(true)
}

/// P183: one requirements file, read ONCE, so the file cannot change between a "does it load" check and the policy check.
/// - Absent (no directory entry, and no broken symlink on the way): nothing to enforce.
/// - Present but unreadable or not TOML: an admin-owned layer refuses to start; so does any layer under fail_closed (the env
///   forces it on, or the broken file's own top-level `fail_closed = true` is still parseable, see [`declares_fail_closed`]).
///   Otherwise (the user-home cloud cache: user-writable, so refusing buys no security against its owner, P162's user rule)
///   the returned warning names the file, and none of its pins are in force.
/// - Parsed: the P162 `[[version_overrides]]` check ([`validate_requirements_value`]).
fn validate_requirements_file(
    path: &Path,
    admin_owned: bool,
    env_fail_closed: Option<bool>,
) -> Result<Option<String>, RequirementsError> {
    let refuse_or_warn = |src: Option<&str>, detail: String| {
        if admin_owned || env_fail_closed == Some(true) || src.is_some_and(declares_fail_closed) {
            Err(RequirementsError::Unloadable {
                path: path.to_path_buf(),
                detail,
            })
        } else {
            Ok(Some(format!(
                "requirements at {} could not be loaded: {detail}; NONE of its pins are in force \
                 (fail_closed = true in the file, or {FAIL_CLOSED_ENV}=1, refuses to start instead)",
                path.display()
            )))
        }
    };
    let src = match read_requirements_source(path, admin_owned) {
        Ok(Some(src)) => src,
        Ok(None) => {
            // P186 A2: absence never forgets the validated copy (as `admin_requirements_source_checked`)
            return Ok(None);
        }
        Err(ReadFailure { detail, readable }) => {
            return refuse_or_warn(readable.as_deref(), detail);
        }
    };
    let parsed = if src.trim().is_empty() {
        Ok(toml::Value::Table(toml::map::Map::new()))
    } else {
        toml::from_str::<toml::Value>(&src).map_err(|e| crate::loader::toml_error_detail(&src, &e))
    };
    match parsed {
        Ok(mut v) => {
            // P183 round 11 (Grok r7 H2): an ADMIN file is never `$VAR`-expanded, here or at runtime; a user file keeps
            // the same expansion as the loader's `load_toml_file`
            if !admin_owned {
                crate::loader::expand_env_vars_in_toml(&mut v);
            }
            validate_requirements_value(
                v,
                &RequirementsSource::File(path.to_path_buf()),
                admin_owned,
            )?;
            if admin_owned {
                // The same read-check-parse-remember the runtime readers call: remembered text is enforced text
                if let Err(detail) = accept_admin_text(path, &src) {
                    return refuse_or_warn(Some(&src), detail);
                }
                let warnings = unexpanded_env_warnings(path, &src);
                if !warnings.is_empty() {
                    return Ok(Some(warnings.join("; ")));
                }
            }
            Ok(None)
        }
        Err(detail) => refuse_or_warn(Some(&src), detail),
    }
}

/// P186f: which uid owns the admin files for a read. The process uid stands in for root only while the admin-root override is
/// set; otherwise it is root. Pure, so a non-root uid is testable when the suite itself runs as root. Test builds only: the
/// product build uses `ROOT_UID` directly.
#[cfg(any(test, feature = "test-seams"))]
fn admin_uid_for(process_euid: u32, override_is_set: bool) -> u32 {
    if override_is_set { process_euid } else { crate::policy_sources::ROOT_UID }
}

/// The file's text; `Ok(None)` only when it is genuinely absent.
/// A dangling symlink, at the file or at its directory (`/etc/fuigo` pointing at a removed directory), is a broken policy,
/// not a missing one (Astra r1, r2).
/// P183 round 4: with `stable_blank` (admin-owned files), a blank read is re-checked like the user `config.toml`: a file caught
/// between an in-place writer's truncate and its write is not "no policy" (the re-read content is used, or the read fails).
fn read_requirements_source(
    path: &Path,
    stable_blank: bool,
) -> Result<Option<String>, ReadFailure> {
    // Unit tests of this crate cannot create root-owned files: the uid that owns them stands in for root
    #[cfg(test)]
    let admin_uid = admin_uid_for(crate::policy_sources::process_euid(), true);
    // P186f: the cargo feature alone is not enough (a binary built with `--all-features` would accept a user-owned file at the
    // real admin path): the process uid stands in for root only while a test has set the admin-root override.
    #[cfg(all(not(test), feature = "test-seams"))]
    let admin_uid = admin_uid_for(
        crate::policy_sources::process_euid(),
        crate::paths::admin_root_override::current().is_some(),
    );
    #[cfg(not(any(test, feature = "test-seams")))]
    let admin_uid = crate::policy_sources::ROOT_UID;
    read_requirements_source_as(path, stable_blank, admin_uid)
}

/// P183 round 8: contents and ownership of an admin file come from ONE opened file, judged by P169's
/// [`crate::policy_sources::admin_owned`] (the single rule: owned by `admin_uid`, not group/other-writable). A file that
/// fails it is treated exactly like a corrupt one by every caller (refuse at startup, keep the last validated copy later).
pub(crate) fn read_admin_bytes(path: &Path, admin_uid: u32) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    // P183 round 10 (Grok r6 H): non-blocking open, then judge the opened object BEFORE reading. A device, fifo, socket or
    // directory, a file or directory the admin does not own, or one a group/other can write is broken, never blank or absent
    let mut file = crate::policy_sources::open_admin_file(path)?;
    let meta = file.metadata()?;
    crate::policy_sources::admin_object_trusted(path, &meta, admin_uid).map_err(std::io::Error::other)?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn read_requirements_source_as(
    path: &Path,
    stable_blank: bool,
    admin_uid: u32,
) -> Result<Option<String>, ReadFailure> {
    let dangling = |p: &Path| std::fs::symlink_metadata(p).is_ok() && std::fs::metadata(p).is_err();
    if let Some(dir) = path.parent()
        && dangling(dir)
    {
        return Err(ReadFailure::unreadable(format!(
            "its directory {} is a symlink whose target cannot be opened",
            dir.display()
        )));
    }
    let read = if stable_blank {
        read_admin_bytes(path, admin_uid)
    } else {
        std::fs::read(path)
    };
    match read {
        // P186 A1: the SAME blank predicate as every classifier downstream (`trim().is_empty()`), so Unicode-only whitespace
        // (\x0b) gets the stability re-check too
        Ok(bytes) if stable_blank && std::str::from_utf8(&bytes).is_ok_and(|t| t.trim().is_empty()) => {
            let recheck = |p: &Path| {
                read_admin_bytes(p, admin_uid).and_then(|b| {
                    String::from_utf8(b).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
                })
            };
            match crate::loader::confirm_blank_with(path, recheck) {
                Ok(text) => Ok(Some(text)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    absent_unless_dangling(path).map_err(ReadFailure::unreadable)
                }
                Err(e) => Err(ReadFailure::unreadable(e.to_string())),
            }
        }
        Ok(bytes) => String::from_utf8(bytes).map(Some).map_err(|e| {
            // Astra r3: the whole lines before the first bad byte are still readable, so a fail_closed there still counts
            let bytes = e.as_bytes();
            let valid = &bytes[..e.utf8_error().valid_up_to()];
            let whole_lines = valid.iter().rposition(|&b| b == b'\n').map_or(0, |i| i + 1);
            ReadFailure {
                detail: format!(
                    "it is not valid UTF-8 (first bad byte at offset {})",
                    valid.len()
                ),
                readable: String::from_utf8(valid[..whole_lines].to_vec()).ok(),
            }
        }),
        Err(_) if dangling(path) => Err(ReadFailure::unreadable(
            "it is a symlink whose target cannot be opened".to_owned(),
        )),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(ReadFailure::unreadable(e.to_string())),
    }
}

/// Why a present requirements file could not be read as text, and the part of it that WAS readable (whole lines), if any.
#[derive(Debug)]
struct ReadFailure {
    detail: String,
    readable: Option<String>,
}

impl ReadFailure {
    fn unreadable(detail: String) -> Self {
        Self {
            detail,
            readable: None,
        }
    }
}

/// P183 (Astra r3, round 4): the admin-owned requirements files' last good TEXT (parsed, non-empty), by path.
/// Startup validation and the later loads (config, hooks, reload) each read the file; if it breaks in between, the pins and
/// hooks come from this copy instead of the layer vanishing. Only genuine absence (or a stable blank) clears it.
fn last_good_admin_sources() -> &'static std::sync::Mutex<std::collections::HashMap<PathBuf, String>>
{
    static LAST_GOOD: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<PathBuf, String>>,
    > = std::sync::OnceLock::new();
    LAST_GOOD.get_or_init(Default::default)
}

/// Whether this process validated an admin file at `path` earlier (so a later break enforces that copy).
pub fn admin_requirements_copy_exists(path: &Path) -> bool {
    last_good_admin_sources()
        .lock()
        .ok()
        .is_some_and(|m| m.contains_key(path))
}

/// P183 round 11 (Grok r7 H1): the identity of the validated copy itself (a hash of its text), `None` when there is none.
/// The managed-settings cache key carries it, so a replaced copy is never served from a cache built on the old one.
pub fn admin_requirements_copy_id(path: &Path) -> Option<u64> {
    use std::hash::{Hash as _, Hasher as _};
    let map = last_good_admin_sources().lock().ok()?;
    let text = map.get(path)?;
    let mut h = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut h);
    Some(h.finish())
}

fn remember_admin_source(path: &Path, src: &str) {
    // P186c: a valid version ends the broken episode
    if let Ok(mut a) = announced_lockdowns().lock() {
        a.remove(path);
    }
    if let Ok(mut map) = last_good_admin_sources().lock() {
        map.insert(path.to_path_buf(), src.to_owned());
    }
}

fn forget_admin_source(path: &Path) {
    if let Ok(mut a) = announced_lockdowns().lock() {
        a.remove(path);
    }
    if let Ok(mut map) = last_good_admin_sources().lock() {
        map.remove(path);
    }
}

/// P183 round 4: the text of an admin-owned requirements file for a load, from ONE read classified like startup's.
/// - Genuinely absent, a stable blank, or comments only: `None`, and the last good copy is forgotten (the admin removed it).
/// - Parses with content: that text, remembered as the last good copy.
/// - Present but broken (dangling symlink at the file or its directory, permission, not UTF-8, a directory, a blank that keeps
///   changing, a parse error): the last good copy, loudly; `None` if there never was one (startup refused that case).
pub(crate) fn admin_requirements_source(path: &Path) -> Option<String> {
    admin_requirements_source_checked(path).unwrap_or(None)
}

/// [`admin_requirements_source`] that tells a broken file this process never validated (`Err`: no copy to keep) from an
/// absent one (`Ok(None)`). P183 round 8: a broken admin file (corrupt, unreadable, not root-owned, group/other-writable) is a
/// lock-down whenever it is read, whether or not a last good copy exists; callers that can refuse take the `Err`.
pub(crate) fn admin_requirements_source_checked(path: &Path) -> Result<Option<String>, String> {
    admin_source_state(path, &admin_lockdown_requirements).into_result()
}

/// What one read of an admin TOML policy file decided (P186c).
pub(crate) enum AdminSource {
    /// The text to enforce (the file's own, or its validated copy); `None`: no policy.
    Text(Option<String>),
    /// P186c (owner decision 24): this process holds a validated copy and the new version was read completely and parsed,
    /// failing ONLY on wrong-typed pinned keys. The lock-down (as text) is enforced instead of the copy until the file is
    /// fixed. `detail` names the keys.
    Locked { text: String, detail: String, version: u64 },
    /// Broken and never validated here: the caller applies the lock-down (or refuses).
    Broken(String),
}

impl AdminSource {
    fn into_result(self) -> Result<Option<String>, String> {
        match self {
            Self::Text(t) => Ok(t),
            Self::Locked { text, .. } => Ok(Some(text)),
            Self::Broken(d) => Err(d),
        }
    }
}

/// [`admin_requirements_source_checked`] with the decision made explicit. `lockdown` is the document this source's callers
/// enforce for a broken file (the requirements form, or the `managed_config.toml` form).
pub(crate) fn admin_source_state(path: &Path, lockdown: &dyn Fn() -> toml::Value) -> AdminSource {
    admin_source_state_read(path, lockdown).0
}

/// P186f: what the file read as, beside the decision (for the session's notice only; the decision is unchanged).
#[derive(Clone, Copy, PartialEq, Eq)]
enum SourceRead {
    /// A valid document (also a blank one).
    Valid,
    /// Gone, unparseable, half-written or not admin-owned: any copy in the decision is the kept one.
    NotValid,
}

fn admin_source_state_read(path: &Path, lockdown: &dyn Fn() -> toml::Value) -> (AdminSource, SourceRead) {
    let read = std::cell::Cell::new(SourceRead::Valid);
    let state = admin_source_state_inner(path, lockdown, &read);
    (state, read.get())
}

fn admin_source_state_inner(path: &Path, lockdown: &dyn Fn() -> toml::Value, read: &std::cell::Cell<SourceRead>) -> AdminSource {
    let broken = |detail: String| -> AdminSource {
        read.set(SourceRead::NotValid);
        let kept = last_good_admin_sources()
            .lock()
            .ok()
            .and_then(|m| m.get(path).cloned());
        tracing::error!(
            path = %path.display(),
            error = %detail,
            kept_last_good = kept.is_some(),
            "admin requirements file can no longer be loaded; keeping the last validated copy of its pins and hooks"
        );
        match kept {
            Some(k) => AdminSource::Text(Some(k)),
            None => AdminSource::Broken(detail),
        }
    };
    let src = match read_requirements_source(path, true) {
        Ok(Some(src)) => src,
        // P183 round 9 (Grok r5 M1): the file is GONE. A process that already validated it keeps enforcing that copy for
        // its life (a local user who can unlink in a writable /etc/fuigo must not lift the policy); a process that never
        // saw the file has no policy to keep, which is unavoidable. Only a root-owned stable blank file clears the copy
        // (below): writing that needs the owner.
        Ok(None) => {
            read.set(SourceRead::NotValid);
            let kept = last_good_admin_sources()
                .lock()
                .ok()
                .and_then(|m| m.get(path).cloned());
            if kept.is_some() {
                tracing::error!(path = %path.display(), "admin requirements file disappeared; keeping the last validated copy");
            }
            return AdminSource::Text(kept);
        }
        Err(failure) => return broken(failure.detail),
    };
    match accept_admin_toml_classified(path, &src) {
        Ok(v) => AdminSource::Text(v.map(|_| src)),
        // P186c: the copy is replaced by the lock-down only for this class, and only when there is a copy to replace (no
        // copy is `Broken`, which every caller already turns into the lock-down)
        Err(f) if f.typed_pins && admin_requirements_copy_exists(path) => {
            match toml::to_string(&lockdown()) {
                Ok(text) => {
                    announce_typed_pin_lockdown(path, &src, &f.detail);
                    AdminSource::Locked { text, detail: f.detail, version: text_version(&src) }
                }
                Err(_) => AdminSource::Broken(f.detail),
            }
        }
        Err(f) => broken(f.detail),
    }
}

/// P183 round 11 (Grok r7 H1, H2): the ONE strict judgement of an admin TOML policy text (`requirements.toml`,
/// `managed_config.toml`). No `$VAR` expansion (the user's environment must not shape it). `Ok(None)`: no content (blank or
/// comments only). `Ok(Some(layer))`: the layer exactly as it is enforced (overrides applied, `fail_closed` stripped).
/// `Err`: broken (parse error, a security key of the wrong type, `[[version_overrides]]` that do not apply).
fn strict_admin_toml(src: &str) -> Result<Option<toml::Value>, StrictFail> {
    let v = toml::from_str::<toml::Value>(src)
        .map_err(|e| StrictFail::other(crate::loader::toml_error_detail(src, &e)))?;
    if v.as_table().is_none_or(|t| t.is_empty()) {
        return Ok(None);
    }
    // P183 round 5: a document startup would refuse (a security key of the wrong type, checked on the layer as the version
    // applies it) is broken too. Round 6/9: `[[version_overrides]]` that do not apply are broken (the base alone could be
    // weaker than the patch), never the base pins.
    let mut applied = v;
    let overrides_err = apply_version_overrides_with_registered(&mut applied).err();
    let wrong = wrong_type_security_keys(&applied);
    if !wrong.is_empty() {
        return Err(StrictFail {
            detail: format!("security keys of the wrong type: {}", wrong.join(", ")),
            // bad `[[version_overrides]]` beside the wrong type is not "ONLY wrong-typed keys": the copy stays
            typed_pins: overrides_err.is_none(),
        });
    }
    if let Some(e) = overrides_err {
        return Err(StrictFail::other(format!("invalid version_overrides: {e}")));
    }
    Ok(Some(applied))
}

/// P183 round 11 (Grok r7 H1, H2): read, trust-check and parse have happened (`src` is the text of one trusted read); judge it
/// with [`strict_admin_toml`] and, on success, REMEMBER it (or forget it, when the file has no content). Startup validation
/// and every runtime reader call this, so the remembered text is always the text last enforced, and only text that passes
/// the check the runtime uses. Warns once per file and key about `$NAME` in a string value (it is used literally).
fn accept_admin_text(path: &Path, src: &str) -> Result<Option<String>, String> {
    Ok(accept_admin_toml(path, src)?.map(|_| src.to_owned()))
}

/// P183 round 12 (Grok r8): [`accept_admin_text`] returning the layer as enforced (overrides applied). The policy-sources
/// reader of `requirements.toml` / `managed_config.toml` calls this and takes its verdict, so there is one decision per read.
pub(crate) fn accept_admin_toml(path: &Path, src: &str) -> Result<Option<toml::Value>, String> {
    accept_admin_toml_classified(path, src).map_err(|f| f.detail)
}

fn accept_admin_toml_classified(path: &Path, src: &str) -> Result<Option<toml::Value>, StrictFail> {
    match strict_admin_toml(src)? {
        Some(v) => {
            warn_unexpanded_env(path, src);
            remember_admin_source(path, src);
            Ok(Some(v))
        }
        None => {
            forget_admin_source(path);
            Ok(None)
        }
    }
}

/// The keys (dotted) whose string value holds `$NAME` or `${...}`.
fn env_reference_keys(v: &toml::Value) -> Vec<String> {
    fn has_ref(s: &str) -> bool {
        s.char_indices().any(|(i, c)| {
            c == '$'
                && s[i + 1..]
                    .chars()
                    .next()
                    .is_some_and(|n| n == '{' || n == '_' || n.is_ascii_alphabetic())
        })
    }
    fn walk(v: &toml::Value, path: &mut Vec<String>, out: &mut Vec<String>) {
        match v {
            toml::Value::String(s) if has_ref(s) => out.push(path.join(".")),
            toml::Value::Table(t) => {
                for (k, item) in t {
                    path.push(k.clone());
                    walk(item, path, out);
                    path.pop();
                }
            }
            toml::Value::Array(a) => {
                for (i, item) in a.iter().enumerate() {
                    path.push(i.to_string());
                    walk(item, path, out);
                    path.pop();
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(v, &mut Vec::new(), &mut out);
    out
}

/// The warning text for an admin file with `$NAME` in a string value, one per file and key.
pub(crate) fn env_literal_warning(path: &Path, key: &str) -> String {
    display_scrub(&format!(
        "administrator policy file {}: key {key}: environment variables are not expanded in administrator policy files; \
         the value is used literally",
        path.display()
    ))
}

fn unexpanded_env_warnings(path: &Path, src: &str) -> Vec<String> {
    toml::from_str::<toml::Value>(src)
        .map(|v| {
            env_reference_keys(&v)
                .iter()
                .map(|k| env_literal_warning(path, k))
                .collect()
        })
        .unwrap_or_default()
}

/// Logged once per process for each file and key (the runtime readers call this on every load).
fn warn_unexpanded_env(path: &Path, src: &str) {
    static SEEN: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    for w in unexpanded_env_warnings(path, src) {
        let first = SEEN
            .get_or_init(Default::default)
            .lock()
            .map(|mut s| s.insert(w.clone()))
            .unwrap_or(false);
        if first {
            tracing::warn!("{w}");
        }
    }
}

/// Replace control and invisible characters in text taken from a file or a path before it reaches a terminal.
/// `fuigo-tty-utils` (already a dependency of this crate) supplies the character set.
pub(crate) fn display_scrub(s: &str) -> String {
    s.chars()
        .map(|c| if fuigo_tty_utils::is_unsafe_display_char(c) { '?' } else { c })
        .collect()
}

/// The admin-owned system requirements layer for a config load: [`admin_requirements_source`], parsed and normalized like
/// [`load_requirements_layer`] (`$VAR` expansion, `fail_closed` stripped, `[[version_overrides]]` applied).
pub(crate) fn load_admin_requirements_layer(path: &Path) -> Option<toml::Value> {
    match admin_source_state(path, &admin_lockdown_requirements) {
        AdminSource::Text(src) => admin_layer_from_source(path, &src?),
        // P186c: wrong-typed pin on a running process, or broken with no validated copy: the lock-down, never "no policy"
        AdminSource::Locked { .. } | AdminSource::Broken(_) => Some(admin_lockdown_requirements()),
    }
}

fn admin_layer_from_source(_path: &Path, src: &str) -> Option<toml::Value> {
    // P183 round 11 (Grok r7 H2): the strict normaliser; a text that fails it is the lock-down document
    match toml::from_str::<toml::Value>(src)
        .map_err(|e| e.to_string())
        .and_then(normalize_admin_requirements_value)
    {
        Ok(v) => Some(v),
        Err(_) => Some(admin_lockdown_requirements()),
    }
}

/// P183 round 4: why a requirements file that exists (possibly as a dangling symlink) cannot be loaded, read the way startup
/// reads it; `None` when it is absent or loads. For `fuigo inspect`.
pub fn requirements_file_load_error(path: &Path) -> Option<String> {
    match read_requirements_source(path, false) {
        Ok(None) => None,
        Ok(Some(src)) => toml::from_str::<toml::Value>(&src)
            .err()
            .map(|e| crate::loader::toml_error_detail(&src, &e)),
        Err(failure) => Some(failure.detail),
    }
}

/// How much of a broken file [`declares_fail_closed`] reads: whole lines, at most this many bytes and this many lines.
const DECLARES_FAIL_CLOSED_MAX_BYTES: usize = 64 * 1024;
const DECLARES_FAIL_CLOSED_MAX_LINES: usize = 2048;

/// Whether a requirements file that does not parse still declares top-level `fail_closed = true`.
/// Its admin asked for fail-closed; a syntax error further down must not silently undo that.
/// No line heuristics (Astra r1, r2): the longest prefix of whole lines that the real TOML parser accepts is parsed, and its
/// root table is read. A prefix that parses has every string, array and table it opened closed, so its root keys mean in
/// it exactly what they mean in the whole file (comments, quoted and escaped keys, multi-line strings all handled by the
/// parser). Round 4 (Grok H2): parseability is not monotone in the prefix length (a prefix inside a closed multi-line string
/// fails while a longer one parses), so the prefixes are tried from the longest down, one line at a time, not bisected.
/// Bounded (Astra r3): only the head is read, at most 64 KiB and 2048 lines; a flag beyond it is not honoured.
fn declares_fail_closed(src: &str) -> bool {
    let mut ends: Vec<usize> = Vec::new();
    for (i, b) in src.bytes().enumerate() {
        if i >= DECLARES_FAIL_CLOSED_MAX_BYTES || ends.len() >= DECLARES_FAIL_CLOSED_MAX_LINES {
            break;
        }
        if b == b'\n' {
            ends.push(i + 1);
        }
    }
    // A short file with no trailing newline is one more whole prefix
    if src.len() <= DECLARES_FAIL_CLOSED_MAX_BYTES
        && ends.len() < DECLARES_FAIL_CLOSED_MAX_LINES
        && ends.last().copied() != Some(src.len())
    {
        ends.push(src.len());
    }
    ends.iter()
        .rev()
        .find_map(|&end| toml::from_str::<toml::Value>(&src[..end]).ok())
        .is_some_and(|v| fail_closed_flag(&v))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P183: an admin-owned requirements layer that exists but is not TOML at all refuses to start, naming the file and the (redacted) parse error.
    /// Before, the layer was dropped and validation returned Ok, so Fuigo started with none of the admin's pins.
    #[test]
    fn unparseable_admin_requirements_refuse_start_p183() {
        let sys = tempfile::tempdir().unwrap();
        let path = sys.path().join("requirements.toml");
        std::fs::write(&path, "[ui\nyolo = false\napi_key = \"s3cr3t\"\n").unwrap();
        let err = validate_requirements_from(Some(sys.path()), None, Ok(None), None).unwrap_err();
        let msg = err.to_string();
        assert!(matches!(err, RequirementsError::Unloadable { .. }));
        assert!(msg.contains(&path.display().to_string()), "{msg}");
        assert!(msg.contains("TOML parse error at line 1"), "{msg}");
        assert!(
            !msg.contains("s3cr3t"),
            "the offending line must stay redacted: {msg}"
        );

        // An undecodable forced MDM payload refuses too, named by its source label.
        let err = validate_requirements_from(None, None, Err("not valid base64".into()), None)
            .unwrap_err();
        assert!(
            err.to_string()
                .contains(crate::macos_managed::MDM_REQUIREMENTS_SOURCE)
        );

        // Absent and blank admin files are not failures.
        let empty = tempfile::tempdir().unwrap();
        assert!(validate_requirements_from(Some(empty.path()), None, Ok(None), None).is_ok());
        std::fs::write(empty.path().join("requirements.toml"), "\n").unwrap();
        assert!(validate_requirements_from(Some(empty.path()), None, Ok(None), None).is_ok());
    }

    /// P183 (Astra r1): a dangling symlink at an admin path is a broken policy, not an absent one.
    #[cfg(unix)]
    #[test]
    fn dangling_admin_symlink_refuses_start_p183() {
        let sys = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(
            sys.path().join("gone.toml"),
            sys.path().join("requirements.toml"),
        )
        .unwrap();
        let err = validate_requirements_from(Some(sys.path()), None, Ok(None), None).unwrap_err();
        assert!(err.to_string().contains("symlink"), "{err}");
    }

    /// P183 (Astra r3 HIGH): invalid UTF-8 further down must not hide a readable top-level `fail_closed = true`.
    #[test]
    fn invalid_utf8_keeps_readable_fail_closed_p183() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("requirements.toml");
        std::fs::write(&path, b"fail_closed = true\n[ui]\nyolo = false\n# \xff\n").unwrap();
        let err = validate_requirements_from(None, Some(home.path()), Ok(None), None).unwrap_err();
        assert!(err.to_string().contains("UTF-8"), "{err}");
        // Without the flag it is still only a warning
        std::fs::write(&path, b"[ui]\nyolo = false\n# \xff\n").unwrap();
        assert_eq!(
            validate_requirements_from(None, Some(home.path()), Ok(None), None)
                .unwrap()
                .len(),
            1
        );
    }

    /// P183 (Astra r3 MEDIUM): deciding fail_closed on a huge broken file is bounded work, not one parse per line.
    #[test]
    fn declares_fail_closed_is_bounded_on_huge_input_p183() {
        let body = "x".repeat(79) + "\n";
        let huge = format!(
            "fail_closed = true\nnote = \"\"\"\n{}",
            body.repeat(100_000)
        );
        let started = std::time::Instant::now();
        assert!(declares_fail_closed(&huge));
        let unflagged = format!("note = \"\"\"\n{}", body.repeat(100_000));
        assert!(!declares_fail_closed(&unflagged));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "took {:?}",
            started.elapsed()
        );
    }

    /// P183 (Astra r3 HIGH): an admin file that validated at startup and then breaks keeps its last validated pins in later
    /// loads (config load, reload), instead of the layer silently vanishing.
    #[test]
    fn broken_admin_layer_keeps_last_validated_pins_p183() {
        let sys = tempfile::tempdir().unwrap();
        let path = sys.path().join("requirements.toml");
        std::fs::write(&path, "[ui]\nyolo = false\n").unwrap();
        validate_requirements_from(Some(sys.path()), None, Ok(None), None).unwrap();
        std::fs::write(&path, "[ui\nyolo = false\n").unwrap();
        let v = load_admin_requirements_layer(&path)
            .expect("validated admin pins must survive a later parse failure");
        assert_eq!(v["ui"]["yolo"].as_bool(), Some(false));
        // P183 round 9 (M1): a deleted file keeps its validated copy for the life of the process
        std::fs::remove_file(&path).unwrap();
        let v = load_admin_requirements_layer(&path).expect("deleted file keeps the copy");
        assert_eq!(v["ui"]["yolo"].as_bool(), Some(false));
    }

    /// P183 round 4 (Grok H1): a system file that validated, then became a dangling symlink, keeps its pins; only real
    /// removal clears them.
    #[cfg(unix)]
    #[test]
    fn admin_pins_survive_dangling_symlink_after_validation_p183r4() {
        let sys = tempfile::tempdir().unwrap();
        let path = sys.path().join("requirements.toml");
        std::fs::write(&path, "[ui]\nyolo = false\n").unwrap();
        validate_requirements_from(Some(sys.path()), None, Ok(None), None).unwrap();
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink(sys.path().join("gone.toml"), &path).unwrap();
        let v = load_admin_requirements_layer(&path)
            .expect("dangling symlink must keep the validated pins");
        assert_eq!(v["ui"]["yolo"].as_bool(), Some(false));
        std::fs::remove_file(&path).unwrap();
        // P183 round 9 (M1): a file this process validated that is then DELETED keeps its copy for the life of the process
        let kept = load_admin_requirements_layer(&path).expect("deleted file keeps the validated copy");
        assert_eq!(kept["ui"]["yolo"].as_bool(), Some(false));
        // only the owner emptying it (a stable blank root-owned file) clears the policy
        std::fs::write(&path, "\n").unwrap();
        assert!(
            load_admin_requirements_layer(&path).is_none(),
            "an explicitly emptied file clears the policy"
        );
        // and the cleared entry is not resurrected by a later broken read
        std::fs::write(&path, "[ui\n").unwrap();
        // P183 round 8: broken with no validated copy is the lock-down, never "no policy"
        assert_eq!(load_admin_requirements_layer(&path), Some(admin_lockdown_requirements()));
    }

    /// P183 round 4 (Grok M3): a blank system file that is being rewritten keeps the pins; a stable blank clears them.
    #[test]
    fn admin_blank_mid_rewrite_keeps_pins_p183r4() {
        let sys = tempfile::tempdir().unwrap();
        let path = sys.path().join("requirements.toml");
        std::fs::write(&path, "[ui]\nyolo = false\n").unwrap();
        validate_requirements_from(Some(sys.path()), None, Ok(None), None).unwrap();
        std::fs::write(&path, "").unwrap();
        // The writer finishes during the blank re-check: the new content is used
        let p2 = path.clone();
        crate::loader::blank_hook::set(Some(Box::new(move || {
            std::fs::write(
                &p2,
                "[ui]\nyolo = false\ndisable_bypass_permissions_mode = true\n",
            )
            .unwrap();
        })));
        let v = load_admin_requirements_layer(&path)
            .expect("a blank mid-rewrite must not drop the pins");
        crate::loader::blank_hook::set(None);
        assert_eq!(v["ui"]["yolo"].as_bool(), Some(false));
        // A blank that stays blank is the admin clearing the policy
        std::fs::write(&path, "").unwrap();
        assert!(load_admin_requirements_layer(&path).is_none());
    }

    /// P183 round 4 (Grok H2): a real top-level flag after a long CLOSED multi-line string, before a broken tail, refuses;
    /// the same bytes with the flag only inside the unclosed tail warn.
    #[test]
    fn declares_fail_closed_after_closed_multiline_string_p183r4() {
        let body: String = (0..10).map(|i| format!("body line {i}\n")).collect();
        let tail: String = (0..6).map(|i| format!("tail line {i}\n")).collect();
        let flagged =
            format!("note = \"\"\"\n{body}\"\"\"\nfail_closed = true\ntail = \"\"\"\n{tail}");
        assert!(declares_fail_closed(&flagged));
        let only_in_tail =
            format!("note = \"\"\"\n{body}\"\"\"\ntail = \"\"\"\nfail_closed = true\n{tail}");
        assert!(!declares_fail_closed(&only_in_tail));
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join("requirements.toml"), &flagged).unwrap();
        assert!(validate_requirements_from(None, Some(home.path()), Ok(None), None).is_err());
        std::fs::write(home.path().join("requirements.toml"), &only_in_tail).unwrap();
        assert_eq!(
            validate_requirements_from(None, Some(home.path()), Ok(None), None)
                .unwrap()
                .len(),
            1
        );
    }

    /// P183 round 4: bounded even for many short lines in an unterminated string (the walk-back is capped).
    #[test]
    fn declares_fail_closed_bounded_on_short_lines_p183r4() {
        let started = std::time::Instant::now();
        let src = format!("note = \"\"\"\n{}", "x\n".repeat(200_000));
        assert!(!declares_fail_closed(&src));
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "took {:?}",
            started.elapsed()
        );
    }

    /// P183 round 4 (Grok M6): a security key of the wrong type in an admin-owned layer refuses to start (it would
    /// otherwise be ignored, lifting the pin); in a user layer it does not.
    #[test]
    fn admin_security_key_wrong_type_refuses_p183r4() {
        for bad in [
            "[ui]\nyolo = \"false\"\n",
            "[ui]\ndisable_bypass_permissions_mode = \"true\"\n",
            "ui = \"locked\"\n",
            "[features]\nweb_fetch = \"false\"\n",
            "fail_closed = \"true\"\n",
            // P183 round 6 (Grok r3 M1, M2): the CLI version bounds are strings; remote_fetch is a bool
            "[cli]\nrequired_minimum_version = 2.0\n",
            "[cli]\nminimum_version = 2\n",
            "[cli]\nmaximum_version = false\n",
            "[cli]\nrequired_maximum_version = [\"9.9.9\"]\n",
            "[features]\nremote_fetch = \"false\"\n",
        ] {
            let sys = tempfile::tempdir().unwrap();
            std::fs::write(sys.path().join("requirements.toml"), bad).unwrap();
            let err =
                validate_requirements_from(Some(sys.path()), None, Ok(None), None).expect_err(bad);
            assert!(
                matches!(err, RequirementsError::Unloadable { .. }),
                "{bad:?}: {err}"
            );
            let mdm: toml::Value = toml::from_str(bad).unwrap();
            assert!(
                validate_requirements_from(None, None, Ok(Some(mdm)), None).is_err(),
                "MDM {bad:?}"
            );
        }
        // telemetry may be a mode string
        let sys = tempfile::tempdir().unwrap();
        std::fs::write(
            sys.path().join("requirements.toml"),
            "[features]\ntelemetry = \"disabled\"\n",
        )
        .unwrap();
        assert!(validate_requirements_from(Some(sys.path()), None, Ok(None), None).is_ok());
    }

    /// P183 round 5 (Grok r2 H2): documented non-bool `[features]` shapes in an admin layer are valid: codebase_indexing as
    /// globs, telemetry as a mode string or (after a version_overrides patch) a table.
    #[test]
    fn admin_valid_feature_shapes_start_p183r5() {
        for ok in [
            "[features]\ncodebase_indexing = [\"/src/**\", \"!/src/secret/**\"]\nweb_fetch = false\n",
            "[features]\ntelemetry = \"disabled\"\n[[version_overrides]]\nminimum_version = \"0.0.0\"\n[version_overrides.features.telemetry]\nenabled = true\n",
            "[features]\ncodebase_indexing = false\nimage_gen_model_override = \"m\"\n",
        ] {
            let sys = tempfile::tempdir().unwrap();
            std::fs::write(sys.path().join("requirements.toml"), ok).unwrap();
            let r = validate_requirements_from(Some(sys.path()), None, Ok(None), None);
            assert!(r.is_ok(), "{ok:?}: {r:?}");
        }
        // Still refused: a registry bool feature as a string, codebase_indexing globs that are not strings
        for bad in [
            "[features]\nweb_fetch = \"no\"\n",
            "[features]\ncodebase_indexing = [1, 2]\n",
        ] {
            let sys = tempfile::tempdir().unwrap();
            std::fs::write(sys.path().join("requirements.toml"), bad).unwrap();
            assert!(
                validate_requirements_from(Some(sys.path()), None, Ok(None), None).is_err(),
                "{bad:?}"
            );
        }
    }

    /// P183 round 5 (Grok r2 H3): a wrong-type rewrite after startup is broken, not the new last good copy.
    #[test]
    fn admin_wrong_type_rewrite_keeps_last_good_p183r5() {
        let sys = tempfile::tempdir().unwrap();
        let path = sys.path().join("requirements.toml");
        std::fs::write(&path, "[ui]\nyolo = false\n").unwrap();
        validate_requirements_from(Some(sys.path()), None, Ok(None), None).unwrap();
        std::fs::write(&path, "[ui]\nyolo = \"false\"\n").unwrap();
        let v = load_admin_requirements_layer(&path).expect("pins kept");
        assert_eq!(v["ui"]["yolo"].as_bool(), Some(false));
        // and again on the next load (the bad text was not remembered)
        assert_eq!(
            load_admin_requirements_layer(&path).unwrap()["ui"]["yolo"].as_bool(),
            Some(false)
        );
    }

    /// P183 round 6 (Grok r3 HIGH): a rewrite after startup whose `[[version_overrides]]` no longer applies (a bound that is
    /// not semver) is broken, like a parse error: the last validated pins stay, even after a hooks scan reads the file first.
    #[test]
    fn admin_broken_version_overrides_rewrite_keeps_last_good_p183r6() {
        const PATCH: &str = "[version_overrides.ui]\nyolo = false\n[version_overrides.sandbox]\nprofile = \"strict\"\n[version_overrides.auto_mode]\nenabled = false\n";
        let assert_pins = |v: &toml::Value, when: &str| {
            assert_eq!(v["ui"]["yolo"].as_bool(), Some(false), "{when}");
            assert_eq!(v["sandbox"]["profile"].as_str(), Some("strict"), "{when}");
            assert_eq!(v["auto_mode"]["enabled"].as_bool(), Some(false), "{when}");
        };
        for base in ["", "[ui]\nyolo = true\n"] {
            let sys = tempfile::tempdir().unwrap();
            let path = sys.path().join("requirements.toml");
            std::fs::write(
                &path,
                format!("{base}[[version_overrides]]\nminimum_version = \"0.0.0\"\n{PATCH}"),
            )
            .unwrap();
            validate_requirements_from(Some(sys.path()), None, Ok(None), None).unwrap();
            assert_pins(&load_admin_requirements_layer(&path).unwrap(), "validated");
            std::fs::write(
                &path,
                format!("{base}[[version_overrides]]\nminimum_version = \"not-semver\"\n{PATCH}"),
            )
            .unwrap();
            let _ = crate::loader::hook_config_layers_at(Some(sys.path()), None);
            let v = load_admin_requirements_layer(&path)
                .expect("a broken version_overrides rewrite must keep the last validated pins");
            assert_pins(&v, &format!("after the broken rewrite, base {base:?}"));
            assert_pins(
                &load_admin_requirements_layer(&path).unwrap(),
                "the broken text was not remembered",
            );
        }
        // P183 round 9 (H1): with no last good copy (never validated in this process) the file is the LOCK-DOWN, not its base pins
        // (absent at start, then a file whose tightening is all inside a version override with a bad bound)
        let sys = tempfile::tempdir().unwrap();
        let path = sys.path().join("requirements.toml");
        std::fs::write(
            &path,
            "[ui]\nyolo = false\n[[version_overrides]]\nminimum_version = \"not-semver\"\n[version_overrides.ui]\nyolo = true\n",
        )
        .unwrap();
        assert_eq!(load_admin_requirements_layer(&path), Some(admin_lockdown_requirements()));
        assert!(admin_requirements_source_checked(&path).is_err());
        std::fs::write(&path, "[ui\n").unwrap();
        // P183 round 8: broken with no validated copy is the lock-down, never "no policy"
        assert_eq!(load_admin_requirements_layer(&path), Some(admin_lockdown_requirements()));
    }

    /// P183 round 6 (sweep): every key a `fuigo-shell` `resolve/*` reader takes from requirements with `as_bool`,
    /// `as_integer` or `as_str` is a typed pin, nested ones included (`toolset.bash.*` is three deep); legal shapes start.
    #[test]
    fn admin_resolve_reader_keys_are_typed_pins_p183r6() {
        for bad in [
            "[features]\nzdr_access_enabled = \"false\"\n",
            "[features]\nturn_transient_retry = 0\n",
            "[features]\nmcp_liveness_watchers = \"no\"\n",
            "[features]\nmcp_auto_restart = \"no\"\n",
            "[features]\nmcp_push_server_status = \"no\"\n",
            "[features]\nmcp_recursive_config_watch = \"no\"\n",
            "[diagnostics]\ncrash_handler = \"off\"\n",
            "diagnostics = \"off\"\n",
            "[ui]\nremember_tool_approvals = \"false\"\n",
            "[ui]\nprompt_suggestions = \"false\"\n",
            "[ui]\nshow_thinking_blocks = 1\n",
            "[ui]\ngroup_tool_verbs = 1\n",
            "[ui]\ncollapsed_edit_blocks = 1\n",
            "[toolset.bash]\nlogin_shell_capture = \"false\"\n",
            "[toolset.bash]\nfind_bfs = \"no\"\n",
            "[toolset.bash]\ngrep_ugrep = \"no\"\n",
            "[toolset.ask_user_question]\ntimeout_enabled = \"yes\"\n",
            "[toolset.ask_user_question]\ntimeout_secs = \"30\"\n",
            "toolset = false\n",
            "[scheduler]\nbackground_loops = \"false\"\n",
            "[mcp]\nstartup_timeout_sec = \"10\"\n",
            "[mcp]\nmax_output_bytes = 1.5\n",
            "cli = \"1.0.0\"\n",
        ] {
            let sys = tempfile::tempdir().unwrap();
            std::fs::write(sys.path().join("requirements.toml"), bad).unwrap();
            let err =
                validate_requirements_from(Some(sys.path()), None, Ok(None), None).expect_err(bad);
            assert!(
                matches!(err, RequirementsError::Unloadable { .. }),
                "{bad:?}: {err}"
            );
        }
        let ok = "[cli]\nminimum_version = \"1.0.0\"\nmaximum_version = \"9.0.0\"\nrequired_minimum_version = \"1.0.0\"\nrequired_maximum_version = \"9.0.0\"\n\
                  [features]\nremote_fetch = false\nzdr_access_enabled = true\nturn_transient_retry = false\nmcp_liveness_watchers = false\nmcp_auto_restart = false\nmcp_push_server_status = false\nmcp_recursive_config_watch = false\n\
                  [diagnostics]\ncrash_handler = false\n\
                  [ui]\nremember_tool_approvals = false\nprompt_suggestions = false\nshow_thinking_blocks = true\ngroup_tool_verbs = true\ncollapsed_edit_blocks = true\n\
                  [ui.display_refresh]\nprobe_enabled = \"off\"\n\
                  [toolset.bash]\nlogin_shell_capture = false\nfind_bfs = true\ngrep_ugrep = true\n\
                  [toolset.ask_user_question]\ntimeout_enabled = true\ntimeout_secs = 30\n\
                  [toolset.web_search]\nallowed_domains = [\"example.com\"]\n\
                  [scheduler]\nbackground_loops = false\n\
                  [mcp]\nstartup_timeout_sec = 10\nmax_output_bytes = 4096\n";
        let sys = tempfile::tempdir().unwrap();
        std::fs::write(sys.path().join("requirements.toml"), ok).unwrap();
        let r = validate_requirements_from(Some(sys.path()), None, Ok(None), None);
        assert!(r.is_ok(), "{r:?}");
    }

    /// P183 round 7 (Grok r4 H1, H2, M4, M5 and the sweep): Grok's documents, and one per newly typed reader, refuse in an
    /// admin layer (system file and MDM) and in a user layer that declares fail_closed; a plain user layer still starts.
    #[test]
    fn admin_policy_shapes_refuse_p183r7() {
        for bad in [
            "[permission]\ndeny = \"Bash\"\n",
            "[permission]\ndeny = [{ tool = \"Bash\" }]\n",
            "[permission]\nallow = 1\n",
            "[permission]\nask = [1]\n",
            "[permission]\nrules = \"deny all\"\n",
            "[[permission.rules]]\ntool = \"bash\"\n",
            "[[permission.rules]]\naction = \"block\"\n",
            "permission = \"deny\"\n",
            "hooks = []\n",
            "hooks = \"deny.sh\"\n",
            "[hooks]\nPreToolUse = \"deny.sh\"\n",
            "[[hooks.PreToolUse]]\nhooks = [{ command = \"deny.sh\" }]\n",
            "[[hooks.PreToolUse]]\nmatcher = 1\nhooks = [{ type = \"command\", command = \"deny.sh\" }]\n",
            "[[hooks.PreToolUse]]\nhooks = [{ type = \"command\", timeout = \"5\" }]\n",
            "[diagnostics]\nerror_reporting = \"false\"\n",
            "[features]\ntelemetry = \"offf\"\n",
            "[features]\ntitle_refresh = \"no\"\n",
            "[telemetry]\ntrace_upload = \"false\"\n",
            "[telemetry]\notel_enabled = \"false\"\n",
            "[telemetry]\nevents_url = 1\n",
            "[managed_mcps]\nenabled = \"false\"\n",
            "[subagents]\nenabled = 0\n",
            "[memory]\nenabled = \"no\"\n",
            "[cli]\nauto_update = \"false\"\n",
            "[cli]\nchannel = 1\n",
            "[models]\ndefault = 1\n",
            "[tools]\nrespect_gitignore = \"yes\"\n",
            "[endpoints]\nfuigo_api_base_url = 1\n",
            "[endpoints]\ndeployment_key = false\n",
        ] {
            let sys = tempfile::tempdir().unwrap();
            std::fs::write(sys.path().join("requirements.toml"), bad).unwrap();
            let err =
                validate_requirements_from(Some(sys.path()), None, Ok(None), None).expect_err(bad);
            assert!(
                matches!(err, RequirementsError::Unloadable { .. }),
                "{bad:?}: {err}"
            );
            let mdm: toml::Value = toml::from_str(bad).unwrap();
            assert!(
                validate_requirements_from(None, None, Ok(Some(mdm)), None).is_err(),
                "MDM {bad:?}"
            );
            let home = tempfile::tempdir().unwrap();
            std::fs::write(home.path().join("requirements.toml"), bad).unwrap();
            assert!(
                validate_requirements_from(None, Some(home.path()), Ok(None), None).is_err(),
                "round 8: a user layer with a malformed key refuses even without fail_closed: {bad:?}"
            );
            std::fs::write(
                home.path().join("requirements.toml"),
                format!("fail_closed = true\n{bad}"),
            )
            .unwrap();
            assert!(
                validate_requirements_from(None, Some(home.path()), Ok(None), None).is_err(),
                "a fail_closed user layer refuses: {bad:?}"
            );
        }
        // The legal shapes start
        let ok = "[permission]\ndeny = [\"Bash(rm *)\"]\nallow = []\n[[permission.rules]]\naction = \"deny\"\ntool = \"webfetch\"\npattern = \"*\"\npattern_mode = \"domain\"\n\
                  [[hooks.PreToolUse]]\nmatcher = \"Bash\"\nhooks = [{ type = \"command\", command = \"deny.sh\", timeout = 5, env = { A = \"b\" } }]\n\
                  [diagnostics]\nerror_reporting = false\n[features]\ntelemetry = \"session_metrics\"\n";
        let sys = tempfile::tempdir().unwrap();
        std::fs::write(sys.path().join("requirements.toml"), ok).unwrap();
        let r = validate_requirements_from(Some(sys.path()), None, Ok(None), None);
        assert!(r.is_ok(), "{r:?}");
    }

    /// P183 round 7 (sweep): the root-owned `/etc/fuigo/managed_config.toml` is admin-owned too: present but broken, or with a
    /// policy key of the wrong type (its `[permission]` denies and `[hooks]` are policy), it refuses to start.
    #[test]
    fn system_managed_config_broken_refuses_p183r7() {
        for bad in [
            "[permission\n",
            "[permission]\ndeny = \"Bash\"\n",
            "hooks = []\n",
            "[features]\nremote_fetch = \"false\"\n",
        ] {
            let sys = tempfile::tempdir().unwrap();
            std::fs::write(sys.path().join("managed_config.toml"), bad).unwrap();
            assert!(
                validate_requirements_from(Some(sys.path()), None, Ok(None), None).is_err(),
                "{bad:?}"
            );
        }
        let sys = tempfile::tempdir().unwrap();
        std::fs::write(
            sys.path().join("managed_config.toml"),
            "[permission]\ndeny = [\"Bash(rm *)\"]\n",
        )
        .unwrap();
        assert!(validate_requirements_from(Some(sys.path()), None, Ok(None), None).is_ok());
    }

    /// P183 round 7 (THE SWEEP): one table-driven test over every typed pin ([`TYPED_PINS`] and both `[features]` bool
    /// lists). One document with every pin in a legal shape starts; that document with any single pin replaced by a value of
    /// the wrong type refuses (MDM and system file, naming the key), and so does a user layer that declares fail_closed.
    #[test]
    fn every_typed_pin_refuses_wrong_type_p183r7() {
        use toml::Value;
        fn table(entries: &[(&str, Value)]) -> Value {
            Value::Table(
                entries
                    .iter()
                    .map(|(k, v)| ((*k).to_owned(), v.clone()))
                    .collect(),
            )
        }
        let legal = |ty: PinType| match ty {
            PinType::Bool => Value::Boolean(false),
            PinType::Str => Value::String("1.0.0".into()),
            PinType::Int => Value::Integer(10),
            PinType::Table => table(&[]),
            PinType::StrArray => Value::Array(vec![Value::String("Bash(rm *)".into())]),
            PinType::Telemetry => Value::String("disabled".into()),
            PinType::CodebaseIndexing => Value::Array(vec![Value::String("/src/**".into())]),
            PinType::PermissionRules => Value::Array(vec![table(&[
                ("action", Value::String("deny".into())),
                ("tool", Value::String("bash".into())),
                ("pattern", Value::String("rm *".into())),
            ])]),
            PinType::HookEvent => Value::Array(vec![table(&[
                ("matcher", Value::String("Bash".into())),
                (
                    "hooks",
                    Value::Array(vec![table(&[
                        ("type", Value::String("command".into())),
                        ("command", Value::String("deny.sh".into())),
                        ("timeout", Value::Integer(5)),
                    ])]),
                ),
            ])]),
        };
        let wrong = |ty: PinType| match ty {
            PinType::Bool => Value::String("false".into()),
            PinType::Str => Value::Integer(1),
            PinType::Int => Value::String("10".into()),
            PinType::Table => Value::String("locked".into()),
            PinType::StrArray => Value::Array(vec![table(&[("tool", Value::String("Bash".into()))])]),
            PinType::Telemetry => Value::String("offf".into()),
            PinType::CodebaseIndexing => Value::Array(vec![Value::Integer(1)]),
            PinType::PermissionRules => Value::Array(vec![table(&[("tool", Value::String("bash".into()))])]),
            PinType::HookEvent => Value::String("deny.sh".into()),
        };
        fn set(doc: &mut Value, path: &[String], v: Value) {
            let (last, parents) = path.split_last().unwrap();
            let mut t = doc.as_table_mut().unwrap();
            for key in parents {
                t = t
                    .entry(key.clone())
                    .or_insert_with(|| Value::Table(Default::default()))
                    .as_table_mut()
                    .unwrap();
            }
            t.insert(last.clone(), v);
        }
        let mut pins: Vec<(Vec<String>, PinType)> = TYPED_PINS
            .iter()
            .map(|(p, ty)| (p.split('.').map(|k| k.replace('*', "PreToolUse")).collect(), *ty))
            .collect();
        for k in REQUIREMENTS_BOOL_FEATURES.iter().chain(REQUIREMENTS_RESOLVE_BOOL_FEATURES) {
            pins.push((vec!["features".into(), (*k).into()], PinType::Bool));
        }
        assert!(pins.len() > 100, "{}", pins.len());
        // Sections first, so a section's legal empty table never replaces the keys set under it
        pins.sort_by_key(|(p, _)| p.len());
        let mut doc = table(&[]);
        for (path, ty) in &pins {
            assert_eq!(pin_type(path), Some(*ty), "{path:?} is shadowed by another pin");
            if *ty != PinType::Table || doc.get(&path[0]).is_none() {
                set(&mut doc, path, legal(*ty));
            }
        }
        let mdm = |v: &Value| validate_requirements_value(v.clone(), &RequirementsSource::Mdm, true);
        assert!(mdm(&doc).is_ok(), "the all-legal document must start: {:?}", mdm(&doc));
        let sys = tempfile::tempdir().unwrap();
        std::fs::write(sys.path().join("requirements.toml"), toml::to_string(&doc).unwrap()).unwrap();
        let r = validate_requirements_from(Some(sys.path()), None, Ok(None), None);
        assert!(r.is_ok(), "all-legal system file: {r:?}");
        for (path, ty) in &pins {
            let mut bad = doc.clone();
            set(&mut bad, path, wrong(*ty));
            let key = path.join(".");
            let err = mdm(&bad).expect_err(&key).to_string();
            assert!(err.contains(&key), "{key}: {err}");
            // Round 8: a user layer with a malformed key refuses with or without fail_closed
            if key == FAIL_CLOSED_KEY {
                continue;
            }
            let mut user = bad.clone();
            assert!(
                validate_requirements_value(user.clone(), &RequirementsSource::File("u".into()), false).is_err(),
                "{key}: a user layer with a malformed key refuses"
            );
            set(&mut user, &[FAIL_CLOSED_KEY.to_owned()], Value::Boolean(true));
            assert!(
                validate_requirements_value(user, &RequirementsSource::File("u".into()), false).is_err(),
                "{key}: a fail_closed user layer refuses"
            );
        }
        // And as a system file, for one pin of every type
        for ty in [
            PinType::Bool,
            PinType::Str,
            PinType::Int,
            PinType::Table,
            PinType::StrArray,
            PinType::Telemetry,
            PinType::CodebaseIndexing,
            PinType::PermissionRules,
            PinType::HookEvent,
        ] {
            let (path, _) = pins.iter().find(|(_, t)| *t == ty).unwrap();
            let mut bad = doc.clone();
            set(&mut bad, path, wrong(ty));
            std::fs::write(sys.path().join("requirements.toml"), toml::to_string(&bad).unwrap()).unwrap();
            assert!(
                validate_requirements_from(Some(sys.path()), None, Ok(None), None).is_err(),
                "{path:?}"
            );
        }
    }

    /// P183 round 7 (Grok r4 H3): `managed-settings.json` with any policy key of the wrong type, not JSON, or a dangling
    /// symlink refuses to start; a legal file starts and becomes the last good copy, which a later broken rewrite keeps;
    /// a stable blank (not removal) clears it; a broken file never validated is `Broken` (callers lock down), never "absent".
    #[test]
    fn managed_settings_wrong_types_refuse_and_keep_last_good_p183r7() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("managed-settings.json");
        let check = || validate_managed_settings_file(Some(&path));
        for bad in [
            r#"[]"#,
            r#"{"env": "DISABLE_TELEMETRY=1"}"#,
            r#"{"env": {"DISABLE_TELEMETRY": ["1"]}}"#,
            r#"{"permissions": "deny"}"#,
            r#"{"permissions": {"deny": "Bash"}}"#,
            r#"{"permissions": {"allow": [1]}}"#,
            r#"{"permissions": {"ask": {"Bash": true}}}"#,
            r#"{"permissions": {"defaultMode": 1}}"#,
            r#"{"permissions": {"disableBypassPermissionsMode": true}}"#,
            r#"{"defaultMode": false}"#,
            r#"{"deniedMcpServers": {"serverUrl": "https://evil.example/*"}}"#,
            r#"{"allowedMcpServers": "*"}"#,
            r#"{"deniedMcpServers": [{"serverUrl": 1}]}"#,
            r#"{"deniedMcpServers": [{"url": "https://evil.example/*"}]}"#,
            r#"{"deniedMcpServers": [{"serverCommand": []}]}"#,
            r#"{"deniedMcpServers": ["evil"]}"#,
            r#"{"strictKnownMarketplaces": {"source": "git", "url": "https://github.com/corp/plugins.git"}}"#,
            r#"{"strictKnownMarketplaces": [{"url": "https://github.com/corp/plugins.git"}]}"#,
            r#"{"strictKnownMarketplaces": [{"source": "git"}]}"#,
            "{ not json",
        ] {
            std::fs::write(&path, bad).unwrap();
            let err = check().expect_err(bad);
            assert!(matches!(err, RequirementsError::Unloadable { .. }), "{bad}: {err}");
            assert!(matches!(managed_settings_json(&path), ManagedSettingsJson::Broken(_)), "{bad}");
        }
        let legal = r#"{"env": {"DISABLE_TELEMETRY": "1", "N": 1, "B": true},
            "permissions": {"deny": ["Bash(rm *)"], "allow": [], "defaultMode": "default", "disableBypassPermissionsMode": "disable"},
            "allowedMcpServers": [{"serverName": "ok"}, {"serverCommand": ["npx", "ok"]}, {"command": "uvx"}],
            "deniedMcpServers": [{"serverUrl": "https://evil.example/*"}],
            "strictKnownMarketplaces": [{"source": "git", "url": "https://github.com/corp/plugins.git"}, {"source": "github", "repo": "corp/x"}],
            "model": "anything"}"#;
        std::fs::write(&path, legal).unwrap();
        check().unwrap();
        // A later rewrite that is not JSON keeps the validated copy
        std::fs::write(&path, "{ not json").unwrap();
        let ManagedSettingsJson::Loaded(kept) = managed_settings_json(&path) else {
            panic!("the last validated copy must be kept");
        };
        assert_eq!(kept["deniedMcpServers"][0]["serverUrl"], "https://evil.example/*");
        // P186c (decision 24; was: the copy is kept): a rewrite with a wrong-typed policy key is the lock-down
        std::fs::write(&path, r#"{"deniedMcpServers": {"serverUrl": "x"}}"#).unwrap();
        assert!(matches!(managed_settings_json(&path), ManagedSettingsJson::Broken(_)));
        // P183 round 13 (Grok r9 M2): removal does NOT clear it (round 7 asserted `Absent` here): a process that validated the
        // file keeps enforcing that copy after an unlink; only the owner's STABLE blank file clears it, and a cleared copy is
        // not resurrected
        std::fs::remove_file(&path).unwrap();
        let ManagedSettingsJson::Loaded(still) = managed_settings_json(&path) else {
            panic!("the validated copy must survive the unlink");
        };
        assert_eq!(still["deniedMcpServers"][0]["serverUrl"], "https://evil.example/*");
        assert!(check().is_ok());
        assert!(admin_requirements_copy_exists(&path));
        std::fs::write(&path, "\n").unwrap();
        assert!(matches!(managed_settings_json(&path), ManagedSettingsJson::Absent));
        assert!(!admin_requirements_copy_exists(&path));
        assert!(check().is_ok());
        std::fs::write(&path, "{ not json").unwrap();
        assert!(matches!(managed_settings_json(&path), ManagedSettingsJson::Broken(_)));
        #[cfg(unix)]
        {
            std::fs::remove_file(&path).unwrap();
            std::os::unix::fs::symlink(dir.path().join("gone.json"), &path).unwrap();
            assert!(check().is_err(), "a dangling symlink is broken, not absent");
        }
    }

    /// P183 round 7 (sweep): the system `managed_config.toml` keeps its last validated copy when it breaks after startup.
    #[test]
    fn system_managed_config_keeps_last_good_p183r7() {
        let sys = tempfile::tempdir().unwrap();
        let path = sys.path().join("managed_config.toml");
        std::fs::write(&path, "[permission]\ndeny = [\"Bash(rm *)\"]\n").unwrap();
        validate_requirements_from(Some(sys.path()), None, Ok(None), None).unwrap();
        std::fs::write(&path, "[permission\n").unwrap();
        let layers = crate::loader::managed_config_layers_at(Some(sys.path()), None);
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].value["permission"]["deny"][0].as_str(), Some("Bash(rm *)"));
        // P186c (decision 24; was: the copy is kept): a wrong-typed pin is the lock-down until the file is fixed
        std::fs::write(&path, "[permission]\ndeny = \"Bash\"\n").unwrap();
        let layers = crate::loader::managed_config_layers_at(Some(sys.path()), None);
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].value, admin_lockdown_managed_config());
        std::fs::write(&path, "[permission\n").unwrap();
        let layers = crate::loader::managed_config_layers_at(Some(sys.path()), None);
        assert_eq!(layers[0].value["permission"]["deny"][0].as_str(), Some("Bash(rm *)"));
        // P183 round 9 (M1): a deleted validated file keeps its copy
        std::fs::remove_file(&path).unwrap();
        let layers = crate::loader::managed_config_layers_at(Some(sys.path()), None);
        assert_eq!(layers.len(), 1);
        assert_eq!(layers[0].value["permission"]["deny"][0].as_str(), Some("Bash(rm *)"));
    }

    /// P183 round 4 (Grok L7): the startup error does not echo the raw bad bound (it can carry a secret).
    #[test]
    fn invalid_version_overrides_error_is_redacted_p183r4() {
        let sys = tempfile::tempdir().unwrap();
        std::fs::write(
            sys.path().join("requirements.toml"),
            "[ui]\nyolo = false\n[[version_overrides]]\nminimum_version = \"s3cr3t-not-semver\"\n",
        )
        .unwrap();
        let msg = validate_requirements_from(Some(sys.path()), None, Ok(None), None)
            .unwrap_err()
            .to_string();
        assert!(msg.contains("minimum_version is not valid semver"), "{msg}");
        assert!(!msg.contains("s3cr3t"), "{msg}");
    }

    /// P183 round 4: the requirements-file reader used by `fuigo inspect` reports a dangling symlink as not loaded.
    #[cfg(unix)]
    #[test]
    fn requirements_file_load_error_reports_dangling_symlink_p183r4() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("requirements.toml");
        assert_eq!(requirements_file_load_error(&path), None);
        std::os::unix::fs::symlink(home.path().join("gone.toml"), &path).unwrap();
        assert!(
            requirements_file_load_error(&path)
                .unwrap()
                .contains("symlink")
        );
    }

    /// P183 (Astra r2): a dangling symlink at the policy DIRECTORY is broken too, not absent.
    #[cfg(unix)]
    #[test]
    fn dangling_admin_dir_symlink_refuses_start_p183() {
        let root = tempfile::tempdir().unwrap();
        let sys = root.path().join("etc-fuigo");
        std::os::unix::fs::symlink(root.path().join("removed"), &sys).unwrap();
        let err = validate_requirements_from(Some(&sys), None, Ok(None), None).unwrap_err();
        assert!(err.to_string().contains("directory"), "{err}");
        // A plain missing directory is still "no system policy"
        let none = root.path().join("absent");
        assert!(validate_requirements_from(Some(&none), None, Ok(None), None).is_ok());
    }

    /// P183 (Astra r1): the per-layer override check re-reads the file; an admin file that fails that read refuses too.
    #[test]
    fn admin_layer_second_read_failure_refuses_p183() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("requirements.toml");
        std::fs::write(&path, "[ui\n").unwrap();
        assert!(matches!(
            validate_requirements_layer(&path, true).unwrap_err(),
            RequirementsError::Unloadable { .. }
        ));
        assert!(validate_requirements_layer(&path, false).is_ok());
    }

    /// P183: the user-home layer follows P162's user rule: it warns and starts, unless fail_closed applies (env force-on, or the file's own readable top-level line).
    #[test]
    fn unparseable_user_requirements_warn_unless_fail_closed_p183() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("requirements.toml");
        std::fs::write(&path, "[ui\nyolo = false\n").unwrap();
        // Starts, but hands back a warning naming the file for the caller to print (tracing is not up yet at startup)
        let warnings = validate_requirements_from(None, Some(home.path()), Ok(None), None).unwrap();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(
            warnings[0].contains(&path.display().to_string()),
            "{warnings:?}"
        );
        assert!(
            warnings[0].contains("NONE of its pins are in force"),
            "{warnings:?}"
        );
        assert!(validate_requirements_from(None, Some(home.path()), Ok(None), Some(false)).is_ok());
        assert!(matches!(
            validate_requirements_from(None, Some(home.path()), Ok(None), Some(true)).unwrap_err(),
            RequirementsError::Unloadable { .. }
        ));
        for declared in [
            "fail_closed = true\n",
            "  fail_closed=true # admin\n",
            "\"fail_closed\" = true\n",
            "'fail_closed' = true\n",
            // a multi-line string whose body looks like a header does not end the top level (Astra r1)
            "note = \"\"\"\n[example]\n\"\"\"\nfail_closed = true\n",
            // quotes in a comment do not hide the flag; an escaped key is the same key (Astra r2)
            "fail_closed = true # \"\"\"\n",
            "\"fail_\\u0063losed\" = true\n",
        ] {
            std::fs::write(&path, format!("{declared}[ui\nyolo = false\n")).unwrap();
            assert!(
                validate_requirements_from(None, Some(home.path()), Ok(None), None).is_err(),
                "{declared:?}"
            );
        }
        // Only a top-level `fail_closed = true` counts: under a table header, or false, it is not the layer's flag.
        for not_declared in [
            "[x]\nfail_closed = true\n[ui\n",
            "fail_closed = false\n[ui\n",
            "# fail_closed = true\n[ui\n",
            // text inside a multi-line string is not an opt-in (Astra r1)
            "fail_closed = false\nnote = \'\'\'\nfail_closed = true\n\'\'\'\n[ui\n",
            // a different quoted key, and an escaped quote that does not end the string, are not opt-ins (Astra r2)
            "\"fail _closed\" = true\n[ui\n",
            "note = \"\"\"\n\\\"\"\"\nfail_closed = true\n\"\"\"\n[ui\n",
            // a flag only after the first unparseable line is not readable
            "[ui\nfail_closed = true\n",
        ] {
            std::fs::write(&path, not_declared).unwrap();
            assert!(
                validate_requirements_from(None, Some(home.path()), Ok(None), None).is_ok(),
                "{not_declared:?}"
            );
        }
    }

    /// P183: `FUIGO_TEST_VERSION` is honoured only in a dev build and only when it parses; otherwise the compiled version is used.
    #[test]
    fn policy_semver_ignores_unusable_or_release_test_version_p183() {
        use crate::loader::policy_semver_from;
        let v = |s: &str| semver::Version::parse(s).unwrap();
        assert_eq!(
            policy_semver_from(Some("garbage"), "1.0.22", true).unwrap(),
            v("1.0.22")
        );
        assert_eq!(
            policy_semver_from(Some("2.0.0"), "1.0.22", false).unwrap(),
            v("1.0.22")
        );
        assert_eq!(
            policy_semver_from(Some(" 2.0.0 "), "1.0.22", true).unwrap(),
            v("2.0.0")
        );
        assert_eq!(
            policy_semver_from(None, "1.0.22", true).unwrap(),
            v("1.0.22")
        );
        assert!(policy_semver_from(Some("garbage"), "not-semver", true).is_err());
    }

    /// Even with `fail_closed = true` in the file: enforcement is `validate_requirements`, not the loader.
    /// P162: the loader keeps the layer's base pins and applies nothing from the bad section.
    #[test]
    fn load_requirements_layer_keeps_base_on_invalid_version_overrides() {
        use std::io::Write;

        let dir = std::env::temp_dir().join(format!("fuigo-vo-soft-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("requirements.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            r#"
fail_closed = true
[[version_overrides]]
minimum_version = "not-a-version"
[version_overrides.features]
telemetry = true
"#
        )
        .unwrap();

        let v = load_requirements_layer(&path).expect("layer must survive");
        assert!(v.get("features").is_none(), "no patch from the bad section");
        assert!(v.get("version_overrides").is_none());
        let _ = std::fs::remove_file(&path);
    }

    /// P162: a requirements layer whose `[[version_overrides]]` cannot parse must keep its parseable base pins.
    /// Dropping the whole layer would silently lift `yolo = false` and the sandbox profile for managed policy.
    #[test]
    fn bad_version_overrides_keep_base_pins_p162() {
        let bad_forms = [
            "[[version_overrides]]\nminimum_version = \"not-a-version\"\n",
            "[[version_overrides]]\nmaximum_version = \"nope\"\n",
            "version_overrides = \"not-an-array\"\n",
        ];
        for (i, bad) in bad_forms.iter().enumerate() {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("requirements.toml");
            std::fs::write(
                &path,
                format!("{bad}\n[ui]\nyolo = false\n[sandbox]\nprofile = \"strict\"\n"),
            )
            .unwrap();
            let v = load_requirements_layer(&path)
                .unwrap_or_else(|| panic!("form {i}: layer dropped whole; pins lost"));
            assert_eq!(v["ui"]["yolo"].as_bool(), Some(false), "form {i}");
            assert_eq!(v["sandbox"]["profile"].as_str(), Some("strict"), "form {i}");
            assert!(
                v.get("version_overrides").is_none(),
                "form {i}: key must be stripped"
            );
        }
    }

    /// P162: the same holds for the MDM value, and no override patch is applied from a bad section.
    #[test]
    fn mdm_bad_version_overrides_keep_base_pins_p162() {
        let raw: toml::Value = toml::from_str(
            "[ui]\nyolo = false\n[[version_overrides]]\nminimum_version = \"x\"\n[version_overrides.ui]\nyolo = true\n",
        )
        .unwrap();
        let v = normalize_requirements_value(raw, crate::macos_managed::MDM_REQUIREMENTS_SOURCE)
            .expect("layer must survive");
        assert_eq!(v["ui"]["yolo"].as_bool(), Some(false));
        assert!(v.get("version_overrides").is_none());
    }

    #[test]
    fn validate_requirements_layer_errs_on_fail_closed_violation() {
        use std::io::Write;

        let dir = std::env::temp_dir().join(format!("fuigo-vo-validate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("requirements.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            r#"
fail_closed = true
[[version_overrides]]
minimum_version = "not-a-version"
"#
        )
        .unwrap();

        let err = validate_requirements_layer(&path, false).unwrap_err();
        assert!(matches!(
            err,
            RequirementsError::InvalidVersionOverrides { .. }
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn validate_requirements_layer_ok_without_fail_closed() {
        use std::io::Write;

        let dir = std::env::temp_dir().join(format!("fuigo-vo-soft2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("requirements.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(
            f,
            r#"
[[version_overrides]]
minimum_version = "not-a-version"
"#
        )
        .unwrap();

        assert!(validate_requirements_layer(&path, false).is_ok());
        // P162: the same file as an admin-owned (system) layer is refused even without fail_closed
        assert!(matches!(
            validate_requirements_layer(&path, true).unwrap_err(),
            RequirementsError::InvalidVersionOverrides { .. }
        ));
        let _ = std::fs::remove_file(&path);
    }

    // Through the pure core: writing `FUIGO_MANAGED_CONFIG_FAIL_CLOSED=1` process-wide made every
    // concurrent `validate_requirements` caller (e.g. the soft-fail layer test) fail closed.
    #[test]
    fn fail_closed_env_can_tighten_but_not_loosen() {
        let off: toml::Value = toml::from_str("fail_closed = false\n").unwrap();
        let on: toml::Value = toml::from_str("fail_closed = true\n").unwrap();

        // env=1 force-enables even when the file is off (tighten is allowed).
        assert!(resolve_fail_closed_mode_for(Some(true), &off));
        assert!(resolve_fail_closed_mode_for(Some(true), &on));

        // env=0 must NOT disable an admin's fail_closed=true (no local bypass).
        assert!(
            resolve_fail_closed_mode_for(Some(false), &on),
            "a local env must not loosen admin fail_closed"
        );
        assert!(!resolve_fail_closed_mode_for(Some(false), &off));

        // Unset: the admin file flag governs
        assert!(resolve_fail_closed_mode_for(None, &on));
        assert!(!resolve_fail_closed_mode_for(None, &off));
    }

    #[test]
    fn fail_closed_flag_reads_the_opt_in() {
        let flag = |s: &str| fail_closed_flag(&toml::from_str::<toml::Value>(s).unwrap());
        assert!(flag("fail_closed = true\n"));
        assert!(!flag("fail_closed = false\n"));
        assert!(!flag("[features]\ntelemetry = true\n"));
        assert!(!flag("fail_closed = \"yes\"\n"));
        assert!(!flag(""));
    }

    #[test]
    fn fail_closed_key_is_stripped_from_returned_layer() {
        use std::io::Write;

        let dir = std::env::temp_dir().join(format!("fuigo-vo-strip-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("requirements.toml");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "fail_closed = true\n[features]\ntelemetry = true\n").unwrap();

        let result = load_requirements_layer(&path).unwrap();
        assert!(
            result.get(FAIL_CLOSED_KEY).is_none(),
            "fail_closed must not leak into the returned config"
        );
        assert_eq!(result["features"]["telemetry"].as_bool(), Some(true));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn load_user_requirements_is_none_without_user_home() {
        // No resolvable user home means no user requirements (no cwd-relative read)
        assert!(load_user_requirements(None).is_none());
    }

    #[test]
    fn load_user_requirements_reads_layer_when_home_present() {
        use std::io::Write;

        let dir = std::env::temp_dir().join(format!("fuigo-req-load-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut f = std::fs::File::create(dir.join("requirements.toml")).unwrap();
        writeln!(f, "[features]\ntelemetry = true\n").unwrap();

        let v = load_user_requirements(Some(&dir)).expect("layer present");
        assert_eq!(v["features"]["telemetry"].as_bool(), Some(true));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_user_requirements_ok_without_user_home() {
        // No user home means nothing to validate, no error
        assert!(validate_user_requirements(None).is_ok());
    }

    #[test]
    fn validate_user_requirements_errs_on_fail_closed_violation() {
        use std::io::Write;

        let dir = std::env::temp_dir().join(format!("fuigo-req-validate-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mut f = std::fs::File::create(dir.join("requirements.toml")).unwrap();
        writeln!(
            f,
            r#"
fail_closed = true
[[version_overrides]]
minimum_version = "not-a-version"
"#
        )
        .unwrap();

        let err = validate_user_requirements(Some(&dir)).unwrap_err();
        assert!(matches!(
            err,
            RequirementsError::InvalidVersionOverrides { .. }
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The macOS MDM layer has no file on disk; `mdm_requirements_value` and `validate_requirements` hand the CFPreferences value straight to these.
    /// Normalizing must still strip `fail_closed` and keep the clamp.
    /// Enforcement must still Err on a bad override under `fail_closed`.
    #[test]
    fn mdm_value_normalizes_and_enforces_like_a_file() {
        let source = crate::macos_managed::MDM_REQUIREMENTS_SOURCE;

        // Effective view: fail_closed stripped, the forced clamp kept.
        let raw: toml::Value =
            toml::from_str("fail_closed = true\n[features]\nweb_fetch = false\n").unwrap();
        let normalized = normalize_requirements_value(raw, source).unwrap();
        assert!(normalized.get(FAIL_CLOSED_KEY).is_none());
        assert_eq!(normalized["features"]["web_fetch"].as_bool(), Some(false));

        // Enforcement keeps fail_closed: a bad override under fail_closed errs; the same override without fail_closed soft-fails (Ok)
        let bad: toml::Value = toml::from_str(
            "fail_closed = true\n[[version_overrides]]\nminimum_version = \"not-a-version\"\n",
        )
        .unwrap();
        assert!(matches!(
            validate_requirements_value(bad, &RequirementsSource::Mdm, true).unwrap_err(),
            RequirementsError::InvalidVersionOverrides { .. }
        ));
        let soft: toml::Value =
            toml::from_str("[[version_overrides]]\nminimum_version = \"not-a-version\"\n").unwrap();
        assert!(validate_requirements_value(soft.clone(), &RequirementsSource::Mdm, false).is_ok());
        // P162: MDM is admin-owned, so enforcement refuses it without fail_closed too
        assert!(validate_requirements_value(soft, &RequirementsSource::Mdm, true).is_err());
    }
    /// P183 round 8: a user requirements file that parses but has a malformed key refuses to load, and the message names the
    /// file path and the key and says how to fix it (before, the key was ignored unless fail_closed was set).
    #[test]
    fn user_file_malformed_key_fails_closed_naming_path_and_key_p183r8() {
        let v: toml::Value = toml::from_str("[features]\nweb_fetch = \"no\"\n").unwrap();
        let path = "/home/u/.fuigo/requirements.toml";
        let err = validate_requirements_value(
            v,
            &RequirementsSource::File(PathBuf::from(path)),
            false,
        )
        .expect_err("a malformed key in a parsing user file must fail closed");
        let msg = err.to_string();
        assert!(msg.contains(path), "{msg}");
        assert!(msg.contains("features.web_fetch"), "{msg}");
        assert!(msg.contains("Fix:"), "{msg}");
    }

    /// P183 round 8: a broken system file with no validated copy is carried as an error by the checked reader and enforces the
    /// lock-down in the infallible one; it is never "no policy".
    #[test]
    fn broken_admin_layer_is_lockdown_not_absent_p183r8() {
        let lock = admin_lockdown_requirements();
        assert_eq!(lock["ui"]["disable_bypass_permissions_mode"].as_bool(), Some(true));
        assert!(
            REQUIREMENTS_BOOL_FEATURES
                .iter()
                .all(|k| lock["features"][*k].as_bool() == Some(false))
        );
    }

    /// P183 round 9 (Grok r5 H3): the lock-down has a value for every typed pin, or says why none is stricter.
    #[test]
    fn lockdown_covers_every_typed_pin_p183r9() {
        let entries = lockdown_entries();
        let set: std::collections::HashSet<&str> = entries.iter().map(|(k, _)| k.as_str()).collect();
        let unset = |k: &str| {
            LOCKDOWN_UNSET.iter().any(|(u, why)| {
                !why.is_empty() && (*u == k || u.strip_suffix('*').is_some_and(|p| k.starts_with(p)))
            })
        };
        let mut missing = Vec::new();
        for (path, ty) in TYPED_PINS {
            if matches!(ty, PinType::Table) {
                continue;
            }
            if !set.contains(path) && !unset(path) {
                missing.push((*path).to_owned());
            }
        }
        for k in REQUIREMENTS_BOOL_FEATURES.iter().chain(REQUIREMENTS_RESOLVE_BOOL_FEATURES) {
            let p = format!("features.{k}");
            if !set.contains(p.as_str()) && !unset(&p) {
                missing.push(p);
            }
        }
        assert!(missing.is_empty(), "pins with no lock-down value and no reason: {missing:?}");
        let lock = admin_lockdown_requirements();
        assert_eq!(lock["permission"]["rules"][0]["action"].as_str(), Some("deny"));
        assert!(lock["permission"]["rules"][0].get("tool").is_none(), "tool defaults to any");
        assert_eq!(lock["sandbox"]["profile"].as_str(), Some("strict"));
        assert_eq!(lock["auto_mode"]["enabled"].as_bool(), Some(false));
        assert_eq!(lock["models"]["allowed_models"][0].as_str(), Some(LOCKDOWN_NO_MODEL));
        assert_eq!(lock["diagnostics"]["error_reporting"].as_bool(), Some(false));
        assert_eq!(lock["memory"]["enabled"].as_bool(), Some(false));
        let mc = admin_lockdown_managed_config();
        assert_eq!(mc["permission"]["rules"][0]["action"].as_str(), Some("deny"));
        assert_eq!(mc["sandbox"]["profile"].as_str(), Some("strict"));
    }

    /// P183 round 9 (Grok r5 M1): a validated admin file that disappears is still enforced; a new process never saw it.
    #[test]
    fn deleted_admin_file_keeps_validated_copy_p183r9() {
        let sys = tempfile::tempdir().unwrap();
        let path = sys.path().join("requirements.toml");
        std::fs::write(&path, "[sandbox]\nprofile = \"strict\"\n").unwrap();
        assert!(admin_requirements_source_checked(&path).unwrap().is_some());
        std::fs::remove_file(&path).unwrap();
        let again = admin_requirements_source_checked(&path).unwrap().expect("copy kept");
        assert!(again.contains("strict"));
        let other = sys.path().join("never-seen.toml");
        assert_eq!(admin_requirements_source_checked(&other), Ok(None));
    }

    /// P183 round 9 (Grok r5 M2): an absent system managed_config.toml is an empty table, opened once.
    #[test]
    fn absent_managed_config_is_empty_without_second_read_p183r9() {
        let sys = tempfile::tempdir().unwrap();
        let v = crate::loader::load_admin_config_file(&sys.path().join("managed_config.toml")).unwrap();
        assert!(v.as_table().unwrap().is_empty());
        let bad = sys.path().join("bad").join("managed_config.toml");
        std::fs::create_dir_all(bad.parent().unwrap()).unwrap();
        std::fs::write(&bad, "[permission\n").unwrap();
        assert!(crate::loader::load_admin_config_file(&bad).is_err());
    }

    /// P183 round 9 (Grok r5 M3): a user file that gains a bad key mid-session keeps its last valid copy; with none it fails closed.
    #[test]
    fn user_file_gaining_bad_key_keeps_last_valid_copy_p183r9() {
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join("requirements.toml");
        std::fs::write(&path, "[permission]\ndeny = [\"Bash\"]\n[sandbox]\nprofile = \"strict\"\n").unwrap();
        assert!(load_requirements_layer(&path).is_some());
        std::fs::write(&path, "[permission]\ndeny = [\"Bash\"]\n[sandbox]\nprofile = 7\n").unwrap();
        let kept = load_requirements_layer(&path).expect("kept");
        assert_eq!(kept["sandbox"]["profile"].as_str(), Some("strict"));
        assert_eq!(kept["permission"]["deny"][0].as_str(), Some("Bash"));
        let fresh = tempfile::tempdir().unwrap();
        let p2 = fresh.path().join("requirements.toml");
        std::fs::write(&p2, "[sandbox]\nprofile = 7\n").unwrap();
        assert_eq!(load_requirements_layer(&p2), Some(admin_lockdown_requirements()));
    }

    /// P183 round 9 (Grok r5 M4): a forced MDM payload that does not decode is the lock-down, not an omitted layer.
    #[test]
    fn undecodable_mdm_payload_is_lockdown_p183r9() {
        assert!(mdm_layer_checked(&Err("bad base64".into())).is_err());
        assert_eq!(mdm_layer_checked(&Ok(None)), Ok(None));
        let ok: toml::Value = toml::from_str("[sandbox]\nprofile = \"strict\"\n").unwrap();
        assert!(mdm_layer_checked(&Ok(Some(ok))).unwrap().is_some());
        let bad: toml::Value = toml::from_str("[[version_overrides]]\nminimum_version = \"x\"\n").unwrap();
        // the strict admin normalizer refuses what the lenient one would strip
        assert!(normalize_admin_requirements_value(bad).is_err());
    }

    // ---- P183 round 10 (Grok r6): the trust rule for an admin path, the broken-source notion, MDM --------------------------

    const GOOD: &str = "[sandbox]\nprofile = \"strict\"\n";

    /// Runs `f` on a thread and fails (instead of hanging the suite) when it does not return in 10 s: a fifo must not block.
    fn within_10s<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        rx.recv_timeout(std::time::Duration::from_secs(10)).expect("the read blocked")
    }

    fn mkfifo(path: &Path) {
        use std::os::unix::ffi::OsStrExt as _;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o644) }, 0);
    }

    /// The audit's SEQUENCE: validate a good file, then replace the directory entry with each kind of untrusted object. The
    /// validated copy is enforced every time (never `Ok(None)`, never the replacement's text), the copy is not forgotten, and a
    /// process with no copy gets an `Err` (lock-down). Without the fix a char device / fifo read blank and cleared the copy.
    #[test]
    fn non_regular_replacement_keeps_validated_copy_p183r10() {
        type Make = fn(&Path);
        let kinds: [(&str, Make); 5] = [
            ("dev-null", |p| std::os::unix::fs::symlink("/dev/null", p).unwrap()),
            ("fifo", mkfifo),
            ("directory", |p| std::fs::create_dir(p).unwrap()),
            ("dangling", |p| std::os::unix::fs::symlink("/nonexistent-p183r10/x", p).unwrap()),
            ("fifo-via-symlink", |p| {
                let target = p.with_extension("fifo");
                mkfifo(&target);
                std::os::unix::fs::symlink(target, p).unwrap();
            }),
        ];
        for (name, make) in kinds {
            let sys = tempfile::tempdir().unwrap();
            let path = sys.path().join("requirements.toml");
            std::fs::write(&path, GOOD).unwrap();
            assert!(admin_requirements_source_checked(&path).unwrap().is_some(), "{name}");
            std::fs::remove_file(&path).unwrap();
            make(&path);
            let p = path.clone();
            let got = within_10s(move || admin_requirements_source_checked(&p));
            let kept = got.unwrap_or_else(|e| panic!("{name}: the copy must be served, got Err({e})")).unwrap_or_else(|| panic!("{name}: Ok(None) forgets the policy"));
            assert!(kept.contains("strict"), "{name}");
            assert!(admin_requirements_copy_exists(&path), "{name}: the copy must not be forgotten");
            // a second call (the cache case) sees the same, and the layer carries the copy's pin
            let p = path.clone();
            assert!(within_10s(move || admin_requirements_source_checked(&p)).unwrap().is_some(), "{name}");

            // no validated copy: the same object is an Err (lock-down), never absent or blank
            let fresh = tempfile::tempdir().unwrap();
            let fp = fresh.path().join("requirements.toml");
            make(&fp);
            let err = within_10s(move || admin_requirements_source_checked(&fp));
            assert!(err.is_err(), "{name}: with no copy this is broken, got {err:?}");
        }
    }

    /// A symlink to a regular file the admin does not own is judged on the target (the opened descriptor): injected uid.
    #[test]
    fn symlink_to_untrusted_file_is_broken_p183r10() {
        let sys = tempfile::tempdir().unwrap();
        let target = sys.path().join("elsewhere.toml");
        std::fs::write(&target, GOOD).unwrap();
        let link = sys.path().join("requirements.toml");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let not_us = crate::policy_sources::process_euid() + 1;
        let err = match read_requirements_source_as(&link, true, not_us) {
            Err(f) => f.detail,
            Ok(v) => panic!("expected a refusal, got {v:?}"),
        };
        assert!(err.contains("expected a file owned by root and not writable by group or others"), "{err}");
        assert!(err.contains("owner uid"), "{err}");
        // owned by the admin uid it is fine, and the link is followed
        assert!(read_requirements_source_as(&link, true, crate::policy_sources::process_euid()).unwrap().is_some());
    }

    /// A group/other-writable directory holding the entry makes the file untrusted, kept copy or lock-down.
    #[test]
    fn writable_parent_directory_is_broken_p183r10() {
        use std::os::unix::fs::PermissionsExt as _;
        let sys = tempfile::tempdir().unwrap();
        let path = sys.path().join("requirements.toml");
        std::fs::write(&path, GOOD).unwrap();
        assert!(admin_requirements_source_checked(&path).unwrap().is_some());
        std::fs::set_permissions(sys.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        let kept = admin_requirements_source_checked(&path).expect("copy kept").expect("copy");
        assert!(kept.contains("strict"));
        // an attacker's replacement text in the writable directory is not served
        std::fs::write(&path, "[sandbox]\nprofile = \"off\"\n").unwrap();
        assert!(admin_requirements_source_checked(&path).unwrap().unwrap().contains("strict"));
        let fresh = tempfile::tempdir().unwrap();
        let fp = fresh.path().join("requirements.toml");
        std::fs::write(&fp, GOOD).unwrap();
        std::fs::set_permissions(fresh.path(), std::fs::Permissions::from_mode(0o775)).unwrap();
        let err = admin_requirements_source_checked(&fp).unwrap_err();
        assert!(err.contains("its directory") && err.contains("expected a directory owned by root"), "{err}");
        std::fs::set_permissions(fresh.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(sys.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    /// The admin directory reached through a (trusted) symlink is a legitimate setup.
    #[test]
    fn admin_directory_behind_a_symlink_is_trusted_p183r10() {
        let real = tempfile::tempdir().unwrap();
        std::fs::write(real.path().join("requirements.toml"), GOOD).unwrap();
        let hold = tempfile::tempdir().unwrap();
        let link = hold.path().join("fuigo");
        std::os::unix::fs::symlink(real.path(), &link).unwrap();
        assert!(admin_requirements_source_checked(&link.join("requirements.toml")).unwrap().is_some());
    }

    /// A blank file clears the copy only when it is a trusted regular file; a fifo/device never does (the audit's clear sequence).
    #[test]
    fn only_a_trusted_blank_regular_file_clears_the_copy_p183r10() {
        let sys = tempfile::tempdir().unwrap();
        let path = sys.path().join("requirements.toml");
        std::fs::write(&path, GOOD).unwrap();
        assert!(admin_requirements_source_checked(&path).unwrap().is_some());
        std::fs::write(&path, "# retired\n").unwrap();
        assert_eq!(admin_requirements_source_checked(&path), Ok(None));
        assert!(!admin_requirements_copy_exists(&path));
    }

    /// `managed_config.toml` takes the same reader: a fifo there is an error, not an empty table.
    #[test]
    fn fifo_managed_config_is_an_error_not_blank_p183r10() {
        let sys = tempfile::tempdir().unwrap();
        let fp = sys.path().join("managed_config.toml");
        mkfifo(&fp);
        let r = within_10s(move || crate::loader::load_admin_config_file(&fp).is_err());
        assert!(r);
    }

    /// One notion of "broken admin source": files, Claude file, MDM (undecodable or bad overrides). A good MDM or none: empty.
    #[test]
    fn broken_admin_sources_cover_files_claude_and_mdm_p183r10() {
        let sys = tempfile::tempdir().unwrap();
        let ok = Ok(None);
        assert!(broken_admin_sources_at(Some(sys.path()), None, &ok).is_empty());
        mkfifo(&sys.path().join("requirements.toml"));
        let d = sys.path().to_path_buf();
        let got = within_10s(move || broken_admin_sources_at(Some(&d), None, &Ok(None)));
        assert_eq!(got.len(), 1);
        assert!(got[0].detail.contains("not a regular file"), "{}", got[0].detail);

        let none = tempfile::tempdir().unwrap();
        let claude = none.path().join("managed-settings.json");
        std::fs::write(&claude, "{ not json").unwrap();
        let b = broken_admin_sources_at(Some(none.path()), Some(&claude), &Ok(None));
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].path, claude);

        let undecodable = Err("bad base64".to_owned());
        let b = broken_admin_sources_at(None, None, &undecodable);
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].path, PathBuf::from(crate::macos_managed::MDM_REQUIREMENTS_SOURCE));
        let bad_over: toml::Value = toml::from_str("[sandbox]\nprofile = \"strict\"\n[[version_overrides]]\nminimum_version = \"x\"\n").unwrap();
        assert_eq!(broken_admin_sources_at(None, None, &Ok(Some(bad_over.clone()))).len(), 1);
        assert!(mdm_layer_checked(&Ok(Some(bad_over))).is_err());
    }

    /// The MDM value `ConfigLayers` reads is the lock-down document for a broken payload, never `None`.
    #[test]
    fn broken_mdm_payload_is_the_lockdown_layer_p183r10() {
        let lock = mdm_value_from(&Err("bad base64".to_owned())).expect("lock-down, not no layer");
        assert_eq!(lock, admin_lockdown_requirements());
        let bad_over: toml::Value = toml::from_str("[[version_overrides]]\nminimum_version = \"x\"\n").unwrap();
        assert_eq!(mdm_value_from(&Ok(Some(bad_over))), Some(admin_lockdown_requirements()));
        assert_eq!(mdm_value_from(&Ok(None)), None);
    }

    /// A user must tell "the admin file is broken" from "my own file has a typo".
    #[test]
    fn lockdown_message_names_source_owner_and_reason_p183r10() {
        let b = RequirementsBroken {
            layers: Vec::new(),
            broken: vec![BrokenAdminFile {
                path: PathBuf::from("/etc/fuigo/requirements.toml"),
                detail: "/etc/fuigo/requirements.toml is not trusted: owner uid 1000, mode 0666; expected a file owned by root and not writable by group or others".into(),
            }],
        };
        let msg = b.to_string();
        assert!(msg.contains("/etc/fuigo/requirements.toml"), "{msg}");
        assert!(msg.contains("administrator"), "{msg}");
        assert!(msg.contains("owner uid 1000, mode 0666"), "{msg}");
        assert_eq!(source_kind(Path::new("/home/u/.fuigo/requirements.toml")), "your own file");
        let e = RequirementsError::Unloadable { path: PathBuf::from("/etc/fuigo/managed_config.toml"), detail: "x".into() };
        assert!(e.to_string().contains("administrator"));
    }

    // ---- P183 round 11 (Grok r7) ----

    /// H1 (TOML sources): v1 is remembered, a stricter valid v2 is then read (it is in force), the file breaks: the copy served
    /// is v2, never v1. Both admin TOML files take the same reader.
    #[test]
    fn a_newer_valid_read_replaces_the_copy_p183r11() {
        for name in ["requirements.toml", crate::loader::MANAGED_CONFIG_FILENAME] {
            let sys = tempfile::tempdir().unwrap();
            let path = sys.path().join(name);
            std::fs::write(&path, "[sandbox]\nprofile = \"loose\"\n").unwrap();
            assert!(admin_requirements_source_checked(&path).unwrap().unwrap().contains("loose"));
            let id1 = admin_requirements_copy_id(&path);
            std::fs::write(&path, "[sandbox]\nprofile = \"strict\"\n").unwrap();
            assert!(admin_requirements_source_checked(&path).unwrap().unwrap().contains("strict"));
            assert_ne!(admin_requirements_copy_id(&path), id1, "{name}: the copy identity must change");
            std::fs::write(&path, "[sandbox\nprofile =").unwrap();
            let kept = admin_requirements_source_checked(&path).unwrap().unwrap();
            assert!(kept.contains("strict") && !kept.contains("loose"), "{name}: {kept}");
        }
    }

    /// P183 round 12 (Grok r8) ANTI-DRIFT: documents (per admin source kind) are fed to BOTH the requirements path and the
    /// policy-sources path; the verdicts must be equal, and equal to the stated rule. Unknown keys are ignored (accepted) on
    /// both; a wrong-typed known key, bad JSON/TOML, a non-object Claude root are broken on both. No copy exists (fresh dirs).
    #[test]
    fn requirements_and_policy_sources_readers_give_the_same_verdict_p183r12() {
        use crate::policy_sources::{PolicyLayerTier as T, policy_sources_at};
        let toml_docs: [(&str, bool); 9] = [
            ("allow_managed_hooks_only = true\n", true),
            // a wrong-typed policy bool itself is accepted by the strict check on both paths (the engine then fails that key
            // closed to the engaging value); it is not a typed pin
            ("allow_managed_hooks_only = \"no\"\n", true),
            ("allow_managed_hooks_only = true\n[ui]\nyolo = \"no\"\n", false),
            ("allow_managed_hooks_only = true\nfuture_key = 1\n[future_table]\nx = \"y\"\n", true),
            ("[sandbox\nprofile =", false),
            ("# comments only\n", true),
            ("", true),
            ("allow_managed_hooks_only = true\n[[version_overrides]]\nminimum_version = \"not a version\"\n", false),
            (ENV_BOUND, false),
        ];
        for (name, tier) in [
            ("requirements.toml", T::SystemRequirements),
            ("managed_config.toml", T::SystemManaged),
        ] {
            for (doc, ok) in toml_docs {
                let d = tempfile::tempdir().unwrap();
                let path = d.path().join(name);
                std::fs::write(&path, doc).unwrap();
                let req = admin_requirements_source_checked(&path).is_ok();
                let pol = policy_sources_at(Some(d.path()), None, None, None)
                    .into_iter()
                    .find(|s| s.tier == tier)
                    .map(|s| s.policy.is_ok());
                assert_eq!(Some(req), pol, "{name}: {doc:?}");
                assert_eq!(req, ok, "{name}: {doc:?}");
            }
        }
        let claude_docs: [(&str, bool); 9] = [
            (r#"{"permissions":{"deny":["Bash"]}}"#, true),
            (r#"{"permissions":{"deny":"Bash"}}"#, false),
            (r#"{"permissions":{"deny":[]},"allowedMcpServers":{}}"#, false),
            (r#"{"permissions":{"deny":["Bash"]},"futureKey":{"a":1}}"#, true),
            ("{not json", false),
            ("[]", false),
            ("42", false),
            ("{}", true),
            ("   \n", true),
        ];
        for (doc, ok) in claude_docs {
            let d = tempfile::tempdir().unwrap();
            let path = d.path().join("managed-settings.json");
            std::fs::write(&path, doc).unwrap();
            let req = !matches!(managed_settings_json(&path), ManagedSettingsJson::Broken(_));
            let pol = policy_sources_at(None, None, Some(&path), None)
                .into_iter()
                .find(|s| s.tier == T::Vendor)
                .map(|s| s.policy.is_ok());
            assert_eq!(Some(req), pol, "claude: {doc:?}");
            assert_eq!(req, ok, "claude: {doc:?}");
        }
        let mdm_docs: [(&str, bool); 4] = [
            ("allow_managed_hooks_only = true\n", true),
            ("allow_managed_hooks_only = true\n[ui]\nyolo = \"no\"\n", false),
            ("future_key = 1\n", true),
            (ENV_BOUND, false),
        ];
        for (doc, ok) in mdm_docs {
            let v: toml::Value = toml::from_str(doc).unwrap();
            let req = mdm_layer_checked(&Ok(Some(v.clone()))).is_ok();
            let pol = policy_sources_at(None, None, None, Some(Ok(v)))
                .into_iter()
                .find(|s| s.tier == T::Mdm)
                .map(|s| s.policy.is_ok());
            assert_eq!(Some(req), pol, "mdm: {doc:?}");
            assert_eq!(req, ok, "mdm: {doc:?}");
        }
    }

    /// P183 round 13 (Grok r9) ANTI-DRIFT, blank and absent: for each admin source (requirements.toml, managed_config.toml, the
    /// Claude file) both readers, after a valid file was remembered, must (A) keep the copy on a blank that keeps changing,
    /// (B) keep enforcing the copy when the file is gone, (C) clear it only on a STABLE blank. Verdicts compared per step.
    #[test]
    fn blank_and_absent_rules_agree_on_every_source_and_reader_p183r13() {
        use crate::policy_sources::{PolicyLayerTier as T, policy_sources_at};
        let cases: [(&str, T, &str); 3] = [
            ("requirements.toml", T::SystemRequirements, "allow_managed_hooks_only = true\n[ui]\nyolo = false\n"),
            ("managed_config.toml", T::SystemManaged, "allow_managed_hooks_only = true\n[ui]\nyolo = false\n"),
            ("managed-settings.json", T::Vendor, r#"{"permissions":{"deny":["Bash"]}}"#),
        ];
        for (name, tier, doc) in cases {
            let d = tempfile::tempdir().unwrap();
            let path = d.path().join(name);
            let claude = tier == T::Vendor;
            // (requirements verdict: does it still enforce a copy, policy-sources verdict: Ok(keys) / Err)
            let req = || {
                if claude {
                    match managed_settings_json(&path) {
                        ManagedSettingsJson::Loaded(v) => Some(v),
                        ManagedSettingsJson::Absent => None,
                        ManagedSettingsJson::Broken(e) => panic!("{name}: broken {e}"),
                    }
                } else {
                    admin_requirements_source_checked(&path)
                        .unwrap_or_else(|e| panic!("{name}: {e}"))
                        .map(|t| toml::from_str::<toml::Value>(&t).map(|v| serde_json::to_value(v).unwrap()).unwrap())
                }
            };
            let pol = || {
                let src = if claude {
                    policy_sources_at(None, None, Some(&path), None)
                } else {
                    policy_sources_at(Some(d.path()), None, None, None)
                };
                src.into_iter().find(|s| s.tier == tier).map(|s| s.policy)
            };
            std::fs::write(&path, doc).unwrap();
            assert!(req().is_some() && pol().unwrap().is_ok(), "{name}: valid");
            let id0 = admin_requirements_copy_id(&path);
            assert!(id0.is_some(), "{name}");
            let marker = |v: &serde_json::Value| {
                if claude { v["permissions"]["deny"][0] == "Bash" } else { v["allow_managed_hooks_only"] == true }
            };
            // A: blank that keeps changing, on each reader
            for reader in 0..2 {
                std::fs::write(&path, "").unwrap();
                let p2 = path.clone();
                let mut n = 0usize;
                crate::loader::blank_hook::set(Some(Box::new(move || {
                    n += 1;
                    std::fs::write(&p2, " ".repeat(n)).unwrap();
                })));
                if reader == 0 {
                    assert!(marker(&req().expect("copy enforced")), "{name}: requirements, unstable blank");
                } else {
                    assert!(pol().unwrap().is_err(), "{name}: policy-sources, unstable blank is Err (copy + lock-down)");
                }
                crate::loader::blank_hook::set(None);
                assert_eq!(admin_requirements_copy_id(&path), id0, "{name}: unstable blank keeps the copy ({reader})");
            }
            // B: the file is gone
            std::fs::remove_file(&path).unwrap();
            assert!(marker(&req().expect("copy enforced")), "{name}: requirements, absent after a copy");
            let keys = pol().expect("layer still built from the copy").unwrap_or_else(|e| panic!("{name}: {e}"));
            assert!(marker(&keys), "{name}: policy-sources, absent after a copy: {keys}");
            assert_eq!(admin_requirements_copy_id(&path), id0, "{name}: absence keeps the copy");
            // C: a stable blank file clears it on both readers
            std::fs::write(&path, "\n").unwrap();
            assert!(req().is_none(), "{name}: requirements, stable blank");
            assert!(!admin_requirements_copy_exists(&path), "{name}: cleared");
            assert_eq!(pol().unwrap().unwrap(), serde_json::json!({}), "{name}: policy-sources, stable blank");
            // and a process that never saw the file: absent is no policy on both
            let other = d.path().join("nested");
            std::fs::create_dir_all(&other).unwrap();
            let gone = other.join(name);
            if claude {
                assert!(matches!(managed_settings_json(&gone), ManagedSettingsJson::Absent));
                assert!(policy_sources_at(None, None, Some(&gone), None).into_iter().all(|s| s.tier != T::Vendor));
            } else {
                assert_eq!(admin_requirements_source_checked(&gone), Ok(None));
                assert!(policy_sources_at(Some(&other), None, None, None).into_iter().all(|s| s.tier != tier));
            }
        }
    }

    /// P186 A1 (Grok p183 r10 LOW): Unicode-only whitespace (`\x0b`) is a blank like any other, so it gets the stability
    /// re-check on the requirements Claude reader; a writer that keeps changing it must not clear the remembered copy.
    #[test]
    fn unicode_whitespace_blank_gets_the_recheck_p186() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("managed-settings.json");
        std::fs::write(&path, r#"{"permissions":{"deny":["Bash"]}}"#).unwrap();
        assert!(matches!(managed_settings_json(&path), ManagedSettingsJson::Loaded(_)));
        std::fs::write(&path, "\x0b").unwrap();
        let p2 = path.clone();
        let mut n = 1usize;
        crate::loader::blank_hook::set(Some(Box::new(move || {
            n += 1;
            std::fs::write(&p2, "\x0b".repeat(n)).unwrap();
        })));
        let got = managed_settings_json(&path);
        let fired = crate::loader::blank_hook::fired();
        crate::loader::blank_hook::set(None);
        assert!(fired > 0, "the \\x0b-only file must be re-checked");
        match got {
            ManagedSettingsJson::Loaded(v) => assert_eq!(v["permissions"]["deny"][0], "Bash"),
            _ => panic!("a changing unicode-whitespace file must keep the Bash deny"),
        }
        assert!(admin_requirements_copy_exists(&path), "the copy stays");
    }

    /// P186 A2 (Grok p183 r10 LOW): startup validation run again after the file is gone leaves the validated copy alone.
    #[test]
    fn startup_validation_leaves_the_copy_on_absence_p186() {
        let sys = tempfile::tempdir().unwrap();
        let path = sys.path().join("requirements.toml");
        std::fs::write(&path, "allow_managed_hooks_only = true\n[ui]\nyolo = false\n").unwrap();
        validate_requirements_from(Some(sys.path()), None, Ok(None), None).unwrap();
        assert!(admin_requirements_copy_exists(&path));
        std::fs::remove_file(&path).unwrap();
        validate_requirements_from(Some(sys.path()), None, Ok(None), None).unwrap();
        assert!(admin_requirements_copy_exists(&path), "absence at a second validation keeps the copy");
        let pins = load_admin_requirements_layer(&path).expect("pins still enforced");
        assert_eq!(pins["ui"]["yolo"].as_bool(), Some(false));
    }

    /// P186 A3 (Grok p183 r10 LOW): a dangling symlink that appears during the blank wait is a broken source (copy plus
    /// lock-down), not absence, on both policy-sources readers.
    #[cfg(unix)]
    #[test]
    fn dangling_symlink_born_during_the_blank_wait_is_broken_p186() {
        use crate::policy_sources::{PolicyLayerTier as T, policy_sources_at};
        for (name, tier, doc) in [
            ("requirements.toml", T::SystemRequirements, "allow_managed_hooks_only = true\n[ui]\nyolo = false\n"),
            ("managed-settings.json", T::Vendor, r#"{"permissions":{"deny":["Bash"]}}"#),
        ] {
            let d = tempfile::tempdir().unwrap();
            let path = d.path().join(name);
            let pol = || {
                let src = if tier == T::Vendor {
                    policy_sources_at(None, None, Some(&path), None)
                } else {
                    policy_sources_at(Some(d.path()), None, None, None)
                };
                src.into_iter().find(|s| s.tier == tier).map(|s| s.policy)
            };
            std::fs::write(&path, doc).unwrap();
            assert!(pol().unwrap().is_ok(), "{name}: valid");
            std::fs::write(&path, "").unwrap();
            let p2 = path.clone();
            let missing = d.path().join("no-such-target");
            crate::loader::blank_hook::set(Some(Box::new(move || {
                let _ = std::fs::remove_file(&p2);
                std::os::unix::fs::symlink(&missing, &p2).unwrap();
            })));
            let got = pol();
            crate::loader::blank_hook::set(None);
            assert!(got.expect("layer built").is_err(), "{name}: a dangling symlink is a broken source");
        }
    }

    /// P183 round 13 (Grok r9 M2): `requirements.toml` is deleted after it was remembered: the requirements pins and the
    /// policy-engine keys (hooks pin) both still apply.
    #[test]
    fn deleted_requirements_toml_keeps_pins_and_policy_keys_p183r13() {
        let sys = tempfile::tempdir().unwrap();
        let path = sys.path().join("requirements.toml");
        std::fs::write(&path, "allow_managed_hooks_only = true\n[ui]\nyolo = false\n").unwrap();
        assert!(load_admin_requirements_layer(&path).is_some());
        std::fs::remove_file(&path).unwrap();
        let pins = load_admin_requirements_layer(&path).expect("pins kept");
        assert_eq!(pins["ui"]["yolo"].as_bool(), Some(false));
        let layer = crate::policy_sources::policy_sources_at(Some(sys.path()), None, None, None)
            .into_iter()
            .find(|s| s.tier == crate::policy_sources::PolicyLayerTier::SystemRequirements)
            .expect("layer built from the copy");
        assert_eq!(layer.policy.unwrap()["allow_managed_hooks_only"], true);
    }

    /// H1 (Claude file): the policy-sources reader's SUCCESSFUL read remembers the text, so a later break serves v2.
    #[test]
    fn a_newer_valid_claude_read_replaces_the_copy_p183r11() {
        let d = tempfile::tempdir().unwrap();
        let path = d.path().join("managed-settings.json");
        let read = |p: &Path| {
            crate::policy_sources::policy_sources_at(None, None, Some(p), None)
        };
        std::fs::write(&path, r#"{"permissions":{"deny":["Bash(v1)"]}}"#).unwrap();
        assert!(matches!(managed_settings_json(&path), ManagedSettingsJson::Loaded(_)));
        let id1 = admin_requirements_copy_id(&path);
        std::fs::write(&path, r#"{"permissions":{"deny":["Bash(v2)"]}}"#).unwrap();
        let src = read(&path);
        assert!(src.iter().any(|s| s.policy.is_ok()));
        assert_ne!(admin_requirements_copy_id(&path), id1);
        std::fs::write(&path, "{not json").unwrap();
        let ManagedSettingsJson::Loaded(kept) = managed_settings_json(&path) else {
            panic!("the copy must be served");
        };
        let text = kept.to_string();
        assert!(text.contains("v2") && !text.contains("v1"), "{text}");
    }

    /// H2: the audit's file. `${VER:-1.0.0}` as an override bound is NOT valid semver without expansion, so the file is broken
    /// from the first read (lock-down with no copy), at startup and at runtime alike, and nothing is remembered.
    const ENV_BOUND: &str = "[sandbox]\nprofile = \"loose\"\n\n[[version_overrides]]\nminimum_version = \"${VER:-1.0.0}\"\n[version_overrides.sandbox]\nprofile = \"strict\"\n";

    #[test]
    fn env_bound_override_file_is_broken_from_the_first_read_p183r11() {
        let sys = tempfile::tempdir().unwrap();
        std::fs::write(sys.path().join("requirements.toml"), ENV_BOUND).unwrap();
        let startup = validate_requirements_for_dirs(Some(sys.path()), None);
        assert!(startup.is_err(), "startup must judge it as the runtime does: {startup:?}");
        let path = sys.path().join("requirements.toml");
        assert!(admin_requirements_source_checked(&path).is_err());
        assert!(!admin_requirements_copy_exists(&path), "a refused text is never remembered");
    }

    /// H2: the strict normaliser is what the layer uses; a text that fails it is the lock-down document, not the base.
    #[test]
    fn admin_layer_from_a_failing_text_is_the_lockdown_p183r11() {
        let layer = admin_layer_from_source(Path::new("/etc/fuigo/requirements.toml"), ENV_BOUND).unwrap();
        assert_eq!(layer, admin_lockdown_requirements());
    }

    /// A `$`-free file is unaffected (valid, remembered, no warning).
    #[test]
    fn dollar_free_admin_file_is_unaffected_p183r11() {
        let sys = tempfile::tempdir().unwrap();
        std::fs::write(sys.path().join("requirements.toml"), GOOD).unwrap();
        let w = validate_requirements_for_dirs(Some(sys.path()), None).unwrap();
        assert!(w.is_empty(), "{w:?}");
        assert!(admin_requirements_copy_exists(&sys.path().join("requirements.toml")));
    }

    /// No expansion at any admin entry point: startup, the checked reader, the layer, the config file and the policy-sources
    /// reader keep `${HOME}` literal, and startup warns once with the exact text.
    #[test]
    fn admin_entry_points_do_not_expand_and_warn_p183r11() {
        let sys = tempfile::tempdir().unwrap();
        let body = "[models]\nallowed_models = [\"${HOME}/m\"]\n";
        for name in ["requirements.toml", crate::loader::MANAGED_CONFIG_FILENAME] {
            let path = sys.path().join(name);
            std::fs::write(&path, body).unwrap();
            let src = admin_requirements_source_checked(&path).unwrap().unwrap();
            assert!(src.contains("${HOME}"), "{name}");
            let layer = admin_layer_from_source(&path, &src).unwrap();
            assert_eq!(layer["models"]["allowed_models"][0].as_str(), Some("${HOME}/m"), "{name}");
        }
        let cfg = crate::loader::load_admin_config_file(&sys.path().join(crate::loader::MANAGED_CONFIG_FILENAME)).unwrap();
        assert_eq!(cfg["models"]["allowed_models"][0].as_str(), Some("${HOME}/m"));
        let w = validate_requirements_for_dirs(Some(sys.path()), None).unwrap();
        let req = sys.path().join("requirements.toml");
        let want = format!(
            "administrator policy file {}: key models.allowed_models.0: environment variables are not expanded in administrator policy files; the value is used literally",
            req.display()
        );
        assert!(w.iter().any(|x| x.contains(&want)), "{w:?}");
        assert_eq!(env_literal_warning(&req, "models.allowed_models.0"), want);
    }

    #[test]
    fn warning_text_is_scrubbed_p183r11() {
        let w = env_literal_warning(Path::new("/etc/fuigo/a\u{1b}[31m\nb.toml"), "k\u{7}");
        assert!(!w.chars().any(|c| c.is_control()), "{w:?}");
        let e = RequirementsError::Unloadable { path: PathBuf::from("/etc/fuigo/x\ny"), detail: "bad\u{1b}[2J".into() };
        assert!(!e.to_string().chars().any(|c| c.is_control()), "{e}");
    }

    /// P186f round 2: the uid choice is a pure function, so a non-root euid is tested even when the suite runs as root.
    #[test]
    fn admin_uid_is_root_unless_the_admin_root_override_is_set_p186f() {
        let user = 1000;
        assert_ne!(user, crate::policy_sources::ROOT_UID);
        assert_eq!(admin_uid_for(user, false), crate::policy_sources::ROOT_UID);
        assert_eq!(admin_uid_for(user, true), user);
        assert_eq!(admin_uid_for(0, false), crate::policy_sources::ROOT_UID);
    }
}

#[cfg(test)]
#[path = "validation_typed_pin_tests.rs"]
mod typed_pin_tests;

/// Test seam for the notice recorder (P186c).
#[cfg(test)]
pub(crate) fn lockdown_notices_for_test(path: &Path) -> Vec<String> {
    test_notices().lock().unwrap().iter().filter(|(p, _)| p == path).map(|(_, m)| m.clone()).collect()
}

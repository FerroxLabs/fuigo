//! Managed MCP, plugin, marketplace and hooks policy sources (P169; upstream 72a61251 and the 1.0.36 hooks pin).
//!
//! Every policy layer is read here: the `managed_config.toml` layers (system and user; the user one is what Fuigo's own
//! managed-config endpoint writes, P47), the `requirements.toml` layers (user, system, macOS MDM) and the Claude
//! `managed-settings.json`. Only the policy keys ([`MANAGED_POLICY_CONFIG_KEYS`]) of a TOML layer are kept, converted to
//! JSON so one parser serves both spellings. Nothing is ever fetched from a remote service here.
//!
//! Fail closed on admin layers: an MDM payload, `/etc/fuigo` file or Claude `managed-settings.json` that exists but cannot
//! be read or parsed, or that a non-root user could have written (not root-owned, or group/other-writable), is a source
//! whose `policy` is `Err`. The policy engine treats it as if every policy key in it were malformed (MCP and marketplace
//! lockdown, every pin engaged), so a broken admin policy file refuses rather than allows.
//!
//! Warn and skip on user-home layers (`$FUIGO_HOME/{requirements,managed_config}.toml`, P169 Grok 4.7 C, shared with
//! P183): the user who can write such a file can also delete it, so a broken one is skipped like an absent one instead of
//! locking the user out. A user file that parses still contributes its rules (strictest wins), and a malformed key in it
//! still fails closed.
//!
//! The boolean pins live here (not in `fuigo-workspace`) so `fuigo-hooks`, which `fuigo-workspace` depends on, reads the
//! `allow_managed_hooks_only` pin from the same rule as `inspect` and the policy engine.

use std::path::{Path, PathBuf};

use tracing::warn;

use crate::loader::{MANAGED_CONFIG_FILENAME, REQUIREMENTS_FILENAME};
use crate::paths::{claude_managed_settings_probe_path, system_config_dir, user_fuigo_home};

/// Trust tier of a policy layer; lower sorts first (mdm > system > user, the Claude file last).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum PolicyLayerTier {
    Mdm,
    SystemRequirements,
    SystemManaged,
    UserRequirements,
    UserManaged,
    /// The Claude `managed-settings.json` (root-owned); applies after every Fuigo layer.
    Vendor,
}

impl PolicyLayerTier {
    /// Who can write the layer: MDM, the system TOML files and the root-owned Claude file are admin-controlled;
    /// `$FUIGO_HOME` layers are user-writable.
    pub fn ownership(self) -> PolicyLayerOwnership {
        match self {
            Self::UserRequirements | Self::UserManaged => PolicyLayerOwnership::User,
            Self::Mdm | Self::SystemRequirements | Self::SystemManaged | Self::Vendor => {
                PolicyLayerOwnership::Admin
            }
        }
    }
}

/// Who can write the layer a policy value came from. An `Admin` restriction accepts only admin-owned exception grants;
/// a `User` restriction accepts any. A user-writable grant that satisfied an admin lockdown would let the restricted
/// user lift it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyLayerOwnership {
    Admin,
    User,
}

impl PolicyLayerOwnership {
    /// Whether a restriction owned by `self` accepts an exception grant owned by `grant`.
    pub fn accepts_grant_from(self, grant: PolicyLayerOwnership) -> bool {
        self == PolicyLayerOwnership::User || grant == PolicyLayerOwnership::Admin
    }
}

/// One policy layer as read from disk.
#[derive(Debug, Clone)]
pub struct PolicySource {
    pub tier: PolicyLayerTier,
    /// Who can write the layer: [`PolicyLayerTier::ownership`]. An admin-tier file a non-root user could have written
    /// never becomes a source of its own: it is an `Err` (fail closed) source (P169, Grok 4.7 #5).
    pub ownership: PolicyLayerOwnership,
    /// The file (or the MDM source label) the layer came from.
    pub path: PathBuf,
    /// The layer's policy keys as JSON, or why the layer could not be read (fail closed).
    pub policy: Result<serde_json::Value, String>,
}

/// Policy keys read from each TOML layer (Claude camelCase and Fuigo snake_case).
pub const MANAGED_POLICY_CONFIG_KEYS: &[&str] = &[
    "allowedMcpServers",
    "allowed_mcp_servers",
    "deniedMcpServers",
    "denied_mcp_servers",
    "allowManagedMcpServersOnly",
    "allow_managed_mcp_servers_only",
    "allowManagedHooksOnly",
    "allow_managed_hooks_only",
    "enableAllProjectMcpServers",
    "enable_all_project_mcp_servers",
    "strictKnownMarketplaces",
    "strict_known_marketplaces",
];

/// The uid that must own an admin-path policy file.
pub(crate) const ROOT_UID: u32 = 0;

/// Every policy layer on this machine, in tier order.
pub fn policy_sources() -> Vec<PolicySource> {
    policy_sources_owned_by(
        system_config_dir().as_deref(),
        user_fuigo_home().as_deref(),
        // The probe path, not `claude_managed_settings_path` (which drops a file it cannot stat): an existing file
        // behind an unreadable directory must fail closed, not vanish (Astra r1 #1).
        claude_managed_settings_probe_path().as_deref(),
        crate::macos_managed::mdm_policy_layer(),
        ROOT_UID,
    )
}

/// [`policy_sources`] over explicit locations (tests). A test cannot create root-owned files, so admin-path files here
/// must be owned by this process's effective uid instead of root; every other admin-file rule is the production one.
pub fn policy_sources_at(
    system_dir: Option<&Path>,
    user_home: Option<&Path>,
    vendor_json: Option<&Path>,
    mdm: Option<Result<toml::Value, String>>,
) -> Vec<PolicySource> {
    policy_sources_owned_by(system_dir, user_home, vendor_json, mdm, process_euid())
}

#[cfg(unix)]
pub(crate) fn process_euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

#[cfg(not(unix))]
pub(crate) fn process_euid() -> u32 {
    ROOT_UID
}

/// [`policy_sources`] with admin-path files required to be owned by `admin_uid` (root in production).
pub fn policy_sources_owned_by(
    system_dir: Option<&Path>,
    user_home: Option<&Path>,
    vendor_json: Option<&Path>,
    mdm: Option<Result<toml::Value, String>>,
    admin_uid: u32,
) -> Vec<PolicySource> {
    let mut out = Vec::new();
    if let Some(value) = mdm {
        let source = crate::macos_managed::MDM_REQUIREMENTS_SOURCE;
        let policy = value
            .and_then(crate::validation::mdm_verdict)
            .and_then(|v| toml_policy_keys(&v))
            .map_err(|e| unreadable(Path::new(source), &e));
        out.push(PolicySource {
            tier: PolicyLayerTier::Mdm,
            ownership: PolicyLayerOwnership::Admin,
            path: PathBuf::from(source),
            policy,
        });
    }
    let files = [
        (
            system_dir,
            REQUIREMENTS_FILENAME,
            PolicyLayerTier::SystemRequirements,
        ),
        (
            system_dir,
            MANAGED_CONFIG_FILENAME,
            PolicyLayerTier::SystemManaged,
        ),
        (
            user_home,
            REQUIREMENTS_FILENAME,
            PolicyLayerTier::UserRequirements,
        ),
        (
            user_home,
            MANAGED_CONFIG_FILENAME,
            PolicyLayerTier::UserManaged,
        ),
    ];
    for (dir, name, tier) in files {
        let Some(path) = dir.map(|d| d.join(name)) else {
            continue;
        };
        if let Some(policy) = read_layer(&path, tier, admin_uid) {
            out.push(PolicySource {
                tier,
                ownership: tier.ownership(),
                path,
                policy,
            });
        }
    }
    if let Some(path) = vendor_json
        && let Some(policy) = read_layer(path, PolicyLayerTier::Vendor, admin_uid)
    {
        out.push(PolicySource {
            tier: PolicyLayerTier::Vendor,
            ownership: PolicyLayerTier::Vendor.ownership(),
            path: path.to_path_buf(),
            policy,
        });
    }
    out.sort_by_key(|s| s.tier);
    out
}

/// One layer read: the policy, or why it could not be read. `None` when the file does not exist, or when a user-home
/// file is broken (warned and skipped, P169 Grok 4.7 C). Contents and ownership come from ONE opened file (Astra r2: a
/// path checked twice can be swapped between the read and the ownership check).
fn read_layer(
    path: &Path,
    tier: PolicyLayerTier,
    admin_uid: u32,
) -> Option<Result<serde_json::Value, String>> {
    match read_layer_strict(path, tier, admin_uid)? {
        Ok(policy) => Some(Ok(policy)),
        Err(why) if tier.ownership() == PolicyLayerOwnership::User => {
            tracing::warn!(
                path = %path.display(),
                error = %why,
                "user policy file could not be read or parsed; skipping it (it neither grants nor locks anything)"
            );
            None
        }
        Err(why) => Some(Err(unreadable(path, &why))),
    }
}

/// [`read_layer`] before the user-tier skip: every failure is an `Err`.
fn read_layer_strict(
    path: &Path,
    tier: PolicyLayerTier,
    admin_uid: u32,
) -> Option<Result<serde_json::Value, String>> {
    use std::io::Read as _;
    let mut file = match open_admin_file(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            // A dangling symlink is a broken policy file, not an absent one.
            if std::fs::symlink_metadata(path).is_ok() {
                return Some(Err("dangling symlink".to_string()));
            }
            return absent_admin_layer(path, tier);
        }
        Err(e) => return Some(Err(e.to_string())),
    };
    let meta = match file.metadata() {
        Ok(m) => m,
        Err(e) => return Some(Err(e.to_string())),
    };
    if !meta.is_file() {
        return Some(Err(format!("{} is not a regular file ({})", path.display(), file_kind(&meta))));
    }
    // P169 (Grok 4.7 #5): an admin-path file a non-root user could have written is broken admin policy. Applied as a
    // (user-owned) layer, an emptied file would silently drop the org's rules; it fails closed instead.
    // P183 round 10: the same rule also judges the directories that hold the entry (`admin_object_trusted`).
    if tier.ownership() == PolicyLayerOwnership::Admin
        && let Err(why) = admin_object_trusted(path, &meta, admin_uid)
    {
        return Some(Err(why));
    }
    let mut content = String::new();
    if let Err(e) = file.read_to_string(&mut content) {
        return Some(Err(e.to_string()));
    }
    // P183 round 13 (Grok r9 M1): a blank admin file is believed only when it holds still (the requirements reader's rule); one
    // that keeps changing is a broken source, so the copy and lock-down apply rather than "no policy"
    if tier.ownership() == PolicyLayerOwnership::Admin && content.trim().is_empty() {
        match crate::validation::confirm_admin_blank(path, admin_uid) {
            Ok(Some(text)) => content = text,
            Ok(None) => return absent_admin_layer(path, tier),
            Err(why) => return Some(Err(why)),
        }
    }
    Some(match tier {
        // P183 round 12 (Grok r8): an ADMIN Claude file is `Ok` only when the strict check the requirements path uses accepts
        // the WHOLE document (it also remembers it); a partly invalid one is `Err`, so the copy and lock-down apply
        PolicyLayerTier::Vendor if tier.ownership() == PolicyLayerOwnership::Admin => {
            crate::validation::accept_managed_settings_text(path, &content)
                .map(|v| v.unwrap_or_else(|| serde_json::json!({})))
        }
        PolicyLayerTier::Vendor => match serde_json::from_str::<serde_json::Value>(&content) {
            Ok(v) if v.is_object() => Ok(v),
            Ok(_) => Err("not a JSON object".to_string()),
            // serde_json's message has no source text, only line and column.
            Err(e) => Err(e.to_string()),
        },
        _ => parse_toml_layer(path, tier, &content),
    })
}

/// P183 round 13 (Grok r9 M2): an ADMIN file that does not exist. A process that holds a validated copy of it keeps enforcing
/// that copy ALONE (no lock-down: the file is gone, not broken, exactly what the requirements reader does for the same
/// deletion); one that never saw the file has no policy to keep.
fn absent_admin_layer(path: &Path, tier: PolicyLayerTier) -> Option<Result<serde_json::Value, String>> {
    if tier.ownership() != PolicyLayerOwnership::Admin {
        return None;
    }
    let copy = crate::validation::kept_copy_of_absent_admin_file(path)?;
    Some(if tier == PolicyLayerTier::Vendor {
        crate::validation::accept_managed_settings_text(path, &copy)
            .map(|v| v.unwrap_or_else(|| serde_json::json!({})))
    } else {
        parse_toml_layer(path, tier, &copy)
    })
}

/// Policy keys of a TOML layer. No `$VAR` expansion: the user's environment must not shape an admin's policy (the MDM
/// rule). Version overrides apply as for the rest of the file; invalid ones fail closed.
fn parse_toml_layer(
    path: &Path,
    tier: PolicyLayerTier,
    content: &str,
) -> Result<serde_json::Value, String> {
    // P183 round 12 (Grok r8): the ADMIN files take the verdict of the requirements path's strict check (`Err` on a wrong-typed
    // security key or bad overrides; it remembers a valid text). Unknown keys are ignored there, so here too.
    if tier.ownership() == PolicyLayerOwnership::Admin {
        let applied = crate::validation::accept_admin_toml(path, content)?
            .unwrap_or_else(|| toml::Value::Table(toml::map::Map::new()));
        return toml_policy_keys(&applied);
    }
    let value: toml::Value = if content.trim().is_empty() {
        toml::Value::Table(toml::map::Map::new())
    } else {
        toml::from_str(content).map_err(|e| crate::loader::toml_error_detail(content, &e))?
    };
    let value = match tier {
        // (admin files returned above, P183 round 12) a user file keeps its base on invalid overrides
        PolicyLayerTier::UserRequirements => {
            crate::validation::normalize_requirements_value(value, &path.display().to_string())
                .ok_or_else(|| "invalid version_overrides".to_string())?
        }
        _ => {
            let mut value = value;
            crate::loader::apply_version_overrides_with_registered(&mut value)
                .map_err(|e| e.to_string())?;
            value
        }
    };
    toml_policy_keys(&value)
}

/// An admin-path file is trusted only when `admin_uid` (root) owns it and neither group nor other can write it.
#[cfg(unix)]
pub(crate) fn admin_owned(meta: &std::fs::Metadata, admin_uid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.uid() == admin_uid && meta.mode() & 0o022 == 0
}

#[cfg(not(unix))]
pub(crate) fn admin_owned(_meta: &std::fs::Metadata, _admin_uid: u32) -> bool {
    true
}

/// P183 round 10 (Grok r6 H): open an admin-path file for reading without ever blocking. A fifo opened `O_RDONLY` waits for a
/// writer; `O_NONBLOCK` returns at once, and the caller `fstat`s the descriptor before reading. A final symlink is FOLLOWED:
/// the object it leads to is judged by the same checks (regular file, owner, mode) on the same descriptor, so a root-owned
/// link to a root-owned file is a legitimate setup and a link to anything else is broken.
pub(crate) fn open_admin_file(path: &Path) -> std::io::Result<std::fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
    }
    #[cfg(not(unix))]
    {
        std::fs::File::open(path)
    }
}

/// P183 round 10 (Grok r6 H): the single trust rule for an opened admin object. It must be a regular file (never a device,
/// fifo, socket or directory) owned by `admin_uid` and not group/other-writable ([`admin_owned`]), and the directory that
/// holds the entry (as the path names it, through any root-owned symlink) and the directory that holds the file it finally
/// resolves to must each be owned by `admin_uid` and not group/other-writable: whoever can write that directory can swap the
/// entry. Only these directories are checked, not every ancestor up to `/`: `/` and `/etc` are the platform's, and checking
/// them would make a sticky shared parent (like a temp dir in the tests) an error. `Err` carries the reason a user sees.
pub(crate) fn admin_object_trusted(
    path: &Path,
    meta: &std::fs::Metadata,
    admin_uid: u32,
) -> Result<(), String> {
    if !meta.is_file() {
        return Err(format!(
            "{} is not a regular file (found {}); expected a regular file owned by root and not writable by group or others",
            path.display(),
            file_kind(meta)
        ));
    }
    if !admin_owned(meta, admin_uid) {
        return Err(format!(
            "{} is not trusted: {}; expected a file owned by root and not writable by group or others",
            path.display(),
            owner_and_mode(meta)
        ));
    }
    let mut dirs = Vec::new();
    if let Some(parent) = path.parent() {
        dirs.push(parent.to_path_buf());
    }
    if let Some(real_parent) = dunce::canonicalize(path)
        .ok()
        .and_then(|p| p.parent().map(Path::to_path_buf))
        && !dirs.contains(&real_parent)
    {
        dirs.push(real_parent);
    }
    for dir in dirs {
        let dir_meta = std::fs::metadata(&dir).map_err(|e| format!("directory {} cannot be checked: {e}", dir.display()))?;
        if !dir_meta.is_dir() || !admin_owned(&dir_meta, admin_uid) {
            return Err(format!(
                "its directory {} is not trusted: {}; expected a directory owned by root and not writable by group or others",
                dir.display(),
                owner_and_mode(&dir_meta)
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn owner_and_mode(meta: &std::fs::Metadata) -> String {
    use std::os::unix::fs::MetadataExt as _;
    format!("owner uid {}, mode {:04o}", meta.uid(), meta.mode() & 0o7777)
}

#[cfg(not(unix))]
fn owner_and_mode(_meta: &std::fs::Metadata) -> String {
    "owner unknown".to_owned()
}

#[cfg(unix)]
fn file_kind(meta: &std::fs::Metadata) -> &'static str {
    use std::os::unix::fs::FileTypeExt as _;
    let t = meta.file_type();
    if t.is_dir() {
        "a directory"
    } else if t.is_fifo() {
        "a fifo"
    } else if t.is_socket() {
        "a socket"
    } else if t.is_char_device() || t.is_block_device() {
        "a device"
    } else {
        "something else"
    }
}

#[cfg(not(unix))]
fn file_kind(_meta: &std::fs::Metadata) -> &'static str {
    "something else"
}

fn unreadable(path: &Path, why: &str) -> String {
    tracing::error!(
        path = %path.display(),
        error = why,
        "policy layer could not be read; failing closed (MCP and marketplace lockdown, every policy pin engaged)"
    );
    crate::validation::display_scrub(why)
}

/// Keep only the policy keys of a TOML layer, as JSON.
fn toml_policy_keys(value: &toml::Value) -> Result<serde_json::Value, String> {
    let table: toml::map::Map<String, toml::Value> = value
        .as_table()
        .map(|t| {
            t.iter()
                .filter(|(k, _)| MANAGED_POLICY_CONFIG_KEYS.contains(&k.as_str()))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
        .unwrap_or_default();
    serde_json::to_value(&table).map_err(|e| e.to_string())
}

// ── Key parsing (shared with the MCP / marketplace engine in fuigo-workspace) ──────────────────

/// One key's value in one source. Only `Absent` means "no restriction": a `Malformed` key (wrong type, or spelled both
/// ways with different values) fails closed.
#[derive(Debug)]
pub enum PolicyKey<T> {
    Absent,
    Present(T),
    Malformed,
}

impl<T> PolicyKey<T> {
    pub fn and_then<U>(self, f: impl FnOnce(T) -> PolicyKey<U>) -> PolicyKey<U> {
        match self {
            PolicyKey::Absent => PolicyKey::Absent,
            PolicyKey::Present(value) => f(value),
            PolicyKey::Malformed => PolicyKey::Malformed,
        }
    }

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> PolicyKey<U> {
        self.and_then(|value| PolicyKey::Present(f(value)))
    }

    pub fn is_absent(&self) -> bool {
        matches!(self, PolicyKey::Absent)
    }

    pub fn is_malformed(&self) -> bool {
        matches!(self, PolicyKey::Malformed)
    }
}

impl<T> PolicyKey<Vec<T>> {
    /// Present-but-empty (lockdown) or malformed (block on error).
    pub fn locks_down(&self) -> bool {
        matches!(self, PolicyKey::Present(e) if e.is_empty()) || self.is_malformed()
    }

    /// The parsed entries; `Absent` and `Malformed` carry none.
    pub fn entries(self) -> Vec<T> {
        match self {
            PolicyKey::Present(entries) => entries,
            PolicyKey::Absent | PolicyKey::Malformed => Vec::new(),
        }
    }
}

/// A key by its accepted spellings, as `(first present key, value)`. Differing values across spellings = `Malformed`.
pub fn policy_field<'a, 'k>(
    json: &'a serde_json::Value,
    keys: &[&'k str],
) -> PolicyKey<(&'k str, &'a serde_json::Value)> {
    let mut present = keys
        .iter()
        .filter_map(|key| json.get(key).map(|value| (*key, value)));
    let Some(first) = present.next() else {
        return PolicyKey::Absent;
    };
    if present.any(|(_, value)| value != first.1) {
        return PolicyKey::Malformed;
    }
    PolicyKey::Present(first)
}

/// An array policy key by its accepted spellings; a non-array value is `Malformed`.
pub fn policy_array<'a>(
    json: &'a serde_json::Value,
    keys: &[&str],
    path: &Path,
) -> PolicyKey<&'a Vec<serde_json::Value>> {
    let (key, value) = match policy_field(json, keys) {
        PolicyKey::Absent => return PolicyKey::Absent,
        PolicyKey::Malformed => {
            warn!(path = %path.display(), keys = ?keys, "policy key is spelled both ways with different values; failing closed");
            return PolicyKey::Malformed;
        }
        PolicyKey::Present(kv) => kv,
    };
    match value.as_array() {
        Some(arr) => PolicyKey::Present(arr),
        None => {
            warn!(path = %path.display(), key, "policy key must be an array of entries; failing closed");
            PolicyKey::Malformed
        }
    }
}

/// A boolean policy key by its accepted spellings. A non-bool value or a spelling conflict warns naming the source and
/// applies the fail-closed value.
pub fn policy_bool(
    json: &serde_json::Value,
    keys: &[&str],
    fail_closed: bool,
    path: &Path,
) -> Option<bool> {
    let (key, value) = match policy_field(json, keys) {
        PolicyKey::Absent => return None,
        PolicyKey::Malformed => {
            warn!(path = %path.display(), keys = ?keys, fail_closed, "policy key is spelled both ways with different values; applying the fail-closed value");
            return Some(fail_closed);
        }
        PolicyKey::Present(kv) => kv,
    };
    match value.as_bool() {
        Some(b) => Some(b),
        None => {
            warn!(path = %path.display(), key, fail_closed, "policy key must be a boolean; applying the fail-closed value");
            Some(fail_closed)
        }
    }
}

// ── Tighten-only boolean pins ─────────────────────────────────────────────────────────────────

/// Tighten-only pin: unpinned, or engaged by a named layer (`false`/`true` in a later layer never un-pins).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum PolicyPin {
    #[default]
    Unpinned,
    Disabled {
        source: PathBuf,
        /// Who can write the pinning layer; carried in the pin so pin and grant rule can never desync.
        ownership: PolicyLayerOwnership,
    },
}

impl PolicyPin {
    pub fn is_disabled(&self) -> bool {
        matches!(self, Self::Disabled { .. })
    }

    /// The policy layer that engaged the pin, if any.
    pub fn source(&self) -> Option<&Path> {
        match self {
            Self::Unpinned => None,
            Self::Disabled { source, .. } => Some(source),
        }
    }

    /// Engage the pin from `path`: the first engaging layer names the source, but an admin-owned layer re-attributes a
    /// user-owned pin, never the reverse.
    pub fn tighten(&mut self, path: &Path, ownership: PolicyLayerOwnership) {
        let upgrades = ownership == PolicyLayerOwnership::Admin
            && matches!(
                self,
                PolicyPin::Disabled {
                    ownership: PolicyLayerOwnership::User,
                    ..
                }
            );
        if !self.is_disabled() || upgrades {
            *self = PolicyPin::Disabled {
                source: path.to_path_buf(),
                ownership,
            };
        }
    }
}

/// The tighten-only boolean pins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoolPin {
    /// `enable_all_project_mcp_servers = false`: drop project MCP servers unless an allow entry grants them.
    ProjectMcp,
    /// `allow_managed_hooks_only = true`: hooks that are not managed policy do not run.
    NonManagedHooks,
}

impl BoolPin {
    pub const ALL: [Self; 2] = [Self::ProjectMcp, Self::NonManagedHooks];

    /// Claude `managed-settings.json` spelling first, Fuigo TOML spelling second.
    pub fn keys(self) -> [&'static str; 2] {
        match self {
            Self::ProjectMcp => [
                "enableAllProjectMcpServers",
                "enable_all_project_mcp_servers",
            ],
            Self::NonManagedHooks => ["allowManagedHooksOnly", "allow_managed_hooks_only"],
        }
    }

    /// The value that engages the pin.
    pub fn engages_on(self) -> bool {
        match self {
            Self::ProjectMcp => false,
            Self::NonManagedHooks => true,
        }
    }
}

/// Resolve one pin across `sources` (strictest wins). An unreadable source engages every pin; an invalid value fails
/// closed to the engaging one.
pub fn resolve_bool_pin(pin: BoolPin, sources: &[PolicySource]) -> PolicyPin {
    let mut out = PolicyPin::Unpinned;
    for source in sources {
        let engaged = match &source.policy {
            Err(_) => true,
            Ok(json) => {
                policy_bool(json, &pin.keys(), pin.engages_on(), &source.path)
                    == Some(pin.engages_on())
            }
        };
        if engaged {
            out.tighten(&source.path, source.ownership);
        }
    }
    out
}

/// The `allow_managed_hooks_only` pin as the policy files are now. P183 round 9 (Grok r5 H2): read on every call, cached by
/// the sources it was built from, so a file that breaks after a good first read engages it without a restart.
pub fn managed_hooks_only_pin() -> &'static PolicyPin {
    static CACHE: std::sync::Mutex<Option<(String, &'static PolicyPin)>> = std::sync::Mutex::new(None);
    let sources = policy_sources();
    let key = format!("{sources:?}");
    let mut guard = CACHE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some((k, pin)) = guard.as_ref()
        && *k == key
    {
        return pin;
    }
    let pin: &'static PolicyPin = Box::leak(Box::new(resolve_bool_pin(BoolPin::NonManagedHooks, &sources)));
    *guard = Some((key, pin));
    pin
}

#[cfg(test)]
#[path = "policy_sources_tests.rs"]
mod tests;

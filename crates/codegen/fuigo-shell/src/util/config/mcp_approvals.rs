//! MC-03 (1.0.47 S3): a changed MCP server definition is not started until the user approves it again.
//!
//! * **Digest `mcpdef.v1`.** SHA-256 over length-prefixed fields with a version tag: what a definition runs or where it
//!   connects (command, every argument byte for byte, env; or transport, url, headers, bearer settings and every OAuth
//!   setting). Taken after `setup` resolves and before `${VAR}` expansion, so the environment is not the definition.
//!   Not hashed: `enabled`, timeouts, `cwd` (spawn drops it). Map-form env/headers are sorted (a map has no order);
//!   list-form ones (an agent definition's inline ACP lists) are hashed in order with duplicates, because launch
//!   applies them in order and the last one wins.
//!   Encoding change rule: keep the old encoder, accept its digest, and add the new digest to the set silently (the
//!   1.0.46 grant fix, `mcp_definition_fingerprint_1045`). If spawn ever honours `cwd`, that is `mcpdef.v2`.
//! * **Stamp.** The digest is computed together with each launch object, from the same read, and travels inside the
//!   object (`_meta["fuigo/mcpAdmission"]`) through merge, substitution, overlays, check, record and launch. The stamp
//!   also carries the OAuth settings of that same read, so connect uses the admitted values, never a fresh disk read.
//! * **Store** `$FUIGO_HOME/mcp_approved_definitions.json`: a set of approved digests per key (newest last, at most
//!   16). Missing = bootstrap (everything first-seen, recorded silently); unreadable, malformed or an unknown version =
//!   Unavailable: covered servers are held, the file is never overwritten except by `fuigo mcp approvals reset`.
//!   Records are never dropped (remove keeps them).
//!
//! Limit (stated, not guarded): a process the user lets run arbitrary commands as the user can approve a definition,
//! just as it can rewrite `config.toml` and this store. In bypass mode that includes the agent's own shell. What the
//! gate guarantees is that a definition changed outside an approval step never starts silently.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use agent_client_protocol as acp;
use anyhow::Result;
use fuigo_config_types::{McpServerConfig, McpServerTransportConfig};
use serde::{Deserialize, Serialize};

/// The `_meta` key of a launch object's admission stamp.
pub(crate) const ADMISSION_META_KEY: &str = "fuigo/mcpAdmission";
/// Digest tag of the current encoding.
pub(crate) const MCPDEF_V1: &str = "mcpdef.v1";
const STORE_VERSION: u32 = 1;
const MAX_DIGESTS_PER_KEY: usize = 16;
pub(crate) const STORE_FILENAME: &str = "mcp_approved_definitions.json";

/// What a covered launch object carries: its approval key, the digest of the definition it was built from, where
/// that definition lives (for notices), and that definition's OAuth settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AdmissionStamp {
    pub key: String,
    pub digest: String,
    pub origin: String,
    /// The OAuth settings of the same read, as a minimal `McpServerConfig` (url placeholder, the OAuth transport
    /// fields, the `[oauth]` block and the untrusted mark). Names only: the secret is read from its variable at connect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oauth: Option<serde_json::Value>,
}

impl AdmissionStamp {
    /// The admitted OAuth configuration, resolved now (the secret's VALUE is the environment, not the definition).
    pub(crate) fn oauth_config(&self) -> Option<crate::util::config::McpOAuthConfig> {
        let source: McpServerConfig = serde_json::from_value(self.oauth.clone()?).ok()?;
        source.oauth_config()
    }
}

// ── digest ───────────────────────────────────────────────────────────

struct Fields(sha2::Sha256);

impl Fields {
    fn new(form: &str) -> Self {
        use sha2::Digest as _;
        let mut f = Self(sha2::Sha256::new());
        f.bytes(b"fuigo.mcpdef.v1");
        f.bytes(form.as_bytes());
        f
    }
    fn bytes(&mut self, b: &[u8]) {
        use sha2::Digest as _;
        self.0.update((b.len() as u64).to_le_bytes());
        self.0.update(b);
    }
    fn str(&mut self, s: &str) {
        self.bytes(s.as_bytes());
    }
    fn count(&mut self, n: usize) {
        self.bytes(&(n as u64).to_le_bytes());
    }
    fn opt(&mut self, s: Option<&str>) {
        match s {
            Some(s) => {
                self.str("some");
                self.str(s);
            }
            None => self.str("none"),
        }
    }
    /// A map: sorted by key (it has no order of its own).
    fn map<'a>(&mut self, m: Option<impl Iterator<Item = (&'a String, &'a String)>>) {
        let mut pairs: Vec<(&String, &String)> = m.map(|m| m.collect()).unwrap_or_default();
        pairs.sort();
        self.pairs(pairs.into_iter().map(|(k, v)| (k.as_str(), v.as_str())));
    }
    /// A list of pairs, in the order given (duplicates kept).
    fn pairs<'a>(&mut self, pairs: impl Iterator<Item = (&'a str, &'a str)>) {
        let pairs: Vec<_> = pairs.collect();
        self.count(pairs.len());
        for (k, v) in pairs {
            self.str(k);
            self.str(v);
        }
    }
    fn sorted_list(&mut self, l: Option<&Vec<String>>) {
        match l {
            Some(l) => {
                let mut l: Vec<&String> = l.iter().collect();
                l.sort();
                self.str("some");
                self.count(l.len());
                for s in l {
                    self.str(s);
                }
            }
            None => self.str("none"),
        }
    }
    fn finish(self) -> String {
        use sha2::Digest as _;
        format!("{MCPDEF_V1}:{:x}", self.0.finalize())
    }
}

/// `mcpdef.v1` of a definition from a config file (map form), as setup resolves it and before expansion.
pub(crate) fn mcpdef_v1_config(config: &McpServerConfig) -> String {
    match &config.transport {
        McpServerTransportConfig::Stdio {
            command, args, env, ..
        } => {
            let mut f = Fields::new("map");
            f.str("stdio");
            f.str(command);
            f.count(args.len());
            for arg in args {
                f.str(arg);
            }
            f.map(env.as_ref().map(|e| e.iter()));
            f.finish()
        }
        McpServerTransportConfig::StreamableHttp {
            url,
            transport_type,
            bearer_token_env_var,
            bearer_token_file,
            headers,
            oauth_client_id,
            oauth_client_secret_env_var,
            oauth_scopes,
        } => {
            let mut f = Fields::new("map");
            f.str("http");
            f.opt(transport_type.as_deref());
            f.str(url);
            f.map(headers.as_ref().map(|h| h.iter()));
            f.opt(bearer_token_env_var.as_deref());
            f.opt(bearer_token_file.as_deref());
            f.opt(oauth_client_id.as_deref());
            f.opt(oauth_client_secret_env_var.as_deref());
            f.sorted_list(oauth_scopes.as_ref());
            match &config.oauth {
                Some(block) => {
                    f.str("oauth");
                    f.opt(block.client_id.as_deref());
                    f.opt(block.client_secret_env_var.as_deref());
                    f.sorted_list(block.scopes.as_ref());
                    f.opt(block.callback_port.map(|p| p.to_string()).as_deref());
                }
                None => f.str("no-oauth"),
            }
            f.finish()
        }
    }
}

/// `mcpdef.v1` of a launch object as written (an agent definition's inline server; list form: env and headers in
/// order, duplicates kept). Its `_meta`, minus the admission stamp, is part of it.
pub(crate) fn mcpdef_v1_acp(server: &acp::McpServer) -> Option<String> {
    let mut f = Fields::new("list");
    let meta = |m: &Option<acp::Meta>| {
        let mut m = m.clone().unwrap_or_default();
        m.remove(ADMISSION_META_KEY);
        serde_json::to_string(&m).unwrap_or_default()
    };
    match server {
        acp::McpServer::Stdio(s) => {
            f.str("stdio");
            f.str(&s.command.to_string_lossy());
            f.count(s.args.len());
            for arg in &s.args {
                f.str(arg);
            }
            f.pairs(s.env.iter().map(|e| (e.name.as_str(), e.value.as_str())));
            f.str(&meta(&s.meta));
        }
        acp::McpServer::Http(s) => {
            f.str("http");
            f.str(&s.url);
            f.pairs(
                s.headers
                    .iter()
                    .map(|h| (h.name.as_str(), h.value.as_str())),
            );
            f.str(&meta(&s.meta));
        }
        acp::McpServer::Sse(s) => {
            f.str("sse");
            f.str(&s.url);
            f.pairs(
                s.headers
                    .iter()
                    .map(|h| (h.name.as_str(), h.value.as_str())),
            );
            f.str(&meta(&s.meta));
        }
        // TODO(acp-0.10): `McpServer` is #[non_exhaustive].
        _ => return None,
    }
    Some(f.finish())
}

// ── stamp ────────────────────────────────────────────────────────────

fn meta_mut(server: &mut acp::McpServer) -> Option<&mut Option<acp::Meta>> {
    match server {
        acp::McpServer::Stdio(s) => Some(&mut s.meta),
        acp::McpServer::Http(s) => Some(&mut s.meta),
        acp::McpServer::Sse(s) => Some(&mut s.meta),
        _ => None,
    }
}

fn meta_ref(server: &acp::McpServer) -> Option<&acp::Meta> {
    match server {
        acp::McpServer::Stdio(s) => s.meta.as_ref(),
        acp::McpServer::Http(s) => s.meta.as_ref(),
        acp::McpServer::Sse(s) => s.meta.as_ref(),
        _ => None,
    }
}

/// The admission stamp a launch object carries, if any.
pub(crate) fn read_stamp(server: &acp::McpServer) -> Option<AdmissionStamp> {
    serde_json::from_value(meta_ref(server)?.get(ADMISSION_META_KEY)?.clone()).ok()
}

/// Mark `server` as built by an uncovered source (`plugin`, `client` or `managed`): the gate admits it without a check.
/// Every other launch object must carry a stamp; one with neither is held (fail closed: a covered loader that lost its
/// stamp never starts silently). The mark lives under the stamp's key, so whatever strips a stamp strips it too.
pub(crate) fn mark_uncovered(server: &mut acp::McpServer, source: &str) {
    if let Some(meta) = meta_mut(server) {
        meta.get_or_insert_with(Default::default).insert(
            ADMISSION_META_KEY.to_owned(),
            serde_json::json!({ "uncovered": source }),
        );
    }
}

/// The uncovered source `server` was marked with ([`mark_uncovered`]), if any.
pub(crate) fn uncovered_source(server: &acp::McpServer) -> Option<&str> {
    meta_ref(server)?
        .get(ADMISSION_META_KEY)?
        .get("uncovered")?
        .as_str()
}

/// Remove any admission stamp (a client- or file-supplied object must not carry one it did not get from the gate's
/// own materialize).
pub(crate) fn strip_stamp(server: &mut acp::McpServer) {
    if let Some(meta) = meta_mut(server)
        && let Some(m) = meta.as_mut()
    {
        m.remove(ADMISSION_META_KEY);
        if m.is_empty() {
            *meta = None;
        }
    }
}

pub(crate) fn set_stamp(server: &mut acp::McpServer, stamp: &AdmissionStamp) {
    let Ok(value) = serde_json::to_value(stamp) else {
        return;
    };
    if let Some(meta) = meta_mut(server) {
        meta.get_or_insert_with(Default::default)
            .insert(ADMISSION_META_KEY.to_owned(), value);
    }
}

/// Where a definition was read from, as the approval key and a display origin. Keys follow the owning scope
/// (Fable r2 M1): every home source is `user`, the three project sources of one directory share that directory,
/// `~/.claude.json projects.<cwd>` keeps its own selector (the loader's raw cwd string), campaigns are `campaign`.
#[derive(Debug, Clone)]
pub(crate) struct DefinitionOrigin {
    pub scope: String,
    pub display: String,
    /// A config.toml definition as written (its `${VAR}` references unexpanded), when expanding it exactly as the loader
    /// does reproduces the loaded definition: the digest is taken over it, so rotating a referenced value is not a
    /// definition change (coordinator: token rotation). `None`: the loaded definition is digested.
    pub raw: Option<Box<McpServerConfig>>,
}

impl DefinitionOrigin {
    pub(crate) fn user(display: impl Into<String>) -> Self {
        Self {
            scope: "user".to_owned(),
            display: display.into(),
            raw: None,
        }
    }
    pub(crate) fn campaign() -> Self {
        Self {
            scope: "campaign".to_owned(),
            display: "a campaign".to_owned(),
            raw: None,
        }
    }
    /// A project file `file` that sits in `dir` (for `.fuigo/config.toml` and `.cursor/mcp.json`, the folder that
    /// holds that subfolder). The directory is canonicalised so a symlinked spelling is one key.
    pub(crate) fn project_dir(dir: &Path, file: &Path) -> Self {
        let dir = dunce_canonical(dir);
        Self {
            scope: format!("project:{}", dir.display()),
            display: file.display().to_string(),
            raw: None,
        }
    }
    pub(crate) fn claude_project(claude_json: &Path, cwd_raw: &str) -> Self {
        Self {
            scope: format!("{}#projects/{cwd_raw}", claude_json.display()),
            display: format!("{} (projects.{cwd_raw})", claude_json.display()),
            raw: None,
        }
    }
    pub(crate) fn agent(file: &Path) -> Self {
        Self {
            scope: format!("agent:{}", dunce_canonical(file).display()),
            display: file.display().to_string(),
            raw: None,
        }
    }
    pub(crate) fn key(&self, name: &str) -> String {
        format!("{}\0{name}", self.scope)
    }
}

fn dunce_canonical(p: &Path) -> PathBuf {
    dunce::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
}

/// The OAuth settings of `expanded` as the stamp carries them (see [`AdmissionStamp::oauth`]).
pub(crate) fn oauth_source(expanded: &McpServerConfig) -> Option<serde_json::Value> {
    let McpServerTransportConfig::StreamableHttp {
        oauth_client_id,
        oauth_client_secret_env_var,
        oauth_scopes,
        ..
    } = &expanded.transport
    else {
        return None;
    };
    if oauth_client_id.is_none() && expanded.oauth.is_none() {
        return None;
    }
    let mut json = serde_json::json!({ "url": "-" });
    let obj = json.as_object_mut()?;
    let mut put = |k: &str, v: serde_json::Value| {
        if !v.is_null() {
            obj.insert(k.to_owned(), v);
        }
    };
    put("oauth_client_id", serde_json::json!(oauth_client_id));
    put(
        "oauth_client_secret_env_var",
        serde_json::json!(oauth_client_secret_env_var),
    );
    put("oauth_scopes", serde_json::json!(oauth_scopes));
    put("oauth", serde_json::to_value(&expanded.oauth).ok()?);
    if expanded.untrusted_source {
        put("__fuigo_untrusted_source", serde_json::Value::Bool(true));
    }
    Some(json)
}

/// Stamp `server` (built from `expanded`) with the digest of `resolved` (the same definition, setup resolved, not yet
/// expanded) under `origin`'s key for `name`.
pub(crate) fn stamp_from_config(
    server: &mut acp::McpServer,
    name: &str,
    resolved: &McpServerConfig,
    expanded: &McpServerConfig,
    origin: &DefinitionOrigin,
) {
    let stamp = AdmissionStamp {
        key: origin.key(name),
        digest: mcpdef_v1_config(resolved),
        origin: origin.display.clone(),
        oauth: oauth_source(expanded),
    };
    set_stamp(server, &stamp);
}

// ── store ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub(crate) struct StoreFile {
    pub version: u32,
    #[serde(default)]
    pub servers: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
pub(crate) enum StoreState {
    /// No file (`ENOENT` only): bootstrap.
    Missing,
    Ok(StoreFile),
    /// Unreadable, malformed or an unsupported version: fails closed.
    Unavailable(String),
}

impl StoreState {
    pub(crate) fn digests(&self, key: &str) -> Option<&[String]> {
        match self {
            Self::Ok(f) => f.servers.get(key).map(Vec::as_slice),
            _ => None,
        }
    }
}

pub(crate) fn store_path() -> PathBuf {
    fuigo_config::fuigo_home().join(STORE_FILENAME)
}

fn parse_store(bytes: &[u8]) -> Result<StoreFile, String> {
    let file: StoreFile =
        serde_json::from_slice(bytes).map_err(|e| format!("malformed JSON: {e}"))?;
    if file.version != STORE_VERSION {
        return Err(format!("unsupported version {}", file.version));
    }
    Ok(file)
}

pub(crate) fn load_store_at(path: &Path) -> StoreState {
    match std::fs::read(path) {
        Ok(bytes) => match parse_store(&bytes) {
            Ok(file) => StoreState::Ok(file),
            Err(reason) => StoreState::Unavailable(reason),
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => StoreState::Missing,
        Err(e) => StoreState::Unavailable(e.to_string()),
    }
}

pub(crate) fn load_store() -> StoreState {
    load_store_at(&store_path())
}

/// Outcome of a first-seen record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FirstSeen {
    /// The key was missing and now holds this digest.
    Recorded,
    /// Another writer recorded the key meanwhile, with this digest among its set.
    Approved,
    /// Another writer recorded the key meanwhile without this digest: hold.
    Held,
    /// The store could not be locked or read under the lock, so whether the key is still missing is unknown: hold
    /// (review Astra M2). Only a write failure after absence was established (`Err`) admits.
    Unavailable(String),
}

#[allow(
    clippy::disallowed_methods,
    reason = "1.0.47 S2 by-path atomic write: $FUIGO_HOME/mcp_approved_definitions.json, outside the at-rest roots (sessions/, logs/)"
)]
fn stage_store(
    path: &Path,
    bytes: &[u8],
) -> std::io::Result<fuigo_config::fs_atomic::StagedReplacement> {
    fuigo_config::fs_atomic::stage_atomically(path, bytes, Some(0o600))
}

fn store_edit<T>(path: &Path, f: impl FnMut(&mut StoreFile) -> (bool, T)) -> Result<T> {
    use fuigo_config::fs_atomic::EditError;
    store_edit_raw(path, stage_store, f).map_err(|e| match e {
        EditError::Edit(e) => e,
        EditError::Lock(e) => anyhow::Error::from(e),
        EditError::Write(e) => anyhow::anyhow!("failed to write {}: {e}", path.display()),
    })
}

/// [`store_edit`] with the lock, write and read/parse failures kept apart.
fn store_edit_raw<T>(
    path: &Path,
    stage: super::persist::StageFn,
    mut f: impl FnMut(&mut StoreFile) -> (bool, T),
) -> Result<T, fuigo_config::fs_atomic::EditError<anyhow::Error>> {
    use fuigo_config::fs_atomic::Edit;
    let shown = path.to_path_buf();
    super::persist::edit_config_file_raw(path, stage, move |current| {
        let mut file = match current {
            Ok(None) => StoreFile {
                version: STORE_VERSION,
                servers: BTreeMap::new(),
            },
            Ok(Some(bytes)) => parse_store(bytes).map_err(|reason| {
                anyhow::anyhow!(
                    "refusing to overwrite unreadable MCP approvals at {} ({reason})",
                    shown.display()
                )
            })?,
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "refusing to overwrite unreadable MCP approvals at {} ({e})",
                    shown.display()
                ));
            }
        };
        let (changed, value) = f(&mut file);
        if !changed {
            return Ok(Edit::Keep(value));
        }
        Ok(Edit::Replace {
            contents: serde_json::to_vec_pretty(&file)?,
            value,
        })
    })
}

/// Compare-or-insert under the store lock: insert `[digest]` only when `key` is still missing. `Err` when the record
/// could not be written; a staging failure can come before the lock, so then absence was read from the unlocked
/// snapshot (the designed first-seen write-failure exception). A lock or locked-read failure is
/// [`FirstSeen::Unavailable`].
pub(crate) fn record_first_seen_at(path: &Path, key: &str, digest: &str) -> Result<FirstSeen> {
    record_first_seen_with(path, stage_store, key, digest)
}

pub(crate) fn record_first_seen_with(
    path: &Path,
    stage: super::persist::StageFn,
    key: &str,
    digest: &str,
) -> Result<FirstSeen> {
    use fuigo_config::fs_atomic::EditError;
    let outcome = store_edit_raw(path, stage, |file| match file.servers.get(key) {
        None => {
            file.servers.insert(key.to_owned(), vec![digest.to_owned()]);
            (true, FirstSeen::Recorded)
        }
        Some(set) if set.iter().any(|d| d == digest) => (false, FirstSeen::Approved),
        Some(_) => (false, FirstSeen::Held),
    });
    match outcome {
        Ok(seen) => Ok(seen),
        // Only a `Replace` is written, so absence was established under the lock.
        Err(EditError::Write(e)) => Err(anyhow::anyhow!("failed to write {}: {e}", path.display())),
        Err(EditError::Lock(e)) => Ok(FirstSeen::Unavailable(e.to_string())),
        Err(EditError::Edit(e)) => Ok(FirstSeen::Unavailable(e.to_string())),
    }
}

/// Add `digest` to `key`'s approved set (newest last, oldest falls off past 16). Never reads config and never touches
/// `enabled`. An Unavailable store is refused, never overwritten (`fuigo mcp approvals reset` repairs it).
pub(crate) fn approve_mcp_definition_at(path: &Path, key: &str, digest: &str) -> Result<()> {
    store_edit(path, |file| {
        let set = file.servers.entry(key.to_owned()).or_default();
        if set.last().is_some_and(|d| d == digest) {
            return (false, ());
        }
        set.retain(|d| d != digest);
        set.push(digest.to_owned());
        if set.len() > MAX_DIGESTS_PER_KEY {
            let excess = set.len() - MAX_DIGESTS_PER_KEY;
            set.drain(..excess);
        }
        (true, ())
    })?;
    tracing::info!(key = %key.replace('\0', " "), "approved MCP server definition");
    Ok(())
}

pub(crate) fn approve_mcp_definition(key: &str, digest: &str) -> Result<()> {
    approve_mcp_definition_at(&store_path(), key, digest)
}

/// `fuigo mcp approvals reset`: rename the store aside (`.bad-<UTC>`), so the next launch bootstraps and records every
/// server configured now. Returns where the old file went, or `None` when there was none.
pub fn reset_mcp_approvals() -> Result<Option<PathBuf>> {
    reset_mcp_approvals_at(&store_path())
}

#[allow(
    clippy::disallowed_methods,
    reason = "renames the approvals file in FUIGO_HOME aside (never a session folder); a rename keeps the old bytes for the user"
)]
pub(crate) fn reset_mcp_approvals_at(path: &Path) -> Result<Option<PathBuf>> {
    if std::fs::symlink_metadata(path).is_err() {
        return Ok(None);
    }
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let aside = path.with_file_name(format!("{STORE_FILENAME}.bad-{stamp}"));
    std::fs::rename(path, &aside)?;
    Ok(Some(aside))
}

/// The one notice for an Unavailable store.
pub(crate) fn unavailable_store_notice(reason: &str) -> String {
    format!(
        "warning: MCP servers from your config files were not started: the approvals file {} could not be read ({reason}). Fix the file, or run `fuigo mcp approvals reset` to start a new one (the old file is kept as {STORE_FILENAME}.bad-<UTC>).",
        display_store_path()
    )
}

fn display_store_path() -> String {
    let path = store_path();
    match fuigo_dirs::home_dir() {
        Some(home) => match path.strip_prefix(&home) {
            Ok(rest) => format!("~/{}", rest.display()),
            Err(_) => path.display().to_string(),
        },
        None => path.display().to_string(),
    }
}

/// The notice for a held server, naming its real origin.
pub(crate) fn held_notice(name: &str, origin: &str) -> String {
    let tidy = fuigo_config::config_override::tidy_note_text;
    let name = tidy(name, 64);
    let origin = tidy(origin, 160);
    format!(
        "warning: MCP server `{name}` was not started: its definition (command, arguments, environment, URL or headers) changed since you approved it ({origin}). If you made this change, approve it with `fuigo mcp enable {name}` and restart, or turn it on in /mcp."
    )
}

/// What a held server will run or connect to, for a prompt or the CLI: the command line, or the URL (redacted) and
/// header NAMES. Cleaned and capped like the campaign notices.
pub(crate) fn launch_display(server: &acp::McpServer) -> String {
    let tidy = fuigo_config::config_override::tidy_note_text;
    match server {
        acp::McpServer::Stdio(s) => {
            let line = std::iter::once(s.command.to_string_lossy().into_owned())
                .chain(s.args.iter().cloned())
                .collect::<Vec<_>>()
                .join(" ");
            format!("runs: {}", tidy(&line, 240))
        }
        acp::McpServer::Http(acp::McpServerHttp { url, headers, .. })
        | acp::McpServer::Sse(acp::McpServerSse { url, headers, .. }) => {
            let names: Vec<&str> = headers.iter().map(|h| h.name.as_str()).collect();
            let url = fuigo_auth::redact_url(url);
            let headers = if names.is_empty() {
                String::new()
            } else {
                format!(" (headers: {})", tidy(&names.join(", "), 120))
            };
            format!("connects to: {}{headers}", tidy(&url, 200))
        }
        _ => String::new(),
    }
}

#[cfg(test)]
#[allow(
    clippy::disallowed_methods,
    reason = "test code: fixtures create, corrupt and remove files in test-owned temp dirs or a test FUIGO_HOME; no product session writer runs there"
)]
#[path = "mcp_approvals_tests.rs"]
mod tests;

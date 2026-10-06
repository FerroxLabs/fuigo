//! Which config sources may name the saved API key `FUIGO_API_KEY` (P118, backlog row P103).
//!
//! Only an exact list of files may: `$FUIGO_HOME/{config,managed_config,requirements}.toml`,
//! `{managed_config,requirements}.toml` under the system directory (`/etc/fuigo`, which has no `config.toml` layer), the
//! user's own `~/.claude.json` and `~/.cursor/mcp.json`, and hook files whose real path is under `$FUIGO_HOME/hooks/`. A project's config, a plugin, a project `.mcp.json`, a worktree, any other file and an MCP
//! server an ACP client supplies (`session/new`, `mcp/upsert`) may not. A reference from such a source is REFUSED when
//! the source is loaded, before any expansion (so an exported key is refused too): it is removed from the value (a name
//! that points at the key, such as `bearer_token_env_var = "FUIGO_API_KEY"`, removes the entry), and a note says which
//! file, which key, and what to do.

use std::path::{Component, Path, PathBuf};
use std::sync::Mutex;

use crate::credential_env::FIRST_PARTY_KEY_ENV_VAR;

/// One reference to the saved key that was refused (and removed) from an untrusted source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedKeyReference {
    /// The file (or plugin label) the reference was found in.
    pub file: String,
    /// The config key it was written under, e.g. `mcp_servers.s.env.TOKEN`.
    pub key: String,
}

impl RefusedKeyReference {
    /// The note shown to the user. Never holds a value.
    pub fn note(&self) -> String {
        format!(
            "{file}: `{key}` names {name}, the saved API key, and was ignored. Only these may name it: \
             $FUIGO_HOME/config.toml, managed_config.toml and requirements.toml, managed_config.toml and \
             requirements.toml under /etc/fuigo, ~/.claude.json, ~/.cursor/mcp.json, and hook files under \
             $FUIGO_HOME/hooks/. Anything else may not: a project config or .mcp.json, a plugin, a worktree, another file \
             under $FUIGO_HOME, a FUIGO_CONFIG_PATH file, a hook file elsewhere (~/.claude/settings.json, a hooks-paths \
             entry), or an MCP server an editor or ACP client supplies. The reference was removed. Move this entry into \
             $FUIGO_HOME/config.toml (usually ~/.fuigo/config.toml) or a hook file into $FUIGO_HOME/hooks/, or have it \
             read another environment variable.",
            file = self.file,
            key = self.key,
            name = FIRST_PARTY_KEY_ENV_VAR
        )
    }
}

/// Absolute, with `.` and `..` resolved lexically.
fn normalize(path: &Path) -> PathBuf {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().unwrap_or_default().join(path)
    };
    let mut out = PathBuf::new();
    for c in abs.components() {
        match c {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// The real path of `path`: symlinks and aliases resolved (P118 round 3, N3). A file or directory that does not exist
/// yet resolves through its nearest existing ancestor, so the answer is the same before and after it is created.
fn canonical(path: &Path) -> PathBuf {
    // Astra P147 r1: an existing path is resolved by the OS as written, so `link/..` follows the link first (a lexical
    // `..` would drop the link and judge the wrong directory).
    let abs = if path.is_absolute() { path.to_path_buf() } else { std::env::current_dir().unwrap_or_default().join(path) };
    if let Ok(real) = dunce::canonicalize(&abs) {
        return real;
    }
    let norm = normalize(path);
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut probe = norm.as_path();
    loop {
        if let Ok(real) = dunce::canonicalize(probe) {
            let mut out = real;
            out.extend(tail.iter().rev());
            return out;
        }
        match (probe.parent(), probe.file_name()) {
            (Some(parent), Some(name)) => {
                tail.push(name.to_os_string());
                probe = parent;
            }
            _ => return norm,
        }
    }
}

/// On case-insensitive file systems (macOS, Windows) `PLUGINS` and `plugins` are one directory: compare folded.
fn fold(path: PathBuf) -> PathBuf {
    if cfg!(any(target_os = "macos", target_os = "windows")) {
        PathBuf::from(path.to_string_lossy().to_lowercase())
    } else {
        path
    }
}

fn resolved(path: &Path) -> PathBuf {
    fold(canonical(path))
}

/// The user-level and managed config files that may name the saved key, by name.
pub(crate) const TRUSTED_CONFIG_FILES: [&str; 3] = ["config.toml", "managed_config.toml", "requirements.toml"];

/// The system-directory (`/etc/fuigo`) files that may name the saved key: the two Fuigo reads there.
pub(crate) const TRUSTED_SYSTEM_FILES: [&str; 2] = ["managed_config.toml", "requirements.toml"];

/// [`source_may_name_saved_key`] with the directories given.
///
/// Trust is an EXACT allowlist of real files (P118 round 3, R2-6/N3), never a directory prefix: `$FUIGO_HOME` holds
/// worktrees, plugins and other repositories' files that must not inherit user authority. Both sides are resolved with
/// `realpath` (and case-folded where the file system is case-insensitive) before they are compared, so a symlink or an
/// alias spelling of an untrusted file is untrusted and an alias of a trusted file (a symlinked `~/.fuigo`) is trusted.
/// The one directory trusted as a whole is the user's `hooks` directory.
pub(crate) fn source_may_name_saved_key_at(
    path: &Path,
    user_home: Option<&Path>,
    system_dir: Option<&Path>,
    home: Option<&Path>,
) -> bool {
    let path = resolved(path);
    let mut exact: Vec<PathBuf> = Vec::new();
    if let Some(dir) = user_home {
        exact.extend(TRUSTED_CONFIG_FILES.iter().map(|f| resolved(&dir.join(f))));
    }
    // P147: Fuigo reads no `config.toml` from the system directory (only the two managed files), so only those two are
    // listed; the note says the same.
    if let Some(dir) = system_dir {
        exact.extend(TRUSTED_SYSTEM_FILES.iter().map(|f| resolved(&dir.join(f))));
    }
    if let Some(home) = home {
        exact.push(resolved(&home.join(".claude.json")));
        exact.push(resolved(&home.join(".cursor").join("mcp.json")));
    }
    exact.contains(&path) || hook_file_may_name_saved_key_in(&path, user_home)
}

/// Whether the config file at `path` may name the saved API key.
pub fn source_may_name_saved_key(path: &Path) -> bool {
    let user = crate::user_fuigo_home();
    let system = crate::system_config_dir();
    let home = fuigo_dirs::home_dir();
    source_may_name_saved_key_at(path, user.as_deref(), system.as_deref(), home.as_deref())
}

/// Whether the hook FILE at `path` may name the saved key (P147, S16/B32): only a file whose real path is under
/// `$FUIGO_HOME/hooks/`. Every other hook file is refused, user-level ones included: `~/.claude/settings.json`, a
/// `~/.fuigo/hooks-paths` target outside `$FUIGO_HOME/hooks`, and a symlink inside `$FUIGO_HOME/hooks` that points
/// outside it (its real path decides). Config-file hooks (`[[hooks]]` in `config.toml` and the managed files) are
/// decided by [`source_may_name_saved_key`], as for every other setting in those files.
pub fn hook_file_may_name_saved_key(path: &Path) -> bool {
    hook_file_may_name_saved_key_in(path, crate::user_fuigo_home().as_deref())
}

/// [`hook_file_may_name_saved_key`] with the user's fuigo home given.
pub fn hook_file_may_name_saved_key_in(path: &Path, user_home: Option<&Path>) -> bool {
    user_home.is_some_and(|user| {
        let hooks = resolved(&user.join("hooks"));
        let path = resolved(path);
        // Astra P147 r1 #1: a hooks directory that is itself an alias of a plugin's or a worktree's directory does not
        // make their files the user's.
        path.starts_with(&hooks)
            && path != hooks
            && !["worktrees", "plugins"].iter().any(|d| path.starts_with(resolved(&user.join(d))))
    })
}

/// The fields that hold the NAME of a credential variable (not a value): an MCP server's `bearer_token_env_var`, its
/// OAuth client-secret variable (`oauth_client_secret_env_var`, `[oauth] client_secret_env_var`) and a model's `env_key`,
/// in either spelling. An arbitrary map entry that happens to end in `_ENV_VAR` is a value, not a selector.
fn is_name_key(key: &str) -> bool {
    let norm: String = key.chars().filter(|c| *c != '_' && *c != '-').collect::<String>().to_ascii_lowercase();
    matches!(norm.as_str(), "bearertokenenvvar" | "oauthclientsecretenvvar" | "clientsecretenvvar" | "envkey")
}

/// Whether `s` is the saved key's name. Windows environment names are case-insensitive, so there a case variant is too.
fn is_key_name(s: &str) -> bool {
    if cfg!(windows) { s.eq_ignore_ascii_case(FIRST_PARTY_KEY_ENV_VAR) } else { s == FIRST_PARTY_KEY_ENV_VAR }
}

/// Whether a credential selector (the NAME of a variable, as `bearer_token_env_var` holds it) names the saved key: the
/// name itself, or text that still reads it (P136).
pub fn names_saved_key(selector: &str) -> bool {
    is_key_name(selector.trim()) || refuse_key_references_in_str(selector).is_some()
}

/// The saved key's value as config that names it sees it now (saved or exported), if any and not empty.
fn saved_key_value() -> Option<String> {
    crate::credential_env::resolve_credential_env_var(FIRST_PARTY_KEY_ENV_VAR).filter(|key| !key.is_empty())
}

/// Whether `value` holds the saved key (P136): the key itself or text containing it (a credential a definition from an
/// untrusted source resolved through another variable that holds it), or a reference to it that a destination would
/// still resolve (Astra P136 r1 #2: a variable whose value is the text `${FUIGO_API_KEY}`).
pub fn holds_saved_key(value: &str) -> bool {
    refuse_key_references_in_str(value).is_some()
        || saved_key_value().is_some_and(|key| value.contains(key.as_str()))
}

/// Remove the saved key's VALUE from every string of ONE server's definition (JSON), recording a refusal for each
/// (P136, Astra r1 #3): a definition from an untrusted source whose text only became the key after expansion (a
/// persisted `${SWITCH:-$}{FUIGO_API_KEY}` loaded with the key exported) holds no reference any more, only the value.
pub fn refuse_key_values_in_server_json(value: &mut serde_json::Value, file: &str) -> Vec<RefusedKeyReference> {
    fn walk(v: &mut serde_json::Value, path: &str, key: &str, file: &str, out: &mut Vec<RefusedKeyReference>) {
        match v {
            serde_json::Value::String(s) => {
                if s.contains(key) {
                    *s = s.replace(key, "");
                    out.push(RefusedKeyReference { file: file.to_owned(), key: path.to_owned() });
                }
            }
            serde_json::Value::Array(items) => {
                for (i, item) in items.iter_mut().enumerate() {
                    walk(item, &format!("{path}[{i}]"), key, file, out);
                }
            }
            serde_json::Value::Object(map) => {
                for (k, item) in map.iter_mut() {
                    let child = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
                    walk(item, &child, key, file, out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    if let Some(key) = saved_key_value() {
        walk(value, "", &key, file, &mut out);
    }
    out
}

fn starts_with_key_name(s: &str) -> Option<&str> {
    let n = FIRST_PARTY_KEY_ENV_VAR.len();
    let head = s.get(..n)?;
    is_key_name(head).then(|| &s[n..])
}

fn is_ident(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_'
}

/// `text` with every read of the saved key removed (`$FUIGO_API_KEY`, `${FUIGO_API_KEY}`, its modifier, length and
/// indirection forms, also nested in another variable's default), or `None` when it holds none. A `$`-run before the
/// name that is even is an escape and is left alone.
pub fn refuse_key_references_in_str(text: &str) -> Option<String> {
    // Removing a reference can join the text around it into a new one (`$FUIGO_${FUIGO_API_KEY}API_KEY`): repeat until
    // nothing is left to remove.
    let mut current = refuse_once(text)?;
    while let Some(next) = refuse_once(&current) {
        current = next;
    }
    Some(current)
}

fn refuse_once(text: &str) -> Option<String> {
    if !text.to_ascii_lowercase().contains(&FIRST_PARTY_KEY_ENV_VAR.to_ascii_lowercase()) {
        return None;
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let mut changed = false;
    while let Some(dollar) = rest.find('$') {
        out.push_str(&rest[..dollar]);
        let run = rest[dollar..].bytes().take_while(|b| *b == b'$').count();
        let after = &rest[dollar + run..];
        let braced = after.starts_with('{');
        let inner = if braced { &after[1..] } else { after };
        let inner = if braced { inner.strip_prefix(['#', '!']).unwrap_or(inner) } else { inner };
        let names = starts_with_key_name(inner).is_some_and(|tail| !tail.starts_with(is_ident));
        if run % 2 == 1 && names {
            out.push_str(&"$".repeat(run - 1));
            changed = true;
            if braced {
                // The reference ends at the first `}` (as the expanders read it).
                rest = after.find('}').map_or("", |end| &after[end + 1..]);
            } else {
                rest = &after[FIRST_PARTY_KEY_ENV_VAR.len()..];
            }
        } else {
            out.push_str(&"$".repeat(run));
            rest = after;
        }
    }
    out.push_str(rest);
    changed.then_some(out)
}

/// Where a walker is in a source, by STRUCTURE (never by what a key is called): an entry of a server's `env` or
/// `headers` table is a value whatever it is named, and a server may itself be named `env`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ctx {
    Root,
    /// The table of servers (`mcp_servers`, `mcpServers`): its entries are servers, whatever they are named.
    Servers,
    Server,
    /// A server's `env` or `headers` table.
    ValueMap,
}

impl Ctx {
    fn child(self, key: &str) -> Ctx {
        match self {
            Ctx::Root if matches!(key, "mcp_servers" | "mcpServers") => Ctx::Servers,
            Ctx::Root => Ctx::Root,
            Ctx::Servers => Ctx::Server,
            Ctx::Server if matches!(key, "env" | "headers") => Ctx::ValueMap,
            Ctx::Server => Ctx::Server,
            Ctx::ValueMap => Ctx::ValueMap,
        }
    }
}

fn in_setup(path: &str) -> bool {
    path.split(['.', '[']).any(|seg| seg == "setup")
}

/// Refuse one string value. Returns true when the whole entry must be removed (it names the saved key as a selector).
fn scrub_str_value(
    value: &mut String,
    key_path: &str,
    file: &str,
    key_name: &str,
    selector_ok: bool,
    out: &mut Vec<RefusedKeyReference>,
) -> bool {
    let selector = selector_ok && is_name_key(key_name);
    if selector && is_key_name(value.trim()) {
        out.push(RefusedKeyReference { file: file.to_owned(), key: key_path.to_owned() });
        return true;
    }
    let mut hit = false;
    if let Some(clean) = refuse_key_references_in_str(value) {
        *value = clean;
        hit = true;
    }
    // A setup template (`${{key}}` rendered later from a mapped value) can build a reference after load: nothing under
    // `setup` may hold the bare name at all.
    if in_setup(key_path) {
        let name = FIRST_PARTY_KEY_ENV_VAR.to_ascii_lowercase();
        while let Some(at) = lower_find(value, &name) {
            value.replace_range(at..at + name.len(), "");
            hit = true;
        }
    }
    if hit {
        out.push(RefusedKeyReference { file: file.to_owned(), key: key_path.to_owned() });
        // Removing a reference can leave the bare name as the whole value of a selector (`FUI${FUIGO_API_KEY}GO_API_KEY`).
        if selector && is_key_name(value.trim()) {
            return true;
        }
    }
    false
}

fn lower_find(value: &str, lower_name: &str) -> Option<usize> {
    value.to_ascii_lowercase().find(lower_name)
}

/// Refuse every reference to the saved key in a TOML source. `file` labels the notes.
pub fn refuse_key_references_in_toml(value: &mut toml::Value, file: &str) -> Vec<RefusedKeyReference> {
    fn walk(v: &mut toml::Value, path: &str, name: &str, ctx: Ctx, file: &str, out: &mut Vec<RefusedKeyReference>) {
        let selector_ok = ctx != Ctx::ValueMap;
        match v {
            toml::Value::String(s) => {
                scrub_str_value(s, path, file, name, selector_ok, out);
            }
            toml::Value::Array(items) => {
                let mut keep = Vec::with_capacity(items.len());
                for (i, mut item) in std::mem::take(items).into_iter().enumerate() {
                    let item_path = format!("{path}[{i}]");
                    if let toml::Value::String(s) = &mut item
                        && scrub_str_value(s, &item_path, file, name, selector_ok, out)
                    {
                        continue;
                    }
                    if !matches!(item, toml::Value::String(_)) {
                        walk(&mut item, &item_path, name, ctx, file, out);
                    }
                    keep.push(item);
                }
                *items = keep;
            }
            toml::Value::Table(table) => {
                let mut drop = Vec::new();
                for (k, item) in table.iter_mut() {
                    let child = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
                    let child_ctx = ctx.child(k);
                    if let toml::Value::String(s) = item
                        && scrub_str_value(s, &child, file, k, ctx != Ctx::ValueMap, out)
                    {
                        drop.push(k.clone());
                        continue;
                    }
                    if !matches!(item, toml::Value::String(_)) {
                        walk(item, &child, k, child_ctx, file, out);
                    }
                }
                for k in drop {
                    table.remove(&k);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(value, "", "", Ctx::Root, file, &mut out);
    out
}

/// Refuse every reference to the saved key in a JSON source (`.mcp.json`, a plugin manifest).
pub fn refuse_key_references_in_json(value: &mut serde_json::Value, file: &str) -> Vec<RefusedKeyReference> {
    refuse_json_at(value, file, Ctx::Root)
}

/// [`refuse_key_references_in_json`] for ONE server's definition, the shape after every layer has been applied.
pub fn refuse_key_references_in_server_json(value: &mut serde_json::Value, file: &str) -> Vec<RefusedKeyReference> {
    refuse_json_at(value, file, Ctx::Server)
}

fn refuse_json_at(value: &mut serde_json::Value, file: &str, start: Ctx) -> Vec<RefusedKeyReference> {
    fn walk(v: &mut serde_json::Value, path: &str, name: &str, ctx: Ctx, file: &str, out: &mut Vec<RefusedKeyReference>) {
        let selector_ok = ctx != Ctx::ValueMap;
        match v {
            serde_json::Value::String(s) => {
                scrub_str_value(s, path, file, name, selector_ok, out);
            }
            serde_json::Value::Array(items) => {
                let mut keep = Vec::with_capacity(items.len());
                for (i, mut item) in std::mem::take(items).into_iter().enumerate() {
                    let item_path = format!("{path}[{i}]");
                    if let serde_json::Value::String(s) = &mut item
                        && scrub_str_value(s, &item_path, file, name, selector_ok, out)
                    {
                        continue;
                    }
                    if !matches!(item, serde_json::Value::String(_)) {
                        walk(&mut item, &item_path, name, ctx, file, out);
                    }
                    keep.push(item);
                }
                *items = keep;
            }
            serde_json::Value::Object(map) => {
                let mut drop = Vec::new();
                for (k, item) in map.iter_mut() {
                    let child = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
                    let child_ctx = ctx.child(k);
                    if let serde_json::Value::String(s) = item {
                        if scrub_str_value(s, &child, file, k, ctx != Ctx::ValueMap, out) {
                            drop.push(k.clone());
                        }
                    } else {
                        walk(item, &child, k, child_ctx, file, out);
                    }
                }
                for k in drop {
                    map.remove(&k);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    walk(value, "", "", start, file, &mut out);
    out
}

/// How many times a value is expanded when asking whether it can BECOME a reference: the config loader expands once when
/// it reads a file, and the shell expands again when it materializes the server, so `Bearer $${P:-$}{FUIGO_API_KEY}` is
/// a reference only after the second pass.
const COMPOSE_PASSES: usize = 8;

/// Refuse, in ONE server's definition (JSON), every string that only BECOMES a reference to the saved key once the config
/// loader expands it (any number of times: `$${P:-$}{FUIGO_API_KEY}`, `${D:-$}FUIGO_API_KEY`), and every selector
/// field (a `bearer_token_env_var`, ...) whose expansion is the key's name. `expand` is the loader's expander. The string
/// is emptied (never replaced by its expansion, which would bake the process environment into the value).
///
/// For a definition that will be WRITTEN to the trusted user config (P133 `mcp/upsert`): the user config is loaded with
/// expansion and may name the key, so a value that composes a reference there would be bound the saved key. Entries of a
/// server's `env` or `headers` table are values, never selectors, whatever they are called.
pub fn refuse_composed_key_references_in_server_json(
    value: &mut serde_json::Value,
    file: &str,
    expand: &dyn Fn(&str) -> String,
) -> Vec<RefusedKeyReference> {
    fn composes(text: &str, expand: &dyn Fn(&str) -> String, selector: bool) -> bool {
        let mut current = text.to_owned();
        for _ in 0..COMPOSE_PASSES {
            current = expand(&current);
            if refuse_key_references_in_str(&current).is_some() || (selector && is_key_name(current.trim())) {
                return true;
            }
        }
        false
    }
    fn walk(
        v: &mut serde_json::Value,
        path: &str,
        name: &str,
        ctx: Ctx,
        file: &str,
        expand: &dyn Fn(&str) -> String,
        out: &mut Vec<RefusedKeyReference>,
    ) -> bool {
        match v {
            serde_json::Value::String(s) => {
                let selector = ctx != Ctx::ValueMap && is_name_key(name);
                if composes(s, expand, selector) {
                    out.push(RefusedKeyReference { file: file.to_owned(), key: path.to_owned() });
                    if selector {
                        return true;
                    }
                    s.clear();
                }
                false
            }
            serde_json::Value::Array(items) => {
                let mut keep = Vec::with_capacity(items.len());
                for (i, mut item) in std::mem::take(items).into_iter().enumerate() {
                    if !walk(&mut item, &format!("{path}[{i}]"), name, ctx, file, expand, out) {
                        keep.push(item);
                    }
                }
                *items = keep;
                false
            }
            serde_json::Value::Object(map) => {
                let mut drop = Vec::new();
                for (k, item) in map.iter_mut() {
                    let child = if path.is_empty() { k.clone() } else { format!("{path}.{k}") };
                    if walk(item, &child, k, ctx.child(k), file, expand, out) {
                        drop.push(k.clone());
                    }
                }
                for k in drop {
                    map.remove(&k);
                }
                false
            }
            _ => false,
        }
    }
    let mut out = Vec::new();
    walk(value, "", "", Ctx::Server, file, expand, &mut out);
    out
}

/// `server` (any ACP-shaped MCP server value: args, env and headers as lists of strings or name/value pairs) with every
/// reference to the saved key removed, a note recorded. `origin` says where it came from (`label` is
/// "MCP server `name` <origin>"). `None` (drop the server) when the cleaned value cannot be rebuilt: fail closed.
pub fn refuse_key_references_in_server_value<T>(server: T, origin: &str) -> Option<T>
where
    T: serde::Serialize + serde::de::DeserializeOwned,
{
    let mut json = serde_json::to_value(&server).ok()?;
    let name = json.get("name").and_then(|n| n.as_str()).unwrap_or("?").to_owned();
    let label = format!("MCP server `{name}` {origin}");
    let mut refused = refuse_key_references_in_server_json(&mut json, &label);
    // P138 b-1: and the key's VALUE, as the config final gate does. A client that holds the key (the pager with it
    // exported expands `Bearer ${FUIGO_API_KEY}` before forwarding) hands over text, not a reference. Compared in
    // memory, never logged: a refusal records the path of the string, not its content.
    refused.extend(refuse_key_values_in_server_json(&mut json, &label));
    if refused.is_empty() {
        return Some(server);
    }
    report_refusals(&refused);
    serde_json::from_value(json).ok()
}

static NOTES: Mutex<Vec<String>> = Mutex::new(Vec::new());

/// Who a refusal belongs to (P136, Astra r3 #4): the session (or connection) whose config load produced it. A session
/// takes a scope before it loads, runs its setup inside it ([`NoticeScope::run`], [`NoticeScope::scoped`], and its
/// session thread through [`NoticeScope::enter`]), and is told exactly the refusals recorded inside it
/// ([`NoticeScope::notes`]). The tag is set when the refusal is recorded, never guessed afterwards from the file's path,
/// so another session's refusals never reach this one; and a shared file every session loads (the user config, a
/// `FUIGO_CONFIG_PATH` file) is recorded, and announced, in each.
///
/// Each scope keeps its own notes (P136 Astra r1 #5), so another session's refusals cannot push them out: a scope holds
/// at most [`MAX_NOTES_PER_SCOPE`] distinct notes (more are counted and summed up in one last note), and at most
/// [`MAX_OPEN_SCOPES`] scopes are open at once (opening one more closes the oldest).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NoticeScope(u64);

static NEXT_SCOPE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

thread_local! {
    /// The scopes entered on this thread, innermost last. A refusal belongs to the innermost.
    static SCOPES: std::cell::RefCell<Vec<u64>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// The distinct notes one scope keeps.
pub const MAX_NOTES_PER_SCOPE: usize = 64;
/// How many scopes may be open (created, not yet collected) at once.
pub const MAX_OPEN_SCOPES: usize = 256;

/// One open scope's notes.
struct ScopeNotes {
    id: u64,
    notes: Vec<String>,
    /// Distinct notes past [`MAX_NOTES_PER_SCOPE`], counted only.
    more: usize,
}

/// The open scopes, oldest first.
static OPEN: Mutex<Vec<ScopeNotes>> = Mutex::new(Vec::new());

/// Leaves the scope it entered when dropped (see [`NoticeScope::enter`]).
#[must_use = "the scope is left when the guard is dropped"]
pub struct NoticeScopeGuard(u64);

impl Drop for NoticeScopeGuard {
    fn drop(&mut self) {
        SCOPES.with(|s| {
            let mut s = s.borrow_mut();
            if let Some(at) = s.iter().rposition(|id| *id == self.0) {
                s.remove(at);
            }
        });
    }
}

impl NoticeScope {
    /// A new, open scope no refusal belongs to yet.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let id = NEXT_SCOPE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut open = OPEN.lock().unwrap_or_else(|e| e.into_inner());
        if open.len() >= MAX_OPEN_SCOPES {
            open.remove(0);
        }
        open.push(ScopeNotes { id, notes: Vec::new(), more: 0 });
        Self(id)
    }

    /// The innermost scope entered on this thread, if any: for work a setup hands to a thread of its own (the session
    /// thread), which enters it there.
    pub fn current() -> Option<NoticeScope> {
        SCOPES.with(|s| s.borrow().last().copied()).map(NoticeScope)
    }

    /// Enter this scope on this thread until the guard is dropped.
    pub fn enter(self) -> NoticeScopeGuard {
        SCOPES.with(|s| s.borrow_mut().push(self.0));
        NoticeScopeGuard(self.0)
    }

    /// Run `f` with every refusal it records (on this thread) belonging to this scope.
    pub fn run<R>(self, f: impl FnOnce() -> R) -> R {
        let _entered = self.enter();
        f()
    }

    /// `fut` with every refusal recorded while it is polled belonging to this scope. Work it hands to another task or
    /// thread is outside the scope unless that work enters it ([`NoticeScope::current`], [`NoticeScope::enter`]).
    pub fn scoped<F: std::future::Future>(self, fut: F) -> InNoticeScope<F> {
        InNoticeScope { scope: self, inner: Box::pin(fut) }
    }

    /// A guard that closes this scope when dropped, whether or not its notes were collected before (collecting is
    /// idempotent): for a setup that can fail, or be dropped, before it announces.
    pub fn close_on_drop(self) -> NoticeScopeCloser {
        NoticeScopeCloser(self)
    }

    /// Collect this scope's notes (each once, in order) and close it: refusals recorded in it afterwards are only logged.
    pub fn notes(self) -> Vec<String> {
        let mut open = OPEN.lock().unwrap_or_else(|e| e.into_inner());
        let Some(at) = open.iter().position(|s| s.id == self.0) else {
            return Vec::new();
        };
        let ScopeNotes { mut notes, more, .. } = open.remove(at);
        if more > 0 {
            notes.push(format!(
                "{more} more references to {FIRST_PARTY_KEY_ENV_VAR}, the saved API key, were refused and removed; the log lists them."
            ));
        }
        notes
    }
}

/// Closes its scope when dropped (see [`NoticeScope::close_on_drop`]).
#[must_use = "the scope is closed when the guard is dropped"]
pub struct NoticeScopeCloser(NoticeScope);

impl Drop for NoticeScopeCloser {
    fn drop(&mut self) {
        let _ = self.0.notes();
    }
}

/// A future polled inside a [`NoticeScope`] (see [`NoticeScope::scoped`]).
pub struct InNoticeScope<F> {
    scope: NoticeScope,
    inner: std::pin::Pin<Box<F>>,
}

impl<F: std::future::Future> std::future::Future for InNoticeScope<F> {
    type Output = F::Output;

    fn poll(mut self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<F::Output> {
        let _entered = self.scope.enter();
        self.inner.as_mut().poll(cx)
    }
}

/// Log each refusal and keep its note (once) for [`refusal_notes`]; it belongs to the current [`NoticeScope`], if any
/// is entered and still open.
pub fn report_refusals(refusals: &[RefusedKeyReference]) {
    record_notes(refusals.iter().map(RefusedKeyReference::note));
}

fn record_notes(new_notes: impl Iterator<Item = String>) {
    let scope = NoticeScope::current();
    let mut notes = NOTES.lock().unwrap_or_else(|e| e.into_inner());
    let mut open = OPEN.lock().unwrap_or_else(|e| e.into_inner());
    let mut owner = scope.and_then(|scope| open.iter_mut().find(|s| s.id == scope.0));
    for note in new_notes {
        if let Some(owner) = owner.as_mut()
            && !owner.notes.contains(&note)
        {
            if owner.notes.len() < MAX_NOTES_PER_SCOPE {
                owner.notes.push(note.clone());
            } else {
                owner.more += 1;
            }
        }
        if !notes.contains(&note) {
            tracing::warn!("{note}");
            notes.push(note);
        }
    }
}

/// Every refusal note recorded so far in this process.
pub fn refusal_notes() -> Vec<String> {
    NOTES.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

impl RefusedKeyReference {
    /// The note for a reference in a server added through `/mcps` or another ACP client's `mcp/upsert` (P152). Such a
    /// server is saved to `$FUIGO_HOME/config.toml` marked as from an untrusted source, so the generic remedy ("move
    /// this entry into config.toml") would send the user in a circle: say what was done and what actually works.
    /// Never holds a value.
    pub fn note_for_added_server(&self) -> String {
        format!(
            "{file}, added through /mcps or an editor: `{key}` names {name}, the saved API key, which a server added \
             this way may not use, so the reference was removed. A server added this way is saved to \
             $FUIGO_HOME/config.toml (usually ~/.fuigo/config.toml) marked `__fuigo_untrusted_source = true`; to give it the \
             key, edit that entry yourself: put the reference back and delete the `__fuigo_untrusted_source` line. Or \
             have it read another environment variable.",
            file = self.file,
            key = self.key,
            name = FIRST_PARTY_KEY_ENV_VAR
        )
    }
}

/// [`report_refusals`] for a server added through `/mcps` or an ACP client's `mcp/upsert`: the notes say so and give
/// the remedy that fits that source ([`RefusedKeyReference::note_for_added_server`]).
pub fn report_added_server_refusals(refusals: &[RefusedKeyReference]) {
    record_notes(refusals.iter().map(RefusedKeyReference::note_for_added_server));
}

/// Path helper for callers that label a source by file.
pub fn file_label(path: &Path) -> String {
    PathBuf::from(path).display().to_string()
}

/// The key an untrusted source's MCP server table carries from load to spawn (P118 round 3). It is set by the loader
/// of a source that may not name the saved key, on every server it defines (including those inside its
/// `version_overrides`), and read back by the server config as `untrusted_source`. A server's provenance is therefore a
/// property of its final definition: it travels with the definition through merge, overlay and override, and a
/// definition that is replaced or removed takes its mark with it.
pub const UNTRUSTED_SOURCE_MARKER: &str = "__fuigo_untrusted_source";

fn mark_servers_toml(v: &mut toml::Value) {
    match v {
        toml::Value::Table(t) => {
            for (k, child) in t.iter_mut() {
                if matches!(k.as_str(), "mcp_servers" | "mcpServers")
                    && let toml::Value::Table(servers) = child
                {
                    for (_, server) in servers.iter_mut() {
                        if let toml::Value::Table(server) = server {
                            server.insert(UNTRUSTED_SOURCE_MARKER.to_owned(), toml::Value::Boolean(true));
                        }
                    }
                } else {
                    mark_servers_toml(child);
                }
            }
        }
        toml::Value::Array(a) => a.iter_mut().for_each(mark_servers_toml),
        _ => {}
    }
}

fn mark_servers_json(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(m) => {
            for (k, child) in m.iter_mut() {
                if matches!(k.as_str(), "mcp_servers" | "mcpServers")
                    && let serde_json::Value::Object(servers) = child
                {
                    for server in servers.values_mut() {
                        if let serde_json::Value::Object(server) = server {
                            server.insert(UNTRUSTED_SOURCE_MARKER.to_owned(), serde_json::Value::Bool(true));
                        }
                    }
                } else {
                    mark_servers_json(child);
                }
            }
        }
        serde_json::Value::Array(a) => a.iter_mut().for_each(mark_servers_json),
        _ => {}
    }
}

/// Mark every MCP server a TOML source defines (also inside `version_overrides`) as from an untrusted source.
pub fn mark_untrusted_servers_toml(v: &mut toml::Value) {
    mark_servers_toml(v);
}

/// The whole refusal for a TOML source that may not name the saved key: refuse, and mark its servers.
pub fn refuse_toml_source(v: &mut toml::Value, file: &str) -> Vec<RefusedKeyReference> {
    let refused = refuse_key_references_in_toml(v, file);
    mark_servers_toml(v);
    refused
}

/// The whole refusal for a JSON source that may not name the saved key (a project `.mcp.json`, a plugin manifest):
/// refuse the references and mark its servers. It does NOT expand `$VAR` (an extra pass would change `$$` for text
/// unrelated to the key, Astra r3 N5); the strings the later passes build are refused on each server's final
/// definition, at the point it becomes a spawn (`McpServerConfig::to_acp_mcp_server`).
pub fn refuse_json_source(value: &mut serde_json::Value, file: &str) -> Vec<RefusedKeyReference> {
    let refused = refuse_key_references_in_json(value, file);
    mark_servers_json(value);
    refused
}

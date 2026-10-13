//! `bearer_token_file` for HTTP MCP servers: the bearer token is read from an owner-only file on every request, so a
//! token rotated on disk applies without a reconnect.
//!
//! The setting is honoured only for a definition in the user's own config (the loaders enforce that; see
//! `McpServerConfig::to_acp_mcp_server`). This module enforces what the FILE must be, each time it is read:
//!
//! * the path is absolute or `~/`-relative (no environment expansion, no relative paths);
//! * the final component is opened without following a symlink (`O_NOFOLLOW`);
//! * the opened file is a regular file, owned by the current user, with no group or other permission bits, and at
//!   most [`MAX_TOKEN_FILE_BYTES`] long (all judged on the open descriptor, so there is no check-then-open race);
//! * the content is read with a bound, one trailing newline is dropped, and what is left must be visible ASCII
//!   (no control characters, no whitespace, no non-ASCII).
//!
//! Windows: not supported in this release. A configured `bearer_token_file` refuses the server (fail closed).
//!
//! Nothing here ever puts the token, or any part of the file's content, in an error, a log line or a `Debug` output.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use agent_client_protocol as acp;
use tokio::task::JoinHandle;

/// Tokens are short; anything larger is the wrong file.
pub const MAX_TOKEN_FILE_BYTES: u64 = 16 * 1024;
/// A token shorter than this is refused ("token too short").
pub const MIN_TOKEN_CHARS: usize = 16;
/// Bounds a read from a stalled network filesystem.
const TOKEN_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// The `_meta` key that carries the configured path from config to the MCP client (`acp::McpServerHttp` has no field).
pub const META_KEY: &str = "fuigo/mcp/bearerTokenFile";

/// Why the setting or its file was refused. The text never holds file content.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum BearerTokenFileError {
    #[error("bearer_token_file is not supported on Windows in this release")]
    UnsupportedPlatform,
    #[error("bearer_token_file must be an absolute path or start with ~/")]
    NotAbsolute,
    #[error("bearer_token_file starts with ~/ but the home directory is unknown")]
    NoHomeDir,
    #[error("`_meta[\"{META_KEY}\"]` must be a string")]
    NotAString,
    #[error("bearer_token_file is a symbolic link")]
    Symlink,
    #[error("bearer_token_file is not a regular file")]
    NotRegular,
    #[error("bearer_token_file is not owned by the current user")]
    WrongOwner,
    #[error("bearer_token_file is readable by others (use mode 0600 or 0400)")]
    TooPermissive,
    #[error("bearer_token_file is larger than 16 KiB")]
    TooLarge,
    #[error("bearer_token_file is empty")]
    Empty,
    #[error("token too short")]
    TooShort,
    #[error("bearer_token_file holds a character that cannot be in a bearer token")]
    BadCharacters,
    #[error("bearer_token_file cannot be read")]
    Unreadable,
    #[error("bearer_token_file read timed out")]
    TimedOut,
    #[error("bearer_token_file is only sent over https (or http to this machine)")]
    InsecureUrl,
    #[error("bearer_token_file cannot be combined with another Authorization setting")]
    ConflictsWithAuthorization,
}

/// The configured string as `_meta` for the ACP server entry.
pub fn bearer_token_file_meta(configured: &str) -> acp::Meta {
    acp::Meta::from_iter([(META_KEY.to_owned(), serde_json::Value::String(configured.to_owned()))])
}

/// The configured string from `_meta`: `Ok(None)` when absent.
pub fn configured_from_meta(meta: Option<&acp::Meta>) -> Result<Option<String>, BearerTokenFileError> {
    let Some(value) = meta.and_then(|meta| meta.get(META_KEY)) else {
        return Ok(None);
    };
    value.as_str().map(|s| Some(s.to_owned())).ok_or(BearerTokenFileError::NotAString)
}

/// Remove a `bearer_token_file` from a server definition that came from somewhere other than the user's own config
/// (a client over ACP, a plugin, a managed source), with a visible note. Returns whether one was removed. Without this
/// a definition could name any file of its choosing and have its content sent to a server of its choosing.
pub fn strip_from_server(server: &mut acp::McpServer, origin: &str) -> bool {
    let (name, meta) = match server {
        acp::McpServer::Http(h) => (h.name.clone(), &mut h.meta),
        acp::McpServer::Sse(s) => (s.name.clone(), &mut s.meta),
        _ => return false,
    };
    let Some(map) = meta.as_mut() else { return false };
    if map.remove(META_KEY).is_none() {
        return false;
    }
    if map.is_empty() {
        *meta = None;
    }
    fuigo_config::mcp_bearer_file::record_note(format!(
        "MCP server `{name}`: bearer_token_file ignored: it is honoured only in your own config.toml, not in a definition {origin}"
    ));
    true
}

/// An absolute path to a token file, with a leading `~/` already expanded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BearerTokenPath(PathBuf);

impl BearerTokenPath {
    /// Parse the configured string. Only a leading `~/` is expanded; nothing else is interpreted.
    pub fn parse(configured: &str, home: Option<&Path>) -> Result<Self, BearerTokenFileError> {
        if !cfg!(unix) {
            return Err(BearerTokenFileError::UnsupportedPlatform);
        }
        let path = match configured.strip_prefix("~/") {
            Some(rest) if !rest.is_empty() => {
                home.ok_or(BearerTokenFileError::NoHomeDir)?.join(rest)
            }
            _ => PathBuf::from(configured),
        };
        if !path.is_absolute() {
            return Err(BearerTokenFileError::NotAbsolute);
        }
        Ok(Self(path))
    }
}

impl AsRef<Path> for BearerTokenPath {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl std::fmt::Display for BearerTokenPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.display().fmt(f)
    }
}

type StalledRead = Arc<parking_lot::Mutex<Option<JoinHandle<Result<String, BearerTokenFileError>>>>>;

/// Clones share the stalled-read slot, and one value lives for a client's lifetime (reconnects included), so a hung
/// mount pins at most one blocking-pool thread per server. The token is never stored here: every request reads again.
#[derive(Clone)]
pub struct BearerTokenFile {
    path: Arc<BearerTokenPath>,
    read_timeout: Duration,
    /// A read that outlived `read_timeout`. Tokio cannot cancel a blocking read, so later reads fail fast until it
    /// returns.
    stalled_read: StalledRead,
}

impl std::fmt::Debug for BearerTokenFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BearerTokenFile").field("path", &self.path.to_string()).finish_non_exhaustive()
    }
}

impl BearerTokenFile {
    pub fn new(path: BearerTokenPath) -> Self {
        Self { path: Arc::new(path), read_timeout: TOKEN_READ_TIMEOUT, stalled_read: Arc::default() }
    }

    #[cfg(all(test, unix))]
    fn with_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = timeout;
        self
    }

    /// Read and check the file now. The returned token is recorded with the sent-credential scrubber, so an upstream
    /// that echoes it back has it replaced at the display and log sinks.
    ///
    /// # Errors
    ///
    /// The generic [`BearerTokenFileError`] for whichever check failed. Nothing is cached: a file that disappears or
    /// fails a check fails this request.
    pub async fn read(&self) -> Result<String, BearerTokenFileError> {
        if self.stalled_read.lock().as_ref().is_some_and(|read| !read.is_finished()) {
            return Err(BearerTokenFileError::TimedOut);
        }
        let mut read = tokio::task::spawn_blocking({
            let path = Arc::clone(&self.path);
            move || read_token_sync(path.as_ref().as_ref())
        });
        let token = match tokio::time::timeout(self.read_timeout, &mut read).await {
            Ok(joined) => joined.map_err(|_| BearerTokenFileError::Unreadable)??,
            Err(_) => {
                *self.stalled_read.lock() = Some(read);
                return Err(BearerTokenFileError::TimedOut);
            }
        };
        fuigo_telemetry::sent_credentials::record(&token);
        Ok(token)
    }
}

/// The file's content as a token, after every check. Blocking.
pub fn read_token_sync(path: &Path) -> Result<String, BearerTokenFileError> {
    let bytes = read_checked_bytes(path)?;
    token_from_bytes(bytes)
}

fn token_from_bytes(bytes: Vec<u8>) -> Result<String, BearerTokenFileError> {
    let mut bytes = bytes;
    // Drop ONE trailing newline (`\n` or `\r\n`), as `echo token > file` leaves.
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.is_empty() {
        return Err(BearerTokenFileError::Empty);
    }
    // Visible ASCII only: no control characters, no whitespace anywhere, nothing that is not a header-safe byte.
    if !bytes.iter().all(u8::is_ascii_graphic) {
        return Err(BearerTokenFileError::BadCharacters);
    }
    // Every accepted token must be one the sent-credential scrubber registers (it ignores anything shorter than 8
    // characters); 16 is the floor so no accepted token can escape redaction.
    if bytes.len() < MIN_TOKEN_CHARS {
        return Err(BearerTokenFileError::TooShort);
    }
    String::from_utf8(bytes).map_err(|_| BearerTokenFileError::BadCharacters)
}

#[cfg(unix)]
fn read_checked_bytes(path: &Path) -> Result<Vec<u8>, BearerTokenFileError> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let file = std::fs::OpenOptions::new()
        .read(true)
        // Never follow a symlink in the final component; never block opening a FIFO or device.
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| match error.raw_os_error() {
            Some(libc::ELOOP) => BearerTokenFileError::Symlink,
            _ => BearerTokenFileError::Unreadable,
        })?;
    // Every check is on the open descriptor, so the file judged is the file read.
    let meta = file.metadata().map_err(|_| BearerTokenFileError::Unreadable)?;
    if !meta.file_type().is_file() {
        return Err(BearerTokenFileError::NotRegular);
    }
    // SAFETY: `geteuid` has no preconditions and cannot fail.
    if meta.uid() != unsafe { libc::geteuid() } {
        return Err(BearerTokenFileError::WrongOwner);
    }
    if meta.mode() & 0o077 != 0 {
        return Err(BearerTokenFileError::TooPermissive);
    }
    if meta.len() > MAX_TOKEN_FILE_BYTES {
        return Err(BearerTokenFileError::TooLarge);
    }
    let mut contents = Vec::new();
    file.take(MAX_TOKEN_FILE_BYTES + 1)
        .read_to_end(&mut contents)
        .map_err(|_| BearerTokenFileError::Unreadable)?;
    if u64::try_from(contents.len()).unwrap_or(u64::MAX) > MAX_TOKEN_FILE_BYTES {
        return Err(BearerTokenFileError::TooLarge);
    }
    Ok(contents)
}

#[cfg(not(unix))]
fn read_checked_bytes(_path: &Path) -> Result<Vec<u8>, BearerTokenFileError> {
    Err(BearerTokenFileError::UnsupportedPlatform)
}

/// The token may travel only over `https`, or plain `http` to a loopback IP LITERAL (`127.0.0.0/8`, `::1`). The name
/// `localhost` is not accepted for a token (a hosts file or resolver can point it elsewhere); use `127.0.0.1` or https.
/// (`servers::is_loopback_http_url` accepts the name for other purposes; the token check does not use it.)
pub fn check_url_may_carry_token(url: &str) -> Result<(), BearerTokenFileError> {
    let Ok(parsed) = url::Url::parse(url) else {
        return Err(BearerTokenFileError::InsecureUrl);
    };
    let loopback_literal = parsed.scheme() == "http"
        && match parsed.host() {
            Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
            Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
            _ => false,
        };
    if parsed.scheme() == "https" || loopback_literal {
        Ok(())
    } else {
        Err(BearerTokenFileError::InsecureUrl)
    }
}

#[cfg(all(test, unix))]
#[path = "bearer_token_file_tests.rs"]
mod tests;

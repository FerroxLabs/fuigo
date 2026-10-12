//! Locator rows and the pure path, directory and reaping rules (S3.5, S3.6; packet 8a). No IO.
//!
//! A row holds a host id, a pid, a start time and a two-value directory tag, never a path. The socket path
//! is built only by [`socket_path`] from a directory the caller already checked plus the host id.
//!
//! `pid` and `started` are DISPLAY ONLY. No decision (reaping, routing, trust) may use them: pids are
//! reused (S3.6) and either value is a claim by whoever wrote the file.

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::limits::{LIST_PAGE_ROWS, MAX_FRAME_BYTES};
use crate::wire::HostId;

/// Bytes of a locator file we will look at (S3.4).
pub const MAX_ROWS_BYTES: usize = MAX_FRAME_BYTES;
/// Rows in a locator file (S3.4).
pub const MAX_ROWS: usize = LIST_PAGE_ROWS;

/// Longest unix socket path we build, in bytes without the NUL. `sun_path` is 108 bytes on Linux and 104 on
/// macOS, both counting the NUL; we use the smaller: 104 - 1 = 103.
pub const SOCKET_PATH_MAX: usize = 103;
/// `/peers/` + 32 hex + `.sock`, appended to the fuigo home.
pub const HOME_SUFFIX_LEN: usize = "/peers/".len() + 32 + ".sock".len();
/// `/fuigo/peers/` + 32 hex + `.sock`, appended to `$XDG_RUNTIME_DIR`.
pub const RUNTIME_SUFFIX_LEN: usize = "/fuigo/peers/".len() + 32 + ".sock".len();

/// Which directory holds the socket. Two values, never a path (S3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostDir {
    Home,
    Runtime,
}

/// One locator row. There is no path field, and unknown fields are refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRow {
    pub host_id: HostId,
    /// Display only. No decision may use it.
    pub pid: u32,
    /// Unix seconds. Display only. No decision may use it.
    pub started: u64,
    pub dir: HostDir,
}

/// Why a locator file was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RowsError {
    TooLarge,
    TooManyRows,
    DuplicateHost,
    Malformed,
}

impl fmt::Display for RowsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::TooLarge => "locator file is over 64 KiB",
            Self::TooManyRows => "locator file has more than 64 rows",
            Self::DuplicateHost => "locator file repeats a host id",
            Self::Malformed => "locator file is not a list of host rows",
        })
    }
}

impl std::error::Error for RowsError {}

/// Parse a locator file: a JSON array of `{host_id, pid, started, dir}` objects in any key order, with
/// whitespace allowed. The size cap is checked before anything is read, the row cap before the 65th row is
/// stored, so memory is bounded by the cap. Unknown or repeated keys, escapes in strings, duplicate host ids
/// and trailing bytes are refused. (Hand-written because this crate carries no JSON dependency; the grammar
/// is exactly what `serde_json` writes for [`HostRow`].)
pub fn parse_rows(bytes: &[u8]) -> Result<Vec<HostRow>, RowsError> {
    if bytes.len() > MAX_ROWS_BYTES {
        return Err(RowsError::TooLarge);
    }
    let mut p = Cursor { b: bytes, i: 0 };
    let mut rows: Vec<HostRow> = Vec::new();
    let mut seen: HashSet<HostId> = HashSet::new();
    p.ws();
    p.expect(b'[')?;
    p.ws();
    if p.peek() == Some(b']') {
        p.i += 1;
    } else {
        loop {
            if rows.len() >= MAX_ROWS {
                return Err(RowsError::TooManyRows);
            }
            let row = p.row()?;
            if !seen.insert(row.host_id.clone()) {
                return Err(RowsError::DuplicateHost);
            }
            rows.push(row);
            p.ws();
            match p.next() {
                Some(b',') => p.ws(),
                Some(b']') => break,
                _ => return Err(RowsError::Malformed),
            }
        }
    }
    p.ws();
    if p.i != bytes.len() {
        return Err(RowsError::Malformed);
    }
    Ok(rows)
}

struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}

impl Cursor<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let c = self.peek()?;
        self.i += 1;
        Some(c)
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn expect(&mut self, c: u8) -> Result<(), RowsError> {
        if self.next() == Some(c) { Ok(()) } else { Err(RowsError::Malformed) }
    }

    /// A string with no escapes and no control characters, returned as a borrowed slice.
    fn string(&mut self) -> Result<&[u8], RowsError> {
        self.expect(b'"')?;
        let start = self.i;
        while let Some(c) = self.next() {
            match c {
                b'"' => return Ok(&self.b[start..self.i - 1]),
                b'\\' | 0..=0x1f => return Err(RowsError::Malformed),
                _ => {}
            }
        }
        Err(RowsError::Malformed)
    }

    fn number(&mut self) -> Result<u64, RowsError> {
        let start = self.i;
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        let digits = &self.b[start..self.i];
        // No empty number and no leading zero (JSON), at most 20 digits.
        if digits.is_empty() || digits.len() > 20 || (digits.len() > 1 && digits[0] == b'0') {
            return Err(RowsError::Malformed);
        }
        let mut n: u64 = 0;
        for d in digits {
            n = n.checked_mul(10).and_then(|n| n.checked_add(u64::from(d - b'0'))).ok_or(RowsError::Malformed)?;
        }
        Ok(n)
    }

    fn row(&mut self) -> Result<HostRow, RowsError> {
        self.expect(b'{')?;
        let (mut host, mut pid, mut started, mut dir) = (None, None, None, None);
        loop {
            self.ws();
            let key = self.string()?.to_vec();
            self.ws();
            self.expect(b':')?;
            self.ws();
            match key.as_slice() {
                b"host_id" if host.is_none() => {
                    let s = std::str::from_utf8(self.string()?).map_err(|_| RowsError::Malformed)?;
                    host = Some(HostId::new(s).map_err(|_| RowsError::Malformed)?);
                }
                b"pid" if pid.is_none() => {
                    pid = Some(u32::try_from(self.number()?).map_err(|_| RowsError::Malformed)?);
                }
                b"started" if started.is_none() => started = Some(self.number()?),
                b"dir" if dir.is_none() => {
                    dir = Some(match self.string()? {
                        b"home" => HostDir::Home,
                        b"runtime" => HostDir::Runtime,
                        _ => return Err(RowsError::Malformed),
                    });
                }
                _ => return Err(RowsError::Malformed),
            }
            self.ws();
            match self.next() {
                Some(b',') => {}
                Some(b'}') => break,
                _ => return Err(RowsError::Malformed),
            }
        }
        match (host, pid, started, dir) {
            (Some(host_id), Some(pid), Some(started), Some(dir)) => Ok(HostRow { host_id, pid, started, dir }),
            _ => Err(RowsError::Malformed),
        }
    }
}

/// The only way a socket path is built: a directory the caller has already checked (S3.3) plus
/// `<host_id>.sock`. A [`HostId`] holds only `[0-9a-f]`, so the result is always a direct child of `dir`.
pub fn socket_path(dir: &Path, host_id: &HostId) -> PathBuf {
    dir.join(format!("{}.sock", host_id.as_str()))
}

/// Where sockets go, chosen by the same rule on both sides (S3.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirChoice {
    /// `<fuigo home>/peers`.
    Home,
    /// `$XDG_RUNTIME_DIR/fuigo/peers`.
    Runtime,
    /// Neither path fits (or there is no runtime directory): peer messaging is off with a visible reason.
    Unavailable(DirUnavailable),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirUnavailable {
    /// The home path is too long and there is no runtime directory.
    NoRuntimeDir,
    /// The home path is too long and the runtime path is too.
    RuntimeTooLong,
}

/// `home_len` is the byte length of the fuigo home path; `runtime_len` the byte length of
/// `$XDG_RUNTIME_DIR`, or `None` when unset. Home is chosen when `<home>/peers/<id>.sock` fits in
/// [`SOCKET_PATH_MAX`] (103: macOS's 104 minus the NUL, smaller than Linux's 108); else Runtime if
/// `<runtime>/fuigo/peers/<id>.sock` fits; else unavailable.
pub fn choose_dir(home_len: usize, runtime_len: Option<usize>) -> DirChoice {
    if home_len.saturating_add(HOME_SUFFIX_LEN) <= SOCKET_PATH_MAX {
        return DirChoice::Home;
    }
    match runtime_len {
        None => DirChoice::Unavailable(DirUnavailable::NoRuntimeDir),
        Some(n) if n.saturating_add(RUNTIME_SUFFIX_LEN) <= SOCKET_PATH_MAX => DirChoice::Runtime,
        Some(_) => DirChoice::Unavailable(DirUnavailable::RuntimeTooLong),
    }
}

/// The result of one connect-and-hello attempt against a row's socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TryResult {
    /// The connection was refused (a socket file with no listener).
    Refused,
    /// The socket file does not exist.
    NoSuchFile,
    /// Connect, write or read ran out of time. Never evidence of death.
    Timeout,
    /// The peer's hello carried another protocol version. Never evidence of death.
    VersionMismatch,
    /// The peer answered a valid hello announcing this host id.
    Hello(HostId),
    /// Anything else (permission, reset, bad frame): no evidence.
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reap {
    /// Remove the row, and only if it is unchanged under the lock (S3.6).
    Reap,
    Keep,
}

/// S3.6 as a pure table over two tries one second apart. `expected` is the host id the row names, `dir` its
/// directory tag. The pid is not a parameter and is never consulted.
///
/// | first | second | `Home` row | `Runtime` row |
/// |---|---|---|---|
/// | any `Timeout` / `VersionMismatch` / `Other` | any | Keep | Keep |
/// | `Hello(expected)` | any | Keep | Keep |
/// | `Refused` | `Refused` | Reap | Reap |
/// | `NoSuchFile` or `Refused` | `NoSuchFile` or `Refused` (not both `Refused`) | Reap | Keep, or Reap when `same_runtime_dir` |
/// | `Hello(x != expected)` | `Hello(x)` (same `x`) | Reap | Reap |
/// | anything else | | Keep | Keep |
///
/// "No such file" does not reap a `Runtime` row by default because a runtime directory can vanish with a logout
/// without the host being gone; only a refused connect proves the file is there and nobody listens. The exception:
/// `same_runtime_dir` is true when the caller opened (with the S3.3 checks) the very runtime peers directory this
/// home's runtime rows use, so an absent socket there is an absent socket in the host's own directory: a reboot
/// wiped it and the host is gone. A caller whose runtime directory differs or cannot be opened passes `false`.
pub fn reap_decision(
    dir: HostDir,
    expected: &HostId,
    first: &TryResult,
    second: &TryResult,
    same_runtime_dir: bool,
) -> Reap {
    use TryResult::*;
    match (first, second) {
        (Refused, Refused) => Reap::Reap,
        (Refused | NoSuchFile, Refused | NoSuchFile) if dir == HostDir::Home || same_runtime_dir => Reap::Reap,
        (Hello(a), Hello(b)) if a == b && a != expected => Reap::Reap,
        _ => Reap::Keep,
    }
}

/// FNV-1a 64 as 16 lower-case hex. Stable across Rust versions (unlike `DefaultHasher`).
fn hash16(bytes: &[u8]) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{h:016x}")
}

/// `<runtime>/fuigo/<16 hex of a hash of the home path>`: the directory that plays the part of the Fuigo home for the
/// runtime socket layout (S3.5). Pure: nothing is touched. The inbox, the dialer and the permission guard all use it.
pub fn runtime_home_dir(runtime: &Path, home: &Path) -> PathBuf {
    #[cfg(unix)]
    let key = {
        use std::os::unix::ffi::OsStrExt;
        hash16(home.as_os_str().as_bytes())
    };
    #[cfg(not(unix))]
    let key = hash16(home.to_string_lossy().as_bytes());
    runtime.join("fuigo").join(key)
}

/// `<runtime>/fuigo/<hash>/peers`: where runtime sockets and nothing else live for `home`.
pub fn runtime_peers_dir(runtime: &Path, home: &Path) -> PathBuf {
    runtime_home_dir(runtime, home).join("peers")
}

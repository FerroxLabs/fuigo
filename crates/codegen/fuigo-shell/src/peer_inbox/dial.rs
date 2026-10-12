//! The dialer and the path rules both ends share (packet 8d; DESIGN S3.1, S3.5).
//!
//! A socket path is built ONLY by [`fuigo_peer::socket_path`] from a directory this process derived itself and a
//! checked [`HostId`]; nothing a peer or a model supplies is ever a path. After the connect and BEFORE the first
//! write the dialer compares the server's uid with ours (`verdict_for`), so a server of another account reached
//! through a planted `<id>.sock` gets no byte from us.
// Inert until packet 8e; only the tests dial.
#![cfg_attr(not(test), allow(dead_code))]

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use fuigo_peer::{
    Hello, HostDir, HostId, Op, Reply, TryResult, choose_dir, socket_path,
};
use fuigo_peer::DirChoice;
use tokio::net::UnixStream;

use super::conn::{self, ConnError};
use crate::leader::peer_check::{PeerVerdict, Side, verdict_for};

/// Longest a connect may take (S3.2).
pub(crate) const CONNECT_DEADLINE: Duration = Duration::from_secs(2);
/// Extra bytes the runtime layout `<xdg>/fuigo/<16 hex>/peers/<id>.sock` has over the `fuigo-peer` constant
/// (`<xdg>/fuigo/peers/<id>.sock`): `"<16 hex>/"` is 17 bytes. Added to the runtime length before `choose_dir`.
const RUNTIME_EXTRA: usize = 17;

/// Where the peers directories are, derived the same way by the inbox and by the dialer from the Fuigo home and
/// `$XDG_RUNTIME_DIR` (S3.5). Holds paths only; nothing is touched.
#[derive(Debug, Clone)]
pub(crate) struct Locations {
    home: PathBuf,
    runtime: Option<PathBuf>,
}

impl Locations {
    pub(crate) fn new(home: &Path, runtime: Option<&Path>) -> Self {
        Self { home: home.to_path_buf(), runtime: runtime.filter(|p| p.is_absolute()).map(Path::to_path_buf) }
    }

    /// From the process environment (`XDG_RUNTIME_DIR`).
    pub(crate) fn from_env(home: &Path) -> Self {
        let rt = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
        Self::new(home, rt.as_deref())
    }

    pub(crate) fn home(&self) -> &Path {
        &self.home
    }

    /// `<xdg>/fuigo/<16 hex of a hash of the home path>`: it plays the part of the "home" for the runtime layout
    /// (so the S3.3 checks apply to it unchanged), and a different Fuigo home gets a different directory.
    pub(crate) fn runtime_home(&self) -> Option<PathBuf> {
        let rt = self.runtime.as_ref()?;
        Some(fuigo_peer::runtime_home_dir(rt, &self.home))
    }

    pub(crate) fn runtime_base(&self) -> Option<&Path> {
        self.runtime.as_deref()
    }

    /// The directory that holds sockets for `dir`.
    pub(crate) fn peers_path(&self, dir: HostDir) -> Option<PathBuf> {
        match dir {
            HostDir::Home => Some(self.home.join("peers")),
            HostDir::Runtime => self.runtime_home().map(|r| r.join("peers")),
        }
    }

    /// The S3.5 rule, applied identically by both ends.
    pub(crate) fn choose(&self) -> DirChoice {
        choose_dir(
            self.home.as_os_str().len(),
            self.runtime.as_ref().map(|r| r.as_os_str().len().saturating_add(RUNTIME_EXTRA)),
        )
    }

    /// `<peers dir>/<host-id>.sock` for a row's `dir` tag.
    pub(crate) fn socket(&self, host: &HostId, dir: HostDir) -> Option<PathBuf> {
        self.peers_path(dir).map(|d| socket_path(&d, host))
    }
}

/// Why a dial failed. No variant carries text from the peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DialError {
    /// The row's directory cannot be derived (a `runtime` row and no `XDG_RUNTIME_DIR`).
    NoDirectory,
    /// Connect, write or read ran out of time.
    Timeout,
    /// A socket file exists and nobody listens.
    Refused,
    /// There is no socket file.
    NoSuchFile,
    /// The server is a process of another account; nothing was written to it.
    WrongUser,
    /// The server announced another host id than the row names.
    ForeignHello,
    /// The server speaks another protocol version.
    VersionMismatch,
    /// Anything else.
    Other,
}

impl DialError {
    /// Map onto the reap table (S3.6). Lossy for [`DialError::ForeignHello`]: the reaper uses [`try_hello`], which
    /// keeps the announced id.
    pub(crate) fn try_result(&self) -> TryResult {
        match self {
            Self::Timeout => TryResult::Timeout,
            Self::Refused => TryResult::Refused,
            Self::NoSuchFile => TryResult::NoSuchFile,
            Self::VersionMismatch => TryResult::VersionMismatch,
            Self::NoDirectory | Self::WrongUser | Self::ForeignHello | Self::Other => TryResult::Other,
        }
    }
}

impl From<ConnError> for DialError {
    fn from(e: ConnError) -> Self {
        match e {
            ConnError::WriteTimeout | ConnError::ExchangeTimeout => Self::Timeout,
            ConnError::VersionMismatch => Self::VersionMismatch,
            ConnError::HostMismatch => Self::ForeignHello,
            _ => Self::Other,
        }
    }
}

fn from_io(e: &io::Error) -> DialError {
    match e.kind() {
        io::ErrorKind::NotFound => DialError::NoSuchFile,
        io::ErrorKind::ConnectionRefused => DialError::Refused,
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => DialError::Timeout,
        _ => DialError::Other,
    }
}

/// Connect (2 s) and refuse a server of another account before anything is written.
async fn connect_checked(path: &Path) -> Result<UnixStream, DialError> {
    let stream = match tokio::time::timeout(CONNECT_DEADLINE, UnixStream::connect(path)).await {
        Err(_) => return Err(DialError::Timeout),
        Ok(Err(e)) => return Err(from_io(&e)),
        Ok(Ok(s)) => s,
    };
    if verdict_for(Side::Client, &stream, path) != PeerVerdict::Accept {
        return Err(DialError::WrongUser);
    }
    Ok(stream)
}

/// One operation against the host `host_id` whose row says `dir`: connect, uid check, hello (the server must
/// announce `host_id`), the operation, one reply.
pub(crate) async fn dial(
    loc: &Locations,
    our: &HostId,
    host_id: &HostId,
    dir: HostDir,
    op: Op,
) -> Result<Reply, DialError> {
    let path = loc.socket(host_id, dir).ok_or(DialError::NoDirectory)?;
    let stream = connect_checked(&path).await?;
    Ok(conn::exchange(stream, Hello::new(our.clone()), host_id, op).await?)
}

/// One reaping try: connect, uid check, hello each way, close. Keeps the announced host id (S3.6).
pub(crate) async fn try_hello(loc: &Locations, our: &HostId, host_id: &HostId, dir: HostDir) -> TryResult {
    let Some(path) = loc.socket(host_id, dir) else {
        return TryResult::Other;
    };
    let stream = match connect_checked(&path).await {
        Ok(s) => s,
        Err(e) => return e.try_result(),
    };
    match conn::probe(stream, Hello::new(our.clone())).await {
        Ok(h) if !h.version_matches() => TryResult::VersionMismatch,
        Ok(h) => TryResult::Hello(h.host_id),
        Err(ConnError::WriteTimeout | ConnError::ExchangeTimeout) => TryResult::Timeout,
        Err(_) => TryResult::Other,
    }
}

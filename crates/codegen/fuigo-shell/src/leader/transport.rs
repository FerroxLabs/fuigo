//! Cross-platform IPC transport between the leader and its clients.
//!
//! - **Unix:** [`LeaderStream`] and [`LeaderListener`] are type aliases for `tokio::net::UnixStream` and `UnixListener`; no wrapper, no unsafe.
//! - **Windows:** wraps `tokio::net::windows::named_pipe::*` (tokio doesn't expose AF_UNIX on Windows).
//!   The leader's filesystem path is hashed into `\\.\pipe\fuigo-leader-<hash>` so callers keep their path-based API.
//!
#[cfg(unix)]
pub(super) use tokio::net::UnixListener as LeaderListener;
#[cfg(unix)]
pub(super) use tokio::net::UnixStream as LeaderStream;

/// Has a leader bound a listener at `path`?
///
/// - Unix: stats the socket file.
/// - Windows: probes the named pipe (Named Pipes don't appear in the filesystem, so `path.exists()` doesn't work).
pub fn listener_is_ready(path: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        path.exists()
    }
    #[cfg(windows)]
    {
        windows_impl::listener_is_ready(path)
    }
}

#[cfg(windows)]
pub(super) use windows_impl::{LeaderListener, LeaderStream};

/// A listening pipe instance that waits for one client: `NamedPipeServer` on Windows, a fake in the tests.
#[cfg(any(windows, test))]
pub(crate) trait PendingInstance {
    /// Wait for a client. Must be cancellation safe: dropping the future loses no connection (tokio documents this
    /// for `NamedPipeServer::connect`; a client that connected meanwhile is reported by the next call).
    fn wait_for_client(&self) -> impl std::future::Future<Output = std::io::Result<()>> + '_;
}

/// Accept one client on the instance held in `slot`, cancellation safe (P145).
///
/// The leader polls `accept()` inside a `select!` with its event channels, so the accept future is dropped whenever an
/// event (a client registering or leaving) wins the race. The old Windows accept TOOK the pending instance out of the
/// slot before awaiting it: a drop destroyed that listening instance, so a client that had just opened it saw its pipe
/// close before it could register ("Protocol error: Connection closed"). This is what made `fuigo leader info` fail on
/// Windows right after the discovery connection it makes first had disconnected. The instance now stays in the slot
/// until a client is connected; only then is it taken and its successor created.
#[cfg(any(windows, test))]
pub(crate) async fn accept_from_slot<S: PendingInstance>(
    slot: &mut Option<S>,
    create: impl Fn() -> std::io::Result<S>,
    max_attempts: usize,
    backoff: std::time::Duration,
) -> std::io::Result<S> {
    let mut last_err: Option<std::io::Error> = None;
    for attempt in 0..max_attempts {
        if slot.is_none() {
            *slot = Some(create()?);
        }
        let result = match slot.as_ref() {
            Some(instance) => instance.wait_for_client().await,
            None => continue,
        };
        match result {
            Ok(()) => {
                let connected = slot.take().ok_or_else(|| std::io::Error::other("pending instance vanished"))?;
                // Best effort: if creating the successor fails here, the next accept creates it.
                *slot = create().ok();
                return Ok(connected);
            }
            Err(e) => {
                // A failed instance is dropped and replaced on the next attempt.
                tracing::debug!(attempt, error = %e, "named-pipe accept connect failed; retrying");
                *slot = None;
                last_err = Some(e);
                tokio::time::sleep(backoff).await;
            }
        }
    }
    if slot.is_none() {
        *slot = create().ok();
    }
    Err(last_err.unwrap_or_else(|| std::io::Error::other("LeaderListener: accept exhausted retries")))
}

#[cfg(windows)]
mod windows_impl {
    use std::io;
    use std::path::Path;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;

    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

    /// Bidirectional IPC stream wrapping a connected named pipe (server- or client-side, depending on how it was created).
    pub(crate) struct LeaderStream {
        inner: StreamInner,
    }

    enum StreamInner {
        Server(tokio::net::windows::named_pipe::NamedPipeServer),
        Client(tokio::net::windows::named_pipe::NamedPipeClient),
    }

    /// The pid of the process that owns the SERVER end of the named pipe `client_end` is connected to, from the OS
    /// (`GetNamedPipeServerProcessId`). Unlike any pid a peer reports in a message, a peer cannot choose this one.
    pub(crate) fn pipe_server_pid_of_handle(client_end: std::os::windows::io::RawHandle) -> Option<u32> {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::Pipes::GetNamedPipeServerProcessId;
        let mut pid: u32 = 0;
        // SAFETY: `client_end` is a live pipe handle owned by the caller for the duration of the call; `pid` is writable.
        unsafe { GetNamedPipeServerProcessId(HANDLE(client_end), &mut pid) }
            .ok()
            .map(|()| pid)
            .filter(|pid| *pid != 0)
    }

    impl LeaderStream {
        /// The OS-reported pid of the server end of the pipe, for a client-side stream (`None` for a server-side stream).
        pub(crate) fn os_server_pid(&self) -> Option<u32> {
            use std::os::windows::io::AsRawHandle;
            match &self.inner {
                StreamInner::Client(c) => pipe_server_pid_of_handle(c.as_raw_handle()),
                StreamInner::Server(_) => None,
            }
        }
        /// The raw handle of a client-side stream (`None` for a server-side stream), for OS queries about the other end.
        pub(crate) fn client_raw_handle(&self) -> Option<std::os::windows::io::RawHandle> {
            use std::os::windows::io::AsRawHandle;
            match &self.inner {
                StreamInner::Client(c) => Some(c.as_raw_handle()),
                StreamInner::Server(_) => None,
            }
        }
        /// The raw handle of a server-side stream (`None` for a client-side stream).
        #[cfg(test)]
        pub(crate) fn server_raw_handle(&self) -> Option<std::os::windows::io::RawHandle> {
            use std::os::windows::io::AsRawHandle;
            match &self.inner {
                StreamInner::Server(s) => Some(s.as_raw_handle()),
                StreamInner::Client(_) => None,
            }
        }
        /// Connect to a listener at `path`.
        /// The path is translated to a named-pipe name and `ClientOptions::open` is used.
        pub(crate) async fn connect<P: AsRef<Path>>(path: P) -> io::Result<Self> {
            use tokio::net::windows::named_pipe::ClientOptions;

            // ClientOptions::open returns ERROR_PIPE_BUSY if all pipe instances are in use
            // The caller's CONNECT_TIMEOUT loop already retries, so return the error and let it handle the retry
            let pipe_name = path_to_pipe_name(path.as_ref());
            let inner = ClientOptions::new().open(pipe_name)?;
            Ok(Self {
                inner: StreamInner::Client(inner),
            })
        }
    }

    // tokio's NamedPipeServer and NamedPipeClient are automatically Unpin (they wrap PollEvented<mio::windows::NamedPipe>, which is Unpin)
    // The wrapping enum and struct are therefore Unpin as well
    // That makes Pin<&mut Self>::get_mut() safe; no unsafe is needed for the structural projection into `inner`
    impl AsyncRead for LeaderStream {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match &mut self.get_mut().inner {
                StreamInner::Server(s) => Pin::new(s).poll_read(cx, buf),
                StreamInner::Client(c) => Pin::new(c).poll_read(cx, buf),
            }
        }
    }

    impl AsyncWrite for LeaderStream {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            match &mut self.get_mut().inner {
                StreamInner::Server(s) => Pin::new(s).poll_write(cx, buf),
                StreamInner::Client(c) => Pin::new(c).poll_write(cx, buf),
            }
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            match &mut self.get_mut().inner {
                StreamInner::Server(s) => Pin::new(s).poll_flush(cx),
                StreamInner::Client(c) => Pin::new(c).poll_flush(cx),
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            match &mut self.get_mut().inner {
                StreamInner::Server(s) => Pin::new(s).poll_shutdown(cx),
                StreamInner::Client(c) => Pin::new(c).poll_shutdown(cx),
            }
        }
    }

    /// Listener for incoming leader IPC connections.
    /// Holds the pipe name plus the next pre-created server instance (Windows named pipes require pre-creating an instance per pending connection).
    pub(crate) struct LeaderListener {
        pipe_name: std::ffi::OsString,
        /// Next pre-created server instance, ready for `connect().await`; accept() rotates it.
        /// The first instance is created in `bind()` with `first_pipe_instance(true)` to lock out other processes from squatting the pipe name.
        /// tokio::sync::Mutex (not parking_lot) because accept() holds the lock across `server.connect().await`.
        next_server: tokio::sync::Mutex<Option<tokio::net::windows::named_pipe::NamedPipeServer>>,
    }

    impl LeaderListener {
        /// Reserve a named-pipe name (no on-disk file is created).
        pub(crate) fn bind<P: AsRef<Path>>(path: P) -> io::Result<Self> {
            let pipe_name = path_to_pipe_name(path.as_ref());
            // Owner = this user; allowed = this user and SYSTEM only (see `peer_auth`).
            let first = crate::leader::peer_auth::win::create_secure_server(&pipe_name, true)?;
            Ok(Self {
                pipe_name,
                next_server: tokio::sync::Mutex::new(Some(first)),
            })
        }

        /// The raw handle of the pre-created pending instance, if any.
        #[cfg(test)]
        pub(crate) async fn pending_raw_handle_for_test(&self) -> Option<std::os::windows::io::RawHandle> {
            use std::os::windows::io::AsRawHandle;
            self.next_server.lock().await.as_ref().map(|s| s.as_raw_handle())
        }

        /// Wait for the next incoming connection.
        /// Mirrors `UnixListener::accept`, returning a connected stream and a unit placeholder for the peer address (named pipes don't carry one).
        /// Cancellation safe (P145): see [`super::accept_from_slot`].
        pub(crate) async fn accept(&self) -> io::Result<(LeaderStream, ())> {
            // Bounded with a backoff so a persistently failing connect() can't busy-spin
            const MAX_ACCEPT_ATTEMPTS: usize = 10;
            const RETRY_BACKOFF: Duration = Duration::from_millis(20);

            let mut slot = self.next_server.lock().await;
            let server = super::accept_from_slot(
                &mut slot,
                || crate::leader::peer_auth::win::create_secure_server(&self.pipe_name, false),
                MAX_ACCEPT_ATTEMPTS,
                RETRY_BACKOFF,
            )
            .await?;
            Ok((
                LeaderStream {
                    inner: StreamInner::Server(server),
                },
                (),
            ))
        }
    }

    impl super::PendingInstance for tokio::net::windows::named_pipe::NamedPipeServer {
        fn wait_for_client(&self) -> impl std::future::Future<Output = io::Result<()>> + '_ {
            self.connect()
        }
    }

    /// Whether a leader has a pipe bound at `path`.
    ///
    /// Probes with `WaitNamedPipeW` (non-connecting), not `ClientOptions::open`.
    /// The latter would open a real client that `accept()` consumes as a phantom session.
    /// `ERROR_FILE_NOT_FOUND` means absent; `TRUE` or any other error (e.g. `ERROR_SEM_TIMEOUT`: exists but busy) means ready.
    pub(super) fn listener_is_ready(path: &Path) -> bool {
        use std::os::windows::ffi::OsStrExt;

        use windows::Win32::Foundation::{ERROR_FILE_NOT_FOUND, GetLastError};
        use windows::Win32::System::Pipes::WaitNamedPipeW;
        use windows::core::PCWSTR;

        // 1 ms is a real timeout; 0 would mean "use the server default"
        const PROBE_TIMEOUT_MS: u32 = 1;

        let pipe_name = path_to_pipe_name(path);
        let wide: Vec<u16> = pipe_name
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        if unsafe { WaitNamedPipeW(PCWSTR(wide.as_ptr()), PROBE_TIMEOUT_MS) }.as_bool() {
            return true;
        }
        // FALSE: only a missing pipe means not-ready.
        let err = unsafe { GetLastError() };
        err != ERROR_FILE_NOT_FOUND
    }

    /// Full named-pipe path: `\\.\pipe\<leaf>`.
    fn path_to_pipe_name(path: &Path) -> std::ffi::OsString {
        let mut name = std::ffi::OsString::from(r"\\.\pipe\");
        name.push(pipe_leaf_name(path));
        name
    }

    /// Deterministic leaf name (`fuigo-leader-<hash>`) for a filesystem path.
    ///
    /// Uses SipHash-1-3 with fixed keys so the hash is stable across Rust versions (unlike `DefaultHasher`, whose algorithm is unspecified).
    fn pipe_leaf_name(path: &Path) -> std::ffi::OsString {
        use siphasher::sip::SipHasher13;
        use std::hash::{Hash, Hasher};

        // Fixed keys: they must never change once shipped
        let mut hasher = SipHasher13::new_with_keys(0x67726f6b_6c656164, 0x65725f70_69706521);
        path.hash(&mut hasher);
        let hash = hasher.finish();
        std::ffi::OsString::from(format!("fuigo-leader-{hash:016x}"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::path::Path;

        #[test]
        fn pipe_name_is_deterministic() {
            let a = path_to_pipe_name(Path::new("/tmp/fuigo.sock"));
            let b = path_to_pipe_name(Path::new("/tmp/fuigo.sock"));
            assert_eq!(a, b);
        }

        #[test]
        fn different_paths_produce_different_names() {
            let a = path_to_pipe_name(Path::new("/tmp/a.sock"));
            let b = path_to_pipe_name(Path::new("/tmp/b.sock"));
            assert_ne!(a, b);
        }

        #[test]
        fn pipe_name_has_correct_prefix() {
            let name = path_to_pipe_name(Path::new("/tmp/test.sock"));
            let s = name.to_string_lossy();
            assert!(s.starts_with(r"\\.\pipe\fuigo-leader-"), "got: {s}");
        }

        #[test]
        fn pipe_name_is_bounded() {
            let long_path = format!("/{}", "a".repeat(500));
            let name = path_to_pipe_name(Path::new(&long_path));
            // \\.\pipe\fuigo-leader- (20 chars) + 16 hex chars = 36 total
            assert!(name.len() <= 256, "pipe name too long: {}", name.len());
        }

        #[tokio::test]
        async fn listener_is_ready_tracks_pipe_lifecycle() {
            // Unique path per process so parallel test binaries don't collide on the derived pipe name
            let path =
                std::env::temp_dir().join(format!("fuigo-ready-probe-{}.sock", std::process::id()));

            // Nothing is bound yet, so the probe hits ERROR_FILE_NOT_FOUND and reports not ready
            assert!(!listener_is_ready(&path));

            let listener = LeaderListener::bind(&path).unwrap();
            // Ready as soon as the pipe is bound, before any accept().
            assert!(listener_is_ready(&path));

            // After the last instance is dropped the pipe name disappears.
            drop(listener);
            assert!(!listener_is_ready(&path));
        }
    }
}

/// P145: the cancellation-safety rule of the Windows accept, exercised with a fake instance on every platform.
#[cfg(test)]
mod accept_slot_tests {
    use super::{PendingInstance, accept_from_slot};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// A fake listening instance: `wait_for_client` completes once `connected` is set.
    struct Fake {
        id: usize,
        connected: Arc<tokio::sync::Notify>,
        ready: Arc<std::sync::atomic::AtomicBool>,
    }
    impl PendingInstance for Fake {
        async fn wait_for_client(&self) -> std::io::Result<()> {
            while !self.ready.load(Ordering::SeqCst) {
                self.connected.notified().await;
            }
            Ok(())
        }
    }

    /// An accept that is dropped mid-wait (another select! branch won) must leave the SAME instance pending, so the
    /// client that connects to it is served by the next accept instead of having its pipe destroyed.
    #[tokio::test]
    async fn p145_a_cancelled_accept_keeps_the_pending_instance() {
        let created = Arc::new(AtomicUsize::new(0));
        let notify = Arc::new(tokio::sync::Notify::new());
        let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let create = {
            let (created, notify, ready) = (created.clone(), notify.clone(), ready.clone());
            move || {
                let id = created.fetch_add(1, Ordering::SeqCst);
                Ok(Fake { id, connected: notify.clone(), ready: ready.clone() })
            }
        };
        let mut slot = Some(create().unwrap());
        // Cancelled: the timeout wins, as an event branch would in the leader's select!.
        let cancelled =
            tokio::time::timeout(Duration::from_millis(20), accept_from_slot(&mut slot, &create, 3, Duration::ZERO)).await;
        assert!(cancelled.is_err(), "nobody connected yet");
        assert_eq!(slot.as_ref().map(|f| f.id), Some(0), "the pending instance survived the cancellation");
        assert_eq!(created.load(Ordering::SeqCst), 1, "no instance was destroyed and recreated");

        // The client connects to that instance; the next accept returns it and pre-creates the successor.
        ready.store(true, Ordering::SeqCst);
        notify.notify_waiters();
        let got = accept_from_slot(&mut slot, &create, 3, Duration::ZERO).await.unwrap();
        assert_eq!(got.id, 0, "the client is served on the instance it connected to");
        assert_eq!(slot.as_ref().map(|f| f.id), Some(1), "successor pending");
    }

    /// A failing instance is replaced, and the attempts are bounded.
    #[tokio::test]
    async fn p145_failed_instances_are_replaced_and_bounded() {
        struct Broken;
        impl PendingInstance for Broken {
            async fn wait_for_client(&self) -> std::io::Result<()> {
                Err(std::io::Error::other("broken"))
            }
        }
        let created = AtomicUsize::new(0);
        let mut slot: Option<Broken> = None;
        let err = accept_from_slot(
            &mut slot,
            || {
                created.fetch_add(1, Ordering::SeqCst);
                Ok(Broken)
            },
            3,
            Duration::ZERO,
        )
        .await
        .err()
        .expect("all attempts fail");
        assert_eq!(err.to_string(), "broken");
        assert_eq!(created.load(Ordering::SeqCst), 4, "one per attempt plus the refill");
        assert!(slot.is_some(), "the slot is refilled for the next accept");
    }
}
/// Packet 2 round 2: the OS names the process behind the server end of a pipe; a real pipe in this test process.
#[cfg(all(test, windows))]
mod os_server_pid_tests {
    use super::windows_impl::pipe_server_pid_of_handle;
    use std::os::windows::io::AsRawHandle;
    use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};
    #[tokio::test]
    async fn the_client_handle_reports_the_pid_of_the_process_serving_the_pipe() {
        let name = format!(r"\\.\pipe\fuigo-test-r2-os-server-pid-{}", std::process::id());
        let server = ServerOptions::new().first_pipe_instance(true).create(&name).unwrap();
        let client = ClientOptions::new().open(&name).unwrap();
        server.connect().await.unwrap();
        assert_eq!(
            pipe_server_pid_of_handle(client.as_raw_handle()),
            Some(std::process::id()),
            "this process created the server end"
        );
    }
}

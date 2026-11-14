//! Linux system sleep/wake via systemd-logind's `PrepareForSleep` D-Bus
//! signal, with a `delay` inhibitor lock so we get a short window to react
//! before the system actually sleeps.
//!
//! Registration runs on a dedicated thread with a bounded deadline. Missing or
//! unresponsive system buses simply leave power notifications unavailable; the
//! caller never waits for D-Bus authentication or logind registration.

use futures_util::StreamExt;
use std::{thread, time::Duration};

use super::{PowerCallback, PowerEvent};

const DEST: &str = "org.freedesktop.login1";
const PATH: &str = "/org/freedesktop/login1";
const IFACE: &str = "org.freedesktop.login1.Manager";

/// Linux listener handle.
///
/// The worker lives until the signal stream closes or the process exits.
/// Callbacks hold a weak owner reference, so dropping this handle needs no join.
pub(crate) struct Listener {
    #[cfg(test)]
    worker: thread::JoinHandle<()>,
}

impl Listener {
    pub(crate) fn start_with_status(
        callback: PowerCallback,
        registered: Box<dyn FnOnce(bool) + Send>,
    ) -> Option<Self> {
        let _worker = thread::Builder::new()
            .name("fuigo-power-listener".into())
            .spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    registered(false);
                    return;
                };
                runtime.block_on(listen(callback, registered));
            })
            .ok()?;

        Some(Self {
            #[cfg(test)]
            worker: _worker,
        })
    }
}

// Includes authentication, Hello, proxy construction and signal subscription. Dropping a timed-out future releases the pending socket.
const REGISTRATION_TIMEOUT: Duration = Duration::from_secs(1);

async fn take_inhibitor(proxy: &zbus::Proxy<'_>) -> Option<zbus::zvariant::OwnedFd> {
    tokio::time::timeout(
        REGISTRATION_TIMEOUT,
        proxy.call(
            "Inhibit",
            &(
                "sleep",
                "fuigo",
                "Pause token refresh across sleep",
                "delay",
            ),
        ),
    )
    .await
    .ok()?
    .ok()
}

async fn listen(callback: PowerCallback, registered: Box<dyn FnOnce(bool) + Send>) {
    let registration = async {
        let conn = zbus::Connection::system().await?;
        let proxy = zbus::Proxy::new_owned(conn, DEST, PATH, IFACE).await?;
        let signals = proxy.receive_signal("PrepareForSleep").await?;
        Ok::<_, zbus::Error>((proxy, signals))
    };
    let (proxy, mut signals) = match tokio::time::timeout(REGISTRATION_TIMEOUT, registration).await
    {
        Ok(Ok(connected)) => connected,
        result => {
            if result.is_err() {
                tracing::warn!(
                    "System bus registration timed out; power events unavailable for this run"
                );
            }
            registered(false);
            return;
        }
    };
    registered(true);
    // Inhibition is optional: even a stalled Inhibit call must leave the
    // connected signal listener working after its own deadline.
    let mut inhibitor = take_inhibitor(&proxy).await;
    while let Some(msg) = signals.next().await {
        let Ok(about_to_sleep) = msg.body().deserialize::<bool>() else {
            continue;
        };
        if about_to_sleep {
            // Keep the delay inhibitor across the bounded callback, just as
            // before: logind may suspend as soon as the descriptor is closed.
            callback(PowerEvent::WillSleep);
            inhibitor = None;
        } else {
            callback(PowerEvent::DidWake);
            inhibitor = take_inhibitor(&proxy).await;
        }
    }
    drop(inhibitor);
}

pub(crate) fn current_power_state() -> crate::PowerState {
    // Linux has no "dark wake" equivalent to query (the system is either
    // suspended or fully awake); report Unknown so callers fall back to the
    // logind `PrepareForSleep` path.
    crate::PowerState::Unknown
}

/// No power-assertion support on this platform: callers carry on unprotected,
/// which is the same behaviour as before assertions existed.
///
/// Never constructed here (`hold_awake` always returns `None`); it exists so
/// the cross-platform `SleepAssertion` has a field type on every target.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) struct Assertion;

pub(crate) fn hold_awake(_reason: &str) -> Option<Assertion> {
    None
}

#[cfg(test)]
mod startup_tests {
    use std::time::{Duration, Instant};

    struct TimeoutWarnings(std::sync::Arc<std::sync::atomic::AtomicUsize>);

    impl tracing::Subscriber for TimeoutWarnings {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            *metadata.level() == tracing::Level::WARN
        }
        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }
        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}
        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}
        fn enter(&self, _: &tracing::span::Id) {}
        fn exit(&self, _: &tracing::span::Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            struct Message(bool);
            impl tracing::field::Visit for Message {
                fn record_debug(
                    &mut self,
                    field: &tracing::field::Field,
                    value: &dyn std::fmt::Debug,
                ) {
                    if field.name() == "message"
                        && format!("{value:?}").contains("power events unavailable for this run")
                    {
                        self.0 = true;
                    }
                }
            }
            let mut message = Message(false);
            event.record(&mut message);
            if message.0 {
                self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
    }

    #[test]
    fn silent_system_bus_does_not_block_startup() {
        const CHILD: &str = "FUIGO_POWER_STARTUP_TEST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let started = Instant::now();
            let _listener = super::Listener::start_with_status(Box::new(|_| {}), Box::new(|_| {}));
            let elapsed = started.elapsed();
            eprintln!("listener start: {elapsed:?}");
            std::thread::sleep(Duration::from_millis(500));
            assert!(
                elapsed < Duration::from_millis(250),
                "startup blocked: {elapsed:?}"
            );
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bus");
        let bus = std::os::unix::net::UnixListener::bind(&path).unwrap();
        // Accept authentication bytes but never answer. Close after 300 ms so
        // the old synchronous implementation fails rather than hanging CI.
        bus.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(3);
            let socket = loop {
                if let Ok((socket, _)) = bus.accept() {
                    break socket;
                }
                assert!(Instant::now() < deadline, "worker never connected");
                std::thread::sleep(Duration::from_millis(5));
            };
            std::thread::sleep(Duration::from_millis(300));
            drop(socket);
        });
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "imp::startup_tests::silent_system_bus_does_not_block_startup",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env(
                "DBUS_SYSTEM_BUS_ADDRESS",
                format!("unix:path={}", path.display()),
            )
            .output()
            .unwrap();
        server.join().unwrap();
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn silent_system_bus_registration_expires() {
        const CHILD: &str = "FUIGO_POWER_DEADLINE_TEST_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let warnings = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
            tracing::subscriber::set_global_default(TimeoutWarnings(warnings.clone())).unwrap();
            struct NotifyDrop(std::sync::mpsc::Sender<()>);
            impl Drop for NotifyDrop {
                fn drop(&mut self) {
                    let _ = self.0.send(());
                }
            }
            let (tx, rx) = std::sync::mpsc::channel();
            let guard = NotifyDrop(tx);
            let started = Instant::now();
            let (status_tx, status_rx) = std::sync::mpsc::channel();
            let listener = super::Listener::start_with_status(
                Box::new(move |_| {
                    let _ = &guard;
                }),
                Box::new(move |available| {
                    status_tx.send(available).unwrap();
                }),
            )
            .unwrap();
            rx.recv_timeout(Duration::from_millis(1500))
                .expect("registration must release its callback on timeout");
            assert!(started.elapsed() < Duration::from_millis(1500));
            assert!(
                !status_rx.recv_timeout(Duration::from_secs(1)).unwrap(),
                "timed-out registration must report unavailable"
            );
            // Callback destruction alone does not prove the runtime/worker exited.
            let deadline = Instant::now() + Duration::from_secs(1);
            while !listener.worker.is_finished() {
                assert!(
                    Instant::now() < deadline,
                    "registration worker did not finish"
                );
                std::thread::sleep(Duration::from_millis(5));
            }
            listener.worker.join().unwrap();
            assert_eq!(
                warnings.load(std::sync::atomic::Ordering::SeqCst),
                1,
                "registration timeout must emit exactly one warning"
            );
            eprintln!(
                "registration expired and worker joined: {:?}",
                started.elapsed()
            );
            // Stay alive until the parent observes EOF on the bus socket. Process
            // teardown must not be what closes a leaked registration connection.
            use std::io::Read;
            let mut ack = [0];
            std::io::stdin().read_exact(&mut ack).unwrap();
            assert_eq!(ack, [1], "parent must observe socket EOF before child exit");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bus");
        let bus = std::os::unix::net::UnixListener::bind(&path).unwrap();
        bus.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            use std::io::Read;
            let deadline = Instant::now() + Duration::from_secs(3);
            let mut socket = loop {
                if let Ok((socket, _)) = bus.accept() {
                    break socket;
                }
                assert!(Instant::now() < deadline, "worker never connected");
                std::thread::sleep(Duration::from_millis(5));
            };
            socket.set_nonblocking(false).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut authentication = Vec::new();
            socket
                .read_to_end(&mut authentication)
                .expect("timed-out registration must close its socket");
            assert!(
                !authentication.is_empty(),
                "exercise an accepted but silent bus"
            );
        });
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "imp::startup_tests::silent_system_bus_registration_expires",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env(
                "DBUS_SYSTEM_BUS_ADDRESS",
                format!("unix:path={}", path.display()),
            )
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let eof = server.join();
        let alive = child.try_wait().unwrap().is_none();
        use std::io::Write;
        if alive {
            let _ = child
                .stdin
                .take()
                .unwrap()
                .write_all(&[u8::from(eof.is_ok())]);
        }
        let output = child.wait_with_output().unwrap();
        eof.unwrap();
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(alive, "child exited before EOF acknowledgement");
    }
}

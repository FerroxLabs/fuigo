/// The signals the 130/143/129 exit-code map covers, claimed from construction for as long as this
/// lives: without a live stream a signal takes its default action and kills the process.
#[cfg(unix)]
pub struct SignalStreams {
    interrupt: Option<tokio::signal::unix::Signal>,
    terminate: Option<tokio::signal::unix::Signal>,
    hangup: Option<tokio::signal::unix::Signal>,
}

#[cfg(unix)]
impl SignalStreams {
    pub fn install() -> SignalStreams {
        use tokio::signal::unix::{SignalKind, signal};

        SignalStreams {
            interrupt: signal(SignalKind::interrupt())
                .inspect_err(|error| tracing::warn!(%error, "no SIGINT handler"))
                .ok(),
            terminate: signal(SignalKind::terminate())
                .inspect_err(|error| tracing::warn!(%error, "no SIGTERM handler"))
                .ok(),
            hangup: signal(SignalKind::hangup())
                .inspect_err(|error| tracing::warn!(%error, "no SIGHUP handler"))
                .ok(),
        }
    }

    pub async fn next_code(&mut self) -> i32 {
        next_signal_code(&mut self.interrupt, &mut self.terminate, &mut self.hangup).await
    }
}

#[cfg(windows)]
pub struct SignalStreams {
    ctrl_c: Option<tokio::signal::windows::CtrlC>,
}

#[cfg(windows)]
impl SignalStreams {
    pub fn install() -> SignalStreams {
        SignalStreams {
            ctrl_c: tokio::signal::windows::ctrl_c()
                .inspect_err(|error| tracing::warn!(%error, "no Ctrl-C handler"))
                .ok(),
        }
    }

    pub async fn next_code(&mut self) -> i32 {
        match self.ctrl_c.as_mut() {
            Some(ctrl_c) => {
                ctrl_c.recv().await;
            }
            None => std::future::pending::<()>().await,
        }
        130
    }
}

/// Wait for the next SIGINT/SIGTERM/SIGHUP and map it to its exit code.
#[cfg(unix)]
pub(crate) async fn next_signal_code(
    sigint: &mut Option<tokio::signal::unix::Signal>,
    sigterm: &mut Option<tokio::signal::unix::Signal>,
    sighup: &mut Option<tokio::signal::unix::Signal>,
) -> i32 {
    tokio::select! {
        _ = recv_optional_unix_signal(sigint) => 130,
        _ = recv_optional_unix_signal(sigterm) => 143,
        _ = recv_optional_unix_signal(sighup) => 129,
    }
}

/// Await one recv on an optional unix signal stream, or pend forever if absent.
#[cfg(unix)]
async fn recv_optional_unix_signal(sig: &mut Option<tokio::signal::unix::Signal>) {
    if let Some(s) = sig.as_mut() {
        let _ = s.recv().await;
    } else {
        std::future::pending::<()>().await;
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::SignalStreams;
    use std::time::Duration;

    /// Streams are claimed from construction: a signal that lands before anything awaits is queued and mapped to its
    /// exit code, not given its default action (which would kill the process with the terminal still in raw mode).
    /// One test sends all three in turn, since signals are process-wide and parallel tests would see each other's.
    #[tokio::test]
    async fn signals_after_install_are_queued_and_mapped_not_fatal() {
        let mut streams = SignalStreams::install();
        for (signal, code) in [
            (libc::SIGINT, 130),
            (libc::SIGTERM, 143),
            (libc::SIGHUP, 129),
        ] {
            // SAFETY: raising a signal on our own process; every one of them has a live tokio stream above.
            assert_eq!(0, unsafe { libc::kill(libc::getpid(), signal) });
            let got = tokio::time::timeout(Duration::from_secs(5), streams.next_code())
                .await
                .expect("the queued signal must be delivered");
            assert_eq!(code, got, "signal {signal}");
        }
    }
}

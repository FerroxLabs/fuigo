//! The idle deadline of a transfer: one timer per direction, renewed only when it fires, instead of
//! a fresh timeout for every read and write (audit L13).

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Sleep;

/// Ends a transfer once no byte has moved for `idle`. The last movement is kept in `last` as
/// milliseconds since `clock`; the two directions of a tunnel share it, so traffic either way keeps
/// both open.
pub(crate) struct IdleDeadline<'a> {
    idle: Duration,
    clock: Instant,
    last: &'a AtomicU64,
    sleep: Pin<Box<Sleep>>,
}

impl<'a> IdleDeadline<'a> {
    pub(crate) fn new(idle: Duration, clock: Instant, last: &'a AtomicU64) -> Self {
        let sleep = Box::pin(tokio::time::sleep_until(due(idle, clock, last)));
        IdleDeadline {
            idle,
            clock,
            last,
            sleep,
        }
    }

    fn touch(&self) {
        self.last
            .store(self.clock.elapsed().as_millis() as u64, Ordering::Relaxed);
    }

    /// Resolves once nothing has moved for `idle`. Cancel-safe: the timer lives in `self`.
    async fn expired(&mut self) {
        loop {
            self.sleep.as_mut().await;
            let next = due(self.idle, self.clock, self.last);
            if next <= tokio::time::Instant::now() {
                return;
            }
            self.sleep.as_mut().reset(next);
        }
    }

    /// One read, failing with `TimedOut` when the transfer has gone idle first.
    pub(crate) async fn read<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
        buffer: &mut [u8],
    ) -> io::Result<usize> {
        let count = tokio::select! {
            read = reader.read(buffer) => read?,
            () = self.expired() => return Err(io::ErrorKind::TimedOut.into()),
        };
        self.touch();
        Ok(count)
    }

    /// Writes all of `bytes`, failing with `TimedOut` when the transfer goes idle first; a peer that
    /// stops reading is dropped, one that keeps taking bytes is served whole.
    pub(crate) async fn write_all<W: AsyncWrite + Unpin>(
        &mut self,
        writer: &mut W,
        mut bytes: &[u8],
    ) -> io::Result<()> {
        while !bytes.is_empty() {
            let count = tokio::select! {
                written = writer.write(bytes) => written?,
                () = self.expired() => return Err(io::ErrorKind::TimedOut.into()),
            };
            if count == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            bytes = &bytes[count..];
            self.touch();
        }
        Ok(())
    }

    /// Shuts `writer` down, giving up quietly when the transfer goes idle first.
    pub(crate) async fn shutdown<W: AsyncWrite + Unpin>(&mut self, writer: &mut W) {
        tokio::select! {
            _ = writer.shutdown() => {}
            () = self.expired() => {}
        }
    }
}

fn due(idle: Duration, clock: Instant, last: &AtomicU64) -> tokio::time::Instant {
    (clock + Duration::from_millis(last.load(Ordering::Relaxed)) + idle).into()
}

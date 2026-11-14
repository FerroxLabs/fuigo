use std::{collections::VecDeque, io, time::Duration};

use mio::{unix::SourceFd, Events, Interest, Poll, Token};
use signal_hook_mio::v1_0::Signals;

#[cfg(feature = "event-stream")]
use crate::event::sys::Waker;
use crate::event::{
    source::EventSource, sys::unix::parse::parse_event, timeout::PollTimeout, Event, InternalEvent,
};
use crate::terminal::sys::file_descriptor::{tty_fd, FileDesc};

// Tokens to identify file descriptor
const TTY_TOKEN: Token = Token(0);
const SIGNAL_TOKEN: Token = Token(1);
#[cfg(feature = "event-stream")]
const WAKE_TOKEN: Token = Token(2);

// I (@zrzka) wasn't able to read more than 1_022 bytes when testing
// reading on macOS/Linux -> we don't need bigger buffer and 1k of bytes
// is enough.
const TTY_BUFFER_SIZE: usize = 1_024;

pub(crate) struct UnixInternalEventSource {
    poll: Poll,
    events: Events,
    parser: Parser,
    tty_buffer: [u8; TTY_BUFFER_SIZE],
    tty_fd: FileDesc<'static>,
    // Mio readiness is edge-triggered. Returning one parsed event must not
    // forget an edge while the fd still has unread bytes.
    tty_ready: bool,
    tty_notification: bool,
    signals: Signals,
    #[cfg(feature = "event-stream")]
    waker: Waker,
}

// None means the descriptor cannot be level-checked (notably /dev/tty on
// macOS poll). It must retain its edge and use one read per mio notification.
#[cfg(any(not(target_os = "macos"), test))]
fn poll_readable(input: bool, invalid: bool) -> Option<bool> {
    if invalid {
        None
    } else {
        Some(input)
    }
}

impl UnixInternalEventSource {
    // Never change shared stdin flags: stdin may be blocking. On macOS use
    // FIONREAD because poll cannot reliably check an opened /dev/tty.
    #[cfg(all(target_os = "macos", not(feature = "libc")))]
    fn tty_is_readable(&self) -> Option<bool> {
        rustix::io::ioctl_fionread(&self.tty_fd)
            .ok()
            .map(|bytes| bytes > 0)
    }

    #[cfg(all(target_os = "macos", feature = "libc"))]
    fn tty_is_readable(&self) -> Option<bool> {
        let mut bytes: libc::c_int = 0;
        // SAFETY: the live tty fd and writable integer match FIONREAD's ABI.
        let result = unsafe { libc::ioctl(self.tty_fd.raw_fd(), libc::FIONREAD, &mut bytes) };
        (result == 0).then_some(bytes > 0)
    }

    #[cfg(all(not(target_os = "macos"), not(feature = "libc")))]
    fn tty_is_readable(&self) -> Option<bool> {
        let mut fds = [rustix::event::PollFd::new(
            &self.tty_fd,
            rustix::event::PollFlags::IN,
        )];
        rustix::event::poll(&mut fds, 0).ok()?;
        let flags = fds[0].revents();
        poll_readable(
            flags.contains(rustix::event::PollFlags::IN),
            flags.contains(rustix::event::PollFlags::NVAL),
        )
    }

    #[cfg(all(not(target_os = "macos"), feature = "libc"))]
    fn tty_is_readable(&self) -> Option<bool> {
        let mut fd = libc::pollfd {
            fd: self.tty_fd.raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd, borrowed only for this zero-time poll.
        let count = unsafe { libc::poll(&mut fd, 1, 0) };
        if count < 0 {
            None
        } else {
            poll_readable(
                fd.revents & libc::POLLIN != 0,
                fd.revents & libc::POLLNVAL != 0,
            )
        }
    }

    pub fn new() -> io::Result<Self> {
        UnixInternalEventSource::from_file_descriptor(tty_fd()?)
    }

    pub(crate) fn from_file_descriptor(input_fd: FileDesc<'static>) -> io::Result<Self> {
        let poll = Poll::new()?;
        let registry = poll.registry();

        let tty_raw_fd = input_fd.raw_fd();
        let mut tty_ev = SourceFd(&tty_raw_fd);
        registry.register(&mut tty_ev, TTY_TOKEN, Interest::READABLE)?;

        let mut signals = Signals::new([signal_hook::consts::SIGWINCH])?;
        registry.register(&mut signals, SIGNAL_TOKEN, Interest::READABLE)?;

        #[cfg(feature = "event-stream")]
        let waker = Waker::new(registry, WAKE_TOKEN)?;

        Ok(UnixInternalEventSource {
            poll,
            events: Events::with_capacity(3),
            parser: Parser::default(),
            tty_buffer: [0u8; TTY_BUFFER_SIZE],
            tty_fd: input_fd,
            tty_ready: false,
            tty_notification: false,
            signals,
            #[cfg(feature = "event-stream")]
            waker,
        })
    }
}

impl UnixInternalEventSource {
    fn try_read_with_readiness(
        &mut self,
        timeout: Option<Duration>,
        readiness: impl Fn(&Self) -> Option<bool>,
    ) -> io::Result<Option<InternalEvent>> {
        if let Some(event) = self.parser.next() {
            return Ok(Some(event));
        }

        let timeout = PollTimeout::new(timeout);

        loop {
            let read_tty = self.tty_ready
                && match readiness(self) {
                    Some(true) => true,
                    Some(false) => {
                        self.tty_ready = false;
                        false
                    }
                    // Unknown is not idle and is not permission to keep reading
                    // blocking stdin. Preserve the edge, but read only once for
                    // each fresh mio notification, as in unmodified 0.28.1.
                    None => self.tty_notification,
                };
            self.tty_notification = false;
            if read_tty {
                match self.tty_fd.read(&mut self.tty_buffer) {
                    Ok(0) => {
                        self.tty_ready = false;
                        return Ok(None);
                    }
                    Ok(count) => self
                        .parser
                        .advance(&self.tty_buffer[..count], count == TTY_BUFFER_SIZE),
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        self.tty_ready = false;
                    }
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                        self.tty_notification = true;
                    }
                    Err(error) => return Err(error),
                }
                if let Some(event) = self.parser.next() {
                    return Ok(Some(event));
                }
                if timeout.elapsed() {
                    return Ok(None);
                }
                if self.tty_ready {
                    continue;
                }
            }
            if let Err(e) = self.poll.poll(&mut self.events, timeout.leftover()) {
                // Mio will throw an interrupted error in case of cursor position retrieval. We need to retry until it succeeds.
                // Previous versions of Mio (< 0.7) would automatically retry the poll call if it was interrupted (if EINTR was returned).
                // https://docs.rs/mio/0.7.0/mio/struct.Poll.html#notes
                if e.kind() == io::ErrorKind::Interrupted {
                    continue;
                } else {
                    return Err(e);
                }
            };

            if self.events.is_empty() {
                // No readiness events = timeout
                return Ok(None);
            }

            // Record the edge before handling signals, which may return early.
            self.tty_notification = self.events.iter().any(|event| event.token() == TTY_TOKEN);
            self.tty_ready |= self.tty_notification;
            for token in self.events.iter().map(|x| x.token()) {
                match token {
                    TTY_TOKEN => {}
                    SIGNAL_TOKEN => {
                        if self.signals.pending().next() == Some(signal_hook::consts::SIGWINCH) {
                            // TODO Should we remove tput?
                            //
                            // This can take a really long time, because terminal::size can
                            // launch new process (tput) and then it parses its output. It's
                            // not a really long time from the absolute time point of view, but
                            // it's a really long time from the mio, async-std/tokio executor, ...
                            // point of view.
                            let new_size = crate::terminal::size()?;
                            return Ok(Some(InternalEvent::Event(Event::Resize(
                                new_size.0, new_size.1,
                            ))));
                        }
                    }
                    #[cfg(feature = "event-stream")]
                    WAKE_TOKEN => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::Interrupted,
                            "Poll operation was woken up by `Waker::wake`",
                        ));
                    }
                    _ => unreachable!("Synchronize Evented handle registration & token handling"),
                }
            }

            // Processing above can take some time, check if timeout expired
            if !self.tty_ready && timeout.elapsed() {
                return Ok(None);
            }
        }
    }
}

impl EventSource for UnixInternalEventSource {
    fn try_read(&mut self, timeout: Option<Duration>) -> io::Result<Option<InternalEvent>> {
        self.try_read_with_readiness(timeout, Self::tty_is_readable)
    }

    #[cfg(feature = "event-stream")]
    fn waker(&self) -> Waker {
        self.waker.clone()
    }
}

//
// Following `Parser` structure exists for two reasons:
//
//  * mimic anes Parser interface
//  * move the advancing, parsing, ... stuff out of the `try_read` method
//
#[derive(Debug)]
struct Parser {
    buffer: Vec<u8>,
    internal_events: VecDeque<InternalEvent>,
}

impl Default for Parser {
    fn default() -> Self {
        Parser {
            // This buffer is used for -> 1 <- ANSI escape sequence. Are we
            // aware of any ANSI escape sequence that is bigger? Can we make
            // it smaller?
            //
            // Probably not worth spending more time on this as "there's a plan"
            // to use the anes crate parser.
            buffer: Vec::with_capacity(256),
            // TTY_BUFFER_SIZE is 1_024 bytes. How many ANSI escape sequences can
            // fit? What is an average sequence length? Let's guess here
            // and say that the average ANSI escape sequence length is 8 bytes. Thus
            // the buffer size should be 1024/8=128 to avoid additional allocations
            // when processing large amounts of data.
            //
            // There's no need to make it bigger, because when you look at the `try_read`
            // method implementation, all events are consumed before the next TTY_BUFFER
            // is processed -> events pushed.
            internal_events: VecDeque::with_capacity(128),
        }
    }
}

impl Parser {
    fn advance(&mut self, buffer: &[u8], more: bool) {
        for (idx, byte) in buffer.iter().enumerate() {
            let more = idx + 1 < buffer.len() || more;

            self.buffer.push(*byte);

            match parse_event(&self.buffer, more) {
                Ok(Some(ie)) => {
                    self.internal_events.push_back(ie);
                    self.buffer.clear();
                }
                Ok(None) => {
                    // Event can't be parsed, because we don't have enough bytes for
                    // the current sequence. Keep the buffer and process next bytes.
                }
                Err(_) => {
                    // Event can't be parsed (not enough parameters, parameter is not a number, ...).
                    // Clear the buffer and continue with another sequence.
                    self.buffer.clear();
                }
            }
        }
    }
}

impl Iterator for Parser {
    type Item = InternalEvent;

    fn next(&mut self) -> Option<Self::Item> {
        self.internal_events.pop_front()
    }
}

#[cfg(test)]
mod readiness_tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    #[test]
    fn hangup_without_pollin_is_not_readable() {
        assert_eq!(poll_readable(false, false), Some(false));
        assert_eq!(poll_readable(true, false), Some(true));
        assert_eq!(poll_readable(false, true), None);
    }

    #[test]
    fn pollnval_preserves_edge_without_repeating_a_blocking_read() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        // A real blocking fd, with a timeout to bound a broken implementation.
        reader
            .set_read_timeout(Some(Duration::from_millis(300)))
            .unwrap();
        #[cfg(not(feature = "libc"))]
        let fd = FileDesc::Owned(reader.into());
        #[cfg(feature = "libc")]
        let fd = {
            use std::os::fd::IntoRawFd;
            FileDesc::new(reader.into_raw_fd(), true)
        };
        let mut source = UnixInternalEventSource::from_file_descriptor(fd).unwrap();
        // Emulate /dev/tty on a platform whose poll reports POLLNVAL. Only
        // the level check is injected; mio notifications and reads are real.
        let unsupported = |_: &UnixInternalEventSource| poll_readable(false, true);
        for byte in [b'x', b'y'] {
            writer.write_all(&[byte]).unwrap();
            assert!(
                matches!(source.try_read_with_readiness(Some(Duration::ZERO), unsupported).unwrap(),
                Some(InternalEvent::Event(Event::Key(key))) if key.code == crate::event::KeyCode::Char(char::from(byte)))
            );
            assert!(source.tty_ready, "unknown readiness must preserve the edge");
            let started = std::time::Instant::now();
            assert!(source
                .try_read_with_readiness(Some(Duration::ZERO), unsupported)
                .unwrap()
                .is_none());
            assert!(source.tty_ready, "unknown readiness must not become idle");
            assert!(
                started.elapsed() < Duration::from_millis(100),
                "repeated a blocking read"
            );
        }
    }

    #[test]
    fn queued_input_is_drained_without_a_second_readiness_edge() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        #[cfg(not(feature = "libc"))]
        let fd = FileDesc::Owned(reader.into());
        #[cfg(feature = "libc")]
        let fd = {
            use std::os::fd::IntoRawFd;
            FileDesc::new(reader.into_raw_fd(), true)
        };
        let mut source = UnixInternalEventSource::from_file_descriptor(fd).unwrap();
        let input: Vec<u8> = (0..4096).map(|n| b'a' + (n % 26) as u8).collect();
        writer.write_all(&input).unwrap();
        // One write/readiness edge, several read buffers. No writer thread can
        // accidentally deliver another edge and hide a parked reader.
        for (index, byte) in input.iter().enumerate() {
            let event = source.try_read(Some(Duration::ZERO)).unwrap();
            assert!(
                matches!(event, Some(InternalEvent::Event(Event::Key(key)))
                if key.code == crate::event::KeyCode::Char(char::from(*byte))),
                "reader lost readiness at byte {index}: {event:?}"
            );
        }
        assert!(source.try_read(Some(Duration::ZERO)).unwrap().is_none());
        writer.write_all(b"z").unwrap();
        assert!(matches!(source.try_read(Some(Duration::ZERO)).unwrap(),
            Some(InternalEvent::Event(Event::Key(key))) if key.code == crate::event::KeyCode::Char('z')));
    }

    #[test]
    fn blocking_descriptor_becomes_idle_without_blocking_poll() {
        let (reader, mut writer) = UnixStream::pair().unwrap();
        // Bound a regression in the implementation without making this fd
        // nonblocking: real terminals use a blocking stdin descriptor too.
        reader
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        #[cfg(not(feature = "libc"))]
        let fd = FileDesc::Owned(reader.into());
        #[cfg(feature = "libc")]
        let fd = {
            use std::os::fd::IntoRawFd;
            FileDesc::new(reader.into_raw_fd(), true)
        };
        let mut source = UnixInternalEventSource::from_file_descriptor(fd).unwrap();
        writer.write_all(b"x").unwrap();
        assert!(source.try_read(Some(Duration::ZERO)).unwrap().is_some());
        let started = std::time::Instant::now();
        assert!(source.try_read(Some(Duration::ZERO)).unwrap().is_none());
        assert!(started.elapsed() < Duration::from_millis(50));
    }
}

//! UNIX related logic for terminal manipulation.

use crate::terminal::{
    sys::file_descriptor::{tty_fd, FileDesc},
    WindowSize,
};
#[cfg(feature = "libc")]
use libc::{
    cfmakeraw, ioctl, tcgetattr, tcsetattr, termios as Termios, winsize, STDOUT_FILENO, TCSANOW,
    TIOCGWINSZ,
};
use parking_lot::Mutex;
#[cfg(not(feature = "libc"))]
use rustix::{
    fd::AsFd,
    termios::{Termios, Winsize},
};

use std::{fs::File, io, process};
#[cfg(feature = "libc")]
use std::{
    mem,
    os::unix::io::{IntoRawFd, RawFd},
};

// Some(Termios) -> we're in the raw mode and this is the previous mode
// None -> we're not in the raw mode
static TERMINAL_MODE_PRIOR_RAW_MODE: Mutex<Option<Termios>> = parking_lot::const_mutex(None);

pub(crate) fn is_raw_mode_enabled() -> bool {
    TERMINAL_MODE_PRIOR_RAW_MODE.lock().is_some()
}

#[cfg(feature = "libc")]
impl From<winsize> for WindowSize {
    fn from(size: winsize) -> WindowSize {
        WindowSize {
            columns: size.ws_col,
            rows: size.ws_row,
            width: size.ws_xpixel,
            height: size.ws_ypixel,
        }
    }
}
#[cfg(not(feature = "libc"))]
impl From<Winsize> for WindowSize {
    fn from(size: Winsize) -> WindowSize {
        WindowSize {
            columns: size.ws_col,
            rows: size.ws_row,
            width: size.ws_xpixel,
            height: size.ws_ypixel,
        }
    }
}

#[allow(clippy::useless_conversion)]
#[cfg(feature = "libc")]
pub(crate) fn window_size() -> io::Result<WindowSize> {
    // http://rosettacode.org/wiki/Terminal_control/Dimensions#Library:_BSD_libc
    let mut size = winsize {
        ws_row: 0,
        ws_col: 0,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    let file = File::open("/dev/tty").map(|file| (FileDesc::new(file.into_raw_fd(), true)));
    let fd = if let Ok(file) = &file {
        file.raw_fd()
    } else {
        // Fallback to libc::STDOUT_FILENO if /dev/tty is missing
        STDOUT_FILENO
    };

    if wrap_with_result(unsafe { ioctl(fd, TIOCGWINSZ.into(), &mut size) }).is_ok() {
        return Ok(size.into());
    }

    Err(std::io::Error::last_os_error().into())
}

#[cfg(not(feature = "libc"))]
pub(crate) fn window_size() -> io::Result<WindowSize> {
    let file = File::open("/dev/tty").map(|file| (FileDesc::Owned(file.into())));
    let fd = if let Ok(file) = &file {
        file.as_fd()
    } else {
        // Fallback to libc::STDOUT_FILENO if /dev/tty is missing
        rustix::stdio::stdout()
    };
    let size = rustix::termios::tcgetwinsize(fd)?;
    Ok(size.into())
}

#[allow(clippy::useless_conversion)]
pub(crate) fn size() -> io::Result<(u16, u16)> {
    if let Ok(window_size) = window_size() {
        return Ok((window_size.columns, window_size.rows));
    }

    tput_size().ok_or_else(|| std::io::Error::last_os_error().into())
}

#[cfg(feature = "libc")]
pub(crate) fn enable_raw_mode() -> io::Result<()> {
    let mut original_mode = TERMINAL_MODE_PRIOR_RAW_MODE.lock();
    if original_mode.is_some() {
        return Ok(());
    }

    let tty = tty_fd()?;
    let fd = tty.raw_fd();
    let mut ios = get_terminal_attr(fd)?;
    let original_mode_ios = ios;
    raw_terminal_attr(&mut ios);
    set_terminal_attr(fd, &ios)?;
    // Keep it last - set the original mode only if we were able to switch to the raw mode
    *original_mode = Some(original_mode_ios);
    Ok(())
}

#[cfg(not(feature = "libc"))]
pub(crate) fn enable_raw_mode() -> io::Result<()> {
    let mut original_mode = TERMINAL_MODE_PRIOR_RAW_MODE.lock();
    if original_mode.is_some() {
        return Ok(());
    }

    let tty = tty_fd()?;
    let mut ios = get_terminal_attr(&tty)?;
    let original_mode_ios = ios.clone();
    ios.make_raw();
    set_terminal_attr(&tty, &ios)?;
    // Keep it last - set the original mode only if we were able to switch to the raw mode
    *original_mode = Some(original_mode_ios);
    Ok(())
}

/// Reset the raw mode.
///
/// More precisely, reset the whole termios mode to what it was before the first call
/// to [enable_raw_mode]. If you don't mess with termios outside of crossterm, it's
/// effectively disabling the raw mode and doing nothing else.
#[cfg(feature = "libc")]
pub(crate) fn disable_raw_mode() -> io::Result<()> {
    let mut original_mode = TERMINAL_MODE_PRIOR_RAW_MODE.lock();
    if let Some(original_mode_ios) = original_mode.as_ref() {
        let tty = tty_fd()?;
        set_terminal_attr(tty.raw_fd(), original_mode_ios)?;
        // Keep it last - remove the original mode only if we were able to switch back
        *original_mode = None;
    }
    Ok(())
}

#[cfg(not(feature = "libc"))]
pub(crate) fn disable_raw_mode() -> io::Result<()> {
    let mut original_mode = TERMINAL_MODE_PRIOR_RAW_MODE.lock();
    if let Some(original_mode_ios) = original_mode.as_ref() {
        let tty = tty_fd()?;
        set_terminal_attr(&tty, original_mode_ios)?;
        // Keep it last - remove the original mode only if we were able to switch back
        *original_mode = None;
    }
    Ok(())
}

#[cfg(not(feature = "libc"))]
fn get_terminal_attr(fd: impl AsFd) -> io::Result<Termios> {
    let result = rustix::termios::tcgetattr(fd)?;
    Ok(result)
}

#[cfg(not(feature = "libc"))]
fn set_terminal_attr(fd: impl AsFd, termios: &Termios) -> io::Result<()> {
    rustix::termios::tcsetattr(fd, rustix::termios::OptionalActions::Now, termios)?;
    Ok(())
}

/// Queries the terminal's support for progressive keyboard enhancement.
///
/// On unix systems, this function will block and possibly time out while
/// [`crossterm::event::read`](crate::event::read) or [`crossterm::event::poll`](crate::event::poll) are being called.
#[cfg(feature = "events")]
pub fn supports_keyboard_enhancement() -> io::Result<bool> {
    if is_raw_mode_enabled() {
        read_supports_keyboard_enhancement_raw()
    } else {
        read_supports_keyboard_enhancement_flags()
    }
}

#[cfg(feature = "events")]
fn read_supports_keyboard_enhancement_flags() -> io::Result<bool> {
    enable_raw_mode()?;
    let flags = read_supports_keyboard_enhancement_raw();
    disable_raw_mode()?;
    flags
}

#[cfg(feature = "events")]
fn poll_keyboard_reply(
    deadline: std::time::Instant,
    mut poll: impl FnMut(std::time::Duration) -> io::Result<bool>,
) -> io::Result<bool> {
    loop {
        match poll(deadline.saturating_duration_since(std::time::Instant::now())) {
            Ok(true) => return Ok(true),
            Ok(false) => {} // The event reader also maps EINTR to false.
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
        if std::time::Instant::now() >= deadline {
            return Ok(false);
        }
    }
}

#[cfg(feature = "events")]
fn poll_trailing_da1(
    deadline: std::time::Instant,
    mut poll: impl FnMut(std::time::Duration) -> io::Result<bool>,
) -> io::Result<bool> {
    if poll_keyboard_reply(deadline, &mut poll)? {
        return Ok(true);
    }
    // One nonblocking drain catches a DA1 queued just as the deadline elapsed.
    match poll(std::time::Duration::ZERO) {
        Err(error) if error.kind() == io::ErrorKind::Interrupted => Ok(false),
        result => result,
    }
}

#[cfg(all(test, feature = "events"))]
mod probe_tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn trailing_da1_gets_one_nonblocking_drain_at_deadline() {
        let mut calls = 0;
        assert!(poll_trailing_da1(Instant::now(), |remaining| {
            assert_eq!(remaining, Duration::ZERO);
            calls += 1;
            Ok(calls == 2)
        })
        .unwrap());
        assert_eq!(calls, 2);
        let mut silent_calls = 0;
        assert!(!poll_trailing_da1(Instant::now(), |remaining| {
            assert_eq!(remaining, Duration::ZERO);
            silent_calls += 1;
            Ok(false)
        })
        .unwrap());
        assert_eq!(silent_calls, 2, "no new wait for a silent DA1");
    }

    #[test]
    fn interruptions_do_not_extend_an_expired_probe() {
        let mut calls = 0;
        assert!(!poll_keyboard_reply(Instant::now(), |_| {
            calls += 1;
            Err(io::Error::from(io::ErrorKind::Interrupted))
        })
        .unwrap());
        assert_eq!(calls, 1);
        let mut drain_calls = 0;
        assert!(!poll_trailing_da1(Instant::now(), |_| {
            drain_calls += 1;
            Err(io::Error::from(io::ErrorKind::Interrupted))
        })
        .unwrap());
        assert_eq!(drain_calls, 2);
    }

    #[test]
    fn interrupted_keyboard_probe_retries_with_same_deadline() {
        let deadline = Instant::now() + Duration::from_millis(200);
        let mut calls = 0;
        let mut previous = Duration::from_millis(200);
        assert!(poll_keyboard_reply(deadline, |remaining| {
            assert!(remaining <= previous, "deadline must not restart");
            previous = remaining;
            calls += 1;
            if calls == 1 {
                Err(io::Error::from(io::ErrorKind::Interrupted))
            } else {
                Ok(true)
            }
        })
        .unwrap());
        assert_eq!(calls, 2);
    }

    #[test]
    fn interrupted_reader_silence_does_not_end_keyboard_probe() {
        // InternalEventReader maps an interrupted source to Ok(false).
        let mut calls = 0;
        assert!(
            poll_keyboard_reply(Instant::now() + Duration::from_millis(200), |_| {
                calls += 1;
                Ok(calls > 1)
            })
            .unwrap()
        );
        assert_eq!(calls, 2);
    }
}

#[cfg(feature = "events")]
fn read_supports_keyboard_enhancement_raw() -> io::Result<bool> {
    use crate::event::{
        filter::{KeyboardEnhancementFlagsFilter, PrimaryDeviceAttributesFilter},
        poll_internal, read_internal, InternalEvent,
    };
    use std::io::Write;
    use std::time::{Duration, Instant};

    // This is the recommended method for testing support for the keyboard enhancement protocol.
    // We send a query for the flags supported by the terminal and then the primary device attributes
    // query. If we receive the primary device attributes response but not the keyboard enhancement
    // flags, none of the flags are supported.
    //
    // See <https://sw.kovidgoyal.net/kitty/keyboard-protocol/#detection-of-support-for-this-protocol>

    // ESC [ ? u        Query progressive keyboard enhancement flags (kitty protocol).
    // ESC [ c          Query primary device attributes.
    const QUERY: &[u8] = b"\x1B[?u\x1B[c";

    let deadline = Instant::now() + Duration::from_millis(200);
    let result = File::open("/dev/tty").and_then(|mut file| {
        file.write_all(QUERY)?;
        file.flush()
    });
    if result.is_err() {
        let mut stdout = io::stdout();
        stdout.write_all(QUERY)?;
        stdout.flush()?;
    }

    if !poll_keyboard_reply(deadline, |remaining| {
        poll_internal(Some(remaining), &KeyboardEnhancementFlagsFilter)
    })? {
        return Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "The keyboard enhancement status could not be read within 200 ms",
        ));
    }
    match read_internal(&KeyboardEnhancementFlagsFilter)? {
        InternalEvent::KeyboardEnhancementFlags(_) => {
            // Flush DA1 only within the same deadline. Some terminals answer
            // Kitty but never send the trailing device-attributes reply.
            if poll_trailing_da1(deadline, |remaining| {
                poll_internal(Some(remaining), &PrimaryDeviceAttributesFilter)
            })? {
                read_internal(&PrimaryDeviceAttributesFilter)?;
            }
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// execute tput with the given argument and parse
/// the output as a u16.
///
/// The arg should be "cols" or "lines"
fn tput_value(arg: &str) -> Option<u16> {
    let output = process::Command::new("tput").arg(arg).output().ok()?;
    let value = output
        .stdout
        .into_iter()
        .filter_map(|b| char::from(b).to_digit(10))
        .fold(0, |v, n| v * 10 + n as u16);

    if value > 0 {
        Some(value)
    } else {
        None
    }
}

/// Returns the size of the screen as determined by tput.
///
/// This alternate way of computing the size is useful
/// when in a subshell.
fn tput_size() -> Option<(u16, u16)> {
    match (tput_value("cols"), tput_value("lines")) {
        (Some(w), Some(h)) => Some((w, h)),
        _ => None,
    }
}

#[cfg(feature = "libc")]
// Transform the given mode into an raw mode (non-canonical) mode.
fn raw_terminal_attr(termios: &mut Termios) {
    unsafe { cfmakeraw(termios) }
}

#[cfg(feature = "libc")]
fn get_terminal_attr(fd: RawFd) -> io::Result<Termios> {
    unsafe {
        let mut termios = mem::zeroed();
        wrap_with_result(tcgetattr(fd, &mut termios))?;
        Ok(termios)
    }
}

#[cfg(feature = "libc")]
fn set_terminal_attr(fd: RawFd, termios: &Termios) -> io::Result<()> {
    wrap_with_result(unsafe { tcsetattr(fd, TCSANOW, termios) })
}

#[cfg(feature = "libc")]
fn wrap_with_result(result: i32) -> io::Result<()> {
    if result == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

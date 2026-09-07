//! Optional xAI paste-code input. Owns a nonblocking /dev/tty handle; no stdin
//! worker survives cancellation, and terminal echo is restored on every exit.
use super::*;

pub(super) async fn code(provider: SubscriptionProvider) -> Result<String> {
    if provider != SubscriptionProvider::Xai {
        return std::future::pending().await;
    }
    #[cfg(unix)]
    {
        if let Ok(file) = open_terminal() {
            eprintln!(
                "If xAI shows a code instead of redirecting, paste it here and press Enter (input hidden)."
            );
            return read_from(file).await;
        }
    }
    // Without a local terminal, retain the bounded browser callback path.
    std::future::pending().await
}

#[cfg(unix)]
pub(super) fn open_terminal() -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    #[cfg(target_os = "macos")]
    let path = {
        use std::os::unix::ffi::OsStrExt;
        // Darwin's /dev/tty alias rejects kqueue registration (EINVAL). Resolve
        // the interactive stdin terminal to its concrete device instead.
        let mut name = [0u8; libc::PATH_MAX as usize];
        // SAFETY: writable PATH_MAX buffer; ttyname_r reports failure for non-TTY stdin.
        let result =
            unsafe { libc::ttyname_r(libc::STDIN_FILENO, name.as_mut_ptr().cast(), name.len()) };
        if result != 0 {
            return Err(std::io::Error::from_raw_os_error(result));
        }
        let name = std::ffi::CStr::from_bytes_until_nul(&name).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid terminal device name",
            )
        })?;
        std::path::PathBuf::from(std::ffi::OsStr::from_bytes(name.to_bytes()))
    };
    #[cfg(not(target_os = "macos"))]
    let path = std::path::PathBuf::from("/dev/tty");
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
}

#[cfg(unix)]
pub(super) async fn read_from(file: std::fs::File) -> Result<String> {
    use std::io::Read;
    use std::os::fd::AsRawFd;
    struct SilentTty {
        file: tokio::io::unix::AsyncFd<std::fs::File>,
        original: libc::termios,
    }
    impl Drop for SilentTty {
        fn drop(&mut self) {
            // SAFETY: the owned file remains open, and original came from tcgetattr.
            unsafe {
                libc::tcsetattr(
                    self.file.get_ref().as_raw_fd(),
                    libc::TCSANOW,
                    &self.original,
                );
            }
        }
    }
    let fd = file.as_raw_fd();
    let mut original = std::mem::MaybeUninit::<libc::termios>::uninit();
    // SAFETY: tcgetattr initializes the struct on success; fd is owned and live.
    if unsafe { libc::tcgetattr(fd, original.as_mut_ptr()) } != 0 {
        return Err(SubscriptionError::Terminal);
    }
    let original = unsafe { original.assume_init() };
    let mut hidden = original;
    hidden.c_lflag &= !(libc::ECHO | libc::ECHONL);
    let file = tokio::io::unix::AsyncFd::new(file).map_err(|_| SubscriptionError::Terminal)?;
    let tty = SilentTty { file, original };
    // SAFETY: valid terminal fd and initialized termios.
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &hidden) } != 0 {
        return Err(SubscriptionError::Terminal);
    }
    let mut input = Vec::new();
    loop {
        let mut ready = tty
            .file
            .readable()
            .await
            .map_err(|_| SubscriptionError::Terminal)?;
        let mut buffer = [0u8; 256];
        match ready.try_io(|fd| fd.get_ref().read(&mut buffer)) {
            Ok(Ok(0)) => return Err(SubscriptionError::Cancelled),
            Ok(Ok(n)) => {
                input.extend_from_slice(&buffer[..n]);
                if input.len() > 4096 {
                    return Err(SubscriptionError::Callback);
                }
                if input.contains(&b'\n') || input.contains(&b'\r') {
                    let code = std::str::from_utf8(&input)
                        .map_err(|_| SubscriptionError::Callback)?
                        .trim();
                    if code.is_empty()
                        || code.chars().any(char::is_whitespace)
                        || code.contains("://")
                    {
                        return Err(SubscriptionError::Callback);
                    }
                    return Ok(code.to_owned());
                }
            }
            Ok(Err(_)) => return Err(SubscriptionError::Terminal),
            Err(_) => continue,
        }
    }
}

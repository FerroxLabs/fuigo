// Ported from upstream 4247f661 `file_reader_tests.rs`, adapted to Fuigo's regular-file-only reader.
use super::*;
use crate::computer::{
    local::{LocalFs, MockFs},
    types::AsyncFileSystem,
};

#[tokio::test]
async fn whole_reads_preserve_large_sources() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("large");
    let bytes = vec![0x80; 8 * 1024 * 1024 + 1];
    tokio::fs::write(&path, &bytes).await.unwrap();
    assert_eq!(bytes, LocalFs.read_file(&path).await.unwrap());
    assert_eq!(bytes, read_regular_file(&path, None).await.unwrap());
}

#[tokio::test]
async fn bounded_reads_are_complete_or_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("source");
    tokio::fs::write(&path, b"abcd").await.unwrap();
    assert_eq!(
        b"abcd",
        LocalFs.read_file_bounded(&path, 4).await.unwrap().as_slice()
    );
    for (source, limit, kind) in [
        (path.as_path(), 3, io::ErrorKind::FileTooLarge),
        (path.as_path(), 0, io::ErrorKind::FileTooLarge),
        (dir.path(), 4, io::ErrorKind::IsADirectory),
    ] {
        assert_eq!(
            Some(kind),
            LocalFs
                .read_file_bounded(source, limit)
                .await
                .unwrap_err()
                .io_error_kind(),
            "{} limit {limit}",
            source.display()
        );
    }
    // usize::MAX cannot overflow the probe.
    assert_eq!(
        b"abcd",
        read_regular_file(&path, Some(usize::MAX)).await.unwrap().as_slice()
    );
    let mock = MockFs::new();
    mock.set_file(&path, b"abcd").await;
    assert_eq!(
        b"abcd",
        mock.read_file_bounded(&path, 4).await.unwrap().as_slice()
    );
    assert_eq!(
        Some(io::ErrorKind::FileTooLarge),
        mock.read_file_bounded(&path, 3)
            .await
            .unwrap_err()
            .io_error_kind()
    );
}

#[tokio::test]
async fn bounded_read_at_the_cap_succeeds_and_one_over_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("ten");
    tokio::fs::write(&path, vec![b'x'; 10]).await.unwrap();
    assert_eq!(
        io::ErrorKind::FileTooLarge,
        read_regular_file(&path, Some(9)).await.unwrap_err().kind()
    );
    assert_eq!(10, read_regular_file(&path, Some(10)).await.unwrap().len());
}

/// A source whose size is unknown to stat is still capped by the read itself.
/// procfs files report length 0 but yield content, the same shape as a file that grows after the stat.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn bounded_read_caps_bytes_not_just_the_stat() {
    let status = Path::new("/proc/self/status");
    assert_eq!(0, std::fs::metadata(status).unwrap().len());
    assert_eq!(
        io::ErrorKind::FileTooLarge,
        read_regular_file(status, Some(16)).await.unwrap_err().kind()
    );
    assert!(read_regular_file(status, None).await.unwrap().len() > 16);
}

/// The acquisition itself is capped: an endless source stops at `max + 1` bytes (Astra r1: the stat check alone hid this).
#[tokio::test]
async fn capped_read_stops_on_an_endless_source() {
    let read = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        read_capped(tokio::io::repeat(b'x'), 4096, 0),
    )
    .await
    .expect("capped read of an endless source must stop");
    assert_eq!(io::ErrorKind::FileTooLarge, read.unwrap_err().kind());
    assert_eq!(
        b"abcd",
        read_capped(&b"abcd"[..], 4, 0).await.unwrap().as_slice()
    );
}

/// `read_tool_source` takes the bounded path on a bounded backend and the plain read only on a backend without one.
#[tokio::test]
async fn read_tool_source_prefers_the_bounded_read() {
    use crate::computer::types::ComputerError;
    use crate::implementations::fuigo_build::read_file::read_tool_source;
    struct Bounded;
    #[async_trait::async_trait]
    impl AsyncFileSystem for Bounded {
        async fn read_file(&self, _: &Path) -> Result<Vec<u8>, ComputerError> {
            panic!("bounded backend must not take the unbounded read");
        }
        fn supports_bounded_read(&self) -> bool {
            true
        }
        async fn read_file_bounded(&self, _: &Path, max: usize) -> Result<Vec<u8>, ComputerError> {
            assert_eq!(
                max,
                crate::implementations::fuigo_build::read_file::MAX_READ_SOURCE_BYTES
            );
            Ok(b"bounded".to_vec())
        }
        async fn write_file(&self, _: &Path, _: &[u8]) -> Result<(), ComputerError> {
            Ok(())
        }
        async fn delete_file(&self, _: &Path) -> Result<(), ComputerError> {
            Ok(())
        }
    }
    struct Plain;
    #[async_trait::async_trait]
    impl AsyncFileSystem for Plain {
        async fn read_file(&self, _: &Path) -> Result<Vec<u8>, ComputerError> {
            Ok(b"plain".to_vec())
        }
        async fn write_file(&self, _: &Path, _: &[u8]) -> Result<(), ComputerError> {
            Ok(())
        }
        async fn delete_file(&self, _: &Path) -> Result<(), ComputerError> {
            Ok(())
        }
    }
    let path = Path::new("/x");
    assert_eq!(b"bounded", read_tool_source(&Bounded, path).await.unwrap().as_slice());
    assert_eq!(b"plain", read_tool_source(&Plain, path).await.unwrap().as_slice());
}

#[tokio::test]
async fn unsupported_backend_never_uses_unbounded_read() {
    struct Unsupported;
    #[async_trait::async_trait]
    impl AsyncFileSystem for Unsupported {
        async fn read_file(&self, _: &Path) -> Result<Vec<u8>, crate::computer::types::ComputerError> {
            panic!("unbounded fallback");
        }
        async fn write_file(
            &self,
            _: &Path,
            _: &[u8],
        ) -> Result<(), crate::computer::types::ComputerError> {
            Ok(())
        }
        async fn delete_file(&self, _: &Path) -> Result<(), crate::computer::types::ComputerError> {
            Ok(())
        }
    }
    assert!(!Unsupported.supports_bounded_read());
    assert!(LocalFs.supports_bounded_read());
    assert_eq!(
        Some(io::ErrorKind::Unsupported),
        Unsupported
            .read_file_bounded(Path::new("anywhere"), 4)
            .await
            .unwrap_err()
            .io_error_kind()
    );
}

#[cfg(unix)]
#[tokio::test]
async fn bounded_read_follows_ordinary_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("source");
    let link = dir.path().join("link");
    tokio::fs::write(&source, b"abcd").await.unwrap();
    std::os::unix::fs::symlink(source, &link).unwrap();
    assert_eq!(
        b"abcd",
        LocalFs.read_file_bounded(&link, 4).await.unwrap().as_slice()
    );
}

/// FIFOs, devices and sockets are refused by both the whole and the bounded read, without blocking.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn special_files_are_refused_without_blocking() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("pipe");
    nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::S_IRUSR | nix::sys::stat::Mode::S_IWUSR)
        .unwrap();
    let sock = dir.path().join("s.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&sock).unwrap();
    let fifo_link = dir.path().join("pipe-link");
    std::os::unix::fs::symlink(&fifo, &fifo_link).unwrap();
    for (path, kind) in [
        (fifo.as_path(), "FIFO"),
        (fifo_link.as_path(), "FIFO"),
        (Path::new("/dev/null"), "character device"),
        (Path::new("/dev/zero"), "character device"),
        (sock.as_path(), "socket"),
    ] {
        for bounded in [false, true] {
            let read = async {
                if bounded {
                    LocalFs.read_file_bounded(path, 1024).await
                } else {
                    LocalFs.read_file(path).await
                }
            };
            let result = tokio::time::timeout(std::time::Duration::from_secs(10), read).await;
            let Ok(result) = result else {
                let _ = std::fs::OpenOptions::new().write(true).open(&fifo);
                panic!("read of {} hung", path.display());
            };
            let error = result.unwrap_err();
            assert_eq!(
                Some(io::ErrorKind::InvalidInput),
                error.io_error_kind(),
                "{}",
                path.display()
            );
            let message = error.to_string();
            assert!(
                message.contains(NOT_REGULAR_FILE) && message.contains(kind),
                "{}: {message}",
                path.display()
            );
        }
    }
}

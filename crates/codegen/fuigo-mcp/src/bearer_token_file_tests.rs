//! `bearer_token_file`: the file checks (rule 2), the value kept out of errors and `Debug` (rule 3), the URL policy
//! (rule 4) and re-reading per request (rule 5). Fake tokens only.

use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use super::*;

const TOKEN: &str = "fake-token-AbC123-not-real";

fn write(dir: &Path, name: &str, bytes: &[u8], mode: u32) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    path
}

fn read(path: &Path) -> Result<String, BearerTokenFileError> {
    read_token_sync(path)
}

#[test]
fn an_owner_only_regular_file_is_read_and_one_trailing_newline_dropped() {
    let dir = tempfile::tempdir().unwrap();
    for (mode, body) in [(0o600, format!("{TOKEN}\n")), (0o400, format!("{TOKEN}\r\n")), (0o600, TOKEN.to_owned())] {
        let path = write(dir.path(), "tok", body.as_bytes(), 0o600);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(read(&path).as_deref(), Ok(TOKEN), "mode {mode:o}, body {body:?}");
    }
}

#[test]
fn a_symlink_is_refused_even_to_a_good_file() {
    let dir = tempfile::tempdir().unwrap();
    let real = write(dir.path(), "real", TOKEN.as_bytes(), 0o600);
    let link = dir.path().join("link");
    symlink(&real, &link).unwrap();
    assert_eq!(read(&link), Err(BearerTokenFileError::Symlink));
}

#[test]
fn group_or_other_permission_bits_refuse_the_file() {
    let dir = tempfile::tempdir().unwrap();
    for mode in [0o640, 0o604, 0o660, 0o644, 0o601, 0o610, 0o700 | 0o010] {
        let path = write(dir.path(), "tok", TOKEN.as_bytes(), mode);
        assert_eq!(read(&path), Err(BearerTokenFileError::TooPermissive), "mode {mode:o}");
    }
}

#[test]
fn a_file_over_16_kib_is_refused_and_exactly_16_kib_is_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let big = write(dir.path(), "big", &vec![b'a'; 16 * 1024 + 1], 0o600);
    assert_eq!(read(&big), Err(BearerTokenFileError::TooLarge));
    let max = write(dir.path(), "max", &vec![b'a'; 16 * 1024], 0o600);
    assert_eq!(read(&max).map(|t| t.len()), Ok(16 * 1024));
}

#[test]
fn a_directory_and_a_fifo_are_not_regular_files() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(read(dir.path()), Err(BearerTokenFileError::NotRegular));
    let fifo = dir.path().join("fifo");
    let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    // SAFETY: `c` is a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    // Must return at once (O_NONBLOCK), not wait for a writer.
    assert_eq!(read(&fifo), Err(BearerTokenFileError::NotRegular));
}

#[test]
fn a_file_owned_by_someone_else_is_refused() {
    // Only root can give a file away; elsewhere the case cannot be built.
    // SAFETY: `geteuid` has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipped: not running as root, cannot create a file owned by another user");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "tok", TOKEN.as_bytes(), 0o600);
    let c = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    // SAFETY: valid path; uid 12345 is arbitrary.
    assert_eq!(unsafe { libc::chown(c.as_ptr(), 12345, 12345) }, 0);
    assert_eq!(read(&path), Err(BearerTokenFileError::WrongOwner));
}

#[test]
fn control_characters_whitespace_and_non_ascii_inside_the_token_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    for body in [
        "abc def\n".as_bytes(),
        b"abc\tdef",
        b"abc\ndef",
        b"abc\x00def",
        b"abc\x1b[31mdef",
        b"tok\n\n",
        " tok".as_bytes(),
        "caf\u{e9}".as_bytes(),
        b"tok\xff",
    ] {
        let path = write(dir.path(), "tok", body, 0o600);
        assert_eq!(read(&path), Err(BearerTokenFileError::BadCharacters), "{body:?}");
    }
    // Shorter than the scrubber's floor: refused with a fixed reason, so every accepted token is redacted.
    for body in [&b"a"[..], b"short\n", b"1234567890abcde\n"] {
        let path = write(dir.path(), "short", body, 0o600);
        let error = read(&path).unwrap_err();
        assert_eq!(error, BearerTokenFileError::TooShort, "{body:?}");
        assert_eq!(error.to_string(), "token too short");
    }
    assert!(read(&write(dir.path(), "min", b"1234567890abcdef\n", 0o600)).is_ok());
    for body in [&b""[..], b"\n", b"\r\n"] {
        let path = write(dir.path(), "empty", body, 0o600);
        assert_eq!(read(&path), Err(BearerTokenFileError::Empty), "{body:?}");
    }
}

#[test]
fn a_missing_file_is_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(read(&dir.path().join("nope")), Err(BearerTokenFileError::Unreadable));
}

#[test]
fn no_error_text_holds_the_token_or_the_path() {
    let dir = tempfile::tempdir().unwrap();
    let secret_named = format!("{TOKEN} secret");
    let path = write(dir.path(), "secret-file-name", secret_named.as_bytes(), 0o640);
    let mut texts = vec![read(&path).unwrap_err().to_string()];
    let bad = write(dir.path(), "bad", secret_named.as_bytes(), 0o600);
    texts.push(read(&bad).unwrap_err().to_string());
    for text in texts {
        assert!(!text.contains(TOKEN) && !text.contains("secret-file-name"), "{text}");
    }
}

#[test]
fn path_rules_absolute_or_home_relative_with_no_expansion() {
    let home = Path::new("/home/someone");
    let ok = BearerTokenPath::parse("~/.config/tok", Some(home)).unwrap();
    assert_eq!(ok.as_ref(), Path::new("/home/someone/.config/tok"));
    assert!(BearerTokenPath::parse("/run/tok", None).is_ok());
    for relative in ["tok", "./tok", "../tok", "", "~", "~/", "~user/tok", "$HOME/tok", "${HOME}/tok", "%USERPROFILE%/tok"] {
        assert_eq!(BearerTokenPath::parse(relative, Some(home)), Err(BearerTokenFileError::NotAbsolute), "{relative:?}");
    }
    assert_eq!(BearerTokenPath::parse("~/tok", None), Err(BearerTokenFileError::NoHomeDir));
}

#[test]
fn the_token_travels_only_over_https_or_http_to_this_machine() {
    for ok in ["https://mcp.example.com/mcp", "http://127.0.0.1:9/mcp", "http://127.5.5.5/mcp", "http://[::1]:9/mcp", "https://localhost/mcp"] {
        assert_eq!(check_url_may_carry_token(ok), Ok(()), "{ok}");
    }
    for bad in ["http://mcp.example.com/mcp", "http://10.0.0.5/mcp", "http://localhost:9/mcp", "http://LOCALHOST/mcp", "http://127.0.0.1.evil.example/mcp", "ftp://x/y", "nonsense"] {
        assert_eq!(check_url_may_carry_token(bad), Err(BearerTokenFileError::InsecureUrl), "{bad}");
    }
}

#[test]
fn meta_must_be_a_string_and_absent_means_none() {
    assert_eq!(configured_from_meta(None), Ok(None));
    let meta = bearer_token_file_meta("/run/tok");
    assert_eq!(configured_from_meta(Some(&meta)), Ok(Some("/run/tok".to_owned())));
    let bad = acp::Meta::from_iter([(META_KEY.to_owned(), serde_json::json!(7))]);
    assert_eq!(configured_from_meta(Some(&bad)), Err(BearerTokenFileError::NotAString));
}

#[tokio::test]
async fn every_read_checks_again_so_rotation_applies_and_a_bad_file_fails_the_request() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "tok", b"first-fake-token-1\n", 0o600);
    let file = BearerTokenFile::new(BearerTokenPath::parse(path.to_str().unwrap(), None).unwrap());
    assert_eq!(file.read().await.as_deref(), Ok("first-fake-token-1"));
    std::fs::write(&path, b"second-fake-token-2\n").unwrap();
    assert_eq!(file.read().await.as_deref(), Ok("second-fake-token-2"), "rotation is picked up");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(file.read().await, Err(BearerTokenFileError::TooPermissive), "the checks run on every read");
    std::fs::remove_file(&path).unwrap();
    assert_eq!(file.read().await, Err(BearerTokenFileError::Unreadable), "a vanished file fails, nothing is reused");
}

#[tokio::test]
async fn debug_shows_the_path_never_the_token_and_the_token_is_registered_with_the_scrubber() {
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "tok", format!("{TOKEN}\n").as_bytes(), 0o600);
    let file = BearerTokenFile::new(BearerTokenPath::parse(path.to_str().unwrap(), None).unwrap());
    let before = format!("{file:?}");
    assert!(before.contains("tok"), "{before}");
    assert_eq!(file.read().await.as_deref(), Ok(TOKEN));
    assert!(!format!("{file:?}").contains(TOKEN));
    let echoed = format!("upstream said: bad credential {TOKEN}");
    let scrubbed = fuigo_telemetry::sent_credentials::scrub(&echoed);
    assert!(!scrubbed.contains(TOKEN), "{scrubbed}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_read_times_out_and_later_reads_fail_fast() {
    // A read that outlives the timeout is simulated by holding the slot with a job that does not finish.
    let dir = tempfile::tempdir().unwrap();
    let path = write(dir.path(), "tok", b"fake-token-12345\n", 0o600);
    let file = BearerTokenFile::new(BearerTokenPath::parse(path.to_str().unwrap(), None).unwrap())
        .with_timeout(Duration::from_millis(50));
    let (release, wait) = std::sync::mpsc::channel::<()>();
    *file.stalled_read.lock() = Some(tokio::task::spawn_blocking(move || {
        let _ = wait.recv();
        Err(BearerTokenFileError::Unreadable)
    }));
    assert_eq!(file.clone().read().await, Err(BearerTokenFileError::TimedOut));
    drop(release);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(file.read().await.as_deref(), Ok("fake-token-12345"), "the slot frees once the stalled read returns");
}

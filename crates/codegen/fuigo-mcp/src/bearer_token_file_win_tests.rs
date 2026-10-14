//! `bearer_token_file` on Windows: the file rule (owner, ACL, inherited ACEs, links, reparse points, size, kind), the
//! path rules, the messages, and re-reading per request. Files only: no pipe, no network, no real user profile (every
//! file lives in a temp dir). Fake tokens only. Owner-only files are created WITH their DACL (`fuigo-win-acl`
//! `test-support`), not repaired afterwards and not with `icacls`.
//!
//! The test user is a normal (non-elevated) user, so the "owner is BUILTIN\Administrators when elevated" arm is not
//! exercised here; it is covered by the pure policy tests in `fuigo-win-acl`.

use std::path::{Path, PathBuf};

use fuigo_win_acl::test_support::{
    create_dir_inheriting_owner_only, create_dir_inheriting_read_for, write_file_also_readable_by, write_owner_only_file,
};

use super::*;

const TOKEN: &str = "fake-token-AbC123-not-real";

fn owner_only(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.join(name);
    write_owner_only_file(&path, bytes).unwrap();
    path
}

fn read(path: &Path) -> Result<String, BearerTokenFileError> {
    read_token_sync(path)
}

#[test]
fn an_owner_only_file_is_read_and_one_trailing_newline_dropped() {
    let dir = tempfile::tempdir().unwrap();
    for (i, body) in [format!("{TOKEN}\n"), format!("{TOKEN}\r\n"), TOKEN.to_owned()].iter().enumerate() {
        let path = owner_only(dir.path(), &format!("tok{i}"), body.as_bytes());
        assert_eq!(read(&path).as_deref(), Ok(TOKEN), "body {body:?}");
    }
}

#[test]
fn a_file_in_a_folder_that_grants_only_us_is_accepted() {
    // The control for the inheritance test below: an inherited entry for us alone is fine.
    let dir = tempfile::tempdir().unwrap();
    let folder = dir.path().join("mine");
    create_dir_inheriting_owner_only(&folder).unwrap();
    let path = folder.join("tok");
    std::fs::write(&path, TOKEN).unwrap();
    assert_eq!(read(&path).as_deref(), Ok(TOKEN));
}

#[test]
fn an_extra_allow_entry_for_users_or_everyone_refuses_the_file_and_the_text_names_the_fix_and_the_path() {
    let dir = tempfile::tempdir().unwrap();
    for (name, trustee) in [("users", "BU"), ("everyone", "WD"), ("authenticated", "AU")] {
        let path = dir.path().join(name);
        write_file_also_readable_by(&path, format!("{TOKEN}\n").as_bytes(), trustee).unwrap();
        let error = read(&path).unwrap_err();
        assert_eq!(error, BearerTokenFileError::TooPermissive, "{trustee}");
        let text = refusal_text(&error, &path);
        assert!(text.contains(&format!("remove access for other users from {}", path.display())), "{text}");
        assert!(!text.contains(TOKEN) && !error.to_string().contains(TOKEN), "{text}");
    }
}

#[test]
fn an_entry_inherited_from_the_folder_refuses_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let folder = dir.path().join("shared");
    create_dir_inheriting_read_for(&folder, "BU").unwrap();
    // Created with default security: the file gets the folder's inheritable entries, including the one for Users.
    let path = folder.join("tok");
    std::fs::write(&path, format!("{TOKEN}\n")).unwrap();
    assert_eq!(read(&path), Err(BearerTokenFileError::TooPermissive));
}

#[test]
fn over_16_kib_is_refused_and_exactly_16_kib_is_allowed() {
    let dir = tempfile::tempdir().unwrap();
    let big = owner_only(dir.path(), "big", &vec![b'a'; 16 * 1024 + 1]);
    assert_eq!(read(&big), Err(BearerTokenFileError::TooLarge));
    let max = owner_only(dir.path(), "max", &vec![b'a'; 16 * 1024]);
    assert_eq!(read(&max).map(|t| t.len()), Ok(16 * 1024));
}

#[test]
fn a_directory_is_not_a_regular_file() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(read(dir.path()), Err(BearerTokenFileError::NotRegular));
}

#[test]
fn a_second_hard_link_refuses_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = owner_only(dir.path(), "tok", TOKEN.as_bytes());
    assert_eq!(read(&path).as_deref(), Ok(TOKEN));
    let link = dir.path().join("second-name");
    std::fs::hard_link(&path, &link).unwrap();
    assert_eq!(read(&path), Err(BearerTokenFileError::MultipleLinks));
    assert_eq!(read(&link), Err(BearerTokenFileError::MultipleLinks));
    let text = refusal_text(&BearerTokenFileError::MultipleLinks, &path);
    assert!(text.contains(&path.display().to_string()), "{text}");
}

#[test]
fn a_symlink_is_refused_even_to_a_good_file() {
    let dir = tempfile::tempdir().unwrap();
    let real = owner_only(dir.path(), "real", TOKEN.as_bytes());
    let link = dir.path().join("link");
    if let Err(error) = std::os::windows::fs::symlink_file(&real, &link) {
        // Creating a symlink needs the SeCreateSymbolicLink privilege or Developer Mode. Not a failure of the code under test.
        eprintln!("skipped: cannot create symlinks without the privilege ({})", error.kind());
        return;
    }
    assert_eq!(read(&link), Err(BearerTokenFileError::Symlink));
    assert_eq!(read(&real).as_deref(), Ok(TOKEN), "the target itself is still fine");
}

#[test]
fn content_rules_match_unix() {
    let dir = tempfile::tempdir().unwrap();
    for (i, body) in
        ["abc def\n".as_bytes(), b"abc\tdef", b"abc\ndef", b"abc\x00def", b"tok\n\n", " tok".as_bytes(), "caf\u{e9}".as_bytes(), b"tok\xff"].iter().enumerate()
    {
        let path = owner_only(dir.path(), &format!("bad{i}"), body);
        assert_eq!(read(&path), Err(BearerTokenFileError::BadCharacters), "{body:?}");
    }
    for (i, body) in [&b"a"[..], b"short\n", b"1234567890abcde\n"].iter().enumerate() {
        let path = owner_only(dir.path(), &format!("short{i}"), body);
        let error = read(&path).unwrap_err();
        assert_eq!(error, BearerTokenFileError::TooShort, "{body:?}");
        assert_eq!(error.to_string(), "token too short");
    }
    assert!(read(&owner_only(dir.path(), "min", b"1234567890abcdef\n")).is_ok());
    for (i, body) in [&b""[..], b"\n", b"\r\n"].iter().enumerate() {
        let path = owner_only(dir.path(), &format!("empty{i}"), body);
        assert_eq!(read(&path), Err(BearerTokenFileError::Empty), "{body:?}");
    }
}

#[test]
fn a_missing_file_is_unreadable_and_no_error_holds_the_token() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(read(&dir.path().join("nope")), Err(BearerTokenFileError::Unreadable));
    let secret = format!("{TOKEN} secret");
    let path = dir.path().join("secret-file-name");
    write_file_also_readable_by(&path, secret.as_bytes(), "BU").unwrap();
    let error = read(&path).unwrap_err();
    // `Display` and `Debug` of the error never hold the content; `refusal_text` adds the path (a config value) only.
    assert!(!error.to_string().contains(TOKEN) && !format!("{error:?}").contains(TOKEN));
    assert!(!refusal_text(&error, &path).contains(TOKEN));
}

#[test]
fn device_pipe_network_and_stream_paths_are_refused_before_anything_is_opened() {
    for bad in [r"\\.\pipe\fake-not-a-server", r"\\.\NUL", r"\\?\C:\fake\tok", r"\\fake-host\share\tok", r"C:\fake\NUL", r"C:\fake\tok:stream"] {
        assert_eq!(BearerTokenPath::parse(bad, None), Err(BearerTokenFileError::UnsupportedPath), "{bad}");
    }
    assert!(BearerTokenPath::parse(r"C:\fake\tok", None).is_ok());
    assert!(BearerTokenPath::parse("C:/fake/tok", None).is_ok());
    for relative in ["tok", r".\tok", r"..\tok", r"\tok", "%USERPROFILE%/tok"] {
        assert_eq!(BearerTokenPath::parse(relative, None), Err(BearerTokenFileError::NotAbsolute), "{relative}");
    }
    let home = Path::new(r"C:\Users\fake");
    assert_eq!(BearerTokenPath::parse("~/.config/tok", Some(home)).unwrap().as_ref(), Path::new(r"C:\Users\fake\.config/tok"));
}

#[test]
fn a_device_that_gets_past_the_path_rules_is_refused_without_blocking() {
    // Straight to the open-and-judge step, skipping the path rules: the NUL device does not pass as a disk file (the
    // checker fails closed with the generic reason) and nothing is read. A pipe path with no server is simply not found. Both return at once.
    assert_eq!(windows_rules::open_judged(Path::new(r"\\.\NUL")).map(drop), Err(BearerTokenFileError::Unreadable));
    assert_eq!(windows_rules::open_judged(Path::new(r"\\.\pipe\fake-not-a-server")).map(drop), Err(BearerTokenFileError::Unreadable));
}

#[test]
fn the_sync_read_and_preflight_apply_the_path_rules_themselves() {
    for bad in [r"\\.\NUL", r"\\.\pipe\fake-not-a-server", r"C:\fake-dir\NUL", r"C:\fake-dir\com1.txt", r"\\server\share\tok", r"C:\fake\tok:stream"] {
        assert_eq!(read(Path::new(bad)), Err(BearerTokenFileError::UnsupportedPath), "{bad}");
        assert_eq!(windows_rules::open_checked(Path::new(bad)).map(drop), Err(BearerTokenFileError::UnsupportedPath), "{bad}");
    }
}

#[test]
fn preflight_refuses_a_shared_file_and_lets_a_missing_one_through() {
    let dir = tempfile::tempdir().unwrap();
    let parse = |p: &Path| BearerTokenPath::parse(p.to_str().unwrap(), None).unwrap();
    assert_eq!(preflight(&parse(&owner_only(dir.path(), "ok", TOKEN.as_bytes()))), Ok(()));
    let shared = dir.path().join("shared");
    write_file_also_readable_by(&shared, TOKEN.as_bytes(), "BU").unwrap();
    assert_eq!(preflight(&parse(&shared)), Err(BearerTokenFileError::TooPermissive));
    assert_eq!(preflight(&parse(&dir.path().join("not-yet"))), Ok(()));
}

#[tokio::test]
async fn every_read_checks_again_so_rotation_applies_and_a_bad_file_fails_the_request() {
    let dir = tempfile::tempdir().unwrap();
    let path = owner_only(dir.path(), "tok", b"first-fake-token-1\n");
    let file = BearerTokenFile::new(BearerTokenPath::parse(path.to_str().unwrap(), None).unwrap());
    assert_eq!(file.read().await.as_deref(), Ok("first-fake-token-1"));
    // Rewrite in place (keeps the owner-only DACL): the next read returns the new token.
    std::fs::write(&path, b"second-fake-token-2\n").unwrap();
    assert_eq!(file.read().await.as_deref(), Ok("second-fake-token-2"), "rotation is picked up");
    // Replace the file by rename (what a rotating agent usually does) with a new owner-only file.
    let next = owner_only(dir.path(), "tok.new", b"third-fake-token-3\n");
    std::fs::rename(&next, &path).unwrap();
    assert_eq!(file.read().await.as_deref(), Ok("third-fake-token-3"), "a rename over the file is picked up");
    // Replace it by a file others can read: the very next request is refused, nothing cached.
    std::fs::remove_file(&path).unwrap();
    write_file_also_readable_by(&path, b"fourth-fake-token-4\n", "BU").unwrap();
    let error = file.read().await.unwrap_err();
    assert_eq!(error, BearerTokenFileError::TooPermissive);
    assert!(file.refusal_text(&error).contains("remove access for other users from"));
    std::fs::remove_file(&path).unwrap();
    assert_eq!(file.read().await, Err(BearerTokenFileError::Unreadable), "a vanished file fails, nothing is reused");
}

#[tokio::test]
async fn debug_shows_the_path_never_the_token_and_the_token_is_registered_with_the_scrubber() {
    let dir = tempfile::tempdir().unwrap();
    let path = owner_only(dir.path(), "tok", format!("{TOKEN}\n").as_bytes());
    let file = BearerTokenFile::new(BearerTokenPath::parse(path.to_str().unwrap(), None).unwrap());
    assert_eq!(file.read().await.as_deref(), Ok(TOKEN));
    assert!(!format!("{file:?}").contains(TOKEN));
    let echoed = format!("upstream said: bad credential {TOKEN}");
    let scrubbed = fuigo_telemetry::sent_credentials::scrub(&echoed);
    assert!(!scrubbed.contains(TOKEN), "{scrubbed}");
}

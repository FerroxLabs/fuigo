use super::*;

/// The file renamed into place must be the inode the writer created: one swapped in under the
/// temp's name is removed and the write refused, leaving no file behind; an undisturbed write
/// lands with the requested mode.
#[cfg(unix)]
#[test]
fn write_atomically_verified_never_keeps_a_file_swapped_in_under_the_temp_name() {
    use std::os::unix::fs::PermissionsExt as _;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("grants.toml");
    let forged = dir.path().join("forged.toml");

    write_atomically_verified(&path, "[[grant]]\n", Some(0o600)).expect("undisturbed write");
    assert_eq!("[[grant]]\n", std::fs::read_to_string(&path).expect("read"));
    let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
    assert_eq!(0o600, mode & 0o777);

    let swaps = std::rc::Rc::new(std::cell::Cell::new(0));
    let hook_swaps = std::rc::Rc::clone(&swaps);
    let hook_forged = forged.clone();
    BEFORE_VERIFIED_RENAME.set(Some(Box::new(move |tmp: &Path| {
        hook_swaps.set(hook_swaps.get() + 1);
        std::fs::write(&hook_forged, "forged = true\n").expect("forge");
        std::fs::rename(&hook_forged, tmp).expect("swap");
    })));
    let refused = write_atomically_verified(&path, "[[grant]]\n", Some(0o600));
    BEFORE_VERIFIED_RENAME.set(None);

    assert_eq!(
        std::io::ErrorKind::InvalidData,
        refused.expect_err("swap").kind()
    );
    assert_eq!(1, swaps.get());
    assert!(!path.exists(), "the swapped-in file is gone");
    let left: Vec<_> = std::fs::read_dir(dir.path())
        .expect("dir")
        .flatten()
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

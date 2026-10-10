//! P176: [`PinnedDir`], the folders the session sweep works in.

use std::ffi::OsStr;

use tempfile::TempDir;

use super::{EntryKind, PinnedDir};

#[cfg(unix)]
#[test]
fn a_link_is_never_opened_as_a_folder() {
    let tmp = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    std::os::unix::fs::symlink(outside.path(), tmp.path().join("link")).unwrap();
    std::fs::write(tmp.path().join("file"), b"x").unwrap();
    let root = PinnedDir::open_root(tmp.path()).unwrap();

    assert!(root.open_child(OsStr::new("link")).is_err());
    assert!(root.open_child(OsStr::new("file")).is_err());
    assert_eq!(EntryKind::Other, root.child_info(OsStr::new("link")).unwrap().kind);
    assert_eq!(EntryKind::File, root.child_info(OsStr::new("file")).unwrap().kind);
}

/// The root's own path may be a link (a `~/.fuigo` that lives elsewhere); it is followed and still counts as in place.
#[cfg(unix)]
#[test]
fn the_root_may_be_reached_through_a_link() {
    let tmp = TempDir::new().unwrap();
    std::fs::create_dir(tmp.path().join("real")).unwrap();
    std::os::unix::fs::symlink(tmp.path().join("real"), tmp.path().join("root")).unwrap();
    let root = PinnedDir::open_root(&tmp.path().join("root")).unwrap();
    assert!(root.still_at_path());
}

#[cfg(unix)]
#[test]
fn a_swapped_folder_is_no_longer_at_its_path() {
    let tmp = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    std::fs::create_dir(tmp.path().join("cwd")).unwrap();
    let root = PinnedDir::open_root(tmp.path()).unwrap();
    let cwd = root.open_child(OsStr::new("cwd")).unwrap();
    assert!(cwd.still_at_path());

    std::fs::rename(tmp.path().join("cwd"), tmp.path().join("moved")).unwrap();
    std::os::unix::fs::symlink(outside.path(), tmp.path().join("cwd")).unwrap();
    assert!(!cwd.still_at_path());

    // The pin still names the real folder: what it lists is the moved folder's content
    std::fs::write(tmp.path().join("moved/inside"), b"x").unwrap();
    assert_eq!(vec![OsStr::new("inside").to_os_string()], cwd.entry_names().unwrap());
}

/// A tree is removed without following any link in it: a link's target survives.
#[cfg(unix)]
#[test]
fn removing_a_tree_never_follows_a_link_in_it() {
    let tmp = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    std::fs::write(outside.path().join("keep"), b"x").unwrap();
    let tree = tmp.path().join("tree");
    std::fs::create_dir_all(tree.join("a/b")).unwrap();
    std::fs::write(tree.join("a/b/f"), b"x").unwrap();
    std::os::unix::fs::symlink(outside.path(), tree.join("a/link")).unwrap();
    let root = PinnedDir::open_root(tmp.path()).unwrap();

    root.remove_child_tree(OsStr::new("tree")).unwrap();

    assert!(!tree.exists());
    assert!(outside.path().join("keep").is_file());
}

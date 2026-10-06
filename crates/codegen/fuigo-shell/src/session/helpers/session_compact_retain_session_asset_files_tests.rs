use std::path::{Path, PathBuf};

use super::{
    MAX_COMPACTION_IMAGE_PATH_PROBES, MAX_COMPACTION_IMAGE_PATHS, retain_session_asset_files,
};

fn path_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// `<root>/<cwd>/<session>/assets`, created, as `persist_user_images` lays it out.
fn session_assets(root: &Path, cwd: &str, session: &str) -> PathBuf {
    let assets = root.join(cwd).join(session).join("assets");
    std::fs::create_dir_all(&assets).unwrap();
    assets
}

/// `count` regular files inside `assets`, named in chronological order.
fn write_assets(assets: &Path, count: usize) -> Vec<String> {
    (0..count)
        .map(|i| {
            let file = assets.join(format!("image-{i:03}.png"));
            std::fs::write(&file, b"png").unwrap();
            path_string(&file)
        })
        .collect()
}

#[tokio::test]
async fn keeps_the_newest_assets_up_to_the_cap() {
    let root = tempfile::tempdir().unwrap();
    let assets = session_assets(root.path(), "cwd", "s1");
    let real = write_assets(&assets, MAX_COMPACTION_IMAGE_PATHS + 1);

    let (kept, dropped) = retain_session_asset_files(real.clone(), root.path()).await;

    assert_eq!(kept, real.get(1..).unwrap_or_default());
    assert_eq!(dropped, 1);
}

/// Junk newer than the real assets must not use up the cap.
#[tokio::test]
async fn newer_junk_does_not_consume_the_cap() {
    let root = tempfile::tempdir().unwrap();
    let assets = session_assets(root.path(), "cwd", "s1");
    let real = write_assets(&assets, 5);
    let junk: Vec<String> = (0..37)
        .map(|i| path_string(&assets.join(format!("gone-{i}.png"))))
        .chain(["/etc/passwd", "/etc/hostname", "/etc/hosts"].map(str::to_owned))
        .collect();
    let paths: Vec<String> = real.iter().cloned().chain(junk).collect();

    let (kept, dropped) = retain_session_asset_files(paths, root.path()).await;

    assert_eq!(kept, real);
    assert_eq!(dropped, 40);
}

/// Mutant discriminated: an attempt counter that only counts kept files (the pre-fix claim).
/// A planted run of missing but lexically valid entries costs a bounded number of filesystem calls: once
/// [`MAX_COMPACTION_IMAGE_PATH_PROBES`] candidates have been examined the scan stops, so a real asset older than
/// that many junk entries is not reached, while one probe fewer still reaches it.
#[tokio::test]
async fn filesystem_probes_are_bounded_by_candidates_not_by_kept_files() {
    let root = tempfile::tempdir().unwrap();
    let assets = session_assets(root.path(), "cwd", "s1");
    let real = write_assets(&assets, 1);
    let junk = |n: usize| -> Vec<String> {
        (0..n)
            .map(|i| path_string(&assets.join(format!("gone-{i}.png"))))
            .collect()
    };

    let within: Vec<String> = real
        .iter()
        .cloned()
        .chain(junk(MAX_COMPACTION_IMAGE_PATH_PROBES - 1))
        .collect();
    let (kept, _) = retain_session_asset_files(within, root.path()).await;
    assert_eq!(kept, real, "the last probe still reaches the real asset");

    let beyond: Vec<String> = real
        .iter()
        .cloned()
        .chain(junk(MAX_COMPACTION_IMAGE_PATH_PROBES))
        .collect();
    let total = beyond.len();
    let (kept, dropped) = retain_session_asset_files(beyond, root.path()).await;
    assert!(kept.is_empty(), "probing stops at the bound");
    assert_eq!(dropped, total);
}

/// Mutant discriminated: the pre-fix filter that accepted only this session's own `assets/` dir.
/// A fork's transcript still names its parent's `assets/`; those files are real and must survive the fork's compaction.
#[tokio::test]
async fn a_fork_keeps_the_images_its_parent_attached() {
    let root = tempfile::tempdir().unwrap();
    let parent_assets = session_assets(root.path(), "cwd", "parent");
    let _fork_assets = session_assets(root.path(), "cwd", "fork");
    // A fork into another cwd lands under another `<cwd>` dir; the parent's paths still qualify.
    let _other_cwd_fork = session_assets(root.path(), "other-cwd", "fork2");
    let inherited = write_assets(&parent_assets, 2);

    let (kept, dropped) = retain_session_asset_files(inherited.clone(), root.path()).await;

    assert_eq!(kept, inherited);
    assert_eq!(dropped, 0);
}

/// Only `<root>/<cwd>/<session>/assets/<file>` qualifies, and only for a regular file.
#[tokio::test]
async fn keeps_only_regular_files_directly_inside_a_session_assets_dir() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let assets = session_assets(root.path(), "cwd", "s1");
    let inside = assets.join("image-1.png");
    std::fs::write(&inside, b"png").unwrap();
    let outside = elsewhere.path().join("image-2.png");
    std::fs::write(&outside, b"png").unwrap();
    let directory = assets.join("nested");
    std::fs::create_dir(&directory).unwrap();
    let missing = assets.join("gone.png");
    let nested_dir = assets.join("sub");
    std::fs::create_dir(&nested_dir).unwrap();
    let nested = nested_dir.join("x.png");
    std::fs::write(&nested, b"png").unwrap();
    // A session file outside `assets/`.
    let not_assets = root.path().join("cwd").join("s1").join("summary.png");
    std::fs::write(&not_assets, b"png").unwrap();
    // A directory named `assets` at the wrong depth.
    let shallow_assets = root.path().join("cwd").join("assets");
    std::fs::create_dir_all(&shallow_assets).unwrap();
    let shallow = shallow_assets.join("x.png");
    std::fs::write(&shallow, b"png").unwrap();
    // Resolves into the assets dir, but only through `..`.
    let dotdot = assets.join("..").join("assets").join("image-1.png");

    let (kept, dropped) = retain_session_asset_files(
        vec![
            path_string(&inside),
            path_string(&outside),
            path_string(&directory),
            path_string(&missing),
            path_string(&dotdot),
            path_string(&nested),
            path_string(&not_assets),
            path_string(&shallow),
            "relative/image-1.png".to_owned(),
        ],
        root.path(),
    )
    .await;

    assert_eq!(kept, vec![path_string(&inside)]);
    assert_eq!(dropped, 8);
}

/// Symlinks at any level are refused: the file itself, the `assets/` dir, and the session dir.
/// Unix-only: creating symlinks on Windows needs a privilege the test cannot assume.
#[cfg(unix)]
#[tokio::test]
async fn symlinks_never_launder_an_outside_file() {
    let root = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let assets = session_assets(root.path(), "cwd", "s1");
    let inside = assets.join("image-1.png");
    std::fs::write(&inside, b"png").unwrap();
    let outside = elsewhere.path().join("image-2.png");
    std::fs::write(&outside, b"png").unwrap();
    let link_inside = assets.join("link-inside.png");
    std::os::unix::fs::symlink(&inside, &link_inside).unwrap();
    let link_outside = assets.join("link-outside.png");
    std::os::unix::fs::symlink(&outside, &link_outside).unwrap();
    // A symlinked `assets/` dir inside an otherwise real session.
    let s2 = root.path().join("cwd").join("s2");
    std::fs::create_dir_all(&s2).unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), s2.join("assets")).unwrap();
    let through_assets_link = s2.join("assets").join("image-2.png");
    // A symlinked session dir whose `assets/` is a real dir elsewhere.
    let outside_session = tempfile::tempdir().unwrap();
    let outside_assets = outside_session.path().join("assets");
    std::fs::create_dir_all(&outside_assets).unwrap();
    std::fs::write(outside_assets.join("image-3.png"), b"png").unwrap();
    std::os::unix::fs::symlink(outside_session.path(), root.path().join("cwd").join("s3")).unwrap();
    let through_session_link = root
        .path()
        .join("cwd")
        .join("s3")
        .join("assets")
        .join("image-3.png");

    let (kept, dropped) = retain_session_asset_files(
        vec![
            path_string(&inside),
            path_string(&link_inside),
            path_string(&link_outside),
            path_string(&through_assets_link),
            path_string(&through_session_link),
        ],
        root.path(),
    )
    .await;

    assert_eq!(kept, vec![path_string(&inside)]);
    assert_eq!(dropped, 4);
}

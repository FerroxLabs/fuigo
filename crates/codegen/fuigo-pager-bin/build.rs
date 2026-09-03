use std::path::Path;
use std::process::Command;

fn git_stdout(args: &[&str]) -> Option<String> {
    Command::new("git")
        .args(args)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
}

fn main() {
    println!("cargo:rerun-if-env-changed=FUIGO_VERSION");
    println!("cargo:rerun-if-changed={}", version_manifest().display());

    // Watch the git files that change on commit/checkout so the version stamp refreshes
    // Never emit a missing path: cargo treats it as always dirty and rebuilds this crate every build
    let mut watch_paths = Vec::new();
    watch_paths.extend(git_stdout(&["rev-parse", "--git-path", "HEAD"]));
    watch_paths.extend(git_stdout(&["rev-parse", "--git-path", "logs/HEAD"]));
    if let Some(head_ref) = git_stdout(&["symbolic-ref", "-q", "HEAD"]) {
        watch_paths.extend(git_stdout(&["rev-parse", "--git-path", &head_ref]));
    }
    for path in watch_paths.iter().filter(|p| Path::new(p).exists()) {
        println!("cargo:rerun-if-changed={path}");
    }

    let commit = git_stdout(&["rev-parse", "HEAD"])
        .map(|s| s.chars().take(12).collect::<String>())
        .filter(|s| s.len() == 12)
        .unwrap_or_else(|| "unknown".to_string());

    // The version half of the stamp must be the SAME value `fuigo_version::VERSION`
    // resolves to, or `fuigo --version` and every other reader disagree.
    // `fuigo_version::VERSION` is `option_env!("FUIGO_VERSION")` falling back to
    // fuigo-version's own `CARGO_PKG_VERSION`, so mirror exactly that -- reading
    // the sibling manifest, NOT this crate's `CARGO_PKG_VERSION`.
    //
    // Using this crate's version is what shipped `1.0.1` from a tree whose single
    // source of truth said `1.0.2`: two package versions that had to be bumped in
    // lockstep, and nothing that noticed when only one was. There is now one.
    let version = match std::env::var("FUIGO_VERSION") {
        Ok(v) => v,
        Err(_) => version_from_source_of_truth(),
    };

    println!("cargo:rustc-env=VERSION_WITH_COMMIT={version} ({commit})");
}

/// Path to fuigo-version's manifest: the one place the shipping version is written.
fn version_manifest() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../fuigo-version/Cargo.toml")
}

/// Reads `version` out of fuigo-version's `[package]` table.
///
/// Panics rather than falling back. A wrong version is not a degraded build, it
/// is a build that lies about which one it is -- and the failure would surface
/// as a published package, not as a red CI job.
fn version_from_source_of_truth() -> String {
    let manifest = version_manifest();
    let text = std::fs::read_to_string(&manifest)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", manifest.display()));
    text.lines()
        .find_map(|line| line.strip_prefix("version = "))
        .map(|v| v.trim().trim_matches('"').to_string())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| panic!("no `version = \"...\"` line in {}", manifest.display()))
}

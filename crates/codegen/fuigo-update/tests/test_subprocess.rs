//! `auto_update::install_npm` and `version::fetch_npm_tag` spawn `npm` by bare name (`Command::new("npm")`).
//! To test them without touching the real npm registry, we install a fake `npm` shell script that logs its args and prints canned stdout.
//! The script lives in a tempdir prepended to `PATH` for the duration of the test.
//!
//! The same pattern covers `gh` for the `gh-release` installer paths.
//!
//! All tests in this file mutate `PATH` (global), so they're serialized with `#[serial]`.

#![cfg(unix)]

mod common;

use serial_test::serial;

use common::FakeBinGuard;
use fuigo_update::auto_update::{install_npm_checked_for_test, install_npm_for_test};
use fuigo_update::version::npm_view_version_for_test;
use std::time::{Duration, Instant};
use fuigo_update::version::{
    fetch_gh_release_version, fetch_npm_tag_for_test, fetch_npm_version_for_test,
};

// ─────────────────────────────────────────────────────────────────────────────
// fetch_npm_tag — reads a single dist-tag from `npm view`.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn fetch_npm_tag_returns_string_response() {
    let g = FakeBinGuard::install_npm();
    g.set_stdout("\"0.1.181\"\n");

    let v = fetch_npm_tag_for_test("latest", None).await.unwrap();
    assert_eq!(v, "0.1.181");
}

#[tokio::test]
#[serial]
async fn fetch_npm_tag_returns_array_response_picks_last() {
    // npm view sometimes returns an array of versions for ambiguous specs.
    // The implementation picks the LAST one (rev().find_map).
    let g = FakeBinGuard::install_npm();
    g.set_stdout(r#"["0.1.179", "0.1.180", "0.1.181"]"#);

    let v = fetch_npm_tag_for_test("latest", None).await.unwrap();
    assert_eq!(v, "0.1.181");
}

#[tokio::test]
#[serial]
async fn fetch_npm_tag_passes_pkg_and_tag_to_npm() {
    let g = FakeBinGuard::install_npm();
    g.set_stdout("\"0.1.181\"");

    let _ = fetch_npm_tag_for_test("latest", None).await.unwrap();
    let log = g.args_log();
    assert_eq!(log.len(), 1, "exactly one npm invocation");
    let args = &log[0];
    assert!(args.contains("view"), "args: {args}");
    // For "latest" tag, no `@latest` suffix is appended in pkg_spec.
    assert!(args.contains("fuigo"), "args: {args}");
    assert!(!args.contains("@latest"), "args: {args}");
    assert!(args.contains("--json"), "args: {args}");
}

#[tokio::test]
#[serial]
async fn fetch_npm_tag_alpha_appends_at_alpha_suffix() {
    let g = FakeBinGuard::install_npm();
    g.set_alpha_stdout("\"0.1.181-alpha.1\"");

    let v = fetch_npm_tag_for_test("alpha", None).await.unwrap();
    assert_eq!(v, "0.1.181-alpha.1");

    let log = g.args_log();
    assert!(
        log[0].contains("fuigo@alpha"),
        "args: {}",
        log[0]
    );
}

#[tokio::test]
#[serial]
async fn fetch_npm_tag_passes_registry_flag_when_set() {
    let g = FakeBinGuard::install_npm();
    g.set_stdout("\"0.1.181\"");

    let _ = fetch_npm_tag_for_test("latest", Some("https://npm.example.com"))
        .await
        .unwrap();
    let log = g.args_log();
    assert!(
        log[0].contains("--registry=https://npm.example.com"),
        "args: {}",
        log[0]
    );
}

#[tokio::test]
#[serial]
async fn fetch_npm_tag_no_registry_flag_when_unset() {
    let g = FakeBinGuard::install_npm();
    g.set_stdout("\"0.1.181\"");

    let _ = fetch_npm_tag_for_test("latest", None).await.unwrap();
    let log = g.args_log();
    assert!(!log[0].contains("--registry"), "args: {}", log[0]);
}

#[tokio::test]
#[serial]
async fn fetch_npm_tag_propagates_npm_failure() {
    let g = FakeBinGuard::install_npm();
    g.set_exit_code(1);

    let err = fetch_npm_tag_for_test("latest", None).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("npm view"), "msg: {msg}");
    assert!(msg.contains("failed"), "msg: {msg}");
}

#[tokio::test]
#[serial]
async fn fetch_npm_tag_failure_names_the_package_and_the_tag() {
    let g = FakeBinGuard::install_npm();
    g.set_exit_code(1);

    for tag in ["latest", "alpha"] {
        let err = fetch_npm_tag_for_test(tag, None).await.unwrap_err();
        let msg = format!("{err:#}");
        let expected = format!("npm view fuigo@{tag} failed");
        assert!(msg.contains(&expected), "expected `{expected}` in: {msg}");
    }
}

#[tokio::test]
#[serial]
async fn fetch_npm_tag_invalid_json_returns_err() {
    let g = FakeBinGuard::install_npm();
    g.set_stdout("not valid json {");

    let err = fetch_npm_tag_for_test("latest", None).await.unwrap_err();
    // serde_json should error on this.
    let msg = format!("{err:#}");
    assert!(!msg.is_empty());
}

#[tokio::test]
#[serial]
async fn fetch_npm_tag_unexpected_json_shape_returns_err() {
    // npm view can return null, an object, etc
    // The function expects string or array of strings; anything else is an error
    let g = FakeBinGuard::install_npm();
    g.set_stdout("42");

    let err = fetch_npm_tag_for_test("latest", None).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("unexpected JSON"), "msg: {msg}");
}

#[tokio::test]
#[serial]
async fn fetch_npm_tag_empty_array_returns_err() {
    let g = FakeBinGuard::install_npm();
    g.set_stdout("[]");

    let err = fetch_npm_tag_for_test("latest", None).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("empty"), "msg: {msg}");
}

// ─────────────────────────────────────────────────────────────────────────────
// fetch_npm_version — alpha channel calls both tags and returns the max.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn fetch_npm_version_stable_calls_only_latest() {
    let g = FakeBinGuard::install_npm();
    g.set_stdout("\"0.1.181\"");

    let v = fetch_npm_version_for_test("stable", None).await.unwrap();
    assert_eq!(v, "0.1.181");
    assert_eq!(g.args_log().len(), 1, "stable should make one call");
}

#[tokio::test]
#[serial]
async fn fetch_npm_version_alpha_returns_max_of_alpha_and_latest_when_alpha_higher() {
    let g = FakeBinGuard::install_npm();
    g.set_stdout("\"0.1.181\""); // latest tag (stable)
    g.set_alpha_stdout("\"0.1.182-alpha.1\""); // alpha tag

    let v = fetch_npm_version_for_test("alpha", None).await.unwrap();
    assert_eq!(v, "0.1.182-alpha.1");
    assert_eq!(g.args_log().len(), 2, "alpha should make two calls");
}

#[tokio::test]
#[serial]
async fn fetch_npm_version_alpha_returns_stable_when_higher() {
    // Common case: stable shipped after a stale alpha tag; the updater must not strand alpha users on the older alpha
    let g = FakeBinGuard::install_npm();
    g.set_stdout("\"0.1.182\"");
    g.set_alpha_stdout("\"0.1.181-alpha.1\"");

    let v = fetch_npm_version_for_test("alpha", None).await.unwrap();
    assert_eq!(v, "0.1.182");
}

// ─────────────────────────────────────────────────────────────────────────────
// install_npm — spawns `npm i -g @pkg@version`.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn install_npm_calls_npm_with_version_arg() {
    let g = FakeBinGuard::install_npm();
    // No stdout/exit setup, so the fake npm succeeds with empty stdout

    install_npm_for_test(Some("0.1.181"), "stable", None).await.unwrap();
    let log = g.args_log();
    assert_eq!(log.len(), 1, "exactly one npm invocation");
    let args = &log[0];
    assert!(args.contains("i -g"), "args: {args}");
    assert!(args.contains("fuigo@0.1.181"), "args: {args}");
}

#[tokio::test]
#[serial]
async fn install_npm_falls_back_to_dist_tag_on_no_target() {
    let g = FakeBinGuard::install_npm();

    install_npm_for_test(None, "stable", None).await.unwrap();
    let log = g.args_log();
    assert!(
        log[0].contains("fuigo@latest"),
        "stable channel uses @latest dist-tag: {}",
        log[0]
    );
}

#[tokio::test]
#[serial]
async fn install_npm_falls_back_to_alpha_dist_tag_on_alpha_channel() {
    let g = FakeBinGuard::install_npm();

    install_npm_for_test(None, "alpha", None).await.unwrap();
    let log = g.args_log();
    assert!(
        log[0].contains("fuigo@alpha"),
        "alpha channel uses @alpha dist-tag: {}",
        log[0]
    );
}

#[tokio::test]
#[serial]
async fn install_npm_passes_registry_flag_when_set() {
    let g = FakeBinGuard::install_npm();

    install_npm_for_test(Some("0.1.181"), "stable", Some("https://npm.example.com")).await.unwrap();
    let log = g.args_log();
    assert!(
        log[0].contains("--registry=https://npm.example.com"),
        "args: {}",
        log[0]
    );
}

#[tokio::test]
#[serial]
async fn install_npm_no_registry_flag_when_unset() {
    let g = FakeBinGuard::install_npm();

    install_npm_for_test(Some("0.1.181"), "stable", None).await.unwrap();
    let log = g.args_log();
    assert!(!log[0].contains("--registry"), "args: {}", log[0]);
}

#[tokio::test]
#[serial]
async fn install_npm_returns_err_on_npm_failure() {
    let g = FakeBinGuard::install_npm();
    g.set_exit_code(1);

    let err = install_npm_for_test(Some("0.1.181"), "stable", None).await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("npm install failed"), "msg: {msg}");
}

#[tokio::test]
#[serial]
async fn install_npm_with_token_passes_userconfig() {
    // SAFETY: serial_test ensures no other thread touches NPM_TOKEN.
    unsafe { std::env::set_var("NPM_TOKEN", "secrettoken") };
    let g = FakeBinGuard::install_npm();

    install_npm_for_test(Some("0.1.181"), "stable", None).await.unwrap();
    let log = g.args_log();
    assert!(
        log[0].contains("--userconfig="),
        "with NPM_TOKEN, must pass --userconfig: {}",
        log[0]
    );
    // The userconfig path should be cleaned up afterwards.
    let userconfig_arg = log[0]
        .split_whitespace()
        .find(|a| a.starts_with("--userconfig="))
        .unwrap()
        .trim_start_matches("--userconfig=");
    assert!(
        !std::path::Path::new(userconfig_arg).exists(),
        "userconfig file should be cleaned up: {userconfig_arg}"
    );
    unsafe { std::env::remove_var("NPM_TOKEN") };
}

#[tokio::test]
#[serial]
async fn install_npm_no_token_no_userconfig() {
    unsafe { std::env::remove_var("NPM_TOKEN") };
    let g = FakeBinGuard::install_npm();

    install_npm_for_test(Some("0.1.181"), "stable", None).await.unwrap();
    let log = g.args_log();
    assert!(!log[0].contains("--userconfig"), "args: {}", log[0]);
}

// ─────────────────────────────────────────────────────────────────────────────
// fetch_gh_release_version — exercises the `gh release list` shell-out.
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
#[serial]
async fn fetch_gh_release_stable_returns_tag_stripped() {
    let g = FakeBinGuard::install_gh();
    // For stable channel, only the `--exclude-pre-releases` invocation is made.
    g.set_stable_only_stdout("v0.1.181\n");

    let v = fetch_gh_release_version("stable").await.unwrap();
    assert_eq!(v, "0.1.181");

    let log = g.args_log();
    assert_eq!(log.len(), 1);
    assert!(
        log[0].contains("--exclude-pre-releases"),
        "args: {}",
        log[0]
    );
}

#[tokio::test]
#[serial]
async fn fetch_gh_release_stable_handles_tag_without_v_prefix() {
    let g = FakeBinGuard::install_gh();
    g.set_stable_only_stdout("0.1.181");

    let v = fetch_gh_release_version("stable").await.unwrap();
    assert_eq!(v, "0.1.181");
}

#[tokio::test]
#[serial]
async fn fetch_gh_release_alpha_returns_max_of_pre_and_stable() {
    // Alpha channel makes two `gh release list` calls (with and without --exclude-pre-releases) and returns the semver-max
    let g = FakeBinGuard::install_gh();
    g.set_with_pre_stdout("v0.1.182-alpha.1");
    g.set_stable_only_stdout("v0.1.181");

    let v = fetch_gh_release_version("alpha").await.unwrap();
    assert_eq!(v, "0.1.182-alpha.1");
    assert_eq!(g.args_log().len(), 2);
}

#[tokio::test]
#[serial]
async fn fetch_gh_release_alpha_returns_stable_when_higher() {
    let g = FakeBinGuard::install_gh();
    g.set_with_pre_stdout("v0.1.180-alpha.5");
    g.set_stable_only_stdout("v0.1.181");

    let v = fetch_gh_release_version("alpha").await.unwrap();
    assert_eq!(v, "0.1.181");
}

#[tokio::test]
#[serial]
async fn fetch_gh_release_propagates_gh_failure() {
    let g = FakeBinGuard::install_gh();
    g.set_exit_code(1);

    let err = fetch_gh_release_version("stable").await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("gh release list"), "msg: {msg}");
    assert!(msg.contains("failed"), "msg: {msg}");
}

#[tokio::test]
#[serial]
async fn fetch_gh_release_empty_response_returns_err() {
    let g = FakeBinGuard::install_gh();
    g.set_stable_only_stdout("");

    let err = fetch_gh_release_version("stable").await.unwrap_err();
    let msg = format!("{err:#}");
    assert!(msg.contains("No releases found"), "msg: {msg}");
}

#[tokio::test]
#[serial]
async fn fetch_gh_release_passes_repo_flag() {
    let g = FakeBinGuard::install_gh();
    g.set_stable_only_stdout("v0.1.181");

    let _ = fetch_gh_release_version("stable").await.unwrap();
    let log = g.args_log();
    assert!(log[0].contains("--repo"), "args: {}", log[0]);
    assert!(
        log[0].contains("FerroxLabs/fuigo"),
        "args: {}",
        log[0]
    );
}

#[tokio::test]
#[serial]
async fn fetch_gh_release_uses_jq_to_extract_tag() {
    // The function constructs `gh release list --json tagName --jq '.[0].tagName'`
    let g = FakeBinGuard::install_gh();
    g.set_stable_only_stdout("v0.1.181");

    let _ = fetch_gh_release_version("stable").await.unwrap();
    let log = g.args_log();
    assert!(log[0].contains("--json"), "args: {}", log[0]);
    assert!(log[0].contains("--jq"), "args: {}", log[0]);
}

// ─────────────────────────────────────────────────────────────────────────────
// P145: a down or hanging registry is bounded and reported, never answered from npm's cache.
// ─────────────────────────────────────────────────────────────────────────────


/// `npm view` runs against an empty private cache (so npm cannot answer a failed request with a stale packument, which
/// made a down registry report "latest" as success) with short retries, and the cache dir is removed afterwards.
#[tokio::test]
#[serial]
async fn p145_npm_view_uses_a_fresh_private_cache_and_short_retries() {
    let g = FakeBinGuard::install_npm();
    g.set_stdout("\"1.0.21\"");

    let v = fetch_npm_tag_for_test("latest", None).await.unwrap();
    assert_eq!(v, "1.0.21");
    let args = &g.args_log()[0];
    assert!(args.contains("--fetch-retries=1"), "args: {args}");
    assert!(args.contains("--fetch-timeout=15000"), "args: {args}");
    assert!(args.contains("--prefer-online"), "args: {args}");
    let cache = args
        .split_whitespace()
        .find_map(|a| a.strip_prefix("--cache="))
        .unwrap_or_else(|| panic!("no --cache= in {args}"));
    assert!(cache.contains("fuigo-npm-view-"), "private cache dir: {cache}");
    assert!(!std::path::Path::new(cache).exists(), "cache dir left behind: {cache}");

    let _ = fetch_npm_tag_for_test("latest", None).await.unwrap();
    let second = &g.args_log()[1];
    assert!(!second.contains(&format!("--cache={cache} ")), "each view gets its own cache: {second}");
}

/// A registry that never answers: `npm view` is stopped at the bound with a clear error, not after npm's own minutes.
#[tokio::test]
#[serial]
async fn p145_npm_view_is_bounded_when_the_registry_hangs() {
    let g = FakeBinGuard::install_npm();
    g.set_sleep(30);

    let started = Instant::now();
    let err = npm_view_version_for_test("fuigo", Some("http://127.0.0.1:4873/"), Duration::from_secs(1))
        .await
        .unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(10), "took {:?}", started.elapsed());
    let msg = format!("{err:#}");
    assert!(msg.contains("no answer from the npm registry"), "msg: {msg}");
    assert!(msg.contains("within 1 s"), "msg: {msg}");
}

/// npm prints nothing (exit 0) for a version the registry does not have: that is an error, not a parse failure.
#[tokio::test]
#[serial]
async fn p145_npm_view_of_a_missing_version_says_so() {
    let _g = FakeBinGuard::install_npm();
    let err = npm_view_version_for_test("fuigo@9.9.9", None, Duration::from_secs(10))
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("the registry has no fuigo@9.9.9"), "{err:#}");
}

/// `update --force-reinstall` with the registry down: the preflight fails fast, says nothing changed, and `npm i -g`
/// never runs (it used to hang silently for more than 400 s).
#[tokio::test]
#[serial]
async fn p145_install_with_registry_down_fails_fast_without_running_npm_install() {
    let g = FakeBinGuard::install_npm();
    g.set_view_exit_code(1);
    g.set_stderr("npm error code ECONNREFUSED");

    let started = Instant::now();
    let err = install_npm_checked_for_test(
        Some("1.0.21"),
        "stable",
        Some("http://127.0.0.1:4873/"),
        Duration::from_secs(5),
        Duration::from_secs(5),
    )
    .await
    .unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(10));
    let msg = format!("{err:#}");
    assert!(msg.contains("cannot install fuigo@1.0.21"), "msg: {msg}");
    assert!(msg.contains("Nothing was changed"), "msg: {msg}");
    assert!(msg.contains("ECONNREFUSED"), "msg: {msg}");
    let log = g.args_log();
    assert_eq!(log.len(), 1, "only the preflight ran: {log:?}");
    assert!(log[0].starts_with("view fuigo@1.0.21 "), "{log:?}");
}

/// A preflight that hangs is bounded too.
#[tokio::test]
#[serial]
async fn p145_install_preflight_is_bounded() {
    let g = FakeBinGuard::install_npm();
    g.set_sleep(30);
    let started = Instant::now();
    let err = install_npm_checked_for_test(None, "stable", None, Duration::from_secs(1), Duration::from_secs(60))
        .await
        .unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(10), "took {:?}", started.elapsed());
    assert!(format!("{err:#}").contains("cannot install fuigo@latest"), "{err:#}");
    assert_eq!(g.args_log().len(), 1);
}

/// The registry answers the preflight, then `npm i -g` stalls: it is stopped at the bound with a clear error.
#[tokio::test]
#[serial]
async fn p145_a_stalled_npm_install_is_stopped_at_the_bound() {
    let g = FakeBinGuard::install_npm();
    g.set_stdout("\"1.0.21\"");
    g.set_install_sleep(30);
    let started = Instant::now();
    let err = install_npm_checked_for_test(
        Some("1.0.21"),
        "stable",
        None,
        Duration::from_secs(5),
        Duration::from_secs(1),
    )
    .await
    .unwrap_err();
    assert!(started.elapsed() < Duration::from_secs(10), "took {:?}", started.elapsed());
    let msg = format!("{err:#}");
    assert!(msg.contains("did not finish within 1 s"), "msg: {msg}");
    let log = g.args_log();
    assert_eq!(log.len(), 2, "{log:?}");
    assert!(log[1].starts_with("i -g fuigo@1.0.21"), "{log:?}");
}

/// The healthy path: preflight then one install.
#[tokio::test]
#[serial]
async fn p145_install_with_a_healthy_registry_runs_preflight_then_install() {
    let g = FakeBinGuard::install_npm();
    g.set_stdout("\"1.0.21\"");
    install_npm_checked_for_test(
        Some("1.0.21"),
        "stable",
        Some("https://npm.example.com"),
        Duration::from_secs(10),
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    let log = g.args_log();
    assert_eq!(log.len(), 2, "{log:?}");
    assert!(log[0].starts_with("view fuigo@1.0.21 version --json --registry=https://npm.example.com"), "{log:?}");
    assert!(log[1].starts_with("i -g fuigo@1.0.21 --registry=https://npm.example.com"), "{log:?}");
}

/// Whether `pid` still names a live (not zombie) process.
fn p145_alive(pid: i32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(stat) => !stat.rsplit(')').next().unwrap_or("").trim_start().starts_with('Z'),
        Err(_) => unsafe { libc_kill0(pid) },
    }
}

unsafe fn libc_kill0(pid: i32) -> bool {
    unsafe extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    unsafe { kill(pid, 0) == 0 }
}

/// Astra P145 r1 #2: at the bound the WHOLE npm tree is killed (a lifecycle script npm started too), not only npm.
#[tokio::test]
#[serial]
async fn p145_a_timeout_kills_the_whole_npm_process_tree() {
    let g = FakeBinGuard::install_npm();
    g.set_grandchild();
    g.set_sleep(30);
    let _ = npm_view_version_for_test("fuigo", None, Duration::from_secs(1)).await.unwrap_err();
    let pid = g.grandchild_pid().expect("grandchild started");
    let deadline = Instant::now() + Duration::from_secs(5);
    while p145_alive(pid) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!p145_alive(pid), "npm's child {pid} survived the timeout");

    // Same for the install bound: the preflight answers, npm i -g starts a lifecycle child and stalls (r2 #6).
    let g2 = FakeBinGuard::install_npm();
    g2.set_stdout("\"1.0.21\"");
    g2.set_install_grandchild();
    g2.set_install_sleep(30);
    let err = install_npm_checked_for_test(Some("1.0.21"), "stable", None, Duration::from_secs(5), Duration::from_secs(1))
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("did not finish within 1 s"), "{err:#}");
    let log = g2.args_log();
    assert_eq!(log.len(), 2, "{log:?}");
    assert!(log[0].starts_with("view ") && log[1].starts_with("i -g "), "{log:?}");
    let pid = g2.install_grandchild_pid().expect("install grandchild started");
    let deadline = Instant::now() + Duration::from_secs(5);
    while p145_alive(pid) && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!p145_alive(pid), "npm install's child {pid} survived the timeout");
}

/// Astra P145 r1 #3 / r2 #4: `npm view` (the check and the install preflight) runs in npm's global mode, like `npm i -g`,
/// so no project .npmrc (cwd or ancestor) selects a different registry for the check than for the install; it runs
/// in the caller's directory so relative config paths resolve as they do for the install.
#[tokio::test]
#[serial]
async fn p145_npm_view_uses_the_install_configuration_context() {
    let g = FakeBinGuard::install_npm();
    g.set_stdout("\"1.0.21\"");
    let _ = fetch_npm_tag_for_test("latest", None).await.unwrap();
    let args = &g.args_log()[0];
    assert!(args.split_whitespace().any(|a| a == "--global"), "args: {args}");
    let cwd = g.cwd_log();
    let here = std::env::current_dir().unwrap();
    assert_eq!(cwd.len(), 1, "{cwd:?}");
    assert_eq!(std::path::Path::new(&cwd[0]), here.as_path(), "same cwd as the install");
}

use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use serde::Deserialize;
use serde_json::Value;
use tokio::fs;
use tokio::process::Command;

use fuigo_shell::env::FuigoBuildEnvironment;
use fuigo_shell::util::fuigo_home::fuigo_home;

const TTL_SECONDS_BEFORE_AUTO_UPDATE: Duration = Duration::from_secs(60 * 30);
const NPM_PACKAGE: &str = "fuigo";
/// The repo the gh-release installer pulls from.
///
/// Was `fuigo-org-shared/fuigo-build` -- a name the rebrand invented from
/// upstream's org, owned by nobody. An updater pointed at a non-existent repo
/// fails in a way that reads like a network problem.
pub const GH_RELEASE_REPO: &str = "FerroxLabs/fuigo";

/// Update channel base. Empty until Fuigo has its own release CDN — the
/// upstream host serves xAI's signed binaries, and an updater pointed there
/// would replace a Fuigo install with `grok`.
pub(crate) const CLI_BASE_URL_PRIMARY: &str = "";

/// Upstream's GCS fallback, also empty.
///
/// It used to read `.../grok-build-public-artifacts/cli`. The rebrand renamed
/// the bucket to `fuigo-build-public-artifacts`, which nobody owns — so the
/// "fallback" was egress to a 404. Worse, an empty primary does NOT disable the
/// updater: `fetch_gcs_version` just falls through to the next base. Both must
/// be empty for the update path to be genuinely off.
pub(crate) const CLI_BASE_URL_FALLBACK: &str = "";

/// CLI base URLs in preference order.
/// Callers (channel-pointer fetch, binary download, in-app updater) try each in turn and stop at the first success.
pub(crate) const CLI_BASE_URLS: &[&str] = &[CLI_BASE_URL_PRIMARY, CLI_BASE_URL_FALLBACK];

/// [`CLI_BASE_URLS`], unless tests set `FUIGO_CLI_BASE_URL` to point fetches and downloads at one base (as they set `FUIGO_INSTALLER`).
/// Loopback-only: downloads are verified by a smoke test, not a checksum, so redirecting to an arbitrary base could serve a hijacked install.
pub(crate) fn cli_base_urls() -> Vec<String> {
    if let Ok(base) = std::env::var("FUIGO_CLI_BASE_URL") {
        let base = base.trim();
        if is_loopback_base(base) {
            return vec![base.to_owned()];
        }
        if !base.is_empty() {
            tracing::warn!("FUIGO_CLI_BASE_URL ignored: only loopback bases are honored");
        }
    }
    // Empty entries are dropped rather than requested. Upstream left them in,
    // so a blank base produced the relative URL "/stable" and burned three
    // retries (1s+2s+4s) before falling through to the next base. With every
    // base empty this returns an empty vec and the callers report
    // "no CLI base URLs configured" without touching the network.
    CLI_BASE_URLS
        .iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| (*s).to_owned())
        .collect()
}

/// Parsed, not prefix-matched: `http://127.0.0.1:9@evil.com` starts with a
/// loopback prefix but its host is `evil.com` (userinfo trick).
fn is_loopback_base(base: &str) -> bool {
    let Ok(u) = url::Url::parse(base) else {
        return false;
    };
    if u.scheme() != "http" || !u.username().is_empty() || u.password().is_some() {
        return false;
    }
    match u.host() {
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        Some(url::Host::Domain(d)) => d == "localhost",
        None => false,
    }
}

/// Minimal configuration the update system needs from the environment.
///
/// Constructed once from `FuigoBuildEnvironment` at startup and threaded through the update call chain.
/// `auto_update` and `version` never need to know about the `FuigoBuildEnvironment` enum directly.
#[derive(Clone)]
pub struct UpdateConfig {
    /// Chat API proxy base URL (versioned `https://cli-chat-proxy.grok.com/v1` endpoint).
    pub proxy_base_url: String,
    /// Auth scope key for `~/.fuigo/auth.json`.
    pub auth_scope: String,
    /// Enterprise deployment key (FUIGO_DEPLOYMENT_KEY).
    pub deployment_key: Option<String>,
    /// Optional extra auth material forwarded with requests when present.
    pub alpha_test_key: Option<String>,
    /// Release channel: "stable" or "alpha". Loaded from config.
    pub channel: String,
    /// Custom npm registry URL. When set, passed as `--registry=` to npm CLI.
    pub npm_registry: Option<String>,
}

/// Hand-written `Debug` (P70): credential values print as `<redacted>` (headers and query parameters by name only), so a `{:?}` of this type in a log, panic or error cannot disclose them.
/// The destructure is exhaustive, so a new field fails to compile here until its Debug output is decided.
impl std::fmt::Debug for UpdateConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self {
            proxy_base_url,
            auth_scope,
            deployment_key,
            alpha_test_key,
            channel,
            npm_registry,
        } = self;
        f.debug_struct("UpdateConfig")
            .field("proxy_base_url", &fuigo_auth::redact_url(proxy_base_url))
            .field("auth_scope", auth_scope)
            .field("deployment_key", &deployment_key.as_ref().map(|_| "<redacted>"))
            .field("alpha_test_key", &alpha_test_key.as_ref().map(|_| "<redacted>"))
            .field("channel", channel)
            .field("npm_registry", &npm_registry.as_deref().map(fuigo_auth::redact_url))
            .finish()
    }
}

impl UpdateConfig {
    pub fn from_environment(env: &FuigoBuildEnvironment) -> Self {
        Self {
            proxy_base_url: env.cli_chat_proxy_base_url(),
            auth_scope: fuigo_shell::auth::FuigoComConfig::default().auth_scope(),
            deployment_key: None,
            alpha_test_key: None,
            channel: "stable".to_string(),
            npm_registry: None,
        }
    }
}

#[derive(Debug, serde::Serialize, Deserialize)]
struct FuigoVersion {
    version: String,
    #[serde(default)]
    stable_version: Option<String>,
    checked_at: String,
}

impl FuigoVersion {
    fn is_fresh(&self, now: time::OffsetDateTime, ttl: Duration) -> bool {
        if let Ok(dt) = time::OffsetDateTime::parse(
            &self.checked_at,
            &time::format_description::well_known::Rfc3339,
        ) {
            // Clock-skew guard: future timestamps are never fresh.
            if dt > now {
                return false;
            }
            now - dt < ttl
        } else {
            false
        }
    }

    fn new(version: String, stable_version: Option<String>, now: time::OffsetDateTime) -> Self {
        let checked_at = now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| now.to_string());
        Self {
            version,
            stable_version,
            checked_at,
        }
    }
}

fn semver_max(a: &str, b: &str) -> Result<String> {
    let va = semver::Version::parse(a)?;
    let vb = semver::Version::parse(b)?;
    Ok(std::cmp::max(va, vb).to_string())
}

/// Fetch the latest version from npm registry using `npm view`.
/// For alpha channel, fetches both `@alpha` and `@latest` dist-tags and returns the semver-greater.
/// This keeps alpha users from getting stuck when a newer stable ships without updating the alpha dist-tag.
async fn fetch_npm_version(channel: &str, npm_registry: Option<&str>) -> Result<String> {
    if channel == "alpha" {
        let (alpha_v, stable_v) = tokio::try_join!(
            fetch_npm_tag("alpha", npm_registry),
            fetch_npm_tag("latest", npm_registry),
        )?;
        return semver_max(&alpha_v, &stable_v);
    }
    fetch_npm_tag("latest", npm_registry).await
}

/// Test-only entry point: invokes the private [`fetch_npm_tag`] for tests that swap in a fake `npm` via PATH.
#[doc(hidden)]
pub async fn fetch_npm_tag_for_test(tag: &str, npm_registry: Option<&str>) -> Result<String> {
    fetch_npm_tag(tag, npm_registry).await
}

/// Test-only entry point: invokes the private [`fetch_npm_version`] for tests that swap in a fake `npm` via PATH.
#[doc(hidden)]
pub async fn fetch_npm_version_for_test(
    channel: &str,
    npm_registry: Option<&str>,
) -> Result<String> {
    fetch_npm_version(channel, npm_registry).await
}

async fn fetch_npm_tag(tag: &str, npm_registry: Option<&str>) -> Result<String> {
    let pkg_spec = if tag == "latest" {
        NPM_PACKAGE.to_string()
    } else {
        format!("{}@{}", NPM_PACKAGE, tag)
    };
    npm_view_version(&pkg_spec, npm_registry, None, NPM_VIEW_TIMEOUT)
        .await
        .map_err(|e| anyhow::anyhow!("npm view @{tag} failed: {e:#}"))
}

/// Wall-clock bound on one `npm view` (P145). With the registry unreachable npm retried for about 70 s and then
/// answered from its cache, so `fuigo update --check` reported a stale "latest" as success; with a blackholed host it
/// could wait far longer. The flags in [`npm_view_args`] make npm give up after about 30 s at most; this bound is the
/// backstop when npm itself hangs.
pub(crate) const NPM_VIEW_TIMEOUT: Duration = Duration::from_secs(45);

/// Network flags for an `npm view` that must reflect the registry now (P145):
/// - `--cache=<empty private dir>`: npm answers a failed registry request from its cache (a stale packument), which
///   made a down registry look like "already up to date". An empty cache has nothing to fall back to.
/// - one retry with short back-off and a 15 s per-request timeout instead of npm's 2 retries of up to 60 s.
pub(crate) fn npm_view_args(
    spec: &str,
    npm_registry: Option<&str>,
    userconfig: Option<&Path>,
    cache_dir: &Path,
) -> Vec<std::ffi::OsString> {
    let mut args: Vec<std::ffi::OsString> = ["view", spec, "version", "--json"]
        .iter()
        .map(Into::into)
        .collect();
    if let Some(registry) = npm_registry {
        args.push(format!("--registry={registry}").into());
    }
    for flag in [
        // The same configuration context as `npm i -g` (Astra P145 r1 #3, r2 #4): in global mode npm reads no project
        // .npmrc (from the cwd or any ancestor), while path-valued settings still resolve against the caller's cwd.
        "--global",
        "--prefer-online",
        "--fetch-retries=1",
        "--fetch-retry-mintimeout=1000",
        "--fetch-retry-maxtimeout=5000",
        "--fetch-timeout=15000",
    ] {
        args.push(flag.into());
    }
    let mut cache = std::ffi::OsString::from("--cache=");
    cache.push(cache_dir.as_os_str());
    args.push(cache);
    if let Some(userconfig) = userconfig {
        let mut flag = std::ffi::OsString::from("--userconfig=");
        flag.push(userconfig.as_os_str());
        args.push(flag);
    }
    args
}

/// A fresh private directory for one `npm view` cache, removed on drop. Created with `create_dir` (fails if the name
/// exists, so a planted directory or symlink is never used) and 0700 on Unix.
struct PrivateNpmCache(std::path::PathBuf);

impl PrivateNpmCache {
    fn create() -> Result<Self> {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let base = std::env::temp_dir();
        let mut last_err = None;
        for _ in 0..8 {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0);
            let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let dir = base.join(format!("fuigo-npm-view-{}-{nanos:x}-{seq}", std::process::id()));
            // Owner-only from the moment it exists (Unix 0700; Windows a protected, inheritable owner-only DACL given
            // to CreateDirectoryW), and fails if the name exists (Astra P145 r1 #5, r2 #5).
            match fuigo_secrets::owner_only::create_owner_only_dir(&dir) {
                Ok(()) => return Ok(Self(dir)),
                Err(e) => last_err = Some(e),
            }
        }
        Err(anyhow::anyhow!(
            "could not create a private npm cache directory under {}: {}",
            base.display(),
            last_err.map(|e| e.to_string()).unwrap_or_default()
        ))
    }
}

impl Drop for PrivateNpmCache {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// `npm view <spec> version --json` against the registry as it is now, bounded by `timeout` (P145). Returns the
/// version npm printed (the last one when it prints a list). The child is killed when the bound fires.
pub(crate) async fn npm_view_version(
    spec: &str,
    npm_registry: Option<&str>,
    userconfig: Option<&Path>,
    timeout: Duration,
) -> Result<String> {
    let cache = PrivateNpmCache::create()?;
    let mut cmd = crate::npm_command::npm_invocation()?.tokio_command();
    cmd.args(npm_view_args(spec, npm_registry, userconfig, &cache.0))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    fuigo_tools::util::detach_command(&mut cmd);
    cmd.envs(fuigo_tools::util::pager_env());
    let output = match crate::npm_command::run_tree_bounded(&mut cmd, timeout).await? {
        crate::npm_command::Bounded::Done(output) => output,
        crate::npm_command::Bounded::TimedOut => anyhow::bail!(
            "no answer from the npm registry{} within {} s",
            npm_registry
                .map(|r| format!(" ({})", fuigo_auth::redact_url(r)))
                .unwrap_or_default(),
            timeout.as_secs()
        ),
    };

    if !output.status.success() {
        anyhow::bail!("{}", npm_error_summary(&String::from_utf8_lossy(&output.stderr)));
    }

    let stdout = String::from_utf8(output.stdout)?;
    if stdout.trim().is_empty() {
        // npm prints nothing (exit 0) for a version the registry does not have.
        anyhow::bail!("the registry has no {spec}");
    }
    let value: Value = serde_json::from_str(stdout.trim())?;
    match value {
        Value::String(version) => Ok(version),
        Value::Array(values) => values
            .iter()
            .rev()
            .find_map(|entry| entry.as_str().map(|item| item.to_string()))
            .ok_or_else(|| anyhow::anyhow!("returned empty version list")),
        _ => anyhow::bail!("returned unexpected JSON"),
    }
}

/// One line from npm's multi-line error output (P145): `<code>: <first message line>`, e.g.
/// `ECONNREFUSED: request to http://127.0.0.1:4873/fuigo failed, reason: connect ECONNREFUSED 127.0.0.1:4873`.
/// `fuigo update --check` used to print npm's whole dump (code, syscall, errno, log-file lines). Handles npm 7-10
/// (`npm error ...`) and older (`npm ERR! ...`); falls back to the last non-empty line; capped at 300 characters.
pub(crate) fn npm_error_summary(stderr: &str) -> String {
    const NOISE: &[&str] = &["syscall ", "errno ", "A complete log", "Log files were not written", "code "];
    let mut code: Option<&str> = None;
    let mut message: Option<&str> = None;
    let mut last: Option<&str> = None;
    for raw in stderr.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        last = Some(line);
        let Some(body) = line
            .strip_prefix("npm error ")
            .or_else(|| line.strip_prefix("npm ERR! "))
            .map(str::trim)
        else {
            continue;
        };
        if let Some(c) = body.strip_prefix("code ") {
            code.get_or_insert(c.trim());
            continue;
        }
        if body.is_empty() || NOISE.iter().any(|n| body.starts_with(n)) {
            continue;
        }
        // `npm error 403 403 Forbidden - GET ...`: drop a leading repeat of the code.
        let body = code
            .and_then(|c| body.strip_prefix(c.trim_start_matches('E')))
            .map(str::trim)
            .filter(|b| !b.is_empty())
            .unwrap_or(body);
        message.get_or_insert(body);
    }
    let line = match (code, message) {
        (Some(c), Some(m)) => format!("{c}: {m}"),
        (Some(c), None) => c.to_string(),
        (None, Some(m)) => m.to_string(),
        (None, None) => last.unwrap_or("npm failed without a message").to_string(),
    };
    let mut out: String = line.chars().take(300).collect();
    if out.len() < line.len() {
        out.push('…');
    }
    out
}

/// Test-only entry point: [`npm_view_version`] with an explicit bound.
#[doc(hidden)]
pub async fn npm_view_version_for_test(
    spec: &str,
    npm_registry: Option<&str>,
    timeout: Duration,
) -> Result<String> {
    npm_view_version(spec, npm_registry, None, timeout).await
}

/// Fetch the latest version from GitHub Releases using `gh release list`.
/// For alpha channel, fetches both pre-release and stable-only, returns the semver-greater.
#[doc(hidden)]
pub async fn fetch_gh_release_version(channel: &str) -> Result<String> {
    if channel == "alpha" {
        let (with_pre, stable_only) = tokio::try_join!(
            fetch_gh_release_latest(false),
            fetch_gh_release_latest(true),
        )?;
        return semver_max(&with_pre, &stable_only);
    }
    fetch_gh_release_latest(true).await
}

/// How many releases `gh release list` returns (newest created first) to pick the highest from. Large enough that
/// a newer line is not pushed out of the window by later releases of older lines (Astra P110 r1 #5); `gh` pages
/// the query, so a repository with few releases costs one request.
const GH_RELEASE_LIST_LIMIT: &str = "1000";

/// The highest version among the releases `gh release list` returned, not the newest created one
/// (R110 U2): an older-line release created later (a hotfix, a backfill) must never become "latest".
/// Drafts are excluded by the query; prereleases by the query and, when `exclude_pre`, by their
/// semver suffix too. Tags that are not `v<semver>` are ignored.
async fn fetch_gh_release_latest(exclude_pre: bool) -> Result<String> {
    let jq = if exclude_pre {
        ".[] | select((.isDraft or .isPrerelease) | not) | .tagName"
    } else {
        ".[] | select(.isDraft | not) | .tagName"
    };
    let mut args = vec![
        "release",
        "list",
        "--repo",
        GH_RELEASE_REPO,
        "--limit",
        GH_RELEASE_LIST_LIMIT,
        "--exclude-drafts",
        "--json",
        "tagName,isDraft,isPrerelease",
        "--jq",
        jq,
    ];
    if exclude_pre {
        args.push("--exclude-pre-releases");
    }
    let mut cmd = Command::new("gh");
    cmd.args(&args).stdin(std::process::Stdio::null());
    fuigo_tools::util::detach_command(&mut cmd);
    cmd.envs(fuigo_tools::util::pager_env());
    let output = cmd.output().await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("gh release list failed: {}", stderr.trim());
    }

    highest_release_version(&String::from_utf8(output.stdout)?, exclude_pre)
        .ok_or_else(|| anyhow::anyhow!("No releases found in {}", GH_RELEASE_REPO))
}

/// The highest `v<semver>` tag in `tags` (one per line), without the `v`.
pub(crate) fn highest_release_version(tags: &str, exclude_pre: bool) -> Option<String> {
    tags.lines()
        .filter_map(|tag| {
            let tag = tag.trim();
            semver::Version::parse(tag.strip_prefix('v').unwrap_or(tag)).ok()
        })
        .filter(|version| !exclude_pre || version.pre.is_empty())
        .max()
        .map(|version| version.to_string())
}

/// Fetch the latest version from a public CLI channel pointer.
///
/// Reads `{base}/{channel}` which contains a plain-text semver string (e.g. `0.1.181`).
/// No auth required; the upstream bucket is public.
///
/// For the alpha channel, fetches both `alpha` and `stable` pointers and returns the semver-greater, matching the npm and gh-release paths.
///
/// Tries each base URL in [`CLI_BASE_URLS`] in order and stops at the first success.
/// Each base also retries up to 3 times with exponential backoff (1s, 2s, 4s) on transient failures before falling through to the next base.
pub(crate) async fn fetch_gcs_version(channel: &str) -> Result<String> {
    let mut last_err: Option<anyhow::Error> = None;
    let bases = cli_base_urls();
    for (i, base) in bases.iter().enumerate() {
        match fetch_gcs_version_from_base(channel, base).await {
            Ok(v) => return Ok(v),
            Err(e) => {
                if i + 1 < bases.len() {
                    tracing::warn!(
                        "channel pointer fetch from {} failed ({:#}); trying next base URL",
                        base,
                        e
                    );
                }
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("no CLI base URLs configured")))
}

/// Test-only entry point: same as [`fetch_gcs_version`] but reads from `base_url` instead of the hardcoded GCS bucket.
#[doc(hidden)]
pub async fn fetch_gcs_version_from_base(channel: &str, base_url: &str) -> Result<String> {
    if channel == "alpha" {
        let (alpha_v, stable_v) = tokio::try_join!(
            fetch_gcs_channel_pointer("alpha", base_url),
            fetch_gcs_channel_pointer("stable", base_url),
        )?;
        return semver_max(&alpha_v, &stable_v);
    }
    fetch_gcs_channel_pointer(channel, base_url).await
}

async fn fetch_gcs_channel_pointer(channel: &str, base_url: &str) -> Result<String> {
    let url = format!("{}/{}", base_url, channel);
    let client =
        fuigo_extra_ca::public_download::PublicDownloadClient::new(Duration::from_secs(15))?;

    let max_retries: u32 = 3;
    let mut last_err = None;
    for attempt in 0..=max_retries {
        if attempt > 0 {
            tokio::time::sleep(Duration::from_secs(1 << (attempt - 1))).await;
        }
        let resp = match client.get(&url).await {
            Ok(r) => r,
            Err(e) => {
                last_err = Some(anyhow::anyhow!(
                    "GCS channel pointer fetch failed for {}: {:#}",
                    url,
                    e
                ));
                continue;
            }
        };
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            last_err = Some(anyhow::anyhow!(
                "GCS channel pointer fetch failed: HTTP {} for {}: {}",
                status,
                url,
                body.chars().take(200).collect::<String>().trim()
            ));
            continue;
        }
        match resp.text().await {
            Ok(body) => {
                let version = body.trim().to_string();
                if version.is_empty() {
                    last_err = Some(anyhow::anyhow!(
                        "empty {} channel pointer at {}",
                        channel,
                        url
                    ));
                    continue;
                }
                if semver::Version::parse(&version).is_err() {
                    anyhow::bail!(
                        "invalid semver in {} channel pointer: '{}'",
                        channel,
                        version
                    );
                }
                return Ok(version);
            }
            Err(e) => {
                last_err = Some(anyhow::anyhow!(
                    "GCS channel pointer body read failed for {}: {:#}",
                    url,
                    e
                ));
                continue;
            }
        }
    }
    Err(last_err.unwrap())
}

/// Fetch the latest version for the given installer type without writing the version cache.
/// Use this when the caller needs to control when the cache is written.
/// Auto-update, for example, should only cache after a successful install or when no update is needed.
pub async fn fetch_latest_version(installer: &str, config: &UpdateConfig) -> Result<String> {
    match installer {
        "npm" => fetch_npm_version(&config.channel, config.npm_registry.as_deref()).await,
        "gh-release" => fetch_gh_release_version(&config.channel).await,
        _ => fetch_gcs_version(&config.channel).await,
    }
}

/// Write the version cache to disk, recording that `version` was seen at the current time.
/// Call after confirming the version is current (no update needed) or after a successful install.
///
/// `stable_version` records the current stable channel pointer so that `channel_label()` can derive `[alpha]` vs `[stable]` without network I/O.
pub async fn write_version_cache(version: &str, stable_version: Option<&str>) {
    let version_path = fuigo_home().join("version.json");
    let now = time::OffsetDateTime::now_utc();
    let json = FuigoVersion::new(
        version.to_string(),
        stable_version.map(|s| s.to_string()),
        now,
    );
    if let Some(dir) = version_path.parent()
        && let Err(e) = fs::create_dir_all(dir).await
    {
        tracing::warn!("failed to create version cache directory: {}", e);
        return;
    }
    let tmp = version_path.with_extension("json.tmp");
    let data = match serde_json::to_vec_pretty(&json) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("failed to serialize version cache: {}", e);
            return;
        }
    };
    if let Err(e) = fs::write(&tmp, data).await {
        tracing::warn!("failed to write version cache tmp file: {}", e);
        return;
    }
    if let Err(e) = fs::rename(&tmp, &version_path).await {
        tracing::warn!("failed to rename version cache file: {}", e);
    }
}

/// Fetch the latest version for the given installer type and cache it.
///
/// Each installer is fully independent: there is no cross-installer fallback.
///
/// - `"npm"`: uses `npm view` against the public registry.
/// - `"internal"`: reads the channel pointer from the public GCS bucket.
/// - `"gh-release"`: uses `gh release list` against GitHub Releases.
pub async fn get_latest_version(installer: &str, config: &UpdateConfig) -> Result<String> {
    let version = fetch_latest_version(installer, config).await?;
    let stable_ptr = try_fetch_stable_pointer().await;
    write_version_cache(&version, stable_ptr.as_deref()).await;
    Ok(version)
}

/// True if `version.json` exists and is within TTL.
pub async fn is_version_cache_fresh() -> bool {
    let version_path = fuigo_home().join("version.json");
    let now = time::OffsetDateTime::now_utc();
    if let Ok(version_str) = fs::read_to_string(&version_path).await
        && let Ok(version) = serde_json::from_str::<FuigoVersion>(&version_str)
        && version.is_fresh(now, TTL_SECONDS_BEFORE_AUTO_UPDATE)
    {
        return true;
    }
    false
}

pub use fuigo_version::installed as get_installed_fuigo_version;

/// Version of the managed fuigo binary currently on disk, read from the
/// `~/.fuigo/bin/fuigo` symlink target (`../downloads/fuigo-<version>-<platform>`)
/// without exec'ing anything.
///
/// Concurrent updaters (TUI background download, leader hourly checker, explicit `fuigo update`) decide staleness from this.
/// They use it instead of their own compiled-in version, so a binary another process already installed is never downloaded a second time.
///
/// Returns `None` when there is no parseable managed symlink (Windows
/// copy-based installs, dev builds) or when the symlink is DANGLING — a
/// link whose target binary was deleted (e.g. manual `~/.fuigo/downloads`
/// cleanup) must not report an installed version, or every updater would
/// claim "already up to date" forever while no runnable binary exists.
/// NOTE: the symlink existing does not prove the *active installer* maintains it.
/// npm manages its own global install and a leftover symlink from a previous internal install would lie about the npm install's version.
/// Callers must gate on the installer (see `disk_version_for_installer` in `auto_update`).
pub fn installed_on_disk_version() -> Option<String> {
    #[cfg(unix)]
    {
        let app = fuigo_shell::util::fuigo_home::fuigo_application();
        let target = std::fs::read_link(&app).ok()?;
        // metadata() follows the symlink: Err means the target is gone (dangling link) and the version it names is not actually on disk
        std::fs::metadata(&app).ok()?;
        version_from_versioned_binary_name(target.file_name()?.to_str()?, "fuigo")
    }
    #[cfg(not(unix))]
    {
        None
    }
}

/// Everything between the `{bin_prefix}-` prefix and the first platform-OS component is the version, validated as semver.
/// Handles the internal layout (`fuigo-0.1.150-macos-aarch64`) and the npm layout without a platform suffix (`fuigo-0.1.150`).
/// Pre-releases parse whole: `fuigo-0.1.150-alpha.1-linux-x86_64` gives `0.1.150-alpha.1`.
/// Unknown layouts (`fuigo-latest`, `fuigo-pager-*` when `bin_prefix` is `fuigo`) return `None` instead of garbage.
///
/// Shared by the disk-version probe above and `cleanup_old_downloads` in `auto_update`; keep it the single place that understands this naming.
pub(crate) fn version_from_versioned_binary_name(name: &str, bin_prefix: &str) -> Option<String> {
    fuigo_shell::leader::version_from_versioned_binary_name(name, bin_prefix)
}

/// Fetch the stable channel pointer for caching alongside the version.
///
/// Tries each base URL in [`CLI_BASE_URLS`] and returns the first success.
/// Best-effort: returns `None` on any failure, and `channel_label()` returns `""` until the next successful fetch.
///
/// The entire operation is capped at 500 ms to keep startup and post-install paths fast.
/// The stable pointer is only used to derive the `[alpha]`/`[stable]` channel label; it is never required for correctness.
/// On slow or unreachable networks the timeout fires and we return `None`; the label populates on the next successful TTL check (~30 min).
pub(crate) async fn try_fetch_stable_pointer() -> Option<String> {
    tokio::time::timeout(Duration::from_millis(500), async {
        for base in cli_base_urls() {
            if let Ok(v) = fetch_gcs_channel_pointer("stable", &base).await {
                return Some(v);
            }
        }
        None
    })
    .await
    .unwrap_or(None)
}

/// Read the cached stable version from `~/.fuigo/version.json` (sync, for display).
///
/// Returns `None` if the file doesn't exist, can't be parsed, or has no `stable_version` field (e.g. written by an older binary).
pub fn cached_stable_version() -> Option<String> {
    let version_path = fuigo_home().join("version.json");
    let content = std::fs::read_to_string(&version_path).ok()?;
    let gv: FuigoVersion = serde_json::from_str(&content).ok()?;
    gv.stable_version
}

/// Returns `Some("alpha")` when `current > stable`, `Some("stable")` when `current <= stable`, or `None` when either version fails to parse.
fn derive_channel<'a>(current: &str, stable: &str) -> Option<&'a str> {
    let current_v = semver::Version::parse(current).ok()?;
    let stable_v = semver::Version::parse(stable).ok()?;
    if current_v > stable_v {
        Some("alpha")
    } else {
        Some("stable")
    }
}

/// Machine-readable channel name derived from the cached stable pointer.
///
/// Returns `Some("alpha")` when the current version is ahead of the cached stable pointer, `Some("stable")` when at or behind.
/// Returns `None` when no cached pointer is available (first launch, old cache format, parse error).
///
/// The result is computed once and cached for the process lifetime.
pub fn channel_name() -> Option<&'static str> {
    use std::sync::OnceLock;
    static NAME: OnceLock<Option<&'static str>> = OnceLock::new();
    *NAME.get_or_init(|| {
        let stable = cached_stable_version()?;
        derive_channel(fuigo_version::VERSION, &stable)
    })
}

/// Channel label derived from the cached stable pointer.
///
/// Compares the compiled-in `VERSION` against the stable pointer stored in
/// `~/.fuigo/version.json` (written by the auto-updater):
/// - `" [alpha]"` when the current version is ahead of stable,
/// - `" [stable]"` when at or behind stable,
/// - `""` when no cached pointer is available (first launch, old cache format).
///
/// The result is computed once and cached for the process lifetime.
pub fn channel_label() -> &'static str {
    use std::sync::OnceLock;
    static LABEL: OnceLock<&'static str> = OnceLock::new();
    LABEL.get_or_init(|| {
        let stable = match cached_stable_version() {
            Some(s) => s,
            None => return "",
        };
        match derive_channel(fuigo_version::VERSION, &stable) {
            Some("alpha") => " [alpha]",
            Some(_) => " [stable]",
            None => "",
        }
    })
}

#[cfg(test)]
mod tests {
    /// P145: npm's multi-line failure becomes one line with the code and the first real message.
    #[test]
    fn p145_npm_error_summary_is_one_line() {
        let refused = "npm error code ECONNREFUSED\nnpm error syscall connect\nnpm error errno ECONNREFUSED\n\
npm error FetchError: request to http://127.0.0.1:4873/fuigo failed, reason: connect ECONNREFUSED 127.0.0.1:4873\n\
npm error A complete log of this run can be found in: C:\\Users\\a\\npm-cache\\_logs\\x.log\n";
        assert_eq!(
            npm_error_summary(refused),
            "ECONNREFUSED: FetchError: request to http://127.0.0.1:4873/fuigo failed, reason: connect ECONNREFUSED 127.0.0.1:4873"
        );
        let forbidden = "npm error code E403\nnpm error 403 403 Forbidden - GET https://m.example/fuigo\nnpm error 403 In most cases";
        assert_eq!(npm_error_summary(forbidden), "E403: 403 Forbidden - GET https://m.example/fuigo");
        assert_eq!(npm_error_summary("npm ERR! code E404\nnpm ERR! 404 Not Found - GET x"), "E404: Not Found - GET x");
        assert_eq!(npm_error_summary("\n  something odd\n"), "something odd");
        assert_eq!(npm_error_summary(""), "npm failed without a message");
        let long = format!("npm error code X\nnpm error {}", "y".repeat(400));
        let got = npm_error_summary(&long);
        assert!(got.chars().count() <= 301 && !got.contains('\n'), "{got}");
    }

    #[test]
    fn loopback_base_rejects_userinfo_and_non_loopback() {
        use super::is_loopback_base;
        assert!(is_loopback_base("http://127.0.0.1:8971"));
        assert!(is_loopback_base("http://localhost:8971"));
        assert!(is_loopback_base("http://[::1]:8971"));
        // Prefix-check bypass vectors.
        assert!(!is_loopback_base("http://127.0.0.1:9@evil.com"));
        assert!(!is_loopback_base("http://localhost.evil.com:80"));
        assert!(!is_loopback_base("https://x.ai/cli"));
        assert!(!is_loopback_base("http://192.168.1.1:80"));
        assert!(!is_loopback_base(""));
    }

    use super::*;

    /// Verifies that a future `checked_at` timestamp (e.g. from clock skew or NTP time-warp) is never considered fresh.
    /// Without the clock-skew guard this would return true indefinitely, silently disabling auto-update.
    #[test]
    fn test_is_fresh_rejects_future_timestamp() {
        let now = time::OffsetDateTime::now_utc();
        let future = now + Duration::from_secs(600);
        let v = FuigoVersion::new("0.1.200".to_string(), None, future);
        assert!(
            !v.is_fresh(now, Duration::from_secs(30)),
            "Future timestamp must not be considered fresh (clock-skew guard)."
        );
    }

    /// Disk-version probe: parsing the version out of the managed install's symlink-target file name (`fuigo-<version>-<platform>`).
    #[test]
    fn test_version_from_versioned_binary_name() {
        let cases: &[(&str, Option<&str>)] = &[
            ("fuigo-0.2.46-darwin-arm64", Some("0.2.46")),
            ("fuigo-0.1.220-linux-x86_64", Some("0.1.220")),
            ("fuigo-0.2.5-windows-x86_64.exe", Some("0.2.5")),
            // Pre-releases must round-trip whole
            // Truncating to "0.1.220" would make an alpha install masquerade as the release and mask updates from alpha to stable
            ("fuigo-0.1.220-alpha.4-linux-x86_64", Some("0.1.220-alpha.4")),
            ("fuigo-0.1.220-alpha.4", Some("0.1.220-alpha.4")), // npm layout
            ("fuigo-pager-0.1.5-darwin-arm64", None),          // "pager" is not a version
            ("fuigo-garbage-darwin-arm64", None),              // unparseable version
            ("fuigo-0.2.46", Some("0.2.46")),                   // no platform suffix
            ("other-0.2.46-darwin-arm64", None),               // wrong prefix
            ("grok-0.2.46-darwin-arm64", None),                // upstream is not Fuigo
            ("fuigo-latest", None),                            // symlink alias, not a version
            ("fuigo", None),                                   // bare name
            ("", None),
        ];
        for (name, expected) in cases {
            assert_eq!(
                version_from_versioned_binary_name(name, "fuigo").as_deref(),
                *expected,
                "version_from_versioned_binary_name({name:?})"
            );
        }

        // bin_prefix discrimination: the pager binary parses under its own prefix but not under "fuigo"
        assert_eq!(
            version_from_versioned_binary_name("fuigo-pager-0.1.5-darwin-arm64", "fuigo-pager")
                .as_deref(),
            Some("0.1.5")
        );
    }

    // ──────────────────────────────────────────────────────────────────────
    // derive_channel — invariant matrix
    //
    // Tests the pure comparison logic that determines [alpha] vs [stable].
    // Covers current 0.1.X-alpha.N, future 0.2.X, edge cases, and errors.
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_derive_channel_matrix() {
        // (current, stable_pointer, expected_channel)
        let cases: &[(&str, &str, Option<&str>)] = &[
            // ── Current 0.1.X workflow ──
            ("0.1.220-alpha.2", "0.1.219", Some("alpha")), // alpha ahead of stable
            ("0.1.219", "0.1.219", Some("stable")),        // stable user on latest
            ("0.1.218", "0.1.219", Some("stable")),        // stable user behind latest
            ("0.1.220-alpha.2", "0.1.220-alpha.2", Some("stable")), // pointer matches exactly
            ("0.1.220-alpha.2", "0.1.220", Some("stable")), // semver: release > pre-release
            // ── Future 0.2.X workflow ──
            ("0.2.5", "0.2.3", Some("alpha")), // alpha ahead of stable
            ("0.2.5", "0.2.5", Some("stable")), // promoted to stable
            ("0.2.3", "0.2.5", Some("stable")), // behind stable
            ("0.2.0", "0.2.0", Some("stable")), // first release, both 0.2.0
            // ── Cross-regime upgrade ──
            ("0.2.0", "0.1.219", Some("alpha")), // new regime ahead of old stable
            ("0.1.220-alpha.2", "0.2.0", Some("stable")), // old pre-release < new stable
            // ── Error cases ──
            ("garbage", "0.1.219", None), // unparseable current
            ("0.1.219", "garbage", None), // unparseable stable
            ("", "0.1.219", None),        // empty current
            ("0.1.219", "", None),        // empty stable
        ];

        for (current, stable, expected) in cases {
            let result = derive_channel(current, stable);
            assert_eq!(
                result, *expected,
                "derive_channel({:?}, {:?}) = {:?}, expected {:?}",
                current, stable, result, expected,
            );
        }
    }

    // ──────────────────────────────────────────────────────────────────────
    // semver_max — invariant matrix
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_semver_max_matrix() {
        // (a, b, expected)
        let cases: &[(&str, &str, &str)] = &[
            ("0.1.140", "0.1.140", "0.1.140"),                         // equal
            ("0.1.140", "0.1.141", "0.1.141"),                         // b higher
            ("0.1.141", "0.1.140", "0.1.141"),                         // a higher
            ("0.1.148-alpha.3", "0.1.148", "0.1.148"),                 // release > pre-release
            ("0.1.148", "0.1.148-alpha.3", "0.1.148"),                 // commutative
            ("0.1.148-alpha.1", "0.1.148-alpha.3", "0.1.148-alpha.3"), // pre-release ordering
            ("0.1.149-alpha.1", "0.1.148", "0.1.149-alpha.1"),         // higher base wins
            ("0.0.0", "0.0.1", "0.0.1"),                               // zero versions
            ("0.99.99", "1.0.0", "1.0.0"),                             // major jump
        ];

        for (a, b, expected) in cases {
            assert_eq!(
                semver_max(a, b).unwrap(),
                *expected,
                "semver_max({:?}, {:?})",
                a,
                b,
            );
        }
    }

    #[test]
    fn test_semver_max_invalid_input_returns_err() {
        assert!(semver_max("garbage", "0.1.141").is_err());
        assert!(semver_max("0.1.141", "garbage").is_err());
        assert!(semver_max("foo", "bar").is_err());
    }

    // ──────────────────────────────────────────────────────────────────────
    // FuigoVersion JSON shape — backward compatibility invariants
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_version_json_backward_compat() {
        // Old format (no stable_version) must parse; serde(default) fills None
        let old = r#"{"version":"0.1.180","checked_at":"2026-04-22T10:30:00Z"}"#;
        let v: FuigoVersion = serde_json::from_str(old).unwrap();
        assert_eq!(v.version, "0.1.180");
        assert!(v.stable_version.is_none());

        // New format with stable_version round-trips correctly.
        let now = time::OffsetDateTime::now_utc();
        let new = FuigoVersion::new("0.2.5".to_string(), Some("0.2.3".to_string()), now);
        let json = serde_json::to_string(&new).unwrap();
        let parsed: FuigoVersion = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.version, "0.2.5");
        assert_eq!(parsed.stable_version.as_deref(), Some("0.2.3"));

        assert!(
            time::OffsetDateTime::parse(
                &parsed.checked_at,
                &time::format_description::well_known::Rfc3339,
            )
            .is_ok()
        );

        // Unknown fields are ignored (forward-compat).
        let future = r#"{"version":"0.1.180","checked_at":"2026-04-22T10:30:00Z","future":"ok"}"#;
        assert!(serde_json::from_str::<FuigoVersion>(future).is_ok());

        // Missing required field (checked_at) is rejected.
        let missing = r#"{"version":"0.1.180"}"#;
        assert!(serde_json::from_str::<FuigoVersion>(missing).is_err());
    }

    // ──────────────────────────────────────────────────────────────────────
    // is_fresh — TTL boundary invariants
    // ──────────────────────────────────────────────────────────────────────

    #[test]
    fn test_is_fresh_ttl_boundaries() {
        let now = time::OffsetDateTime::now_utc();
        let v = FuigoVersion::new("0.1.200".to_string(), None, now);

        // Within the TTL the timestamp is fresh
        assert!(v.is_fresh(now, Duration::from_secs(60)));
        assert!(v.is_fresh(now + Duration::from_secs(29), Duration::from_secs(30)));

        // At the TTL boundary it is not fresh (strict <)
        assert!(!v.is_fresh(now + Duration::from_secs(30), Duration::from_secs(30)));

        // Past the TTL it is not fresh
        assert!(!v.is_fresh(now + Duration::from_secs(31), Duration::from_secs(30)));

        // A zero TTL is never fresh
        assert!(!v.is_fresh(now, Duration::ZERO));

        // A malformed timestamp is not fresh
        let bad = FuigoVersion {
            version: "0.1.200".to_string(),
            stable_version: None,
            checked_at: "not-rfc3339".to_string(),
        };
        assert!(!bad.is_fresh(now, Duration::from_secs(60)));
    }

    /// R110 (U2): the highest version wins over list order (gh lists newest created first);
    /// stable ignores semver prereleases; junk tags are skipped.
    #[test]
    fn highest_release_version_is_semver_max_not_list_order() {
        use super::highest_release_version;
        let tags = "v1.0.19\nv1.0.22-rc.1\nv1.0.21\nnightly\nv1.0.20\n";
        assert_eq!(highest_release_version(tags, true).as_deref(), Some("1.0.21"));
        assert_eq!(highest_release_version(tags, false).as_deref(), Some("1.0.22-rc.1"));
        assert_eq!(highest_release_version("v1.0.10\nv1.0.9\n", true).as_deref(), Some("1.0.10"));
        assert_eq!(highest_release_version("", true), None);
        assert_eq!(highest_release_version("latest\n", true), None);
    }
}

#[cfg(test)]
mod p70_redacted_debug {
    use super::*;

    /// `{x:?}` and `{x:#?}` hold `<redacted>` (control) and no fragment of any secret.
    fn assert_redacted(debug: &dyn std::fmt::Debug, secrets: &[&str]) {
        for out in [format!("{debug:?}"), format!("{debug:#?}")] {
            assert!(out.contains("<redacted>"), "control: the secret field is printed as redacted: {out}");
            for secret in secrets {
                let chars: Vec<char> = secret.chars().collect();
                for w in chars.windows(6) {
                    let frag: String = w.iter().collect();
                    assert!(!out.contains(&frag), "Debug output holds {frag:?} of a secret: {out}");
                }
            }
        }
    }

    #[test]
    fn update_config_debug_redacts_keys() {
        let cfg = UpdateConfig {
            proxy_base_url: "https://p70.invalid/v1".into(),
            auth_scope: "fuigo::p70".into(),
            deployment_key: Some("p70dk-FAKE-2b3c4d5e".into()),
            alpha_test_key: Some("p70ak-FAKE-6f7a8b9c".into()),
            channel: "stable".into(),
            npm_registry: None,
        };
        assert_redacted(&cfg, &["p70dk-FAKE-2b3c4d5e", "p70ak-FAKE-6f7a8b9c"]);
    }
}

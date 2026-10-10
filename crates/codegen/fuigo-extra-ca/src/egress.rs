//! Egress guard: Fuigo must not contact the upstream vendor's estate.
//!
//! # Why this is a DNS resolver and not a URL check
//!
//! Fuigo inherited ~70 source files carrying `x.ai` / `grok.com` URLs as
//! constants, defaults, and fallbacks. Repointing them one at a time is a
//! whack-a-mole that a later merge, a config file, a managed policy blob, or a
//! server-supplied redirect can silently undo. A URL check also has to be
//! written at every call site, which is exactly the property that made the
//! problem hard.
//!
//! Refusing to RESOLVE the names instead makes the guarantee structural: the
//! connection cannot be established regardless of which code path built the
//! URL or where the string came from. It is the same move as the rebrand
//! transform's mask-first pass — make the bad outcome unreachable by
//! construction rather than by the correctness of a hundred call sites.
//!
//! # What this does NOT cover
//!
//! Be precise about the boundary, because an overstated guarantee is worse
//! than none:
//!
//! - Only clients built through [`crate::build_reqwest_client`],
//!   [`crate::build_blocking_reqwest_client`] and
//!   [`crate::subscription::SubscriptionClient`]. `clippy.toml` disallows the
//!   raw reqwest constructors, so that is nearly everything — but `fuigo-mcp`
//!   carries a separate reqwest 0.13 stack, and `fuigo-computer-hub-sdk`
//!   builds its own OIDC client. Neither is covered here.
//! - [`crate::subscription::SubscriptionClient`] carries the ONE exemption:
//!   each instance may resolve exactly its own recipient's host (for the xAI
//!   subscription, `auth.x.ai` for the token client or `api.x.ai` for the
//!   inference client) and nothing else on the list. Every other blocked
//!   name, including the rest of `x.ai`, `grok.com` and `mixpanel.com`, is
//!   still refused on that client. The exemption is safe only together with
//!   that client's exact-URL recipient check and its disabled redirects; see
//!   [`resolver_allowing_exactly`].
//! - Not websockets that dial an IP directly, and not a literal IP address in
//!   a URL. There is no name to refuse.
//! - Not a substitute for removing the URLs. It is the backstop that proves
//!   the removal worked, and catches the ones we missed.
//!
//! Set `FUIGO_ALLOW_UPSTREAM_HOSTS=api.x.ai,auth.x.ai` (comma-separated exact
//! hostnames) to lift the block for just those names: no suffix or subdomain
//! matching, case-insensitive, one trailing dot tolerated. A malformed list
//! warns and allows nothing; it never becomes the full lift.
//!
//! Set `FUIGO_ALLOW_UPSTREAM_HOSTS=1` to lift the block — for someone who
//! genuinely wants to point Fuigo at xAI with their own API key. It is
//! PROCESS-WIDE: every guarded client in the process may then resolve every
//! blocked name, telemetry backstops (`mixpanel.com`) included. Subscription
//! login and inference do not need it (see the exemption above).

use std::net::ToSocketAddrs;

use reqwest::dns::Addrs;
use reqwest::dns::Name;
use reqwest::dns::Resolve;
use reqwest::dns::Resolving;

/// Escape hatch. Truthy value lifts the block entirely.
pub const ENV_FUIGO_ALLOW_UPSTREAM_HOSTS: &str = "FUIGO_ALLOW_UPSTREAM_HOSTS";

/// Registrable domains Fuigo refuses to resolve, with every subdomain.
///
/// `x.ai` covers api/auth/accounts/docs/console; `grok.com` covers the chat
/// proxy, the asset CDN and both websocket planes. `mixpanel.com` is upstream's
/// product analytics — disabled by default in this fork because no token is
/// baked in, but a config file can still switch it on.
const BLOCKED_DOMAINS: &[&str] = &["x.ai", "grok.com", "mixpanel.com"];

/// Whether `host` is inside one of [`BLOCKED_DOMAINS`].
///
/// Matches on label boundaries, never as a bare substring. This matters: the
/// tree contains deliberate SSRF fixtures such as `prefixx.ai` and
/// `api.x.ai.evil.example`, and both must come out UNBLOCKED — the first is a
/// different registrable domain, the second is `evil.example`. A naive
/// `contains()` would get both wrong and would hide the very bug those
/// fixtures exist to catch.
pub fn is_blocked_host(host: &str) -> bool {
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    BLOCKED_DOMAINS.iter().any(|blocked| {
        host == *blocked
            || host
                .strip_suffix(blocked)
                .is_some_and(|prefix| prefix.ends_with('.'))
    })
}

/// What `FUIGO_ALLOW_UPSTREAM_HOSTS` allows.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum UpstreamAllowance {
    /// Unset, empty, falsy or invalid: the whole block stays in force.
    #[default]
    None,
    /// `1`/`true`/`yes`/`on`: the whole block is lifted (process-wide).
    All,
    /// A comma-separated list of exact hostnames (lowercase, no trailing dot).
    /// Only these names are lifted; no suffix or subdomain matching.
    Hosts(Vec<String>),
}

/// A syntactically valid DNS hostname with at least two labels. IP literals,
/// wildcards, ports, paths and bare words like `1` are not accepted.
fn valid_allow_host(h: &str) -> bool {
    h.len() <= 253
        && h.contains('.')
        && !h.chars().all(|c| c.is_ascii_digit() || c == '.')
        && h.split('.').all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// A malformed `FUIGO_ALLOW_UPSTREAM_HOSTS` list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidAllowList;

/// Parse the value of `FUIGO_ALLOW_UPSTREAM_HOSTS`. Pure; the caller decides
/// whether to warn. Returns `Err(InvalidAllowList)` for a malformed list, which callers must
/// treat as [`UpstreamAllowance::None`], never as the full lift.
pub fn parse_upstream_allowance(
    raw: Option<&str>,
) -> Result<UpstreamAllowance, InvalidAllowList> {
    let Some(raw) = raw else {
        return Ok(UpstreamAllowance::None);
    };
    let trimmed = raw.trim();
    let lower = trimmed.to_ascii_lowercase();
    if matches!(lower.as_str(), "1" | "true" | "yes" | "on") {
        return Ok(UpstreamAllowance::All);
    }
    if matches!(lower.as_str(), "" | "0" | "false" | "no" | "off") {
        return Ok(UpstreamAllowance::None);
    }
    let mut hosts = Vec::new();
    for entry in trimmed.split(',') {
        let trimmed_entry = entry.trim();
        let host = trimmed_entry.strip_suffix('.').unwrap_or(trimmed_entry).to_ascii_lowercase();
        if !valid_allow_host(&host) {
            return Err(InvalidAllowList);
        }
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    Ok(UpstreamAllowance::Hosts(hosts))
}

/// The allowance from the environment. A malformed value warns (once) and
/// allows nothing.
pub fn upstream_allowance() -> UpstreamAllowance {
    static WARNED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    let raw = std::env::var(ENV_FUIGO_ALLOW_UPSTREAM_HOSTS).ok();
    match parse_upstream_allowance(raw.as_deref()) {
        Ok(a) => a,
        Err(InvalidAllowList) => {
            if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                tracing::warn!(
                    "{ENV_FUIGO_ALLOW_UPSTREAM_HOSTS} is not 1/true/yes/on or a comma-separated \
                     list of exact hostnames; ignoring it (no upstream host is allowed)"
                );
            }
            UpstreamAllowance::None
        }
    }
}

/// Whether the guard is active for this process. `false` only for the full
/// lift; a host list leaves the guard active and exempts just those names
/// (see [`is_refused_host`]).
pub fn guard_enabled() -> bool {
    upstream_allowance() != UpstreamAllowance::All
}

/// Whether the guard refuses `host` for an ordinary client: it is on the
/// denylist and the environment allowance does not cover it. Call sites that
/// used `guard_enabled() && is_blocked_host(h)` use this instead.
pub fn is_refused_host(host: &str) -> bool {
    refuses(host, None)
}

/// Whether the guard refuses `host` on a client whose single permitted
/// vendor host is `allowed` (`None` for every ordinary client). The exception
/// is an exact, case-sensitive match: resolver names come from the parsed URL,
/// which is already lowercase, and a trailing-dot spelling is refused. The
/// environment host list is matched exactly after lowercasing and dropping one
/// trailing dot.
fn refuses(host: &str, allowed: Option<&str>) -> bool {
    refuses_under(host, allowed, &upstream_allowance())
}

fn refuses_under(host: &str, allowed: Option<&str>, allowance: &UpstreamAllowance) -> bool {
    if !is_blocked_host(host) || allowed.is_some_and(|allowed| host == allowed) {
        return false;
    }
    match allowance {
        UpstreamAllowance::All => false,
        UpstreamAllowance::None => true,
        UpstreamAllowance::Hosts(list) => {
            let h = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
            !list.contains(&h)
        }
    }
}

/// Refuses upstream-vendor names; delegates everything else to the OS resolver.
#[derive(Debug, Default, Clone, Copy)]
pub struct EgressGuard;

impl Resolve for EgressGuard {
    fn resolve(&self, name: Name) -> Resolving {
        guarded_resolve(name.as_str().to_owned(), None)
    }
}

/// [`EgressGuard`] with one exact-host exception. Crate-private: the only
/// holder is [`crate::subscription::SubscriptionClient`], which also refuses
/// every URL but its recipient's exact endpoints and never follows a redirect,
/// so the exception cannot be steered to another path, host or client.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ExactHostException {
    host: &'static str,
}

impl Resolve for ExactHostException {
    fn resolve(&self, name: Name) -> Resolving {
        guarded_resolve(name.as_str().to_owned(), Some(self.host))
    }
}

/// The guard for a client that may resolve `host`, and no other blocked name.
pub(crate) fn resolver_allowing_exactly(host: &'static str) -> std::sync::Arc<ExactHostException> {
    std::sync::Arc::new(ExactHostException { host })
}

fn guarded_resolve(host: String, allowed: Option<&'static str>) -> Resolving {
    Box::pin(async move {
        if refuses(&host, allowed) {
            tracing::warn!(
                host = %host,
                "blocked egress to an upstream vendor host; set {}=1 or list the exact host to allow",
                ENV_FUIGO_ALLOW_UPSTREAM_HOSTS
            );
            return Err(Box::<dyn std::error::Error + Send + Sync>::from(format!(
                "fuigo refuses to contact upstream vendor host `{host}` \
                 (set {ENV_FUIGO_ALLOW_UPSTREAM_HOSTS} to 1 or to a list naming the exact host to allow)"
            )));
        }
        #[cfg(test)]
        if test_hook::record_admitted(&host) {
            return Err(Box::<dyn std::error::Error + Send + Sync>::from(
                test_hook::ADMITTED_SENTINEL,
            ));
        }
        // Port 0: reqwest overrides it with the scheme's port, or the one
        // named in the URL. It is a placeholder, not a destination.
        let addrs =
            tokio::task::spawn_blocking(move || (host.as_str(), 0).to_socket_addrs()).await??;
        Ok(Box::new(addrs) as Addrs)
    })
}

/// Test-only observation point: lets a test see which names the guard ADMITS
/// without a real DNS lookup or connection. Thread-local, so it is only active for
/// a test that arms it on a current-thread runtime (where reqwest's connect future
/// runs on the arming thread); every other test, and every shipped build, gets the
/// OS resolver.
#[cfg(test)]
pub(crate) mod test_hook {
    use std::cell::RefCell;

    pub(crate) const ADMITTED_SENTINEL: &str = "test hook: name admitted by the egress guard";

    thread_local! {
        static ADMITTED: RefCell<Option<Vec<String>>> = const { RefCell::new(None) };
    }

    /// Arm the hook on this thread; [`take`] returns the names admitted since.
    pub(crate) fn arm() {
        ADMITTED.with(|a| *a.borrow_mut() = Some(Vec::new()));
    }

    pub(crate) fn take() -> Vec<String> {
        ADMITTED.with(|a| a.borrow_mut().take().unwrap_or_default())
    }

    pub(super) fn record_admitted(host: &str) -> bool {
        ADMITTED.with(|a| match a.borrow_mut().as_mut() {
            Some(names) => {
                names.push(host.to_owned());
                true
            }
            None => false,
        })
    }
}

/// The guard as reqwest wants it.
pub fn resolver() -> std::sync::Arc<EgressGuard> {
    std::sync::Arc::new(EgressGuard)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_the_apex_and_its_subdomains() {
        for host in [
            "x.ai",
            "api.x.ai",
            "auth.x.ai",
            "accounts.x.ai",
            "grok.com",
            "cli-chat-proxy.grok.com",
            "assets.grok.com",
            "code.grok.com",
            "computer-hub.grok.com",
            "api.mixpanel.com",
        ] {
            assert!(is_blocked_host(host), "{host} should be blocked");
        }
    }

    /// P87: the subscription exception admits exactly one name. Its siblings
    /// in the same registrable domain, the other vendor domains and spelling
    /// variants stay refused; ordinary names are unaffected.
    #[test]
    fn exact_host_exception_admits_only_that_host() {
        assert!(
            guard_enabled(),
            "FUIGO_ALLOW_UPSTREAM_HOSTS lifts the guard this test pins; unset it"
        );
        assert!(!refuses("auth.x.ai", Some("auth.x.ai")));
        assert!(!refuses("api.x.ai", Some("api.x.ai")));
        for (host, allowed) in [
            ("api.x.ai", Some("auth.x.ai")),
            ("x.ai", Some("auth.x.ai")),
            ("accounts.x.ai", Some("auth.x.ai")),
            ("auth.x.ai.", Some("auth.x.ai")),
            ("AUTH.X.AI", Some("auth.x.ai")),
            ("api.mixpanel.com", Some("api.x.ai")),
            ("cli-chat-proxy.grok.com", Some("api.x.ai")),
            ("auth.x.ai", None),
            ("api.x.ai", None),
        ] {
            assert!(
                refuses(host, allowed),
                "{host} must stay refused (allowed {allowed:?})"
            );
        }
        assert!(!refuses("github.com", Some("auth.x.ai")));
        assert!(!refuses("github.com", None));
    }

    #[test]
    fn is_case_insensitive_and_tolerates_a_trailing_root_dot() {
        assert!(is_blocked_host("API.X.AI"));
        assert!(is_blocked_host("api.x.ai."));
    }

    /// The whole reason this matches on label boundaries. These two hosts are
    /// SSRF fixtures elsewhere in the tree; blocking them would both be wrong
    /// and would mask the bug they were written to catch.
    #[test]
    fn does_not_block_lookalikes() {
        for host in [
            "prefixx.ai",
            "notx.ai",
            "api.x.ai.evil.example",
            "evil-x.ai.attacker.com",
            "grok.com.evil.example",
            "mygrok.com",
            "api.fluxrouter.ai",
            "github.com",
        ] {
            assert!(!is_blocked_host(host), "{host} must NOT be blocked");
        }
    }

    fn allow(raw: &str) -> UpstreamAllowance {
        parse_upstream_allowance(Some(raw)).expect("valid")
    }

    #[test]
    fn parses_the_full_lift_none_and_host_lists() {
        for v in ["1", "true", "YES", " on "] {
            assert_eq!(allow(v), UpstreamAllowance::All, "{v}");
        }
        for v in ["", "0", "false", "no", "off"] {
            assert_eq!(allow(v), UpstreamAllowance::None, "{v}");
        }
        assert_eq!(parse_upstream_allowance(None), Ok(UpstreamAllowance::None));
        assert_eq!(
            allow("api.x.ai, AUTH.x.ai.,api.x.ai"),
            UpstreamAllowance::Hosts(vec!["api.x.ai".into(), "auth.x.ai".into()])
        );
    }

    #[test]
    fn an_invalid_entry_is_an_error_never_the_full_lift() {
        for v in [
            "1,api.x.ai", "api.x.ai,", ",api.x.ai", "*.x.ai", "x.ai/path", "api.x.ai:443",
            "https://api.x.ai", "10.0.0.1", "api..x.ai", "-a.x.ai", "bogus", "api.x.ai auth.x.ai",
            "maybe", "api.x.ai..", "auth.x.ai,api.x.ai..", "api.x.ai.,.",
        ] {
            assert_eq!(parse_upstream_allowance(Some(v)), Err(InvalidAllowList), "{v:?}");
        }
    }

    #[test]
    fn a_host_list_allows_exactly_those_names() {
        let a = allow("api.x.ai,auth.x.ai");
        for h in ["api.x.ai", "auth.x.ai", "API.X.AI", "api.x.ai."] {
            assert!(!refuses_under(h, None, &a), "{h} should be allowed");
        }
        // Only ONE trailing root dot is a spelling variant of the name.
        assert!(refuses_under("api.x.ai..", None, &a));
        for h in [
            "x.ai", "accounts.x.ai", "v2.api.x.ai", "grok.com", "cli-chat-proxy.grok.com",
            "api.mixpanel.com", "mixpanel.com",
        ] {
            assert!(refuses_under(h, None, &a), "{h} must stay refused");
        }
        // SSRF fixtures are not on the denylist at all and stay unaffected.
        for h in ["prefixx.ai", "api.x.ai.evil.example"] {
            assert!(!refuses_under(h, None, &a), "{h} is not a vendor host");
        }
        // A list naming a lookalike does not unlock the real domain.
        let b = allow("api.x.ai.evil.example");
        assert!(refuses_under("api.x.ai", None, &b));
    }

    #[test]
    fn the_full_lift_and_the_default_are_unchanged() {
        for h in ["api.x.ai", "mixpanel.com", "assets.grok.com"] {
            assert!(!refuses_under(h, None, &UpstreamAllowance::All));
            assert!(refuses_under(h, None, &UpstreamAllowance::None));
        }
        assert!(!refuses_under("github.com", None, &UpstreamAllowance::None));
    }
}

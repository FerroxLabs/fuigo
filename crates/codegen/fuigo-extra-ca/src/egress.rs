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

/// Whether the guard is active for this process.
pub fn guard_enabled() -> bool {
    !std::env::var(ENV_FUIGO_ALLOW_UPSTREAM_HOSTS)
        .is_ok_and(|v| matches!(v.trim(), "1" | "true" | "yes" | "on"))
}

/// Whether the guard refuses `host` on a client whose single permitted
/// vendor host is `allowed` (`None` for every ordinary client). The exception
/// is an exact, case-sensitive match: resolver names come from the parsed URL,
/// which is already lowercase, and a trailing-dot spelling is refused.
fn refuses(host: &str, allowed: Option<&str>) -> bool {
    guard_enabled() && is_blocked_host(host) && allowed.is_none_or(|allowed| host != allowed)
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
                "blocked egress to an upstream vendor host; set {}=1 to allow",
                ENV_FUIGO_ALLOW_UPSTREAM_HOSTS
            );
            return Err(Box::<dyn std::error::Error + Send + Sync>::from(format!(
                "fuigo refuses to contact upstream vendor host `{host}` \
                 (set {ENV_FUIGO_ALLOW_UPSTREAM_HOSTS}=1 to allow)"
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
}

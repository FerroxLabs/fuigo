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
//! - Only clients built through [`crate::build_reqwest_client`] and
//!   [`crate::build_blocking_reqwest_client`]. `clippy.toml` disallows the raw
//!   reqwest constructors, so that is nearly everything — but `fuigo-mcp`
//!   carries a separate reqwest 0.13 stack, and `fuigo-computer-hub-sdk`
//!   builds its own OIDC client. Neither is covered here.
//! - Not websockets that dial an IP directly, and not a literal IP address in
//!   a URL. There is no name to refuse.
//! - Not a substitute for removing the URLs. It is the backstop that proves
//!   the removal worked, and catches the ones we missed.
//!
//! Set `FUIGO_ALLOW_UPSTREAM_HOSTS=1` to lift the block — for someone who
//! genuinely wants to point Fuigo at xAI with their own key.

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

/// Refuses upstream-vendor names; delegates everything else to the OS resolver.
#[derive(Debug, Default, Clone, Copy)]
pub struct EgressGuard;

impl Resolve for EgressGuard {
    fn resolve(&self, name: Name) -> Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            if guard_enabled() && is_blocked_host(&host) {
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
            // Port 0: reqwest overrides it with the scheme's port, or the one
            // named in the URL. It is a placeholder, not a destination.
            let addrs = tokio::task::spawn_blocking(move || (host.as_str(), 0).to_socket_addrs())
                .await??;
            Ok(Box::new(addrs) as Addrs)
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

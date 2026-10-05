//! P47: the **service-endpoint** trust class — may the session token go to an auxiliary service?
//!
//! P30 split destinations into two classes (`docs/destination-trust-policy.md`): FluxRouter-operated
//! (identity disclosure, compiled, [`crate::fluxrouter`]) and user-configured API origin (credential
//! delivery, `fuigo_shell_base::util::TrustedApiOrigins`). P42 made every *inference-class* session
//! delivery decide through one predicate (`fuigo-shell` `auth::session_delivery::session_may_reach`).
//! The auxiliary Ferrox-service clients (managed config, `/user`, billing, consent, privacy, remote
//! settings and bundles, sandbox, skills, workspaces, conversations, chat modes, session registry,
//! feedback, trace upload, the OTLP exporter, the WebSocket relay, the Computer Hub) were a third
//! class with no destination check at all. This module is that class's one predicate:
//! [`session_may_reach_service`].
//!
//! # The rule
//!
//! The session token may be attached to a service request for `url` only when **all** hold:
//!
//! 1. `url` parses and carries no userinfo;
//! 2. its scheme is `https` (or `wss`, for the two WebSocket services: relay and hub);
//! 3. its host is not loopback (`localhost` and `*.localhost`, `127.0.0.0/8`, `::1`, an IPv4-mapped
//!    loopback) and not unspecified (`0.0.0.0`, `::`), which also reaches this machine;
//! 4. its origin is one of:
//!    * **FluxRouter-operated** ([`crate::fluxrouter::is_fluxrouter_operated_url`]: compiled host, `https`,
//!      default port);
//!    * a **configured API origin**: the caller passes the P42 predicate (`session_may_reach`, the
//!      `[endpoints]` trust set) as `configured_api_origin`; a process with no such set passes `|_| false`;
//!    * the **configured service base** of the calling client: `configured_service_base` is the base the
//!      client resolved from operator configuration (an `[endpoints]` service key, `[hub].url`, a named
//!      service env var). Same scheme, host (case, IDN and trailing root dot normalised) and port.
//!
//! There is no exception for loopback or cleartext. A configured `http://` or loopback service base
//! does not admit itself: rules 2 and 3 are checked before rule 4.
//!
//! `configured_service_base` must come from configuration, never from a caller, a server response or
//! a URL the client is about to follow. A URL derived from such a source (a hub URL passed on a
//! control command, a redirect) is admitted only if it is on a configured origin.
//!
//! # Failure
//!
//! A refusal is a [`RefusedServiceDestination`]. Callers do not send the request at all — neither with
//! the token nor without it — and return an error whose text is [`RefusedServiceDestination`]'s
//! `Display`: it names the refused origin (scheme, host, port; never a path or query) and the remedy.
//! Sending it unauthenticated would put the body and the identity headers on an untrusted wire and
//! come back as a 401 that every client reports as "run `fuigo login`", which is wrong.

use std::fmt;

/// Why a service destination may not receive the session token.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceRefusal {
    /// The URL does not parse or has no host.
    Unparseable,
    /// The URL carries userinfo (`https://user@host/`), a separate credential channel.
    Userinfo,
    /// The scheme is not `https`/`wss` (plain `http`, `ws`, or anything else).
    Cleartext,
    /// The host is this machine (loopback or unspecified address, `localhost`).
    Loopback,
    /// None of FluxRouter-operated, a configured API origin, or the client's configured service base.
    NotTrusted,
}

/// A refused service destination: the request must not be sent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefusedServiceDestination {
    /// `scheme://host[:port]` of the refused URL, or `<unparseable>`. Never a path, query or userinfo.
    pub origin: String,
    pub reason: ServiceRefusal,
}

impl RefusedServiceDestination {
    /// Stable short label for logs and telemetry.
    pub fn reason_label(&self) -> &'static str {
        match self.reason {
            ServiceRefusal::Unparseable => "unparseable",
            ServiceRefusal::Userinfo => "userinfo",
            ServiceRefusal::Cleartext => "cleartext",
            ServiceRefusal::Loopback => "loopback",
            ServiceRefusal::NotTrusted => "not_trusted",
        }
    }
}

impl fmt::Display for RefusedServiceDestination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let why = match self.reason {
            ServiceRefusal::Unparseable => "it is not a valid URL",
            ServiceRefusal::Userinfo => "the URL carries a user name or password",
            ServiceRefusal::Cleartext => "it is not https (or wss)",
            ServiceRefusal::Loopback => "it is this machine (loopback)",
            ServiceRefusal::NotTrusted => {
                "it is neither FluxRouter nor a configured `[endpoints]` or service origin"
            }
        };
        write!(
            f,
            "Your Fuigo sign-in was not sent to {}: {why}. The request was not made. \
             Point the service's endpoint setting (for example `[endpoints].cli_chat_proxy_base_url`) \
             at an https origin that is not this machine.",
            self.origin
        )
    }
}

impl std::error::Error for RefusedServiceDestination {}

/// `scheme://host[:port]` (default port omitted), the only form of a refused URL that is ever shown.
fn origin_of(url: &reqwest::Url) -> String {
    let host = url.host_str().unwrap_or("");
    match url.port() {
        Some(port) => format!("{}://{host}:{port}", url.scheme()),
        None => format!("{}://{host}", url.scheme()),
    }
}

fn normalized_host(url: &reqwest::Url) -> Option<String> {
    url.host_str()
        .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
        .filter(|h| !h.is_empty())
}

/// Whether `url` addresses this machine: `localhost` / `*.localhost` (RFC 6761 reserves both for
/// loopback), any loopback or unspecified IP, including an IPv4-mapped IPv6 loopback.
pub fn is_local_host(url: &reqwest::Url) -> bool {
    let Some(host) = normalized_host(url) else {
        return false;
    };
    if host == "localhost" || host.ends_with(".localhost") {
        return true;
    }
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    match bare.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => ip.is_loopback() || ip.is_unspecified(),
        Ok(std::net::IpAddr::V6(ip)) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ip
                    .to_ipv4_mapped()
                    .is_some_and(|v4| v4.is_loopback() || v4.is_unspecified())
        }
        Err(_) => false,
    }
}

/// Same scheme, normalised host and effective port; the base must itself carry no userinfo.
fn same_origin(candidate: &reqwest::Url, base: &str) -> bool {
    let Ok(base) = reqwest::Url::parse(base.trim()) else {
        return false;
    };
    base.username().is_empty()
        && base.password().is_none()
        && candidate.scheme() == base.scheme()
        && normalized_host(&base).is_some()
        && normalized_host(candidate) == normalized_host(&base)
        && candidate.port_or_known_default() == base.port_or_known_default()
}

/// The service-endpoint trust class's single predicate. See the module documentation for the rule.
///
/// `configured_api_origin` is the configured-API-origin answer for `url` (in `fuigo-shell`, P42's
/// `session_may_reach`); `configured_service_base` is the calling client's own configured base.
pub fn session_may_reach_service(
    url: &str,
    configured_service_base: Option<&str>,
    configured_api_origin: impl FnOnce(&str) -> bool,
) -> Result<(), RefusedServiceDestination> {
    let Ok(parsed) = reqwest::Url::parse(url) else {
        return Err(RefusedServiceDestination {
            origin: "<unparseable>".into(),
            reason: ServiceRefusal::Unparseable,
        });
    };
    let refuse = |reason| {
        Err(RefusedServiceDestination {
            origin: origin_of(&parsed),
            reason,
        })
    };
    if normalized_host(&parsed).is_none() {
        return refuse(ServiceRefusal::Unparseable);
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return refuse(ServiceRefusal::Userinfo);
    }
    if !matches!(parsed.scheme(), "https" | "wss") {
        return refuse(ServiceRefusal::Cleartext);
    }
    if is_local_host(&parsed) {
        return refuse(ServiceRefusal::Loopback);
    }
    // FluxRouter-operated, on its own port only: the compiled class is host-only, a service origin is not.
    if (crate::fluxrouter::is_fluxrouter_operated_url(url) && parsed.port().is_none())
        || configured_service_base.is_some_and(|base| same_origin(&parsed, base))
        || configured_api_origin(url)
    {
        return Ok(());
    }
    refuse(ServiceRefusal::NotTrusted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decide(url: &str, base: Option<&str>) -> Result<(), ServiceRefusal> {
        session_may_reach_service(url, base, |_| false).map_err(|r| r.reason)
    }

    #[test]
    fn fluxrouter_operated_and_the_configured_base_are_admitted() {
        assert_eq!(decide("https://api.fluxrouter.ai/v1/user", None), Ok(()));
        assert_eq!(decide("https://API.FluxRouter.ai./x", None), Ok(()));
        let base = Some("https://proxy.example.test/v1");
        assert_eq!(decide("https://proxy.example.test/v1/billing", base), Ok(()));
        assert_eq!(decide("https://proxy.example.test:443/other", base), Ok(()));
        assert_eq!(decide("wss://hub.example.test/ws", Some("wss://hub.example.test/ws")), Ok(()));
        // the configured-API-origin answer is consulted
        assert!(session_may_reach_service("https://gw.example.test/v1", None, |u| u.contains("gw.")).is_ok());
    }

    #[test]
    fn cleartext_loopback_userinfo_and_other_origins_are_refused_even_when_configured() {
        use ServiceRefusal::*;
        assert_eq!(decide("http://api.fluxrouter.ai/v1", None), Err(Cleartext));
        assert_eq!(decide("ws://hub.example.test/ws", Some("ws://hub.example.test/ws")), Err(Cleartext));
        assert_eq!(decide("http://proxy.example.test/v1", Some("http://proxy.example.test/v1")), Err(Cleartext));
        for local in [
            "https://localhost/v1",
            "https://app.localhost/v1",
            "https://127.0.0.1/v1",
            "https://127.9.9.9:8443/v1",
            "https://[::1]/v1",
            "https://[::ffff:127.0.0.1]/v1",
            "https://0.0.0.0/v1",
            "wss://localhost:9988/v1/tools",
        ] {
            assert_eq!(decide(local, Some(local)), Err(Loopback), "{local}");
        }
        assert_eq!(
            decide("https://u:p@proxy.example.test/v1", Some("https://proxy.example.test")),
            Err(Userinfo)
        );
        let base = Some("https://proxy.example.test/v1");
        assert_eq!(decide("https://proxy.example.test:8443/v1", base), Err(NotTrusted));
        assert_eq!(decide("https://proxy.example.test.evil.example/v1", base), Err(NotTrusted));
        assert_eq!(decide("https://evil.example/v1", base), Err(NotTrusted));
        assert_eq!(decide("wss://proxy.example.test/v1", base), Err(NotTrusted));
        assert_eq!(decide("https://api.fluxrouter.ai:8443/v1", None), Err(NotTrusted));
        // a base with userinfo admits nothing
        assert_eq!(decide("https://proxy.example.test/v1", Some("https://u@proxy.example.test")), Err(NotTrusted));
        assert_eq!(decide("not a url", None), Err(Unparseable));
    }

    #[test]
    fn the_refusal_names_the_origin_and_the_remedy_and_never_the_path() {
        let refused = session_may_reach_service(
            "http://127.0.0.1:9/v1/feedback?token=secret",
            None,
            |_| false,
        )
        .unwrap_err();
        let text = refused.to_string();
        assert!(text.contains("http://127.0.0.1:9"), "{text}");
        assert!(text.contains("The request was not made"), "{text}");
        assert!(text.contains("[endpoints].cli_chat_proxy_base_url"), "{text}");
        assert!(!text.contains("secret") && !text.contains("/v1"), "{text}");
        assert_eq!(refused.reason_label(), "cleartext");
    }
}

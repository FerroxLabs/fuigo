//! FluxRouter, Fuigo's default inference route, and the gate for request extensions only it may receive.
//!
//! # Two destination trust classes, deliberately kept apart (P30)
//!
//! Fuigo classifies a request destination in two unrelated ways, and they answer different questions.
//! Neither is called "first party" any more: that word used to name both, and the two must never be merged.
//!
//! * **FluxRouter-operated** — this module. A COMPILED host check against [`FLUXROUTER_API_HOST`]. It
//!   decides **identity disclosure**: whether the `x-fuigo-*` identity headers (account id, tenant UUID,
//!   persisted machine id, client version and identifier) may go on the wire, via
//!   [`IdentityDisclosure`]. It also decides whether a FluxRouter-only request body field may be sent
//!   ([`is_fluxrouter_url`]). Nothing a user configures can widen it.
//! * **User-configured API origin** — `fuigo_shell_base::util::TrustedApiOrigins` and its free
//!   predicates (`is_fuigo_api_bearer_url`, `is_configured_api_origin`, `is_fuigo_api_url`). Derived
//!   from `[endpoints]`. It decides **credential delivery**: where the session bearer and
//!   `FUIGO_API_KEY` may be attached, and where the API-key kill switch refuses a key.
//!
//! Why configuration must not decide identity: a user may legitimately configure
//! `https://api.openai.com/v1`, or a loopback gateway, as a trusted origin. Handing that origin the
//! credential the user chose to send it is correct; handing it a stable Ferrox account identifier that
//! correlates the same user across every provider they use is exactly the leak P15 closed.
//!
//! Why the compiled host must not decide credentials: credential delivery has to follow the endpoint
//! the user actually configured, or a self-hosted gateway gets no credential at all (the defect P17-R
//! fixed in `fuigo-shell-base`).
//!
//! The consequence, and it is intended: a user on their own configured HTTPS gateway receives the session
//! bearer (they chose that destination) and does NOT receive the identity headers (Fuigo did not choose
//! it). The withholding is logged by `fuigo_sampler`'s `apply_identity_headers`. The full policy and
//! the call-site table are in `docs/destination-trust-policy.md`.
//!
//! The split is enforced by type as well as by name: the identity gate in `fuigo-sampler` takes an
//! [`IdentityDisclosure`], which can only be granted by [`IdentityDisclosure::for_destination`] (i.e.
//! by this module's compiled host check). There is no constructor from a `bool`, so a configured-trust
//! answer cannot be passed where an identity decision is required.
//!
//! Identity carried in a request BODY follows the same decision (P54): [`IdentityDisclosure::body_identity`]
//! for a field that is omitted when withheld, [`IdentityDisclosure::body_key_for`] for a field the
//! receiving feature needs as a stable key (a destination-scoped [`destination_pseudonym`] when withheld;
//! [`IdentityDisclosure::body_key_for_websocket`] when the destination is a WebSocket, P81).
//!
//! Strict providers (OpenAI, Anthropic, xAI) reject an unknown body field with a 400, so a FluxRouter-only
//! request field is gated on the destination host too. Configuration trust is the wrong gate there for the
//! same reason: a user may configure a direct OpenAI base URL as a trusted origin, and loopback gateways
//! are trusted too.

/// FluxRouter's API host. It serves `/v1` (Chat Completions, Responses) and `/anthropic` (Messages).
pub const FLUXROUTER_API_HOST: &str = "api.fluxrouter.ai";

/// Whether `url` addresses [`FLUXROUTER_API_HOST`], on any scheme, port or path.
///
/// An exact host match after `Url::parse` (which lowercases the host and separates userinfo, so
/// `https://api.fluxrouter.ai@evil.example/` is `evil.example`) and removal of the DNS root dot.
/// Lookalikes such as `api.fluxrouter.ai.evil.example`, and the website `fluxrouter.ai`, are not the API.
pub fn is_fluxrouter_url(url: &str) -> bool {
    reqwest::Url::parse(url).is_ok_and(|parsed| {
        parsed
            .host_str()
            .is_some_and(|host| host.trim_end_matches('.') == FLUXROUTER_API_HOST)
    })
}

/// Whether `url` addresses a **FluxRouter-operated inference route**, and may therefore
/// receive the `x-fuigo-*` **identity** headers.
///
/// This is the identity-disclosure predicate. It is NOT the credential-delivery predicate and must
/// never be used as one: credential delivery follows the user's configuration
/// (`fuigo_shell_base::util::is_fuigo_api_bearer_url` / `is_configured_api_origin`). See the module
/// note. Prefer [`IdentityDisclosure::for_destination`], which carries the answer as a type the
/// identity gate requires. Before P30 this was `is_first_party_url`; the name was retired because
/// `fuigo-shell-base` used "first-party" to mean "user-configured".
///
/// Identity means the headers that name *who* is calling and stay the same across
/// destinations: `x-fuigo-user-id` (the Ferrox account id), `x-fuigo-deployment-id` (the
/// tenant UUID), `x-fuigo-agent-id` (a persisted machine id that survives logout),
/// `x-fuigo-client-version` and `x-fuigo-client-identifier`.
///
/// It deliberately does NOT cover the per-session **correlation** headers
/// (`x-fuigo-conv-id`, `-req-id`, `-session-id`, `-turn-idx`, `-transient-retry`). Those are
/// per-session randoms and per-turn counters: they identify nobody across two destinations,
/// so withholding them buys no privacy, and they are load-bearing at every destination —
/// `x-fuigo-transient-retry` is how a self-hosted gateway separates a resubmit from a new
/// turn when it accounts for retry traffic, and the integration harness classifies
/// foreground against auxiliary calls on `-turn-idx`/`-req-id`. P15 withheld the whole
/// namespace from every other destination and broke both; P15-R narrows the gate back
/// to the class it was chartered to protect. `fuigo_sampler`'s `FuigoRequestHeaders::apply`
/// is the single place that split is applied.
///
/// Deliberately a COMPILED host check, not a configuration-derived one. The module note
/// above applies with full force here: a user may legitimately configure
/// `https://api.openai.com/v1` as a trusted origin, and loopback gateways are trusted
/// too — so configured trust would hand a stable account identifier to exactly the
/// third parties this gate exists to keep it from.
///
/// **HTTPS is required**, so `http://api.fluxrouter.ai/v1` is NOT FluxRouter-operated for this purpose. Cleartext to
/// the right host still puts the account id and tenant UUID on the wire for every observer
/// on the path — the host being correct does not make the hop private, and a downgrade is
/// the cheapest way to defeat a host-only gate. The credential-bearing sibling predicate
/// takes the same position and is the precedent: `fuigo_shell_base::util`'s
/// `is_trusted_fuigo_https_url` refuses a non-`https` scheme before it looks at the host,
/// and its own test pins `http://api.fluxrouter.ai/v1` as refused.
/// [`is_fluxrouter_url`] stays scheme-agnostic on purpose: it gates a request *body field*,
/// where the only question is whether the host will understand it.
///
/// FAILS CLOSED. A managed deployment that repoints its inference base URL away from
/// [`FLUXROUTER_API_HOST`] stops receiving these headers. That direction is deliberate:
/// the cost is proxy-side version gating and telemetry going dark, which is visible and
/// recoverable, against the alternative of silently disclosing a cross-provider
/// correlator, which is neither. "Visible" is now load-bearing rather than aspirational:
/// `fuigo_sampler`'s `apply_identity_headers` logs every withholding, and `warn`s with the
/// remedy named when the config actually carried an identity to withhold.
pub fn is_fluxrouter_operated_url(url: &str) -> bool {
    is_fluxrouter_url(url)
        && reqwest::Url::parse(url).is_ok_and(|parsed| parsed.scheme() == "https")
}

/// The identity-disclosure decision for one destination: may the `x-fuigo-*` identity headers go there?
///
/// A type, not a `bool`, so the identity gate cannot be fed the wrong trust class. The only way to
/// obtain a *permitting* value is [`Self::for_destination`], which asks [`is_fluxrouter_operated_url`].
/// There is deliberately no `From<bool>`, no public field and no `permitted()` constructor: a
/// configured-trust answer (`fuigo_shell_base::util::is_fuigo_api_bearer_url` and friends) is a
/// `bool`, and a `bool` cannot become one of these. Withholding is always safe, so
/// [`Self::WITHHELD`] is public.
///
/// ```compile_fail
/// // A configured-trust answer cannot be smuggled in: the field is private.
/// let configured: bool = true;
/// let _ = fuigo_extra_ca::fluxrouter::IdentityDisclosure { permitted: configured };
/// ```
///
/// ```compile_fail
/// // Nor converted.
/// let _: fuigo_extra_ca::fluxrouter::IdentityDisclosure = true.into();
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub struct IdentityDisclosure {
    permitted: bool,
}

impl IdentityDisclosure {
    /// Identity headers are withheld. Always safe to construct: it fails closed.
    pub const WITHHELD: Self = Self { permitted: false };

    /// Decide for `url`, by the compiled FluxRouter-operated check and nothing else.
    pub fn for_destination(url: &str) -> Self {
        Self {
            permitted: is_fluxrouter_operated_url(url),
        }
    }

    /// Decide for a WebSocket handshake URL (P43). `wss` to the FluxRouter API host is the TLS
    /// equivalent of `https` and is permitted; `ws` (cleartext) and every other host or scheme are
    /// withheld. Nothing configured can widen it, exactly as for [`Self::for_destination`].
    pub fn for_websocket_destination(url: &str) -> Self {
        Self {
            permitted: is_fluxrouter_url(url)
                && reqwest::Url::parse(url).is_ok_and(|parsed| parsed.scheme() == "wss"),
        }
    }

    /// Whether the identity headers may be sent.
    pub fn is_permitted(self) -> bool {
        self.permitted
    }

    /// `pairs` as a header map when identity is permitted; an EMPTY map when it is withheld (P43).
    ///
    /// For request builders: `.headers(disclosure.header_map([("x-userid", id)]))`. A value
    /// that is not a valid header value is skipped (identity is attribution, never required for
    /// the request to be authorised). Every name must be an identity-class name
    /// ([`is_identity_header`]); a non-identity name here is a call-site bug and is skipped too,
    /// so this helper can never be used to smuggle an ungated header.
    pub fn header_map<'a, I>(self, pairs: I) -> reqwest::header::HeaderMap
    where
        I: IntoIterator<Item = (&'static str, &'a str)>,
    {
        let mut map = reqwest::header::HeaderMap::new();
        if !self.permitted {
            return map;
        }
        for (name, value) in pairs {
            // The canonical lowercase spelling, so `from_static` can never panic on case.
            let Some(canonical) = IDENTITY_HEADER_NAMES
                .iter()
                .find(|identity| identity.eq_ignore_ascii_case(name))
            else {
                debug_assert!(false, "{name} is not an identity header");
                continue;
            };
            if let Ok(value) = reqwest::header::HeaderValue::from_str(value) {
                map.insert(reqwest::header::HeaderName::from_static(canonical), value);
            }
        }
        map
    }

    /// Remove every identity-class header from `headers` when identity is withheld (P43).
    /// Returns how many were removed. Used where a header map is assembled before the
    /// destination is final (`send_with_auth`, WebSocket handshakes, OTLP export).
    pub fn withhold_from_header_map(self, headers: &mut reqwest::header::HeaderMap) -> usize {
        if self.permitted {
            return 0;
        }
        let mut removed = 0;
        for name in IDENTITY_HEADER_NAMES {
            if headers.contains_key(name) {
                headers.remove(name);
                removed += 1;
            }
        }
        removed
    }

    /// Whether `name` may be written for this destination: always for a non-identity name,
    /// only when permitted for an identity-class one. For string-keyed header maps
    /// (`IndexMap<String, String>` tool headers, OTLP export maps).
    pub fn allows_header(self, name: &str) -> bool {
        self.permitted || !is_identity_header(name)
    }

    /// Body-carried identity (P54): `value` when identity is permitted, `None` when withheld.
    ///
    /// For a request-body field that names *who* is calling (an account id, an e-mail address,
    /// a team, organisation or deployment id, the persisted machine id) and that the receiving
    /// feature does not need when identity is withheld: the caller OMITS the field on `None`.
    /// Decide `self` on the URL the body is actually sent to.
    pub fn body_identity(self, value: &str) -> Option<&str> {
        self.permitted.then_some(value)
    }

    /// Body-carried identity the receiving feature needs as a STABLE key (P54): `value` itself
    /// when `destination` is FluxRouter-operated ([`Self::for_destination`]); otherwise
    /// [`destination_pseudonym`]`(destination, value)`, a key that is stable for this value at
    /// this origin and different at every other origin, so two non-FluxRouter destinations
    /// cannot link the same user or machine by it, and neither learns the real identifier.
    ///
    /// Decided here, on the one URL it is given, so the decision and the pseudonym's origin can
    /// never come from two different URLs.
    pub fn body_key_for(destination: &str, value: &str) -> String {
        if Self::for_destination(destination).permitted {
            value.to_owned()
        } else {
            destination_pseudonym(destination, value)
        }
    }

    /// [`Self::body_key_for`] for identity sent over a WebSocket (P81): `value` itself when
    /// `destination` is FluxRouter-operated by the WebSocket rule
    /// ([`Self::for_websocket_destination`]: `wss` to the FluxRouter API host); otherwise the same
    /// [`destination_pseudonym`]`(destination, value)`. One scheme, one recipe: only the question
    /// "is this destination FluxRouter-operated" differs between an `https` and a `wss` URL.
    ///
    /// Decided here, on the one URL it is given, for the same reason as [`Self::body_key_for`].
    pub fn body_key_for_websocket(destination: &str, value: &str) -> String {
        if Self::for_websocket_destination(destination).permitted {
            value.to_owned()
        } else {
            destination_pseudonym(destination, value)
        }
    }
}

/// Domain separator for [`destination_pseudonym`]. Changing it re-keys every pseudonym.
const BODY_PSEUDONYM_DOMAIN: &[u8] = b"fuigo.p54.body-identity-pseudonym.v1";

/// A destination-scoped pseudonym for an identity `value` (P54), shaped as a UUID (version 8,
/// RFC 9562 variant) so a server that validates a UUID-shaped id still accepts it.
///
/// `SHA-256(domain ‖ 0 ‖ origin ‖ 0 ‖ value)`, truncated to 128 bits. The origin is the URL's
/// `scheme://host[:port]` (so every path at one server maps to the same key); an unparseable
/// destination is hashed verbatim. The pseudonym is one-way: the destination cannot recover
/// `value`, and two origins get unrelated keys for the same `value`.
///
/// # What "stable at this origin" means (P54-K)
///
/// The origin is `Url::origin().ascii_serialization()`: the scheme, the host lowercased, and
/// the port only when it is not the scheme's default. So `https://h.example:443/x` and
/// `HTTPS://H.EXAMPLE/` key the same, userinfo and the path, query and fragment are ignored, and
/// an operator can move paths freely. Anything that changes the origin re-keys every value:
/// `http` → `https`, a non-default port, an IP literal instead of the host name, a host alias,
/// or a trailing DNS dot (kept by the URL parser for a non-FluxRouter host). Two services on
/// different origins (a session registry and a session backend, say) therefore receive
/// different keys for one machine.
///
/// # Reproducing it (deterministic, no secret)
///
/// A destination that already holds a raw id (sessions registered before P54, say) can compute
/// the key it will see from now on and migrate its own rows. The hash cannot be inverted, but it
/// is public and unsalted, so a party holding a CANDIDATE value can confirm it by hashing; the
/// values Fuigo feeds it are opaque ids (a UUID machine id, an account id), not guessable text,
/// and a normally generated UUIDv5 machine id can never equal its own v8-shaped pseudonym. In
/// Python:
///
/// ```text
/// import hashlib
/// def pseudonym(origin, value):
///     d = hashlib.sha256(b"fuigo.p54.body-identity-pseudonym.v1" + b"\0"
///                        + origin.encode() + b"\0" + value.encode()).digest()
///     b = bytearray(d[:16]); b[6] = (b[6] & 0x0f) | 0x80; b[8] = (b[8] & 0x3f) | 0x80
///     h = b.hex(); return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
/// pseudonym("https://backend.example", "5d1f0c2a-7a7a-4b4b-8c8c-0123456789ab")
/// # 'c3ad749c-6794-8fb7-a4f2-03664010e911'
/// ```
///
/// The test `destination_pseudonym_matches_its_published_recipe` pins that vector, so the
/// recipe above and this function cannot drift apart unnoticed.
pub fn destination_pseudonym(destination: &str, value: &str) -> String {
    use sha2::Digest as _;
    let origin = reqwest::Url::parse(destination)
        .ok()
        .map(|url| url.origin().ascii_serialization())
        .filter(|origin| origin != "null")
        .unwrap_or_else(|| destination.to_owned());
    let mut hasher = sha2::Sha256::new();
    hasher.update(BODY_PSEUDONYM_DOMAIN);
    hasher.update([0u8]);
    hasher.update(origin.as_bytes());
    hasher.update([0u8]);
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    )
}

/// The identity-class header names (P43): every header Fuigo itself writes that names *who* is
/// calling and is the same at every destination. Only a FluxRouter-operated destination may
/// receive them, decided by [`IdentityDisclosure`].
///
/// * `x-fuigo-user-id`, `x-fuigo-deployment-id`, `x-fuigo-agent-id`, `x-fuigo-client-version`,
///   `x-fuigo-client-identifier`: the P15 identity class the inference sampler already gates.
/// * `x-userid`, `x-email`, `x-teamid`: the Ferrox account id, the account e-mail address and the
///   team id, sent by the auxiliary-service clients, the relay and the internal OTLP exporter.
///
/// Correlation headers (`x-fuigo-conv-id`, `-req-id`, `-session-id`, `-turn-idx`,
/// `-transient-retry`) and the two-valued `x-fuigo-client-mode` are deliberately absent (P15-R).
/// Headers a USER configured for a destination (`extra_headers`, OTLP header settings) are the
/// user's choice and are never stripped by these helpers' callers.
pub const IDENTITY_HEADER_NAMES: [&str; 8] = [
    "x-fuigo-user-id",
    "x-fuigo-deployment-id",
    "x-fuigo-agent-id",
    "x-fuigo-client-version",
    "x-fuigo-client-identifier",
    "x-userid",
    "x-email",
    "x-teamid",
];

/// Whether `name` is an identity-class header ([`IDENTITY_HEADER_NAMES`]), case-insensitively.
pub fn is_identity_header(name: &str) -> bool {
    IDENTITY_HEADER_NAMES
        .iter()
        .any(|identity| identity.eq_ignore_ascii_case(name))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fluxrouter_api_urls_match_on_every_surface_and_spelling() {
        for url in [
            "https://api.fluxrouter.ai/v1",
            "https://api.fluxrouter.ai/anthropic",
            "https://api.fluxrouter.ai/v1/chat/completions",
            "http://api.fluxrouter.ai/v1",
            "HTTPS://API.FLUXROUTER.AI/v1",
            "https://api.fluxrouter.ai./v1",
            "https://api.fluxrouter.ai:8443/v1",
            "https://user@api.fluxrouter.ai/v1",
        ] {
            assert!(is_fluxrouter_url(url), "{url} is FluxRouter's API");
        }
    }

    #[test]
    fn other_hosts_and_lookalikes_do_not_match() {
        for url in [
            "https://api.openai.com/v1",
            "https://api.anthropic.com/v1",
            "https://api.x.ai/v1",
            "https://openrouter.ai/api/v1",
            "https://fluxrouter.ai/v1",
            "https://www.fluxrouter.ai/v1",
            "https://staging.api.fluxrouter.ai/v1",
            "https://api.fluxrouter.ai.evil.example/v1",
            "https://evil-api.fluxrouter.ai.attacker.com/v1",
            "https://api.fluxrouter.ai@evil.example/v1",
            "https://evil.example/api.fluxrouter.ai/v1",
            "http://localhost:8080/v1",
            "http://127.0.0.1:8080/v1",
            "api.fluxrouter.ai",
            "not a url",
            "",
        ] {
            assert!(!is_fluxrouter_url(url), "{url} is not FluxRouter's API");
        }
    }

    /// The identity gate is the FluxRouter predicate AND `https`, and nothing else — every
    /// lookalike and userinfo case above included. Pinned as an equality against the composed
    /// predicate, so the gate can neither drift into admitting a host the FluxRouter predicate
    /// rejects, nor quietly widen past the scheme restriction.
    #[test]
    fn identity_gate_is_the_fluxrouter_predicate_restricted_to_https() {
        for url in [
            "https://api.fluxrouter.ai/v1",
            "https://api.fluxrouter.ai/anthropic",
            "HTTPS://API.FLUXROUTER.AI/v1",
            "https://api.fluxrouter.ai./v1",
            "https://api.fluxrouter.ai:8443/v1",
            "https://user@api.fluxrouter.ai/v1",
            "http://api.fluxrouter.ai/v1",
            "http://api.fluxrouter.ai/anthropic",
            "HTTP://API.FLUXROUTER.AI/v1",
            "https://api.openai.com/v1",
            "https://api.anthropic.com/v1",
            "https://openrouter.ai/api/v1",
            "https://api.fluxrouter.ai@evil.example/v1",
            "https://api.fluxrouter.ai.evil.example/v1",
            "http://127.0.0.1:8080/v1",
            "not a url",
            "",
        ] {
            let https = reqwest::Url::parse(url).is_ok_and(|parsed| parsed.scheme() == "https");
            assert_eq!(
                is_fluxrouter_operated_url(url),
                is_fluxrouter_url(url) && https,
                "{url}: the identity gate is not `FluxRouter host AND https`"
            );
        }
    }

    /// M11. A scheme downgrade to the correct host must not carry identity: cleartext puts the
    /// Ferrox account id and the tenant UUID on the wire for every observer on the path, which
    /// is the same disclosure a third-party destination would cause, and a downgrade is the
    /// cheapest way to defeat a host-only gate. `ws`/`wss` and anything else are refused too:
    /// only `https` is an inference route.
    ///
    /// Each case asserts the host predicate FIRST. Without that the test would also pass if
    /// `is_fluxrouter_url` stopped matching, which would prove nothing about the scheme.
    #[test]
    fn a_scheme_downgrade_to_the_right_host_is_not_fluxrouter_operated() {
        for url in [
            "http://api.fluxrouter.ai/v1",
            "http://api.fluxrouter.ai/anthropic",
            "http://api.fluxrouter.ai:8443/v1",
            "http://api.fluxrouter.ai./v1",
            "HTTP://API.FLUXROUTER.AI/v1",
            "ws://api.fluxrouter.ai/v1",
            "wss://api.fluxrouter.ai/v1",
        ] {
            assert!(
                is_fluxrouter_url(url),
                "{url} must still match FluxRouter's host, or this case proves nothing"
            );
            assert!(
                !is_fluxrouter_operated_url(url),
                "{url} is not https and must not receive x-fuigo-* identity headers"
            );
        }
        assert!(
            is_fluxrouter_operated_url("https://api.fluxrouter.ai/v1"),
            "the https route must stay FluxRouter-operated, or the gate is simply off"
        );
    }

    /// The headers this gate protects are a cross-provider correlator. Third-party and
    /// loopback destinations must never be FluxRouter-operated, whatever else changes.
    #[test]
    fn third_party_and_loopback_are_never_fluxrouter_operated() {
        for url in [
            "https://api.openai.com/v1",
            "https://api.anthropic.com/v1",
            "https://api.x.ai/v1",
            "https://openrouter.ai/api/v1",
            "http://localhost:8080/v1",
            "http://127.0.0.1:8080/v1",
            "https://localhost:8080/v1",
            "https://127.0.0.1:8080/v1",
            "https://api.fluxrouter.ai.evil.example/v1",
            "https://api.fluxrouter.ai@evil.example/v1",
            "http://api.fluxrouter.ai/v1",
        ] {
            assert!(!is_fluxrouter_operated_url(url), "{url} must not receive x-fuigo-* identity headers");
        }
    }

    /// P30. `IdentityDisclosure::for_destination` is exactly the identity predicate: every URL the
    /// predicate tables above exercise, permitted iff `is_fluxrouter_operated_url`.
    #[test]
    fn identity_disclosure_is_granted_by_the_compiled_host_check_alone() {
        for url in [
            "https://api.fluxrouter.ai/v1",
            "https://api.fluxrouter.ai/anthropic",
            "HTTPS://API.FLUXROUTER.AI/v1",
            "https://api.fluxrouter.ai./v1",
            "http://api.fluxrouter.ai/v1",
            "https://api.openai.com/v1",
            "https://my.gateway.example/v1",
            "https://localhost:8080/v1",
            "http://127.0.0.1:8080/v1",
            "https://api.fluxrouter.ai@evil.example/v1",
            "not a url",
            "",
        ] {
            assert_eq!(
                IdentityDisclosure::for_destination(url).is_permitted(),
                is_fluxrouter_operated_url(url),
                "{url}: identity disclosure must be decided by the FluxRouter-operated check alone"
            );
        }
        assert!(IdentityDisclosure::for_destination("https://api.fluxrouter.ai/v1").is_permitted());
        assert!(!IdentityDisclosure::WITHHELD.is_permitted());
    }

    /// P43. The WebSocket decision: `wss` to the compiled host only; `ws` cleartext, other hosts
    /// and lookalikes are withheld.
    #[test]
    fn websocket_identity_disclosure_needs_wss_to_the_fluxrouter_host() {
        assert!(IdentityDisclosure::for_websocket_destination("wss://api.fluxrouter.ai/v1/stt").is_permitted());
        assert!(IdentityDisclosure::for_websocket_destination("WSS://API.FLUXROUTER.AI./ws").is_permitted());
        for url in [
            "ws://api.fluxrouter.ai/v1/stt",
            "wss://api.fluxrouter.ai.evil.example/ws",
            "wss://api.fluxrouter.ai@evil.example/ws",
            "wss://relay.example/ws",
            "ws://127.0.0.1:9/ws",
            "https://api.openai.com/v1",
            "not a url",
        ] {
            assert!(
                !IdentityDisclosure::for_websocket_destination(url).is_permitted(),
                "{url} must not receive identity headers"
            );
        }
    }

    /// P43. The helpers every non-sampler writer uses: a withheld decision yields an empty map,
    /// strips every identity name (any case) and nothing else; a permitted one keeps them.
    #[test]
    fn identity_helpers_gate_exactly_the_identity_class() {
        let pairs = [("x-userid", "acct-1"), ("x-email", "a@b.example"), ("x-fuigo-client-version", "1.0.21")];
        let withheld = IdentityDisclosure::for_destination("https://cli-proxy.example/v1");
        assert!(withheld.header_map(pairs).is_empty());
        let permitted = IdentityDisclosure::for_destination("https://api.fluxrouter.ai/v1");
        let map = permitted.header_map(pairs);
        assert_eq!(map.len(), 3);
        assert_eq!(map["x-userid"], "acct-1");

        let mut headers = reqwest::header::HeaderMap::new();
        for name in IDENTITY_HEADER_NAMES {
            headers.insert(name, reqwest::header::HeaderValue::from_static("v"));
        }
        headers.insert("authorization", reqwest::header::HeaderValue::from_static("Bearer t"));
        headers.insert("x-fuigo-client-mode", reqwest::header::HeaderValue::from_static("cli"));
        headers.insert("x-fuigo-session-id", reqwest::header::HeaderValue::from_static("s"));
        let mut kept = headers.clone();
        assert_eq!(permitted.withhold_from_header_map(&mut kept), 0);
        assert_eq!(kept.len(), headers.len());
        assert_eq!(withheld.withhold_from_header_map(&mut headers), IDENTITY_HEADER_NAMES.len());
        let left: Vec<_> = headers.keys().map(|k| k.as_str().to_owned()).collect();
        assert_eq!(left.len(), 3, "only the non-identity headers survive: {left:?}");
        assert!(headers.contains_key("authorization"));

        // A value that is not a valid header value is skipped, not fatal: identity is attribution,
        // so a malformed account id never blocks an otherwise authorised request (P43, pinned).
        let malformed = permitted.header_map([("x-userid", "bad\nvalue"), ("x-email", "ok@b.example")]);
        assert!(!malformed.contains_key("x-userid"));
        assert_eq!(malformed["x-email"], "ok@b.example");

        assert!(is_identity_header("X-UserId"));
        assert!(is_identity_header("X-Fuigo-Client-Identifier"));
        assert!(!is_identity_header("x-fuigo-client-mode"));
        assert!(!is_identity_header("x-fuigo-conv-id"));
        assert!(withheld.allows_header("authorization"));
        assert!(!withheld.allows_header("X-Email"));
        assert!(permitted.allows_header("x-email"));
    }

    /// P54. Body identity: `body_identity` yields the value only when permitted; `body_key_for`
    /// keeps the real value for FluxRouter and substitutes a destination-scoped pseudonym
    /// everywhere else — never the value itself, stable per origin, different across origins.
    #[test]
    fn body_identity_goes_only_to_fluxrouter_and_others_get_an_origin_scoped_pseudonym() {
        let id = "3f2c1d7e-0000-4000-8000-00000000abcd";
        let flux = "https://api.fluxrouter.ai/v1/sessions/s1";
        assert_eq!(IdentityDisclosure::for_destination(flux).body_identity(id), Some(id));
        assert_eq!(IdentityDisclosure::body_key_for(flux, id), id);
        for other in [
            "https://cli-proxy.example/v1/sessions/s1",
            "http://api.fluxrouter.ai/v1/sessions/s1",
            "https://api.fluxrouter.ai.evil.example/v1",
            "http://127.0.0.1:9/v1",
            "https://api.mixpanel.com/track",
        ] {
            assert_eq!(IdentityDisclosure::for_destination(other).body_identity(id), None, "{other}");
            let key = IdentityDisclosure::body_key_for(other, id);
            assert_ne!(key, id, "{other} must not receive the identifier itself");
            assert!(!key.contains(id), "{other}");
            assert_eq!(key, destination_pseudonym(other, id));
            assert_eq!(key, IdentityDisclosure::body_key_for(other, id), "stable for one origin");
        }
        // Same origin, other path: same key. Other origin: unrelated key. Other value: other key.
        let a = destination_pseudonym("https://cli-proxy.example/v1/sessions/a", id);
        assert_eq!(a, destination_pseudonym("https://cli-proxy.example/other", id));
        assert_ne!(a, destination_pseudonym("https://other-proxy.example/v1/sessions/a", id));
        assert_ne!(a, destination_pseudonym("https://cli-proxy.example:8443/v1/sessions/a", id));
        assert_ne!(a, destination_pseudonym("https://cli-proxy.example/v1/sessions/a", "other-id"));
        // UUID-shaped, version 8, RFC 9562 variant.
        assert_eq!(a.len(), 36);
        assert_eq!(a.matches('-').count(), 4);
        assert_eq!(&a[14..15], "8");
        assert!(matches!(&a[19..20], "8" | "9" | "a" | "b"), "{a}");
        assert!(a.chars().all(|c| c == '-' || c.is_ascii_hexdigit()));
        // An unparseable destination is hashed verbatim, never passed through.
        assert_ne!(destination_pseudonym("not a url", id), id);
    }

    /// P81. The WebSocket variant decides by the WebSocket rule and uses the SAME recipe: `wss` to
    /// the FluxRouter API host keeps the value (where the `https`-only `body_key_for` would
    /// pseudonymise it), every other URL gets exactly `destination_pseudonym` of that URL, keyed
    /// on the `wss` origin (path-independent, different per relay, different from the `https`
    /// origin of the same host).
    #[test]
    fn websocket_body_key_keeps_the_value_for_fluxrouter_and_uses_the_one_recipe_elsewhere() {
        let id = "5d1f0c2a-7a7a-4b4b-8c8c-0123456789ab";
        for flux in ["wss://api.fluxrouter.ai/ws/relay", "WSS://API.FLUXROUTER.AI./ws", "wss://api.fluxrouter.ai:8443/x"] {
            assert_eq!(IdentityDisclosure::body_key_for_websocket(flux, id), id, "{flux}");
            assert_ne!(IdentityDisclosure::body_key_for(flux, id), id, "{flux}: the https rule does not admit wss");
        }
        for other in [
            "wss://relay.example/ws",
            "ws://api.fluxrouter.ai/ws/relay",
            "https://api.fluxrouter.ai/ws/relay",
            "wss://api.fluxrouter.ai.evil.example/ws",
            "wss://api.fluxrouter.ai@relay.example/ws",
            "not a url",
            "",
        ] {
            let key = IdentityDisclosure::body_key_for_websocket(other, id);
            assert_eq!(key, destination_pseudonym(other, id), "{other}");
            assert_ne!(key, id, "{other}");
            assert!(!key.contains(id), "{other}");
        }
        // Computed independently with the published Python recipe (origin `wss://relay.example`).
        assert_eq!(
            IdentityDisclosure::body_key_for_websocket("wss://relay.example/ws", id),
            "1aee0aad-2c8c-814c-a3bd-c47d513a2170"
        );
        let relay = IdentityDisclosure::body_key_for_websocket("wss://relay.example/ws", id);
        assert_eq!(relay, IdentityDisclosure::body_key_for_websocket("WSS://Relay.Example:443/other?x=1", id));
        for rekeyed in ["wss://relay.example:8443/ws", "wss://other-relay.example/ws", "https://relay.example/ws", "ws://relay.example/ws"] {
            assert_ne!(IdentityDisclosure::body_key_for_websocket(rekeyed, id), relay, "{rekeyed}");
        }
    }

    /// P54-K. The pseudonym is reproducible from the recipe in the doc comment, with no secret:
    /// three vectors computed independently in Python (hashlib) are pinned here, so an operator
    /// migrating rows keyed on a raw id can trust the published algorithm, and a change to the
    /// domain tag, the truncation or the UUID shaping is caught.
    #[test]
    fn destination_pseudonym_matches_its_published_recipe() {
        const MACHINE_ID: &str = "5d1f0c2a-7a7a-4b4b-8c8c-0123456789ab";
        for (destination, value, expected) in [
            ("https://backend.example", MACHINE_ID, "c3ad749c-6794-8fb7-a4f2-03664010e911"),
            ("https://backend.example/sessions/s1", MACHINE_ID, "c3ad749c-6794-8fb7-a4f2-03664010e911"),
            ("https://api.mixpanel.com/track", "acct-7f3e", "fab2042c-4597-848c-b78b-c2f31bc9080e"),
            ("http://127.0.0.1:8080/v1", MACHINE_ID, "c4c79e43-96c6-832a-a524-5e09c7430ad9"),
        ] {
            assert_eq!(destination_pseudonym(destination, value), expected, "{destination} {value}");
            assert_eq!(IdentityDisclosure::body_key_for(destination, value), expected);
        }
    }

    /// P54-K. The operator-facing stability contract, pinned both ways: spellings that keep the
    /// origin keep the key (default port, host case, userinfo, path/query/fragment, trailing
    /// slash), and spellings that change the origin re-key (scheme, non-default port, IP literal
    /// for the name, host alias, trailing DNS dot). A FluxRouter URL is never pseudonymised, so
    /// its trailing dot is irrelevant here; it is the identity check that trims it.
    #[test]
    fn destination_pseudonym_keys_on_the_normalized_origin_only() {
        let id = "5d1f0c2a-7a7a-4b4b-8c8c-0123456789ab";
        let base = destination_pseudonym("https://backend.example/sessions/s1", id);
        for same in [
            "https://backend.example",
            "https://backend.example/",
            "https://backend.example:443/other/path",
            "HTTPS://BACKEND.EXAMPLE/v1",
            "https://user:pw@backend.example/v1",
            "https://backend.example/v1?x=1#frag",
            "https://Backend.Example",
        ] {
            assert_eq!(destination_pseudonym(same, id), base, "{same} must key the same");
        }
        let http_base = destination_pseudonym("http://backend.example/v1", id);
        assert_eq!(destination_pseudonym("http://backend.example:80/x", id), http_base);
        for other in [
            "http://backend.example/sessions/s1",
            "https://backend.example:8443/sessions/s1",
            "https://backend.example./sessions/s1",
            "https://backend-alias.example/sessions/s1",
            "https://203.0.113.10/sessions/s1",
            "https://registry.example/sessions/s1",
        ] {
            assert_ne!(destination_pseudonym(other, id), base, "{other} must re-key");
        }
        // Two services on different origins get different keys for one machine.
        assert_ne!(
            destination_pseudonym("https://registry.example/v1/sessions/register", id),
            destination_pseudonym("https://backend.example/sessions/s1", id)
        );
    }

    /// P30. The policy case the packet was filed for: a user's own HTTPS gateway — exactly the kind
    /// of origin `fuigo-shell-base` will hand the session bearer once it is configured — is not
    /// granted identity disclosure. This crate cannot see configuration at all, which is the point:
    /// whatever the user configured, the answer here is the same.
    #[test]
    fn a_user_configured_gateway_is_not_granted_identity_disclosure() {
        for url in [
            "https://my.gateway.example/v1",
            "https://api.openai.com/v1",
            "https://gateway.fluxrouter.ai/v1",
        ] {
            assert!(
                !IdentityDisclosure::for_destination(url).is_permitted(),
                "{url} is not FluxRouter-operated and must not receive identity headers, configured or not"
            );
        }
    }
}

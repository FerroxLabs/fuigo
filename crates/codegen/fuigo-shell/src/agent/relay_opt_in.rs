//! P93: no bridge to a relay FluxRouter does not operate unless the user explicitly opts in to its origin.
//!
//! A relay bridged to the agent (`agent/app.rs`: headless-relay mode and leader mode) drives the agent exactly like a
//! local ACP client: it can read files (`_fuigo/fs/read_file` takes absolute paths), run terminals, add MCP servers,
//! and write configuration and read it back. P82's filters only keep the agent from handing such a relay credentials
//! it did not ask for; they are not a boundary against a relay that asks. So the trust decision is made before the
//! bridge exists, here, on the relay URL the socket would be opened to:
//!
//! * a FluxRouter-operated relay (`IdentityDisclosure::for_websocket_destination`: `wss` to the FluxRouter API host,
//!   the rule P43 / P77 / P81 / P82 use) is bridged as before, with no opt-in;
//! * any other relay is bridged only when the user named its ORIGIN (`scheme://host[:port]`, `wss` read as `https`
//!   and `ws` as `http`) in one of the two places only the user controls:
//!   - `trusted_origins` under `[relay]` in the user config file (`$FUIGO_HOME/config.toml`), read from that file
//!     alone: never from a project's `.fuigo/config.toml`, the `FUIGO_CONFIG` overlay, managed or remote settings,
//!     campaigns or `requirements.toml`;
//!   - the `FUIGO_TRUSTED_RELAY_ORIGINS` environment variable (origins separated by commas or whitespace).
//!
//!   A relay cannot supply its own opt-in: it is refused before a single byte is written to it.
//!
//! Otherwise the bridge is refused: no socket is opened, so no frame (not even `initialize`) is sent, and the refusal
//! says what to set and where ([`RelayOptInRefused`]). Changing the relay URL to another origin needs a new opt-in.
//!
//! Relay sync (`relay/sync.rs`, TUI session sharing) is not a bridge: the relay cannot send the agent requests through
//! it. It still sends the relay the whole session transcript, so (P125) it is gated by the same opt-in
//! ([`relay_sync_gate`]): a relay FluxRouter does not operate receives no session unless the user named its origin.
//!
//! A refusal is shown where the user is looking (P125): [`RelayOptInRefused::notice_params`] is the payload of the
//! `fuigo/relay/refused` notification the leader sends to interactive clients and the TUI agent sends for a refused
//! relay sync, and the pager renders it (which relay, why, how to trust it).
use fuigo_extra_ca::fluxrouter::IdentityDisclosure;

/// The extension notification that tells a client a relay was refused (P125).
pub const RELAY_REFUSED_METHOD: &str = "fuigo/relay/refused";
/// The extension notification that tells a client the leader no longer refuses its relay (the user opted in).
pub const RELAY_REFUSAL_CLEARED_METHOD: &str = "fuigo/relay/refusal_cleared";

/// The raw JSON-RPC line for an extension notification: the ACP client side accepts a custom method only with the `_`
/// prefix on the wire (and hands it on without it), as every other `fuigo/...` notification the agent sends.
fn ext_notification_line(method: &str, params: serde_json::Value) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "method": format!("_{method}"),
        "params": params,
    })
    .to_string()
}

/// P125: the line that tells interactive clients the leader's relay refusal is over.
pub fn refusal_cleared_payload() -> String {
    ext_notification_line(RELAY_REFUSAL_CLEARED_METHOD, serde_json::json!({}))
}

/// Environment variable naming the relay origins the user trusts to drive the agent.
pub const TRUSTED_RELAY_ORIGINS_ENV: &str = "FUIGO_TRUSTED_RELAY_ORIGINS";
/// The `config.toml` path of the same opt-in, read from the user config file only.
pub const TRUSTED_RELAY_ORIGINS_CONFIG_PATH: &str = "relay.trusted_origins";

/// Why the bridge to a relay may be opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RelayBridgeTrust {
    /// No relay URL is configured (the default install): there is nothing to bridge to, and the relay connection's
    /// own destination gate (P47) refuses an empty URL before any socket exists. Unchanged by P93.
    NoRelayConfigured,
    /// The relay is FluxRouter-operated; no opt-in is needed.
    FluxRouterOperated,
    /// The user opted in to this relay origin.
    OptedIn {
        /// The relay's origin, as matched.
        origin: String,
        /// Where the opt-in came from.
        source: OptInSource,
    },
}

/// Where an opt-in was read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OptInSource {
    /// `[relay] trusted_origins` in the user config file.
    UserConfig,
    /// `FUIGO_TRUSTED_RELAY_ORIGINS`.
    Environment,
}

/// The bridge to a relay that is not FluxRouter-operated was refused: no opt-in names its origin.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RelayOptInRefused {
    /// The relay's origin, or `None` when the relay URL is not a `ws`/`wss` URL with a host.
    origin: Option<String>,
    /// The user config file the opt-in belongs in.
    user_config: String,
    /// What the relay was to be used for.
    purpose: RelayPurpose,
}

/// What a relay connection is for; it decides what the refusal tells the user is at stake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayPurpose {
    /// The agent is bridged to the relay (headless-relay and leader mode): the relay drives the agent.
    Bridge,
    /// The TUI syncs the session to the relay (session sharing): the relay receives the transcript.
    Sync,
}

impl RelayPurpose {
    fn wire(self) -> &'static str {
        match self {
            Self::Bridge => "bridge",
            Self::Sync => "sync",
        }
    }
}

impl RelayOptInRefused {
    /// The relay origin that was refused (`None`: the URL has no usable origin).
    pub fn origin(&self) -> Option<&str> {
        self.origin.as_deref()
    }
    /// What the relay was to be used for.
    pub fn purpose(&self) -> RelayPurpose {
        self.purpose
    }
    /// P125: the params of the `fuigo/relay/refused` notification that shows this refusal in the TUI: the relay's
    /// origin (`null` when the URL has none), what it was to be used for, the full text (the same text the refusal
    /// prints elsewhere: which relay, why, how to trust it) and, for a session's relay sync, the session.
    pub fn notice_params(&self, session_id: Option<&str>) -> serde_json::Value {
        let mut params = serde_json::json!({
            "origin": self.origin,
            "use": self.purpose.wire(),
            "message": self.to_string(),
        });
        if let Some(session_id) = session_id {
            params["sessionId"] = serde_json::Value::from(session_id);
        }
        params
    }
    /// P125: [`Self::notice_params`] as the JSON-RPC notification line an IPC server sends to a client.
    pub fn notice_payload(&self) -> String {
        ext_notification_line(RELAY_REFUSED_METHOD, self.notice_params(None))
    }
    /// Log the refusal (the caller also shows it: stderr, or the error it returns).
    pub fn record(&self, site: &'static str) {
        tracing::warn!(
            site,
            relay_origin = self.origin.as_deref().unwrap_or("<unparseable>"),
            "relay bridge refused: the relay is not FluxRouter-operated and no opt-in names its origin"
        );
    }
}

impl std::fmt::Display for RelayOptInRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Some(origin) = self.origin.as_deref() else {
            let refusal = match self.purpose {
                RelayPurpose::Bridge => "Fuigo will not connect to the configured relay",
                RelayPurpose::Sync => "Fuigo will not sync this session to the configured relay",
            };
            return write!(
                f,
                "{refusal}: its URL (FUIGO_WS_URL, --fuigo-ws-url or \
                 fuigo_com_config.fuigo_ws_url) is not a ws:// or wss:// URL with a host, so no opt-in can name it."
            );
        };
        let (refusal, risk) = match self.purpose {
            RelayPurpose::Bridge => (
                format!("Fuigo will not connect to the relay at {origin}"),
                "a relay the agent is connected to can drive the agent like a local client (read your files, run \
                 commands, change MCP servers and configuration)",
            ),
            RelayPurpose::Sync => (
                format!("Fuigo will not sync this session to the relay at {origin}"),
                "a relay that session sharing syncs to receives your whole session transcript (prompts, replies \
                 and tool output)",
            ),
        };
        write!(
            f,
            "{refusal}: FluxRouter does not operate it, and {risk}. If you run this relay yourself or otherwise \
             trust it, opt in for its origin: add `trusted_origins = [\"{origin}\"]` under `[relay]` in your user \
             config {user_config} (a project's .fuigo/config.toml cannot set it), or set \
             {TRUSTED_RELAY_ORIGINS_ENV}={origin} for the processes you start after it. A running leader re-reads the \
             config file when the next headless client attaches. See \"Relays not operated by FluxRouter\" in the \
             destination trust policy.",
            user_config = self.user_config,
        )
    }
}

impl std::error::Error for RelayOptInRefused {}

/// An origin as the opt-in compares it: secure or not (`wss`/`https` vs `ws`/`http`), lowercase host without a
/// trailing dot, and the effective port.
#[derive(Clone, Debug, PartialEq, Eq)]
struct RelayOrigin {
    secure: bool,
    host: String,
    port: u16,
}

impl RelayOrigin {
    fn parse(spelling: &str) -> Option<Self> {
        let url = url::Url::parse(spelling.trim()).ok()?;
        let secure = match url.scheme() {
            "wss" | "https" => true,
            "ws" | "http" => false,
            _ => return None,
        };
        let host = url.host_str()?.trim_end_matches('.').to_ascii_lowercase();
        if host.is_empty() {
            return None;
        }
        let port = url.port_or_known_default()?;
        Some(Self { secure, host, port })
    }
}

impl std::fmt::Display for RelayOrigin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (scheme, default_port) = if self.secure { ("https", 443) } else { ("http", 80) };
        write!(f, "{scheme}://{}", self.host)?;
        if self.port != default_port {
            write!(f, ":{}", self.port)?;
        }
        Ok(())
    }
}

/// One opt-in entry as the user wrote it, with where it was read from.
#[derive(Clone, Debug)]
struct OptIn {
    spelling: String,
    source: OptInSource,
}

/// The P93 decision for bridging the agent to the relay at `ws_url` (the URL the relay socket is opened to), with the
/// opt-ins read now from the user config file and the environment.
pub fn relay_bridge_gate(ws_url: &str) -> Result<RelayBridgeTrust, RelayOptInRefused> {
    if ws_url.trim().is_empty() {
        return Ok(RelayBridgeTrust::NoRelayConfigured);
    }
    if IdentityDisclosure::for_websocket_destination(ws_url).is_permitted() {
        return Ok(RelayBridgeTrust::FluxRouterOperated);
    }
    decide(ws_url, &load_opt_ins())
}

/// P125: the decision for SYNCING a TUI session to the relay at `ws_url`: the same rule as [`relay_bridge_gate`] (a
/// FluxRouter-operated relay, or one whose origin the user opted in to), because a relay that sync connects to
/// receives the whole session transcript.
pub fn relay_sync_gate(ws_url: &str) -> Result<RelayBridgeTrust, RelayOptInRefused> {
    if ws_url.trim().is_empty() {
        return Ok(RelayBridgeTrust::NoRelayConfigured);
    }
    if IdentityDisclosure::for_websocket_destination(ws_url).is_permitted() {
        return Ok(RelayBridgeTrust::FluxRouterOperated);
    }
    decide_for(RelayPurpose::Sync, ws_url, &load_opt_ins())
}

/// [`relay_bridge_gate`] on given opt-ins, for a relay that is not FluxRouter-operated.
fn decide(ws_url: &str, opt_ins: &[OptIn]) -> Result<RelayBridgeTrust, RelayOptInRefused> {
    decide_for(RelayPurpose::Bridge, ws_url, opt_ins)
}

fn decide_for(
    purpose: RelayPurpose,
    ws_url: &str,
    opt_ins: &[OptIn],
) -> Result<RelayBridgeTrust, RelayOptInRefused> {
    let refused = |origin: Option<String>| RelayOptInRefused {
        origin,
        user_config: user_config_display(),
        purpose,
    };
    let Some(relay) = RelayOrigin::parse(ws_url).filter(|_| {
        url::Url::parse(ws_url.trim()).is_ok_and(|u| matches!(u.scheme(), "ws" | "wss"))
    }) else {
        return Err(refused(None));
    };
    for opt_in in opt_ins {
        match RelayOrigin::parse(&opt_in.spelling) {
            Some(trusted) if trusted == relay => {
                return Ok(RelayBridgeTrust::OptedIn {
                    origin: relay.to_string(),
                    source: opt_in.source,
                });
            }
            Some(_) => {}
            None => tracing::warn!(
                entry = %opt_in.spelling,
                source = ?opt_in.source,
                "ignoring a trusted relay origin that is not an http(s)/ws(s) origin"
            ),
        }
    }
    Err(refused(Some(relay.to_string())))
}

/// Every opt-in entry: the environment's, then the user config file's.
fn load_opt_ins() -> Vec<OptIn> {
    let mut opt_ins: Vec<OptIn> = std::env::var(TRUSTED_RELAY_ORIGINS_ENV)
        .ok()
        .into_iter()
        .flat_map(|value| {
            value
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .map(|spelling| OptIn {
            spelling,
            source: OptInSource::Environment,
        })
        .collect();
    // The user layer alone (`$FUIGO_HOME/config.toml`), never the merged config: no project, overlay, managed,
    // remote, campaign or requirements layer can name a relay the agent may be driven by.
    match crate::config::load_from_disk() {
        Ok(user) => opt_ins.extend(user_config_opt_ins(&user)),
        Err(error) => tracing::warn!(
            %error,
            "the user config could not be read; no relay opt-in is taken from it"
        ),
    }
    opt_ins
}

/// `[relay] trusted_origins` of the user config layer: an array of strings (a single string is accepted too).
fn user_config_opt_ins(user: &toml::Value) -> Vec<OptIn> {
    let Some(value) = user.get("relay").and_then(|relay| relay.get("trusted_origins")) else {
        return Vec::new();
    };
    let spellings: Vec<String> = match value {
        toml::Value::String(s) => vec![s.clone()],
        toml::Value::Array(entries) => entries
            .iter()
            .filter_map(|entry| {
                let s = entry.as_str();
                if s.is_none() {
                    tracing::warn!("ignoring a non-string entry in [relay] trusted_origins");
                }
                s.map(str::to_owned)
            })
            .collect(),
        other => {
            tracing::warn!(
                found = other.type_str(),
                "[relay] trusted_origins must be an array of origins; ignored"
            );
            Vec::new()
        }
    };
    spellings
        .into_iter()
        .map(|spelling| OptIn {
            spelling,
            source: OptInSource::UserConfig,
        })
        .collect()
}

fn user_config_display() -> String {
    fuigo_config::user_fuigo_home()
        .map(|home| home.join(fuigo_config::USER_CONFIG_FILENAME).display().to_string())
        .unwrap_or_else(|| "~/.fuigo/config.toml".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opt_in(spelling: &str) -> OptIn {
        OptIn {
            spelling: spelling.to_owned(),
            source: OptInSource::UserConfig,
        }
    }

    #[test]
    fn an_opt_in_matches_the_relay_origin_only() {
        let relay = "wss://Relay.Example./ws?x=1";
        for same in [
            "https://relay.example",
            "https://relay.example/",
            "wss://relay.example:443",
            "HTTPS://RELAY.EXAMPLE/any/path",
        ] {
            assert_eq!(
                decide(relay, &[opt_in(same)]),
                Ok(RelayBridgeTrust::OptedIn {
                    origin: "https://relay.example".into(),
                    source: OptInSource::UserConfig
                }),
                "{same}"
            );
        }
        for other in [
            "http://relay.example",
            "ws://relay.example",
            "http://relay.example:443",
            "https://relay.example:8443",
            "https://other.example",
            "https://sub.relay.example",
            "https://example",
            "relay.example",
            "*.relay.example",
            "",
        ] {
            let refused = decide(relay, &[opt_in(other)]).expect_err(other);
            assert_eq!(refused.origin(), Some("https://relay.example"), "{other}");
        }
        assert!(decide(relay, &[]).is_err());
    }

    #[test]
    fn ipv6_idn_and_userinfo_origins() {
        let opted_in = |relay: &str, entry: &str| decide(relay, &[opt_in(entry)]).is_ok();
        assert!(opted_in("wss://[::1]:9443/ws", "https://[::1]:9443"));
        assert!(opted_in("wss://[0:0:0:0:0:0:0:1]:9443/ws", "https://[::1]:9443"));
        assert!(!opted_in("wss://[::1]:9443/ws", "https://[::2]:9443"));
        assert!(!opted_in("wss://[::1]:9443/ws", "https://[::1]"));
        // The URL parser punycodes an internationalised host, so both spellings name one origin, and a lookalike
        // in another script is another origin.
        assert!(opted_in("wss://bücher.example/ws", "https://xn--bcher-kva.example"));
        assert!(opted_in("wss://xn--bcher-kva.example/ws", "https://BÜCHER.example"));
        assert!(!opted_in("wss://bucher.example/ws", "https://bücher.example"));
        // Userinfo is not part of an origin, on either side.
        assert!(opted_in("wss://user:secret@relay.example/ws", "https://relay.example"));
        assert!(opted_in("wss://relay.example/ws", "https://someone@relay.example"));
        assert!(!opted_in("wss://relay.example@evil.example/ws", "https://relay.example"));
        // A relay URL's userinfo is never echoed into the refusal.
        let refused = decide("wss://user:secret@relay.example/ws", &[]).unwrap_err().to_string();
        assert!(!refused.contains("secret") && !refused.contains("user:"), "{refused}");
    }

    #[test]
    fn no_relay_configured_is_not_a_refusal() {
        // The default install: no relay URL, nothing to bridge (P47 refuses an empty URL before any socket).
        for blank in ["", "  "] {
            assert_eq!(relay_bridge_gate(blank), Ok(RelayBridgeTrust::NoRelayConfigured));
        }
    }

    #[test]
    fn a_relay_url_without_a_ws_origin_is_refused_whatever_the_opt_ins() {
        for url in ["relay.example", "https://relay.example", "file:///tmp/x", "wss://"] {
            let refused = decide(url, &[opt_in("https://relay.example")]).expect_err(url);
            assert_eq!(refused.origin(), None, "{url}");
        }
    }

    #[test]
    fn the_refusal_says_what_to_set_and_where() {
        let refused = decide("wss://relay.example:9443/ws", &[]).unwrap_err();
        let text = refused.to_string();
        for needle in [
            "https://relay.example:9443",
            "trusted_origins = [\"https://relay.example:9443\"]",
            "[relay]",
            "FUIGO_TRUSTED_RELAY_ORIGINS=https://relay.example:9443",
            ".fuigo/config.toml cannot set it",
        ] {
            assert!(text.contains(needle), "missing {needle:?} in {text}");
        }
        assert!(!text.contains("/ws"), "the refusal names the origin, not the URL: {text}");
    }

    #[test]
    fn a_fluxrouter_relay_needs_no_opt_in() {
        assert_eq!(
            relay_bridge_gate("wss://api.fluxrouter.ai/ws/relay"),
            Ok(RelayBridgeTrust::FluxRouterOperated)
        );
    }

    #[test]
    fn user_config_entries_are_read_from_relay_trusted_origins() {
        let user: toml::Value = toml::from_str(
            "[relay]\nenabled = true\ntrusted_origins = [\"https://a.example\", 7, \"wss://b.example\"]\n",
        )
        .unwrap();
        let got: Vec<String> = user_config_opt_ins(&user).into_iter().map(|o| o.spelling).collect();
        assert_eq!(got, ["https://a.example", "wss://b.example"]);
        let single: toml::Value =
            toml::from_str("[relay]\ntrusted_origins = \"https://a.example\"\n").unwrap();
        assert_eq!(user_config_opt_ins(&single).len(), 1);
        let top_level: toml::Value =
            toml::from_str("trusted_origins = [\"https://a.example\"]\n").unwrap();
        assert!(user_config_opt_ins(&top_level).is_empty());
    }

    /// P125: syncing a session decides like bridging, but the refusal says what is at stake for a sync.
    #[test]
    fn a_sync_refusal_names_the_relay_the_transcript_and_how_to_trust_it() {
        let refused = decide_for(RelayPurpose::Sync, "wss://relay.example:9443/ws", &[]).unwrap_err();
        assert_eq!(refused.purpose(), RelayPurpose::Sync);
        let text = refused.to_string();
        for needle in [
            "will not sync this session to the relay at https://relay.example:9443",
            "FluxRouter does not operate it",
            "session transcript",
            "trusted_origins = [\"https://relay.example:9443\"]",
            "FUIGO_TRUSTED_RELAY_ORIGINS=https://relay.example:9443",
        ] {
            assert!(text.contains(needle), "missing {needle:?} in {text}");
        }
        assert!(!text.contains("drive the agent"), "a sync refusal is not the bridge text: {text}");
        let bridge = decide("wss://relay.example:9443/ws", &[]).unwrap_err().to_string();
        assert!(bridge.contains("drive the agent") && !bridge.contains("transcript"), "{bridge}");
        // An opt-in for the origin lifts it, exactly as for a bridge.
        assert!(decide_for(RelayPurpose::Sync, "wss://relay.example:9443/ws", &[opt_in("https://relay.example:9443")]).is_ok());
    }

    #[test]
    fn the_sync_gate_needs_no_opt_in_for_fluxrouter_or_no_relay() {
        assert_eq!(relay_sync_gate(""), Ok(RelayBridgeTrust::NoRelayConfigured));
        assert_eq!(
            relay_sync_gate("wss://api.fluxrouter.ai/ws/relay"),
            Ok(RelayBridgeTrust::FluxRouterOperated)
        );
    }

    #[test]
    fn a_refusal_is_a_notice_the_tui_can_show() {
        let refused = decide_for(RelayPurpose::Sync, "wss://relay.example/ws", &[]).unwrap_err();
        let params = refused.notice_params(Some("sess-1"));
        assert_eq!(params["origin"], "https://relay.example");
        assert_eq!(params["use"], "sync");
        assert_eq!(params["sessionId"], "sess-1");
        assert_eq!(params["message"], refused.to_string());
        let line: serde_json::Value = serde_json::from_str(&refused.notice_payload()).unwrap();
        assert_eq!(line["method"], format!("_{RELAY_REFUSED_METHOD}"));
        assert_eq!(line["params"]["origin"], "https://relay.example");
        assert!(line.get("id").is_none(), "a notification has no id");
        let no_origin = decide("relay.example", &[]).unwrap_err().notice_params(None);
        assert!(no_origin["origin"].is_null() && no_origin.get("sessionId").is_none());
    }

    /// P125 (Astra r1): the leader's notice crosses the pager's ACP decoder, which accepts an extension notification
    /// only with the `_` prefix on the wire, and comes out as the `fuigo/relay/refused` extension the pager handles.
    #[test]
    fn the_leaders_notice_decodes_as_an_acp_extension_notification() {
        use agent_client_protocol::{AgentNotification, ClientSide, Side};
        let refused = decide("wss://relay.example/ws", &[]).unwrap_err();
        let line: serde_json::Value = serde_json::from_str(&refused.notice_payload()).unwrap();
        let method = line["method"].as_str().unwrap();
        let params = serde_json::value::to_raw_value(&line["params"]).unwrap();
        let decoded = ClientSide::decode_notification(method, Some(&params))
            .unwrap_or_else(|e| panic!("the ACP client side rejects {method}: {e:?}"));
        match decoded {
            AgentNotification::ExtNotification(ext) => {
                assert_eq!(&*ext.method, RELAY_REFUSED_METHOD);
                let got: serde_json::Value = serde_json::from_str(ext.params.get()).unwrap();
                assert_eq!(got["origin"], "https://relay.example");
            }
            other => panic!("not an extension notification: {other:?}"),
        }
    }
}

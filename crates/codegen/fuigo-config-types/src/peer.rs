//! `[peer]` config value types (peer messaging, packet 4). Nothing reads this section from `config.toml` yet: the
//! session takes the policy from its host through the session handle; a later packet plumbs the file value.

use serde::{Deserialize, Serialize};

/// What a session does with a message from another session (design S4.2).
///
/// Every value stays subject to the mode-equality rule: `accept` admits only when the sender's mode equals the
/// receiver's; any difference holds. The default is `accept` (equality-gated).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PeerInboundPolicy {
    #[default]
    Accept,
    Hold,
    Refuse,
}

impl PeerInboundPolicy {
    pub const ALL: [PeerInboundPolicy; 3] = [Self::Accept, Self::Hold, Self::Refuse];
}

/// The `[peer]` section of `config.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct PeerConfig {
    pub inbound: PeerInboundPolicy,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_inbound_is_accept_and_parses_lowercase() {
        assert_eq!(PeerConfig::default().inbound, PeerInboundPolicy::Accept);
        let c: PeerConfig = toml::from_str("inbound = \"hold\"").unwrap();
        assert_eq!(c.inbound, PeerInboundPolicy::Hold);
        let c: PeerConfig = toml::from_str("inbound = \"refuse\"").unwrap();
        assert_eq!(c.inbound, PeerInboundPolicy::Refuse);
        assert!(toml::from_str::<PeerConfig>("inbound = \"Always\"").is_err());
        assert_eq!(toml::from_str::<PeerConfig>("").unwrap(), PeerConfig::default());
    }
}

//! Types for the `search_tool`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize, JsonSchema, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SearchScope {
    #[default]
    Mcp,
    Native,
}

/// Input for the `search_tool` tool.
#[derive(Debug, Clone, Deserialize, Serialize, JsonSchema)]
pub struct SearchToolInput {
    /// MCP integrations by default. Native reveals eligible deferred built-in
    /// schemas for the next request; invoke those tools by their original names.
    #[serde(default)]
    pub scope: SearchScope,
    /// Keywords to match against tool names, server names, and descriptions.
    /// Include the server name and action for best results
    /// (e.g. "linear create issue", "slack read thread history").
    pub query: String,
    /// Maximum number of results to return (default 5).
    #[serde(default = "default_limit")]
    pub limit: Option<u8>,
}

fn default_limit() -> Option<u8> {
    Some(5)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_discovery_scope_is_explicit_and_old_input_stays_mcp() {
        let old: SearchToolInput=serde_json::from_str(r#"{"query":"images"}"#).unwrap();
        assert_eq!(old.scope,SearchScope::Mcp);
        let native: SearchToolInput=serde_json::from_str(r#"{"query":"images","scope":"native"}"#).unwrap();
        assert_eq!(native.scope,SearchScope::Native);
        assert!(serde_json::from_str::<SearchToolInput>(r#"{"query":"images","scope":"all-powerful"}"#).is_err());
    }
}

//! Single source of truth for the `fuigo/mcp/*` ACP wire strings.
//!
//! These method/`_meta` keys are part of the cross-language MCP-over-ACP protocol the SDK speaks (mirrors the SDK's `_mcp_wire.py` / `mcpWire.ts`).
//! Reference these constants instead of re-typing the literals so the agent and SDK can't drift apart.

/// Forward tool-invocation method (client to agent): `fuigo/mcp/call`.
///
/// The pager/client asks the agent to invoke an MCP tool on a server the agent is connected to, outside the LLM loop.
/// See `extensions::mcp::handle_call`.
pub const MCP_CALL: &str = "fuigo/mcp/call";

/// Reverse zero-IPC tool-invocation method (agent to client): `fuigo/mcp/sdk_call`.
///
/// The agent invokes a tool in the SDK's in-process MCP server by sending the MCP JSON-RPC message back to the client over the ACP reverse channel.
/// It is distinct from [`MCP_CALL`] so the two disjoint schemas don't share a method string for metrics/tracing.
/// See the agent-side ACP invoker that handles this method.
pub const MCP_SDK_CALL: &str = "fuigo/mcp/sdk_call";

/// `session/new` `_meta` key listing in-process SDK MCP servers: `fuigo/mcp/servers`.
pub const MCP_SERVERS: &str = "fuigo/mcp/servers";

/// `initialize` `_meta` capability flag advertising in-process SDK MCP support (enables the SDK's `transport="acp"`): `fuigo/mcp/sdk`.
pub const MCP_SDK: &str = "fuigo/mcp/sdk";

/// Reverse elicitation method (agent to client): `fuigo/mcp/elicit`.
///
/// The agent forwards an MCP server's `elicitation/create` request to the client, which shows the user a popup and returns accept/decline/cancel.
pub const MCP_ELICIT: &str = "fuigo/mcp/elicit";

/// Elicitation-complete notification (agent to client): `fuigo/mcp/elicit_complete`.
///
/// The agent forwards a server's `notifications/elicitation/complete` so the client can dismiss the popup for the given `elicitationId`.
pub const MCP_ELICIT_COMPLETE: &str = "fuigo/mcp/elicit_complete";

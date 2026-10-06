# P113 Astra r1 final report (gpt-6-astra, read-only; raw transcript sha256 aa047d067b305f79, kept outside the repo)

Read-only audit of `d1b6ba58..e1171e61`, with HEAD confirmed at `e1171e61`. No builds, tests, or application execution performed.

1. **HIGH — Feedback archives retain credentials encoded in bash output.**  
   [feedback_archive.rs:207](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-shell/src/upload/feedback_archive.rs:207) matches credential text against serialized bytes. Production bash output stores `BashOutput.output` as a JSON array of numbers via [tool_dispatch.rs:426](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-shell/src/session/acp_session_impl/tool_dispatch.rs:426). If a command prints a recorded credential, its string copies can be redacted while the complete credential remains recoverable from `rawOutput.output` in archived `updates.jsonl`. This encoding is performed by Fuigo itself.  
   **Test coverage:** Not caught. The archive regression covers string-valued events and plain text; searching archived text for `KEY` cannot detect this representation.

2. **HIGH — Valid MCP error responses still persist credentials outside EventWriter.**  
   [storage/jsonl/mod.rs:377](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-shell/src/session/storage/jsonl/mod.rs:377) and [storage/jsonl/mod.rs:646](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-shell/src/session/storage/jsonl/mod.rs:646) serialize chat and session updates without scrubbing. A server handed `${FUIGO_API_KEY}` can return valid `tools/call` content with `isError: true` and the echoed key. [servers.rs:1605](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-mcp/src/servers.rs:1605) preserves that text in its tool output, which reaches these writers. The key therefore remains on disk despite the scrubbed event. After restarting with a different key, the process-local registry cannot remove the old key during feedback packing.  
   **Test coverage:** Not caught. The new transport test covers undecodable stdout; the archive test explicitly records its historical fixture’s key before packing.

3. **HIGH — Auth-provider helpers still inherit Fuigo’s internal secrets.**  
   [auth_provider.rs:286](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-shell/src/auth/auth_provider.rs:286) removes only `FIRST_PARTY_CREDENTIAL_ENV_VARS`; its production spawn does not apply the expanded policy. That separate list omits `FUIGO_AGENT_SECRET`, the logs/metrics OTLP header variables, and the telemetry ingestion credentials. Starting Fuigo with these exported and invoking a configured auth-provider helper exposes them to that helper and its descendants.  
   **Test coverage:** Not caught. The new pin checks membership in the tools denylist, not the helper’s environment. The existing helper test’s independent list has the same omissions.

4. **MEDIUM — JSON MCP configurations awaiting setup bypass credential registration.**  
   [util/config/mcp.rs:1644](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-shell/src/util/config/mcp.rs:1644) accepts JSON configurations without registering their credential names. [util/config/mcp.rs:1350](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-shell/src/util/config/mcp.rs:1350) then skips a server requiring setup before reaching either newly protected conversion method. A `.mcp.json` server naming `CORP_BEARER` and awaiting its site selection consequently leaves that ambient variable inheritable by another stdio server, hook, or shell.  
   **Test coverage:** Not caught. The JSON regression directly invokes conversion on configurations without setup; it bypasses the loader’s early exit.

5. **MEDIUM — The relay’s initial proxy log still leaks a password spelling this patch accepts.**  
   [relay.rs:298](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-shell/src/agent/relay.rs:298) uses a different parser from the updated tunnel code. For `http://alice:1234/privatepass@proxy.example:3128`, the new parser treats `1234/privatepass` as the password. However, `redact_url` interprets `alice:1234` as the authority and `/privatepass@proxy.example:3128` as the path, which it preserves. The initial INFO log therefore retains the credentials under the patch’s explicitly supported unescaped-slash syntax.  
   **Test coverage:** Not caught. The new logging test calls `open_connect_tunnel` directly and never exercises `relay_proxy_for`.

6. **MEDIUM — An `@` in a proxy path now changes the connection destination.**  
   [proxy.rs:223](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-shell/src/agent/proxy.rs:223) searches for the last `@` before separating the authority from the path. Consequently, `http://proxy.company:3128/path@other.example:8080` now connects to `other.example:8080`; previously it connected to `proxy.company:3128`. This is a routing regression for the existing path-stripping behavior.  
   **Test coverage:** Not caught. No added case places `@` solely in the path.

The added environment probes use subprocess isolation, and the new registry tests use distinct names. I found no concrete additional process-global-state hazard in those tests.

DO-NOT-LAND

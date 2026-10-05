tokens used
301,640
**Three HIGH findings remain. P136 does not yet satisfy (a), (c), and (d).**

Audited all 13 commits in `98371398..92787667`, including P133 through `9ffc92df` and both P136 commits. Compared against `v1.0.20` (`2eb306e0`). HEAD remained `92787667587605259c4ec31a94411c663f7c1e66`. No files changed; no builds, tests, or application code executed. Reproductions below are source-derived. `R136-p136.md` was absent.

| R3 finding | Verdict | Evidence |
|---|---|---|
| **1 — HIGH: OAuth extraction ignores provenance** | **FIXED** | Both OAuth secret fields now pass through the provenance-aware resolver: [config-types/mcp.rs:638](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-config-types/src/mcp.rs:638). The `${SWITCH:-FUIGO_API_KEY}` restart case is rejected by [mcp.rs:624](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-config-types/src/mcp.rs:624). Other credential paths remain vulnerable, below. |
| **2 — HIGH: missing/disabled OAuth definition fails open** | **FIXED** | OAuth extraction now requires successful enabled-server materialization: [util/config/mcp.rs:227](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-shell/src/util/config/mcp.rs:227), [mcp.rs:1369](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-shell/src/util/config/mcp.rs:1369). Missing disk or active definitions explicitly reject inheritance; surviving definitions require normalized full equality: [managed_mcp.rs:664](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-shell/src/session/managed_mcp.rs:664). |
| **3 — HIGH: pager copy weakens trusted disk configuration** | **NOT FIXED** | Unchanged, ordinary-name copies now work. Renaming and subsequent reloads still lose trusted identity and scrub legitimate credentials: [managed_mcp.rs:139](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-shell/src/session/managed_mcp.rs:139), [managed_mcp.rs:210](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-shell/src/session/managed_mcp.rs:210). |
| **4 — MEDIUM: cross-session ownership and shared-file path heuristic** | **FIXED** | Refusals receive their scope when recorded, and retrieval selects that scope without inspecting paths: [key_naming.rs:606](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-config/src/key_naming.rs:606), [key_naming.rs:565](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-config/src/key_naming.rs:565). New/load setup establishes separate scopes. Delivery gaps remain below, but I found no remaining cross-session disclosure in these traced paths. |

1. **HIGH — Legitimate forwarded user servers still lose credentials after renaming or reload.**

   **Startup reproduction:** Save an unexported key and configure `"com.example"` in canonical `config.toml`, `~/.claude.json`, or `~/.cursor/mcp.json`, with `Authorization = "Bearer ${FUIGO_API_KEY}"`. Start through the pager.

   First admission recognizes the disk definition, then renames it to `com-example`. `resolve_mcp_servers` passes that admitted list into another admission during merge. The disk map still contains `com.example`, so the second admission scrubs the renamed copy to `Bearer `. The original dotted server does not rescue tool access: invalid tool namespaces are rejected.

   Evidence: [agent_ops.rs:558](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-shell/src/agent/mvp_agent/agent_ops.rs:558), [managed_mcp.rs:139](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-shell/src/session/managed_mcp.rs:139), [managed_mcp.rs:189](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-shell/src/session/managed_mcp.rs:189), [servers.rs:1428](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-mcp/src/servers.rs:1428).

   **Reload reproduction:** Use an ordinary name such as `corp` with the same authorization header. After successful pager startup, add an innocuous `X-Note` header to its user configuration. Hot reload reuses the original forwarded snapshot. It now differs from disk, gets its key reference scrubbed, and overwrites the newly loaded trusted definition.

   Evidence: [session_admin.rs:648](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-shell/src/extensions/session_admin.rs:648), [managed_mcp.rs:210](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-shell/src/session/managed_mcp.rs:210).

   **Attribution:** P133 credential-loss regressions versus both baselines; P136 only partially repairs them.

2. **HIGH — A bearer variable can introduce a saved-key reference after the final scrub.**

   **Reproduction:** Save the key without exporting it. Start Fuigo with another variable containing the *literal* text `${FUIGO_API_KEY}`, for example `MCP_TOKEN_REF`. Submit an ACP `fuigo/mcp/upsert` targeting an attacker-controlled HTTP endpoint with `bearer_token_env_var = "MCP_TOKEN_REF"`.

   The definition is marked untrusted, but its scrub happens before the bearer variable is resolved. The resolver rejects the saved key’s name and exact value; it accepts the literal reference returned by `MCP_TOKEN_REF`. That becomes `Authorization: Bearer ${FUIGO_API_KEY}`. The HTTP spawn subsequently resolves it to the saved secret.

   Evidence: scrub-before-conversion at [config-types/mcp.rs:526](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-config-types/src/mcp.rs:526), header construction at [mcp.rs:584](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-config-types/src/mcp.rs:584), incomplete value check at [mcp.rs:629](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-config-types/src/mcp.rs:629), late binding at [servers.rs:5134](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-mcp/src/servers.rs:5134).

   **Attribution:** Already possible at `98371398`; still violates P136(c). This exact deferred-reference payload remains literal in `v1.0.20`, whose HTTP spawn lacks the later saved-key binding.

3. **HIGH — Persisted untrusted headers can resolve an exported key before provenance is checked.**

   **Reproduction:** While `SWITCH=safe`, upsert an HTTP server with:

   ```json
   {"headers":{"Authorization":"Bearer ${SWITCH:-$}{FUIGO_API_KEY}"}}
   ```

   The current-environment composition check accepts it and persists the untrusted marker. Restart with `SWITCH` absent and `FUIGO_API_KEY` exported.

   Loading canonical user TOML produces `Bearer ${FUIGO_API_KEY}` on its first expansion. MCP materialization expands it again, producing the actual credential. The final untrusted scrub sees no reference, and ordinary header values never pass through `credential_from_env_var`. The attacker’s endpoint receives the key despite the persisted marker.

   Evidence: environment-dependent admission at [key_naming.rs:430](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-config/src/key_naming.rs:430), trusted-file expansion at [loader.rs:232](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-config/src/loader.rs:232), second expansion before conversion at [util/config/mcp.rs:373](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-shell/src/util/config/mcp.rs:373), reference-only final scrub at [config-types/mcp.rs:491](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-config-types/src/mcp.rs:491).

   **Attribution:** Residual vulnerability present at both baselines. Marker persistence and P136’s selector checks do not close it.

4. **MEDIUM — Refusals produced outside the setup future are never delivered to their owner.**

   **Reproduction:** After session creation, call `fuigo/session/update_mcp_servers` with a new server containing `${FUIGO_API_KEY}` in a header. Admission removes it, but this handler establishes no `NoticeScope` and sends no `NotifyConfigNotice`. Its refusal receives `None` ownership and cannot appear in any session’s scoped notices.

   Evidence: [session_admin.rs:570](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-shell/src/extensions/session_admin.rs:570), [key_naming.rs:607](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-config/src/key_naming.rs:607), [key_naming.rs:569](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-config/src/key_naming.rs:569).

   The same omission affects startup work on the session thread. For example, a trusted project’s `.fuigo/hooks/key.json` containing a command hook that references the key is loaded and scrubbed on that thread. The outer setup scope is not propagated: [spawn.rs:2631](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-shell/src/session/acp_session_impl/spawn.rs:2631), [spawn.rs:1461](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-shell/src/session/acp_session_impl/spawn.rs:1461).

   **Attribution:** Incomplete P133 notice coverage; P136 additionally drops worker-thread refusals that the previous process-wide collection could capture. Requirement (d) remains unmet.

5. **MEDIUM — Another session can evict an owner’s undelivered notices.**

   **Reproduction:** Session A records a refusal, then awaits during setup. Before A announces notices, session B submits a stdio definition containing 4,097 arguments that reference the key. B’s refusals fill the global window and evict A’s entry. A subsequently receives no warning.

   Scope tagging prevents misdelivery, but all scopes still share a 4,096-entry FIFO. Undelivered entries have no protection or overflow notification.

   Evidence: [key_naming.rs:602](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-config/src/key_naming.rs:602), [key_naming.rs:612](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-config/src/key_naming.rs:612), [agent_ops.rs:2220](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-shell/src/agent/mvp_agent/agent_ops.rs:2220).

   **Attribution:** P133 introduced bounded user-notice collection; P136 enlarges the window but retains the delivery defect.

DO-NOT-LAND
ASTRA_EXIT=0

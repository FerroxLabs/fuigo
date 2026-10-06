tokens used
349,492
**DO-NOT-LAND: three HIGH findings remain at `0ed078cf`.**

Read-only source audit; no builds, tests, or repository code executed. All line numbers below refer to `0ed078cf`, not the newer worktree HEAD. The original round-2 reports were unavailable; the mapping uses the six round-2 findings enumerated in [R133-p133.md](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/docs/strike/receipts/R133-p133.md:7).

| Round-2 finding | Verdict | Evidence |
|---|---|---|
| R1-1 — HIGH: persisted upsert laundering | **NOT FIXED fully** | The marker now persists at [config-types/mcp.rs:293](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-config-types/src/mcp.rs:293), but OAuth extraction bypasses it. Finding 1 below. |
| R1-4 — MEDIUM: notices cross session/project boundaries | **NOT FIXED fully** | Non-path labels still pass every session’s filter at [key_naming.rs:568](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-config/src/key_naming.rs:568). Finding 4 below. |
| HIGH: `workspace.configure_mcp` binds the key | **FIXED** | Incoming definitions are scrubbed before startup at [hub_server.rs:756](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-workspace/src/hub_server.rs:756). |
| HIGH: same-named client server inherits configured OAuth secret | **NOT FIXED fully** | The destination check retains credentials when its disk-server lookup fails at [managed_mcp.rs:599](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-shell/src/session/managed_mcp.rs:599). Finding 2 below. |
| MEDIUM: `json` / `streaming-messages-json` drop notices | **FIXED** | Both formats explicitly emit the warning to stderr at [headless.rs:555](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-pager/src/headless.rs:555) and line 563. |
| MEDIUM: active-session upsert refusal is never announced | **FIXED** | The handler enqueues its refusals at [extensions/mcp.rs:2194](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-shell/src/extensions/mcp.rs:2194); the actor dispatches `ConfigNotice` at [run_loop.rs:1353](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-shell/src/session/acp_session_impl/run_loop.rs:1353). |

1. **HIGH — A persisted untrusted upsert can still select the saved key through OAuth.**

   Upsert an HTTP server with `oauth_client_id = "client"` and `oauth_client_secret_env_var = "${SWITCH:-FUIGO_API_KEY}"` while `SWITCH=OTHER_SECRET`. The current-environment composition check accepts it and persists the untrusted marker.

   Restart without `SWITCH`. Loading the trusted user file expands the selector to `FUIGO_API_KEY`. [util/config/mcp.rs:225](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-shell/src/util/config/mcp.rs:225) calls `oauth_config()` **before** `to_acp_mcp_server()`. [config-types/mcp.rs:620](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-config-types/src/mcp.rs:620) does not inspect `untrusted_source`; line 632 resolves the saved key. Scrubbing the separate ACP representation afterward cannot remove that already-extracted secret.

   The destination filter passes because the persisted and active URLs match. When this server’s OAuth flow runs, the secret enters its client credentials at [oauth.rs:416](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-mcp/src/oauth.rs:416).

   **Attribution:** remaining laundering vulnerability, already possible at `15c21ddf` and `v1.0.20`; marker persistence does not close the OAuth path.

2. **HIGH — OAuth destination checking fails open for disabled user JSON definitions.**

   Configure `corp` in canonical `~/.cursor/mcp.json` with `enabled: false`, its legitimate URL, an OAuth client ID, and `oauth_client_secret_env_var: "FUIGO_API_KEY"`. With Cursor MCP compatibility enabled, an ACP client supplies a same-named server pointing to its own endpoint.

   [util/config/mcp.rs:225](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-shell/src/util/config/mcp.rs:225) retains the OAuth settings, while the disabled definition produces no ACP server because of [config-types/mcp.rs:537](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-config-types/src/mcp.rs:537). Consequently, [managed_mcp.rs:599](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-shell/src/session/managed_mcp.rs:599) finds no disk server and returns `true`, preserving the secret for the attacker’s destination.

   The disabled-name filter does not rescue this case: [util/config/mcp.rs:1762](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-shell/src/util/config/mcp.rs:1762) collects disabled TOML definitions and the TOML disabled list, not disabled Cursor JSON entries.

   **Attribution:** residual round-2 OAuth vulnerability; also possible at both baselines. Missing destination evidence must reject credential inheritance.

3. **HIGH — NEW P133 regression: normal TUI/headless startup strips legitimate user-config credentials.**

   Save the key without exporting it, and put `Authorization = "Bearer ${FUIGO_API_KEY}"` in a server’s headers in `~/.fuigo/config.toml`.

   The pager loads that canonical configuration and forwards it through `session/new` or `session/load`: [effects/mod.rs:225](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-pager/src/app/effects/mod.rs:225), [headless.rs:1003](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-pager/src/headless.rs:1003). P133 treats these forwarded definitions as untrusted and removes the reference at [managed_mcp.rs:121](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-shell/src/session/managed_mcp.rs:121).

   The cleaned client copy then **overwrites the correctly loaded trusted disk definition** at [managed_mcp.rs:184](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-shell/src/session/managed_mcp.rs:184). The server receives `Bearer ` and authentication fails. Explicit key references in stdio arguments and environment values suffer the same regression.

   **Attribution:** introduced by P133 versus both `15c21ddf` and `v1.0.20`. This affects untouched canonical user configuration, beyond the documented `/mcps Add` restriction.

4. **MEDIUM — Notice ownership remains incomplete.**

   During overlapping session starts, session A can receive session B’s client-server refusal because labels such as `MCP server … supplied by the ACP client` are not absolute paths and therefore always pass [key_naming.rs:568](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-config/src/key_naming.rs:568). Project plugin manifest paths outside the few recognized filename patterns also pass. Impact: disclosure of another session’s source/server names and misleading warnings.

   Conversely, a shared `FUIGO_CONFIG_PATH=/opt/shared/.fuigo/config.toml` is misclassified as another project’s file and its notice is suppressed for a session elsewhere, via [key_naming.rs:574](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-config/src/key_naming.rs:574).

   **Attribution:** cross-session user-visible delivery is introduced by P133 versus both baselines; the round-2 filename heuristic only partially corrects it.

The direct env/header/argument scrubbers, URL-alias handling, inline-agent refusal, and binding-before-session-ID substitution remain in place. The LOW allowlist wording is corrected at [key_naming.rs:29](/Volumes/Mando/WaylandBots/Fuigo/wt-p133/crates/codegen/fuigo-config/src/key_naming.rs:29). I found no additional concrete crash or hang defect in the examined changes; runtime behavior was not tested.

DO-NOT-LAND
ASTRA_EXIT=0

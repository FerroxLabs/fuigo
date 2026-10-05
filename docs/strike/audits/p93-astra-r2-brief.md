# P93 Astra audit brief, round 2

Repository: this worktree (branch strike/p93). Diff to audit: `git diff e0145e0f..HEAD` (read it; read any file you need).
Read-only. Do not run cargo.

Background: P82 (`docs/strike/receipts/R089-p82.md` §1 item 1) found that a relay bridged to the agent (headless-relay
mode, leader mode: `crates/codegen/fuigo-shell/src/agent/app.rs`) drives the agent like a local ACP client
(`_fuigo/fs/read_file` with absolute paths, `_fuigo/terminal/create`, `_fuigo/mcp/upsert` with `bearer_token_env_var`,
config write-then-read-back with env expansion). Decision (Sean, 2026-10-03): (a) the trust policy states a relay the
user configures is trusted to drive the agent; (b) Fuigo refuses to bridge to a relay that is not FluxRouter-operated
unless the user explicitly opts in.

Claims of this diff:
1. When the relay URL in effect (`fuigo_com_config.fuigo_ws_url`: `FUIGO_WS_URL`, `--fuigo-ws-url`, config) is not
   FluxRouter-operated (`IdentityDisclosure::for_websocket_destination`), the leader (`spawn_leader_relay`: eager, on
   demand, and the `DeferredRelayArm` path) and headless-relay mode (`run_headless` early check, `spawn_headless_relay`,
   and `fuigo agent --leader headless` in `fuigo-pager-bin/src/main.rs` before contacting a leader) do not open the relay
   socket unless an opt-in names the relay's origin. No socket means no frame (including `initialize`).
2. The opt-in can only come from the user: `[relay] trusted_origins` read from `$FUIGO_HOME/config.toml` alone
   (`crate::config::load_from_disk()`), or `FUIGO_TRUSTED_RELAY_ORIGINS`. A repository's `.fuigo/config.toml`, the
   `FUIGO_CONFIG` overlay, managed config, remote settings, campaigns, requirements, and the relay itself cannot supply it.
3. The opt-in is per origin (`scheme://host[:port]`, wss≡https, ws≡http, host case and trailing dot normalised,
   effective port); another origin needs a new opt-in.
4. Refusal is actionable (what to set, where), logged (tracing warn) and shown (stderr / the returned error).
5. FluxRouter relays and the default install are unchanged; relay sync (`relay/sync.rs`) is intentionally not gated.
6. Tests (`fuigo-shell/src/agent/p93_relay_opt_in_tests.rs`, `relay_opt_in.rs` unit tests,
   `fuigo-pager-bin/tests/p93_relay_opt_in_process.rs`) exercise the real startup paths.

Find defects: any way a relay that is not FluxRouter-operated gets a bridge (a byte on its socket) without a user
opt-in for its exact origin; any way a repo, the relay, a remote/managed/campaign/overlay layer, or an attacker-
controlled input can supply or widen the opt-in; origin-matching bugs (IDN, IPv6, userinfo, default ports, scheme
confusion, `ws` vs `wss`); bypasses through other entry points that bridge the agent to a relay (look for every
`spawn_relay_connection*` caller and anything else that forwards relay frames into the agent); misleading docs
(`docs/destination-trust-policy.md`, `crates/codegen/fuigo-pager/docs/user-guide/15-agent-mode.md`,
`26-config-reference.md`); tests that would pass with the gate removed (check each test's controls). For each finding:
severity BLOCKER/HIGH/MEDIUM/LOW, file:line, concrete scenario, whether a test catches it. End with exactly one of
LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.

ROUND 2. HEAD is now 7d73127b. Round 1 (docs/strike/audits/p93-astra-r1.md) found 3 MEDIUM + 1 LOW; claimed fixes in
7d73127b: (1) `fuigo agent --leader headless` applies `--fuigo-ws-url`/`--fuigo-ws-origin` before the opt-in check and
the leader lookup (`apply_headless_url_args`); (2) a leader that refused decides again (re-reading the user config) on
every headless registration; `leader/server.rs` now notifies relay demand on every headless registration
(`send_replace(true)`), not only the first; (3) `cold_mint_auth_write_arms_deferred_relay` opts in to its loopback
relay in its own process; (4) policy/user guide say an opted-in relay can write the opt-in list. Also: an empty relay
URL (default install) is `NoRelayConfigured`, not a refusal (P47 still refuses an empty URL before any socket);
IPv6/IDN/userinfo unit tests. Verify these fixes and look for new defects they introduce (e.g. the re-check loop in
`spawn_leader_relay`, watch-channel semantics, anything else that consumes relay demand, the blank-URL passthrough).

# P93 Astra audit brief, round 3

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

ROUND 3. HEAD is now 233b4833. Round 1 and 2 reports: docs/strike/audits/p93-astra-r1.md, p93-astra-r2.md. Round 2's
MEDIUM (a registration arriving between the leader's refusal and its waiting task's first poll was swallowed) is
claimed fixed in 233b4833: `spawn_leader_relay` marks the demand watch seen BEFORE `bridge_permitted`, and the task no
longer marks it; regression `a_registration_right_after_the_refusal_is_not_lost` (eager, on demand, deferred arm, no
yield between refusal, opt-in and registration). Verify the fix and all earlier fixes, and look for anything new.

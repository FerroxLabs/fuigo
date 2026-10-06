# P93 Astra round 1 — final report (verbatim)

Model gpt-6-astra, read-only, on `e0145e0f..904d68aa`. Raw transcript: Hetzner `/root/fuigo-builds/p93/audits/p93-astra-r1.txt`.

Audited `e0145e0f..904d68aa` (including the two test additions committed during review). Read-only; no cargo or tests run.

1. **MEDIUM — The leader-client gate ignores `--fuigo-ws-url`.**  
   [main.rs:1408](/Volumes/Mando/WaylandBots/Fuigo/wt-p93/crates/codegen/fuigo-pager-bin/src/main.rs:1408) checks `agent_config` before the headless arguments are applied at line 1596. The leader branch returns before reaching that application.

   **Scenario:** With the default empty relay URL, `fuigo agent --leader headless --fuigo-ws-url wss://relay.example/ws` rejects an “invalid” empty URL even when the user has opted into `https://relay.example`. With another URL configured, it checks and contacts that destination instead. This is incorrect endpoint selection, not a demonstrated connection to an unapproved origin.

   **Tests:** Not caught. Both process tests supply `FUIGO_WS_URL`; neither exercises the CLI override. Apply the mode-specific URL before checking trust and constructing `LeaderEnvUrls`.

2. **MEDIUM — Following the opt-in remedy can leave an existing leader permanently disconnected.**  
   [app.rs:642](/Volumes/Mando/WaylandBots/Fuigo/wt-p93/crates/codegen/fuigo-shell/src/agent/app.rs:642) returns on refusal, discarding the demand receiver and relay-start state. `DeferredRelayArm` also consumes itself after this refusal at line 719.

   **Scenario:** An authenticated leader starts without consent for a third-party relay and keeps serving local clients. The user adds the documented user-config opt-in, then runs `agent --leader headless`. The client passes its check and attaches, but the existing leader cannot start the relay; the client waits indefinitely. Supplying the environment opt-in to that client also cannot update the existing leader’s environment.

   **Tests:** Not caught. The apparent retry control at [p93_relay_opt_in_tests.rs:289](/Volumes/Mando/WaylandBots/Fuigo/wt-p93/crates/codegen/fuigo-shell/src/agent/p93_relay_opt_in_tests.rs:289) creates a fresh relay start rather than reusing the refused leader. Preserve a retry path, or report the refusal to the client with an explicit leader-restart remedy.

3. **MEDIUM — The new gate invalidates an existing cold-mint regression test.**  
   [app.rs:1785](/Volumes/Mando/WaylandBots/Fuigo/wt-p93/crates/codegen/fuigo-shell/src/agent/app.rs:1785) configures `ws://127.0.0.1:<random-port>` without a relay opt-in. The new guard therefore returns before installing a handle, contradicting the assertion at [app.rs:1845](/Volumes/Mando/WaylandBots/Fuigo/wt-p93/crates/codegen/fuigo-shell/src/agent/app.rs:1845).

   **Scenario:** `cold_mint_auth_write_arms_deferred_relay` fails in a clean environment. This is a stale fixture caused by the change, not evidence that cold mint itself is broken.

   **Tests:** The existing test catches it; the new P93 tests do not. This failure is deduced from source, not an executed result. Adapt its fixture while retaining the auth-reload and handle-installation assertions.

4. **LOW — The policy overstates who can author subsequent opt-ins.**  
   [destination-trust-policy.md:307](/Volumes/Mando/WaylandBots/Fuigo/wt-p93/docs/destination-trust-policy.md:307) says the relay cannot opt in and another origin needs its own user opt-in.

   **Scenario:** Already-trusted relay A can use `_fuigo/fs/write_file` to add origin B to `$FUIGO_HOME/config.toml`. That handler permits absolute paths with confinement disabled by default ([fs.rs:232](/Volumes/Mando/WaylandBots/Fuigo/wt-p93/crates/codegen/fuigo-shell/src/extensions/fs.rs:232)). A subsequent startup accepts B without another human decision.

   **Tests:** Not caught; none exercises allowlist modification through a bridged agent. This follows from the accepted full-control policy. Qualify the documentation: an **unbridged** relay cannot bootstrap consent; an already-trusted relay has the authority to modify it.

I found no additional initial-connection bypass through the enumerated bridge callers, config-layer merging, or origin comparison. Relay sync remains separate from agent request forwarding. The negative tests would detect removal of their respective guards; positive-only tests appropriately would not. IDN, IPv6, and userinfo cases lack explicit P93 regression coverage.

DO-NOT-LAND

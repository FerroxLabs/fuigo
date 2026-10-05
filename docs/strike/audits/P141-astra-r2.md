# P141 Astra round 2 (gpt-6-astra, read-only) on d0e30df7

Final report only (full transcript not kept in the public tree). Brief: scratchpad `p141/astra-r2.txt`.

Audited clean `strike/p141` at `d0e30df7`. Static review only: no cargo, tests executed, or edits. **Both round-1 regressions are fixed; two inherited guarantees remain incomplete.**

| Finding | Verdict | Evidence |
|---|---|---|
| R1 HIGH: copies bypass trusted-name precedence | **FIXED** | Every admitted entry passes [managed_mcp.rs:385](/Volumes/Mando/WaylandBots/Fuigo/wt-p141/crates/codegen/fuigo-shell/src/session/managed_mcp.rs:385). Regression test: `managed_mcp_p141_tests.rs:199`. |
| R1 MEDIUM: copies change duplicate-client ordering | **FIXED** | Ordered admission at [managed_mcp.rs:270](/Volumes/Mando/WaylandBots/Fuigo/wt-p141/crates/codegen/fuigo-shell/src/session/managed_mcp.rs:270), followed by ordered insertion. Both orders tested at `managed_mcp_p141_tests.rs:236`. |
| R1 MEDIUM: actor retains old seed after update/reconnect | **NOT FIXED** completely | Reconnect propagation exists at [session_setup.rs:1147](/Volumes/Mando/WaylandBots/Fuigo/wt-p141/crates/codegen/fuigo-shell/src/agent/mvp_agent/session_setup.rs:1147); update still has the ordering gap below. |
| R1 MEDIUM: kill switch checks stale content | **NOT FIXED** completely | [managed_mcp.rs:276](/Volumes/Mando/WaylandBots/Fuigo/wt-p141/crates/codegen/fuigo-shell/src/session/managed_mcp.rs:276) fixes direct copy edits, but subsequent trusted substitution remains unchecked. |
| Fable MEDIUM 1: plugin must not replace forwarded user server | **NOT FIXED** completely | Initial admission/trust-grant case is fixed; overlapping update/reload still permits takeover below. |
| Fable LOW 2: single merge per ingress | **FIXED** | One merge at [managed_mcp.rs:183](/Volumes/Mando/WaylandBots/Fuigo/wt-p141/crates/codegen/fuigo-shell/src/session/managed_mcp.rs:183); callers consume its result at `agent_ops.rs:559` and `session_admin.rs:574`. |
| Fable LOW 3: retained copies follow edits/deletes | **FIXED** | Current disk-name lookup and deletion handling at [managed_mcp.rs:246](/Volumes/Mando/WaylandBots/Fuigo/wt-p141/crates/codegen/fuigo-shell/src/session/managed_mcp.rs:246). Renamed/plugin-shadowing tests: `managed_mcp_p141_tests.rs:43/74`. |

Remaining findings:

- **MEDIUM — update and seed adoption are not atomic.** [session_admin.rs:597](/Volumes/Mando/WaylandBots/Fuigo/wt-p141/crates/codegen/fuigo-shell/src/extensions/session_admin.rs:597) awaits initialization before sending the seed at line 606. Meanwhile, [run_loop.rs:1502](/Volumes/Mando/WaylandBots/Fuigo/wt-p141/crates/codegen/fuigo-shell/src/session/acp_session_impl/run_loop.rs:1502) initializes asynchronously, allowing `ReloadPlugins` to run.
  Concrete sequence: start with an empty client seed and plugin `corp=P`; update forwards the user’s Cursor `corp=U`; plugin reload uses the old empty seed and restores P; the later seed assignment does not reapply U. **Inherited in both baselines.** [The new test](/Volumes/Mando/WaylandBots/Fuigo/wt-p141/crates/codegen/fuigo-shell/src/agent/mvp_agent/tests/p141_single_merge_tests.rs:84) substitutes an immediate-ack receiver; it never exercises this interleaving.

- **MEDIUM — trusted-name substitution can introduce a blocked URL after admission.** [managed_mcp.rs:385](/Volumes/Mando/WaylandBots/Fuigo/wt-p141/crates/codegen/fuigo-shell/src/session/managed_mcp.rs:385) replaces the checked server, then inserts it without another kill-switch check.
  Concrete scenario: trusted user definition `com.example→B`; trusted folder’s project definition `com/example→A`; disabled Cursor configuration names B. Forward only the project definition: its marked copy resolves to A and passes, normalizes to `com-example`, then trusted-name substitution inserts B under that alias. **Inherited from `7f766889`; a regression relative to `v1.0.20`, predating P141.** Tests at `managed_mcp_p141_tests.rs:167/199` cover blocking and name collisions separately, not their combination.

Re-verification:

- **Key isolation:** no disclosure bypass found in the inspected ACP/project/plugin paths. Reference/value scrubbing remains at [key_naming.rs:541](/Volumes/Mando/WaylandBots/Fuigo/wt-p141/crates/codegen/fuigo-config/src/key_naming.rs:541) and after config expansion at [mcp.rs:491](/Volumes/Mando/WaylandBots/Fuigo/wt-p141/crates/codegen/fuigo-config-types/src/mcp.rs:491); OAuth settings remain definition-bound at `managed_mcp.rs:891`.
- **Copy marks cannot be ACP-forged:** [private entries, no deserializer, and plain-vector conversion assigning `None`](/Volumes/Mando/WaylandBots/Fuigo/wt-p141/crates/codegen/fuigo-shell/src/session/managed_mcp.rs:134).
- **Trusted user precedence and renamed/plugin-shadowing edit/delete behavior hold in the merge itself.** The actor ordering gap prevents an unconditional reload guarantee.

No newly introduced P141 regression found against either baseline. Required closure: adopt seed and server configuration together in the actor; check the final definition after trusted substitution. Add coverage for both counterexamples.

**DO-NOT-LAND**

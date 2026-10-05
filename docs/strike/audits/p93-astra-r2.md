# P93 Astra round 2 — final report (verbatim)

Model gpt-6-astra, read-only, on `e0145e0f..7d73127b`. Raw transcript: Hetzner `/root/fuigo-builds/p93/audits/p93-astra-r2.txt`.

Audited `e0145e0f..7d73127b` read-only. No cargo, builds, or tests run. **One MEDIUM defect remains in the retry fix.**

1. **MEDIUM — A registration after refusal can be consumed without rechecking trust.**  
   [app.rs:656](/Volumes/Mando/WaylandBots/Fuigo/wt-p93/crates/codegen/fuigo-shell/src/agent/app.rs:656)

   The trust check runs synchronously at line 643, but `borrow_and_update()` runs later, when the spawned local task first gets polled. It marks every notification received during that interval as seen.

   **Concrete scenario:** The leader refuses the relay. Before its waiting task first runs, the user adds the config opt-in and a headless client registers. The IPC server calls `send_replace(true)`. The waiting task then consumes that notification at line 656, retains `permitted = false`, and waits for another registration. The opted-in client hangs without starting the relay. This interleaving is possible because the IPC server runs independently, while leader startup performs synchronous config discovery and watcher setup after spawning the waiting task.

   **Tests:** Not caught. The [retry test:331](/Volumes/Mando/WaylandBots/Fuigo/wt-p93/crates/codegen/fuigo-shell/src/agent/p93_relay_opt_in_tests.rs:331) yields repeatedly before adding consent and sending the successful registration. It therefore tests an already-waiting receiver. Despite its comment, it also omits deferred-arm retry coverage.

   **Correction:** Establish the consumed demand generation before checking trust, so registrations arriving afterward remain pending. Add a deterministic regression: refuse, write the opt-in, send demand **before yielding**, then require the same leader to connect. Include the deferred-arm variant.

| Work item | Status | Progress / pending work |
|---|---|---|
| Overall execution goal | ✅ Done | Round-two source audit complete; one MEDIUM finding. |
| CLI endpoint override | ✅ Done | Both URL arguments now precede the gate and leader lookup. |
| Refused-leader retry | ⬜ Pending | Ordinary retries are wired correctly; the initial notification window remains. |
| Cold-mint fixture | ✅ Done | Own-process opt-in added; auth-reload and handle assertions retained. |
| Trust documentation | ✅ Done | Policy and guide acknowledge that an opted-in relay can modify subsequent opt-ins. |
| Bridge and origin audit | ✅ Done | No additional unauthorized-origin bridge or opt-in provenance bypass found. |

`send_replace(true)` correctly notifies on repeated registrations; I found no additional production demand consumer or retry-loop spin. Blank URLs still reach P47’s refusal before socket creation. Origin comparison separates schemes and effective ports, with the added IDN, IPv6, and userinfo cases consistent with the parser.

The negative gate tests contain assertions that would detect removal of their respective guards; positive-only tests are controls. These conclusions are from source inspection, not executed test or mutation results.

DO-NOT-LAND

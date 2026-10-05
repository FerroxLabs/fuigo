Reviewed `fc3ccb94..a675f2e2` read-only. No Cargo or native tests run. Two legacy-memory failures were confirmed with an in-memory model of the string operations; other findings follow from source tracing.

1. **HIGH — Reinjection hides valid legacy memory from subsequent invalidation.**  
   [memory_context.rs:112](/Volumes/Mando/WaylandBots/Fuigo/wt-p91/crates/codegen/fuigo-shell/src/session/helpers/memory_context.rs:112) detects only nonced blocks, while invalidation retains a legacy block whose sources remain current. On resume, `first_turn_memory_reminder` therefore searches again and upsert appends a nonced block. The legacy block is no longer at the system message’s end, so [the legacy matcher](/Volumes/Mando/WaylandBots/Fuigo/wt-p91/crates/codegen/fuigo-shell/src/session/helpers/memory_context.rs:201) stops checking it.

   **Scenario:** Legacy block references A; reinjection returns B. Delete or edit A while B remains current. A’s stale content remains in the system prompt indefinitely while B stays valid.

   **Existing tests:** Do not catch this. The legacy test stops after validation; the resume test creates its persisted block with the current nonced formatter.

2. **HIGH — Genuine pre-P91 blocks containing an opening-tag literal survive `--no-memory`.**  
   [memory_context.rs:204](/Volumes/Mando/WaylandBots/Fuigo/wt-p91/crates/codegen/fuigo-shell/src/session/helpers/memory_context.rs:204) rejects legacy recognition whenever the body contains another memory-context tag. The pre-P91 emitter inserted snippets verbatim, and its safety filter permitted opening tags.

   **Scenario:** A previously recalled snippet says `This project emits a <memory-context> element.` The resulting genuine legacy block fails recognition, even at the system message’s end. Resuming with memory disabled retains its facts without source validation.

   **Existing tests:** Do not catch this. `legacy_shapes_elsewhere_are_kept` explicitly expects retention of the nested-opening-tag shape, without testing that the old production emitter could generate it.

3. **HIGH — Structurally invalid provenance is silently discarded instead of making migration unproven.**  
   [storage.rs:1016](/Volumes/Mando/WaylandBots/Fuigo/wt-p91/crates/codegen/fuigo-memory/src/storage.rs:1016) parses provenance into unrestricted `serde_json::Value`. Records such as `{}`, `null`, or an object missing `workspace` are accepted and contribute no evidence.

   **Scenario:** A mixed legacy directory has a valid hostile-host creator header and victim notes whose provenance record has lost its `workspace` field. Migration ignores that malformed record and adopts the whole directory into the hostile host’s namespace. This violates the round-one requirement that an unparsable provenance item makes ownership unproven.

   **Existing tests:** Do not catch this. They cover oversized evidence and syntactically invalid JSON, but not valid JSON with an invalid provenance structure.

4. **MEDIUM — Index quarantine follows directory symlinks and can overwrite existing files.**  
   [storage.rs:1106](/Volumes/Mando/WaylandBots/Fuigo/wt-p91/crates/codegen/fuigo-memory/src/storage.rs:1106) uses a fixed `.pre-p91-index` directory without checking its type or containment, then renames files into it without collision protection.

   **Scenario:** `.pre-p91-index` already points to another workspace on the same filesystem. Migration moves `index.sqlite` through that link, replacing the other workspace’s database. An existing quarantine file can likewise be overwritten during a retry; `rename` permits replacement of an existing destination file. [Rust documentation](https://doc.rust-lang.org/std/fs/fn.rename.html)

   **Existing tests:** Do not catch this. The quarantine test starts with no quarantine directory and checks only filename selection and successful moves.

5. **MEDIUM — Concurrent migrations can permanently strand the legacy directory.**  
   [storage.rs:1107](/Volumes/Mando/WaylandBots/Fuigo/wt-p91/crates/codegen/fuigo-memory/src/storage.rs:1107) has no migration lock or coordination with destination initialization.

   **Scenario:** Two starters enumerate the same index. A moves it aside. B’s move fails with `NotFound`, so B returns from migration and initializes the new workspace directory. A’s final directory rename then fails because that destination is nonempty. Both sessions use fresh memory, and future starts skip migration because the destination exists. The original notes remain stranded under the legacy name.

   **Existing tests:** Do not catch this. Migration fixtures are sequential and do not interleave migration failure with production `ensure_initialized()`.

6. **MEDIUM — The new production-path R5 test can pass without exercising the server.**  
   [handle_tests.rs:5605](/Volumes/Mando/WaylandBots/Fuigo/wt-p91/crates/codegen/fuigo-workspace/src/handle_tests.rs:5605) discards the convergence result and asserts only that no agent IDs were recorded. Per-server startup failures are returned in `SessionMcpDelta.failed`, so the helper’s outer `expect` does not establish successful startup.

   **Scenario:** The `0.0.0.0` connection fails or goes through an unsuitable proxy. Zero requests reach the listener, yet the test passes. Its Unix-wide routing assumption is also unsafe: Darwin maps an unspecified destination to the primary local address, which does not guarantee reaching a listener bound specifically to `127.0.0.1`. This conclusion follows from [Apple’s XNU source](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/netinet/in_pcb.c). A name-only implementation can therefore survive this fixture failure.

   **Existing tests:** No assertion establishes `inits > 0`, successful server installation, or an empty failure list. The test is excluded on Windows.

Round-one verification: **#1** nearest-opening pairing, **#4** the 64-bit suffix, **#6** exact index-name selection, and **#7** the legacy slug are addressed in source with targeted tests. **#2** remains incomplete through finding 3. **#3** now fails closed on initial nonce-creation failure, but legacy handling retains findings 1–2. **#5** fixes the original publish-before-cleanup ordering, with findings 4–5 remaining. **#8** reaches production code but has finding 6.

M3’s fixture meaningfully bypasses index-time filtering and directly checks recall-time rejection. M4 now includes production HTTP coverage. The production first-party-plus-loopback predicate is present; no additional header-enforcement bypass was identified.

DO-NOT-LAND

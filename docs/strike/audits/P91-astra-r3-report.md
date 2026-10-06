Reviewed `fc3ccb94..c84b4c08` read-only. **Two HIGH and two MEDIUM findings remain.** No Cargo or native tests were run. Findings follow from production-path tracing; an in-memory string model also confirmed finding 2.

1. **HIGH — Pre-P91 compaction memory survives invalidation and `--no-memory`.**  
   [memory_context.rs:283](/Volumes/Mando/WaylandBots/Fuigo/wt-p91/crates/codegen/fuigo-shell/src/session/helpers/memory_context.rs:283)

   Legacy recognition runs only for `System` items. Synthetic user items pass through the nonce-only stripper. However, the pre-P91 compaction path inserted bare-tagged memory inside a synthetic system reminder: [compaction_context.rs:296](/Volumes/Mando/WaylandBots/Fuigo/wt-p91/crates/codegen/fuigo-shell/src/session/helpers/compaction_context.rs:296) → [compaction_utils.rs:1069](/Volumes/Mando/WaylandBots/Fuigo/wt-p91/crates/codegen/fuigo-chat-state/src/compaction_utils.rs:1069).

   **Scenario:** Compact before upgrading, then resume under P91 after deleting the recalled source—or with `--no-memory`. The persisted compaction reminder retains the recalled facts without validation. Removing the leading system message’s memory block does not remove this second copy.

   **Existing tests:** Do not catch it. `legacy_shapes_elsewhere_are_kept` explicitly asserts preservation of legacy memory in a synthetic reminder. The compaction-item removal test uses the new nonced formatter.

2. **HIGH — An old header inside a recalled snippet causes partial removal, leaving stale facts permanently unrecognizable.**  
   [memory_context.rs:208](/Volumes/Mando/WaylandBots/Fuigo/wt-p91/crates/codegen/fuigo-shell/src/session/helpers/memory_context.rs:208)

   The rightmost-opening search also accepts an opening/header sequence occurring **inside** the old block’s snippet:

   ```text
   Decision: deploy = retired-cluster
   Docs show:
   <memory-context>
   ## Relevant Memory from Past Sessions
   example
   ```

   This passes the old safety filter and fits beneath the snippet limit. On invalidation, the embedded opening becomes the removal boundary. Everything before it—including the deployment fact and original opening/source marker—survives. The final closing tag disappears, so subsequent invalidations cannot recognize the remainder. This occurs with memory disabled as well.

   **Existing tests:** Do not catch it. Despite its comment claiming coverage of a copied header, `legacy_tail_with_tag_literals_inside_is_still_recognised` uses `"not a header"` inside the snippet. The in-memory model confirmed both retained facts and failure of subsequent recognition.

3. **MEDIUM — An equivalent-URL starter can bypass the migration lock and strand legacy memory.**  
   [storage.rs:1063](/Volumes/Mando/WaylandBots/Fuigo/wt-p91/crates/codegen/fuigo-memory/src/storage.rs:1063)

   Lock acquisition happens only when the caller’s particular legacy directory exists. Origins ending in `widgets.git/` and `widgets.git` resolve to the same new directory but different legacy directories.

   **Scenario:** Only the `.git/` legacy directory exists. Starter A begins migrating it while holding the lock. Starter B uses the equivalent `.git` origin, finds its own legacy path absent, returns before locking, and initializes the shared destination. A’s directory rename then fails because that destination is nonempty. Future starts skip migration because the destination exists; the old notes remain stranded. The destination-directory restriction is documented by [Rust](https://doc.rust-lang.org/std/fs/fn.rename.html).

   **Existing tests:** Do not catch it. The concurrent test uses one origin and temporary workspaces. Those workspaces are classified as ephemeral, so `ensure_initialized()` skips the destination creation central to the original race. Consequently, that fixture does not reliably protect against reverting the lock either.

4. **MEDIUM — Migration does not coordinate with still-running pre-P91 sessions.**  
   [storage.rs:1138](/Volumes/Mando/WaylandBots/Fuigo/wt-p91/crates/codegen/fuigo-memory/src/storage.rs:1138)

   The new migration lock coordinates new migrators only. Existing pre-P91 actors retain the old storage paths and do not acquire it.

   **Scenario:** Keep an old session running while starting the upgraded binary. Migration moves its memory directory. A subsequent capture in the old session recreates the legacy directory and writes there, splitting future notes from the upgraded session’s memory. If an old search is active during migration, its database and sidecars can also be renamed while open—a documented [SQLite hazard](https://www.sqlite.org/howtocorrupt.html#unlinking_or_renaming_a_database_file_while_in_use). If an open-handle restriction instead makes migration fail, startup still initializes the destination, suppressing later migration retries.

   **Existing tests:** Do not catch it. Migration fixtures use closed dummy index files and cooperating new-code starters; none holds an old storage client or live SQLite connection across migration.

None of these scenarios requires an attacker to directly modify `~/.fuigo` or control the user’s system prompt.

| Work item | Status | Progress / pending work |
|---|---|---|
| Overall execution goal | ✅ Done | Read-only audit completed; no runtime qualification claimed. |
| Round 2 #1: legacy detection | ✅ Done | Recognized legacy tails now suppress reinjection. |
| Round 2 #2: opening literals | ⬜ Pending | Ordinary literals handled; embedded old headers retain finding 2. |
| Round 2 #3: provenance structure | ✅ Done | Invalid JSON and missing/non-string `workspace` reject adoption. |
| Round 2 #4: fresh quarantine | ✅ Done | Fresh `create_dir` addresses the reported pre-existing symlink/overwrite case. |
| Round 2 #5: migration serialization | ⬜ Pending | Same-legacy migrators serialize; findings 3–4 remain. |
| Round 2 #6: production HTTP test | ✅ Done | Linux-only fixture now requires `inits > 0`. |

The nearest-opening nonce matcher, suffix-preserving upsert, project-instruction exclusion, 64-bit remote suffix, exact index filenames, and corrected legacy slug are present. M3 directly exercises recall-time rejection; M4 exercises configured-header stripping through production HTTP. No additional first-party-plus-loopback enforcement bypass was identified.

DO-NOT-LAND

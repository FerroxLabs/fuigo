Reviewed `fc3ccb94..07884d8a`. No files changed; no Cargo or native tests run. Findings are from source tracing, with an in-memory string model confirming the truncation sequence.

1. **HIGH — An unmatched opening tag consumes a later legitimate block and intervening instructions.**  
   [fuigo-chat-state/src/types.rs:52](/Volumes/Mando/WaylandBots/Fuigo/wt-p91/crates/codegen/fuigo-chat-state/src/types.rs:52) pairs the first opening tag with the first subsequent closing tag, ignoring intervening openings. Starting with the existing `unclosed_own_tag_is_not_replaced_from` fixture, the first injection preserves `TAIL_CANARY`; a second injection deletes it. Invalidation likewise deletes everything between an echoed opening tag and a later legitimate block’s close when memory is disabled or stale.  
   **Existing tests:** Do not catch this. The unmatched-tag test stops after the first injection; the invalidation test contains no subsequent complete block.

2. **HIGH — Incomplete migration evidence can authorize cross-host adoption.**  
   [fuigo-memory/src/storage.rs:976](/Volumes/Mando/WaylandBots/Fuigo/wt-p91/crates/codegen/fuigo-memory/src/storage.rs:976) examines at most 512 session files; line 984 silently skips files larger than 1 MiB. Neither condition makes ownership unproven. For example, a legacy directory containing a victim’s oversized `MEMORY.md` and a small hostile-host capture can migrate into the hostile host’s directory: the victim header is skipped, the hostile capture proves ownership, and the entire directory moves. Conflicting provenance beyond the file limit produces the same problem.  
   **Existing tests:** Do not catch this. Mixed-provenance fixtures contain only small, fully scanned files.

3. **HIGH — Legacy resumed memory remains active despite deletion, scope changes, or `--no-memory`.**  
   [fuigo-shell/src/session/helpers/memory_context.rs:175](/Volumes/Mando/WaylandBots/Fuigo/wt-p91/crates/codegen/fuigo-shell/src/session/helpers/memory_context.rs:175) validates only the current installation nonce. Top-level resume preserves the existing system message, so pre-P91 blocks survive without source validation—even with memory disabled. These facts remain model-visible system content; they are not “inert text.” The per-process fallback at line 55 causes the same failure after restarting when nonce persistence fails.  
   **Existing tests:** Do not catch the lifecycle failure. `bare_memory_context_pair_is_not_ours_and_is_kept` explicitly asserts retention; the resume test generates its block using the current process’s formatter and nonce.

4. **HIGH — Host isolation still depends on only 32 hash bits.**  
   [fuigo-memory/src/storage.rs:832](/Volumes/Mando/WaylandBots/Fuigo/wt-p91/crates/codegen/fuigo-memory/src/storage.rs:832) retains only eight hexadecimal digits, and the slug contains no host. An attacker can retain the victim’s repository basename and vary subdomains under an owned domain until the prefix matches the victim’s public identity—approximately \(2^{32}\) candidate hashes for a targeted match. The resulting directory is identical, with no full-identity check before using existing memory. This retains an older weakness in the new R2 security boundary; it does not require shipping forged `.git` metadata.  
   **Existing tests:** Do not catch this. They compare a handful of ordinary hosts; no collision fixture or stored-identity validation exists. No collision search was run during this review.

5. **MEDIUM — Migration publishes the directory before finishing index deletion.**  
   [fuigo-memory/src/storage.rs:1054](/Volumes/Mando/WaylandBots/Fuigo/wt-p91/crates/codegen/fuigo-memory/src/storage.rs:1054) renames first, then deletes index files without coordination. Session A can pause after renaming; session B sees the destination, skips migration, and opens its index; A then deletes that live database or its journals. On POSIX this permits detached database handles and conflicting journal state, a documented [SQLite corruption scenario](https://www.sqlite.org/howtocorrupt.html#unlinking_or_renaming_a_database_file_while_in_use). Deletion failures are also discarded, relevant to Windows sharing restrictions.  
   **Existing tests:** Do not catch this. Migration tests are sequential and use a closed dummy index.

6. **MEDIUM — Index cleanup deletes unrelated Markdown and backups.**  
   [fuigo-memory/src/storage.rs:1065](/Volumes/Mando/WaylandBots/Fuigo/wt-p91/crates/codegen/fuigo-memory/src/storage.rs:1065) removes every file whose name starts with `index.sqlite`. A legitimate `index.sqlite-notes.md` or `index.sqlite.backup` is permanently deleted during migration. The cleanup needs an exact set of database and sidecar names.  
   **Existing tests:** Do not catch this. They seed only `index.sqlite` and assert its removal.

7. **MEDIUM — The trailing-slash fix-up computes the wrong legacy directory name.**  
   [fuigo-memory/src/storage.rs:855](/Volumes/Mando/WaylandBots/Fuigo/wt-p91/crates/codegen/fuigo-memory/src/storage.rs:855) uses the **new** slug for the legacy hash. For `https://github.com/acme/widgets.git/`, pre-P91 normalization produced `acme/widgets.git`, whose directory slug was `widgets-git`. Migration instead searches for `widgets-<legacy-hash>`. Existing memory is therefore missed, without the promised migration warning.  
   **Existing tests:** Do not catch this. URL-equivalence tests exercise fresh directories; migration fixtures use ordinary `.git` origins.

8. **MEDIUM — R5 tests would miss reverting the production enforcement.**  
   [fuigo-mcp/src/servers_p91_tests.rs:36](/Volumes/Mando/WaylandBots/Fuigo/wt-p91/crates/codegen/fuigo-mcp/src/servers_p91_tests.rs:36) tests the header helper directly, and the URL test likewise calls only the predicate. Replacing the production call at `servers.rs:5405` with its previous name-only implementation would leave these tests passing. The new workspace HTTP test uses loopback endpoints exclusively, so it would also pass that revert.  
   **Existing tests:** Cover configured-header stripping through production, but do not cover a designated first-party **non-loopback** server through `start_mcp_server`.

DO-NOT-LAND

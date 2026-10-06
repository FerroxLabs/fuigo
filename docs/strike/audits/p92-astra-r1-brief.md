# Astra round 1 brief — P92 (memory filter hardening), receipt R099

You are an independent read-only auditor. Do NOT build, compile or run anything. Audit the diff
`fc3ccb94..8735c062` in this worktree (branch `codex/fuigo-p92`). Commit 94c70e7f is a Codex build-lane WIP;
de4f99e6, e3845a00 and 8735c062 are a Claude gate's corrections. Files: `crates/codegen/fuigo-memory/src/{safety.rs,
storage.rs,index.rs,dream.rs,filter_tests.rs,filter_corpus.txt,lib.rs}`, `crates/codegen/fuigo-memory/Cargo.toml`,
`Cargo.lock`, `crates/codegen/fuigo-shell/src/session/acp_session_impl/memory_dream.rs`,
`crates/codegen/fuigo-shell/src/session/acp_session_tests/memory_config_tests.rs`,
`crates/codegen/fuigo-shell/src/session/memory/hooks.rs`. Ignore `P92-CODEX-NOTES.md`.

Background: audit findings R3/R4 in `/Volumes/Mando/WaylandBots/Fuigo/.ijfw/memory/codex-audit/238791e1-rest.md`.
R3: the memory admission filter (`is_safe_memory`) was a substring denylist, bypassed by rewording, doubled spaces,
zero-width characters, and missed GitHub/AWS tokens. R4: the filter ran on the whole resulting file at write time, so
one flagged line (even a false positive like "password: min 8 chars") made every later write fail, dropped the whole
file from the index, and made `/dream` report "no readable session content".

Claims to verify:
1. `is_safe_memory` normalises (NFKC; invisible/format characters both removed and read as a space; whitespace
   collapsed), folds (lowercase, ß→ss, combining marks dropped), matches an override family with word boundaries, a
   privileged imperative ("always run ... sudo"), any private-key armour header, a few legacy needles, and credentials
   via the shared `fuigo_secrets::redact_secrets` patterns plus a few extras. No new third-party crate.
2. Writes check only the NEW entry (`validate_entry`), not the assembled file. Every write path that persists memory
   text is covered.
3. `read_file` returns a filtered view: rejected lines become blank lines (line offsets kept, disk bytes unchanged);
   a private-key block is omitted from header to END; a payload split across lines omits its paragraph; across a
   paragraph break, both neighbouring paragraphs; otherwise the whole view is blanked. Index, recall revision hashes,
   search and embeddings all use that view; an all-blank view removes the file from the index.
4. Dream filters its model input but keeps original source snapshots and recovery bytes; `/dream` now shows the real
   skip reason (`DreamInputError::as_str`).
5. False positives on ordinary engineering text are low (corpus test over 193 lines).

Find defects: bypasses that still work against the stated goals; false positives on ordinary text; any path that now
persists, indexes, embeds or injects flagged content; any path where a flagged historical line still disables a whole
file; offset/range bugs in the filtered read; behaviour regressions vs fc3ccb94 (anything the old filter caught that
the new one admits); test gaps (a test that would still pass with the fix reverted); panics; performance traps.
Do NOT report the P91-owned regions (`storage.rs` ~816-895 workspace keying, `index.rs` `chunk_source_revision`).

For each finding: severity BLOCKER/HIGH/MEDIUM/LOW, file:line, a concrete scenario (exact input text), and whether
a test catches it. End with LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.

# P91 Astra round 3 — audit brief

You are an independent security reviewer. Read-only. Do not run cargo.
Repository: this worktree. Diff under review: `git diff fc3ccb94..HEAD` (branch `strike/p91`; commits 77248ca7 tests-first,
545f11ac fix, and any later fix-up commits).

Background (audit findings being fixed, from `.ijfw/memory/codex-audit/238791e1-rest.md`, not in this repo):
- R1: per-turn stale-memory invalidation (`fuigo-shell/src/session/helpers/memory_context.rs`, `invalidate_stale_memory_context`)
  deleted every `<memory-context>…</memory-context>` span and, on an unmatched open tag, dropped the REST of the item. It ran
  over the project-instructions item, whose layout is repo rules then the user's global `~/.fuigo/AGENTS.md` rules, so a repo
  AGENTS.md containing `<memory-context>` deleted the user's own rules, memory on or off. The chat-state upsert
  (`fuigo-chat-state/src/actor/request_builder.rs`, `upsert_memory_reminder_text`) also cut the system prompt at the first
  `<memory-context>`.
- R2: workspace memory directories were keyed by `org/repo` of the git origin, host dropped
  (`fuigo-memory/src/storage.rs`), so `https://evil.example/victimcorp/secret-app` shared memory with
  `git@github.com:victimcorp/secret-app`.
- R5: `X-Grok-Agent-ID` (bound session id) + local-agent posture (no proxy/redirect/OAuth) were granted by configured server
  NAME only (`fuigo-workspace/src/mcp.rs`, `fuigo-mcp/src/servers.rs`); no production caller populates the name list today.
- M3/M4: missing tests for the recall-time safety filter (`fuigo-memory/src/index.rs` `chunk_source_revision`) and for the
  unconditional strip of a config-supplied `X-Grok-Agent-ID`.

Claims of the fix:
1. Fuigo-inserted memory blocks carry a per-installation random nonce in both tags (`<memory-context nonce="N">` …
   `</memory-context nonce="N">`, N stored at `$FUIGO_HOME/.memory-context-nonce`, created only when a block is inserted).
   Invalidation, detection and upsert only touch complete blocks with that nonce; unmatched/bare/foreign-nonce tags are kept
   byte for byte; project-instruction items are not scanned. Recalled snippets/paths have memory-context tags escaped.
2. Repo rule text (`format_rules_section`, `format_agents_md_section`) neutralises memory-context tags.
3. Memory identity is `host/org/repo` (scheme, user info, port, `.git`, host case ignored). A legacy `org/repo` directory is
   renamed to the new name only if a workspace path recorded inside it (MEMORY.md header or capture provenance) still exists
   with exactly the same host/org/repo origin and no existing recorded path has another identity; otherwise it is left
   untouched and logged. The index inside a migrated directory is deleted (it holds absolute paths).
4. The agent-id header and local-agent posture require the first-party designation AND a loopback http(s) URL; any
   config-supplied agent-id header is stripped.
5. Known residual (stated, not fixed): a directory whose `.git/config` is attacker-supplied (e.g. an archive that ships
   `.git`) still chooses its identity.

Rounds 1 and 2 (docs/strike/audits/P91-astra-r1.txt, -r2.txt) were addressed by a675f2e2 and c84b4c08. Round 2 fixes:
#1 a pre-P91 tail block counts as present in `conversation_has_memory_context` (no reinjection after it);
#2 legacy recognition takes the RIGHTMOST bare opening tag that begins the old header with no bare close between it
   and the final close; opening-tag literals inside are allowed;
#3 every provenance record must be JSON with a string `workspace`, else evidence is incomplete;
#4 index files go into a FRESH `.pre-p91-index-<pid>-<nanos>` directory created with create_dir;
#5 migrations are serialised by `.memory-migrate.lock` in the memory root, with a re-check after locking;
#6 the 0.0.0.0 production-path test is Linux-only and asserts the server was reached.
Verify each fix, then look for anything new. Prefer concrete, reachable scenarios; say so explicitly when a finding
depends on an attacker already controlling files under ~/.fuigo or the user's own system prompt.

Find defects in the diff: correctness, security (bypasses of 1-4, new truncation/deletion paths, path/rename hazards in the
migration, TOCTOU, symlinks, races between concurrent sessions, Windows), behaviour regressions (resume, fork, compaction,
memory off, `--no-memory` writing files), and tests that do not exercise the production path or would not catch a revert.
For each finding: severity BLOCKER/HIGH/MEDIUM/LOW, file:line, concrete scenario, whether an existing test catches it.
End with one verdict line: LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.

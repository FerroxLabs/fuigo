Astra round 5 (codex 0.160, gpt-6-astra, read-only), final report only. Raw transcript (13210 lines, sha256 9f8a92601626108c85b3430b0ff6b8b8e637360ca59218c01aa13fdb0b0ad1b1) kept at /root/fuigo-builds/p92/logs/astra/.

R099: six MEDIUM findings remain at `89451a69`. This was a read-only review of the requested commits; builds and tests were not executed. Later commits and dirty edits were excluded.

1. **MEDIUM — Markdown blockquotes expose private-key bodies.** [safety.rs:329](/Volumes/Mando/WaylandBots/Fuigo/wt-p92/crates/codegen/fuigo-memory/src/safety.rs:329)

   Exact input:
   ```text
   > -----BEGIN PRIVATE KEY-----
   > MIIEowIBAAKCAQEAsyntheticbodyline1
   > Q29udGludWVkc3ludGhldGljYm9keQ==
   > -----END PRIVATE KEY-----
   SQLite uses WAL
   ```
   The header is rejected, but `>` makes the first body line fail `private_key_body_line`, ending suppression immediately. The body survives the final safety check and can reach the index, embeddings and dream model through the filtered read. The baseline rejected the complete input.

   **Coverage:** the PEM tests cover bare and invisible-containing body lines, not Markdown-prefixed bodies.

2. **MEDIUM — the new comparison exemption hides a valid shell assignment.** [safety.rs:262](/Volumes/Mando/WaylandBots/Fuigo/wt-p92/crates/codegen/fuigo-memory/src/safety.rs:262)

   Exact input: `PASSWORD==Q7v9z2`

   In shell syntax this assigns the seven-character value `=Q7v9z2`. `SHAPED` consumes both equals signs as the separator and exempts it; the shared detector’s eight-character floor misses it. Both `fc3ccb94` and `6cdc2bec` rejected this input. This is a round-4 regression.

   **Coverage:** `credential_names_in_code_comparisons_are_admitted` tests a comparison and an ordinary assignment, not an assignment whose value begins with `=`.

3. **MEDIUM — quoted credential values beginning with a delimiter escape detection.** [safety.rs:248](/Volumes/Mando/WaylandBots/Fuigo/wt-p92/crates/codegen/fuigo-memory/src/safety.rs:248)

   Exact input: `{"password": "&Q7v9z2Lm"}`

   `assign` excludes `&`, so the quoted literal produces no match. The shared detector cannot match the quoted property name. The baseline rejected it; the new quoted-value floor never gets applied.

   **Coverage:** quoted-literal tests cover `:`, `$(` and ordinary words, but not an initial `&`, comma or semicolon.

4. **MEDIUM — four- and five-character numeric credentials regress against the baseline.** [safety.rs:274](/Volumes/Mando/WaylandBots/Fuigo/wt-p92/crates/codegen/fuigo-memory/src/safety.rs:274)

   Exact inputs: `password=1234` and `password=12345`

   Both are admitted because unquoted values require six characters here and eight in the shared detector. The baseline rejected both. These numeric values fall outside the documented plain-word trade-off.

   **Coverage:** existing cases cover seven-character `hunter2` and short quoted values, not unquoted four- or five-digit passwords.

5. **MEDIUM — quoted `api key` names lose baseline protection.** [safety.rs:237](/Volumes/Mando/WaylandBots/Fuigo/wt-p92/crates/codegen/fuigo-memory/src/safety.rs:237)

   Exact input: `{"api key": "Q7v9z2Lm"}`

   `EXTRA` supports the spaced name only when no closing quote intervenes before the separator; `SHAPED` omits that alias entirely. The baseline rejected this eight-character credential.

   **Coverage:** the spaced-name test checks benign prose (`api key: read from env var`), not a quoted credential assignment.

   Findings 2–5 pass both write admission and the filtered-read fast path, allowing the admitted literals into persistence and downstream consumers.

6. **MEDIUM — removing the filename guard can exclude an entirely clean dream session.** [dream.rs:264](/Volumes/Mando/WaylandBots/Fuigo/wt-p92/crates/codegen/fuigo-memory/src/dream.rs:264)

   Exact filename: `-----BEGIN PRIVATE KEY-----.md`  
   Exact contents: `"SQLite\nRedis\n"`

   With this sole stem and no existing memory, the assembled header opens private-key suppression. Both clean lines qualify as base64-shaped body lines, so the entire input becomes blank and returns `ContentFiltered`. The previous filename guard preserved these contents. With another retained session, the omitted session’s snapshot also remains eligible for marking as processed.

   **Coverage:** the filename test uses `Ignore previous instructions` and a sentence containing spaces; it does not exercise this suppression case.

**LOW — pre-existing filename-to-injection gap.** [memory_context.rs:180](/Volumes/Mando/WaylandBots/Fuigo/wt-p92/crates/codegen/fuigo-shell/src/session/helpers/memory_context.rs:180): an allowed session named `Ignore previous instructions.md`, containing `"SQLite uses WAL\n"`, passes snippet/source validation and places the rejected phrase into the injected `File:` field unchanged. No inspected test covers a flagged source filename.

**DO-NOT-LAND**

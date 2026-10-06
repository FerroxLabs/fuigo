Astra round 4 (codex 0.160, gpt-6-astra, read-only), final report only. Raw transcript (19801 lines, sha256 a845b5cbc83296711b9035cd71ca8dea2f176a1943d9b144424a6e468b7ffa3a) kept at /root/fuigo-builds/p92/logs/astra/.

Static review of `6cdc2bec`; no builds, tests, or application code executed. Three MEDIUM findings remain.

1. **MEDIUM — PEM body suppression stops on an invisible character.** [safety.rs:314](/Volumes/Mando/WaylandBots/Fuigo/wt-p92/crates/codegen/fuigo-memory/src/safety.rs:314)

   Exact input, expressed as a Rust string:
   ```rust
   "-----BEGIN PRIVATE KEY-----\nMIIEowIBAAKCAQEA\u{200b}syntheticbodyline1\nQ29udGludWVkc3ludGhldGljYm9keQ==\n-----END PRIVATE KEY-----\nSQLite uses WAL\n"
   ```

   `private_key_body_line` checks raw bytes, so U+200B ends the block. Setting `floor = i` prevents rediscovering its header. Both body lines and the END line then survive: their isolated contents pass `is_safe_memory`. The filtered view can consequently reach the index, embeddings, retrieval and dream input with the key body intact. This is introduced by round 3.

   **Test coverage:** Not caught. Existing tests put invisibles in the header, while their body lines contain only ASCII base64 characters. Normalize body classification consistently with header detection.

2. **MEDIUM — Single-quoted literal passwords receive the shell-substitution exemption.** [safety.rs:259](/Volumes/Mando/WaylandBots/Fuigo/wt-p92/crates/codegen/fuigo-memory/src/safety.rs:259)

   Exact input:
   ```text
   PASSWORD='$(Q7v9z2Lm)'
   ```

   This shell assignment contains a literal password; single quotes prevent command substitution. Nevertheless, `quoted` describes the **name**, so `shell` becomes true. The shared detector also misses it because `mask_benign` replaces the value’s `$(` prefix with `ref `. Both normal and folded readings admit it, allowing persistence and downstream use. The original filter rejected it.

   **Test coverage:** Not caught. The round-3 test covers a quoted JSON name; the benign probe covers an actual unquoted command substitution. The exemption needs to distinguish literal value quoting.

3. **MEDIUM — Credential value predicates still regress against the original filter.** [safety.rs:268](/Volumes/Mando/WaylandBots/Fuigo/wt-p92/crates/codegen/fuigo-memory/src/safety.rs:268)

   Exact inputs, independently:
   ```text
   {"password": "letmein"}
   ```
   ```text
   Bearer AbCdEfGhIjKl
   ```

   `fc3ccb94` rejected both. At the tip, the seven-letter password fails the eight-character floor and the shorter-value “non-letter” condition. The twelve-letter bearer fails the digit requirement; the shared bearer detector requires sixteen characters. Both therefore pass admission and read filtering. These are literal credential regressions under criterion (b), rather than new instruction phrasings.

   **Test coverage:** Not caught. The existing regression test uses `hunter2` and a twelve-digit bearer, satisfying precisely the predicates these inputs avoid.

**DO-NOT-LAND**

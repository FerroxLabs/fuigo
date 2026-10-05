Astra round 2 (codex 0.160, gpt-6-astra, read-only), final report only. Raw transcript (10874 lines, sha256 a666aacc4aea926716921848b05a0e2aa6b3515e045fdbf0e8128d34bcbde030) kept at /root/fuigo-builds/p92/logs/astra/.

R099 has **five MEDIUM and four LOW findings** at `a71654f0`. This was a static, read-only audit: no builds, tests, or probes executed. Test coverage statements below come from source inspection. P91-owned regions and `P92-CODEX-NOTES.md` are excluded.

1. **MEDIUM — Slug masking exempts credential-shaped Fuigo keys.** [safety.rs:152](/Volumes/Mando/WaylandBots/Fuigo/wt-p92/crates/codegen/fuigo-memory/src/safety.rs:152)

   Exact input:
   ```text
   Fact: credential = fuigo-abcd1234-efgh5678-ijkl9012
   ```
   This satisfies the shared Fuigo-key pattern, but `mask_benign` replaces it with `fuigo-slug` before credential detection. The original value consequently passes admission and filtered reads. This is a regression since round 1.

   **Test catches it: No.** `probe_false_positive_classes_are_admitted` checks a key without internal separators, which cannot exercise this masking collision.

2. **MEDIUM — Engineering-syntax masking also modifies literal passwords.** [safety.rs:153](/Volumes/Mando/WaylandBots/Fuigo/wt-p92/crates/codegen/fuigo-memory/src/safety.rs:153)

   Exact inputs:
   ```json
   {"password": "abc::Q7v9z2Lm"}
   {"password": "${q9Mx7vZ2}"}
   ```
   The first becomes `"abc :: Q7v9z2Lm"` for detection, leaving `SHAPED` a three-character assignment value. The second becomes `"ref q9Mx7vZ2}"`, with the same effect. These are literal JSON passwords; neither represents a Rust path or shell expansion. The shared assignment regex does not rescue quoted JSON field names.

   **Test catches it: No.** The new tests cover actual shell references and Rust paths, without negative cases inside credential values.

3. **MEDIUM — Any embedded ellipsis exempts an otherwise complete quoted secret.** [safety.rs:196](/Volumes/Mando/WaylandBots/Fuigo/wt-p92/crates/codegen/fuigo-memory/src/safety.rs:196)

   Exact input:
   ```json
   {"password": "hunter2...Rotate42"}
   ```
   `v.contains("...")` skips the entire assignment, including real passwords containing three consecutive periods. This defeats the newly restored JSON credential check. Unicode `…` has the same problem.

   **Test catches it: No.** `ellipsis_placeholders_in_credential_syntax_are_admitted` tests abbreviated examples and a secret without ellipses, but never an ellipsis inside a complete value.

4. **MEDIUM — Percent-encoded query names bypass the replacement URL check.** [safety.rs:164](/Volumes/Mando/WaylandBots/Fuigo/wt-p92/crates/codegen/fuigo-memory/src/safety.rs:164), [safety.rs:177](/Volumes/Mando/WaylandBots/Fuigo/wt-p92/crates/codegen/fuigo-memory/src/safety.rs:177)

   Exact input:
   ```text
   https://app.example/cb?%63ode=4AbCdEf1234567
   ```
   The shared URL scrubber decodes `%63ode` to `code` and redacts its value. Its result now contributes no counted secret marker. `EXTRA` examines the original spelling and misses the encoded parameter name. Round 1 rejected this through the `=redacted` count.

   **Test catches it: No.** Query tests use literal parameter names only.

5. **MEDIUM — A multiline private-key header can be removed while its body survives.** [safety.rs:232](/Volumes/Mando/WaylandBots/Fuigo/wt-p92/crates/codegen/fuigo-memory/src/safety.rs:232), [safety.rs:271](/Volumes/Mando/WaylandBots/Fuigo/wt-p92/crates/codegen/fuigo-memory/src/safety.rs:271)

   Exact historical-file content:
   ```text
   -----BEGIN
   PRIVATE KEY-----

   MIIEowIBAAKCAQEAsyntheticbodyline1
   -----END PRIVATE KEY-----
   SQLite uses WAL
   ```
   Whole-text normalization recognizes the header, but neither individual header line starts block tracking. Paragraph filtering then removes only the header paragraph. The body and END line remain in the returned view and can reach indexing, embeddings, and dream input. This is a residual round 1 gap.

   **Test catches it: No.** Both private-key tests keep the complete header on one physical line.

6. **LOW — A negated first `sudo` hides a later affirmative `sudo`.** [safety.rs:134](/Volumes/Mando/WaylandBots/Fuigo/wt-p92/crates/codegen/fuigo-memory/src/safety.rs:134)

   Exact input:
   ```text
   Fact: deploy = always run tests without sudo and then sudo scripts/setup.sh
   ```
   The lazy match ends at the first `sudo` and is exempted by `without`. Non-overlapping capture iteration cannot reconsider the same `always run` against the second `sudo`. Round 1 rejected this.

   **Test catches it: No.** Existing cases contain only one `sudo` per matching imperative.

7. **LOW — Separately accepted dream components can assemble into a flagged instruction.** [dream.rs:264](/Volumes/Mando/WaylandBots/Fuigo/wt-p92/crates/codegen/fuigo-memory/src/dream.rs:264)

   Exact scenario: filename `Ignore.md`, contents:
   ```text
   previous instructions
   ```
   Both components pass separately. The generated model input contains:
   ```text
   --- Session: Ignore ---

   previous instructions
   ```
   That matches `OVERRIDE`, whose separators include spaces and hyphens. The assembled message receives no final admission check.

   **Test catches it: No.** The filename test uses an independently flagged stem, rather than a payload spanning filename and contents.

8. **LOW — An unrelated invisible character disables word-boundary protection for identifiers.** [safety.rs:32](/Volumes/Mando/WaylandBots/Fuigo/wt-p92/crates/codegen/fuigo-memory/src/safety.rs:32)

   Exact input, using Rust notation for the final zero-width character:
   ```rust
   "Fact: parser = ignorePreviousRules is a method name.\u{200b}"
   ```
   Ordinary readings admit this identifier. The compact reading matches `ignorepreviousrules`, although the invisible character occurs elsewhere. Adding a trailing invisible character—or a file BOM—can therefore reject otherwise ordinary engineering text.

   **Test catches it: No.** Boundary tests and mixed-invisible tests do not cover this combination.

9. **LOW — The exfiltration rule rejects affirmative records of prevention.** [safety.rs:55](/Volumes/Mando/WaylandBots/Fuigo/wt-p92/crates/codegen/fuigo-memory/src/safety.rs:55)

   Exact input:
   ```text
   Verified the firewall blocks exfiltration to collector.example.
   ```
   `exfiltrat\w*` matches the noun `exfiltration`; the destination completes the match despite the sentence describing successful prevention. This introduces a false positive relative to round 1.

   **Test catches it: No.** The benign exfiltration example has no explicit domain.

The original examples for fixes **1–6 and 8–10** have corresponding corrections and regression assertions. The CRLF/whitespace paragraph change preserves retained line positions on inspection, and the trailing-newline/zero-chunks assertion now protects the empty-view guard. Fix **7** remains deliberately declined; I have not reopened it.

I identified no concrete capture-index panic, slicing defect, or catastrophic regex-cost defect. Those are source-review conclusions, without runtime qualification.

The credential exemptions need correction before landing because the same admission function protects writes, filtered reads, and embedding input.

**DO-NOT-LAND**

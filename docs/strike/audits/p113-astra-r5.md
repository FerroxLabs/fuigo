# P113 Astra r5 final report (gpt-6-astra, read-only; raw transcript sha256 d6f835161c32acdd, kept outside the repo)

Audited `d9eb19dd..451ae5a8` at clean HEAD `cc0167a4`. Source inspection only; no builds, tests, or file changes. Finding 1 remains from r4; findings 2–4 are introduced regressions.

1. **HIGH — R4 #1 still leaks PEM bodies across actual session records.**  
   [feedback_archive.rs:420](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-shell/src/upload/feedback_archive.rs:420) clears `pem_open` on an intervening ordinary string. Put BEGIN, the complete base64 body, and END in three `agent_message_chunk` updates. The [stored envelope](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-shell/src/session/storage/mod.rs:844) contains `"method":"session/update"` before each payload. That 14-character value resets the state before the next body is visited, so the unrecorded private-key body leaves the archive intact.  
   **Coverage:** The [new cross-record fixture](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-shell/src/upload/feedback_archive.rs:937) uses single-property objects without session metadata.

2. **HIGH — Telemetry now preserves entire unterminated private keys.**  
   [sanitizer.rs:145](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-secrets/src/sanitizer.rs:145) removes only complete PEM blocks in telemetry mode. An unrecorded diagnostic containing BEGIN and a complete base64 private-key body, but missing END, now survives unchanged. [Sentry’s message scrub](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-telemetry/src/sentry.rs:219) consequently exports it. At `d9eb19dd`, the body was removed. Keeping the BEGIN marker has also kept the credential material.  
   **Coverage:** [sanitizer.rs:631](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-secrets/src/sanitizer.rs:631) replaces the former redaction assertion with a header-presence assertion; it never checks that the body is absent.

3. **HIGH — The new line anchor exposes torn PEM bodies followed by terminal formatting.**  
   [sanitizer.rs:35](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-secrets/src/sanitizer.rs:35) now requires the whole body line to match. For `BEGIN + "\n" + B + "\x1b[0m"`, where `B` is a complete, unwrapped, unrecorded private-key body and END is missing, the ANSI reset prevents that line from matching. Only BEGIN is removed; all of `B` remains recoverable. The previous regex removed `B` before the escape. This also reaches archived raw output: [Bash retains the output bytes](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-tools/src/implementations/fuigo_build/bash/mod.rs:2216), and [byte-array scrubbing uses this same detector](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-shell/src/upload/feedback_archive.rs:479).  
   **Coverage:** The [new fixture](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-shell/src/upload/feedback_archive.rs:952) covers indentation and a separate diagnostic line, not an ANSI suffix.

4. **MEDIUM — PEM state now erases unrelated ordinary JSON text.**  
   [feedback_archive.rs:412](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-shell/src/upload/feedback_archive.rs:412) treats any sufficiently long string containing only alphanumerics, whitespace, `+`, `/`, or `=` as body material. For:
   ```json
   ["-----BEGIN PRIVATE KEY-----\nQUJD\nrequest failed: timeout",
    "the token count is 12345678"]
   ```
   the second string becomes `[REDACTED_SECRET]`. The first string’s ordinary diagnostic ends the regex’s body match, but [line 430](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-shell/src/upload/feedback_archive.rs:430) still leaves the cross-string state open. Previously the second string survived.  
   **Coverage:** The [existing intervening-text fixture](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-shell/src/upload/feedback_archive.rs:873) uses `"kept"`, below the 16-character threshold.

Per-r4 dispositions:

- **#1 — NOT FIXED.** Simple arrays and single-property records are handled, but actual session envelopes reset the state: [feedback_archive.rs:420](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-shell/src/upload/feedback_archive.rs:420). See finding 1.
- **#2 — FIXED for the reported complete fragmented block.** Preliminary telemetry scrubbing retains BEGIN, allowing [Sentry’s joined check](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-telemetry/src/sentry.rs:112) to detect BEGIN/body/END. The new unterminated-block regression is finding 2.
- **#3 — FIXED.** [feedback_archive.rs:361](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-shell/src/upload/feedback_archive.rs:361) decodes complete parsed byte arrays regardless of physical newlines.
- **#4 — FIXED for the reported indented body.** [sanitizer.rs:35](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-secrets/src/sanitizer.rs:35) accepts spaces and tabs before body lines.
- **#5 — FIXED.** [feedback_archive.rs:385](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-shell/src/upload/feedback_archive.rs:385) selects unused suffixes for colliding shape-redacted property names, preserving their values.
- **#6 — FIXED for the reported diagnostic line.** The line anchor preserves `request failed: timeout` whole; the [updated assertion](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-secrets/src/sanitizer.rs:634) covers that case.
- **#7 — FIXED.** The [builder-only test](/Volumes/Mando/WaylandBots/Fuigo/wt-p113/crates/codegen/fuigo-shell-terminal/src/pty_session.rs:940) supplies a secret absent from the parent and exercises the production helper. Removing builder enumeration would fail its assertion. It remains Unix-gated; this is not native Windows qualification.

DO-NOT-LAND

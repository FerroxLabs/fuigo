# R-xs-p5b: peer audit log (packet 5 part B; S8.1-S8.4)

Branch `strike/xs-p5b`, base `d94f2cb1`. New module `fuigo-shell/src/session/peer_audit.rs` (+ `peer_audit_tests.rs`).

## Line format
File `<fuigo home>/peer-audit.jsonl` (0600; Windows: `fuigo_secrets::owner_only::restrict_to_owner`), one rotated file
`peer-audit.jsonl.1`. Every line has EXACTLY these 11 keys, always present, `null` when unknown (a test fails if a key is
added or missing):

    {"t":1800000000,"msg":"m-1","from_host":"0123456789abcdef0123456789abcdef","from_session":"sender-session","to_host":null,"to_session":"recv-session","mode":"acceptEdits","bytes":42,"outcome":"held","reason":"mode_mismatch","count":1}

- `t` unix seconds (for an aggregate line: the first event in the minute, not before the minute start).
- `outcome`: admitted, held, released, reheld, expired, rejected_by_operator, refused, saturated, duplicate, suppressed.
- `reason`: the serde name of the HoldReason / RejectReason, else null. `mode`: the sender's CLAIMED mode (null when only the key is at hand).
- `bytes`: body length only. `count`: 1, or the aggregate count. `to_host` is null until the transport packet gives the receiving process a host id.
- Never: body, any name or title, token, path, address string. Not hashed ids: ids are written RAW (random host id; session id is already a file name in the same home; the log exists to be matched against transcripts and the peer's log).
  Every string is restricted to `[A-Za-z0-9._:-]`, 64 chars; anything else (message id is peer text) becomes `sha256:<16 hex>`.

## Call sites (all in `session/peer_admission.rs`, inside the existing decision points; no decision changed)
`PeerAdmissionState::submit`: refuse (policy/flag/etc.) -> refused/saturated, same id different body -> refused/ambiguous,
repeat -> duplicate, over session bounds -> saturated, hold -> held+reason, admit -> admitted.
`release`: refused/unavailable, released. `reject`: rejected_by_operator. `Inner::sweep`: expired. `Inner::check_at_drain`:
expired, reheld+reason, refused+reason, refused/unavailable. `recheck_queued` (untracked row): refused/unavailable.
`untrack` (enqueue failed after an admit): refused/unavailable.
Other edits: `session/mod.rs` (module), `acp_session_impl/spawn.rs` (one line: `PeerAdmissionState::for_session(id)` names the receiver; `peer_admit.rs` is NOT touched).

## Bounds
- 8 MiB per file, rotate at cap minus 64 KiB headroom, one rotated file: total under 16 MiB.
- Rejections (refused/saturated/duplicate) of one (pair, outcome, reason): one line per minute with a count. Table capped at 256 keys; overflow counted into one `suppressed` line per minute. Individual events (admitted, held, ...) capped at 600/minute, overflow into the same `suppressed` line. Worst case about 860 lines/minute for the whole host.
- Queue to the writer: 1024, then dropped with a counter (`Sink::dropped`). Write errors counted (`Sink::write_errors`); ONE `tracing::warn` per 5 minutes with the error kind only. (`/peers` display of the counters is a later packet.)
- Writes never block the session: `AuditCtx::emit` is `try_send` only; the admission mutex is held only for that. One writer thread per home per process. Flag off: `emit` returns first; no thread, no directory, no file.
- Cross-process: `O_APPEND`, `O_NOFOLLOW`, one `write_all` per line; the handle is re-opened when the path's inode changed; rotation takes `fuigo_config::fs_atomic::lock_file_for_write(<home>/.peer-audit.lock)` and re-checks the size under it. `rename` replaces the old rotated file atomically.

## Verification
See the tip commit report for test totals. Canary test (`canary_and_exact_field_set_across_every_outcome`): admit, duplicate, hold, release, reheld, operator reject, expire, refuse, saturate with a marker in body and name, plus the real release tokens: zero hits in every file under the temp home; only `peer-audit*` / `.peer-audit*` files exist (the held store has no on-disk state).
Two-process test re-executes the test binary twice, 100 lines each, cap 64 KiB: 200 distinct lines survive, rotated once.

## Not verified / limits
- Windows owner-only ACL path (`restrict_to_owner`) is compiled-in but UNRUN. `O_NOFOLLOW` is unix only.
- The existing session-title log line is untouched (design section 7). No debug log is added by this code.
- The session-level canary (full actor) was not added; the canary runs at the admission-state level, where every call site lives.
- Part A may add new outcomes (rate limit, totals); they need one `audit_*` call each at their decision points.
- Receiving `to_host` is null (no host id exists in this tree). Rotation under a stalled lock holder: the lock helper gives up after its own wait and the line is dropped (counted).

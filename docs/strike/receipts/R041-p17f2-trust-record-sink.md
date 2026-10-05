# R041 — P17-F2: trust records at the base crate

Parent `bf8514ee`, tip: see the commit that adds this file (code tip `8253794a462644cc3117c0da98908d62fcca93bf`).
Toolchain digest (in-tree, 1.94.0): `b75985398e5509a90a7d5d68f8ec6690675f703c5cfa11893b04fc9c3fceca69`.

## Part 1 — choice: (a) sink trait in `fuigo-shell-base`
Chosen over (b) because it removes the defect rather than policing it: `set_trusted_api_origins` and
`TrustedOriginAuthority::publish` now enqueue the record themselves, so any caller anywhere gets it. No new
crate edge (`fuigo-shell-base` does not depend on `fuigo-telemetry`; the app injects `UnifiedLogTrustSink`
from `fuigo-shell/src/agent/config.rs`). Size: ~110 lines of production code, over the ~150 guide's spirit
but under it; the extra went to what Astra found (below).
Design: record queued under the trust-set write lock (queue order = mutation order); one drainer at a time
(try_lock + recheck), delivering outside every lock; pop only after delivery; unbounded queue until a sink
is installed (no loss); unchanged republishes not queued; sink panic is re-raised after releasing the drain
lock, record stays queued, `flush_trust_records()` redelivers (at-least-once); a refused sink is dropped
outside the state lock. Also closes Fable #16 (seed path unlogged) in the shell: the seed is now recorded.
Residual: records stay in memory until the app installs the sink; the shell's two Config paths do that
before the first write, and an app that never installs one gets only `tracing` (unchanged from before).

## Part 2 — Fable P17 LOWs (R013 + `strike-contracts/docs/strike/audits/fable-audit-20260930.md`)
| # | LOW | status |
|---|---|---|
| 15 | test not renamed; `install_test_trusted_origins` says OnceLock | already fixed in R013 §1.6; this packet also fixes the remaining stale "process-wide `OnceLock`" at `config_tests.rs:1562` |
| 16 | seed path unlogged; `test_settings_refresh.rs` cite | seed recorded via the sink (this packet); cite replaced in R013 |
| 6 (Astra LOW) | stale docs | R013 §1.6 |
| 17-20 | R008/R011/queue-plan receipts, commit-message timing | SKIPPED: not P17 files (contract/receipt docs owned by the coordinator) |
Other `OnceLock` hits in the tree describe real `OnceLock`s (`fuigo_home()`, rg path) and are correct.

## Evidence (rp.sh p17f2, Hetzner, `slot-run.sh`; log: `/root/fuigo-builds/p17f2.out`)
| run | pkg | exit | derived == headers | failures | log sha256 |
|---|---|---|---|---|---|
| parent bf8514ee | fuigo-shell-base | 0 | 4 == 4, 0 unfinished | 0 | 4ff36585b9dd66ccd4fddbd9d35a1414332693f5d5216abec9b95f424be45468 |
| parent bf8514ee | fuigo-shell | 0 | 38 == 38 | 0 | 716dfd94b8bcd000d7cca49ce32980ab2c9932c241c0cfdf57b9cb485b8c4e84 |
| tip 8253794a | fuigo-shell-base | 0 | 5 == 5 (+1 new binary) | 0 | 9ce96dd71946c605a76ed11ead4e844b15057ee2d2953e77c3b839da5b064855 |
| tip 8253794a | fuigo-shell | 0 | 38 == 38 | 0 | 40dd539ad49cb2421e045565153f3386a48a258cef3b5554b31412e9ba0cacb7 |
Tip failing set (empty) ⊆ parent failing set (empty). Isolation table: not needed, no tip-only failures.
Clippy `--all-targets` both pkgs: parent exit 0, 23 warnings; tip exit 0, 23 warnings; new: none.
Run completed 2026-10-01T08:43:39Z. Single full run per side (claim is about this packet, not suite stability);
baseline `2eb306e` control not run.

## Mutants (`/root/fuigo-builds/p17f2-mut.sh`, `/root/fuigo-builds/p17f2m.out`, tip `8253794a`)
Control: exit 0, 1 passed (sha256 6ef772c2…23f0). An earlier mutant run was INVALID: my test had an orphan-rule
compile error (E0117), so control and all mutants exited 101 with the same log; fixed in `8253794a`, rerun below.
| mutant | result |
|---|---|
| M1 publish does not enqueue | FAIL, replay count |
| M2 seed does not enqueue | FAIL, replay count |
| M3 pop before delivery | FAIL, panicked-record assertion |
| M4 unchanged republish queued | FAIL, "no record lost" count |
| M5 rejected sink dropped under state lock | FAIL, "installing a refused sink deadlocked: Timeout" |
| M6 sink panic swallowed | FAIL, panic-must-propagate assertion |

## Astra audit (`gpt-6-astra`, saved `docs/strike/audits/P17-F2-astra-r{1,2,3}.txt`)
r1 REQUEST CHANGES (3 HIGH: fixed 32-record buffer loss, ordering races, conditional install) -> queue redesign.
r2 REQUEST CHANGES (HIGH reject-drop under lock, MEDIUM panic strands queue, MEDIUM tests) -> fixed, tests added.
r3 final verdict, quoted: "VERDICT: PASS — source audit; no new defects found."
r1 HIGH #3 (install only via Config) is answered by the residual above, accepted in r2/r3 briefs.

## Not verified / proposals
- rustfmt: the new test is formatted; `util/mod.rs` is rustfmt-clean for the checked hunks.
- Baseline `2eb306e` not run. Integration moved to `ac7bfe92` after my base; not rebased.
- Proposal: an app-level bootstrap that installs the sink at process start for all three binaries, rather than from Config.

---
## Addendum (coordinator: no deferments) — sink installed at process start; rebased on `ac7bfe92`
Code tip `493fe1d896ed0158f1d5b400a69224373bcee479`, rebased onto `ac7bfe92ea6034f2d1efa348715e28d2d820dfd7`. The
tables above were taken at the pre-rebase base `bf8514ee`; THIS section is the gate of record.
The "proposal" in the previous section is implemented:
- `fuigo_shell::agent::config::install_trust_record_sink` is now `pub`; `fuigo-pager-bin`'s `main()` calls it right
  after `mark_process_start()`, before arg parsing and before any Config path. `fuigo-pager` is the only product
  binary with a `main` in this tree (the three modes, TUI/agent/headless, share it); the other `[[bin]]`s
  (`chat-history-downgrade`, `voice-probe`, workspace probes, benches) never write the trust set. The Config paths
  keep their calls as a backstop.
- New test `fuigo-shell/tests/trust_record_reaches_unified_log.rs`: a seed made before any sink or Config path
  reaches the redirected unified log as a `process baseline` record with `via: seed`, host only, no path.
- New test `fuigo-pager-bin` `trust_record_sink_wiring::main_installs_the_trust_record_sink_first` (source scan of
  `main()`: call present and ahead of `parse_cli` and `validate_requirements`).

Mutants (tip `493fe1d8`, `/root/fuigo-builds/p17f2-mut2.sh`, own target dir, deleted after): controls pass
(shell exit 0 sha256 ae82073d…b0a7; pager exit 0 sha256 8d700280…8700).
| mutant | result |
|---|---|
| N1 `install_trust_record_sink` installs nothing | FAIL (exit 101): the log is never created, so `snapshot_log().expect(..)` at test line 20 fails (the failure is "no log", not the baseline assertion) |
| N2 `main()` does not call it | FAIL (exit 101), "main() must install" |
| N3 `main()` calls it after `validate_requirements` | FAIL (exit 101), ordering assertion |

Astra on the new commit (`P17-F2-astra-r4.txt`): "No BLOCKER/HIGH/MEDIUM/LOW defects found." Final line quoted:
"VERDICT: PASS — source audit; build/runtime verification pending."

Gate (`/root/fuigo-builds/rp.sh p17f2rp ac7bfe92… strike/p17f2 /root/fuigo-builds/p17f2.bundle fuigo-shell-base
fuigo-shell fuigo-pager-bin`; log `/root/fuigo-builds/p17f2rp.out`; finished 2026-10-01T10:09:05Z; toolchain digest
`b75985398e5509a90a7d5d68f8ec6690675f703c5cfa11893b04fc9c3fceca69`):
| side | pkg | exit | derived == headers | failures | log sha256 |
|---|---|---|---|---|---|
| parent ac7bfe92 | fuigo-shell-base | 0 | 4 == 4 | 0 | aaf72b3cc4d44e490025a241c9755ce5d57902e7090a2414d2a8ab8ffe3b15b8 |
| parent ac7bfe92 | fuigo-shell | 0 | 38 == 38 | 0 | 37dc6659c2463034fb7f563429fa2209822fcadc195974af222be30fbc60997e |
| parent ac7bfe92 | fuigo-pager-bin | 0 | 5 == 5 | 0 | 9c72260b5e9dee61015cdc034fdecc753fba6b556183775ccce24cce1d92132e |
| tip 493fe1d8 | fuigo-shell-base | 0 | 5 == 5 | 0 | 874e4f04c5fb707fd05276458c1a852b4f0434c96fea6ba6948f4195859fe6b5 |
| tip 493fe1d8 | fuigo-shell | 0 | 39 == 39 (+1 test binary) | 0 | eaff9c699009eb94815746cd74081b680e46a7c4daccd99ccc44ab35999cf8dc |
| tip 493fe1d8 | fuigo-pager-bin | 0 | 5 == 5 | 0 | 620231249347fef01400ae9c52e1dcdb96f0c4fb1acb395c9e574f4642e8367f |
Tip failing sets (all empty) ⊆ parent failing sets (all empty); no isolation needed. Clippy `--all-targets`, three
packages: parent exit 0, 25 warnings; tip exit 0, 25; new: none. One run per side; baseline `2eb306e` control not run.
Not verified: end-to-end launch of the real binary writing to a real `$FUIGO_HOME` log (wiring is source-scanned, the
sink-to-log path is exercised by the shell integration test).

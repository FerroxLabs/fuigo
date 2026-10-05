# R049: P17-F3 gate abort, rp.sh/iso.sh, iso auto mode, survivors.txt, feature-gated targets

Branch `strike/p17f3`, parent `b6c7b4cee8b1258d10fade2375fcacba3e1c409b`, tip = the commit that contains this file.
No Rust changed: no product cargo gate was run (scripts and python only). Toolchain digest (read in-tree on the build box):
`rustc 1.94.0 (4a4ef493e 2026-03-02)`, `rustc -vV | sha256sum` = `b75985398e5509a90a7d5d68f8ec6690675f703c5cfa11893b04fc9c3fceca69`.

## STATUS (2026-10-03 02:50Z, after the coordinator's "one more round"): audited NO-HIGH + 0 MEDIUM, mutants re-run on the final tree, staged, NOT installed
Final code tip **`8ee19ba7`** (self-test and mutant harness only; the seven shipped scripts are byte-identical to `6744e5bb` and to the staged `.new` files). This receipt is committed on top (docs only).

**Not met / open (read this first)**
* The scripts are **staged, not installed** (coordinator installs; `rpb.sh` runs of p75g / p77g / p70gs / p70ga were live at 18:21Z). Commands below; nothing changed in them.
* **Two mutants survive, both justified** (not testable / equivalent): M20 and M31; details in the Mutants section. The mutant set ran on `cb2958b8`; the final tip `8ee19ba7` differs from it only by one self-test fixture (+1 assertion), and only M48, which that fixture is about, was re-run on `8ee19ba7`.
* Astra rounds 21-28: transcripts lost in the 16:18Z wipe (second-hand table only).

**Met (this round, coordinator items 1-5)**
1. R35 MEDIUM (`/nonexistent`) and LOW (`KEEP`) fixed (`c10b34e1`), then six more audit rounds on the self-test until **R42 `NO-HIGH`, 0 MEDIUM** (on `d47782c3`) **R43 `NO-HIGH`, 0 MEDIUM** (on `cb2958b8`) and **R44 `NO-HIGH`, 0 MEDIUM, 1 LOW** (on `8ee19ba7`, the final tip). **Shipped scripts byte-identical**: sha256 of `rp.sh iso.sh derive.py abort-lib.sh safe-kill.py gated-targets.py iso-resolve.py` at `8ee19ba7` = the staged table below (checked at every sync; `final-gate.sh`, `gate-lib.sh`, `gate-verify.sh` also unchanged since `89e593ed`).
2. **`mut.py` replaced by `scripts/strike/gate-mutants.py`** (in git), reviewed for kill-safety by Astra BEFORE it ran: review 1 `DO-NOT-RUN` (1 BLOCKER 7 HIGH 3 MEDIUM), 2 `DO-NOT-RUN` (1/2/4), 3 `DO-NOT-RUN` (0/0/1), **4 `SAFE-TO-RUN` (0/0/0, "no remaining cross-tenant kill path under the stated model")** on `bb21edad`; the harness is unchanged since (sha256 `5c302ff09889019301ab8e811842488919c42b1e93499b8d47e707ec4b0f8d41`). Its safety design is in its docstring (nonce per run, pre-launch check that nothing carries it, pidfd kills with post-open identity check, cgroup.kill only on scopes whose NAME carries the nonce, final-gate scopes never cgroup-killed, no pkill/pgrep/systemctl kill, receipts, own session, fail closed). The old `p17f3/mut.py` was renamed `mut.py.UNSAFE-host-wide-kills-DO-NOT-RUN` (mode 644).
3. **Mutants re-run on the final tree** (`cb2958b8`, 74 mutants between two unmutated controls, skip-e2e): **66 KILLED, 4 KILLED-OTHER (attributed below, all genuine), 4 survivors, both controls SURVIVED, 0 leaks**. Full mode for the 4 survivors: M29 KILLED; **M48 SURVIVED -> a real weakness of the large-environment fixture, fixed in `8ee19ba7`, then M48 killed** on `8ee19ba7`; M20 and M31 survive (justified). A scout run on `d47782c3` had found another real weakness (M19 survived): fixed in `cb2958b8`, then M19 KILLED. **Net: 72 of 74 killed; 2 justified survivors.**
4. **Full self-test on the final tip `8ee19ba7`: 395 passed, 0 failed, exit 0, stderr 0 B** (`/root/fuigo-builds/p17f3/bfin17.out`, sha256 `8fb4cae159a0eeda1b0b64cac1439eeda7b5520cc4934a7c7dd119ca0e8d64fa`, 02:1xZ, tree `tFinal3`; the new assertion is the +1). `cb2958b8`: 394/0 (`afin16.out`, sha256 `91a076d2d15508b62bd86831d31b9807c9abd41ffeaccee0a1105967420ce5ab`). Every intermediate tip in this round also 394/0 (table under Evidence).
5. Light on the box: `df -h /` before each launch (60-71 % used); one self-test or one mutant run at a time, never both; nothing under `slot-run.sh` (see Unverified for why); no cargo on the Mac.

## Staged on the build box, NOT installed (16:46Z; re-verified 2026-10-03 01:3xZ, unchanged)
All seven are byte-identical to `scripts/strike/` at `6744e5bb` and at the final tip `8ee19ba7` (no re-stage was needed), `root:root`, mode 755, in `/root/fuigo-builds/`:
| staged file | sha256 | replaces (live sha256 at 16:46Z) |
|---|---|---|
| `rp.sh.new` | `fc9f016db6713a105c0bb7efb962521a8a64abcbeb6e0cfe75ed74b97f37e4ba` | `rp.sh` `1c54303f7e3391553299243f778d486bbd5298213a6ff64c688d4b339952567e` |
| `iso.sh.new` | `0d2af06cade90b977f6a82ad2563e0e2ee47f562f7e4331556e18e27b954a5f6` | `iso.sh` `01bf31e0148896b86268b6359c9d87ccacb3438456904eea17e582f3c5f4a2e5` |
| `derive.py.new` | `e6d605c360278e28b5606b8a7815f8caaa90fa989851dc6267faa3485ae5ae00` | `derive.py` `d44681c017fd504e87f74f248e3723d2592c857704da492384637a2ad136fa5a` |
| `abort-lib.sh.new` | `306c885537fc3f296d6a1086d7c40e927e60b3d045913e754f0ad867a4002653` | `abort-lib.sh` (already identical) |
| `safe-kill.py.new` | `cbf56be0597ee378b611fbe75e3b097b02f999940d4c88186a8106fad11d6056` | `safe-kill.py` `18880988fdb74eca95d0f77d9deffde7dffd1ad243eea58d452d936968b3e829` (pre-`SAFE_KILL_VAR` copy from 13:33Z) |
| `gated-targets.py.new` | `8a42ee1d819de814b3af0fb1611faf77f023c07945b780626102e8a47bf987aa` | `gated-targets.py` (already identical) |
| `iso-resolve.py.new` | `f28fb84b7ed821d787d4fc0e9095d69d45cec5ef17367fa776cb471414c55fb0` | `iso-resolve.py` (already identical) |

The four helpers were placed under their real names by the earlier agent (new names, no live script reads them: checked with `grep -l` over `/root/fuigo-builds/*.sh`). `rp.sh.new`/`iso.sh.new`/`derive.py.new` did not change since 13:32Z; `safe-kill.py` did, so the copy sitting there is stale (functionally the same for rp.sh/iso.sh: the only difference is the `SAFE_KILL_VAR` knob the self-test uses). Live `rpb.sh` `d313361e...890b`, `rpf.sh` `20046c1f...a9c6`, `slot-run.sh`, `disk-guard.sh`: untouched by this packet.

**Install (coordinator; only when NO `rp.sh`/`rpb.sh`/`rpf.sh`/`iso.sh` run is live: `rpb.sh` and `rpf.sh` call `python3 $B/derive.py`, and the new `derive.py` de-duplicates executables and counts rlib/proc-macro doc-tests, so swapping it mid-run could make a parent and a tip count differ):**
```
ssh -o ControlPath=none hetzner-dsm
cd /root/fuigo-builds
ps -eo sid,etime,cmd | grep -E '(rpb|rpf|rp|iso)\.sh' | grep -v grep        # must print nothing
sha256sum -c - <<'SUMS'
fc9f016db6713a105c0bb7efb962521a8a64abcbeb6e0cfe75ed74b97f37e4ba  rp.sh.new
0d2af06cade90b977f6a82ad2563e0e2ee47f562f7e4331556e18e27b954a5f6  iso.sh.new
e6d605c360278e28b5606b8a7815f8caaa90fa989851dc6267faa3485ae5ae00  derive.py.new
306c885537fc3f296d6a1086d7c40e927e60b3d045913e754f0ad867a4002653  abort-lib.sh.new
cbf56be0597ee378b611fbe75e3b097b02f999940d4c88186a8106fad11d6056  safe-kill.py.new
8a42ee1d819de814b3af0fb1611faf77f023c07945b780626102e8a47bf987aa  gated-targets.py.new
f28fb84b7ed821d787d4fc0e9095d69d45cec5ef17367fa776cb471414c55fb0  iso-resolve.py.new
SUMS
cp -p derive.py derive.py.bak            # rp.sh.bak / iso.sh.bak already exist: KEEP them (the self-test's stale-binary case runs rp.sh.bak)
for f in abort-lib.sh safe-kill.py gated-targets.py iso-resolve.py derive.py iso.sh rp.sh; do mv $f.new $f; done   # helpers first, rp.sh last
sha256sum rp.sh iso.sh derive.py abort-lib.sh safe-kill.py gated-targets.py iso-resolve.py
```
Rollback: `cp -p rp.sh.bak rp.sh; cp -p iso.sh.bak iso.sh; cp -p derive.py.bak derive.py` (note `rp.sh.bak` is the pre-packet rp.sh WITHOUT the `. $B/disk-guard.sh` line the live one has). After install `rp.sh <lane> <parent> <tipref> <bundle> <pkgs>` with `FEAT=...` replaces `rpb.sh`/`rpf.sh`; retiring those two is the coordinator's call. The old lane-local `mut.py` (host-wide kills) is retired; use `scripts/strike/gate-mutants.py` (in git) for any future mutant run.

## Evidence that exists (each from a real run on the build box)
| What | Tree | Result |
|---|---|---|
| baseline `gate-selftest.sh` | `b6c7b4ce` | 124 passed, 0 failed, stderr 0 B |
| full `gate-selftest.sh` | `c846a607` | 368 passed, 0 failed, stderr 0 B |
| full `gate-selftest.sh` (`final1`) | `1357b030` (round-19 fixes) | **370 passed, 0 failed, stderr 0 B** (the last full run) |
| rp.sh feature-gated demo (`demo-gated.txt`) | `d00c44af` scripts | old rp.sh: tip `exit=0 failures=0` (regression invisible). new rp.sh: lists `--test gated [extra]`, second pass `--features gatedemo/extra`, `tip gatedemo+features exit=101 derived=1 hu=1 failures=1`, `only-tip: gated_regression` |

Self-test runs after `89e593ed` (all in `/root/fuigo-builds/p17f3/`, each a single run of the tree as synced at the time; stderr 0 B in every one). The commit of `ofin`..`rfin6` is inferred from start time vs commit time (the tree dir was overwritten by the next sync); `rfin7` and `sfin8` are verified by sha256.
| run | UTC | commit | result | `.out` sha256 |
|---|---|---|---|---|
| `ofin` | 13:56-14:04 | `fa06f9c5` (R27 fix) | 394 / 0 | `35c36c54...5d19` |
| `nfin` | 14:06-14:27 | `b73b10cb` (R28 fix) | 394 / 0 | `ad00b3ee...e24c` |
| `mfin` | 14:28-14:36 | `e5c1fca7` (R29 fix) | 394 / 0 | `91294a20...7289` |
| `rfin` | 14:38-14:45 | `af008cc5` (R30 fix) | **392 / 2** | `48ddb837...19aa` |
| `rfin2` | 14:47-14:57 | `004635e2` | 394 / 0 | `d17b380c...d2da` |
| `rfin3` | 15:02-15:19 | `2343c765` (R31 fix) | **394 / 2** | `8f87fafc...05ab` |
| `rfin4` | 15:20-15:30 | `83c91a94` | 394 / 0 | `509b49ee...4a4f` |
| `rfin5` | 15:36-15:48 | `c6efb340` (R32 fix) | **392 / 2** | `3589b315...947a` |
| `rfin6` | 15:48-15:58 | `e97f95f8` | 394 / 0 | `98a7b59c...0ce8` |
| `rfin7` | 16:02-16:17 | `e6b0cb39` (R33 fix) | 394 / 0 | `246a7eef...85ed` |
| `sfin8` | 16:37-16:45 | `6744e5bb` (R34 fix) | **394 / 0** | `58433c3e...b333` |

The three red runs are not flakes and were not re-run to green; each was a defect in that round's own self-test edit, fixed by the next commit:
* `rfin`: `gate_reap_scope recorded the 3 sleeps ... (got '0/4' wanted '3/4')` and `gate_kill_if_marked ... (got '3/3/0' wanted '3/3/2')`: three fixture-name patterns had not received the run tag. Fixed `004635e2`.
* `rfin3`: `ukill: unit '...' is older than this run, not signalled` (twice): `date -d ""` is midnight, so an empty activation timestamp was read as an old unit. Fixed `83c91a94`.
* `rfin5`: `no systemd scope of the run remains (got 'enumeration-failed' wanted '0')` (twice): `grep -c` exits 1 on a zero count and selected the failure branch. Fixed `e97f95f8`.

Self-test runs of the coordinator round (2026-10-02, all 394 passed / 0 failed / exit 0 / stderr 0 B; each one run of the tree as synced; tree commit verified by the sha256 of `gate-selftest.sh`):
| run | UTC | commit | `.out` sha256 |
|---|---|---|---|
| `tfin9` | 16:57-17:07 | `023b8213` (R35 fix + harness v1) | `22d4b074...904d` |
| `ufin10` | 17:14-17:27 | `a7a1df21` (R36 fix) | `5dd5ffb3...bcb` |
| `vfin11` | 17:33-17:43 | `ac733058` (R37 fix) | `97425bb4...f8` |
| `wfin12` | 17:45-17:53 | `bb21edad` (R38 fix) | `d7f49738...5f5b` |
| `xfin13` | 17:53-18:00 | `d43b3098` (R39 fix) | `7fe19059...3d38` |
| `yfin14` | 18:00-18:08 | `d08fa0eb` (R40 fix) | `65c70cc3...f331` |
| `zfin15` | 18:08-18:21 | `d47782c3` (R41 fix) | `247de5fd...72e6` |
| `afin16` | 19:42-19:49 | `cb2958b8` (M19 fixture fix) | `91a076d2...e5ab` |
| **`bfin17`** | **2026-10-03 02:1x** | **`8ee19ba7` (final; 395 passed)** | **`8fb4cae1...64fa`** |
After each: 0 `fuigo-*` scopes, 0 `rb-selftest-stale*` refs in the shared integration repo, no new `selftest-*` lane.

Abort demonstrations (`/root/fuigo-builds/p17f3/demo-*.txt`, real runs, old = `.bak`/`b6c7b4ce`, new = intermediate trees, not the final tip):
* **old rp.sh, abort by `kill -- -<pgid>`**: `sleep 7003` (the clippy build script) alive, `cargo-clippy` tree alive, lane lock `HELD-by-orphan`, target dir and worktree remain. This reproduces the P17-R leak.
* **new rp.sh, `pkill -s <sid>` / `kill -INT` / `kill -TERM`**: 0 sleeps, 0 processes in the session, no process naming the lane, lane lock free, 0 scopes, target dir and worktree removed, `.out` ends `ABORTED: cleaned up`. Setsid and env-cleared children (`sleep 7002`) die via their systemd scope.
* **old iso.sh, group kill**: `sleep 7001/7002` alive, lock held. **new iso.sh**: clean.
* **final-gate.sh, run phase, TERM / SIGKILL**: new: sleeps gone, cgroup gone, env marker carriers `[]`, 0 scopes, lock free, rc 143 / 137 with `watchdog.log: killed by watchdog`. **Old gate, SIGKILL: plain and setsid sleeps, the test binary and the cgroup all survive** (6 members), env-marker carriers listed.
* **survivors.txt** (`demo-surv.txt`): a test leaves `setsid sleep 7005`. Old gate: verdict says only `GATE_ORPHANS=1`, no file. New gate: `verdict.txt` lists `phase=run via=cgroup pid=.. ppid=1 sleep 7005`; `survivors.txt` has state, sid, start time, run marker, cwd, exe, cgroup path, full cmdline; gate exit 3 INADMISSIBLE.
* iso auto mode: resolved `--test t` from the log header, 3 runs `1 passed` (the legacy `--lib` finds 0 tests).

## What changed (all under `scripts/strike/`, plus the two Hetzner-only scripts' reviewed sources)
* `abort-lib.sh` (new): session-leader guard (python supervisor, signals forwarded, `PR_SET_PDEATHSIG`), `bg` = every command in its own systemd scope as a job, abort flag checked inside the scope (race-free launch gate), scope kills in two passes, evidence read from `cgroup.events`, fail-closed (97/98).
* `safe-kill.py`, `gate-lib.sh`: no pid or session number is trusted: kills are pidfd + start time + run marker; `gate_abort_run` (trap and SIGKILL watchdog), `gate_reap_marker`, `gate_reap_scope`, `gate_scopes_populated`, watchdog liveness by pid+start time, EXIT sweep that fails the gate (exit 3) and keeps the watchdog armed.
* `final-gate.sh`: own session, build/--list/run/git/cargo-metadata all scoped, watchdog, `survivors.txt` + summary in `verdict.txt` (also on build/list failure), feature-gated targets listed in header and verdict.
* `rp.sh`, `iso.sh`: `abort_guard`, `<lane>.sid`, `bg`, per-invocation abort flag, containment checks, CLI and `.out` format unchanged except the added feature-gated lines; `iso.sh` auto mode (`ISO_FROM_LOG`, `ISO_META`, `iso-resolve.py`), names with spaces via `ISO_NAMES_NEWLINE=1`, collision-free log stems, lock before truncating `.out`.
* `gated-targets.py`, `derive.py NODOC=1`: P60 request. Choice: a second pass with only the features the skipped targets declare (not all-features, which can enable exclusive features and rebuilds normal targets), own derived count, own header check, failset merged. `final-gate.sh` does not run them (A.2.1 counts the default set) but names them.
* `gate-selftest.sh`: 124 -> 370 assertions plus the feature-gated cases (untested as a full run, see STATUS). Switches `GATE_SELFTEST_SKIP_E2E`, `GATE_SELFTEST_FAILFAST` are for mutant runs only.
* R029: limit (h) now states the false-red half of Fable LOW #7 (`GATE: FAIL (cargo_exit=0 but failures: block non-empty)`, absent from the current tree as Fable found, workspace not re-audited). The `pend<0` text is corrected: the result-handler branch is an equivalent mutant (totals check subsumes it); the `pend<0` in `fin()` is load-bearing (mutant `doctest-trailing-unpaired-running-rejected` fails). Fable LOW (b): kill-retry accumulates over attempts (unit-tested with a fake).

## Mutants on the final tree (`cb2958b8`, harness `gate-mutants.py` sha256 `5c302ff0...8d41`)
Command (from `/root/fuigo-builds/p17f3`, tree `tFinal2` = rsync of `cb2958b8`, started by `chain-mut.sh` only after `afin16` was 394/0):
`setsid python3 tFinal2/scripts/strike/gate-mutants.py --work mutwork --out mutants-cb2958b8-skipe2e.txt tFinal2` (19:49Z-01:30Z).
Result `mutants-cb2958b8-skipe2e.txt` sha256 `78abcdf474a6cf869fd23cd87975ae6e87aaf01b2c1c6b64bf49c96ce5c88365`: `DONE (KILLED=66, KILLED-OTHER=4, SURVIVED=6)`, every line `leaked_after_cleanup=0`; both controls (opening, closing) SURVIVED 366/0. KILLED = the first FAIL line is the assertion that killed that mutant before (`EXPECT`); KILLED-OTHER = killed by a different first assertion, attributed by hand:
| mutant | first FAIL | attribution |
|---|---|---|
| M32 supervisor child keeps forwarding handlers | pre-exec SIGKILL case (`tiny2`): child did not die with the supervisor | genuine: with the forwarding handler inherited, the parent-death SIGTERM is swallowed in the fork->exec window. Was a justified survivor before; the R29 acknowledged-pre-exec handshake now detects it. |
| M39 iso auto guesses without metadata | structural pin `iso.sh auto mode refuses to guess without cargo metadata` | genuine: the pin checks exactly the text the mutant changes |
| M79 safe-kill lstrip of "SIG" | `skill: could not signal pid .. with INT (safe-kill exit 2): unknown signal INT` | genuine: same defect (INT becomes NT); `skill` now reaches it before the dedicated assertion |
| M83 safe-kill ignores SAFE_KILL_VAR | watchdog case: run still `active` | genuine: the self-test's `skill` (SAFE_KILL_VAR=FUIGO_SELFTEST_ID) can no longer signal its fixtures; production behaviour (default FUIGO_GATE_RUN) is unchanged by design |

Survivors in skip-e2e mode, then **full mode** (`--full M20 M29 M31 M48`, `mutants-cb2958b8-full.txt`):
| mutant | full mode on `cb2958b8` (`mutants-cb2958b8-full.txt`, sha256 `d51e3c58...8cf5`, both controls 394/0, 0 leaks) | then | justification |
|---|---|---|---|
| M29 gate trap without cleanup | **KILLED** (`[gate TERM mid-build] gate exits 143 and says it aborted`, got 3/1) | - | - |
| M48 marker read via `tr \| grep -m1` | SURVIVED | **fixture fixed (`8ee19ba7`): marker first in a fixed-order `env -i` environment, followed by 400 kB, with an assertion that pins the order. M48 on `8ee19ba7`: killed** (`mutants-final-M48-skipe2e.txt`, sha256 `4dd3f0e8...1934`, both controls SURVIVED, 0 leaks; reported KILLED-OTHER only because its EXPECT entry was the old e2e assertion; the first FAIL is `survivors: the run marker is recorded for a process with a very large environment`, the assertion written for exactly this defect) | - |
| M20 supervisor handlers installed after spawn | SURVIVED | - | masked by `PR_SET_PDEATHSIG` + the getppid check: a signal arriving between spawn and handler install has no observable different outcome; only a SIGKILL in a nanosecond window differs (not deterministically testable). Unchanged since R049's earlier mutant round. |
| M31 doc result without running (`pend<0` branch) | SURVIVED | - | equivalent mutant (R029): the totals check subsumes that branch |

Scout run on `d47782c3` (aborted by session after 23 runs to fix what it found; `mutants-d47782c3-skipe2e-ABORTED-scout.txt` sha256 `73528182...d6b`, `--cleanup-from` reported 0 leaks for all 23 nonces): **M19 (abort_guard without the SIGINT shim) SURVIVED**. Cause: the INT/HUP cases' precondition "signal ignored on entry" came from how the SUITE was launched (ignored under `setsid nohup ... &`, measured SigIgn 0x7; default under a terminal, `env -i`, `systemd-run`, or the harness, 0x4), so they were vacuous outside `nohup`. Fixed in `cb2958b8` (`trap '' INT HUP QUIT` in mini_case's launching subshell; audited R43 NO-HIGH 0 MEDIUM); on the final tree M19 and M22 are KILLED by the leader-INT case.

## Mutants, earlier runs (89e593ed and before; superseded by the section above)
Harness `mut.py` (M01..M82; one edit each to a script copy; reaps leaked fixtures by scope and exact command line between mutants and records `leaked_after_cleanup`; the first attempt was invalid because leaks contaminated later mutants). Two modes: skip-e2e (fast, `GATE_SELFTEST_SKIP_E2E=1`) and full (`MUT_FULL=1`); both `FAILFAST`. Results: `/root/fuigo-builds/p17f3/mutants-skipe2e.txt` (all 72), `mutants-full.txt`, `mutants-full2.txt`.
* skip-e2e: 61 killed (exit=1), 10 survived (71 ran then; M80-M82 added afterwards) (M01 control, M05, M20, M29, M31, M32, M36, M46, M48, M59). Full mode: M29 and M48 killed; M01 identity control passes (it is the same file).
* **Closed with new tests, then killed in full mode on the final tree**: M05 (zombie: fixture now verified to be state Z), M36 (fake `systemctl` says inactive while the cgroup is populated), M46 (reaper never signals an unmarked pid), M59 (launcher.id pin); new mutants M80 (no pager build), M81 (no `FUIGO_BINARY` pin) killed; **M82 (checkout guard) survived once (`mutants-full2.txt`), a pin on the guard condition was added (`89e593ed`), and it was then re-run and killed**: `mutants-m82.txt` (13:34Z, tree `tP`), `exit=1`, `344 passed, 1 failed`, FAIL line `rp.sh: a failed checkout (or HEAD != the requested revision) is fatal before anything is built`. (The earlier text of this receipt said it was not re-run; the result file shows it was.)
* **Survived, justified**: M31 equivalent (R029). **M20 and M32** (supervisor handlers installed after spawn / child keeps forwarding handlers): masked by `PR_SET_PDEATHSIG` plus the `getppid` check; every observable outcome of the spawn window is identical with and without them (M33, which removes the pdeathsig, is killed). They only matter for a SIGKILL landing between the getppid check and exec (nanoseconds): not deterministically testable.
* Result files (sha256): `mutants-final-skipe2e.txt` `a4d83b38...2c05` (71 lines: 61 `exit=1`, 10 `exit=0`), `mutants-full.txt` `0e26c9eb...b84f`, `mutants-full2.txt` `9d801931...0c3` (M05, M36, M46, M59, M80, M81 killed; M82 survived), `mutants-m82.txt` `345ae74b...1b13a` (M82 killed).
* **Provenance, from the result files' own headers:** the skip-e2e set (`mutants-final-skipe2e.txt` is byte-identical to `mutants-skipe2e.txt`) ran on tree `tX` from 02:41Z, when the skip-e2e self-test had 355 assertions, i.e. before the stale-binary work; `mutants-full.txt` on `tS` 09:36Z; `mutants-full2.txt` on `tR` 12:31Z; `mutants-m82.txt` on `tP` 13:34Z (`89e593ed`). Those tree dirs no longer exist, so the exact commit of the first three is not provable. **Nothing was re-run on `6744e5bb`** (see Unverified).
* M80/M81 were killed by structural pins that run before the e2e stale-binary case; that case itself was shown discriminating separately (above).

## Audit (Astra gpt-6-astra, read-only, `< /dev/null`)
`docs/strike/audits/p17f3-astra.txt` holds each round's final answer (rounds 1-20 and 29-44 verbatim, plus the four harness reviews; 21-28 as a second-hand table, their transcripts were lost in the wipe). Full transcripts of rounds 29-44: `docs/strike/audits/p17f3-astra-r<N>.raw.txt`; harness reviews: `p17f3-astra-mutants-review<N>.raw.txt`. Rounds 29-33 were run by the previous agents (codex 0.159.3); 34 and 35 by the resumed agent with the project-local codex 0.160 (`.tools/node_modules/.bin/codex`).

Rounds 1-18: HIGH-FOUND, every HIGH fixed (they covered: scope names lost in subshells, SIGINT ignored by backgrounded shells, supervisor races, containment failing open, recycled pids and session ids, launcher races, watchdog identity). Round 19 (`c846a607`): **VERDICT: NO-HIGH** (3 MEDIUM, 2 fixed). Round 20 (`1357b030`): **`VERDICT: NO-HIGH`**, 2 MEDIUM + 1 LOW remain, listed below.

| Round | Audited | Verdict | Findings | What was done |
|---|---|---|---|---|
| 21 | `d00c44af` (feature-gated targets) | HIGH-FOUND | gated-target discovery failure was silent | fixed `2715a326` |
| 22 | `2715a326` | NO-HIGH | mediums/low: metadata exit status, `[+features]` failset identity, safe-kill signal names | fixed `488795df` |
| 23 | `45fdd3de` (disk guard) | NO-HIGH | disk-guard failure not fatal; self-test counts | fixed `dc0886f8` |
| 24 | `0f9049e9`, `cd86ddb8` | HIGH-FOUND | `FUIGO_BINARY` inherited; `FEAT` broke the pager build | fixed `d66a6320` |
| 25 | `d66a6320` | HIGH-FOUND | a failed checkout re-proved the wrong revision | fixed `0cd9cefc` |
| 26 | `0cd9cefc` | NO-HIGH | 1 MEDIUM: `gated-targets.py` ignores dependency-enabled features | not fixed (limit) |
| 27 | `89e593ed` (inferred) | HIGH-FOUND | self-test signalled fixtures without an identity check; zombie handshake | fixed `fa06f9c5` |
| 28 | `fa06f9c5` (inferred) | HIGH-FOUND | HIGH self-test could kill unmarked processes selected by name; MEDIUM pre-exec SIGKILL test could pass vacuously | fixed `b73b10cb` |
| 29 | `fa06f9c5..b73b10cb` | HIGH-FOUND | 2 HIGH (numeric `kill`/`pkill -s` after an earlier environ check; `gatedemo5-helper` scope cleanup hit every run's scope), 1 MEDIUM (handshake) | fixed `e5c1fca7` (pidfd + `FUIGO_SELFTEST_ID` `skill`, `SAFE_KILL_VAR`) |
| 30 | `b73b10cb..e5c1fca7` | HIGH-FOUND | 2 HIGH (unverified pid/group/session signals; cross-run scope cleanup), 3 MEDIUM, 2 LOW | fixed `af008cc5`, `004635e2`; LOW synthetic pids 4001/4002 and `kill -0` probes accepted |
| 31 | `e5c1fca7..004635e2` | HIGH-FOUND | 1 HIGH (two `systemctl kill` on pid-derived unit names), 3 MEDIUM, 2 LOW | fixed `2343c765`, `83c91a94` |
| 32 | `004635e2..83c91a94` | HIGH-FOUND | 1 HIGH (pid-only unit names on indirect signal paths: rec2/flg/flg2), 2 MEDIUM, 2 LOW carried | fixed `c6efb340`, `e97f95f8` |
| 33 | `83c91a94..e97f95f8` | HIGH-FOUND | 1 HIGH (`fuigo-gate-ln/flag/none-$$` reach `gate_abort_run` SIGKILLs), 2 MEDIUM (`ukill` empty timestamp; `selftest-isolock-$$`), 1 LOW | fixed `e6b0cb39` |
| **34** | `e97f95f8..e6b0cb39` | **NO-HIGH** | MEDIUM `selftest-stale-<label>-$$-$RANDOM` lane + open-glob cleanup; MEDIUM `/nonexistent-dir/...` negative-write fixtures; LOW fixed `nounit.scope` placeholder | all three verified real and fixed in `6744e5bb` |
| **35** | `e6b0cb39..6744e5bb` | **NO-HIGH** | confirms the three R34 fixes; MEDIUM (pre-existing) host-global `/nonexistent` in 8 negative fixtures; LOW `KEEP=<dir>` reuse is not run-unique | **not fixed** (limits below; proposal) |
| 36 | `6744e5bb..023b8213` | NO-HIGH | 8 MEDIUM (unbounded nonce, relative/regex-special KEEP, not-a-repo fixture inside a checkout, inherited ISO_*/ABORT_* and git config, unpinned rp.sh.bak) + 3 LOW | fixed `cf5e93e6` |
| 37 | `023b8213..a7a1df21` | NO-HIGH | 6 MEDIUM (GIT_CONFIG_COUNT, NODOC, CARGO_BUILD_TARGET, shared integration repo, last-pid session check, CDPATH) | fixed `06aa25e2` (whitelist + `env -i` re-exec); shared-repo use itself downgraded to LOW in R38 under the byte-identical constraint |
| 38 | `a7a1df21..ac733058` | NO-HIGH | 2 MEDIUM (ref cleanup unchecked; planted-survivor 300 s wait then lane deleted under a live gate) | fixed `dd356a1b` |
| 39 | `ac733058..bb21edad` | NO-HIGH | 1 MEDIUM ($W deleted under a still-running gate) | fixed `d43b3098` |
| 40 | `bb21edad..d43b3098` | NO-HIGH | 1 MEDIUM (retention armed too late under FAILFAST) | fixed `d08fa0eb` |
| 41 | `d43b3098..d08fa0eb` | NO-HIGH | 1 MEDIUM (abort cases shared ga.out/ga.rc) | fixed `d47782c3` |
| **42** | `d08fa0eb..d47782c3` | **NO-HIGH, 0 MEDIUM** | - | - |
| **43** | `d47782c3..cb2958b8` (M19 fix) | **NO-HIGH, 0 MEDIUM** | confirms the signal analysis; no other case depends on the suite's launch context | - |
| **44** | `cb2958b8..8ee19ba7` (M48 fixture) | **NO-HIGH, 0 MEDIUM** | LOW: the 64 KiB pipe-capacity premise is platform-specific (64 KiB pages would hide M48 again) | accepted (x86_64 4 KiB pages on the build box) |
| harness 1-4 | `gate-mutants.py` at `023b8213`, `a7a1df21`, `ac733058`, `bb21edad` | DO-NOT-RUN x3, then **SAFE-TO-RUN** (0/0/0) | review 1: mutated kill code as root, nonce substring matches, poisoned runs/ scopes, name-based deletion, labels, parent session, fail-open inspection, unbounded waits; review 2: `p.kill()` on a possibly auto-reaped pid, pre-existing nonce identity, infrastructure errors as KILLED, scope not an acceptance condition; review 3: `lexists` hides EIO | fixed `a7a1df21`, `ac733058`, `bb21edad` |

Rounds 27-35 concern only the self-test harness (`gate-selftest.sh`, plus the `SAFE_KILL_VAR` line in `safe-kill.py`): the shipped `rp.sh`, `iso.sh`, `derive.py`, `abort-lib.sh`, `gated-targets.py`, `iso-resolve.py`, `final-gate.sh`, `gate-lib.sh`, `gate-verify.sh` are byte-identical from `89e593ed` to `6744e5bb`. The last round that audited those is R26 (`0cd9cefc`); the three test-only commits after it (`8b1e6f75`, `338843a5`, `89e593ed`: self-test only) were, as far as the surviving record shows, what R27 looked at.

## Known limits (not fixed)
* `gated-targets.py` considers each package's own default features only; a dev-dependency of another selected package can enable a gated target, so the gate may list a target as "NOT run" that cargo did run (over-reports; Astra R26 MEDIUM).
* `aux.units` read through `cat` failing after `-r` succeeded fails open in `gate_scopes_populated`/`gate_abort_run` (Astra R20 MEDIUM).
* `survivors.txt` summary says "were killed" even when a survivor outlived SIGKILL; the gate is INADMISSIBLE regardless (R20 MEDIUM).
* The structural pin on the survivor-report failure checks a dead condition (R20 LOW).
* Survivor description can name a pid-reused process (kill is identity-checked) (R19 MEDIUM, accepted).
* Exact old-vs-new parity of the deployed scripts rests on my reading plus the demos; the originals are not in git.

## Known limits added by rounds 27-43 (self-test only, accepted LOWs)
* Exported shell functions are not caught by the environment whitelist (only variables); a caller would have to pre-sanitize everything else (R38 LOW).
* A host-wide cargo `[build] target` would move `target/debug` (rp.sh assumes it too) (R38 LOW).
* The stale-binary case runs the real old and new `rp.sh`, which fetch into the shared `/root/fuigo-builds/integration/src-p15r` by design (the self-test deletes and verifies its own `rb-<lane>` refs); it depends on the deployed `rp.sh.bak` (pinned by sha256 `28299238...d53b`) and `slot-run.sh` (R38 LOW under the byte-identical constraint).
* `kill -0` liveness probes are identity-blind (accepted since R30). The synthetic-pid LOW is closed (pids above PID_MAX_LIMIT).
* `gate-mutants.py`: not a sandbox. Mutants run as root like the self-test; its threat model assumes co-tenants do not forge its nonce.

## Unverified
* Self-test and mutants were run from a tree (`p17f3/tFinal2`), not with the scripts in their installed location.
* Only M48 was re-run on the final tip `8ee19ba7`; the other 73 mutant results are from `cb2958b8`, which differs only by that one fixture and its new assertion (`git diff cb2958b8 8ee19ba7`: 1 file, +6 -2).
* The self-test is not run through `slot-run.sh` (it asserts on its own session/scope layout); its own cargo use is three tiny fixture workspaces, and its end-to-end gates take slots through the real `final-gate.sh` -> `slot-run.sh`.
* Rounds 21-28: no transcript; verdicts are the previous agents' own record.
* `derive.py.new` vs the live `/root/fuigo-builds/derive.py` were not compared on real `--message-format=json` output.
* Exact old-vs-new output parity of `rp.sh`/`iso.sh` rests on the earlier demos; the deployed originals are not in git.
* Left on the box from runs before names were run-unique (not ours to guess at; 140 K): `/root/fuigo-builds/selftest-abort-2690586-19503`, `selftest-isolock-2916357` (+ `.out`), `selftest-surv-3305693-509`.

## Proposals
* Install the staged scripts between runs (commands above), then run `bash scripts/strike/gate-selftest.sh /root/fuigo-builds` once from a checkout against the installed files.
* Retire `rpb.sh`/`rpf.sh` after the install (rp.sh honours `FEAT=` and builds the pager fresh per side).
* Remove the three stale `selftest-*` leftovers listed above; delete `p17f3/t*` tree copies and `p17f3/src` when the coordinator has what it needs.

## Restack s28 (2026-10-03)
* New base: `strike/integration` e3139a996d1b4df22a0f54e5f58314a42351bd86; branch `strike/p17f3-s28`, 63 commits rebased from `strike/p17f3` (020070cb, old base b6c7b4ce) with no conflicts. Tip before the transcript-removal commit: `33d40418bd1b3b4c1fb5a773b140a108ab9bfdce`; the tip is the commit that adds this section.
* Files merged by hand: none. Integration changed only one file in this packet's scripts since b6c7b4ce, `scripts/strike/final-gate.sh` (adds `export CARGO_NET_OFFLINE=true` to the `--network none` inner command); git merged it automatically and the line is present in the rebased file (`bash -n` ok). No other scripts/strike or docs/strike file of this packet was touched by integration.
* Raw Astra transcripts removed (`p17f3-astra-r29..r43`, `p17f3-astra-mutants-review1..4`); kept `p17f3-astra.txt` (per-round final answers), `p17f3-astra-r44.raw.txt` (final round) and this receipt. No `*-brief.md` exists for P17-F3. Branch diff vs integration: 72351 insertions before, 4462 after (`git diff --shortstat`); the removed files stay in branch history and on the build box. This section refers to the removed files only by name.
* Installed scripts: sha256 of all seven (rp.sh, iso.sh, derive.py, abort-lib.sh, safe-kill.py, gated-targets.py, iso-resolve.py) in `scripts/strike/` equal the live `/root/fuigo-builds/<name>`; no mismatch (the `.new` staging copies are gone, the installs have happened).
* Self-test from the rebased tree on the build box (`/root/fuigo-builds/p17l`, lane clone of integration plus a git bundle, bundle sha256 `bfdae02b...b144`): `env RUST_MIN_STACK=16777216 RG_BIN_PATH=/usr/bin/rg CARGO_TERM_COLOR=never CARGO_BUILD_JOBS=16 nice -n 10 bash scripts/strike/gate-selftest.sh /root/fuigo-builds`, **395 passed, 0 failed, exit 0, stderr 0 B**, log sha256 `60829227eeafdd4b18009b2709617fcf09478a3e64d0d09a7f33fe07c60a3cb0`, 09:12Z to 09:23Z, tested tree `984bfc7e` (the transcript-removal commit; scripts identical to the rebased scripts). Same count as the old base.

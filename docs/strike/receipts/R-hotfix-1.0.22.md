# R-hotfix-1.0.22 — the 1.0.21 release plus P188 and P192

Branch `strike/hotfix-1.0.22`, created from the 1.0.21 release commit
`123b6e51059b22f06eff85debd8f6db124861bc3` (`strike/rc4-1.0.21`: de6ca7dd plus the 1.0.21 version bump). It holds
ONLY P188 and P192; every other 1.0.22 packet goes to 1.0.23. The version bump and final gate are the coordinator's.

## Ports

| Commit | Source | Range ported | Excluded |
|---|---|---|---|
| `bf8e16489` | P188 (`strike/p188`, code `dbdef6cdc`) | `git diff 6221893ca..dbdef6cdc` | `docs/strike/audits/*`, `docs/strike/receipts/*` |
| `e40a8ce47` | P192 (`strike/p192`, code `42e7312a2`) | `git diff 6221893ca..42e7312a2` | `docs/strike/audits/*`, `docs/strike/receipts/*` |
| `671a4d878` | P192 Grok r2 HIGH (`strike/p192`) | `git diff 42e7312a2..9d1263ac2` | same |
| `4c43d9b7d`, `c80e6a211` | P192 Grok r3 LOW (cherry-picks of `strike/p192` `842bb9800`, `131b76d58`) | test, then fix | — |

`dbdef6cdc` is P188 after the Grok 4.7 follow-up on `strike/p188` (two r3 pin tests + the LOW goal-summary stream-id
claim; see R188 "Grok 4.7 review follow-up").

## Conflicts

**None.** Both diffs were applied with `git apply -3` onto the hotfix; every hunk applied (no conflict markers, no
hand edits), and the staged diff has the same `git patch-id --stable` as the source range
(P188 `a1340939c152…`, P192 `557a78e920cf…`, P192 r2 `fa901d69fa83…`; the r3 LOW commits cherry-picked
without conflict), so the port is byte-identical to each packet's code.

Files that other 1.0.22 packets also changed between `123b6e510` and `6221893ca` (hunks landed at an offset; the
other packets' lines there were NOT pulled in, 1.0.21's stay):

| File | Packet hunks | Other packets' change there (left out) |
|---|---|---|
| `fuigo-pager/src/headless.rs` | P188: 13 | folder-trust grant report (`report_cli_trust_grant`) |
| `fuigo-shell/src/agent/mvp_agent/acp_agent.rs` | P188: 1 (capability key) | P172 session-sweep move |
| `fuigo-shell/src/session/acp_session.rs` | P188: 2 (field, test module) | P164/P172/P178 test modules and fields |
| `fuigo-shell/src/session/acp_session_impl/updates.rs` | P188: 3 | `last_reasoning_signature` (other packet) |
| `fuigo-shell/src/session/persistence.rs` | P188: 3 (merge guard, drain before retry_state) | P164/P172/P178 sweep, rewind reconcile |
| `fuigo-shell/src/session/storage/mod.rs` | P188: 8 (rebuild cut, tests) | P164/P172 replay changes |
| `Cargo.lock` | P192: 1 (`url` in fuigo-config deps) | kanal removal, version 1.0.20 line |
| `fuigo-shell/src/agent/config.rs`, `config_tests.rs` | P192 | other packets' config changes |

Minimal pieces from other packets: **none needed**. Both packets compile and pass on 1.0.21 as they are (gates below).
P192 also carries its user-guide page (`fuigo-shell/docs/user-guide/02-authentication.md`), which ships in the binary
with the code; it is not an audit or receipt.

## Gates (Hetzner, slot-run; never on the Mac)
All judged by rp.sh / slot-run on the build box; `.out` sha256 first 16 hex.

- **P188 focus on `strike/p188` `dbdef6cdc`** (lane `hf1022-p188`): x3 green (sampler 1, shell 14, pager 8, wire 1);
  3 hand mutants KILLED (see R188). `focus.out` `2fd01db0c2cc0c83`.
- **Hotfix tip `c80e6a211` (final code)**, lane `hf1022-hf`, tests under `unshare -n` (`hf4.out` `dc04032aa4d96b8b`):
  P192 x3: fuigo-config `p192_` 12 passed, sampler prewarm 1, fuigo-shell `p192_` + native-resolver + auth_error_no_retry
  55 passed, each run 0 failed; P188 x1: sampler 1, shell 14, pager 8, wire 1 passed. Earlier tips: `bf8e16489` P188
  x3 green; `e40a8ce47` and `671a4d878` P192 x3 green (`hf2.out` `ef768fcf486753e7`).
- **Grok r3 LOW** (lane `hf1022-p192l`, `low.out` `5e52be416cd830d8`): green 12; four mutants (one per removed key)
  KILLED, each by its own test.
- **rp.sh two-sided vs `123b6e510`, tipref `strike/hotfix-1.0.22`** (only-tip empty, clippy new 0, DONE on every lane):
  - `hf1022-rph` fuigo-shell `--features test-support,config-docs` at `c80e6a211`: tip derived 67/67 0 failures,
    +features 5/5 0 failures; only-parent: two parent-side flakes (`refresh_token_is_not_replayed_across_a_cross_origin_redirect`,
    `p47_wire_remote_settings`; both passed at the parent in lanes `hf1022-rpa`/`hf1022-rpc`). `3ad6d9c1bf98e066`.
  - `hf1022-rpg` fuigo-config, fuigo-extra-ca at `c80e6a211`: 0 failures both sides. `0a949eec043dfbfb`.
  - `hf1022-rpd` fuigo-config, fuigo-config-types, fuigo-extra-ca, fuigo-sampler, fuigo-http, fuigo-telemetry,
    fuigo-pager, fuigo-pager-bin, fuigo-pager-minimal, fuigo-update at `e40a8ce47` (the r2/r3 commits touch only
    fuigo-config code and fuigo-config/fuigo-shell tests, re-gated above). `5c65f19e552d9a04`.
  - Earlier: `hf1022-rpa` shell at `bf8e16489` `c45644b67c9cfb58`; `hf1022-rpb` 8 pkgs at `bf8e16489`
    `8ba0b21581c5db8c`; `hf1022-rpc` shell at `e40a8ce47` `2c0ade7656e141ed`. All pass.
- **P192 ACP repro** (`/root/fuigo-builds/hf1022-repro/p192/`) against `fuigo-pager` built at `c80e6a211`
  (sha256 `47a35b5da53ff4cf`), `--network none`, VARIANTS=ABCDM: xAI and ChatGPT, no "refuses to contact upstream
  vendor host", every turn on the subscription transport (summaries `3f38212032197a6f`, `d861f429de3a9c94`).
  Capture: 10 of 10 vendor inference POSTs carry the subscription bearer; FLUX_KEY_TO_VENDOR_HOST 0 (`verdict.txt`
  `48480435430176a5`).
- **P188 ACP repro** (`/root/fuigo-builds/hf1022-repro/p188/`, for MurageMobile): 1.0.21 FAIL (reply three times),
  hotfix `bf8e16489` PASS (two discards, client view = accepted reply only).
- Not run here: the final gate and version bump (coordinator step), live ChatGPT/xAI accounts.

## Release-note lines (1.0.22 hotfix)
- F (P188): A model reply that failed mid-stream and was resent no longer shows twice (or three times): every client
  is told to discard the dead attempt (`retry_state` `discardEmitted`/`streamStartMs`, capability `retryDiscard`), the
  TUI and `fuigo -p` drop it, and a ChatGPT `response.completed` with empty `output` keeps the streamed reply.
- F/S (P192): see R192 on `strike/p192` and `docs/release-notes-1.0.22.md` F2-F4, S1.

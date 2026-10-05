# R013 — P17-R: trusted-origin changes are recorded soundly; a failed config read keeps file state and applies fresh remote settings

Author: Claude Opus 5.5 (`claude-opus-5-5`), who took over P17-R from the coordinator after
the 2026-09-30 audits. Branch `strike/p17r`: gated as v1 `634232a4`, v2 `60fd50c2`, v3 `922f5d3e` on integration
`f89618ef`; now v1 `0d8d2d5e`, v2 `14bf7b46`, v3 `65830d38` on `14cab7e7` (see below). **Not merged anywhere.**

History of this packet on the branch. v1 was the coordinator's draft (`05157d8b`). v2
(`adbf192e`, on `8e11724`) answered the Astra and Fable audits of v1. v3 answers Astra's audit
of v2, which found three defects, all verified by the coordinator. The branch was rebased twice
as integration moved (`8e11724` → `8b4b8f40` → `f89618ef`), with no conflicts and no file
overlap either time. The pre-rebase SHAs are kept below only where a run was taken at them.

**Base moved after the gate — read this first.** The gate in §3 ran on `922f5d3e` (parent
`f89618ef`), which is pinned as branch `p17r-v3-gated-922f5d3e`. At 2026-09-30T23:43:40Z,
after that gate finished, `strike/p17r` was rebased onto integration `14cab7e7` (P09-v2/v3
landed). The reflog records it as `rebase (finish) … onto 14cab7e7`; it was not done by this
session. The three code commits are patch-identical: `git range-diff f89618ef..922f5d3e
14cab7e7..65830d38` shows `=` for all three (`0d8d2d5e`, `14bf7b46`, `65830d38`). But the base
now carries 40 more files, including P09 session and compaction code in `fuigo-shell`. **The
current tip is therefore not gated.** §3's evidence applies to the same patches on
`f89618ef`. A re-proof against `14cab7e7` (focused tests + mutants + `fuigo-shell` suite with
parent `14cab7e7`) is needed before this lands.

Sean's decision is preserved throughout. The trust set follows a legitimate reload, with no
intersection against a startup baseline and no prompt, and the control is detection. v1 claimed
detection it did not deliver; v2 made the claim nearly true; v3 closes the two gaps Astra found.

## 1. What changed and why

### 1.1 Records never carry an endpoint string (Astra v1 #1, HIGH)

What `TrustedApiOrigins::new` stores: Astra was right, and the "the P17 value type rejects
userinfo" claim was wrong. `new` only trims and drops blanks. Userinfo is rejected at MATCH
time, and only by the strict matcher. So `https://user:secret@host/v1?key=...` is stored
verbatim, and v1 logged it verbatim. Since v2, no record contains any entry text.

### 1.2 The record is what each matcher ADMITS (Astra v2 #1, HIGH; v3)

v2 recorded `scheme://host[:port]` for every entry, ignoring userinfo. But the set is consulted
through **two** matchers that admit different things:

- `matches_configured_origin` is the strict, credential-bearing tier behind
  `is_fuigo_api_bearer_url`, `is_trusted_fuigo_https_url` and `is_configured_api_origin`. It
  **refuses** a trusted entry that carries userinfo.
- `host_matches_configured_origin` is the scheme-agnostic tier behind `is_fuigo_api_url`. It
  does **not** refuse userinfo; it compares hosts only.

So under v2, `https://u:p@gw/v1` → `https://gw/v1` gave the strict tier a new origin (nothing →
`https://gw`), yet it compared `Unchanged`, was logged at debug, and wrote no unified-log
record. The reverse edit was a silent narrowing.

v3 records `RecordedTrust { origins, hosts }`, each mirroring one matcher exactly:
- `origins` holds one `scheme://host[:port]` per entry that parses, has a host and carries no
  userinfo. The host is normalized as the matcher sees it (case, IDN, trailing root dot), and a
  scheme-default port is omitted. `Url::port()` is `None` exactly when the port is the scheme
  default, so the rendering is equal iff the matcher's key is.
- `hosts` holds one normalized host per entry that parses and has a host, userinfo or not.

An entry that admits nothing in a tier is absent from that tier, and entry text never appears.
Comparison is on both tiers. The userinfo→plain edit is now `Changed` with `is_widening()`,
and a path-only edit is `Unchanged`. `is_widening()` means "some URL is newly admitted by
either matcher".

The new test `the_trust_record_agrees_with_the_matchers` asserts, for a userinfo entry, an
unparseable entry and a valid one, and for five probe URLs, that `is_fuigo_api_bearer_url` and
`is_configured_api_origin` agree with `origins` and `is_fuigo_api_url` agrees with `hosts`. The
new test `dropping_userinfo_from_an_endpoint_is_a_recorded_widening` pins the audit's case in
both directions.

I took the two-tier record rather than the coordinator's suggestion to drop userinfo entries
entirely, because the suggestion assumed a userinfo entry trusts nothing. It does trust
something: `is_fuigo_api_url` still admits its host. That predicate also feeds
`endpoint_is_first_party`, which grants a session bearer (see the `host_matches_configured_origin`
doc). Dropping the entry would have hidden a real host-tier change.

### 1.3 Every write is recorded, and the record survives default filters (Astra v1 #5, Fable #16)

*Seed path.* `set_trusted_api_origins` returns `Option<TrustSetChange>` and emits the same
event as `publish`. In production `new_from_toml_cfg` seeds BEFORE `resolve_runtime_fields`
claims the authority, so the seed is usually the write that installs the process baseline.
v1's "published for the first time" line typically never fired. Mutant C, which leaves the seed
unrecorded, confirmed this: the integration test found no baseline record at all.

*What default filters keep.* Checked per subscriber. tracing-subscriber 0.3.23 (`Cargo.lock`)
matches directive targets by `starts_with` (`filter/env/directive.rs:246`), so
`fuigo_shell=info` also covers `fuigo_shell_base`.

| mode | subscriber / default filter | `info` baseline | `warn` movement |
|---|---|---|---|
| TUI | in-app log view: `WARN` default plus `fuigo_shell=info` | shown in memory, not persisted | shown in memory, not persisted |
| agent (`fuigo agent`, ACP) | stderr, `error` unless `RUST_LOG` | no | no |
| headless (`fuigo -p`) | stderr, `off` unless `RUST_LOG` (`fuigo-pager-bin/src/main.rs` `init_tracing_simple`) | no | no |
| any, with `FUIGO_DEBUG_LOG` / `FUIGO_LOG_FILE` | file firehose, `fuigo_shell=debug` | yes | yes |

With tracing alone, a default agent or headless user keeps nothing, so the config layer also
writes to the unified log (`$FUIGO_HOME/logs/unified.jsonl`). That log is always on in every
mode and has no level filter. It records the process baseline at `info` and every movement at
`warn`; unchanged republishes are not written. The `tracing` levels are: baseline `info`,
unchanged `debug`, any movement `warn`. Narrowing is also `warn` because a refused credential is
how the silent-401 presents.

*What a default user sees:* nothing on screen in agent or headless mode, and a movement in the
TUI's in-app log. In every mode, `unified.jsonl` gets one baseline line per process and one line
per movement. Comparing successive baselines shows an edit made between sessions.

*Limits:* the unified log is capped (`MAX_SIZE`, 5 MB) and trimmed oldest-first. A write that
fails is dropped. Whoever can rewrite `config.toml` can usually rewrite the log too. This is
detection, not prevention, and it is not tamper-evident.

*Where the persistent write lives:* `record_trust_change` in `fuigo-shell/src/agent/config.rs`.
The only two non-test callers of either write path are in that file (verified with `git grep`),
and `fuigo-shell-base` has no `fuigo-telemetry` edge.

### 1.4 The failed-read path (Astra v1 #2, #3; Fable #7, #8; Astra v2 #2, MEDIUM; v3)

v1 skipped `re_resolve_runtime_fields` on a load error. That left remote-derived fields stale
(managed MCPs, subagent limits, memory, storage mode) against the remote settings
`refresh_remote_settings` had just stored.

v2 retained the raw table last resolved against and replayed it. Astra found the flaw: that
table is `load_effective_config()`'s output, which already has that moment's **remote campaign
patches merged in as TOML**. TOML outranks remote settings, so a campaign that fresh settings
withdrew came back.

v3 retains the **disk layers** instead, with no raw table on `Config`.
`util::config::load_effective_config()` is the one choke point every binary uses at startup
(`fuigo-pager-bin/src/main.rs`, `fuigo-pager/src/acp/mod.rs`, `fuigo-pager/src/headless.rs`),
and the refresh path uses it too. It now remembers the `ConfigLayers` it read successfully
(`last_good_config_layers()`), so the fallback exists from startup. On a failed read,
`agent_ops::reapply_config_after_settings_refresh` recomputes the effective table from those
layers **under the current remote settings** (`effective_config_for_remote_settings`, which
takes the remote campaigns from `cfg.remote_settings` and falls back to the process cache only
when there are no settings, mirroring `set_remote_campaigns_from_settings`). It then
re-resolves:
- file-derived fields, the trust set included, keep their last-known-good values;
- remote-derived fields, remote campaign patches included, follow the fresh settings;
- with no last-good layers, it skips.

The retained layers are process-global. That is correct for "the last successful read of the
disk in this process", and the helper takes them as a parameter, so tests inject their own.

Limit: dismissed campaign ids are re-read from `campaigns_state.json`, and that read fails
open to empty. If it also fails in the same window, a dismissed campaign could re-apply until
the next successful read. The same limit applies to the normal read path.

*`sync_campaign_fields` (Fable #8):* deliberately unchanged, and the code comment now says so.
On a failed read it clears only the campaign-driven FLAG and recovery value
(`CampaignField::reset`), never the value itself. That is its own tested fail-closed rule
(`campaign_field_reset_clears_driven_state`), it is shared with `store_remote_settings`, and it
does not touch the trust set.

*Other empty-table fallback:* `MvpAgent::with_models` does `load_effective_config().ok()` with
an empty-table fallback. It feeds only worktree type, restore code and the session-registry
override, so it is out of scope. It does now also refresh the last-good layers on success,
which is harmless.

### 1.5 The empty / absent / truncated file (Astra #3): a proven gap, out of packet, proposed

Findings:
1. `fuigo-config/src/loader.rs` `read_toml_file` returns `Ok(empty table)` for blank content and
   for `NotFound`. This is byte-identical at `2eb306e`, `8e11724` and `05157d8b` (sha256 prefix of
   lines 12–32: `ba6bfeb46515e6c5` at all three).
2. Most writers are atomic: `persist::update_config` and `atomic_write_string`, the MCP writers
   and `fs_atomic::write_atomically` all use temp file + rename. But eight production writers in
   `fuigo-shell/src/config/mod.rs` rewrite `~/.fuigo/config.toml` with plain `std::fs::write`,
   which truncates and then writes: `add_plugin_path`, `remove_plugin_path`,
   `add_disabled_plugin`, `remove_disabled_plugin`, `add_dismissed_plugin_cta_to_file`,
   `add_enabled_plugin`, `remove_enabled_plugin`, `remove_hooks_path_from_file`. Seven match the
   one-line pattern at all three revisions and the eighth is multi-line. None of them takes
   `lock_config_for_write`. A reader racing one of them sees an empty file (→ `Ok(empty)`) or a
   line-truncated file. A truncated file that still parses is also `Ok` and silently drops
   everything after the cut, including `[endpoints]` if it comes last. External editors that
   save in place have the same shape.
3. An empty or absent file IS a legitimate user choice: deleting `config.toml` or emptying it is
   how a user resets to defaults. Under Sean's rule the trust set must follow that reset.
   Nothing at the reader can tell "emptied on purpose" from "caught mid-rewrite" by content.

Conclusion: not fixable soundly inside this packet's surface. The sound fix is at the writers,
plus possibly a stable-read check in the loader, which changes every config load in the product.

Honest attribution: the *file-reset* behaviour is pre-existing at the release baseline
`2eb306e`. The *trust-set consequence* is not. At `2eb306e` the trust set was frozen at first
load (`publish_trusted_api_origins` absent: 0 occurrences of `self.publish_trusted_api_origins();`
at `2eb306e`, 1 at `8e11724`), so an empty-file reload could not move it. That consequence
arrived with P17 (`92417f4b`, in `8e11724`'s ancestry), by the same route as the `Err` hazard v1
fixed. Relative to P17-R's parent it is pre-existing; relative to the release it came with P17.
`an_empty_reload_table_discards_the_configured_trust_set` now pins this residual explicitly.

**Packet proposal P17-F1: atomic `config.toml` writers.** Convert the eight writers above to
`persist::atomic_write_string` under `fs_atomic::lock_config_for_write` (read-modify-write
inside the lock), with a test per writer that a concurrent reader never observes an empty or
partial file. Optional second half, separately gated: in `read_toml_file`, when the USER layer
reads blank, re-stat and re-read once after a short delay and accept blank only if stable. That
narrows the editor window without refusing a deliberate reset. Owner: config subsystem. Risk:
low for the writers, product-wide for the loader half.

**Packet proposal P17-F2: trust records at the base crate.** If a third caller of
`set_trusted_api_origins` or `TrustedOriginAuthority::publish` ever appears outside
`agent/config.rs`, it would emit `tracing` but not the unified-log record. Either move the
persistent write into `fuigo-shell-base` (needs a `fuigo-telemetry` edge, or a sink trait
injected at startup) or add a test that enumerates callers. Low priority; no such caller exists
today.

### 1.6 Stale and false statements (Fable #2, #6, #15, #16; Astra #6)

| statement | where | now |
|---|---|---|
| caller-side coverage "asserted in `agent_ops`" | `config_tests.rs` | removed; points at the real caller tests in `mvp_agent/tests.rs` |
| `trusted_origins_reload_republishes.rs` | `config.rs` doc | removed; names the two real files |
| `nothing_after_the_config_layer_can_widen_the_trust_set` | renamed test file | renamed `parsing_a_config_or_seeding_after_startup_cannot_move_the_trust_set` |
| `install_test_trusted_origins`: "process-wide `OnceLock` where the first write wins" | `config.rs` | "`RwLock<Option<..>>`, seed is first-write-wins" |
| `tests/test_settings_refresh.rs` (nonexistent, pre-existing) | `re_resolve_runtime_fields` doc | replaced with the real coverage |
| "every `/new`" unconditional | `config.rs` doc, renamed test header | "the background reapply session creation spawns, once auth resolves, coalesced while in flight" |
| "if this ever starts passing" (meant failing) | `config_tests.rs` | "if this assertion ever FAILS" |
| extra, same family, found by sweep: "OnceLock" descriptions of the RwLock store | `fuigo-shell-base/tests/credential_origins.rs:1`, `fuigo-shell-base/src/util/mod.rs` test doc, `fuigo-pager/src/voice/auth.rs` test doc | corrected (comment-only) |

Sweep method: `git grep -F -c` on the working tree, with a positive control of the same pattern
at v1 `05157d8b`. The plain `grep` on this Mac is an unreliable wrapper, so it was not used.

| pattern | at v1 | now |
|---|---|---|
| ``asserted in `agent_ops` `` | 1 | 0 |
| `trusted_origins_reload_republishes` | 1 | 0 |
| `nothing_after_the_config_layer_can_widen_the_trust_set` | 1 | 0 |
| ``OnceLock` where the first write wins`` | 1 | 0 |
| `test_settings_refresh` | 1 | 0 |
| `starts passing` | 1 | 0 |
| ``on every settings reapply (`/new`)`` | 1 | 0 |
| ``every `/new` `` | 1 | 1 (the corrected sentence: "not on literally every `/new`") |

### 1.7 Test sensitivity claims (Astra v2 #3, LOW; v3)

v2's header claimed each caller test failed against both earlier behaviours; mutant B showed
only one did. v3's header in `mvp_agent/tests.rs` lists per test the mutants it was **measured**
to catch, from the runs in §3. One first draft of that list was itself wrong: it predicted
`does_not_resurrect…` passes under A, but it fails there because of its trust-set assertion.
The header was corrected before the gate on the final tip.

## 2. Audit findings → resolution

| finding | resolution |
|---|---|
| Astra v1 #1 HIGH: raw endpoints logged | no entry text in any record (§1.1, §1.2); mutant C proves the tests catch a regression |
| Astra v1 #2 / Fable #7: skip leaves remote-derived fields stale | re-resolve from last-good disk layers under fresh remote settings (§1.4); mutant B |
| Astra v1 #3: empty or absent file bypasses the guard | proven out of packet, with proposal P17-F1 (§1.5) |
| Astra v1 #4 / Fable #2: test does not protect the caller; env-dependent | caller tests drive the caller's own decision code; the env vars that could mask them are removed under `EnvVarGuard`; mutants A, B, E |
| Astra v1 #5 / Fable #16: seed unlogged; filters suppress; path-only edits reported | seed recorded; unified-log record; comparison on what the matchers admit (§1.2, §1.3) |
| Astra v1 #6 / Fable #6, #15: stale statements | §1.6 |
| Fable #1 BLOCKER: no passing evidence | §3–§5 |
| Fable #8: `sync_campaign_fields` resets on failure | characterized precisely and left as is, with reasons (§1.4) |
| **Astra v2 #1 HIGH**: userinfo widening recorded as Unchanged | two-tier `RecordedTrust` (§1.2); mutant D |
| **Astra v2 #2 MEDIUM**: replay resurrects withdrawn campaigns | retain disk layers, not the merged table (§1.4); mutant E |
| **Astra v2 #3 LOW**: overstated test sensitivity | measured per-test table (§1.7, §3) |

## 3. Receipt — v3 at the tip `922f5d3e` (parent `f89618ef`), the gating run

- **Commit:** `922f5d3e3608f6018cf32de34bfea722bbf25cf4` (strike/p17r). Parent control:
  `f89618efccc265c7978c465ec7e75b6c0c143723`. Baseline control:
  `2eb306e08ae24d05c15c74b6b1c1d3235e0f1d96`.
- **Where:** hetzner-dsm, private lane `/root/fuigo-builds/p17r-v3/`, using its own clone and its
  own `CARGO_TARGET_DIR`, `nice -n 19`, `CARGO_BUILD_JOBS=8`, and no lane lock. Every full
  `-p fuigo-shell` run was taken under `flock /root/fuigo-builds/.shell-test.lock`. The target
  (57 GB) was deleted at the end. Script: `/root/fuigo-builds/p17r-v3/gate.sh`; log of record:
  `/root/fuigo-builds/p17r-v3/gate.out`.
- **Toolchain (from inside the tree):** rustc 1.94.0 (`4a4ef493e`, 2026-03-02), cargo 1.94.0.
  `rust-toolchain.toml` sha256
  `32a47ba7c3bcc9063bd056b833d12d51b628a38862b499fb4388d22c58cd64ca`. `rustc -vV` sha256
  `b75985398e5509a90a7d5d68f8ec6690675f703c5cfa11893b04fc9c3fceca69`.
- **Commands (verbatim):** full suites `cargo test --locked --no-fail-fast -p <pkg>`. Focused:
  `cargo test --locked -p fuigo-shell-base --lib -- a_trust_record the_trust_record_agrees dropping_userinfo a_path_only_edit a_moved_endpoint`;
  `cargo test --locked -p fuigo-shell --lib -- a_failed_config_read an_empty_reload_table`;
  `cargo test --locked -p fuigo-shell --test trusted_origins_follow_config --test trusted_origins_parsing_is_not_authority`.
  Clippy: `cargo clippy --locked --no-deps -p fuigo-shell -p fuigo-shell-base --all-targets`.
  Pager: `cargo check --locked --tests -p fuigo-pager` (for the comment-only edit in `voice/auth.rs`).
- **Completeness (A.2.1 as amended in `dd3b6484`):** the derived count comes from
  `cargo test --locked -p <pkg> --no-run --message-format=json` (test executables + doc-test
  runs, filtered by manifest path). `target_headers`/`unfinished` come from the contract's awk.
  Each run's own `P17RV3_DONE cargo_exit=` marker was checked, and no exit is 124 or ≥128.

### 3.1 Full suites

| rev | package | derived (exe+doc) | headers / unfinished | cargo_exit | failures | admissible | log sha256 | UTC |
|---|---|---|---|---|---|---|---|---|
| `922f5d3e` cand | fuigo-shell-base | 4 (3+1) | 4 / 0 | 0 | 0 | yes | `d2d6d58a29dd4f0c3e417f29b592528050f782cd871f355f6e623b768369f610` | 2026-09-30T22:27:06Z |
| `922f5d3e` cand | fuigo-shell | 37 (36+1) | 37 / 0 | 101 | 3 | yes | `5754a3439ad7ca4d453895665891735a5b477fa042242aa858bd2e33514c769c` | 2026-09-30T22:31:53Z |
| `f89618ef` parent | fuigo-shell-base | 4 (3+1) | 4 / 0 | 0 | 0 | yes | `0a499da80ff67a0b772da9eda358b81a9f3ac1e382c1d8cb97d46573f6b82516` | 2026-09-30T22:32:28Z |
| `f89618ef` parent | fuigo-shell | 37 (36+1) | 37 / 0 | 101 | 7 | yes | `bb467051e428521392f52eb94b9af678ff24098a52e2a1d9ead5a692a4949518` | 2026-09-30T22:37:51Z |
| `2eb306e` baseline | fuigo-shell | 35 (34+1) | 35 / 0 | 101 | 3 | yes | `856b81bceedd0c89bf7521ee47c8996eae6a45b902c0c7c4c12dead45e1fa9f4` | 2026-09-30T22:45:17Z |

`result_lines` is 52 at cand and parent and 50 at the baseline. Per A.2.1 rule 4 that is not a
target count: the lib test binary re-execs itself and prints extra result lines.

### 3.2 Failing-set diff (from the `failures:` block)

- cand (3): `extensions::session_updates::tests::handle_falls_back_to_id_lookup_for_divergent_cwd`,
  `inherited_parent_pool_keeps_the_mcp_meta_tools_reachable_from_the_child`,
  `inspect::tests::describe_requirements_file_flags_invalid_version_overrides_as_parse_error`.
- parent (7): `configured_endpoints_become_the_trusted_origins`,
  `wait_settings_leaves_the_fetch_for_accept`, `handle_falls_back_to_id_lookup_for_divergent_cwd`,
  `init_session_load_backfills_worktree_identity_on_untagged_summary`, and three
  `session::worktree::tests::*`.
- baseline (3): `wait_settings_leaves_the_fetch_for_accept`,
  `dropping_the_guard_silences_the_heartbeat_before_anyone_else_can_hold_the_lock`,
  `handle_falls_back_to_id_lookup_for_divergent_cwd`.

The candidate set is **not** ⊆ the parent set. Two names are candidate-only:
- `inspect::tests::describe_requirements_file_flags_invalid_version_overrides_as_parse_error`:
  isolated (`--lib -- --exact`) 3/3 **pass at the parent and 3/3 pass at the candidate**. It
  also failed in the parent full run at `8b4b8f40` (§4), and v3 does not touch `inspect`. It is
  suite-load or order dependent at both revisions and is not attributable to this packet.
- `inherited_parent_pool_keeps_the_mcp_meta_tools_reachable_from_the_child`
  (`tests/inherited_mcp_pool_child_acp.rs`): **not isolated**. The gate script only isolates
  `--lib` names, so it skipped this integration-test function. It is in the recorded v1 base
  failset at `8e11724` (`/root/fuigo-builds/p17r-base-fuigo-shell.failset`), so it failed
  before any P17-R code existed. That is attribution by prior record, not by a same-session
  isolation pair. **Unverified in this session.**

`handle_falls_back_to_id_lookup_for_divergent_cwd` fails at all three revisions. In v2's run it
failed isolated 3/3 at both `8e11724` and `adbf192e` (§4): a deterministic inherited failure.

### 3.3 Clippy

Exit 0 on both sides. Warning set (message @ file, line numbers stripped): 19 entries each, and
**byte-identical** (sha256 `62c8494d2568d8a4264c030aae10e2a54f292fc64451160a02376cbb2451f9ad` at
both `922f5d3e` and `f89618ef`), so none are new and none are gone. Log sha256: cand
`3111bfe2b40f0ce7a14bef69bebe554432a1e4c13dc230db29a56fda138ccdf4`, parent
`5682a5db459524be9fc8a6d0278a50e24b89548e79a3a5b2f608e39fefd2da51`. `cargo check --tests -p fuigo-pager`
exits 0 (log `8f5132ec761388bfae6304988539f61119dcef81a3d21fa85251795d1d4f42ff`).

### 3.4 New tests and mutants

On the candidate, all 12 new or changed tests pass (focused log
`032c2e55d69892fcfc1f723e258852018b241b3863f5cbe47c06c60ba0ad2bf1`, 2026-09-30T22:04:17Z).
Each mutant is one commit on top of `922f5d3e` that restores one earlier behaviour, and is
never for merge:

| mutant | restores | commit | focused log sha256 |
|---|---|---|---|
| A | pre-fix empty-table substitution (`8e11724`) | `d8cdecb9` | `443215c6aaa93676a727bf78c104bf393d86d5e28c1d31f220c38f4d93362425` |
| B | v1 skip-the-re-resolve | `816f9dbc` | `bededc01ac2db5c933018a89a57fe0946b071e61f0ac9379596e1ba1ab6c22e2` |
| C | v1 recording: raw strings, seed unrecorded | `f77c3303` | `dbfe7e3a6b18cbe4216abe280589c94a6ba3eb3d280d0fe76a95277323040cd7` |
| D | v2 recording: userinfo ignored, so a userinfo edit compares Unchanged | `3b2a9f0b` | `3ddc17f194388ae97ba6f0ae4a4996cf7280b779c851dd8197913c16591ecf5f` |
| E | v2 fallback: replay the last effective (campaign-merged) table | `1e455d15` | `9d81f8cca0ee3fcb3e115a725a30efa2e7c7a835b089fb4e9f0d9ac6709c9748` |

Measured, FAILED = the test catches that mutant:

| test | A | B | C | D | E |
|---|---|---|---|---|---|
| mvp `…keeps_the_configured_trust_set` | FAILED | ok | ok | ok | ok |
| mvp `…still_applies_freshly_fetched_remote_settings` | FAILED | FAILED | ok | ok | ok |
| mvp `…does_not_resurrect_a_withdrawn_remote_campaign` | FAILED | FAILED | ok | ok | FAILED |
| mvp `…before_any_successful_read_leaves_the_config_alone` | FAILED | ok | ok | ok | ok |
| config `an_empty_reload_table_discards_the_configured_trust_set` (characterization) | ok | ok | ok | ok | ok |
| base `a_trust_record_carries_only_scheme_host_and_port` | ok | ok | FAILED | FAILED | ok |
| base `the_trust_record_agrees_with_the_matchers` | ok | ok | FAILED | FAILED | ok |
| base `dropping_userinfo_from_an_endpoint_is_a_recorded_widening` | ok | ok | FAILED | FAILED | ok |
| base `a_path_only_edit_is_not_a_trust_change` | ok | ok | FAILED | ok | ok |
| base `a_moved_endpoint_is_recorded_as_a_widening_naming_both_origins` | ok | ok | FAILED | ok | ok |
| int `a_reloaded_endpoint_becomes_first_party` (unified-log record) | ok | ok | FAILED | FAILED | ok |
| int `parsing_a_config_or_seeding_after_startup_cannot_move_the_trust_set` | ok | ok | ok | ok | ok |

Every mutant is caught by at least one test. The last two rows catch no mutant, by design: the
characterization test pins behaviour none of the mutants change, and the parsing test guards the
authority rule, which the mutants do not touch. Each failure was checked to be on its intended
assertion. In the v2 run, for example, the mutant A trust test failed with left
`["https://api.fluxrouter.ai/v1"]` against right `["https://my.gateway.invalid/v1"]`, and the
mutant C integration test showed no baseline record at all.

## 4. Earlier complete runs (A.2.1 rule 6: every complete run is reported)

**v3 at `c1c1684b` on parent `8b4b8f40`.** This is the same tree content, rebased with no
conflicts and no file overlap. Private lane, same script. All admissible:

| rev | package | headers/unfinished | exit | failures | log sha256 |
|---|---|---|---|---|---|
| `c1c1684b` | fuigo-shell-base | 4/0 | 0 | 0 | `ca95d110b646fe394b0e2073b6b0eed3f23eafbdf63f9744e4943c6393c27996` |
| `c1c1684b` | fuigo-shell | 37/0 | 101 | 9 | `87a35a47c7dffb00a37f3e7825b49cef5799ff8a0aaaa2aab0a006f72caaa126` |
| `8b4b8f40` | fuigo-shell-base | 4/0 | 0 | 0 | `0554d47d55377e7bbb2c0da5a85ef2e5ee3db95d99ca06cc29f750d503c92040` |
| `8b4b8f40` | fuigo-shell | 37/0 | 101 | 6 | `f0a1e72ad646be62b31d63dc9e89d452604c0fe7025368010344d78bf149b37e` |
| `2eb306e` | fuigo-shell | 35/0 | 101 | 3 | `88f6d4dc7d3ddd60fc250fb93704c76a03bb18ca37642920a84fb293b229a02b` |

Seven names were candidate-only here: `embedded_otel_gate_keeps_a_session_user_fail_closed`,
`provider_resolves_relative_program_against_cwd`, two `session::workflow::registry::tests::*`,
and three `session::worktree::tests::*`. Every one was isolated 3/3 at `8b4b8f40` and 3/3 at
`c1c1684b`, and **every run passed**. None of them fails at the tip run in §3. Mutant results
were identical to §3. Logs are under `/root/fuigo-builds/p17r-v3/run-8b4b8f40/`.

A first v3 gate at `591b4e90` was stopped by me on purpose, before any suite ran, to correct
the test-sensitivity header. Its process group and `timeout`'s separate group were both killed,
and no processes survived. Only its focused and mutant runs completed; their results match §3
except for the header text. Log: `run-8b4b8f40/gate-aborted-591b4e90.out`.

**v2 at `adbf192e` on `8e11724`** (shared integration target, same full-suite command).
Admissible under A.2.1 (37 headers / 0 unfinished):
- cand `fuigo-shell`: 18 failures, log `e84174f3bd227bc81cfd8249cbe1ad97cd58d8846a8d4a10b49ca0fa2f4b3051`;
- rerun base `8e11724`: 18 failures, `742b46ce0b5cacdb4b0d7846edded2089645acd82116cea0be58d9cb2c06bae6`;
- rerun cand: 18 failures, `46eaefc4e8c2bdad9ede88c1f44f7330161e1e72f54e0ac960b604fefba00fbb`.

The two same-session reruns differed by 3 names in each direction, which is the known churn.
Isolation ×3 at both revs:
- `handle_falls_back_to_id_lookup_for_divergent_cwd` fails 3/3 at both;
- `embedded_otel_gate…`, `wait_settings_leaves_the_fetch_for_accept`,
  `shutdown_waits_for_in_flight_cpu_profile_stop` and
  `init_session_load_backfills_worktree_identity_on_untagged_summary` pass 3/3 at both.

`fuigo-shell-base` was 4/4, exit 0. Clippy warning sets were identical at `8e11724` and
`adbf192e`. Logs: `/root/fuigo-builds/p17rv2-*`.

## 5. What I could not verify

- Isolation of `inherited_parent_pool_keeps_the_mcp_meta_tools_reachable_from_the_child` at
  `f89618ef`/`922f5d3e` (§3.2). Attribution rests on its presence in the `8e11724` base failset.
- Suite stability (A.2.1 rule 7) is not claimed. No three consecutive identical full runs were
  taken, and the recorded churn says the suite is not stable.
- A real disk-failure end to end. `fuigo_home()` is a process-wide `OnceLock`, so the caller
  tests inject the read result and the last-good layers; the one-line production wiring in
  `refresh_settings_and_reapply` is exercised only by compilation and review.
- That the TUI in-app log view is visible to a user by default. I verified the filter admits
  `warn`, not the UI surface.
- The unified log's behaviour on a read-only or full home directory. The code drops the write,
  which I read in `unified_log::open_writer_at`; I did not test it.
- rustfmt: my own lines are formatted, with `rustfmt --check` hunks applied only where they
  intersect lines I changed relative to the parent. The files still carry pre-existing
  unformatted code (25 hunks outside my lines), which I left alone.

## 6. Packet proposals

- **P17-F1: atomic `config.toml` writers** (§1.5). Convert the eight `std::fs::write` writers in
  `fuigo-shell/src/config/mod.rs` to `persist::atomic_write_string` under
  `fs_atomic::lock_config_for_write`, with a no-empty-or-partial-read test per writer. An
  optional, separately gated second half is a stable-read check for a blank user layer in
  `read_toml_file`.
- **P17-F2: trust records at the base crate.** Move the persistent record into
  `fuigo-shell-base`, via an injected sink or a `fuigo-telemetry` edge, or add a test that
  enumerates the write-path callers, so that a future third caller cannot bypass the
  unified-log record.
- **P17-F3: gate tooling.** When a gate aborts, kill by session (`pkill -s <gate sid>`), not by
  process group. `timeout` puts its child in a new process group, so `kill -- -<pgid>` of the
  gate left clippy running until I killed its group separately. Isolation should also cover
  integration-test functions (resolve the `--test` target from the `Running tests/…` header
  that precedes the name).

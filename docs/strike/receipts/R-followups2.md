# R-followups2: four follow-ups from the audits of the W3-E, P186f and W3-B landings

Branch `strike/followups2`, base `61a228a1`. Built and tested on Hetzner lane `fu2` only.

## Item 1: `fuigo inspect` and project-level plugin config
- Problem: a plugin disabled only in a project `.fuigo/config.toml` showed as enabled; hook and LSP rows ignored `enabled`.
- Change (`fuigo-shell/src/inspect/mod.rs`): inspect builds its plugin config with `config::resolve_effective_plugins_config(cwd)`,
  the function the session uses. Hook and LSP rows come from the plugins the registry marks active (enabled AND trusted),
  the same set the plugin rows use. Config warnings still come from the user-level lenient parse.
- Project-config trust condition (read from the function, not assumed): the project `[plugins].disabled` list is merged
  WHATEVER the folder trust (tighten-only, fail-safe); project `[plugins].paths` are merged ONLY when the folder is trusted
  (`folder_trust::project_scope_allowed`). Inspect now applies exactly this, because it calls the same function. Claude
  `enabledPlugins` is merged unless `strictKnownMarketplaces` restricts it (also the session's rule; inspect now follows it).
- Tests: `inspect_honours_a_project_level_plugin_disable_followups2`, `inspect_hides_hook_and_lsp_rows_of_a_disabled_plugin_followups2`.
  RED at `0966e5ac`: both FAILED (assertion "project-disabled plugin shown as enabled"; hook/LSP row assertions). Fix `0216396b`.
## Item 2: active-sessions stale-temp test (test only)
- `stale_wide_tmp_file_does_not_leak_into_json` now reads the written file: new session id present, "stale" absent. Commit `db2e3b78`.
- Mutation (lane worktree only, not committed): the write path renames an existing temp file as is -> the test FAILED at lib.rs:339.
## Item 3: admin-policy "valid again" after "is now empty"
- Change (`session/admin_policy_watch.rs`): new `told_blank` set; a path told "is now empty" is remembered; the next completed
  read that classes it Valid says the existing "valid again and is in force" sentence once. Blank reads stay silent; a Locked
  read clears the memory (normal enter notice). Enforcement code untouched.
- Tests: `a_file_told_now_empty_that_turns_valid_says_valid_again_once_followups2` (RED at `d588ff00`, fix `5e8bf551`),
  `a_file_told_now_empty_that_goes_wrong_typed_never_says_valid_again_followups2` (guard against over-saying; `7f6c4bbe`).
## Item 4: pager retry-action dedupe
- Change (`fuigo-pager/src/app/error_display.rs`): `compose_detail` drops the action only when it equals the detail's last
  sentence, or is "try sending again" and the detail ends in any retry phrase. Test
  `a_longer_retry_action_is_not_dropped_for_a_plain_try_again_followups2`: RED `0966e5ac` (left "Something broke. Try again."), fix `06b91835`.
  `leader_restart_messages_carry_retry_advice_once` stays green. Wrap-indent note not done, as instructed.

## Release notes: Plugins line extended (one sentence); item 12 gets "(also after the "now empty" message)".
## User-visible: inspect lists project-disabled plugins as disabled and hides their hook/LSP rows; the admin-policy notice appears once.
## Known limits: the wrong-typed-after-empty test asserts only "no valid-again" (that version produced no enter notice in the test).

## Proof (tip `e91e30e4`, code identical since `0216396b` except tests)
| Check | Result |
|---|---|
| new tests x3 (shell 4, pager 1, active-sessions 1) | ok x3 |
| lib suites shell / pager / active-sessions | 8246 / 9895 / 9 passed, 0 failed |
| `cargo test --locked -p fuigo-extra-ca` (guard) | all ok; no pin changed |
| clippy --all-targets (3 crates) | no warning on changed files |
| `0216396b` dropped the two inspect tests by mistake | restored in `e91e30e4`, then rerun as above |

## Unverified
A live session reading a project config; a real `fuigo inspect` binary run. Pager and active-sessions full suites were run at
`7f6c4bbe` (inspect restore touched shell tests only); clippy on pager/active-sessions at `7f6c4bbe`.

# Round 2: the silent no-copy lock-down (Grok r1 MEDIUM 1)
- Problem: a running session whose admin file is broken with NO validated copy (e.g. after "now empty" forgot the copy) is under
  the full lock-down but the watch classed it `Other` and said nothing.
- How "no copy" is known: TOML (`requirements.toml`, `managed_config.toml`): `admin_source_state_read` already returns
  `AdminSource::Broken(detail)` exactly when the file is broken and `last_good_admin_sources()` holds no copy (a copy gives
  `Text(Some(copy))` = `Other`, or `Locked`). Claude `managed-settings.json`: `read_managed_settings` `Err(detail)` with
  `!admin_requirements_copy_exists(path)`, or `WrongTyped` without a copy (the `Locked` arm is the with-copy case). I only read
  these (the same read-only classifier `admin_policy_states_at`); no loader changed.
- Change: new `AdminFileClass::BrokenNoCopy(AdminLockdown)` (+ `broken_version`: hash of the file text, else of the detail; +
  `admin_lockdown_gone_notice`). Watch: it counts as "now locked", so it uses the existing once-per-(path, version) enter notice
  (fresh-start wording + "All tools are denied until an administrator fixes this file."); valid -> "valid again ... lifted";
  blank -> "now empty"; file gone -> new "no longer there ... sets no policy" (never "last valid policy", via `told_nocopy`).
- First read of a new session: unchanged rules. Broken-with-copy stays `Other` (silent). A session cannot start while a file is
  broken with no copy (start refuses); a new session inside an already-running process that is in that state is told once, which is true.
- Enforcement untouched: `git diff 766a3c47 HEAD --stat` shows only `validation.rs` (classifier + notice builders after the
  `admin_policy_states_at`/enum region), `lib.rs` (export), the watch, its tests and docs.
- Test expectation changed: `a_user_owned_file_is_admin_policy_only_while_the_admin_root_override_is_set_p186f` first assertion
  `Other` -> `BrokenNoCopy` (a not-admin-owned file with no copy IS the lock-down; before the override it was classed `Other`).
  `a_file_told_now_empty_that_goes_wrong_typed_...followups2` strengthened to expect the one deny notice.
- Unverified: a live TUI session; the macOS MDM source (not part of the watch).

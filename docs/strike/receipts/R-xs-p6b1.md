# R-xs-p6b1: peer messaging packet 6 part B1 (shell writes, session store, non-edit tools under the peer guard)

Branch `strike/xs-p6b1` on `hub`, base `42adeae1`. Built and tested on Hetzner lane `xs-p6b1` only.

## What is guarded (only while the session is peer-influenced; otherwise nothing here runs)
- S6.4 shell: `peer_guard_denial` (`permission/peer_guard.rs`) sends `AccessKind::Bash` (which includes `Monitor`) to
  `peer_bash_denial` (`manager/mod.rs`). It runs the existing bash evaluator and `bash_protected_write_target` (redirects, `tee`,
  `cp`/`mv`/`ln` destinations, `sed -i`, rename-over, `git config`, nested `sh -c`), with the extended set added to the floor through
  a scoped thread-local (`with_peer_extended_set`, `shell_access.rs`) so every destination kind and the symlink/`..` resolution of
  `edit_target_protection` apply to instruction files, rule dirs, peer config, git config and the session store. Outside that scope
  `edit_target_protection` is unchanged. An unparseable script (`SegmentEvaluation::Unparseable`) is denied, only when influenced.
  Runs inside `PermissionHandle::request`'s first statement, so before allow-all, yolo, auto, grants and rules.
- S6.2 session store: `<fuigo home>/sessions/**` and `.fuigo/sessions/**` (transcript, `peer_influence.json` marker, every file the
  persistence layer puts in the session dir) join the protected set for edit tools and shell.
- Item 4 (subagent): a clone of an influenced handle (what a subagent holds, part A shares the atomic) is denied a shell write; test only.

## Not covered (stated limits)
- S6.5: no existing permission code identifies an MCP / `use_tool` call as a file write, delete or rename with a path, so none was
  invented; `AccessKind::MCPTool` is NOT guarded. Dynamic tools whose input carries `filePath`/`file_path` are already `Edit` (part A).
- Writes hidden inside interpreters or scripts the evaluator does not decompose (python -c, a script file) are only caught when the
  evaluator marks them opaque/unparseable; otherwise not seen (S6.5 limit, and S6.6 change detection is later work).
- The whole `sessions/` tree is protected, not only the current session's directory (over-protects other sessions; a stricter
  match needs the session id inside the permission layer).
- Denial text names "the command's write target", not the specific path.

## Tests (`permission/manager/peer_guard_shell_tests.rs`)
`s6_4_shell_table_every_mode_denies_when_influenced_and_is_untouched_otherwise` (11 commands x every mode and the allow-all handle:
redirect, append, tee, cp, mv rename-over, write via symlink alias, sed -i, git config, unparseable, transcript, state file; control
never sees the guard), `s6_4_ordinary_shell_commands_match_the_control_when_influenced`, `s6_4_subagent_clone_of_an_influenced_handle_is_denied_a_shell_write`,
`s6_2_session_store_is_in_the_protected_set`, `s6_4_extended_set_does_not_leak_into_the_ordinary_floor`.
Red/green: with the guard Bash arm and the sessions entries reverted, 3 of 5 fail (table, subagent, session store); with the change 5 of 5 pass.

## Round 2

Changes (all active only inside `with_peer_extended_set`; ordinary floor and non-influenced decisions unchanged):
- Globs: any write target or scanned token containing `* ? [` is unpinned (deny) (`ShellWriteFacts::protection_in`).
- Opaque forms (Grok HIGH): an `opaque_write` redirect (`> "$OUT"`) is denied; a shell interpreter (`sh`, `bash`, ...) whose script is not a parsed literal `-c` string (`sh -c "$X"`, pipe into `sh`, here-doc into `sh`/`bash`, `bash script.sh`) is unpinned.
- Directory landings: `copied_tree_protection` and the missing-parent arm of `via_directory_protection` use `scoped_protected_reason` (floor plus extended set, lexical); a `cp`/`mv`/`rsync` destination that is itself `.claude`/`.fuigo`/`.cursor` is denied (`is_peer_bare_container`, spelling or after symlinks). Covers `cp --parents` and `rsync` of a directory.
- Links: new `DestinationKind::LinkOperand`; every operand of `ln` and of `cp` with `-l`/`-s`/`--link`/`--symbolic-link` is judged as a write target (protected path or bare container). `ln -s a.txt b.txt` and `ln a.txt h.txt` outside protected places are NOT denied (neither operand is protected).
- Refusal text: `peer_unanalysable_denial_text` (could not be analysed, names `/peers clear-influence`) for an unparseable script or a protected hit that has an unresolved element; the resolved-target text is unchanged (path not named: the evaluator returns only a reason, not the path).
- `git config --get user.name` is NOT denied by the guard (read form falls to the ordinary path); `git config user.name x` stays denied.
- Hub path: `hub.rs` calls `peer_guard_denial` first, which calls `peer_bash_denial`; that function now wraps the whole evaluation (parse and facts) in the extended-set scope, so the hub path gets the same verdict. `hub_protected_target` (floor only) runs after, unchanged.

Tests (all through `PermissionHandle::request`, every mode incl. allow-all): `s6_4_r2_glob_words_*`, `s6_4_r2_opaque_shell_forms_*`, `s6_4_r2_directory_landings_*` (9 rows), `s6_4_r2_link_operands_*` (8 rows), `s6_4_r2_refusal_text_*`, `s6_4_r2_ordinary_commands_pass_*` (8 rows), `s6_4_r2_git_config_get_*`, `s6_4_extended_set_does_not_leak_through_request`; `s6_2_session_store_*` now also goes through `request`. RED on 87f4bca7: the five denial tables and the text test fail; the two control tests pass.

Remaining limits: interpreter writes (`python -c`, `perl -e`, scripts), MCP/dynamic tools, `bash script.sh` is denied conservatively, glob-bearing legitimate targets (`> out[1].txt`) are denied while influenced.

## Round 3

Changed (extended-set scope only; the ordinary floor and non-influenced decisions are unchanged):
1. Brace words (`{a,b}`, `{m..m}`) in write targets and scanned tokens are unpinnable, like glob words (deny).
2. `source`, `.`, `eval` are unanalysable (deny).
3. `rm`, `rmdir`, `unlink`, `shred`, `truncate`, `mv` (source side) operands: deny when the path is protected or a directory holding a fixed well-known protected name (bounded, no walk; also a `.git` directory).
4. `xargs` / `find -exec|-execdir|-ok|-okdir` with a writer, deleter or shell inner command, and `find -delete`: deny. `find . -name x` and `xargs grep` pass.
5. `chmod`, `chown`, `chgrp`, `chattr`, `touch` operands are judged as write targets.
6. git: `remote add|set-url|rename|remove|rm|set-head|set-branches`, `submodule add|init|update|set-url|set-branch|sync|deinit`, `branch -u|--set-upstream-to|--unset-upstream|--edit-description`, `init`, `clone`, `worktree add`, `lfs install`, `-c core.hooksPath|sshCommand|fsmonitor|editor`, `--exec-path`: deny. Read forms pass.
7. Controls prove `git checkout main`, `git switch main`, `git pull`, `cargo build`, `npm test`, `python script.py`, `make` pass when influenced, same as the control.
8. Glob and brace denials use the "could not be analysed" text.

Stated limits: `git checkout|switch|restore|reset|merge|pull|rebase|stash|apply|am|cherry-pick|revert`, package managers, build tools, interpreters and script files are NOT denied (owner decision 47 pending, recommendation M). These can rewrite a protected file; the second layer (change detection, part B2) is what covers them. (`git stash` and the other worktree rewrites that the base already unpins keep their base behaviour.)

Tests (all through `PermissionHandle::request`, every mode, with control): `s6_4_r3_command_forms_are_denied_when_influenced`, `s6_4_r3_glob_and_brace_words_use_the_unanalysable_text`, `s6_4_r3_controls_pass_when_influenced`. RED on f02b90a3: the first two fail (first row `brace_redirect_seq`); GREEN on the round-3 tip.

## Round 3 follow-up (git option spellings)

The round 3 audit found variant spellings of the git rules that still passed: the attached form `-ckey=value`,
`--config-env` (attached and split), an abbreviated `--exec-p=`, the attached `git branch -uorigin/main` and
abbreviated `--set-up=`. `git_parts` and the `branch` arm in `shell_access/peer_cmd.rs` now take them. Rows added to
`R3_CASES` (8) and to the controls (4: `git branch -vv`, `git branch -a`, `-c color.ui=always` in both spellings).
Red on `60308f46`: `s6_4_r3_command_forms_are_denied_when_influenced` fails at the first new row.

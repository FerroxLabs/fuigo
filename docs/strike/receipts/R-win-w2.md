# R-win-w2: copied session file names use `/` on Windows

## What the names are for, and what a Windows user saw
`CopiedSessionFile.name` (persistence.rs, `collect_session_files_walk`, `archive_logs::collect_terminal_logs`) is the
tar entry name of the session-state archive built in `upload/trace.rs:1618` (`archive.append_data(.., &file.name, ..)`)
for the trace/feedback upload; `trace.rs:1557` also matches names for sort priority. Nothing in this repo reads
the names back into paths (no restore of a `CopiedSessionFile`), so there is no reading-side join to guard and no
traversal finding here. The tar crate (0.4.45 `path2bytes`, windows) already rewrites `\` to `/` when it writes the header,
so the uploaded archive was probably already correct. What was wrong: the in-memory names (`a\b\deep.txt`,
`terminal\01.log`) differed from the `/` form every other producer uses (`mcp_stderr/...`), so name comparisons
in the process and four tests failed. Not run: a real upload checked on the receiving side.

## Change
- `copied_file_name(rel_path)`: windows joins the path COMPONENTS with `/` (non-UTF-8 component: skipped as before);
  non-windows is `rel_path.to_str()`, byte-identical to before (a unix backslash stays part of the name).
  Used for both producers (session files and terminal logs).
- New test `a_nested_file_is_recorded_with_forward_slashes` (all OS).
- Item 2 DONE, one line: `managed_mcp.rs:691` `plugin_manifest_label` builds the path by components
  (`rel.split('/').fold(root, join)`), so the refusal text has one separator on Windows; unix text identical.
  (The `/` lives in `MANIFEST_PATHS` constants, so fuigo-agent is untouched.)

## Evidence (Windows lane)
- RED at 2a37852a (`w2red`): 5 failed of 16 (4 collect_session_files + p118 refusal), messages `a\b\deep.txt` vs `a/b/deep.txt`.
- First fix (session files only) left 2 of 17 failing (`w2g1..3`): terminal logs were a second producer; fixed.
- GREEN at 6a7085a4 (`w2h1..3`): 17 passed, 3 runs. Filter `collect_session_files an_inline_plugin_refusal`.
- Whole suite `w2full`: 8040 run, 97 failed (was 107 in fails-nextest.txt). Gone: the 5 from W-1, the 4
  collect_session_files tests, the p118 refusal test. New names: none (three names that looked new are 70-char
  truncations in the old list). 107 - 5 - 5 = 97.

## Unverified
A real copy/share between a Windows and a unix machine; Linux lanes (coordinator); clippy not run.
Crates touched: fuigo-shell only.

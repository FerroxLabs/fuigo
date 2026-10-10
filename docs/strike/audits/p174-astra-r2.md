Audited clean `wt-p174` at **`d1496d0fd`**, against `813c9ce41`, base `6221893ca`, and v1.0.21 `de6ca7dda`. The five specific fixes are present, but **an inherited, in-scope HIGH remains in dedupe**. No cargo, runtime tests, or file changes; `git diff --check` passed. Hub files are untouched.

| Round-1 finding | Result | Reason |
|---|---|---|
| **1 — HIGH: ignored `target_file` injected by dedupe** | **FIXED** | Both dedupe passes now require every raw-parsed entry to appear in `judged_read_paths`. This closes the reported injection. A separate resolution mismatch remains below. [read_dedupe_hook.rs:24](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-shell/src/session/acp_session_impl/read_dedupe_hook.rs:24) |
| **2 — HIGH: Unicode fallback** | **FIXED** | Permission checking calls the reader’s shared resolver, including Unicode fallback, then follows the returned path’s symlinks. `d1496d0fd` correctly adjusts the test to expect the fallback sibling. [read_file/mod.rs:595](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-tools/src/implementations/fuigo_build/read_file/mod.rs:595) |
| **3 — HIGH: backslash-named symlink** | **FIXED** | Literal symlink resolution of `opened` supplies the physical target before policy evaluation. [manager/mod.rs:1329](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:1329) |
| **4 — HIGH: single-file forms** | **FIXED** | Both Codex and Fuigo `read_file` now produce targets without requiring a `files` list. OpenCode and grep remain excluded as agreed. [types.rs:293](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/types.rs:293) |
| **9 — MEDIUM: incorrect Codex/media resolution** | **FIXED** | Codex and media use `Literal`; relative media paths are anchored to process cwd. Fuigo alone uses `ModelPath`. [types.rs:297](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/types.rs:297) |

The remaining findings are:

1. **HIGH — inherited in both baselines; in scope: dedupe still opens a different, unjudged file.**

   Concrete scenario: cwd `/w`, home `/home/u`, `/w/~` symlinks to `/w/secrets`, and policy denies `Read(/w/secrets/**)`. Both `/home/u/note.txt` and `/w/secrets/note.txt` exist.

   Fuigo `read_file({"target_file":"~/note.txt"})` judges and reads `/home/u/note.txt`. The new membership guard accepts the identical string `~/note.txt`. However, dedupe’s [canonical_path at read_dedupe.rs:229](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-shell/src/session/read_dedupe.rs:229) performs `cwd.join(path)` without tilde expansion. The recording pass therefore opens and hashes **`/w/secrets/note.txt`**, despite its deny rule. See [read_dedupe_hook.rs:229](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-shell/src/session/acp_session_impl/read_dedupe_hook.rs:229).

   This requires neither a race nor ACP filesystem differences. Subsequent dedupe checks also hash that wrong file, potentially report its line count, and suppress changed home-file content. Dedupe must consume the judged resolved path, or decline these mismatched resolutions.

2. **MEDIUM — new versus both baselines: unconditional filesystem work inside the shared permission manager.**

   [manager/mod.rs:1857](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:1857) resolves every target sequentially **before** discovering that no compiled policy exists. Fuigo canonicalization has [no timeout](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-tools/src/util/fs.rs:53); missing names also trigger parent-directory scans. Literal symlink resolution adds synchronous filesystem work.

   Concrete scenario: a read on an unresponsive mounted filesystem, with no Read rules configured, now stalls the shared permission actor and its queued requests/mode changes. Previously that filesystem work belonged to tool execution. Large missing-file batches also repeatedly scan their parent directories. This is source-established additional work and blocking exposure; latency was not benchmarked.

3. **MEDIUM — round-2 regression from `813c9ce41`; restores an inherited baseline omission: one-path prompts lose their path listing.**

   The new [manager/mod.rs:1617](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:1617) guard enriches prompts only when there are **more than one distinct targets**.

   Concrete examples under a Read ask rule:

   - Fuigo `{"files":[{"path":"/w/private/key"}]}` retains the title ``Read ` ` `` with an empty target rather than naming the file.
   - `image_edit` with one local image retains only `imagine-edit: <prompt>`.

   The permission update lacks the path in its title/locations; it remains buried in raw input. Clients rendering title/locations therefore omit it. The same issue affects duplicate entries collapsing to one target and single-local-image video calls. This is separate from P173’s hub payload omission.

4. **LOW — new versus both baselines: valid whitespace spellings disable dedupe.**

   For Fuigo `{"target_file":" a.txt "}`, the reader correctly sanitizes the path. But [parse_read_entries](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-shell/src/session/read_dedupe.rs:194) trims it to `a.txt`, while judged paths retain `" a.txt "`. The new membership test rejects dedupe, so repeated unchanged reads return full content. This is conservative and safe, but loses existing dedupe behavior.

For ordinary reads, the shared-plan extraction preserves ordering, blank-entry filtering, range deduplication, byte budgets, and existing error handling. I found no additional content/offset/error-format regression. Auto mode evaluates the combined deny/ask before its fast path; Read allows do not authorize media side effects.

**YOLO remains an inherited exception to “an ask prompts”:** it still waives ordinary Read asks, while denies bind before YOLO. `prompt_policy=Allow` also waives asks. Those branches are unchanged by P174. See [manager/mod.rs:1908](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:1908) and [2448](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:2448).

The previously excluded ways to reach unjudged files also remain:

| Severity / origin | Concrete remaining route |
|---|---|
| **HIGH — inherited, excluded TOCTOU** | A permitted symlink is retargeted after judging; execution resolves/opens again. [read_file/mod.rs:630](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-tools/src/implementations/fuigo_build/read_file/mod.rs:630) |
| **HIGH — inherited, excluded ACP filesystem** | The client resolves an approved pathname to a different physical file than the host judged. [adapter.rs:34](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/file_system/adapter.rs:34) |
| **HIGH — inherited, P173-owned hub dispatch** | Hub calls reach tool execution without this manager’s per-file Read evaluation. [hub.rs:550](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/hub.rs:550) |
| **HIGH — inherited, excluded cursor rules** | With cursor rules enabled, reading an allowed source file opens adjacent `.cursor/rules/*.mdc` without judging those rule files. [cursor_rules_on_read.rs:264](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-tools/src/implementations/cursor_rules_on_read.rs:264) |
| **MEDIUM — inherited, excluded attachment tokens** | `[Image #1]` can resolve to a registered local attachment that Read-target extraction excluded. Limited to registered attachments. [image_edit/mod.rs:130](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-tools/src/implementations/fuigo_build/image_edit/mod.rs:130) |
| **MEDIUM — inherited, P173-owned prompt** | Hub-routed approval still says “Read a file” without listing paths. [hub_permission.rs:120](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/hub_permission.rs:120) |

No BLOCKER found. The dedupe resolution bypass is an unresolved **HIGH within P174’s scope**, independently of the excluded residuals.

**NOT-LAND-OK**



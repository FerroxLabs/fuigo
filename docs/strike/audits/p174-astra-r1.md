**NOT FIXED.** P174 closes the ordinary multi-file classification gap, but files can still be read without their actual targets being judged.

Reviewed `813c9ce41` against `6221893ca`. For v1.0.21, I used the repository-recorded code baseline `de6ca7dda`; no local `v1.0.21` tag exists. [Baseline receipt](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/docs/strike/receipts/R172-p172.md:4)

The implementation correctly collects both primary and `files[]` paths, combines deny > ask > allow, preserves the image tools’ separate approval requirement, and populates targets after PreToolUse rewrites. ACP permission requests receive every listed path. Those improvements are visible in [types.rs:272](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/types.rs:272), [gate_preflight.rs:177](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/gate_preflight.rs:177), and [tool_calls.rs:1688](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-shell/src/session/acp_session_impl/tool_calls.rs:1688).

The remaining findings are:

1. **HIGH — Deduplication can introduce a denied file after permission approval.**  
   First, read `/w/ok.txt` normally so it is cached. Then submit this Codex call:

   ```json
   {"target_file":"/w/secrets/key","files":[{"path":"/w/ok.txt"}]}
   ```

   Codex’s typed input ignores `target_file`, so P174 judges only `ok.txt`. Deduplication reparses the original JSON, recognizes `target_file`, serves cached `ok.txt`, and rewrites `files` to contain `/w/secrets/key`. Dispatch executes that rewrite without another permission check. Its recording pass also directly reads paths taken from this broader raw parser.

   Evidence: [read_dedupe.rs:187](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-shell/src/session/read_dedupe.rs:187), [read_dedupe_hook.rs:40](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-shell/src/session/acp_session_impl/read_dedupe_hook.rs:40), [tool_calls.rs:765](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-shell/src/session/acp_session_impl/tool_calls.rs:765), [read_dedupe_hook.rs:215](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-shell/src/session/acp_session_impl/read_dedupe_hook.rs:215). **Inherited from both baselines.**

2. **HIGH — Fuigo’s Unicode fallback reads a target absent from the permission plan.**  
   Suppose `public/k ey` contains U+00A0 and is a symlink to `secrets/key`; `public/k ey`, with an ordinary space, does not exist. With `deny=["Read(secrets/**)"]`, request the ordinary-space spelling through `files`. The gate sees that nonexistent spelling. The reader subsequently finds the Unicode filename and follows its symlink into the denied directory. An exact deny on the Unicode filename is likewise missed.

   Evidence: [read_file/mod.rs:604](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-tools/src/implementations/fuigo_build/read_file/mod.rs:604), [util/fs.rs:128](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-tools/src/util/fs.rs:128), [util/fs.rs:182](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-tools/src/util/fs.rs:182). **Inherited from both baselines.**

3. **HIGH — A Unix backslash-named symlink still bypasses Read rules.**  
   Let the literal Unix filename `/w/public\link` be a symlink to `/w/secrets/key`, while `/w/public/link` is absent or harmless. Policy changes `\` into `/` before its physical lookup. Both P174 spellings consequently inspect the wrong filesystem path, while Codex, Fuigo and the image readers follow the literal symlink. A `Read(secrets/**)` deny or ask misses the actual target.

   P174 does not carry over P184’s separate, literal physical-target resolution.

   Evidence: [policy.rs:1053](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/policy.rs:1053), [policy.rs:1065](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/policy.rs:1065), [manager/mod.rs:1821](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:1821). **Inherited from both baselines.**

4. **HIGH — Single-file forms retain resolution bypasses.**  
   `read_targets_for` returns `None` when `files` is absent or contains only blanks. A Fuigo call with `target_file` equal to `"\"secrets/key\""` is judged under the quoted spelling, then opens `secrets/key` after quote removal. Absolute display-cwd paths, tilde expansion and the missing-leading-slash heuristic have the same mismatch.

   OpenCode `read` also resolves paths after raw-path judgment. Fuigo `grep` has this problem for explicit files; its negative globs do not protect an explicitly passed file.

   Evidence: [types.rs:276](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/types.rs:276), [resources.rs:479](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-tools/src/types/resources.rs:479), [opencode/read/mod.rs:173](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-tools/src/implementations/opencode/read/mod.rs:173), [grep/mod.rs:809](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-tools/src/implementations/fuigo_build/grep/mod.rs:809). **Inherited from both baselines.**

5. **HIGH — Recursive grep still reads unjudged files.**  
   With `deny=["Read(secrets/**)"]`, search the permitted workspace root:

   - Codex `grep_files` supplies no managed deny exclusions. It reads denied contents and exposes matches through filenames—a content oracle.
   - OpenCode `grep` likewise supplies no exclusions and returns matching content.
   - Fuigo grep adds deny exclusions, but **ask rules are discarded** when deriving that list. `ask=["Read(secrets/**)"]` does not prompt when a root search reaches those files.

   Evidence: [codex/grep_files/tool.rs:81](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-tools/src/implementations/codex/grep_files/tool.rs:81), [opencode/grep/mod.rs:163](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-tools/src/implementations/opencode/grep/mod.rs:163), [resolution.rs:341](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/resolution.rs:341). **Inherited from both baselines.**

6. **HIGH — Fuigo reads and returns additional Cursor rule files without judging them.**  
   With `cursor_rules_on_read` enabled, deny `Read(src/.cursor/rules/private.mdc)` and read `src/main.rs`. A matching rule file is read and its body appended to the result, although it was absent from `read_targets`. The same mechanism applies during multi-file reads.

   Evidence: [read_file/mod.rs:859](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-tools/src/implementations/fuigo_build/read_file/mod.rs:859), [cursor_rules_on_read.rs:264](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-tools/src/implementations/cursor_rules_on_read.rs:264), [cursor_rules_on_read.rs:429](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-tools/src/implementations/cursor_rules_on_read.rs:429). **Inherited from both baselines.**

7. **HIGH — Approval is not bound to the filesystem object subsequently opened.**  
   Two concrete cases remain:

   - A symlink initially points to an allowed file, then another process retargets it to `secrets/key` while approval is pending. Execution follows the replacement.
   - With the ACP filesystem backend, the manager resolves symlinks on the agent’s filesystem, but the client performs the read. A client-side symlink to a denied target can differ from the agent-side path.

   Sharing `planned_entries` binds input strings, not physical targets or backend resolution.

   Evidence: [policy.rs:1107](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/policy.rs:1107), [codex/read_file/tool.rs:394](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-tools/src/implementations/codex/read_file/tool.rs:394), [file_system/adapter.rs:34](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/file_system/adapter.rs:34). **Inherited; these scenarios require concurrent mutation or differing ACP filesystems.**

8. **HIGH — Direct hub dispatch still bypasses per-file policy.**  
   `read_file` has no hub access mapping and falls through to `None`. The direct hub handler therefore dispatches it without permission evaluation, even with the live permission flag enabled. Image tools receive a tool-level prompt, but their local files are not evaluated against Read rules there.

   Evidence: [hub_permission.rs:228](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/hub_permission.rs:228), [hub_permission.rs:309](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/hub_permission.rs:309), [hub.rs:484](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/hub.rs:484). **Inherited; P173 integration dependency.** P174 leaves both hub files untouched, respecting the ownership constraint.

9. **MEDIUM — NEW: Codex/media calls can be denied because of a different file they never open.**  
   The manager applies Fuigo’s `resolve_model_path` to every target. Codex opens absolute paths literally; image tools also do not perform Fuigo’s display-cwd or quote rewriting.

   For example, a legitimate Codex target `/w/public/note'` is additionally judged as `/w/public/note`; a deny on the latter incorrectly refuses the former. In a forked session, a literal Codex/media path under `/display` is also judged under `/real`, despite the reader opening `/display`.

   Evidence: [manager/mod.rs:1825](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/manager/mod.rs:1825), [codex/read_file/tool.rs:382](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-tools/src/implementations/codex/read_file/tool.rs:382), [image_edit/mod.rs:163](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-tools/src/implementations/fuigo_build/image_edit/mod.rs:163). **New versus both `6221893ca` and the recorded v1.0.21 baseline.**

10. **MEDIUM — The manager’s chat/hub prompt omits every read target.**  
    This is separate from direct hub dispatch. The manager constructs the correct ACP title/locations, but `Prompter` drops that update when routing approval through the hub transport. Its payload says only “Read a file” or “Run image_edit,” with no paths. The added hub assertion checks prompt count, not payload contents.

    Evidence: [prompter.rs:772](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/prompter.rs:772), [hub_permission.rs:120](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/hub_permission.rs:120), [read_target_tests.rs:297](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-workspace/src/permission/manager/read_target_tests.rs:297). **Inherited plumbing; P174’s “lists every path” acceptance remains unmet.**

11. **MEDIUM — Directory and glob tools disclose denied descendants.**  
    Codex/Fuigo `list_dir` judge the root and then traverse descendants without per-entry Read checks. OpenCode `glob` similarly enumerates files without managed exclusions; OpenCode directory reads expose children. Listing `/w` can therefore reveal names under `secrets/**` without its deny or ask binding. This is metadata disclosure, distinct from grep’s content reads.

    Evidence: [codex/list_dir/tool.rs:177](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-tools/src/implementations/codex/list_dir/tool.rs:177), [fuigo_build/list_dir/mod.rs:283](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-tools/src/implementations/fuigo_build/list_dir/mod.rs:283), [opencode/glob/mod.rs:175](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-tools/src/implementations/opencode/glob/mod.rs:175). **Inherited from both baselines.**

12. **MEDIUM — File-backed attachment tokens are explicitly exempted.**  
    If `[Image #1]` resolves to `file:///w/secrets/photo.png`, `image_edit` excludes the token from `read_targets`, then reads that file after its separate tool approval. A path-scoped Read deny/ask never sees it. Tokens are restricted to current user attachments, so this does **not** grant arbitrary path selection, but the stated “every local file” guarantee is false.

    Evidence: [image_edit/mod.rs:130](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-tools/src/implementations/fuigo_build/image_edit/mod.rs:130), [image_edit/mod.rs:373](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-tools/src/implementations/fuigo_build/image_edit/mod.rs:373), [placeholder_images.rs:91](/Volumes/Mando/WaylandBots/Fuigo/wt-p174/crates/codegen/fuigo-shared/src/placeholder_images.rs:91). **Inherited path-policy gap, retained deliberately by P174.**

Other requested boundaries checked:

- Ordinary Fuigo multi-file relative/display-cwd resolution, `..`, and stable ordinary symlinks receive the expected checks. The exceptions are above.
- Codex rejects relative paths before reading. Its relative-path manager tests are policy tests; actual read-bypass scenarios require absolute paths.
- Relative image paths are made absolute against **process cwd**, matching their readers. Session cwd still anchors relative policy patterns.
- `image_edit` strips `file://` in both extraction and execution. Video tools treat it as a literal local filename in both places. Data URLs, and video HTTPS references, perform no local file read.
- PreToolUse rewrites are judged correctly. Deduplication is the later rewrite that breaks that guarantee.
- YOLO and `prompt_policy=allow` still override ordinary ask rules; matched denies bind before those shortcuts. These inherited mode semantics qualify the unqualified “an ask prompts” claim.

**Regression comparison:** finding 9 is the new P174 regression against both baselines. I found no new HIGH introduced by these three commits; the HIGH findings are unresolved security gaps, which still prevent acceptance.

This was source-only verification: no Cargo, execution fixtures, or files modified. `git diff --check` passed and the worktree remained clean. The added reader tests compare input-derived headers; the ACP test captures a request and rejects execution. They do not establish that the actual opened targets equal the judged targets.

**NOT-LAND-OK**

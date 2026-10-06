# Cross-Session Memory

Memory lets Fuigo recall facts, decisions, and patterns from earlier sessions. Fuigo indexes the information you save and searches it automatically, so a new session can reuse relevant context.

---

## What Is Memory?

Without memory, each Fuigo session starts fresh: the model knows nothing about previous sessions. When you enable memory, Fuigo can:

- Recall project conventions you explained before.
- Reuse debugging steps that worked.
- Carry architectural decisions forward across sessions.
- Avoid re-asking questions it already has answers to.

Fuigo 1.0.8 enables local workspace memory by default. Global sharing, embeddings,
and automatic model-driven flush/consolidation require explicit configuration.
Fuigo 1.0.7 and earlier defaulted memory off.

---

## Enabling Memory

### Environment Variable

```bash
export FUIGO_MEMORY=1
fuigo
```

### Config File (Persistent)

```toml
# ~/.fuigo/config.toml
[memory]
enabled = true
```

### Force-Disable

To disable memory for the process even when TOML or remote settings enable it:

```bash
export FUIGO_MEMORY=0
```

### Mid-Session Toggle

Toggle memory on or off during a session without restarting:

```
/memory on
/memory off
```

The toggle is session-scoped -- it does not persist to `config.toml`. Toggling off removes access to memory tools but keeps existing files on disk. Toggling on re-initializes memory storage and registers the memory tools.

You can also toggle from inside the `/memory` modal by pressing `t`.

### Priority Order

1. Hidden deprecated compatibility flag, when supplied
2. `FUIGO_MEMORY` env var: `1`/`true` enables, `0`/`false` disables
3. `[memory]` section in effective TOML
4. Managed remote settings
5. Default: enabled locally

### Local-only defaults and explicit sharing

```toml
[memory]
enabled = true
global_enabled = false

[memory.dream]
enabled = false

[compaction.memory_flush]
enabled = false
```

Set `memory.global_enabled = true` deliberately to include the shared global
`MEMORY.md` in automatic retrieval and permit global memory writes. Otherwise,
existing shared files are preserved but excluded; `/remember` saves to the current
workspace. Inspecting or explicitly clearing existing global memory remains available.

No embedding model is selected by default. An explicit `[memory.embedding].model`
opts into that route; a remote model suggestion alone does not enable it. Likewise,
automatic dream and flush runs require their `enabled = true` setting. An application
can set `memory.enabled = false` in its own `FUIGO_HOME/config.toml` or use
`FUIGO_MEMORY=0`. Configuration changes apply when a session is created; the
session-local off/on toggle preserves its original storage root and sharing policy.

---

## How Memory Is Stored

Memory is stored as Markdown files under `~/.fuigo/memory/`:

| Location | Scope | Description |
|----------|-------|-------------|
| `~/.fuigo/memory/MEMORY.md` | Global | Facts that apply across all your projects |
| `~/.fuigo/memory/<project-slug>-<hash>/MEMORY.md` | Workspace | Project-specific conventions and context |
| `~/.fuigo/memory/<project-slug>-<hash>/sessions/` | Sessions | Per-session summaries and logs |

Fuigo suffixes each workspace directory with a hash of the repository's identity (16 hex digits for a remote identity, 8 for a path). The identity is the `origin` remote as `host/org/repo` when the directory is a Git repository with an `origin` remote, or the directory path otherwise. The scheme, user name, port and a trailing `.git` are ignored, so `git@github.com:acme/app.git` and `https://github.com/acme/app` are the same identity, and every clone and worktree of that repository on this machine shares one memory directory. The same `org/repo` on a different host (for example `https://other.example/acme/app`) is a different identity and gets its own directory.

The identity comes from the repository's own `.git/config`. Fuigo cannot tell a genuine clone from a directory whose `.git/config` was copied or edited to name the same `origin` (for example, an archive that ships its `.git` folder). Such a directory shares the memory of that repository. Turn memory off (`FUIGO_MEMORY=0`) when you work in a repository you do not trust.

Earlier versions used `org/repo` without the host as the identity. A directory created that way is moved to the new name the first time it is opened, but only when Fuigo can prove it belongs to this host: everything recorded in it must be readable, at least one project path recorded in it (the `# Project Memory — <path>` header of its `MEMORY.md`, or the workspace recorded with a captured session note) must still exist on this machine with an `origin` of exactly the same `host/org/repo`, and no recorded path may point at a different host. Otherwise the old directory is left untouched, nothing is deleted, and Fuigo prints a one-time notice that names the old directory and the new one (the same notice appears if a proven directory cannot be moved). A `MEMORY_MIGRATE` warning is also written to the log. If the old memory is yours, move its contents into the new directory by hand. The notice is shown once for each old directory and new directory pair, so later starts stay quiet; in the full-screen interface it is printed again when you leave it. A moved directory's old search index is kept aside in a `.pre-p91-index-…` folder inside it, and a new index is built from its Markdown files. Close sessions started by an older Fuigo before you upgrade: a session that is still running keeps writing to the old directory.

An SQLite index supports search within the current workspace directory and, when explicitly
enabled, the shared global `MEMORY.md`. Memory directories of other identities, and recovery
snapshots, are excluded from reads and retrieval, including through symlinks.

Fuigo serializes its memory writes and replaces files atomically, so concurrent appends preserve entries and interrupted replacements leave complete files. On Unix, Fuigo writes memory files with owner-only permissions. Nonempty workspace directories are retained even when they contain curated notes but no session logs.

Search uses:
- **FTS5** provides the default full-text search for keyword matching.
- **vec0** adds vector search for semantic similarity when an embedding model is configured.

---

## Automatic Saves

When a session ends, Fuigo saves a structured metadata summary to that session's daily log. The summary contains:

- Message counts (user, assistant, and tool results).
- Topics: the first few substantive user prompts from the session, up to five.
- The session date and time (UTC).
- Bounded explicit `Fact:`, `Decision:`, `Correction:`, and `Outcome:` lines, plus selected visible assistant completion statements.

Fuigo builds the summary from conversation metadata without an LLM call, without added latency. Fuigo skips the save for trivial sessions -- those with fewer than three substantive prompts, or fewer than 50 bytes of user text.

Captured statements carry their session, workspace, speaker, turn, and observation time. They are historical claims, not independent proof that an assistant's reported outcome occurred. Tool-result bodies and private reasoning are excluded from this capture path. The session ID forms part of a collision-resistant log filename. To turn automatic saves off, set `session.save_on_end = false`. For richer capture of decisions, patterns, and reasoning, use `/flush`.

A conservative filter excludes recognized credential patterns and instruction-injection text from capture and retrieval. It does not detect every possible secret or malicious instruction; keep sensitive material out of memory files.

---

## Saving Rich Knowledge with /flush

For richer capture -- decisions, patterns, debugging workflows, API discoveries -- use `/flush` in the TUI:

```
/flush
```

This triggers an LLM-generated summary of the current session's most important content and writes it to a dated session log. The summary is indexed and searchable in future sessions.

Use `/flush` when you want to preserve important context:
- Before compaction (which discards old conversation turns)
- At the end of a productive debugging session
- After discovering important patterns or conventions

---

## Working with Memory

### Remember

Ask Fuigo to remember something, and it appends the note to a `MEMORY.md` file -- the workspace file for project-specific items, or the global `~/.fuigo/memory/MEMORY.md` for cross-project preferences:

```
> remember to always open PR links after pushing
```

Fuigo records entries as durable statements under organized headings, such as `## Preferences`, `## Project Context`, or `## Debugging`. The file watcher reindexes the change on the next memory search, so the new entry is searchable within the current session.

For a fact that changes, use a stable explicit key, for example `Decision: database = SQLite`, followed later by `Correction: database = PostgreSQL`. Retrieval prefers the newer statement with the same key. This handles explicit keyed updates; it does not resolve every contradiction in ordinary prose.

You can also save a note directly with the `/remember` command:

```
/remember always open PR links after pushing
```

Run `/remember` with no text to enter remember mode, where the next line you type becomes the note. Either way, Fuigo opens a review panel showing the note (with an optional rewritten version you can toggle with `Tab`); the note is written only after you confirm. On save, Fuigo shows `Memory saved to ~/.fuigo/memory/MEMORY.md`.

### Forget

Ask Fuigo to forget something, and it finds and removes the matching entry:

```
> forget the snake_case convention
```

Forget is best-effort: the model searches memory and removes entries that match. For guaranteed removal, edit the files under `~/.fuigo/memory/` directly and delete the entry yourself. To locate a file, open the `/memory` browser and press `y` to copy its path.

Deleted or changed source text is checked before retrieval, without waiting for the watcher. Previously injected memory whose source changed is removed before the next turn. Copies in other source files must be removed separately. Dream retains raw session logs and private recovery versions on disk; recovery versions are excluded from memory retrieval.

### Recall

Ask what Fuigo remembers:

```
> what do you remember?
```

Fuigo searches the current workspace and shared global memory and summarizes what it finds, grouped by source: global preferences, project-specific knowledge, and session history. Use `/memory` to browse the raw files.

### Direct Editing

You can edit memory files directly under `~/.fuigo/memory/`. The file watcher reindexes your changes on the next memory search. Use `/flush` to save the current session now, and `/dream` to consolidate session logs into organized topics.

---

## Browsing Memory with /memory

The `/memory` command opens a modal showing all memory files:

```
/memory
```

Files are grouped by scope:
- **Global** -- cross-project memory (`MEMORY.md`).
- **Workspace** -- project-specific memory (`MEMORY.md`).
- **Sessions** -- per-session summaries, in reverse chronological order.

The modal uses a split-pane layout: the file list on the left, a read-only content preview on the right. The preview updates as you move through the list.

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `↑`/`↓` or `j`/`k` | Move through the file list |
| `PgUp`/`PgDn` | Jump 10 entries |
| `/` | Filter the file list |
| `y` | Copy the selected file's path to the clipboard |
| `x` | Delete the selected session file (press `x` again to confirm) |
| `t` | Toggle memory on or off |
| `Ctrl+F` | Toggle fullscreen |
| `Esc` | Close the modal, or exit filter mode |

The preview pane is read-only. Scroll it with the mouse wheel or by dragging its scrollbar. You can delete only session files, not the global or workspace `MEMORY.md`.

When the memory modal's content area is under 80 columns, the modal hides the preview pane and shows the file list only.

You can also open `/memory` from the command palette.

---

## Memory Notifications

When you save a note with `/remember`, Fuigo confirms in the scrollback:

```
Memory saved to ~/.fuigo/memory/MEMORY.md
```

Background saves — flush, automatic dream, and session-end — run silently. An explicit `/dream` reports its result or why it could not run. Use `/memory` at any time to browse what Fuigo has stored.

---

## Dream Consolidation with /dream

The `/dream` command consolidates scattered memory fragments into organized topics:

```
/dream
```

Dream proposes a consolidated workspace memory from session logs and existing entries. `/dream` requires memory to be enabled. Raw session sources remain available after consolidation, and the previous workspace memory is saved privately under `.memory-recovery/` before replacement. Recovery files are not indexed or injected.

Only one Dream run owns a workspace at a time, with ownership acquired before the model call. Failed or cancelled runs preserve the sources and do not record success; a result is rejected if its input changed while the model was working.

### Auto-Dream

Dream is **off by default**. Turn it on with `enabled = true`, and Fuigo then defers the startup check until the session loop is running and checks periodically. Once enabled, consolidation runs when enough time has passed and enough sessions have accumulated:

```toml
[memory.dream]
enabled = true     # Run automatic consolidation (default: false -- off unless you set this)
min_hours = 24     # Minimum hours between consolidations
min_sessions = 5   # Minimum sessions since the last consolidation
check_interval_secs = 3600 # Also check the gates hourly
```

---

## How Memory Affects Prompts

### First-Turn Injection

On the first turn of each session, Fuigo automatically searches memory for content relevant to the current project and injects it as context. This means Fuigo starts with knowledge from previous sessions without a reminder.

First-turn injection can be configured:

```toml
[memory.initial_injection]
enabled = true     # Enable or disable first-turn injection
min_score = 0.9    # Score threshold for first-turn injection
```

### After Compaction

Memory is also searched after auto-compaction to recover relevant context that may have been discarded.

---

## Memory Search

Fuigo searches memory automatically, but you can also trigger searches manually in the chat:

```
Search memory for "auth middleware patterns"
Read my workspace MEMORY.md
```

The model has access to two memory tools:
- `memory_search` -- Search the current workspace and shared global memory
- `memory_get` -- Read an allowed memory file by path

### Search Scoring

The default embedding model is unset, so memory starts in full-text-only mode. Lexical confidence reflects query coverage, so a lone weak keyword match does not become a high-confidence answer merely because no better result exists. Results are filtered by a minimum score threshold (default: `0.7`).

With an explicitly configured embedding route, search uses normalized vector similarity alongside text confidence. When both signals match, their default weights are `0.7` and `0.3`; a single available signal retains its own confidence. Repeated access can improve ordering but cannot promote an otherwise rejected result past the confidence threshold. Duplicate text is removed from results.

Embedding caches are bound to the endpoint, model, and dimensions. Switching that identity invalidates incompatible vectors while retaining Markdown and lexical search. A subscription login does not supply embedding access, and memory does not silently substitute a paid embedding route; without usable embedding configuration and credentials it falls back to lexical search.

### Source Weights

Each memory source has a weight multiplier applied to its score. All sources default to `1.0`, and you can adjust any of them under `[memory.search.source_weights]`:

| Source | Weight | Description |
|--------|--------|-------------|
| `workspace` | 1.0 | Project-specific memory |
| `session` | 1.0 | Session logs |
| `global` | 1.0 | Cross-project memory |

### Temporal Decay

Session memories decay over time so recent sessions are prioritized:

```toml
[memory.search.temporal_decay]
enabled = true           # Enable time-based decay
half_life_days = 30.0    # Score halves after this many days
```

Only session chunks decay. Global and workspace memories are exempt since they contain curated long-term knowledge.

### MMR (Maximal Marginal Relevance)

MMR re-ranking penalizes redundant results to improve diversity:

```toml
[memory.search.mmr]
enabled = true           # Enable diversity re-ranking
lambda = 0.7             # 0.0 = max diversity, 1.0 = pure relevance
```

---

## CLI Commands

The `fuigo memory` command manages memory from the shell. It has one subcommand, `clear`:

```bash
# Clear workspace memory (MEMORY.md, sessions/, and index.sqlite). This is the default scope.
fuigo memory clear

# The same scope, stated explicitly
fuigo memory clear --workspace

# Clear the global MEMORY.md
fuigo memory clear --global

# Clear both workspace and global memory
fuigo memory clear --all

# Skip the confirmation prompt (-y is the short form)
fuigo memory clear --yes
```

`fuigo memory clear` only clears the current memory folder. If an older version of Fuigo wrote notes into the repository's old memory folder after the move to the host-qualified name, `clear` lists that folder as not cleared, with its path and how to remove it. Fuigo never reads or deletes it.

To edit memory from the shell, open the files in your editor directly -- for example, `$EDITOR ~/.fuigo/memory/MEMORY.md`.

---

## Configuration Reference

### Core Settings (`[memory]`)

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Enable memory. Resolved across layers, highest first: `FUIGO_MEMORY`, the `--no-memory` CLI flag, this config key, a remote feature flag, then the built-in default of `true` |
| `session.save_on_end` | `true` | Write metadata summary on session end |
| `watcher.enabled` | `true` | Watch `~/.fuigo/memory/` for external edits and reindex |

### Index Settings (`[memory.index]`)

| Key | Default | Description |
|-----|---------|-------------|
| `max_chunk_chars` | `1600` | Maximum chunk size in characters |
| `chunk_overlap_chars` | `320` | Character overlap between chunks |

### Embedding Settings (`[memory.embedding]`)

| Key | Default | Description |
|-----|---------|-------------|
| `provider` | `"api"` | Embedding provider (currently `"api"`) |
| `model` | unset | Embedding model name. Unset or `""` uses full-text-only retrieval. |
| `dimensions` | `1024` | Embedding vector dimensions |

### Search Settings (`[memory.search]`)

| Key | Default | Description |
|-----|---------|-------------|
| `max_results` | `6` | Maximum search results |
| `min_score` | `0.7` | Minimum relevance score |
| `vector_weight` | `0.7` | Weight for vector similarity |
| `text_weight` | `0.3` | Weight for BM25 text similarity |

### Initial Injection Settings (`[memory.initial_injection]`)

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Enable first-turn memory injection |
| `min_score` | `0.9` | Score threshold for first-turn results |

### Dream Settings (`[memory.dream]`)

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `false` | Enable automatic Dream consolidation |
| `min_hours` | `24` | Minimum hours between consolidations |
| `min_sessions` | `5` | Minimum sessions since the last consolidation |
| `stale_lock_secs` | `3600` | Seconds before a stale consolidation lock is reclaimed |
| `check_interval_secs` | `3600` | Periodic Dream-gate check interval in seconds. Set `0` to disable periodic checks. |

### Flush Settings (`[compaction.memory_flush]`)

You configure flush under `[compaction]`, not `[memory]`, because it is a compaction behavior.

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `false` | Enable the pre-compaction memory flush |
| `soft_threshold_tokens` | `4000` | Token headroom before the compact threshold that triggers a flush |
| `max_flush_write_chars` | `8000` | Maximum characters the flush may write to memory |
| `flush_model` | unset | Model for the flush turn. When unset or `""`, Fuigo uses the session's primary model. |
| `idle_timeout_secs` | unset | Idle seconds before a background flush. Unset by default, so idle flushes do not run; set a value to enable them, or `0` to disable explicitly. |
| `semantic_dedup_threshold` | unset | Cosine-similarity threshold for de-duplicating flushed content. When unset, defaults to `0.92`. |

### Pruning Settings (`[compaction.pruning]`)

You configure pruning under `[compaction]`, not `[memory]`, because it is a compaction behavior.

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | `true` | Enable tool-result pruning |
| `keep_last_n_turns` | `3` | Number of recent turns whose tool results are never pruned |
| `soft_trim_threshold` | `4000` | Character threshold above which old tool results are soft-trimmed |
| `soft_trim_head` | `1500` | Characters kept from the start of a soft-trimmed result |
| `soft_trim_tail` | `1500` | Characters kept from the end of a soft-trimmed result |
| `hard_clear_age_turns` | `10` | Turn age after which tool results are replaced with a placeholder |

---

## Memory Staleness

When a session memory is old, Fuigo attaches a staleness note to it in search results. Older results get a stronger reminder to verify the current state before you rely on them. These notes help you spot stored facts that might no longer be accurate. Global and workspace memories never receive staleness notes, because they hold curated long-term knowledge.

---

## File Watcher

By default, Fuigo watches its memory locations for external file changes, scoped to the current workspace and shared global `MEMORY.md`. If you edit these files directly (e.g., in your editor), the changes are picked up automatically on the next memory search:

- Created or modified files are reindexed.
- Deleted files have their stale chunks removed from the index.

```toml
[memory.watcher]
enabled = true    # default
```

---

## Troubleshooting

### Memory Not Working

1. Verify memory is enabled: check `fuigo inspect` output.
2. Check `FUIGO_MEMORY` or `[memory] enabled` in effective TOML.
3. Check for `FUIGO_MEMORY=0` or a deprecated compatibility flag overriding config.

### Memory Not Appearing in Sessions

Memory is injected on the first turn. If you started a session before enabling memory, start a new session with `/new`.

### Viewing Memory Files

Use `/memory` in the TUI to browse all memory files with a preview. You can also access them directly:

```bash
ls ~/.fuigo/memory/
cat ~/.fuigo/memory/MEMORY.md
$EDITOR ~/.fuigo/memory/MEMORY.md
```

### Debug Logging

```bash
RUST_LOG=debug FUIGO_LOG_FILE=/tmp/fuigo.log fuigo
grep "memory" /tmp/fuigo.log
```

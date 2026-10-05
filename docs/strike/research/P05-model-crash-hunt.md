# P05 — the `/model` SIGABRT hunt

Packet P05-HUNT (Fable lead, Astra independent, cross-audit). Integration parent `e93beb94c18fca399b763c98f205fb349364b191`.
Fix packet P05b landed on `strike/p05h` (receipt `docs/strike/receipts/R060-p05h.md`).

## 1. What was reported, what the machine recorded

Report: "SIGABRT when using `/model` in the interactive TUI (shipped build), not reproducible on demand."

The Mac that produced the report holds four crash reports for the shipped binary
(`~/Library/Logs/DiagnosticReports/fuigo-native-2026-09-2{5,6}-*.ips`; binary `fuigo 1.0.19 (b156799be642)`,
UUID `3F81817D-…` for three of them, an older build `cd353ecb-…` for one). **All four are the same crash and none
is a TUI `/model` switch:**

| report | lifetime | threads | responsible proc | parent at crash |
|---|---|---|---|---|
| 2026-09-25 06:45:34 | 250 ms | main, tokio-rt-worker, startup-slow-phase, memtrace, reqwest, OTel (no agent) | ghostty | launchd (parent already gone) |
| 2026-09-25 20:56:21 | 10 s | + acp-agent-worker, notify-rs, power-listener (full agent) | com.murage.app (Electron) | launchd |
| 2026-09-25 21:49:58 | 700 ms | as first | ghostty | launchd |
| 2026-09-26 15:29:17 | 450 ms | as first | ghostty | launchd |

Every report: `EXC_CRASH (SIGABRT)`, `abort() called`, faulting thread **main**, frames

```
__pthread_kill ← abort ← std::process::abort ← __rust_abort ← rust_panic ← std::panicking::panic_with_hook
← core::panicking::panic_fmt ← std::io::stdio::_print ← fuigo_pager::async_main::{{closure}}::{{closure}}
← tokio …::block_on ← fuigo_pager::main
```

That is the panic `print!`/`println!` raise when the write to stdout fails ("failed printing to stdout"), and
`panic = "abort"` (Cargo.toml `[profile.release]`) turns it into SIGABRT. Disassembling the shipped binary at the
return address (`async_main::{{closure}}::{{closure}}+6724`, three reports) shows the `_print` call receiving the
compact `fmt::Arguments` for the constant `"You are not authenticated.\n"` (pointer into the string pool, length tag
27·2+1 = 55). That literal exists once: `crates/codegen/fuigo-pager/src/models.rs`,
`AuthStatus::NotAuthenticated => println!("You are not authenticated.")` in `list_available_models`, the
**`fuigo models` CLI subcommand**, dispatched by `async_main` (`Command::Models`). It is the first line the command
prints, before the agent starts: hence 250–700 ms lifetimes with no agent thread. The Electron-spawned report is the
older build at a different offset in the same function (another `println!` in `async_main`'s dispatch); same class.

`parentProc = launchd` in all four means the process that spawned fuigo had already exited when fuigo wrote: its
stdout pipe had no reader, the write returned `EPIPE` (SIGPIPE is `SIG_IGN` in Rust binaries, kept so on purpose by
`app/signal_handler.rs`), and `println!` panicked.

No crash report exists for a `fuigo-native` TUI process, and no `panic` entry exists in `~/.fuigo/logs/unified.jsonl`.
The "/model" in the report is the `fuigo models` command.

## 2. Reproduction (Beast, Linux, debug build at the parent e93beb94 — `panic = "abort"` in dev too)

`epipe.py`: spawn the binary with stdout = a pipe whose read end is already closed, empty `FUIGO_HOME`.

| command | parent e93beb94 | tip f2df1fa0 |
|---|---|---|
| `fuigo-pager models` | **signal 6**, stderr `thread 'main' panicked at …/std/src/io/stdio.rs:1165:9: failed printing to stdout: Broken pipe (os error 32)` | exit 0, 0.31 s |
| `fuigo-pager sessions list` | **signal 6**, same panic | exit 0 |
| `fuigo-pager --version` | exit 1 `Error: Broken pipe` (already used `write_version(&mut stdout.lock())?`) | unchanged |
| `fuigo-pager completions bash` | clap_complete `.expect("failed to write completion file")` → abort | exit 0 |
| `fuigo-pager login --provider chatgpt --status` | `println!("chatgpt: signed out")` in fuigo-shell → abort | exit 0 |
| `fuigo-pager mcp doctor` | 16 raw `println!` in `fuigo-shell/src/mcp_doctor.rs::print_report` → abort | exit 0 (tip ec2458cd) |
| `fuigo-pager sessions list` with stdout = `/dev/full` (ENOSPC, not a gone reader) | panic → abort | exit 1, one `fuigo: stdout write failed` note (tip ec2458cd) |

The TUI itself was also driven for real in tmux (120×40, private home, API-key auth, bogus base URL) through 32
scripted steps: `/model` dropdown, Enter with no args, full names with spaces and parentheses, `/m`, effort
sub-menu by typing and by Tab, unknown model, rejected effort, dropdown open through 30×8 and 12×4 resizes, the
zero-turn harness rebuild to an OpenAI (codex) model and back, switching after a failed first turn, `/new` then
switching. No crash, no panic in the log (`drive1.log`, `drive2.log` in the lane).

## 3. The `/model` call graph (for the record)

Pager: `slash/commands/model.rs` (`suggest_args` → `detect_effort_phase`/`build_model_items`/`build_effort_items`;
`run` → `Action::SetDefaultModel` | `Action::SwitchModel`) ← `slash/mod.rs` dropdown ranking, or `app/modals.rs`
ArgPicker (palette / Ctrl+M) → `dispatch/router.rs` → `dispatch/settings/setters.rs::set_default_model`
(`set_current`, toast, `Effect::PersistSetting{default_model}` + `Effect::SwitchModel`) → `effects/mod.rs`
(`acp::SetSessionModelRequest`) → `TaskResult::SwitchModelComplete` → `dispatch/session/lifecycle.rs::
handle_switch_model_complete` (scrollback block, `Effect::PersistPreferredModel`, queue drain). Session-less:
`deferred_model_switch` applied in `on_session_created`; dashboard: `stage_dashboard_model`.

Shell (embedded in the TUI process by default — `[cli] use_leader` is off unless set, see `app/mod.rs`
`resolve_leader_mode`; so a shell panic *would* abort the TUI): `acp_agent.rs::set_session_model` →
`set_model_gated` (`resolve_model_id`, `user_selectable`) → `handlers/model_switch.rs::apply`
(`harness_switch_decision` → Keep | Reject | **Rebuild** at turn 0 when the target's `agent_type` is incompatible,
e.g. an OpenAI slug inferred as `codex`) → `SessionCommand::SetSessionModel` → `acp_session_impl/model_switch.rs::
handle_set_session_model` (sampling config, credentials, prompt rewrite, `PersistenceMsg::CurrentModel`, family-switch
compaction when `model_family` differs) and `handle_rebuild_agent_for_definition` (`*self.agent.borrow_mut()`,
MCP re-registration, zero-turn prefix rewrite).

## 4. Candidate table

| # | site | trigger | verdict | evidence |
|---|---|---|---|---|
| C1 | every `println!`/`print!` on a CLI path: `fuigo-pager/src/{models,sessions_cmd,mcp_cmd,plugin_cmd,memory_cmd,trace_cmd,worktree_cmd/mod,completions_cmd}.rs`, `app/session_startup.rs`, `fuigo-pager-bin/src/main.rs`, `fuigo-shell/src/auth/subscription/{mod,inference}.rs`; plus clap_complete's own `.expect` on the writer | stdout reader gone (`| head`, parent exited, Electron host closed the pipe) → `EPIPE` → panic → abort | **CONFIRMED** | four crash reports + disassembly (§1); live repro at parent for 4 commands (§2); Astra: "C1 — CONFIRMED" |
| C2 | `acp_session_impl/model_switch.rs:244` `*self.agent.borrow_mut() = new_agent` (zero-turn harness rebuild from `/model`) vs `self.agent.borrow()` held across `.await` in `compaction.rs` 1341/1353–1375/1579–1620 | a manual `/compact` task (`run_loop.rs:1114`, spawned, sets neither `running_task` nor the config lock) suspended at a bridge await while a turn-0 `/model` rebuilds | PLAUSIBLE, not reproduced | Astra found the concrete overlap; needs compactable history at turn 0 (a resumed session) plus the race. Not the recorded crash (wrong frames). Proposal P2 |
| C3 | family-switch compaction: `compaction.rs` `unreachable!("ladder only steps forward")`, `take_last_success().expect(…)` | `/model` across `model_family` values with model-minted history | REFUTED | `next_stage` can only be `VerbatimFitted`/`Lossy`/`None`; success stores the output before `Ok` (`full_replace_compaction.rs:154`); user's catalog has `model_family = None` everywhere, so `is_family_switch` is false (Astra; verified) |
| C4 | `slash/commands/effort_levels.rs:67` `char::from(b'a' + idx as u8)` | ≥160 reasoning-effort options from the server | debug-only (release wraps; no shipping profile sets `overflow-checks`) | Cargo.toml profiles; Astra concurs. Proposal P3 |
| C5 | ratatui `set_span`/`set_line` in `views/picker.rs`, `views/modal_window.rs`; `Buffer::index_of` panics outside the area | `/model` ArgPicker at widths 0–20, resize with the picker open | REFUTED for this path | `render_modal_window` returns `None` below 20 cols / 6 rows and clamps; rows check remaining height; slash dropdown uses `set_line_safe` and has tiny-geometry tests; tmux 30×8 and 12×4 runs clean |
| C6 | `slash/mod.rs` `text[start..cursor.min(args_end)]`, `text[1..query_end]` | cursor byte offset inside a multi-byte char | REFUTED for the current producer | cursor comes from `TextArea::cursor()`; `EditBuffer` normalises to grapheme boundaries (`fuigo-ratatui-textarea/src/editor.rs:299,519–559`); `/model` itself guards `is_char_boundary` (`model.rs:115`) |
| C7 | `agent_ops.rs:1992` `.expect("resolve_catalog_key returns a key present in models")` | id resolves by `.model` scan but key absent | REFUTED | one owned catalog snapshot for both lookups |
| C8 | `session_config.rs:167` `&effort_options[0]` | empty effort menu | REFUTED | guarded by `!effort_options.is_empty()` |
| C9 | `dashboard.rs:801` `block_in_place(Handle::current().block_on(…))` | `/cd` location picker, not `/model` | out of path | multi-thread runtime; noted only |
| C10 | `fuigo/models/update`, model cache load, config write-back (`persist_models_default`, `update_config`) | stale/corrupt cache, concurrent writes | REFUTED | serde with defaults, loader errors propagate, file + process locks |
| C11 | stack overflow in the switch future on the ACP worker | deep frames | not supported | session threads get 8 MiB (`spawn.rs:2649`); the 16 MiB test requirement is about full turn futures |

## 5. Astra's independent hunt and the cross-audit

Round 1 (independent, no hypotheses given, 396k tokens): "no confirmed real-input panic explaining the release abort
in this checkout"; ranked (1) unproven stack exhaustion in family-switch compaction, (2) raw ratatui draws in
picker/modal_window, (3) the debug-only `b'a' + idx` overflow, (4) compaction `agent.borrow()` across awaits vs the
rebuild `borrow_mut` ("HIGH that borrows cross await; LOW for reachable collision"), (5)–(22) invariant-protected or
ruled out; upstream changelogs 0.2.68 / 0.2.94 record *earlier* fixes for completion-menu resize and filtered-list
shrink crashes, already in tree; no later `/model` abort fix upstream. Verdict line: "Single most likely cause:
undetermined — naming stack overflow, Unicode slicing or resize as the cause would exceed the evidence found."
(Its first attempt was blocked by the provider's content filter on the words "crash hunter"/"SIGABRT"; the second
brief was reworded as a reliability review.)

Round 2 (refutation of the table above with the crash-report evidence, 223k tokens): "**C1 explains the recorded
`_print` panic.** … C1 — CONFIRMED … C2 — PLAUSIBLE, with a concrete concurrency gap [manual compaction task] …
C3 — REFUTED for these two panic sites … C4 — CONFIRMED as debug-only … **Refuted as this release SIGABRT cause** …
C5 — REFUTED for the inspected `/model` ArgPicker path … C6 — REFUTED for the current prompt producer." Its fix
critique raised three HIGHs (clap_complete's `.expect`, the three fuigo-shell subscription prints, silent non-EPIPE
failures reporting success) and three MEDIUMs (no `process::exit` in a macro, retry budget / flush, test deadline
and a live-reader control); all were taken into the second commit.

Round 3 (diff audit of `e93beb94..f2df1fa0`, 144k tokens): REJECT — one HIGH (the `fuigo mcp doctor` report printer in
`fuigo-shell/src/mcp_doctor.rs` still had 16 raw `println!`), plus the Sentry guard skipped by the hard-failure exit,
the legacy `login`/`logout` `finalize_and_exit(0)`, test env isolation, the spawn-lint exception, and end-to-end
hard-failure coverage; all six went into the third commit `ec2458cd`. Round 4 re-audited that diff (see the receipt
for the verdict). Full texts: `docs/strike/audits/p05h-astra.txt`.

## 6. What remains unknown

- The reporter's framing ("in the interactive TUI") does not match the only recorded crashes; if a TUI-process
  abort also happened it left no `.ips` and no log line. With P05a's crash handler on, a recurrence would record
  the panic message and the thread; the discriminator is simple: `std::io::stdio::_print` on the main thread with a
  sub-second lifetime is this bug (now fixed); anything inside `fuigo_shell::…::model_switch`,
  `handle_rebuild_agent_for_definition` or `compaction` on the session thread would be C2.
- Which `println!` the Electron-spawned (older build) crash hit cannot be symbolicated without that binary; every
  `println!` in `async_main` is now on the best-effort path, so the class is closed regardless.

## 7. Proposals (not in this packet's ownership)

- P1 — `fuigo-shell` headless/other crates still use raw `println!` outside CLI paths (e.g. `headless.rs` keeps its
  own BrokenPipe policy, fine); a workspace-wide `clippy::print_stdout` deny with allow-lists would stop regressions
  at compile time instead of the source pin.
- P2 — Harden C2: in `compaction.rs` clone the tool-bridge handle (`self.tool_bridge_handle()`, as `reminders.rs`
  does) instead of holding `self.agent.borrow()` across `render_prompt(...).await`, or make the manual-compaction task
  take the model-switch config lock.
- P3 — `effort_levels.rs:67`: cap the sort prefix (`idx.min(25)`) or widen it; harmless in release, a debug panic
  with an absurd server menu.

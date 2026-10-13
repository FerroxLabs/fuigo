# R-1026 - W-SANDBOX (packet 26-1, decision 67)

Behaviour: Windows only. A sandbox profile other than `off` on Windows (where no sandbox can exist): keep running, warn at every start.
Linux and macOS, with or without `enforce`: unchanged from base `dd2978d5` (existing fail-closed refusal and messages); the new text is never produced there.
Text (exact): `Sandbox profile <p> is set but sandboxing is not available on Windows: commands and file tools run unsandboxed.`

## Where
- Decision + text: `fuigo-sandbox/src/lib.rs` `unavailable_warning_for(profile, on_windows)` / `unavailable_warning()` (`cfg!(windows)`). The "on this build" variant and `can_enforce` are removed.
- stderr (all modes, before any model request): `fuigo-shell/src/config/mod.rs` `apply_sandbox`.
- `fuigo wrap` (returns before `apply_sandbox`): `fuigo-pager-bin/src/main.rs` Wrap branch calls `fuigo_shell::config::wrap_sandbox_warning_line()` (returns `None` on non-Windows without reading config; pure core `wrap_sandbox_warning_line_for`).
- TUI + ACP: `agent_ops.rs` `announce_config_notices` -> existing `NotifyConfigNotice` / `ConfigNotice`. `/status`: `Sandbox warning` field in `session_info_fields`.
- Headless `plain`: `fuigo-pager/src/headless.rs` `plain_lifecycle_line` drops the session notice that equals the startup stderr line, so the text prints once. `json` / `streaming-messages-json` keep their one stderr notice line; `stream-json` keeps its one `config_notice` object (unchanged).

## Unix unchanged from base (how checked)
Read `git diff dd2978d5` for every non-Windows path: on unix `unavailable_warning_for` returns `None` (`!on_windows`), so the `apply_sandbox` print, the `announce_config_notices` send, the `/status` field, the plain filter and the wrap warning (early `!cfg!(windows)` return, no config read) are all no-ops. The apply/refuse code (`config/mod.rs` refusal, `lib.rs` apply/bwrap plans) is not in the diff.

## Early-return paths (no warning needed)
`--version`, `doctor`, subscription commands, mermaid and voice workers run no agent tools: left alone.
`workspace_server` (`fuigo-workspace/src/bin/workspace_server.rs`): the remote-sandbox ToolServer reads `FUIGO_SANDBOX_PROFILE` itself (default `workspace`), never calls `set_configured_profile`, and already logs `Sandbox could not be applied (unsupported platform)` / `NOT active` via tracing when apply fails; it is a Linux remote-sandbox server, not a user-configured profile, so no stderr warning was added.

## Docs
`18-sandbox.md` and `release-notes-1.0.26.md` say Windows only. The pre-existing sentence on what continues without enforcement is corrected: on Linux/macOS only `off` and `devbox` continue; every other profile (and any custom profile) refuses to start (`config/mod.rs` `requires_protection`).

## Tests
`fuigo-sandbox` unavailable_warning_* (Windows text exact, unix none, off none, scrub); `fuigo-shell` `wrap_prints_the_sandbox_warning_on_windows_only`, stderr-line tests; `fuigo-pager` `plain_mode_prints_the_sandbox_warning_once`, `/status` field test. Results: see the packet report.

# Fuigo 1.0.21 release notes

This release follows 1.0.20. If you are upgrading from 1.0.17, 1.0.18 or 1.0.19, the notes for 1.0.18 to 1.0.20
also apply.

## Before you upgrade

- **Close every running Fuigo session first** (TUI, `fuigo -p`, editor and desktop-app sessions, leaders).
  Workspace memory moves to a new folder name on first use (B1), and a session still running an older Fuigo keeps
  writing the old folder. Older and newer Fuigo also do not share all file locks (K9), so do not run both at once.
- If you sign in to xAI with a subscription and set `FUIGO_ALLOW_UPSTREAM_HOSTS=1` to make it work, remove it (B12).
- If you connect Fuigo to a relay that FluxRouter does not operate, add it to `[relay] trusted_origins` (B8). This
  now includes TUI session sharing: a self-hosted relay you already sync to stops syncing until you add it (B31).
- If a project's config, a plugin, a project `.mcp.json`, your editor's MCP settings or a server you added with
  `/mcps Add` names `FUIGO_API_KEY`, move that entry to `~/.fuigo/config.toml`, or export the key before starting
  Fuigo (B32).
- Install with `npm i -g fuigo`, or update with `fuigo update`. If npm stops the install with a message that install
  scripts are blocked, run `npm i -g fuigo --allow-scripts=fuigo`. If you install by hand with npm while Fuigo is
  running, run `fuigo leader kill` afterwards so the shared session restarts on the new version.

---

## Security fixes

- **S1. Your provider keys stay out of the programs Fuigo starts.** Fuigo no longer passes your provider keys,
  including `FLUX_API_KEY`, `ANTHROPIC_AUTH_TOKEN` and any variable your config names as an `env_key`, to commands
  the model runs, hooks, MCP servers or language servers. To give one of them a key on purpose, put it in that
  server's or hook's `env`, or in `[shell_environment_policy] set`. If you add a key variable to your config while a
  session's shell is running, that shell restarts in the same directory before its next command; a variable you
  once named as a key stays hidden from tools until Fuigo restarts.
- **S2. Identity goes only to FluxRouter.** Your account id, team, machine id, host name, e-mail and client labels,
  in request headers and request bodies, are sent in full only to FluxRouter-operated services. A third-party model
  provider (OpenAI, Anthropic, OpenRouter and others) receives none of them. A registry, session backend, storage
  proxy or collector you run yourself receives no identity, or a stable per-server pseudonym. A default install,
  where those services are unset, sees no change. Operators: see B9.
- **S3. Your sign-in session token goes only where you configured it.** The token is sent to a model endpoint or a
  service (settings, storage, image, video, web search, hub, relay) only over https or wss, to an origin that is
  FluxRouter-operated or exactly matches your configuration, never to a URL with an embedded login, and never to
  this machine's loopback address. Otherwise the request is refused with a "Session token not sent" message. API
  keys are not affected.
- **S4. Uploads are decided by where they go.** Session archives, traces, diagnostics, review-comment records,
  share bundles and heap profiles go only to a FluxRouter-operated storage proxy or to your own Direct GCS or S3
  `trace_upload_bucket`. Any other storage proxy receives none of them; Fuigo tells you once (on exit in the
  full-screen interface, or, when the upload ran in a shared session (leader), as a note in the TUI) and your local files are untouched. To keep sending traces to your own storage, set a
  `gs://` or `s3://` `trace_upload_bucket`.
- **S5. A hub or relay you run yourself learns less about you.** It no longer receives this machine's host name,
  machine id or who is signed in (e-mail, name, picture, team and organisation ids and names). It sees the machine
  under a new, stable, per-hub or per-relay pseudonymous id once after upgrading. FluxRouter hubs and relays and
  local clients are unchanged.
- **S6. A relay you run yourself can no longer ask for credentials.** When Fuigo is bridged to a relay that
  FluxRouter does not operate, the relay can no longer ask the agent for your session token or API key, and the
  agent no longer sends it secret values: cloud-environment secrets, variables and scripts, MCP server commands,
  arguments, URLs and environment values, hook commands and URLs, and the environment of terminals it asks the relay
  to open. `fuigo agent serve` with an empty secret no longer accepts connections without one.
- **S7. Sign-in tokens go only to your identity provider's own address.** Fuigo sends authorization codes and
  refresh tokens only to an https token endpoint on your issuer's own address and never follows a redirect away
  from it (shell sign-in and the workspace hub). Subscription sign-in connections reach only their provider's own
  endpoint. A token refresh that this rule refuses is not retried, so the refresh token is not sent again and again; your
  stored sign-in is kept and the reason is shown. See B11 for what this changes.
- **S8. Credentials echoed back in errors are hidden.** API keys and other credentials that a provider echoes back
  in an error are shown as `<redacted>` on screen, and are kept out of log files, telemetry, session files and
  failure-hook input. Fuigo's own decisions about an error (credit limit reached, free usage used up, sign in
  again, disk full, which upgrade offer to show, the headline of a failed turn) no longer depend on how its text was
  redacted, including for a turn that finishes while you are away. `fuigo -p` no longer prints a credential a provider
  echoed back, in plain, JSON, streaming-JSON or structured-output errors. Trace and turn uploads, the memory archive,
  `fuigo trace` exports and workspace uploads are scrubbed of credentials, keys and PEM blocks before they leave your
  machine (see K24 for keys that were re-encoded first).
- **S9. A mistyped subagent tool list no longer grants every tool.** An unknown name in a subagent's tool
  allowlist used to give it the full toolset, terminal included; unknown names now grant nothing, and an error log
  line names them. Fix the names in the agent's tool list.
- **S10. Memory is harder to poison.** The memory filter now catches reworded override instructions, spacing and
  zero-width tricks, and GitHub, AWS, Slack and Google tokens, while ordinary notes are kept. This includes text with
  its letters spaced or dotted apart (`i g n o r e   a l l ...`); notes that merely contain lone letters (`Grades
  used: A B C D F`) are kept. A repository's
  `AGENTS.md` can no longer remove your own `~/.fuigo/AGENTS.md` rules from the prompt, and the first-party MCP
  agent-id header is only ever sent to a designated server on this machine.
- **S11. Your saved API key is no longer in Fuigo's environment.** Fuigo no longer copies the key you saved (at the
  prompt, in `~/.fuigo/auth.json` or through `fuigo/setApiKey`) into its own environment, so programs it starts
  (terminals, `!` commands, git and gh, your auth helper, the status line, notification hooks) no longer see it. A
  key you export as `FUIGO_API_KEY` before starting Fuigo is used exactly as before. As in 1.0.20, hooks, MCP servers
  and the model's commands never inherit it; S13 lists the other programs that no longer do. To hand the saved
  key to one MCP server, hook or model on purpose, name it in that place's configuration (B28).
- **S12. Logs and errors show less of your credentials.** Diagnostic logs identify a credential by a short
  fingerprint (`sha256:ab12/len=40`) instead of its last characters. Debug logs list request header names without
  their values, and logged URLs no longer show passwords or query-string values. A login embedded in a URL no longer appears in a
  log line or in the headless 401 error. When a provider's response cannot
  be parsed, the error says where (`Data error at line 1 column 347`) instead of quoting the response. `fuigo trace`
  prints `Deploy: configured` instead of part of the deployment key. Errors from the external sign-in command name
  it by fingerprint instead of repeating its command line.
- **S13. Fuigo's own secrets stay out of every program it starts.** Besides your provider keys (S1), Fuigo no longer
  passes its own secrets to commands the model runs, `!` commands, editor-client terminals, hooks, MCP and language
  servers, search tools, workspace search or an auth-provider helper: `FUIGO_AGENT_SECRET`, `FUIGO_AUTH`,
  `FUIGO_AUTH_PATH`, `FUIGO_DEPLOYMENT_KEY`, `FUIGO_EXTRA_AUTH_KEY`, `FUIGO_TRACE_UPLOAD_CREDENTIALS_FILE`, the OTLP
  header variables (`FUIGO_INTERNAL_OTLP_HEADERS`, `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_EXPORTER_OTLP_LOGS_HEADERS`,
  `OTEL_EXPORTER_OTLP_METRICS_HEADERS`) and the telemetry tokens. A variable an MCP server's `bearer_token_env_var`
  or client-secret setting names is likewise hidden from every other program (for example `gh` in a `!` command
  loses a `GITHUB_TOKEN` that you set up for an MCP server), and `!` commands and client terminals now also lose
  Fuigo's own API keys (`FUIGO_API_KEY`, `FUIGO_CODE_API_KEY`, `FLUX_API_KEY`) and every variable your config names as a
  credential (a model's `env_key`, an MCP `bearer_token_env_var` or client secret). Other providers' keys you export
  yourself (for example `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`) are still passed to them (K4).
  Git, jj, direnv,
  `$EDITOR` and `$PAGER`, sign-in and identity commands, the status line, notification hooks and `fuigo wrap` no
  longer inherit Fuigo's own secrets (`FUIGO_API_KEY`, `FUIGO_AGENT_SECRET`, `FUIGO_AUTH`, the telemetry keys); your
  own credential variables, including a name your config registers for an MCP server (such as `GITHUB_TOKEN`), still
  reach them, so git credential helpers work as in 1.0.20. *What to do:* to give one of them to a program on
  purpose, name it in that server's or hook's `env`, or export it under another name.
- **S14. Credentials stay out of event logs and feedback archives.** Credentials Fuigo sent, and the keys it holds,
  read `<redacted>` in `events.jsonl` (including an MCP server's undecodable reply) and in every file of a `/feedback`
  archive, raw command output included. The archive also redacts strings shaped like a credential that Fuigo never
  saw (an old, rotated key, for example). The user name and password in `HTTPS_PROXY` no longer appear in relay logs
  or errors, and a relay proxy URL with `@` after a `/`, `?` or `#` is refused. A private key split across several
  session records, or broken off and followed by terminal colour codes, is now also redacted in the archive. Session
  files are created readable by you only (mode 0600) and are tightened when written, and so are forks, backups,
  compaction summaries pulled from remote storage and the session lock files (on Windows an owner-only access list).
  On Unix, every file Fuigo writes in a session folder is owner-only (0600) in an owner-only (0700) folder: terminal
  `call_*.log` files, client-terminal logs, `prompt_history.jsonl`, `session_search.sqlite` and its
  `-wal`/`-shm`/`-journal` files, lock files, workflow journals, resume, goal and sub-agent state, and pasted images. A
  file an older version left 0644 is tightened the next time Fuigo writes it. The npm installer writes `config.toml`
  0600. On a home folder that cannot change permissions (vfat, exFAT, some SMB and FUSE
  mounts) sessions and the event log still save: the tightening is skipped with one warning.
- **S15. MCP sign-in tokens go only to the provider's own address.** MCP OAuth now sends authorization codes, refresh
  tokens and client secrets only to a token endpoint on the authorization server's own origin, or to the built-in
  Google pair, the same rule as the shell's sign-in (S7). Server metadata that names any other token endpoint is
  refused with a message saying so; an editor is told why a sign-in was refused (token endpoint on another origin,
  cross-origin redirect, issuer mismatch, blocked address) instead of "Authentication failed", and the reason never
  contains a code, token, secret or query string. See B33.
- **S16. Only your own files can hand out your saved key.** Exactly these files may name
  `FUIGO_API_KEY`: `config.toml`, `managed_config.toml` and `requirements.toml` in `~/.fuigo` (or `$FUIGO_HOME`; the
  two managed files there are the copies Fuigo keeps in sync with your organisation's console), `managed_config.toml`
  and `requirements.toml` in `/etc/fuigo`, `~/.claude.json`, `~/.cursor/mcp.json`, and hook files whose real path is
  under `~/.fuigo/hooks/`. Nothing else can: not hooks in `~/.claude/settings.json` or `~/.claude/settings.local.json`,
  `~/.cursor/hooks.json`, a `hooks-paths` directory outside `~/.fuigo/hooks/`, or a link in `~/.fuigo/hooks/` to a file
  elsewhere, not a project's config, a plugin, a project `.mcp.json`, a worktree, a `FUIGO_CONFIG_PATH` file or any
  other file under `~/.fuigo`, not an MCP server an editor or app sends (`session/new`, `session/load`, `mcp/upsert`,
  so an editor's project settings and `/mcps Add` too), not a hub client's `workspace.configure_mcp` server, and not
  an agent definition's inline `mcpServers` entry or frontmatter hooks. Those sources cannot reach the key by a
  `${FUIGO_API_KEY}` reference, by a variable that holds it, or through an OAuth or bearer setting, even when
  `FUIGO_API_KEY` is exported. A server from those sources that carries the key's value itself, not only a
  reference to it, loses it too. Editors that forward your own MCP servers no longer change which definition runs
  after a folder-trust grant or a plugin reload: your own server keeps its name and its saved-key reference. The
  reference is removed and a note naming the source reaches that session (a note in
  the TUI, a warning on stderr or in `streaming-json` when headless). Your own servers keep working when the TUI or
  headless mode forwards them. An MCP OAuth client setting applies only to the enabled server definition it was
  configured with. A key handed to a hook's child programs is covered by the error redaction of S8. See B32, B35.
- **S17. A pulled session cannot point outside its folder.** A session pulled from remote storage can no longer
  name a compaction checkpoint file outside its own session folder, including sessions an older Fuigo already
  pulled. A checkpoint (or a fork's copy of one) that is a symlink or any other non-regular file is no longer read.
  Checkpoint reads stay beneath the session folder without following links on every platform: on Windows each folder
  on the path is held open and checked until the file is open, so a folder swapped for a link or junction in between
  cannot redirect the read.

## Behaviour changes you will notice

Each item says what changed and what to do.

- **B1. Workspace memory is now kept per host, organisation and repository.** The same repository name on another
  host gets separate memory. Fuigo moves an existing memory folder to the new name automatically only when it can
  prove the folder belongs to that repository; otherwise the old folder stays where it is and Fuigo shows a
  one-time notice naming the old and new folders. *What to do:* close older sessions before upgrading; if you see
  the notice and the old folder is yours, move it to the new name by hand. Run untrusted repositories with
  `FUIGO_MEMORY=0`. Memory blocks in the prompt now carry a per-install marker kept in
  `~/.fuigo/.memory-context-nonce`. In a shared session the notice is shown once in the TUI, as a note in the session
  you are looking at, or printed when you quit if no session was open.
- **B2. `/dream` leaves filtered lines out of the rewritten `MEMORY.md`.** One rejected line no longer breaks a
  whole memory file, and `/dream` says why it skipped something. *What to do:* nothing; the previous file is kept in
  the project's `.memory-recovery/` folder if a line you wanted was dropped. `/dream` also says so when it cannot run
  (memory off, or no session logs) instead of staying silent.
- **B3. Crash reports are on by default and stay on your machine.** If Fuigo crashes, the next start tells you
  where the report is (`~/.fuigo/crash/history/`). Nothing is uploaded. *What to do:* to turn it off set
  `[diagnostics] crash_handler = false` or `FUIGO_CRASH_HANDLER=0`.
- **B4. Headless runs report denials with their own exit codes.** `fuigo -p` exits **3** when the run ended at a
  permission or token-budget denial, prints one line with the remedy on stderr, and adds a `permissionDenied`
  record to every output format; a denial the model recovered from exits 0 with a notice. It exits **4** when Fuigo
  could not start at all ("Fuigo never started, nothing was run"). Budget limits now arrive as typed denials (`error_kind: execution_incomplete`,
  `data.code: execution_budget_denied`, `data.rule`) and exit 3: the budget refusing the next model request, the
  model-call limit (`FUIGO_MAX_MODEL_CALLS`) reserving the last call for the final answer (whether the model answers
  in it, calls a tool in it, or a Stop hook or goal continues after it), and the runtime limit
  (`FUIGO_MAX_RUNTIME_SECS`, or an execution's or parent's deadline) passing while a request is in flight or before it
  is sent (a few paths are not typed yet; see K25). A prompt sent after the runtime limit expired now fails
  with -32603 instead of -32602. *What to do:* scripts should treat exit 3 as "blocked" and exit 4 as "never
  started"; ACP clients should match `data.code` and `data.rule`, not `error_kind: api`. Remedies name the real
  flags `--allow` and `--deny`. `--allow Bash` lets the shell tool run, but no `--allow` rule covers a shell command
  that writes a file by redirect (`> file`); that is a deliberate write floor. Run such commands with
  `--always-approve` (deny rules still apply) or under `--permission-mode auto` if its classifier approves them, or
  have the model write with its file tools.
- **B5. The Anthropic Messages backend works as documented.** The default output limit is now 32,000 tokens
  (older Anthropic models rejected 128,000), and the `anthropic-version` header is added when you did not set one.
  *What to do:* if replies are cut short, raise `max_completion_tokens` in `[model_providers.<id>]`.
- **B6. Hooks and MCP servers that need a key must be given it.** (See S1.) *What to do:* a hook or MCP server that
  relied on inheriting `$FLUX_API_KEY` or another configured key variable needs that variable in its own `env`, or
  in `[shell_environment_policy] set`. `!` commands you type yourself are unchanged.
- **B7. The session token is not sent to cleartext, loopback or unconfigured addresses.** (See S3.) *What to do:*
  point `[endpoints]` at an https origin (same scheme, host and port) for any gateway that needs the session token.
  A local `http://localhost` gateway still receives `FUIGO_API_KEY` and per-model keys. Hubs, relays and auxiliary
  services on `http://`, `ws://` or loopback addresses (local development) no longer receive it: use https or wss,
  or an API key.
- **B8. Relays that FluxRouter does not operate need your opt-in.** If you connect `fuigo agent headless` or
  `fuigo agent leader` to such a relay (`FUIGO_WS_URL`, `--fuigo-ws-url`, `fuigo_com_config.fuigo_ws_url`), Fuigo
  refuses to connect until you trust it. *What to do:* add `trusted_origins = ["https://your-relay.example"]` under
  `[relay]` in `~/.fuigo/config.toml` (project and managed settings cannot supply it), or set
  `FUIGO_TRUSTED_RELAY_ORIGINS`. Through such a relay, MCP servers, hooks and cloud environments appear without
  their secret fields, MCP setup cannot be finished, and terminals it opens run without the session environment.
  `fuigo agent --leader headless --fuigo-ws-url URL` now honours the URL (it was ignored).
- **B9. Operators of your own services see machines and accounts under new ids once.** (See S2, S5.) *What to do:*
  if you run your own registry, session backend, storage proxy, collector, hub or relay and key rows on raw ids,
  compute the new keys with the published recipe (the `destination_pseudonym` documentation) and migrate. A hub
  that told local from sandbox servers by host name loses that key. Self-hosted gateways that keyed on Fuigo's
  identity headers no longer receive them; there is no opt-in.
- **B10. Uploads to a third-party storage proxy are withheld.** (See S4.) *What to do:* set a `gs://` or `s3://`
  `trace_upload_bucket` to keep traces. The one-shot `/feedback` session archive is offered only through a
  FluxRouter-operated proxy.
- **B11. Some sign-in setups stop working.** Identity providers that issue tokens from a different host than their
  issuer, such as Amazon Cognito user pools, can no longer sign in or refresh (`fuigo login` says why before the
  browser opens); Google works through a built-in pair. An `http://` issuer is refused, so a local Keycloak on
  `http://localhost:8080` stops working. A refused refresh keeps your stored sign-in and shows the reason. Hub
  connections to such providers no longer refresh automatically. *What to do:* use an https issuer that serves its
  own token endpoint; there is no switch in this release.
- **B12. xAI subscription sign-in works with the network guard on.** *What to do:* remove
  `FUIGO_ALLOW_UPSTREAM_HOSTS=1` if you set it for xAI; it lifts the guard for every connection.
- **B13. `fuigo logout` removes every stored subscription account and says tokens were not revoked.** Subscription
  sign-in also survives stray requests to its callback address, and ChatGPT sign-in now holds port 1455 on both IPv6
  and IPv4 loopback. *What to do:* to end a subscription for good, revoke tokens in the provider's account settings;
  free port 1455 before ChatGPT sign-in if another program holds it.
- **B14. Helper models you chose keep their own route.** In a subscription session, a helper model you set yourself
  (image description, session titles, auto-mode classifier) keeps its own route, and defaults follow the
  subscription; if a title helper cannot be used, titles fall back to the session model. Changing
  `[models] image_description` now reaches open sessions after a config reload. *What to do:* nothing.
- **B15. An interrupted `/goal` can be resumed.** Esc, a provider error, an output-limit cut or a refusal now ends
  only that turn, and `/goal resume` continues the same goal; a goal that ran out of budget says which limit stopped
  it. A goal with a token budget that is interrupted while a request is in flight (Esc before the first output, or a
  resend that reports no usage) also resumes: that request is charged a cautious estimate (at least 16,384 tokens
  in total and 4,096 of output, or the largest request seen so far), and the budget still stops the goal with its
  usual message. *What to do:* nothing.
- **B16. `--no-memory` now stops every memory write.** Trace files, the per-turn memory archive, subagent memory,
  `#` and `/remember` notes are all refused while memory is off, and `--no-memory` wins over
  `--experimental-memory`. *What to do:* clients that wrote `MEMORY.md` themselves should call the
  `fuigo/memory/save_note` extension.
- **B17. Plugin hooks run from the start of a session and show in the pager.** A trusted plugin's hooks now fire
  from a session's first hook load and are shown as a `[hooks: N]` badge; untrusting or revoking a plugin removes
  them; inline hooks carried by a plugin agent are refused in primary sessions. *What to do:* to stop a plugin's
  hooks, untrust or disable the plugin; to hide the badge, turn the plugins UI off.
- **B18. An API key passed by an editor or app is no longer saved automatically.** `authenticate` with
  `fuigo.api_key` keeps the key in memory only. *What to do:* to keep the old behaviour send
  `_meta: {"fuigo/apiKey": {"persist": true}}`; `fuigo/setApiKey` still saves as before.
- **B19. For apps that embed Fuigo non-interactively, `ask_user_question` waits at most 30 seconds** (it was 30
  minutes); a missing or silent embedder gets the standard "no operator" reply. A non-interactive ACP client that stays silent gets that reply instead of blocking. *What to do:* answer within 30
  seconds.
- **B20. Config and state writes are stricter.** Every config and state file is replaced atomically under a shared
  cross-process lock, so two Fuigo processes no longer lose each other's edits. Newly created config files are mode
  0600. A writer now refuses a file it cannot read instead of treating it as empty and overwriting it, and a config
  file that keeps changing while it is read is reported as busy. A write is refused when Fuigo cannot tell which
  file a path really names. Lock waits can exceed 10 seconds under heavy contention. *What to do:* if a write is
  refused, fix the unreadable file or the directory permissions; chmod a new config file yourself if others must
  read it.
- **B21. Output errors exit cleanly.** When stdout cannot be written (a closed pipe is ignored; a real write
  failure such as a full disk is not), `fuigo` commands including `fuigo models` and `fuigo logout` exit 1 instead
  of aborting (for example `fuigo logout > /dev/full`). A closed stderr no longer aborts Fuigo. *What to do:* nothing.
- **B22. Some non-secret values may appear as `<redacted>`.** Values Fuigo sends in request headers or the query
  string (for example an `api-version` value) may be shown as `<redacted>` in error messages even when not secret.
  *What to do:* nothing; this is expected.
- **B23. Session recovery is recorded, and bounded.** A turn lost to a crash or close is recorded as interrupted
  the next time the session loads, and the model is told. Loading a session that another Fuigo process is
  recovering fails after 60 seconds with "This session is being recovered by another Fuigo process". The first `fuigo --continue -p` after a run was killed mid-turn no
  longer hangs: it records the lost turn, the next model request carries the note, and headless prints the 60-second
  refusal text instead of `Session does not exist`. A continued session whose log holds a background task that died
  with the old process no longer hangs headless `--continue` either (that hang has been there since 1.0.20). *What to
  do:* retry the load shortly.
- **B24. Some sign-in failures now ask you to sign in again.** A subscription token exchange that fails after the
  request was sent now forces a re-login instead of risking reuse of a consumed token. Temporary server errors
  before the request left your machine still do not. *What to do:* sign in again when asked.
- **B25. Trusted-origin changes are logged.** A change to the set of trusted API origins (from a config reload or a
  remote setting) is recorded in `$FUIGO_HOME/logs/unified.jsonl`. Editing `[endpoints]` during a session no longer withholds the session
  token from the endpoint still in use: trusted origins are the endpoints in use plus the re-read `[endpoints]`, and a
  config that fails to parse keeps the trust set as it was. *What to do:* read that log to audit changes.
- **B26. A session whose saved history was cut by a crash is repaired when you open it.** Before, every request
  in such a session failed until `fuigo/session/repair` was run by hand. Fuigo now first copies the file as found to
  `chat_history.jsonl.pre-repair` in the session folder, then repairs the history and shows one note saying what it
  removed. The note is shown once, not again each time the session loads. A subagent that resumes such a session and
  a fork of it get the repaired history too. Sessions that broke before this release are repaired too, as long as
  their `chat_history.jsonl.corrupt` file is still there. While that copy cannot be made (full disk, read-only
  folder), the repair stays in memory only, and rewind and compaction are refused with the reason: a refused
  compaction sends nothing to the model first, an automatic compaction shows its failure note once, and a model or
  mode switch, a goal or memory change, an editor's system-prompt override or an image strip says once that the saved
  history was not rewritten and why. *What to do:* if rewind or compaction is refused, free disk
  space or fix the session folder's permissions; the refusal ends by itself once the copy succeeds. A session without
  its `.corrupt` file still needs `fuigo/session/repair`.
- **B27. Fuigo no longer aborts when it cannot write a diagnostic.** A warning or message that cannot be written
  because the terminal or pipe is gone or the disk is full is dropped, and the command ends with its normal exit
  code; `fuigo update --check` and `fuigo-workspace-server --capabilities` exit 1 on a real stdout write failure.
  Output that went straight to the terminal now goes to Fuigo's log: Wayland connection errors on Linux, and a
  workflow script's `print` and `debug` before the workflow's log is ready (log target `fuigo_workflow::script`).
  With `WAYLAND_DEBUG` set, Fuigo copies to the clipboard through `wl-copy` or another clipboard tool instead of its
  built-in Wayland client. With `FUIGO_LOG_FILE` set, an invalid `RUST_LOG` directive is ignored without a warning.
  *What to do:* look in the log for messages you used to see on the terminal; check `RUST_LOG` spelling yourself.
- **B28. `${FUIGO_API_KEY}` in your configuration hands the saved key to that one place.** (See S11.) In an MCP
  server's `env`, `args` and `headers`, `bearer_token_env_var = "FUIGO_API_KEY"`, a model's `api_key` or
  `env_key`, and a hook's command or `env`, a `${FUIGO_API_KEY}` reference is resolved from the saved key when that
  server, model or hook is used. The saved key is never filled into a URL (an MCP server's `url`, an HTTP hook's
  `url`), an MCP server's `command` or `cwd`, or a model's `extra_headers`; those keep the literal text. Fuigo's own
  records of your configuration show `${FUIGO_API_KEY}`, not the key. Write `$${FUIGO_API_KEY}` to send the text
  `${FUIGO_API_KEY}` itself. New: a hook's `env` values are now expanded, and so are references in MCP servers an
  editor passes in `session/new`. *What to do:* a script, hook or MCP server that relied on inheriting
  `FUIGO_API_KEY` must name it in its configuration as above: neither 1.0.20 nor this release passes an exported key to hooks, MCP
  servers or the model's commands. For an HTTP hook URL that needs the key, export it (an exported key is filled into
  your own config when it is read). `${FUIGO_API_KEY:-default}` gives the saved key, or the default when there is
  none, wherever `${FUIGO_API_KEY}` is resolved (release candidates sent the default); in a URL, command, `cwd` or any
  other setting it is the default. A key an editor passes to ACP `authenticate` resolves trusted references too; a saved
  or exported key still wins. If a dashboard matched log fields on key tails, match the fingerprint.
  Only your own configuration files can do this (B32).

- **B29. gh-release installs: "latest" is the highest version, and automatic updates never go down.** A gh-release
  install now takes the highest released version as the latest one, and an automatic update never moves to a lower
  version, even if the newest release is withdrawn. `fuigo update --version X` or `fuigo update --force` still
  installs an older version on purpose. After such a downgrade, a newer shared session (leader) that is still running
  is asked to stop and restarts on the installed version, and a newer client started later leaves that session
  running and says so. A client that meets a newer shared session says so and names `fuigo leader kill`. After such a
  downgrade, a newer Fuigo started from the managed folder no longer restarts the installed version's shared session
  each time it starts: it uses that session and says once which version it behaves like and how to run the installed
  one (Windows keeps the restart). Clients from 1.0.20 and earlier keep the old behaviour.

- **B30. Rewind and fork refuse instead of guessing.** A rewind that cannot rebuild the conversation, or cannot read
  the saved file versions completely, now changes nothing and says so. When some files cannot be reverted, Fuigo lists
  each one, keeps the conversation and the saved file versions so you can run the same rewind again, and no longer
  reports success; this also covers a file whose existence cannot be checked. A fork is refused, with nothing
  created, when its history cannot be rebuilt exactly at the chosen point (for example a session that mixes turns from
  before and after an upgrade), when the destination session id already exists, or when the source session compacts
  while it is being copied ("try again"). Previously such a fork could carry a summary of later work or overwrite the
  destination. A rewind that finishes never leaves its safety copy
  (`rewind_points.jsonl.pre-rewind`) behind, even when another process was holding the session's update log, so the
  next rewind is not wrongly refused. When a leftover copy does exist, the message says to delete it, and to move it
  over only if the transcript still shows the turns that rewind should have removed. A rewind no longer reports success
  when its history truncation cannot be written: a rewrite or append lock that stays stuck refuses the rewind up front
  with an error and leaves the transcript and history untouched. In the TUI, `/rewind` rewinds the conversation only
  (as in 1.0.20); reverting files is done from an editor or app over ACP. A damaged saved-file entry in a session's rewind history blocks only rewinds to that prompt or
  earlier; the message names the prompt, the file and the line, says nothing was changed, and says which rewinds
  still work. Forks no longer need room in the system temp directory: they are staged next to the new session.
  Refusing to fork an older compacted session at a point now suggests forking the whole session instead. A fork copies
  one snapshot of its source: a prompt added while the fork is made is in both the fork's transcript and its model
  history, or in neither (see K17). An invalid prompt, a cancelled turn or a failed image save no longer leaves forks
  refused. A refused fork no longer leaves an empty session folder behind. A damaged entry in a session's saved file
  versions no longer makes export fail, and a rewind that rewrites the saved file versions no longer loses an entry
  another Fuigo process adds at the same moment. Two Fuigo processes rewinding the same session at once no longer
  lose a rewind-history edit: the second waits (up to 10 s, then the rewind can be retried) for the first. The new
  lock file `rewind_points.jsonl.rewrite.lock` is owner-only (see K19).

- **B31. TUI session sharing needs your opt-in for a relay FluxRouter does not operate.** (See B8, K3.) Session
  sharing in the TUI now syncs only to FluxRouter's relay or to a relay whose origin you list under
  `[relay] trusted_origins` (or in `FUIGO_TRUSTED_RELAY_ORIGINS`). Otherwise the TUI says which relay was refused,
  why, and how to trust it; a shared session's refusal of an untrusted relay is shown the same way instead of only
  in the log, including a refusal that happens while the session is being created. *What to do:* if you already sync
  to a self-hosted relay, add its origin to `trusted_origins`.
- **B32. Only your own files can name `FUIGO_API_KEY`.** (See S16, B28.) A `${FUIGO_API_KEY}` reference is honoured
  only in `config.toml`, `managed_config.toml` and `requirements.toml` in `~/.fuigo` (or `$FUIGO_HOME`) and in
  `/etc/fuigo`, in `~/.claude.json`, in `~/.cursor/mcp.json` and in hook files whose real path is under `~/.fuigo/hooks/`. Anywhere else, including hooks in
  `~/.claude/settings.json`, `~/.claude/settings.local.json`, `~/.cursor/hooks.json` or a `hooks-paths` directory
  elsewhere (move them into `~/.fuigo/hooks/`),
  including a project's config, a plugin, a project `.mcp.json`, every other file under `~/.fuigo` (worktrees,
  plugins, a hand-made `foo.toml`), MCP servers an editor or app sends, servers added with `/mcps Add`, a hub's
  `workspace.configure_mcp` and an agent's inline MCP servers, the reference is removed and a note at session start
  names the source and the setting. `/mcps Add` can no longer save a server that names the key. *What to do:* move
  such an entry into `~/.fuigo/config.toml` or another file above; move a hook declared in an agent's frontmatter
  that needs the key to `~/.fuigo/hooks`.
- **B33. MCP servers whose sign-in issues tokens from another address are refused.** (See S15.) An MCP OAuth
  provider whose token endpoint is on a different origin than its metadata, other than Google (for example Amazon
  Cognito), can no longer sign in or refresh, as for the shell (B11). *What to do:* use a provider that serves its
  own token endpoint; there is no switch in this release. When a provider's metadata cannot be fetched, a saved
  sign-in that is near or past expiry is reported as a connection problem to retry, not as a request to sign in
  again; no refresh is sent until the metadata checks out.
- **B34. For editor and app integrators: two leader notices now arrive.** Clients that read the ACP stream as raw
  JSON must accept the notifications `_fuigo/config_changed` and `_fuigo/leader_reconnected` (see F17). A TUI client that registers with `leader_notices` also receives
  `_fuigo/leader/notice` (`params.message`); other clients are not sent it.
- **B35. Your own MCP server wins over a same-named one an editor sends.** (See S16.) When an editor or app sends an
  MCP server with the same name as one in your own configuration but a different definition, your definition runs and
  a warning is logged; in 1.0.20 the editor's copy replaced yours. A copy that matches your enabled definition is
  treated as yours. MCP OAuth client settings of a disabled server, or of a server whose running definition differs
  from the configured one, are not used. After you edit or delete an MCP server in your configuration, a session's
  next reload uses what is on disk, including renamed servers (`com.example` becoming `com-example`) and servers that
  override a plugin's: the copy your editor forwarded no longer outlives a delete or masks an edit, and no longer
  logs a refusal on every reload. Trusting a folder or running `/plugins reload` no longer lets a repo plugin
  silently replace a server your editor forwarded. *What to do:* if an editor must run its own variant, give it a different
  name.
- **B36. Your own `managed_config.toml` or `requirements.toml` in `~/.fuigo` is kept.** Fuigo keeps these two files in
  sync with your organisation's console and removes them when you are not signed in to a team. A copy Fuigo did not
  write is now saved as `<name>.user-<time>.bak` (with a warning) before it is replaced or removed. *What to do:* put
  your own settings in `~/.fuigo/config.toml`, or system-wide in `/etc/fuigo`.
- **B37. `fuigo update` fails fast when the registry is down.** With the registry down or silent, `fuigo update`
  fails in seconds (about 32 s at worst) with a one-line error and a non-zero exit; `fuigo update --check` exits 1
  instead of printing raw npm output or a cached "latest". The installed Fuigo is never touched. *What to do:* retry
  later.
- **B38. Permission prompts are harder to answer by accident.** Prompts preselect *allow once*, and text you type
  into an open prompt can no longer answer it: an Enter, digit or Backspace inside typing is held, and a digit never
  picks an "allow always" or always-approve row. A broad grant is chosen only deliberately: arrow keys or a digit to
  move to the row, then Enter after a short pause, a double-click, or Ctrl+O for always-approve. *What to do:* pause
  briefly before pressing Enter on a broad-grant row.
- **B39. Prompts and commands in the TUI are less likely to be lost.** A prompt sent while Fuigo reconnects to its
  leader stays in the composer with a notice, and a request the dead connection never answered (a queued message too)
  fails with a message saying it may not have run. `/feedback` thanks you only after the report was sent, and shows
  one message with the reason if sending fails. `/fork` and the new-session worktree question accept a typed yes or
  no. *What to do:* resend a prompt that was marked as possibly not run if it matters.

## Fixes

- **F1. Streams from providers no longer abort on something new.** An unknown stream event (such as a keepalive
  during long reasoning), content type, finish reason or role no longer kills an already billed turn; a tool call
  whose arguments lost a fragment fails instead of running with altered arguments.
- **F2. Resuming a compacted session keeps the model's full history.** In 1.0.10 to 1.0.17, reopening a compacted
  session rebuilt the model's history from the screen transcript and lost every command, file read and edit since
  the compaction; resumed sessions now get exactly the history they had. A missing or damaged checkpoint file now
  opens with a warning instead of failing.
- **F3. Search reports a failure when it cannot run.** When ripgrep cannot start, Fuigo reports an error instead of
  an empty "nothing found", and a failed lookup of ripgrep is retried instead of being remembered forever.
- **F4. Subscription sign-in is more forgiving.** A temporary failure while refreshing (server error, rate limit,
  or a request that never left your machine) no longer forces a browser re-login; temporary provider errors are
  retried as for API keys, and the provider's own error text reaches you. If saving a refreshed sign-in fails, the
  new tokens are kept in memory and the save is retried. A broken extra CA bundle is reported as a local TLS problem
  naming the file.
- **F5. A reloaded `[endpoints]` setting keeps its credentials** instead of returning 401 until restart (see B25).
- **F6. Crash and abort fixes.** A memory-corruption bug when the agent shut down shortly after starting (for
  example a quick `fuigo models` or headless run) is fixed; a double borrow that could abort `/compact` while
  `/model` rebuilt the agent is fixed; the `/model` abort on macOS (a print to a closed stdout) is fixed.
- **F7. Workflows finish and resume correctly.** A workflow whose host stopped answering no longer waits forever;
  pausing or stopping it ends as paused or cancelled instead of Failed; a run paused before its first step can be
  resumed.
- **F8. Concurrent Fuigo processes no longer lose sign-in tokens.** Every write to `auth.json` takes the
  cross-process lock and keeps the fresher credential; the hub token refresh waits for the lock and retries a failed
  write.
- **F9. Windows config editing.** Managed-text edits and the config loader no longer fail or hang on Windows, and
  a state file is replaced under the name it already has.
- **F10. Smaller fixes.** IPv6 loopback proxies (`http://[::1]:PORT`) are recognised; the TUI no longer briefly
  shows the agent's default model on start; headless plain output prints each failure once and an interrupt reports
  the turn's usage; LSP diagnostics credit the right document version; an empty `SSH_TTY` no longer counts as a
  remote session; `.envrc` output written by a busy child is no longer lost; the theme updates on `/minimal` and
  fullscreen switches; the built-in memory guide states the real defaults; the "uploads withheld" notice now lists
  review comments.
- **F11. GitHub Releases are published again, and the `gh-release` install path works.** Each release from 1.0.21 on
  is also a GitHub Release `v<version>` carrying the npm packages, `release-manifest.json`, `SHA256SUMS` and, new,
  the six raw binaries (`fuigo-<version>-<os>-<arch>`) that a Fuigo installed with `FUIGO_INSTALLER=gh-release`
  downloads to update itself. No earlier release carried those binaries, so that install path never updated (the
  newest GitHub Release was v1.0.11). Existing gh-release installs pick up 1.0.21 with no change on your side; the
  path still needs a signed-in `gh`. Every GitHub Release asset is the exact bytes npm serves for that version, so a
  release re-run after a partial publish cannot ship different binaries on the two channels.
- **F12. gh-release updates are checked and never half-installed.** From 1.0.21 on, a gh-release install downloads
  each update to a temporary file, checks it against the release's `SHA256SUMS`, and only then replaces `fuigo`, so
  an interrupted or corrupt download no longer breaks the install. (Your 1.0.20 or older client still installs 1.0.21
  itself the old way; the check applies to the updates after it.)
- **F14. Rewinds report the truth.** A rewind succeeds only once its conversation is saved; if saving fails it says
  so and keeps the saved file versions, so it can be retried. (In the TUI,
  `/rewind` is conversation-only; see B30.)
- **F15. A crash right after a compaction no longer loses it.** Each compaction records what it activated and a
  fingerprint of the saved history. If Fuigo stops before the compacted history is fully written, or the rewrite
  fails, the reopened session (and any fork of it) continues from the compacted history plus everything said since,
  even after later compaction attempts fail.
- **F16. An app that embeds Fuigo can turn plugin discovery off.** `FUIGO_CONFIG='{"plugins":{"auto_discover":false}}'`
  now keeps the machine owner's plugins (and the MCP servers, hooks and skills they bring) out of the sessions that app
  starts, alongside the existing `FUIGO_CLAUDE_*_ENABLED=0`, `FUIGO_CURSOR_*_ENABLED=0` and `FUIGO_CODEX_*_ENABLED=0`
  switches. Through `FUIGO_CONFIG` it can only be turned off, never on.
- **F13. Notes an older Fuigo writes to the old memory folder are reported.** If an older Fuigo (a downgrade, or an
  old binary sharing `~/.fuigo`) writes notes into a repository's old memory folder after 1.0.21 moved it, Fuigo tells
  you, naming both folders, and leaves both alone so you can move the notes by hand. It tells you again only if those
  notes change. `fuigo memory clear` now lists such an old folder as not cleared, with its path, and start-up no
  longer checks an old folder that holds no notes. In a shared session (leader) the notice now appears in the TUI as a
  note in the session on screen.
- **F17. Shared-session notices reach the screen again.** The version-mismatch warning, a UI config change and the
  reconnect notice from a shared session (leader) were silently dropped by the TUI in 1.0.20; they are now shown, and
  the TUI still understands the version-mismatch warning from an older leader. A client whose release differs from
  the leader's now gets `_fuigo/leader/version_mismatch` (leaders 1.0.21 and later; a commit stamp or build metadata
  alone never warns).
- **F18. Helper models follow a model switch.** The session-title and auto-mode classifier helpers are rebuilt when
  you switch model or the model catalog reloads, instead of keeping the ones the session started with.
- **F19. npm packages carry provenance.** Every published npm package now carries a provenance attestation that
  links it to the release build, and the release check downloads the published packages through the same pinned
  public registry the release uses, and their digests are compared with the GitHub Release assets before releasing.
- **F20. Smaller fixes from the final audits.** A session whose only pending upload is a compaction summary that the
  storage service refuses no longer repeats two failing requests on every sync; the summary is dropped with one
  warning. Switching a session's model no longer rebuilds every other open session's title helper.
- **F21. Smaller fixes for editors and agents.** `fuigo agent --no-leader stdio` follows MCP and model config edits
  live. A folder-trust grant tells each session about a refused `${FUIGO_API_KEY}` reference once. Refusals in an
  agent definition's inline MCP servers or hooks are reported to the session that spawned it.
- **F22. Windows updates and leaders work.** `fuigo update`, `fuigo update --check` and automatic updates work on
  Windows npm installs again (the "program not found" failure is gone), and `fuigo leader list` shows a live Windows
  leader as Reachable. On Windows `prompt_context.json`, `system_prompt.txt`, `turn_owner.lock` and
  `resources_state.json` are owner-only like the other session files, and so is `events.jsonl`.
- **F23. Smaller TUI fixes.** `/mcps` (full and minimal) shows why a server is unavailable, and the note for a server
  added through `/mcps` tells you to edit it in place. A stale "Starting session..." line no longer sits under a
  finished reply. Resuming a session that is already open says you switched to its tab.

## Known limits

- **K1.** An older Fuigo session still running during the upgrade keeps writing the old memory folder (F13 tells
  you when it finds notes there). A repository
  whose `.git/config` is attacker-supplied still chooses its own memory identity; use `FUIGO_MEMORY=0` for
  untrusted repositories.
- **K2.** Compacted sessions already reopened by 1.0.10 to 1.0.17 keep the gap in their history. Sessions pulled
  from remote storage that were compacted before this version resume without their summary (with a warning).
  Compactions from now on keep it when the storage service accepts the checkpoint; otherwise the upload still
  succeeds without it.
- **K3.** The relay protection (S5, S6, B8, B31) protects against a passive relay, not an active hostile one: a relay
  you trust can still drive the agent like a local client.
- **K4.** `!` commands and client terminals still get the rest of your environment, including provider keys your
  config does not name. Shell startup files that re-export a key (for example `.zshenv`) put it back.
- **K5.** Credential hiding (S8) errs on the side of hiding: proxy credentials of the same scheme that were not used
  for the request, and long non-secret values Fuigo sent (an `api-version`, for example, since some gateways
  authenticate by it), may be shown as `<redacted>` when they did not need to be.
- **K7.** MCP OAuth providers whose token endpoint is on another origin than their metadata, other than Google (for
  example Cognito), are refused, as for the shell (B33). When an automatic token refresh is refused, the reason is in
  the log, but the screen shows only "Request failed".
- **K8.** The memory filter (S10) is a heuristic: a reworded instruction can get through. Look-alike letters are now
  caught. Letter-spaced text joined by commas, semicolons, quotes or longer gaps is not. The installer does not
  tighten an existing 0644 `config.toml` (S14); Fuigo does so the next time it writes it.
- **K9.** Older Fuigo versions do not take the new locks on state files, and on case-insensitive disks may use a
  different lock name; do not run old and new versions side by side. A file deleted and recreated with the same id
  between plan and apply passes the config check on Windows (as with inode numbers on Unix).
- **K10.** A background child started with `cmd &` can outlive the command and the session, as in a shell.
- **K11.** In headless mode a deny rule, a prompt-policy deny or a hook deny still produces no denial record and
  exits 0; `streaming-messages-json` carries no remedy.
- **K12.** Platform coverage: the Fuigo shell test suite has not run natively on Windows, and the new macOS file
  locking code has not run on macOS (a macOS test job is added to CI in this release; its first run is on the
  release branch). Windows on ARM and macOS on Intel crash recording are untested natively. Session history repair
  (B26) and the saved-key changes (S11, B28) are tested on Linux only.
- **K13.** Saved key (S11, B28, B32): a hook's command or `env` that names the key gives it to everything that hook
  runs. An HTTP MCP server can briefly use two key versions if the key is changed while it starts. Hooks on Windows
  (PowerShell) are untested.
- **K14.** Session history repair (B26): on a file system without hard links or advisory locks the repair stays in
  memory. The backup is made once: a later repair of the same session keeps the first `.pre-repair` copy. A client
  older than this release does not show the repair note. While the backup still cannot be made, each later open of
  the session repairs it in memory again and says so.
- **K15.** Diagnostic output (B27): in one rare case Fuigo can still abort at exit, when its log writer is stalled at
  shutdown and stdout is broken at the same time.
- **K17.** Forks (B30): a prompt is in both the fork's transcript and its model history, or in neither, except when
  the source is rewound at that moment, when an older Fuigo is writing the same session, when the session's lock is
  stuck for over 10 seconds (the fork is then refused and can be retried), or when a turn vanished without ending and
  its lock was released after 120 seconds. Text streamed within one turn is not covered. A fork taken during a long
  image description waits up to 10 seconds and is then refused and can be retried.
- **K16.** Local session files keep tool output as written: a key echoed by a tool stays in your local history; only
  what leaves the machine is scrubbed. In `/feedback` archives (S14), finding a private key Fuigo never held is a
  heuristic, so a key split in an unusual way can still get through. `!` commands and client terminals run a login
  shell, so a key your shell profile (`~/.zprofile`, `~/.bash_profile`) exports is set there again; secrets Fuigo or
  your editor passes in (`FUIGO_AGENT_SECRET`, `FUIGO_AUTH`) are not.
- **K19.** A rewind-history rewrite by a Fuigo older than 1.0.21 does not take the new rewrite lock (B30), so it can
  still race a 1.0.21 rewrite of the same session and lose one edit. If the lock file cannot be opened, the rewrite
  goes ahead without that exclusion. Two 1.0.21 processes never lose an edit this way. If Fuigo is killed in the
  middle of a rewind, the next resume does not reconcile the leftover `.pre-rewind` copy; the next rewind is refused
  with the steps to recover (B30).
- **K20.** Saved key (S16, B32): a refused `FUIGO_API_KEY` reference is shown when a session starts or loads and when
  its MCP servers are updated or added, and when you trust a project folder. A refusal found later, at a hot reload of
  the configuration or of a plugin, is only written to the log.
- **K21.** Saved-key notes (S16) are kept for at most 256 sessions starting at once (one more closes the oldest), and
  each session keeps at most 64 distinct notes plus a count of the rest.
- **K22.** MCP servers an editor forwards (B35): if you edit a forwarded server whose name Fuigo renames (a dotted
  name such as `com.example` runs as `com-example`) away from a URL your policy now blocks, its copy is dropped and
  its tools disappear until you restart. No key is involved. This was not reproduced in testing.
- **K23.** MCP servers an editor forwards (B35): setting `enabled = false` on, or leaving an untrusted project's
  config with, a server whose name Fuigo renames does not stop the renamed copy the editor forwards. The copy never
  gets `FUIGO_API_KEY` (S16). This predates 1.0.21. Two of your own servers whose names rename to the same name are
  matched to the first one found.
- **K24.** Credential hiding (S8, S14): a key that was re-encoded before it was sent or logged, for example base64 or
  URL-encoded, is not recognised by any scrub. This is the same as in 1.0.20.
- **K25.** Headless exit codes (B4): these paths are not yet typed denials. A goal's token `--budget` reached when an
  answer completes exits 0 (the goal stops budget-limited). The output grant spent on the last salvaged truncated
  (`max_tokens`) response exits 1. A completion requirement with `maxRetries` of 2 or more, retrying past the call
  limit's final answer, exits 1. A `/btw` side question refused by the process counter or clock fails as `api`. A
  failure the provider answered itself (a status, an auth refusal, a rate limit, a stream error) keeps its cause and
  exits 1, even if the runtime limit passed while it was being reported.

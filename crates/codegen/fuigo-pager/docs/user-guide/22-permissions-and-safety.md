# Permissions and safety

Control what Fuigo can access and do: permission modes, allow/ask/deny rules, hooks, and the optional OS-level sandbox.

- **Modes** set how often Fuigo asks for approval (always-approve, auto, ask, and related).
- **Rules** set which tools are allowed, asked about, or blocked within that baseline.

---

## Permission modes

When Fuigo edits a file, runs a command, or calls an external tool, it may pause for approval. Permission modes control how often that happens.

Modes set a baseline. Allow, ask, and deny [rules](#configuring-permissions) still apply on top of any mode.

### Starting points

| Situation | Mode |
| --------- | ---- |
| Interactive TUI | Default (ask), or auto for fewer prompts with background checks |
| Scripts, SDKs, CI, agent servers | Always-approve; add [deny rules](#configuring-permissions) or hooks for hard limits |

```bash
fuigo -p "Run the tests" --always-approve
fuigo agent --always-approve stdio
fuigo agent --always-approve serve --bind 127.0.0.1:2419 --secret <token>
```

ACP clients can set `"_meta": { "yoloMode": true }` on `session/new`. See [Agent mode](15-agent-mode.md#automation-and-sdks).

### Available modes

| Mode | What runs without asking | Best for |
| ---- | ------------------------ | -------- |
| `default` (**ask**) | Read-only tools and built-in read-only shell commands | Interactive day-to-day use |
| `acceptEdits` | File edits without a prompt | Local coding while you review diffs later |
| `plan` | Starts an interactive session in [plan mode](19-plan-mode.md) (read-only until you accept the plan). Refused with `-p`, which has nobody to approve a plan | Planning before any code changes |
| `auto` | Work the safety check allows; other calls are blocked or escalated | Interactive sessions that want fewer prompts |
| `dontAsk` | Only pre-approved tools and built-in read-only handling | Strict CI allowlists |
| `bypassPermissions` (**always-approve**) | Tool calls in general (`deny` rules, hooks, and some shell `ask` rules still apply) | Trusted automation and agent servers |

**Always-approve** is the product name; config and Claude-compatible settings may use `bypassPermissions` for the same mode. Always-approve and auto are mutually exclusive (always-approve takes precedence when both are requested).

### How to set the mode

**Interactive TUI:** `Shift+Tab` / `Ctrl+O`, `/always-approve` or `/auto`, or `/settings` ([shortcuts](03-keyboard-shortcuts.md), [commands](04-slash-commands.md)).

**CLI:**

```bash
fuigo --always-approve -p "Run the test suite"
fuigo --permission-mode auto
fuigo agent --always-approve serve --bind 127.0.0.1:2419 --secret <token>
```

**Config:**

```toml
[ui]
permission_mode = "always-approve"   # or "auto", "ask", …
```

Claude-compatible `defaultMode` in `.claude/settings.json` is also supported (see [Claude-compatible settings](#3-claude-code-compatibility-claudesettingsjson)). CLI overrides config for that process.

### Always-approve

Skips ordinary permission prompts so tools run without waiting for a click. `deny` rules, hooks, and some shell `ask` rules still apply. Admins can lock the mode off (below).

| Mechanism | Example |
| --------- | ------- |
| CLI | `--always-approve` (alias `--yolo`), or `--permission-mode bypassPermissions` |
| Config | `[ui] permission_mode = "always-approve"` |
| Interactive | `/always-approve`, `Ctrl+O` |
| ACP | `_meta.yoloMode: true` on `session/new` |

#### Always-approve with hard limits

Keep always-approve for automation, and add deny rules for paths or commands you never want run:

```toml
# project .fuigo/config.toml
[ui]
permission_mode = "always-approve"

[permission]
deny = [
  "Bash(rm -rf *)",
  "MCPTool(sales__delete_*)",
]
```

```bash
fuigo -p "Deploy the service" --always-approve --deny 'Bash(rm -rf *)'
```

Deny always wins over allow and over always-approve’s normal pass-through. See [Configuring permissions](#configuring-permissions).

### Auto mode

Reduces interactive prompts by checking many tool calls before they run. Routine local work often proceeds. A call the classifier will not auto-allow surfaces a permission prompt so you can allow or reject it. In non-interactive sessions (`fuigo -p`, unidentified stdio), that same call fails and is reported to the model (for example `Auto mode blocked this action …`).

In Auto mode the model decides the shell commands Fuigo's plain-text rule cannot read (an opaque or rich script, a routine build), unless Fuigo detects that content the repository controls will run: the repository's git configuration (`core.fsmonitor`, a driver, a pager, an alias, `log.showSignature`) or hooks, a git command in a repository Fuigo could not read (`GIT_DIR=…`, a `cd` that leaves the folder uncertain, a script it cannot split into words, any command that names `git` but is not a git command Fuigo scans, such as `env -C dir git status`, `time git status`, `taskset -c 0 git status`, `sudo` or `sh -c`; `gh` runs git, so Fuigo scans the repository for it as for git), a configuration file a command loads that can make it run a program (`grep --config` reading a repository `.ugrep`, `cargo --config`, `bazel --bazelrc`, `wget --config`, `ssh -F`, `rustc @file`, `kubectl`/`helm --kubeconfig`, `docker --config`, npm-family `--userconfig`/`--globalconfig`, `node --env-file`) or that a tool reads from the project by default in the folder it runs in (after `cd`, `cargo -C`/`--directory`, `npm --prefix`, `pnpm --dir`, `yarn --cwd`, and inside `sh -c`; a folder change Fuigo cannot pin, such as `cd "$X"` or `env -C`, counts): an `.npmrc` `onload-script` or other program key for npm, pnpm and yarn, a `.yarnrc.yml` `yarnPath` or `plugins` or a `.yarnrc` `yarn-path` for yarn, a `.cargo/config.toml` alias for the subcommand, a `[build]` `rustc`, `rustc-wrapper`, `rustc-workspace-wrapper` or `rustdoc` naming a file (a bare program name such as `sccache` is fine), an `[env]` entry, a credential provider or an `include` (a Cargo config line Fuigo cannot read counts), a `.bazelrc` `startup`, `import` or `try-import` line or option Fuigo would ask about on the command line, bazelisk's `tools/bazel`; a tool named behind a launcher Fuigo does not model, such as `taskset -c 0 npm ls`, counts too. That project configuration counts only for commands that do not already run the project's code (`npm ls`, `npm outdated`, `yarn info`, `cargo metadata`, `cargo tree`, `cargo fmt`, `bazel version`, `bazel query`, ...): a build, test, run or install (`yarn build`, `cargo build`, `bazel build`) runs the project's code by design, as below; or an environment that picks which program runs or what it loads (a `PATH` entry that is relative or in the project, a variable from the lists below). Fuigo tells the model about it. Since 1.0.35, in a trusted folder the repository's content is the folder's own, so the model's allow stands; only the environment (the last case) makes a command no grant covers ask you even when the model allows it. In a folder you have not trusted no command runs without your approval or grant anyway. Your grants, allow rules, "allow all commands", always-approve and your answers are unchanged. Fuigo's grep tool asks in Auto mode too when `RG_BIN_PATH` or `RUNFILES_DIR` picks its program from the project. In a trusted folder those project configuration files no longer take a command off the read-only lists.

For automation that must run tools without interactive approval, use always-approve (and deny rules if you need hard blocks) rather than auto alone.

### Disable always-approve (administrators)

Organizations can prevent always-approve from being enabled via CLI, TUI, or `/always-approve`. Set this in the system-wide `/etc/fuigo/requirements.toml`, or serve it from your console (Fuigo keeps its synced copy at `~/.fuigo/requirements.toml`; a hand-made file there is moved aside, not applied):

```toml
[ui]
disable_bypass_permissions_mode = true
```

Do not use `permission_mode` for this lock; that key is a switchable default. The legacy `[ui] yolo = false` key in `requirements.toml` also disables always-approve for compatibility.

Fuigo can still load Claude-style permission **rules** from managed settings; always-approve is locked with `requirements.toml` as shown above.

### Disable always-approve for yourself

To make sure always-approve can never be turned on in your own sessions, by you or by anything the agent or a repository does, put the same key in your own `config.toml` (`~/.fuigo/config.toml`, or `$FUIGO_HOME/config.toml`):

```toml
[ui]
disable_bypass_permissions_mode = true
```

It works on every OS (including Windows, which has no system-wide `requirements.toml`), console sync never touches it, and only your own `config.toml` counts: a project `.fuigo/config.toml`, `FUIGO_CONFIG` / `FUIGO_CONFIG_PATH` and managed config cannot set or clear it. A running session keeps the always-approve mode it started with: a lock added mid-session does not switch that session's mode, and removing the lock takes effect for a session's mode from the next session start. The hub that authorizes tool calls reads the file on every call, though, so it enforces a lock you add from the very next call (the calls it judges are handled as if always-approve were off) and stops enforcing a lock you remove from the next call too. Removing it is your choice. The agent cannot remove it for you: your `config.toml` is a protected file, and every route that would let the agent write it without asking is exactly what the lock turns off. `[ui] yolo = false` in `config.toml` is not a lock. When `requirements.toml` also locks, its message is the one you see.

---

## How a tool call is authorized

When the model requests a tool, the following checks happen in order:

1. **`PreToolUse` hooks**. A hook can deny a tool call before any other check. A hook that allows a call does not skip the checks below; it only declines to deny. See [10-hooks.md](10-hooks.md).

2. **Permission rules** (from configuration files or `--allow`/`--deny` flags)
   - A matching `deny` rule rejects the call. `deny` wins over every other rule.
   - A matching `ask` rule prompts you, including for file reads, searches, and shell commands that would otherwise be auto-approved.
   - A matching `allow` rule approves the call.

3. **Remembered grants**. Per-command approvals you saved from earlier prompts apply here, scoped to the current project. An existing grant can satisfy an `ask` rule instead of re-prompting. Commands on the [dangerous list](#dangerous-commands) prompt again rather than using a remembered prefix. See [Interactive Approvals](#interactive-approvals-and-where-they-persist).

4. **Built-in auto-approvals**. Read-only tools and a fixed set of read-only shell commands run without prompting (see below).

5. **Prompt policy** (set by the [permission mode](#permission-modes)): prompt you, auto-approve, or auto-deny the call.

[Always-approve](#always-approve) short-circuits this pipeline after step 2: `deny` rules, hooks, and `ask` rules that match a shell command's segments still apply, but remembered grants (including remembered "never allow" entries) are not consulted, and `ask` rules on non-shell tools do not prompt.

---

## Operations That Never Prompt by Default

The operations below are treated as read-only and run without prompting, in every mode including `dontAsk`, unless a matching `deny` rule or a hook blocks them. An `ask` rule forces a prompt for file reads, searches, and shell commands (see [How a Tool Call Is Authorized](#how-a-tool-call-is-authorized)).

### Read-Only Tools

- `read_file`
- `list_dir`
- `grep` (content search)
- `web_search`
- `todo_write`
- `get_command_or_subagent_output` / `wait_commands_or_subagents` / `kill_command_or_subagent` (subagent control)
- Invoking skills

### Read-Only Shell Commands

**Plain text first.** With no grant from you, a shell command runs without asking only when it is plain text, so that what Fuigo checks is what bash runs (the limits are in [Shell state between commands](#shell-state-between-commands)):

- simple commands joined only by `&&`, `||`, `;`, `|` or a newline (no subshell, `{ …; }` group, background `&`, heredoc, here-string, process substitution or comment);
- every word is unquoted text made of letters, digits and `._/:=@%+,-`, or one quoted string that is the whole word (single quotes without a newline; double quotes without a newline, `$`, a backtick, `\` or `!`). No empty quotes, partly quoted words, escapes, `$` expansions, globs (`*`, `?`, `[`), braces or a leading `~`;
- the program is a plain name: no path, no `NAME=value` in front, not a wrapper (`env`, `command`, `builtin`, `exec`, `timeout`, `nice`, `nohup`, `stdbuf`, `xargs`, `sudo`, `time` and similar) and not `cd`, `pushd`, `popd`, `set`, `shopt`, `eval`, `source`, `.`, `alias`, `export` or `unset`;
- redirects go only from or to `/dev/null` (`2>/dev/null`, `>>/dev/null`, `&>/dev/null`, `< /dev/null`; a file descriptor is a single digit).

Then the read-only list below and its per-command checks apply. Pipes between plain commands still run without asking (`git log --oneline | head -5`, `ls | wc -l`). Anything richer asks, even when every program in it is read-only: `ls ~/x`, `cat *.md`, `ls src/*.rs`, `ls {src,tests}`, `echo "$HOME"`, `cd src && git status`, `FOO=1 ls`, `ls 2>&1`. Quote a whole word to keep it plain (`grep -rn foo src '--include=*.rs'`). In Auto mode the same rule decides the fast path, the exact no-op `true`/`:`/`false` included; a richer command goes to the model. The commonest case is `cargo test 2>&1 | tail -5`: drop the `2>&1` or write `2>/dev/null` to keep it on the fast path.

Your own grants are explicit overrides and are not held to the plain-text rule: a remembered prefix or glob grant, "allow all commands" for the session, sandbox auto-allow, a configured catch-all `allow` rule and an approval of the exact whole command. They keep only the floors in [Commands the classifier cannot vouch for](#commands-the-classifier-cannot-vouch-for).

After splitting chained commands (on `&&`, `||`, `;`, and pipes), the following commands are recognized as read-only when they appear as the primary command. This list is word-boundary matched, so `ls` does not match `lsof` or `less`. (Your own `Bash(...)` rules match differently; see [Rule Matching Reference](#rule-matching-reference).)

**Filesystem (read-only viewing):**
- `ls`, `cat`, `pwd`, `date`, `whoami`, `hostname`, `uptime`, `ps`
- `head`, `tail`, `wc`, `sort`, `uniq`, `tr`, `cut`

**Git (read-only):**
- `git status`, `git branch`, `git log`, `git diff`, `git ls-files`, `git show`, `git rev-parse`
- `git blame`, `git describe`, `git merge-base`, `git shortlog`
- `git check-ignore`, `git check-attr`, `git cat-file`, `git ls-tree`, `git show-ref`, `git for-each-ref`, `git rev-list`, `git name-rev`, `git count-objects`

**Search and inspection:**
- `grep`, `rg` (not `rg --pre` / `rg --pre=…`, which spawn a preprocessor per file, and not the `grep` options that run a program; see [Commands the classifier cannot vouch for](#commands-the-classifier-cannot-vouch-for))

**Kubernetes (read-only):**
- `kubectl get`, `kubectl logs`, `kubectl describe`

> **Note:** `tee` is not on this list because it can write its input to arbitrary files. `cargo check` is not on this list because it compiles and runs `build.rs`, proc-macros, and any `build.rustc-wrapper` from the repo (in Ask mode it therefore prompts; Auto mode may still heuristic-allow `cargo` as a project code runner). `sort --compress-program=…` (including unique long-option abbreviations), `git -c` / `--config-env` overrides, and a git command whose local/worktree config installs an executable hook (`core.fsmonitor`, a `diff.*.command`/`textconv`/`external` driver, a shell alias `alias.<name> = !…`, or any alias for a subcommand that is not part of git, such as `alias.lol = reset --hard` for `git lol`; git always runs its own subcommands before an alias of the same name, so `alias.status = …` changes nothing) raise a request-level floor and prompt rather than auto-approve, unless the user granted that exact full script or always-approve is enabled.

**Forms that take a listed command off the list.** A command on the read-only list, or on the Auto mode routine list, is approved by name only in its ordinary forms. These forms ask instead (in Auto mode they go to the model); a grant from you still covers them:

- `date` setting the clock (`date -s …`, `date MMDDhhmm`) or reading dates from a file (`-f`); only `+FORMAT`, `-u`, `-R`, `-I`, `-d`, `-r` and the BSD print options are routine. `hostname` with an operand, `-F`/`--file` or `-b`.
- `uniq`: every operand after the input is written (`uniq - out.txt`, `uniq -f 1 in out.txt`), so it is checked like any other write.
- `sort -T`/`--temporary-directory`, `--random-source`, `--files0-from`; `wc`/`du --files0-from`; `diff --from-file`/`--to-file`; `file -f`/`-m`/`-M`/`-C`; `tree --fromfile`/`--fromtabfile`/`--infofile`/`-R`; `strings @FILE`; `jq --rawfile`/`--slurpfile`/`--argfile`; interactive `top` and `htop` (they take keys such as kill from stdin; `top -b` and macOS `top -l` are fine).
- `git branch` other than its listing forms (`-d`/`-D`, `-f`, `-m`/`-M`, `-c`/`-C`, upstream changes, `--edit-description`, a new branch name); `git diff --no-index` or a `git diff` path outside the work tree (absolute, `~`, through `..`); `git grep --no-index`; `git blame --contents`/`--ignore-revs-file`/`-S`. In Auto mode, `git commit -F FILE`/`-t FILE` (stdin `-` is fine) and `git pull -s` with a strategy that is not built in.
- `kubectl --cache-dir`, `--log-file`/`--log-dir`, `--profile-output` and a template read from a file (`-o go-template-file=…`, `jsonpath-file=…`, `--template`).
- Auto mode build tools: `cargo` subcommands other than build, check, test, bench, run, clippy, fmt, doc, fix, tree, metadata, fetch, update, clean, new/init, add/remove and the other project commands (so `cargo install`, `publish`, `login`, `yank` and external `cargo-NAME` subcommands ask), `--registry`/`--index`, and `--target-dir`/`--manifest-path`/`-C` outside the project; `make -C`/`-f`/`-I` outside the project or a variable whose value is a path (`make CC=./x`); `cmake` other than configuring (`-S`, `-B` inside the project, `-G`, `-D` with a plain value, presets) or `--build DIR` with its build options, so `--install`, `--graphviz`, `--system-information` and native options after `--` ask; `go env -w`/`-u`, `go clean -cache`/`-modcache`/`-testcache`/`-i`, `go telemetry on`/`off`, and profile, trace, cover, overlay or `-modfile` flags; `pytest --junitxml`, `--basetemp`, `--log-file`, `--debug`, `--report-log`, `--html`, `--cov-report` with a path, `-c`/`--config-file`, `--rootdir`, `--confcutdir` and `--pastebin`; `bazel` startup options, commands other than build/test/query/run and the other read or build commands, and toolchain, action-environment, repository, cache, remote, experimental, profile and log options, or a `--copt`/`--linkopt` naming a path or another linker; `just -f`/`-d` outside the project, `--dotenv-*`, `--tempdir`, `--init`, `--set` and an override whose value is a path; `npm`/`pnpm`/`yarn` `config`, `link`/`unlink`, `store` other than `path`/`status`, `version` with a bump, and any option not spelled exactly as one of the common install, lockfile and output options (`--save-dev`/`-D`, `--save-exact`/`-E`, `--omit=dev`, `--frozen-lockfile`, `--ignore-scripts`, `--if-present`, `--silent`, `--json`, `--depth=N`, ...). npm accepts abbreviations, combined shorthands and shorthands with a value, so `-gq`, `-L global` and `--prefi=…` ask like `-g`, `--prefix`, `--registry` and `--cache`; options for the script go after `--` (`npm test -- --watch`); `uv self`, `uv cache clean`/`prune`, `--system`, `--break-system-packages`, `--target`, `--prefix`, `-o`/`--output-file`, `--out-dir`, another index or config file, and a `--directory`/`--project`/`venv`/`init` path outside the project; `rustup self` and `rustup toolchain link`.

These checks apply per segment. In a command like `ls && rm -rf /`, the `ls` segment is recognized as read-only, but the `rm` segment is not on the list. In `default` mode the `rm` segment prompts; under `dontAsk` it is denied.

### Folder trust

**Whose authority counts.** You decide once per folder whether to trust it. A folder is its git repository (with its
linked worktrees, Fuigo's managed worktrees and its submodules), or the folder itself when it is not in a repository;
a repository nested inside another one (a vendored clone) is its own folder. Fuigo asks the first time you start it in
a folder, in the full-screen app, the stderr prompt or an ACP client that supports the question:

- **Trusted:** the folder's own settings load (project MCP and LSP servers, hooks, `.envrc`, `.fuigo/config.toml`
  permission rules, workflows, plugins, instructions and skills), and shell commands follow every rule on this page as
  before.
- **Not trusted** (you answered no, or Fuigo cannot ask): none of those settings load, and no shell command runs
  unless your approval or grant covers the command: an approval at the prompt, a remembered command or prefix, "allow
  all commands", your own config or `--allow` rule, or always-approve. Everything else asks, or under `dontAsk` and in
  headless runs is refused with a message saying how to trust the folder. The read-only lists, the Auto mode fast
  path, routine check and model, and sandbox auto-allow approve nothing there (the model is not asked), and Fuigo runs
  no git, jj or direnv of its own in the folder before you trust it or a grant covers a command; reading, searching and
  editing files work as usual.

A folder's trust covers the commands that start there: a command counts as trusted when the folders it starts in
are trusted (the session folder and the tool's working directory). Naming another folder in a command (`cd ../other`,
`git -C`, `GIT_DIR=`, `make -C`, ...) does not change the answer, as in other coding agents: a
command that starts in a trusted folder is judged as that folder's, and every command that starts in a folder you have
not trusted asks.

Your home folder and the filesystem root can never be trusted: Fuigo shows one dim line instead of the question, loads
no project settings there, and every command asks. Folders trusted before 1.0.35 were trusted for their settings only,
so Fuigo asks once more; until you answer (or in a headless run) such a folder is not trusted.

To trust a folder without the question: run `fuigo --trust` in it once, type `/trust` in an ACP client session
(`/untrust` stops trusting it: the next command asks and project settings stop), or list it in your own
`~/.fuigo/config.toml`:

```toml
[folder_trust]
trusted_folders = ["/home/me/src/project"]
```

A project's own `.fuigo/config.toml` cannot set this, and a "no" you saved beats the list. Headless runs (CI,
embedding apps) cannot answer the question, so use `--trust`, the list above or an `--allow` rule there. Answers are
kept in `~/.fuigo/trusted_folders.toml` (`$FUIGO_HOME` if set; a relative `FUIGO_HOME` is ignored and nothing is
trusted). The agent cannot edit that file, your config or Fuigo's worktree database without asking you, and `fuigo
--trust` always asks. `[folder_trust] enabled = false` (or `FUIGO_FOLDER_TRUST=0`) in your own config switches the
whole check off with a warning at start: every folder is then trusted.

### Commands the classifier cannot vouch for

**Within a trusted folder.** Your own environment and dotfiles, and any state created by commands you approved, are your authority. Content a repository controls (files in the workspace, including `.git/config` and anything it includes, and config files a program discovers from the working directory) must never make a command that runs without asking do anything beyond a read-only action. Fuigo does not try to work out what an environment variable's value points at. If your `PATH` has a relative entry (`.`, `bin`, `node_modules/.bin`), an empty one, or one inside the project (an activated virtualenv's `.venv/bin`, a direnv `PATH_add bin`), or if any variable that changes which program runs or what it loads is set, Fuigo asks before every shell command that has no grant (for the per-program variables, every command of that program); grants you gave still apply. Deactivate the virtualenv or start Fuigo outside it to keep `pytest` and `python3 --version` on the fast path. The ambient git check then also runs only an absolute `git` from a clean `PATH` (or an absolute `GIT_BIN_PATH` outside the project) that does not resolve, through a symlink, into the project, never one the repository could supply; if Fuigo finds none, git commands ask. A command approved without a grant (by the read-only lists, or by Auto mode on its own: its fast path, its routine-command check or its model; a setup program such as `sleep` or `timeout` that no grant names counts too; shell builtins such as `cd` and `export` run no program and neither grant nor withhold) is checked a second time, by the same rules, against the environment its shell will actually run it in: what your login shell's startup files export, the agent shell's exports (an approved `export` or `source .venv/bin/activate` included) and the session's variables. If that environment steers the command, or its `PATH` is empty or unset (the shell then searches a built-in list that can include the current folder), the command does not run and says it needs your approval in that environment; every such command is checked on its own, so running it again gives the same answer until you allow it with an allow rule (such as `--allow 'Bash(ls *)'`), "allow all commands" or always-approve, or remove the variable. A command you approved at a prompt, or that your grants, allow rules, "allow all commands" or always-approve cover, is never stopped this way. In Auto mode, when the environment Fuigo started with already steers the command, a model allow asks you instead of being stopped here. Common setups trip the environment check: an editor's integrated terminal (VS Code, Cursor) exports `GIT_ASKPASS`, a stock Debian or Ubuntu `~/.bashrc` exports `LESSOPEN` and `LESSCLOSE` for `lesspipe`, and `EDITOR='code --wait'`, a desktop `SSH_ASKPASS`, Nix or CI `CC`/`CXX`, `GOFLAGS`, or the `npm_config_userconfig` that `npx fuigo` sets all count. The prompt names the variable. To keep those commands on the fast path, start Fuigo without it (`env -u GIT_ASKPASS fuigo`, or VS Code's `git.terminalAuthentication: false`; `unset LESSOPEN LESSCLOSE`). On Windows, cmd.exe runs every command with `NoDefaultCurrentDirectoryInExePath` set, so a bare program name is never taken from the project folder; PowerShell never runs a program from the current folder without `.\`.

**Windows: PowerShell and cmd.exe.** When Fuigo runs commands in PowerShell (`pwsh` or `powershell.exe`) or cmd.exe, every shell command without a grant asks, read-only ones included, in Ask mode and in Auto mode: Fuigo's plain-text rule and read-only lists judge a command the way bash reads it, and those shells read the same text with other quoting, separators and redirects. Grants, allow rules (`--allow`), your answer at the prompt, "allow all commands" and always-approve still apply. To avoid the prompts, use grants or `--allow`, or run commands in Git Bash with `FUIGO_SHELL=bash`. Git Bash on Windows and every Unix shell are unchanged. A hub judges by the shell of the machine it runs on: a command a Linux or macOS hub approves without a grant for a Windows peer running PowerShell or cmd.exe does not run there, and the peer says it needs your approval.

Some commands look read-only by name but can run another program, open a network connection, expose secrets, or depend on what the shell expands at run time. These always ask, even when the read-only list, a remembered prefix grant, "allow all commands" for the session, sandbox auto-allow or the Auto mode fast path would otherwise cover them. Only an approval of that exact full command runs them without a prompt.

- **A tool in a mode that runs a program or script:** `sed` with the `e` command or `s///e`, a `-f` script file, or a script only the shell resolves; `find -exec`/`-ok`, `fd -x`, `xargs`, `sudo`/`doas`, `rsync -e`, `go run`/`go install`/`go generate`/`go tool`/`-toolexec`/`go vet -vettool`, `git grep -O` (also inside a short-option cluster such as `-nO`), `rg --pre`, `rg` while `RIPGREP_CONFIG_PATH` is set to anything (see the inherited environment below), `sort --compress-program`, `scp -S`, `tar -I`/`--use-compress-program`/`--to-command`/`--checkpoint-action=exec=…`, `man -P`/`--pager`/`-H`, `wget --use-askpass`/`-e`/`--config`, and a shell reading its program from stdin.
- **Build tools in a mode that runs another program:** `make --eval`/`-E`, a makefile from stdin (`-f -`), `make -p` (prints every variable, the environment included), a variable that replaces the recipe shell or make's own options (`SHELL=`, `MAKEFLAGS=`, `MAKEFILES=`, ...) or holds a make function call (`'X=$(shell …)'`); `cmake -E`, `-P`, `-C`, `--toolchain`, `--open`, a `-D` naming a compiler, launcher, linker, make program or included script (`-DCMAKE_C_COMPILER=…`, `-DFOO_EXECUTABLE=…`), and make's options after `cmake --build DIR --`; `cargo --config` (`build.rustc-wrapper`, `target.*.runner`, aliases), `cargo -Z…` and `cargo doc --open`; `rustc -C linker=`/`link-arg=`/`link-args=`/`dlltool=`, `-Z…`, `--extern` of anything but an `.rlib`/`.rmeta`, and `@file` arguments; `pytest --pdb`/`--trace`/`--pdbcls` (the debugger reads stdin), `-p NAME` (`-p no:NAME` is fine) and `-o`/`--override-ini`; `just --shell`, `--shell-arg`, `--shell-command`, `-c`/`--command`, `--chooser`, `--choose` and `-e`/`--edit`; `bazel --run_under`, `--workspace_status_command`, `--credential_helper` and `--bazelrc`; npm-family options naming a program (`--script-shell`, `--node-options`, `--git`, `--node-gyp`, `--shell`, `--editor`, `--browser`, `--viewer`, also abbreviated); `uv --python PATH`/`-p PATH` (a version such as `3.12` is fine); `rustup doc` without `--path`; `go build -ldflags` naming an external linker (`-extld`), `-gccgoflags`, `go bug` and `go doc -http`; `gh --web`/`-w`, `gh auth status --show-token`/`-t`, and a `gh --jq`/`-q` filter reading the environment.
- **Interpreter code the command does not show:** inline code for `python`/`python3`/`pypy` (`-c`), `perl` (`-e`/`-E`, also inside a cluster such as `-lne`, a `-M` value that is not a plain module name), `ruby` (`-e`), `node` (`-e`/`--eval`/`-p`/`--print`, a `data:` preload), `deno eval`, `bun -e`/`exec`, `php` (`-r`/`-R`/`-B`/`-E`) and `lua` (`-e`), and a program read from stdin, a heredoc, a here-string or an interactive REPL (`python3 <<'PY'`, `python3 -i`, `irb`, a bare `tclsh`/`wish`). An interpreter option the classifier does not know, or a script only the shell resolves, counts as hidden code. A script operand naming stdin or a descriptor (`/dev/stdin`, `/dev/fd/0`, `/proc/self/fd/0`) is a program from a pipe and asks too, also after a shell's end of options (`bash -- /dev/stdin`, `bash - /dev/stdin`). A script file or module run (`python3 path.py`, `python3 -m pytest`, `node build.js`, `perl script.pl`, `uv run python -m pytest`) is visible code execution and is not floored: a glob grant naming the interpreter (`python3 *`), an exact command grant, "allow all commands" and sandbox auto-allow run it as before; a bare interpreter prefix grant stays pinned to the exact command. No interpreter invocation except a lone `--version`, `--help` or the interpreter's own version flag (`python3 -V`, `node -v`, `perl -v`/`-V`, `ruby -v`, `lua -v`, `php -v`) gets read-only or Auto mode routine approval, and PyPy's do not either.
- **awk:** an `awk`/`gawk`/`mawk`/`nawk` program is vouched for only when it is the first operand and contains none of `system`, `|`, `getline`, `ENVIRON`, `PROCINFO`, `SYMTAB`, `FUNCTAB`, `>`, `@`, a backslash, or a string spliced onto a name (an opening `"` right after a letter, digit or `_`, or a closing `"` right before one, as in `sy"s"tem`; ordinary strings such as `print "x"` and `$1=="foo"` are fine; an odd number of quotes asks). A program from `-f`/`--file`, `-e`/`--source` or a library, any option outside the plain set (`-F`, `-v`, `--assign`, `--field-separator` and flags that run nothing), an abbreviated long option, and a program only the shell resolves all ask. `>` is also awk's comparison, so `awk '$3 > 5'` asks too.
- **ssh, scp and sftp:** `-o` with `ProxyCommand`, `LocalCommand`, `PermitLocalCommand`, `KnownHostsCommand` (any `…Command` key, any case, attached or separate), a PKCS#11 or security-key provider, `Include` or `Match`; `-F`; `-S`; and `ssh -I`. Every `sftp` invocation asks: a batch file or a command list on stdin can run local `!` commands.
- **Network sockets:** a redirect to `/dev/tcp/…` or `/dev/udp/…`, in either direction.
- **Secrets:** environment reads always ask, and naming a variable does not exempt them: `env`, `printenv` (with or without a name), `set` with no operand, `export`/`declare`/`typeset`/`readonly`/`local` with only options or with `-p` (`declare -p TOKEN` included), `jq env` / `jq '$ENV'`, a `jq` filter file (`-f`, also in a cluster such as `-nf`) or `import`/`include`, awk `ENVIRON`/`PROCINFO`/`SYMTAB`, `ps` with the environment option, and a process environment file (`/proc/self/environ`, `/proc/thread-self/environ`, `/proc/<pid>/environ`, or any path into `/proc/self` or `/proc/<pid>`, also relative such as `proc/self`, and any glob that can match one, wildcard-only parts included, such as `/proc/s*/envi*` or `/pr?c/????/???????`; a glob too long to check quickly counts as a match) as an operand or a redirect source. Also kubectl Secret reads (`kubectl get secrets`, `get pods,secrets`, `describe secret`, `get --raw …`, and `get`/`describe` with `-f`/`--filename` or `-k`/`--kustomize`, whose resource kinds are in a file) and kubectl options that point it at another server or identity (`-s`/`--server`, including an attached `-shttps://…`).
- **Shell state:** `printf -v NAME`, a `printf` format holding `%n` (with any flags or width), and a `printf` format only the shell resolves: each can assign a shell variable (`PATH` included) that later commands in the same script resolve through. Also a `set` option that changes how later words are read (`set +B`, `set -f`, `set -k`, `set -o posix`; error-handling options such as `set -euo pipefail` are fine), `shopt`, `alias`, `unalias`, `enable` and `hash` with arguments, and an assignment such as `PATH=./bin` behind `command env`.
- **Wrappers:** an abbreviated or unknown option of `timeout`, `nice`, `stdbuf`, `ionice` or `chrt` (`timeout --sig TERM 5 …`) leaves the program it runs unknown.
- **Git:** `git grep -O` and the driver options (`--ext-diff`, `--textconv`, `--output`, …) also through a path-qualified or case-variant `git` and after any global option (`git --no-optional-locks grep -O…`); `git push` after global options (`git --no-pager push`) is on the dangerous list. A file in the repository that your own git config includes counts like `.git/config`, and so does a repository's `trace2.*Target` set to a path (it makes `git status` write a file) or `log.showSignature` set to true (it makes `git log` and `git show` run `gpg`). A `post-index-change` or `fsmonitor-watchman` hook in the repository's hooks directory (`.git/hooks`, shared by linked worktrees, or `core.hooksPath`), in the repository or a populated submodule, makes every git command ask, grants included: git runs them on read-only commands (`post-index-change` when `git status` refreshes the index). On Linux and macOS only a hook file with an execute bit counts, as git skips the others. The hooks `git lfs install`, `pre-commit install`, lefthook or overcommit write (`pre-commit`, `post-checkout`, `pre-push`, ...) never run on a read-only command, so `git status` and `git log` stay approved. A git command that is not a read-only query (`git commit`, `git checkout`, `git merge`, ...) in a repository with any hook of its own (any file of the hooks directory but a `*.sample`; on Linux and macOS an executable one) is not approved without a grant: the Auto mode fast path and routine-command check leave it to the model, told about the hooks, and in a trusted folder the model's allow stands; your grants, allow rules, "allow all commands" and sandbox auto-allow still apply. Hook names match the way git finds them: in any letter case (macOS and Windows volumes ignore case), and on Windows with any extension (`post-index-change.exe`). The same settings naming your own programs (`less -R`, `/usr/local/bin/difft`, `ssh -i ~/.ssh/key`) are yours and run as before.
- **Inherited environment** (set, with any non-empty value): every command asks while `LD_PRELOAD`, `LD_AUDIT`, `DYLD_INSERT_LIBRARIES` or any other `DYLD_*` not named below, `GCONV_PATH`, `BASH_ENV` or `ENV` is set. `git` asks while `GIT_EXTERNAL_DIFF`, `GIT_SSH`, `GIT_SSH_COMMAND`, `GIT_PAGER`, `GIT_EDITOR`, `GIT_SEQUENCE_EDITOR`, `GIT_ASKPASS`, `SSH_ASKPASS`, `GIT_PROXY_COMMAND`, `GIT_EXEC_PATH`, `GIT_CONFIG_COUNT`, `GIT_CONFIG_PARAMETERS`, `GIT_CONFIG_GLOBAL`, `GIT_CONFIG_SYSTEM`, `GIT_CONFIG`, `GIT_DIR`, `GIT_COMMON_DIR`, `GIT_TEMPLATE_DIR` or `LESSCLOSE` is set; `rg` with `RIPGREP_CONFIG_PATH`; `file` with `MAGIC`; `gh` with `GH_CONFIG_DIR`, `GH_PAGER`, `GH_BROWSER`, `BROWSER`, `GH_EDITOR`; `docker` with `DOCKER_CONFIG`; `npm`, `npx` and `pnpm` with `NPM_CONFIG_USERCONFIG`, `NPM_CONFIG_GLOBALCONFIG`, `NPM_CONFIG_SCRIPT_SHELL` (either case); `yarn` with `YARN_RC_FILENAME`; `cargo` with `RUSTC`, `RUSTDOC`, `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`, `CARGO_BUILD_RUSTC_WRAPPER`; `go` with `GOENV`, `GOFLAGS`; `go`, `make` and `cmake` with `CC`, `CXX`; `make` with `MAKEFILES`, `MAKEFLAGS`, `GNUMAKEFLAGS`; `cmake` with `CMAKE_TOOLCHAIN_FILE`; `node` with `NODE_OPTIONS`; `ruby` and `irb` with `RUBYOPT`; `perl` with `PERL5OPT`. Variables people commonly set get one simple check instead: the library search paths `LD_LIBRARY_PATH`, `DYLD_LIBRARY_PATH`, `DYLD_FALLBACK_LIBRARY_PATH`, `DYLD_FRAMEWORK_PATH` and `DYLD_FALLBACK_FRAMEWORK_PATH` (every command, each entry), `RUSTUP_TOOLCHAIN` (rustup tools; a plain toolchain name such as `stable` or a path outside the project), `PAGER` (git, gh), `LESSOPEN`, `EDITOR`, `VISUAL`, `XDG_CONFIG_HOME` (git, go), `KUBECONFIG` (kubectl, each entry), `CARGO_HOME` (cargo), `RUSTUP_HOME` (rustup tools), `GOROOT` (go), `ZDOTDIR`, `SHELL`, `FUIGO_SHELL`, `FUIGO_HOME` and `FUIGO_CONFIG_PATH` (every command), `FUIGO_TOOLS_UGREP_PATH` (grep), `FUIGO_TOOLS_BFS_PATH` (find), and `RG_BIN_PATH` and `RUNFILES_DIR` (Fuigo's own grep tool) must be a plain absolute path outside the project (letters, digits and `/._-+@,` only: no spaces, quotes, `~` or `$`), or for `PAGER`, `LESSOPEN`, `EDITOR`, `VISUAL`, `SHELL` and `FUIGO_SHELL` a plain program name such as `less` or `vim`; `PAGER='less -R'` asks.
- **Uncertain directory:** a `cd` in a pipeline or a subshell before a git command, a `cd` on the right of an `||`, and a `cd` on the left of an `||` when git may run on the right or anything runs after the `||` list, and a `cd` that runs only if an earlier command succeeded when more of the script follows (`ls x && cd dir; git status`), since the directory git runs in is not known. `cd repo && git status || echo missing` is certain and keeps its approval under your broad grants.
- **Arguments only the shell resolves:** quote fragments and escapes are joined the way bash joins them (`--p''re` is `--pre`) and brace groups are expanded before any check. A glob that could expand into an option or a program name (`cat *.md` asks; `cat ./*.md` does not under your broad grants), a glob inside an option value (`--include=*.rs`, `rg -g *.rs`; quote the whole word instead), a brace expansion over 64 words or nested deeper than 8, ANSI-C `$'…'` quoting, an empty quote pair next to `~` or a brace (`''~`), an expansion, or a structure the parser cannot decompose is treated as unknown. Where such a word is the script, program text or format of a tool above, that tool's floor applies.
- **Fuigo's own `grep` and `find`:** in the agent shell a plain `grep` runs the bundled ugrep and a plain `find` runs the bundled bfs, so their options are judged as those tools' options. For `grep`: `--filter=…` (runs a filter command per file), `--pager`, `--view`, `-Q`/`--query` (the interactive viewer, which can open `$PAGER` or `$EDITOR`), `--config`/`---FILE` (loads a configuration file from the working or home directory, anywhere before `--`, even as an `-e` value), `--save-config` (writes a file) and `--from` (searches the paths listed in a file). For `find`: `-rm` (the same as `-delete`), `-f PATH` (also at the end of a flag group such as `-Lf`), `-files0-from`, `-help`/`--help` (runs `$PAGER` on a terminal), and a path after the expression (`find . -name x /etc` searches `/etc`). Neither tool accepts abbreviated long options.
- **Program identity:** a path-qualified or case-variant program name (`./env ls`, `/tmp/x/timeout 5 ls`, `bin/explorer ls`, `LS`) never gets read-only or Auto mode routine approval, because it is whatever file sits at that path. A plain name resolves through `PATH` as before.

A destructive command from the [dangerous list](#dangerous-commands) also asks under a session-wide grant and sandbox auto-allow (the Auto mode fast path already blocked it).

#### Shell state between commands

The agent's shell keeps its state (directory, variables, functions, aliases, options) from one command to the next. Before each command, Fuigo drops any function or alias named like a program it approves by name (`ls`, `cat`, `git`, `python3`, ...) or like a shell builtin its own wrapper uses (`builtin`, `command`, `eval`, `read`, `trap`, `source`, `.`, ...), and the command-not-found hook. In zsh it also drops every global alias (`alias -g`), every suffix alias (`alias -s`), every `TRAP*` function and the hook functions (`chpwd`, `periodic`, `precmd`, `preexec`, `zshaddhistory`, `zshexit`); in bash it clears the `DEBUG`, `RETURN`, `ERR` and `EXIT` traps and `PROMPT_COMMAND`. It resets the shell options that change how plain words are read or run code around a command: bash `keyword`, `histexpand`, `xtrace`, `functrace` and `errtrace` off; zsh `EQUALS`, `MAGIC_EQUAL_SUBST`, `AUTO_CD`, `XTRACE` and `PROMPT_SUBST` off; `PS4` back to its default. So a function or alias you define in your shell startup files, or one an earlier command defines, with one of those names does not carry over between the agent's commands: `alias ls='ls --color'` or a `git` wrapper function is gone for the agent. The only replacements Fuigo keeps are its own `grep` (ugrep) and `find` (bfs). If such a name cannot be dropped (a `readonly` function, or a startup file that replaces zsh's `functions` hash), Fuigo refuses every agent command with `fuigo: refusing to run: …` until the startup file is changed and the session restarted.

An approved command runs with your full authority. It can do anything you could do in that shell, including changing the state later commands run in (defining functions, changing `PATH` or options, editing your startup files). Fuigo's checks judge each command as it is written, not what an earlier approved command left behind, so approve only commands you would run yourself.

What is deliberately **not** floored:

- Your grants are not held to the plain-text rule (see [Read-Only Shell Commands](#read-only-shell-commands)). "Allow all commands" and sandbox auto-allow keep every floor in this section, and also ask for structure the parser cannot decompose (a variable or command substitution, a loop, a function, a subshell, a declaration such as `export FOO=1`); approve that exact script to remember it. The catch-all rule still asks for the tool-mode, build-tool, interpreter, awk, ssh, network-socket, secret, shell-state and uncertain-directory cases above, and for an argument only the shell resolves (`cat *`), except in a recovered filename script such as `LOG=./out.log; ls -lh "$LOG"`. It does not ask for a dangerous-list command or for structure the parser cannot decompose into plain commands (a `for` loop, a brace sequence such as `{1..99999}`).
- In Auto mode, routine build and test commands (`make`, `make all`, `cargo build`, `cargo test`, `npm test`, `npm run build`, `pytest`, `go test`, `just`, `bazel build`, ...) run the repository's own build code (its Makefile, build scripts, test files and package scripts) without asking: running project code is what they are for. Ask mode never does: these programs are not on its read-only list, so they ask unless you granted them (a remembered grant, "allow all commands" or sandbox auto-allow). The forms listed above (inline makefiles, config and wrapper overrides, installs and registry changes, paths outside the project) ask in Auto mode too.
- Interpreter and module search paths (`PYTHONPATH`, `PYTHONSTARTUP`, `NODE_PATH`) are not checked: the only interpreter forms approved without a grant are a lone version or help flag, which loads no module (CPython exits on `--version`, `-V` and `--help` before it imports `site`, so neither a `sitecustomize.py` in the folder or on `PYTHONPATH` nor a `.pth` file runs), and `pytest` runs the project's tests and `conftest.py` by design. `NODE_OPTIONS`, `RUBYOPT` and `PERL5OPT` make their interpreter ask (see above).
- Ordinary network use (`curl`, `ssh host command`, `git fetch`) under a session-wide grant: what a command can reach over the network is the sandbox's job (see [18-sandbox.md](18-sandbox.md)). Only the local-program options above are floored.
- A pager run on its own (`less file`) or a command's default pager; only an option that names the pager program is floored.
- `time` in front of a command under your broad grants (without a grant it is not plain text and asks).

---

---

## Configuring Permissions

Fuigo reads permission rules from three compatible sources. Rules from all sources are merged into one set; a rule's effect depends on its action (`deny` > `ask` > `allow`), not on which file it came from.

### Where Permission Rules Live (Scopes)

Permission rules can be global (all projects), project-scoped (one repository), or personal to you within a project:

| Scope | File | Shared with teammates |
|-------|------|-----------------------|
| Global (all projects) | `~/.fuigo/config.toml` | No |
| Project (committed) | `<project>/.fuigo/config.toml` | Yes (commit it) |
| Project (personal) | `<project>/.claude/settings.local.json` | No (gitignore it) |
| Interactive grants | Stored internally by Fuigo, per project | No |

Notes on scoping:

- Fuigo discovers a `.fuigo/config.toml` at every directory level from the repository root down to your working directory, so a subdirectory can add rules on top of the repo root's.
- Rules from all scopes are merged into one rule set; `deny` > `ask` > `allow` applies across scopes, so a global `deny` cannot be overridden by a project `allow`.
- Fuigo has no native `config.local.toml`. For personal, uncommitted rules in a project, use `.claude/settings.local.json`; Fuigo reads it directly (see [Claude Code Compatibility](#3-claude-code-compatibility-claudesettingsjson)).
- Interactive "Always allow" decisions are stored outside the repository, scoped to the project (see [Interactive Approvals](#interactive-approvals-and-where-they-persist)).

To stop prompts for a specific command in one project, add a narrow allow rule to that project's `.fuigo/config.toml` (or `.claude/settings.json`):

```toml
[permission]
allow = ["Bash(cargo test *)", "Bash(npm run build)"]
```

This approves only the listed commands. Always-approve mode, by contrast, approves all tool calls.

### 1. CLI Flags

```bash
fuigo -p "Review the API changes" \
  --allow 'Bash(git *)' \
  --allow 'Bash(gh *)' \
  --allow 'Read' \
  --allow 'Grep' \
  --deny 'Bash(rm -rf *)'
```

`--allow RULE` and `--deny RULE` can be repeated and are always enforced.

Rule syntax examples:
- `Bash(git *)` — any command starting with `git `
- `Bash(npm run build)` — exact command (or prefix)
- `Bash(git commit:*)` — the `cmd:*` suffix form, equivalent to prefix matching on `git commit`
- `Read(src/**)` — read access under `src/`
- `Edit(**/*.rs)` — edit any Rust file
- `Grep` — all grep operations
- `MCPTool(my-server__*)` — MCP tools from a specific server

See [Rule Matching Reference](#rule-matching-reference) for the exact matching semantics, including how chained commands and wildcards are evaluated.

### 2. Native Configuration (`~/.fuigo/config.toml` and `.fuigo/config.toml`)

```toml
[permission]
rules = [
  { action = "allow", tool = "bash", pattern = "git *" },
  { action = "allow", tool = "bash", pattern = "gh *" },
  { action = "allow", tool = "read" },
  { action = "allow", tool = "grep" },
  { action = "deny",  tool = "bash", pattern = "rm -rf *" },  # block a dangerous pattern
  { action = "ask",   tool = "edit" },
]
```

The structured `tool` field accepts the lowercase names `bash`, `read`, `edit`, `grep`, `mcp`, `webfetch`, and `websearch`, corresponding to the tool classes in [Tool Names](#tool-names).

Because `deny` always wins, you cannot combine these `allow` rules with a catch-all `deny` on `bash` to mean "only allow git/gh"; a `deny tool = "bash"` rule would block `git` and `gh` too. For deny-by-default, use `defaultMode: "dontAsk"` in `.claude/settings.json` or a `PreToolUse` hook (below).

Rules from the global `~/.fuigo/config.toml` and every project `.fuigo/config.toml` (from the repo root down to your working directory) are merged into one rule set, alongside any `.claude/settings.json` rules.

Managed configuration deployed by your organization also contributes `[permission]` rules: the system `/etc/fuigo/managed_config.toml`, and a user-level copy that Fuigo maintains automatically at `~/.fuigo/managed_config.toml`. Managed rules merge like rules from any other source, with two properties specific to managed `allow` rules: your own `deny` and `ask` rules win over a managed `allow` (severity ordering), and a catch-all managed `allow` is ignored when always-approve is locked off. For rules that users cannot edit away, use the root-owned system `/etc/fuigo/requirements.toml`.

Permission rules from every source are read once, when a session starts. Changes apply to the next session.

The native `[permission]` section also accepts the compact `allow` / `deny` / `ask` string-array form, using the same rule strings as the `--allow` / `--deny` flags and `.claude/settings.json`:

```toml
[permission]
deny = [
  "Read(/Users/you/private/**)",
  "Edit(/Users/you/private/**)",
  "Bash(rm -rf *)",
]
allow = [
  "Bash(git *)",
  "Bash(gh *)",
]
```

`deny` always wins over `allow` (evaluation is `deny` > `ask` > `allow`), regardless of order or source. To block reads of paths outside your project at the OS level as well, combine deny rules with the `strict` sandbox profile (see [18-sandbox.md](18-sandbox.md)).

### 3. Claude Code Compatibility (`.claude/settings.json`)

Fuigo reads `~/.claude/settings.json` and `~/.claude/settings.local.json`, plus the project-level `<project>/.claude/settings.json` and `settings.local.json` (walking up to the repo root). The native `.fuigo` source for permission rules is `config.toml`, described in the section above.

Example:

```json
{
  "permissions": {
    "defaultMode": "dontAsk",
    "allow": [
      "Read",
      "Grep",
      "Bash(git *)",
      "Bash(gh *)"
    ],
    "deny": [
      "Bash(rm -rf *)"
    ]
  }
}
```

Supported `defaultMode` values include `default`, `auto`, `acceptEdits`, `bypassPermissions`, `dontAsk`, and `plan`. Fuigo reads `defaultMode` from its canonical location under `permissions`; a top-level `defaultMode` is also accepted when the nested key is absent.

`permissions.allow`, `permissions.deny`, and `permissions.ask` entries are translated into native rules and then matched with the semantics in the [Rule Matching Reference](#rule-matching-reference). Translation notes:

- Rules for MCP tools may use either the `mcp__server__tool` form found in `.claude/settings.json` files or the native `MCPTool(server__tool)` form (see [MCP Rules](#mcp-rules)).
- Rules naming an unrecognized tool, and parameter rules such as `Agent(model:opus)`, are skipped with a warning rather than failing the load.
- `permissions.additionalDirectories` is parsed but not supported.

You can import existing Claude settings interactively with **Ctrl+I** ("Import Claude settings").

---

## Rule Matching Reference

This section defines exactly how rules are matched.

### Bash Rules

A `Bash(...)` pattern matches a command (each chained segment, for `allow` rules — see "Chained commands" below) in either of two ways:

- **Prefix**: the command starts with the pattern text, compared character for character. There is no word-boundary requirement, so `Bash(git)` matches `gitleaks` as well as `git status`. Include a trailing space and wildcard (`Bash(git *)`) to require the prefix to be a whole word.
- **Glob**: the pattern matches the whole command (or the whole segment) as a glob. `*` can appear at any position and matches any characters, including spaces and slashes, so `Bash(git * main)` matches `git checkout main`. `?` and `[...]` are also supported.

Matching is case-sensitive. Leading whitespace in the command is trimmed before matching. For `deny` and `ask` rules the raw command string is otherwise not normalized; segment-level checks additionally match normalized forms (see below).

A trailing `:*` suffix on a Bash rule is stripped to a plain prefix: `Bash(git commit:*)` becomes prefix `git commit`. Because prefixes have no word boundary, a `deny` written as `Bash(sed:*)` also blocks commands such as `sed-custom`.

**Chained commands.** Fuigo parses each command like a shell and splits it on `&&`, `||`, `;`, `|`, and newlines. The rule actions treat segments differently:

- `deny` and `ask` rules are checked against every segment, and against the whole string. One denied segment rejects the entire command.
- `allow` rules are conjunctive: the command is auto-approved by rule only when **every** segment independently matches an allow rule. `Bash(git *)` approves `git status && git diff`, but not `git status && rm -rf /` — the `rm` segment matches no allow rule, so the command falls through to the mode's normal handling (a prompt in `default` mode; the classifier in `auto` mode, which may still approve or block it; a denial under `dontAsk`). A single allow rule can therefore never approve a chain that smuggles in an unrelated command.

> **Allow rules are not a closed allowlist.** A command that matches no allow rule is not thereby denied — it falls through to the mode. In `auto` mode the classifier can approve commands your rules never mention. For deny-by-default policies, use `dontAsk` (or always-approve plus `deny` rules for hard blocks), as described under [Configuring Permissions](#configuring-permissions).

Commands that cannot be split into simple segments (subshells, command substitution `$(...)`, backticks, background `&`, control flow) prompt as a single unit when Bash restrictions are configured.

Each segment is normalized before rules are matched. Leading environment assignments such as `RUST_LOG=debug` are stripped, and a fixed set of wrappers (`timeout`, `nice`, `ionice`, `chrt`, `stdbuf`, `env`) is peeled away, so rules match the inner command: `Bash(npm test *)` approves `RUST_LOG=debug timeout 30 npm test --workers=4`. This applies to `deny`, `ask`, and `allow` rules and remembered grants. The read-only command list applies only once a command is plain text, and a command with an assignment or a wrapper in front is not (see [Read-Only Shell Commands](#read-only-shell-commands)).

A few more matching details:

- Rules also apply inside a literal script passed to `bash -c`. For `allow`, every command inside that script must itself be allowed.
- Wrappers not on the list (`sudo`, `xargs`, `nohup`, …) are not peeled. Write rules that name them explicitly.
- When the parser cannot safely peel a form (for example `env -S`), the command prompts instead of matching an `allow` rule.
- Matching sees the parsed words joined by single spaces, without shell quotes. Write patterns against the unquoted command.

### Dangerous Commands

A built-in list (`rm`, `chmod`, `chown`, `chgrp`, `chattr`, `pkill`, `kill`, `killall`, `git push`) prompts even when a segment is covered by a remembered command prefix or the read-only command list. An explicit `allow` rule in configuration does approve them, and always-approve mode auto-approves them like any other command; use `deny` rules to block them unconditionally. Review rules like `Bash(rm *)` carefully before adding them as allow rules.

### Read, Edit, and Grep Rules

Path patterns are globs matched against the tool path after lexical normalization (`.`/`..` collapsed; relative paths joined with the session working directory). A `~`-prefixed tool path is matched literally — never joined with the working directory — because tools expand `~` to the home directory only after the permission check:

- `*` and `?` do not cross `/`; `**` does. `Read(src/*)` matches `src/main.rs` but not `src/nested/mod.rs`; use `Read(src/**)` for the whole tree.
- A bare filename matches only that exact string. Use `**/.env` to match `.env` at any depth.
- There are no anchor prefixes: a leading `//` or `~/` in a pattern is treated as literal glob text. Write absolute-path patterns or `**/` patterns instead.
- Because `.`/`..` are collapsed before matching, rooted patterns cannot be escaped by traversal: `Read(./**)` scopes to the working directory (bare relatives like `src/main.rs` match; `./../../etc/passwd` does not), and `Read(src/**)` stays under `src/`. Unrooted patterns (`*`, or a leading `**` as in `**/*.rs`) intentionally match at any depth, anywhere.
- `Read` rules also govern `grep` searches; `Grep(...)` rules match only grep.
- Native Read/Edit/Grep checks follow in-path symlinks for deny and ask on the resolved target. An allow that matches only the resolved target does not grant allow for the tool argument.
- An in-path symlink that cannot be resolved prompts when any deny or ask file rule applies to that tool.

`Read` and `Edit` deny rules additionally apply to file paths that shell commands touch (for example `cat` or `sed` on a denied path), including literal inline scripts passed to `bash`, `sh`, `dash`, `zsh`, or `ksh` with `-c`. The shell-level check uses the same working-directory-aware normalization and symlink follow for deny/ask as the direct Read/Edit/Grep tools described above (an absolute operand under the working directory also matches rooted rules like `Read(src/**)`). For OS-level enforcement that covers every process, combine deny rules with the sandbox ([18-sandbox.md](18-sandbox.md)).

### MCP Rules

`MCPTool(...)` patterns match the full Fuigo tool name in `server__tool` form, with glob support: `MCPTool(linear__*)` matches every tool from the `linear` server. Fuigo tool names carry no `mcp__` prefix.

The `mcp__` rule spelling used in `.claude/settings.json` files is also accepted and rewritten onto the same matcher: `mcp__linear` (every tool on the `linear` server), `mcp__linear__get_issue` (one tool), `mcp__linear__*` (every tool on the server), and `mcp__*` (every MCP tool).

### WebFetch Rules

- `WebFetch(domain:example.com)` matches that host and every subdomain (`api.example.com`), case-insensitively, ignoring a leading `www.`. Wildcards are not supported inside `domain:` patterns.
- A pattern without the `domain:` prefix globs against the entire URL: `WebFetch(https://api.example.com/*)`.

### Tool Names

Recognized tool names: `Bash`, `Read`, `Edit` (and `Write`), `Grep` (and `Glob`), `MCPTool`, `WebFetch`, `WebSearch`. A bare `*` rule matches every tool. Globs are not supported in the tool-name position.

Rules naming an unrecognized tool (for example `Agent(model:opus)`) are skipped with a warning rather than failing the load.

### Evaluation Order

Rules from every source are merged into one set and evaluated by severity, not order: any matching `deny` rejects, otherwise any matching `ask` prompts, otherwise any matching `allow` approves. When no rule matches, the request falls through to the built-in auto-approvals and then the prompt policy, as described in [How a Tool Call Is Authorized](#how-a-tool-call-is-authorized).

---

## Interactive Approvals and Where They Persist

When a tool call requires approval, the permission prompt offers these choices:

- **Allow once**: approve this single invocation.
- **Reject once**: reject it, optionally with a message back to the model.
- **Enable always-approve mode**: approves all future tool calls, not just the one being prompted.
- **Allow all edits this session**: shown for file edits. This grant is held in memory only and does not survive a restart.

### Per-Command "Always Allow"

A narrower set of options remembers just the specific command, MCP tool, or web-fetch domain being prompted, for example "Always allow `cargo test`". These rows are on by default. Disable them with:

```toml
# ~/.fuigo/config.toml
[ui]
remember_tool_approvals = false
```

Organizations can disable them via the same key in `requirements.toml` or managed configuration. With the gate enabled (the default), prompts gain:

- **`Always allow: <command>`**, which persists an allow for the command prefix.
- A matching "never allow" row, which persists a deny the same way.
- Equivalent "always allow" and "never allow" rows for MCP tools and web-fetch domains. The "never allow" row always remembers the exact tool (never a whole server) or the exact domain being prompted; a remembered deny wins over any grant, and a denied domain also covers its subdomains.

The remembered prefix is limited to a short form of the command: read-only commands persist just their listed prefix (for example `git status`, not the full argument list), and other commands persist a short leading prefix. The prompt shows exactly what will be remembered before you confirm.

Commands on the [dangerous list](#dangerous-commands) (for example `git push` and `rm`) never honor a remembered *prefix*: only an exact grant for the entire command counts, so their "Always allow" row defaults to the full command. Approving it stops prompts for that exact invocation only; any different arguments prompt again. When no rememberable grant could stop a script from prompting again — a dangerous command behind an `env` prefix, or a chain whose other steps would still need approval — the "Always allow" row is not offered at all rather than saving a rule that would not work.

### Persistence Is Per Project

Interactive grants are stored in Fuigo's own state directory under your home directory, scoped to the git repository you launched Fuigo in (its repository root), so a grant accepted at the repo root also applies in sessions started from a subdirectory of the same repository. Outside a git repository, grants are scoped to the launch directory, and each git worktree keeps its own grants. A grant made in one project never applies in another, grants are not written into the repository, and they are not meant to be hand-edited.

To inspect or reset a project's grants, open the `sessions` subdirectory of your Fuigo home (the `.fuigo` directory under your home directory, or `$FUIGO_HOME`): each project directory there (URL-encoded scope root) holds a `permission.toml` (plus per-client `permission_<client>.toml` variants) listing the remembered command prefixes, globs, MCP tools/servers, web-fetch domains, and "never allow" entries. Deleting the file resets that project's grants; the next matching tool call prompts again. Treat it as read-only state — to *add* rules, use the declarative `[permission]` configuration instead.

Interactive grants are personal, per-machine state. For an allowlist you can review in code review and share with teammates, use declarative rules in the project's `.fuigo/config.toml` instead.

---

## Restricting Bash to Specific Commands with a Hook

A `PreToolUse` hook can enforce an allow list on the `Bash` tool that applies in every permission mode. Hooks are evaluated before the permission system; a hook deny stops the call, and a hook allow falls through to the normal permission checks (so your `deny` rules still apply).

> **Note:** Hooks fail open. If a hook script crashes, times out, or is missing, the tool call proceeds as if the hook had allowed it, and the failure is reported in the UI. A hook used as a security boundary must handle its own errors, and must account for chained commands, as the example below does. See [10-hooks.md](10-hooks.md).

### Example: Allow Only `git` and `gh`

**`~/.fuigo/hooks/git-gh-only.json`**

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash",
        "hooks": [
          {
            "type": "command",
            "command": "git-gh-only.sh",
            "timeout": 5
          }
        ]
      }
    ]
  }
}
```

**`~/.fuigo/hooks/git-gh-only.sh`**

```bash
#!/bin/sh
# Allow only git and gh commands, including within chained commands.

set -eu

deny() {
  echo '{"decision": "deny", "reason": "'"$1"'"}'
  exit 2
}

INPUT=$(cat)
CMD=$(echo "$INPUT" | jq -r '.toolInput.command // empty')

[ -n "$CMD" ] || deny "Empty command is not allowed"

# Normalize '&&' and '||' to ';' so chains can be checked segment by
# segment, then reject constructs this script cannot inspect.
CMD=$(echo "$CMD" | sed 's/&&/;/g; s/||/;/g')
case "$CMD" in
  *'$('*|*'`'*|*'&'*|*'>'*|*'<'*) deny "Substitution, background, and redirection are not permitted" ;;
esac

# Split on the separators and require every segment to start with git or gh.
echo "$CMD" | tr ';|' '\n\n' | while IFS= read -r SEGMENT; do
  SEGMENT=$(echo "$SEGMENT" | sed 's/^[[:space:]]*//')
  [ -n "$SEGMENT" ] || continue
  case "$SEGMENT" in
    git\ *|git|gh\ *|gh) ;;
    *) deny "Only git and gh commands are permitted. Blocked segment: $SEGMENT" ;;
  esac
done
```

```bash
chmod +x ~/.fuigo/hooks/git-gh-only.sh
```

This hook denies every `Bash` command unless each chained segment starts with `git` or `gh`, and rejects command substitution, backgrounding, and redirection outright because it cannot verify what they execute. It works in every permission mode.

For hook installation, the JSON format, the trust model for project hooks, and other events, see [10-hooks.md](10-hooks.md), which also contains a complementary "block dangerous patterns" example.

---

## Example Configurations

### Headless git and gh Only (CI and Automation)

```bash
fuigo -p "Implement the feature using only git and GitHub CLI" \
  --allow 'Read' \
  --allow 'Grep' \
  --allow 'Bash(git *)' \
  --allow 'Bash(gh *)'
```

Install the `git-gh-only` hook above to deny every other `Bash` command. For deny-by-default on all tools, also set `{"permissions": {"defaultMode": "dontAsk"}}` in `.claude/settings.json`.

### Read-Only Code Reviewer

```toml
# .fuigo/config.toml
[permission]
rules = [
  { action = "allow", tool = "read" },
  { action = "allow", tool = "grep" },
  { action = "deny",  tool = "edit" },
  { action = "deny",  tool = "bash" },
]
```

### Interactive Development

Use `default` mode plus narrow `Bash(...)` allow rules for the commands you run most (`git`, `cargo test`, `rg`, and similar).

---

## Shell commands you type with `!`

A command you type with `!` is not asked about: it never shows an approval prompt. What it does obey are the denials. Before it runs, it is refused if a `Bash` deny rule (user, project or managed) matches it, if managed policy locks the session down, if it reads or writes a file that a deny rule covers, or if a `UserPromptSubmit` or `PreToolUse` hook blocks or denies it (see [Hooks](10-hooks.md)). Ask rules, `dontAsk`, plan mode and the auto-mode classifier do not refuse a `!` line and do not prompt for one: only an explicit deny does. This has a limit you should know: a deny rule stops a `!` line only when Fuigo can read the command well enough to match it. A line it cannot take apart (for example `bash -c "$VAR"`, `eval ...`, or a redirect to a variable) would only make Fuigo ask if the model had requested it, so as a `!` line it runs. Your own saved "never allow" answers to earlier prompts are not applied to `!` lines either: they record what you told the model, not a policy. The sandbox applies to it as before. A refused command does not run, and the line you see names what refused it.

## Combining with the Sandbox

Permissions control what the model is allowed to request. The OS-level sandbox (see [18-sandbox.md](18-sandbox.md)) controls what the process can do even after a command is approved.

Recommended combination for untrusted code:

1. `dontAsk` plus narrow allow rules, or a restrictive hook
2. `--sandbox strict` or a custom profile
3. Project trust plus review of any `SessionStart` hooks

---

## Managing Permissions in the TUI

- Permission decisions appear in the transcript.
- The `/always-approve` command toggles always-approve mode; other modes are set through `defaultMode` (see [How to set the mode](#how-to-set-the-mode)).
- Permission prompts include per-command "Always allow" options that persist for the current project only (on by default; disable with `[ui] remember_tool_approvals = false`). See [Interactive Approvals](#interactive-approvals-and-where-they-persist).
- To manage hooks and plugins, run `/hooks` or `/plugins` (on most terminals, **Ctrl+L** also opens the Extensions modal; on VS Code, Cursor, Windsurf, and Zed, `Ctrl+L` is mid-turn interject instead). See [10-hooks.md](10-hooks.md).

---

## Best Practices

1. **Prefer narrow patterns.** `Bash(git *)` grants less access than a bare `Bash` allow rule.
2. **Combine layers.** `dontAsk`, narrow allow rules, a restrictive hook, and the sandbox each restrict independently.
3. **Review project configuration from unfamiliar sources.** Folder trust gates project permission rules in `.fuigo/config.toml` and `.claude/settings.json` (including `allow` rules and `defaultMode`), plus startup loading of project instructions (`AGENTS.md`, rules) and project skills. An untrusted checkout's copies are skipped, and their presence triggers the folder-trust question; a headless run with these sources needs `--trust` or a prior grant. Review them and any project hooks before trusting an unfamiliar checkout (see the security notes in [10-hooks.md](10-hooks.md)).
4. **Test your policy.** With `defaultMode: "dontAsk"` set (or your `PreToolUse` hook installed), run representative commands and confirm what is blocked.
5. **Treat the read-only command list as a convenience, not a security boundary.**

---

## See also

- [Hooks](10-hooks.md) — PreToolUse and other lifecycle scripts
- [Headless mode](14-headless-mode.md) — One-shot CLI and automation flags
- [Agent mode](15-agent-mode.md) — ACP, stdio, and agent servers
- [Sandbox](18-sandbox.md) — OS-level isolation profiles
- [Configuration](05-configuration.md) — Native `config.toml` structure


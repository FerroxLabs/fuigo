# R-xs-home0700: Fuigo home created 0700, peer inbox message names the fix

## Cause
`fuigo_dirs::fuigo_home()` created the home with `create_dir_all` (mode 0777 & !umask). A normal Ubuntu user has umask 002,
so `~/.fuigo` came out 775 and `peer_inbox/dirs.rs` (`open_home`, `HomeWritableByOthers`, rule unchanged) refused to
start the inbox. The npm postinstall and bootstrap also made `~/.fuigo/bin` with `mkdirSync(..., {recursive:true})`, which
creates `~/.fuigo` the same way. All earlier tests ran as root with umask 022.

## Change
- `fuigo_dirs::ensure_private_home(path)` (`crates/codegen/fuigo-dirs/src/lib.rs`): if the home does not exist, create parents
  as before, then create the home alone with `DirBuilder::mode(0o700)`. No chmod: `mkdir` applies `mode & !umask`, a umask only
  removes bits, so 0700 survives every umask. An existing home is never touched. Non-unix: plain `create_dir`.
- Creation sites and coverage:
  - `fuigo-dirs/src/lib.rs` `fuigo_home()` (was `create_dir_all`): now calls the helper. Every `fuigo_config::fuigo_home()`,
    `user_fuigo_home()` and `util::fuigo_home::fuigo_home()` caller goes through it.
  - `fuigo-pager-bin/src/main.rs` `main()`: early `fuigo_config::fuigo_home()` right after the `--version`/`doctor` dispatch,
    before the fd-limit check, subscription commands, requirements gate and every session path. The pager, `agent stdio`,
    headless and `agent leader` are all this one binary, so this is their common early init.
  - Writers that take the home as a parameter and `create_dir_all` under it (`shell/src/builtin.rs:19`,
    `extensions/marketplace.rs:1281`, `auth/storage.rs:437,447`, `config/global_hook_sources.rs:320`, sessions/logs/auth/
    downloads writers using `create_dir_all_owner_only`): their home argument comes from `fuigo_home()`, already created by main.
  - `fuigo-fast-worktree` `WorktreeDb::open` now calls `fuigo_dirs::ensure_private_home(home)` before its `create_dir_all` (the crate
    already depended on `fuigo-dirs`; no new edge). `open_at` with an arbitrary path is unchanged.
  - Shell installers `fuigo-pager/scripts/install.sh` and `install-enterprise.sh` (both `#!/bin/bash`, use `$HOME/.fuigo`, no FUIGO_HOME):
    `ensure_private_home()` (`[ -d "$1" ] || ( umask 077 && mkdir -p "$1" )`, POSIX) runs before the `mkdir -p` of downloads/bin and
    before the completions `mkdir -p`. An existing home is not chmod-ed. No other script in the repo creates `~/.fuigo`.
  - npm: `bin/fuigo-replace.js` `ensureFuigoHome(home)` (mkdir of the home alone with mode 0o700 when missing, EEXIST ignored),
    called from `bin/postinstall.js` and `bin/fuigo-bootstrap.js` before the `bin` dir is made. `bin` and below keep default modes.

## Message
`/peers status`, `/peers list` and the ACP `unavailable` error now say
`peer messaging is unavailable: the Fuigo home is not private to this user (run: chmod go-w <home>)`
(`peer_inbox/host.rs` `reason_message`; path escaped and capped by `display_escape`, 160 chars). `Disabled::reason_text()` keeps its
fixed text (prefix of the new one). The command is printed only when the home consists solely of `[A-Za-z0-9_./~+@:-]`, does not
start with `-` and was not truncated; otherwise (space, `;`, `$()`, backtick, quote, newline, non-ASCII, leading `-`) the message is
`peer messaging is unavailable: remove write access for group and others from the Fuigo home: <escaped path>` (no command, one line).
A missing/empty home falls back to `reason_text()`. User guide chapter 28 (troubleshooting table and one paragraph) updated.

## Tests (fail on 4073e481: helper and message function do not exist; JS home came out 775)
- `fuigo-dirs`: `fresh_home_is_0700_under_umask_002_and_existing_home_is_untouched`.
- `fuigo-shell/peer_inbox/locator_tests.rs`: `home_created_under_umask_002_is_private_and_accepted` (real `CheckedDir::create_or_open`),
  `existing_group_writable_home_is_not_modified_and_reason_names_chmod`.
- `fuigo-shell/peer_inbox/locator_tests.rs`: `reason_message_prints_a_command_only_for_a_shell_safe_path`;
  `host_tests.rs`: `status_of_a_group_writable_home_yields_the_message_with_the_armed_home` (host status -> `PeerHost::reason_message`).
  Home availability: a `Failed` phase is only reached through `run_start(home)` with `home` from `arm` (`host.rs` `session_started`,
  `g.home.clone()` else return), and `reason_message` reads that same host's home; it is never cleared. If absent: generic text.
- `fuigo-update/tests/test_install_sh.rs`: `install_scripts_create_a_missing_fuigo_home_private_and_keep_an_existing_one` runs the REAL
  `install.sh` and `install-enterprise.sh` (fake curl, offline) under `umask 002`: fresh HOME gives `.fuigo` 700, existing 775 stays 775.
  Runs with `cargo test -p fuigo-update --test test_install_sh` (not wired into CI by this change; the crate's tests already run there).
- `npm/fuigo/scripts/test-postinstall.js`: fresh home 0700 under `process.umask(0o002)`, existing 775 home unchanged.

## Not changed / limits
- An existing home (775 from an older version) is never modified: the user runs `chmod go-w ~/.fuigo` once, as the message says.
- The ANCESTOR case still shows the generic text: the `Disabled` value is `Copy` and does not carry the offending directory.
- Step 5 (real-process umask 002 test) skipped: the PTY harness pre-creates the temp home and has no umask hook; setting the
  umask in the test process is process-global and would race the parallel tests.
- Other `[[bin]]` dev tools were not audited for home creation; `fuigo-fast-worktree` `open_at(path)` with a caller path is unchanged.
- The `dash -n` check fails on both installers because they are bash scripts (arrays/`local`); only the new function is POSIX.
- A host that embeds the crates without `fuigo-pager-bin::main` still gets 0700 through `fuigo_home()` as long as that is the first creator.

# Fuigo 1.0.46 release notes

## Security

- **Shell settings from a sandboxed command are no longer replayed as code into less-sandboxed commands.** In 1.0.45 and earlier, shell settings left by a sandboxed command (environment, aliases, functions, options) were replayed as code into later commands, including less-sandboxed ones. 1.0.46 replays them as data and only into commands that are at least as sandboxed; a less-sandboxed command starts from your login shell state, keeps the working directory, and shows a one-line notice.
- **Shell state is restored strictly as data.** Anything a command writes into the saved state that is not a plain value is dropped, a command can no longer replace the state with a frame it writes itself, and denied variables are never restored from a snapshot.
- **Variables that make a shell or the loader run code are not carried.** `BASH_ENV`, `ENV`, `PS4`, `PROMPT_COMMAND`, `ZDOTDIR`, `LD_PRELOAD`, `LD_LIBRARY_PATH` and `DYLD_*` set by a sandboxed command no longer reach later less-sandboxed commands (they still carry to the next sandboxed command where that is safe).
- **Tracing and `noexec` never carry over.** `xtrace`, `verbose` and `noexec` are not restored between commands, in any spelling.
- **Recalled memory is framed as untrusted data.** The notice now appears on every path: the system message, the post-compaction reminder, and `memory_search` and `memory_get` results.
- **The memory screen reads through encodings.** It now catches instructions hidden in base64, hex, URL, ROT13 and escape encodings, invisible tag characters, reversed text, long identifier-heavy notes, and "ignore previous instructions" in 14 languages.
- **`memory_search` results are screened like automatic recall.** Flagged excerpts are dropped and flagged file names are withheld.
- **Resumed sessions re-screen cached memory.** A session saved by 1.0.45 drops its cached memory block and rebuilds it with the untrusted-memory notice and current screening; a block from an older policy can no longer pass as current by embedding the new marker.
- **Secret redaction was rebuilt.** Every rule now reads the original text and all redactions are written in one pass, so one rule can no longer hide a secret from another. URL passwords are removed the way the URL parser reads them: slashless `https:user:pw@host`, upper-case schemes, extra slashes or backslashes, several `@`, any scheme, IPv6 hosts, passwords with spaces or non-ASCII characters, and URLs split by a tab, newline or carriage return. Secret query values are redacted for any scheme, and URL fragments are written as `#redacted`. URLs are otherwise left byte-for-byte as they were, and Windows paths with an `@types` folder are no longer mangled. Credential assignments written with percent escapes inside a URL, values that are URLs ending in `...`, and text after a URL that ends in a valueless credential key such as `?db_password` are all redacted.
- **Password-like values that contain a credential word are redacted.** For example `correct.horse.secret` no longer reaches telemetry text.
- **bwrap lookup is safer on Linux.** Fuigo looks in system folders first, skips a bubblewrap that your user or others could replace, warns when it has to use one from `PATH`, and reports a missing bubblewrap clearly without ever launching it from the current directory. `/status` shows which launcher is in use.
- **Dependencies updated.** The TLS stack (rustls, webpki, bundled roots), rmcp, zip, zstd, SQLite, git2, tokio and others are updated to clear published advisories.
- **Windows: sandbox optional, off by default.** The warning and docs now say so and point to WSL2 for anyone who wants a sandbox. There is no Windows sandbox; use WSL2 with bubblewrap.

## Fixes

- **zsh `setopt` changes now persist between commands**, as do changes to `PATH` and other exported tied parameters, and `typeset -U PATH`.
- **Multi-line aliases carry between commands** in bash and zsh.
- **Shell state survives long commands.** Working directory, exported variables and aliases are no longer lost after a command that runs longer than 5 seconds.
- **A command that ignores SIGTERM after its timeout no longer freezes the shell session.**
- **macOS stock bash 3.2:** a 5-second stall after a command timeout is gone, programs a command runs no longer inherit the shell-state channel, and up to 200 ms of extra time per command with a background job left running is removed.
- **MCP "always allow" grants from 1.0.45 no longer warn "definition changed"** after you upgrade.
- **The MCP "definition changed" warning notices a new image tag or numeric option**; per-run ports stay quiet.
- **A server you switched off stays off** when a client server's name differs from it only in punctuation.
- **A managed-policy update stops and keeps the current policy** if its revision floor cannot be saved.
- **Signed-URL uploads choose the proxy or direct path** using the URL as the HTTP library normalizes it.
- **A sign-in error callback with no state is held for 5 seconds** so a valid callback arriving meanwhile wins; valid callbacks are unaffected.

## Improvements

- **`fuigo doctor --report`** prints a Markdown summary of your setup (version, OS, terminal, sandbox, trust, providers, MCP servers, plugins, leader, recent errors) to paste into a bug report. Nothing is sent anywhere, and secrets, URLs, headers and environment values are left out.
- **Clearer sandbox messages.** The Linux bubblewrap line in `/status` and the Windows sandbox hint appear in the startup warning, `/status` and the welcome screen.

## Developer and CI

- **`cargo-deny` runs in the release gate**, so advisories and license problems stop a release.
- **Fuzzing:** one script now fuzzes the tool-call splitter, the ACP reader, the secret scrubber and the proxy matcher.
- **Benchmark gate:** each release is compared with the previous one on a fixed set of coding tasks before it is tagged; a drop in solved tasks blocks the release.
- **Tests and structure:** new regression tests for the fixes above, flaky telemetry span tests stabilised, source-text tests made independent of formatting, and the two largest permission modules split into smaller files with no change in behaviour.

# Changelog

Each release has its own notes under `docs/`. Binaries and npm platform packages are attached to the matching [GitHub release](https://github.com/FerroxLabs/fuigo/releases); the npm package is [`fuigo`](https://www.npmjs.com/package/fuigo).

| Version | Notes | Highlights |
| --- | --- | --- |
| 1.0.31 | [release notes](docs/release-notes-1.0.31.md) | Fix: switching provider with `/model` no longer replays reasoning the new provider rejects; `/remember` reports the real file it wrote or that the note was not saved; session rules survive a model switch; MCP tool progress reaches the client; untrusted-folder tests; project-rules guide corrected; new README, brand and community files. |
| 1.0.30 | [release notes](docs/release-notes-1.0.30.md) | Shared leader: one owner per session, prompts go only to the owner; project and `npx` copies no longer update the global install; more global-install layouts recognised. |
| 1.0.29 | [release notes](docs/release-notes-1.0.29.md) | Shared leader: only the window that owns a session can change its permission mode; npm 11 install and upgrade fixes; two fixes for messages between sessions. |
| 1.0.28 | [release notes](docs/release-notes-1.0.28.md) | Fixes for messages between sessions: refusals are reported, text-only replies are no longer treated as refusals. |
| 1.0.27 | [release notes](docs/release-notes-1.0.27.md) | `bearer_token_file` for HTTP MCP servers works on Windows with the same owner-only rule as macOS and Linux. |
| 1.0.26 | [release notes](docs/release-notes-1.0.26.md) | Loud warning when a sandbox profile is set on Windows; MCP bearer token from a file; `/context-window`; one shell wait setting; larger Windows stack. |
| 1.0.25 | [release notes](docs/release-notes-1.0.25.md) | Named sessions that list and message each other (off by default); headless warning when an MCP server fails to start; parked sessions for host applications. |
| 1.0.24 | [release notes](docs/release-notes-1.0.24.md) | Security and reliability: permission and admin-policy rules hold in more places; multi-window Windows fixes; far fewer requests after a key or sign-in stops working. |
| 1.0.23 | [release notes](docs/release-notes-1.0.23.md) | Build and shipping only: signed Windows and macOS programs; Linux builds run on older distributions; Linux ARM crash fixed. |
| 1.0.22 | [release notes](docs/release-notes-1.0.22.md) | Subscription sign-in fixes: repeated ChatGPT replies, and Grok and ChatGPT subscription models being refused. |
| 1.0.21 | [release notes](docs/release-notes-1.0.21.md) | Workspace memory moves to a new folder on first use; cumulative notes for 1.0.18 to 1.0.20 apply when upgrading from 1.0.17. |

Releases before 1.0.21 are listed on the [releases page](https://github.com/FerroxLabs/fuigo/releases). The release process itself is described in [RELEASE.md](RELEASE.md).

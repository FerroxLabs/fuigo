# Fuigo 1.0.30 release notes

This release follows 1.0.29. It closes the remaining gaps in the shared leader, stops project and `npx` copies from updating your global install, and fixes several smaller problems.

## Shared leader

- Each session now has exactly one owner, decided by the leader. Only the owner can change the session's mode (plan, default, agent), its model, its other settings, turn plan mode on or off, rename, delete, close or park it, or change its MCP servers. Before, any window connected to the leader could. A permission mode change the leader refuses, such as Shift+Tab to Always-Approve in a window that does not own the session, is no longer saved as the mode new windows start in, and the window goes back to the mode it was in. If an older shared leader is still running, a mode change in an open session is not saved as the default, and Fuigo says so once; run `fuigo leader kill` to restart the leader. Resetting permissions skips sessions another window owns.
- Permission prompts and the other questions a session asks, such as questions to you, plan approval, file requests and MCP sign-in prompts, now go only to the window that owns the session, and only that window's answer counts. Before, every window that had the session open was asked and the first answer won, so another window set to approve everything could approve the owner's tool calls. A question asked while the owner is reconnecting waits for the session's next owner. Remote clients through the relay follow the same rule.
- When a window opens a session another window owns, it can no longer replace that session's MCP servers, system prompt or client hooks, including when the session is first loaded from disk.
- A remote client connected through the relay follows the same rule as any other window. Its hold on a session ends once nothing it asked for is still running and 60 seconds have passed with no message from it and no output in that session, or as soon as the relay connection drops. Anything it left unanswered then goes to the first window already waiting to take the session over; if no window is waiting, it is dropped. While the relay owns a session, prompts only the owner can answer are not sent to local windows. Sending a message to a session never makes a window or the relay its owner.
- When the owner's window closes or loses its connection, the session waits 30 seconds for that same window to reconnect and take it back. After that, the first window still open that tried to open the session becomes its owner, and it can reconnect and take the session back in the same way. Prompts only the owner can answer, such as file requests and scheduled prompts, including those from a subagent's own subagents, are held during those 30 seconds (up to 64 per session) and delivered to whoever then owns the session.
- A load that fails, from a window or through the relay, or closing or deleting a session, no longer leaves anyone as the session's owner.
- When a window opens a session with its own system prompt, that prompt is now kept even if Fuigo switches the session back to the model it was last used with. Before, the switch could replace it with the model's default prompt.
- Without the shared leader (the default), a session can now be open in only one window at a time. Before, two windows could open the same session and overwrite each other's changes, such as switching plan mode. Opening a session that is already open in another window, with `--resume` or from `/resume`, now says so and leaves the session as it is (from `/resume`, the picker closes and your window stays on the session you were in): close it in the other window first, or turn on the shared leader (`--leader`) to use it from several windows. The shared leader keeps to the same rule with windows that do not use it, and a window that closes or crashes frees its sessions straight away. Deleting, renaming or repairing a session that is open in another window is refused the same way, and the automatic cleanup of old sessions leaves such a session alone.

## Installing with npm

- A copy of Fuigo installed inside a project, or run with `npx`, no longer updates itself by installing the latest version globally. `fuigo update` in such a copy tells you how to update it instead (`npm i fuigo@latest` in the project, or `npx fuigo@latest`).
- Fuigo recognises more global installs: a custom npm prefix on Windows, Scoop, Volta, Yarn, pnpm and bun. A project folder that happens to be named `lib` is no longer mistaken for a global install, and a global npm folder that has a `package.json` beside it (for example a Windows npm prefix set to your home folder) is no longer mistaken for a project.
- On Windows, starting an older global copy (for example from another Node version) no longer replaces a newer installed version, as was already the case on macOS and Linux.
- `fuigo update` and automatic updates now finish setting up the new version even when npm hides part of the install path. npm 11 prints anything that looks like an ID in a path as `***`; Fuigo now asks npm to run the setup in the package's own folder instead of reading that path.

## Other

- A history save that cannot reach the session's writer is now logged instead of being lost silently.
- With a sign-in configured by your organisation, the subscription screen no longer shows from an out-of-date answer while Fuigo is still checking your subscription. A second check made at the same moment now waits for the first one's result.
- Tests: two campaign tests that depended on a sign-in Fuigo does not use now supply the campaign directly; four model-switch tests used a model type Fuigo does not have and now use one it does; tests no longer leave shared-leader processes running after they finish; tests for urgent announcements and subscription checks now run against a secure test server the way Fuigo talks to the real one; lint warnings fixed; the leader test that only ran on Unix now runs on Windows too.

## Known limits

- After the 30-second wait, Fuigo cannot tell the original window reconnecting late from any other window, so the first window that tried to open the session becomes its owner.
- On Windows, every run goes through a small launcher that checks the installed version before starting Fuigo, as before.

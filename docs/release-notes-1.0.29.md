# Fuigo 1.0.29 release notes

This release follows 1.0.28. It closes a gap in the shared leader, fixes installing and upgrading with npm 11, and fixes two problems with messages between sessions.

## Shared leader

- When several windows share one Fuigo process (the leader), only the window that owns a session can now change that session's permission mode. Before, any program running as your user could connect to the leader, give the name of the Fuigo window, and switch that window's sessions to always-approve or auto. The leader now gives each connection its own id, which the connecting program cannot choose, and a session accepts a mode change only from the connection that started, loaded or resumed it. A mode change that arrives without that id changes nothing.
- When a window connected to the leader opens a session that another connected window is using, the session's permission mode does not change and the session stays with the window using it, whatever the request asks for.
- A program connected to the leader can no longer ask for another window's session history to be sent to it. The leader now always records the real connection that made the request.
- The same applies to a remote client connected through the relay: it can change the mode only of sessions it started, loaded or resumed.
- A single window that runs without a shared leader works as before.

## Installing with npm

- `npm install -g fuigo` no longer runs an install script. npm 11 skips install scripts it has not been told to allow and printed a warning about `allowScripts`. Fuigo now sets itself up the first time you run it, so there is nothing to allow and no warning.
- Upgrading with npm 11 now runs the new version. In 1.0.28, npm 11 skipped the install script, so after an upgrade Fuigo kept starting the version it had installed before. If you upgraded to 1.0.28 with npm 11 and `fuigo --version` still shows an older version, installing 1.0.29 fixes it.
- `fuigo update` and automatic updates now finish setting up the new version themselves before they report success or restart Fuigo. If that setup fails, the update reports an error and automatic updates wait 6 hours before trying that version again; `fuigo update` tries again straight away.
- Only a global install (`npm install -g`) sets up `~/.fuigo` when it starts. A copy of Fuigo installed inside a project, or run with `npx`, starts its own binary and does not set up `~/.fuigo`. On macOS and Linux, starting an older global copy never replaces a newer installed version.
- Fuigo reads the npm registry setting from your home folder, so a project's `.npmrc` is no longer copied into your Fuigo settings. If `config.toml` cannot be read, Fuigo leaves it as it is instead of replacing it.
- Reinstalling the same version with a changed binary still replaces it, as in 1.0.25. `FUIGO_HOME` is still honoured. With `FUIGO_INSTALL_COMPLETIONS=1`, shell completions are now installed the first time Fuigo runs instead of during `npm install`.

## Messages between sessions

- A message from another session that arrives while a window is still on its start screen now shows in that window. Before, it went to a hidden session and nothing appeared.
- A message that was held, released and then held again is now treated as held again. Before, Fuigo could treat it as delivered.

## Other

- A test of the language-server support no longer depends on a 200 ms timing and no longer fails on a busy machine. Fuigo's behaviour is unchanged.

## Known limits

- When the window that was using a session has closed, another window that opens the session can become its owner, as before. Fuigo cannot tell a window that reconnected from another program.
- A remote client connected through the relay that opens a session a local window is using takes the session over, as before, and the same is true the other way round. The relay is your own signed-in account.
- Opening a session that another window is using can still change that session's MCP servers, system prompt and client hooks, as in 1.0.28. It cannot change its permission mode.
- A copy of Fuigo installed inside a project, or run with `npx`, still updates itself the way an npm install does: an automatic update installs the latest version globally and sets up `~/.fuigo`, as in 1.0.28. Start it with `--no-auto-update`, set `[cli] auto_update = false` in `~/.fuigo/config.toml`, or use a global install, if you do not want that.
- The first run after installing or upgrading with npm takes a moment longer while Fuigo unpacks itself. Later runs start directly.
- On Windows, every run goes through a small launcher that checks the installed version before starting Fuigo, as it did before.

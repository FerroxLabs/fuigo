# Fuigo 1.0.37 release notes

## Windows

- **On Windows, a PATH ending in `;` no longer makes every shell command ask.** Empty `PATH` entries (a trailing
  `;`, or `;;`) mean nothing on Windows, so Fuigo now drops them from the `PATH` of the shell commands it runs, both
  in its own shell and in an editor's terminal (it sends that `PATH` with the command when the editor runs it), and
  no longer counts them as an entry that can steer which program runs. A relative entry, `.`, or an entry inside the
  project still makes commands ask, and macOS and Linux are unchanged (there an empty entry is the current folder).
- **Editor terminals now get the same environment check as Fuigo's own shell.** When an editor runs a command for
  Fuigo in its own terminal, a command approved without asking (a read-only command, or one Auto mode approved) is
  now checked against the environment Fuigo sends with it, as Fuigo's own shell already did. If that environment
  can change which program runs (for example a session `PATH` that puts `.` or a folder of the project first, from
  your settings or a trusted `.envrc`), the command does not run and Fuigo says why; an allow rule, your answer or
  "allow all commands" still runs it.

# Fuigo 1.0.34 release notes

## Hooks

- One switch for embedding apps: `FUIGO_MANAGED_HOOKS_ONLY` (any non-empty value except `0`) makes a Fuigo process behave as if managed policy had set `allow_managed_hooks_only = true`. Only hooks from `/etc/fuigo/managed_config.toml` and `/etc/fuigo/requirements.toml` run. Your own hooks (`~/.fuigo/hooks`, `~/.claude`, `~/.cursor`, the hooks in `config.toml`), project hooks, plugin hooks and agent hooks are all skipped, and enabling or adding one is refused with a note that names the variable. It applies in the terminal app, headless `-p` and ACP alike. It can only tighten: it never turns off a pin your organization set, and with it unset or `0` nothing changes.
- The headless-mode guide has a new "Embedding Fuigo" section. It also says that on Windows Fuigo finds its home folder from `USERPROFILE`, not `HOME`, so an app isolating a child run there must set `USERPROFILE` (and `FUIGO_HOME`), not only `HOME`.

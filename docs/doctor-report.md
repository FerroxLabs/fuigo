# `fuigo doctor --report`

When something goes wrong, run one command and paste what it prints into your bug report:

```sh
fuigo doctor --report
```

The report is Markdown, made on your machine and printed to your terminal. **Nothing is sent anywhere**: there is no upload, no telemetry and no network call. Read it once before you paste it.

## What it contains

| Section | What it shows |
|---------|---------------|
| Environment | Fuigo version and commit, OS and architecture, kernel, shell, terminal (with multiplexer and SSH), install method (npm global, npm local or `npx`, standalone) |
| Sandbox and trust | Sandbox mode and which layer set it, whether it was lowered (for example `enforce` on a host with no backend), the backend, the `bwrap` path, the current folder and whether it is trusted |
| Models and providers | Default model, configured model names and provider names. Names only: never a key, URL or header |
| Leader and peers | Whether the shared leader is set in your config, and whether peer messaging is on |
| MCP servers | Name, transport (`stdio (program)`, `http` or `sse`), enabled or not, and scope. Never a URL, header, argument or environment value |
| Plugins | How many are installed |
| Config files | Where your config, managed config, sandbox config, project config and log live, and whether each exists |
| Recent errors | The last 10 `error` lines of `~/.fuigo/logs/unified.jsonl` |

## What it leaves out

Values are collected as names and states, not contents, so an API key, bearer token, header, URL with a key in it or MCP environment variable is never read into the report. Everything that is printed also goes through the same secret sanitizer Fuigo uses for crash reports: credential shapes become redacted placeholders, your home folder is shown as `~`, other users' names are removed from paths, control characters are stripped, and each value is one line of at most 300 characters.

The sanitizer works on patterns. If your own log lines hold a secret in a shape it cannot recognise, that text can still appear under "Recent errors", so look at that section before you paste.

## Related

- `fuigo doctor` prints the terminal and clipboard checks, with `fuigo doctor --json` for scripts and `fuigo doctor fix` for automatic fixes.
- `fuigo doctor --report` cannot be combined with `--json`.

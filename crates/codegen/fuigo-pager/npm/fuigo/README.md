# Fuigo

Bring Fuigo into your terminal. Fast, flicker-free CLI built for plans, subagents, and parallel work.

## Install

```bash
npm i -g fuigo
```

npm downloads only the binary matching your platform, not all six.

## Get Started

```bash
# Launch the interactive TUI
fuigo

# Run a single task
fuigo -p "Explain this codebase"
```

On first launch, Fuigo helps you set up a provider. For CI or headless environments, set an API key directly:

```bash
export FUIGO_API_KEY="fuigo-..."
```

## Update

```bash
fuigo update
```

Or if installed via npm:

```bash
npm i -g fuigo@latest
```

## Supported Platforms

| Platform | Architecture |
|---|---|
| macOS | Apple Silicon (arm64), Intel (x86_64) |
| Linux | x86_64, arm64 |
| Windows | x86_64, arm64 |

## Documentation

Fuigo ships its own documentation. Run `/docs` inside the TUI, or read the
extracted copy under `~/.fuigo/docs/user-guide/`, covering configuration, MCP
servers, custom models, headless mode and agent mode.

## Feedback

Run `/feedback` inside Fuigo to report issues or send feedback directly.

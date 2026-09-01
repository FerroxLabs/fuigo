# Fuigo

Bring Fuigo into your terminal. Fast, flicker-free CLI built for plans, subagents, and parallel work.

**[Homepage](https://x.ai/cli)** | **[Documentation](https://docs.x.ai/build/overview)**

## Install

```bash
curl -fsSL https://x.ai/cli/install.sh | bash
```

Or install with npm:

```bash
npm i -g fuigo
```

## Get Started

```bash
# Launch the interactive TUI
fuigo

# Run a single task
fuigo -p "Explain this codebase"
```

On first launch, Fuigo opens your browser to authenticate. For CI or headless environments, use an API key from [console.x.ai](https://console.x.ai):

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
| macOS | Apple Silicon (arm64) |
| Linux | x86_64, arm64 |
| Windows | x86_64 |

## Documentation

For full documentation including configuration, MCP servers, custom models, headless mode, agent mode, and more, visit [docs.x.ai/build/overview](https://docs.x.ai/build/overview).

## Feedback

Run `/feedback` inside Fuigo to report issues or send feedback directly.

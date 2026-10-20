<p align="center">
  <img alt="Fuigo. The model is the fire. Fuigo is the bellows." src="https://raw.githubusercontent.com/FerroxLabs/fuigo/main/docs/assets/brand/banner-dark.png" width="900">
</p>

# Fuigo: the open coding agent that holds its own with the best, on any model

On 24 hard, real-world engineering tasks, with every agent on the same model, Fuigo solved **43 of 48** runs. Claude Code solved 41 and Grok Build 41. Fuigo did it for **18-27% less per solved task**, with no timeouts. ([How we tested](https://github.com/FerroxLabs/fuigo/blob/main/docs/benchmark.md))

It isn't tied to one model company. Bring an OpenAI or Anthropic key, sign in with your ChatGPT subscription, or run a model on your own machine. It reads your code, edits it, runs your tests, and **asks before it changes a file or runs a command**. Kernel sandboxing, outbound destination checks and folder trust are built in, not bolted on. It remembers what it learned. And it is one engine: the same agent runs in your terminal, unattended in CI, or inside your product. It is the engine behind [Murage](https://github.com/FerroxLabs/murage)'s AI workforce.

Apache-2.0. Yours to own.

[Source and README](https://github.com/FerroxLabs/fuigo) · [Connect a model](https://github.com/FerroxLabs/fuigo/blob/main/docs/connect-a-model.md) · [User guide](https://github.com/FerroxLabs/fuigo/blob/main/crates/codegen/fuigo-pager/docs/user-guide/README.md) · [Releases](https://github.com/FerroxLabs/fuigo/releases)

## Install

Requires Node.js 20 or newer. The launcher installs the native binary for macOS, Linux or Windows (arm64 and x64).

```sh
npm install -g fuigo@latest
fuigo --version
```

Update later with `fuigo update` or `npm install -g fuigo@latest`.

## Quickstart

```sh
fuigo login --provider chatgpt     # or set OPENAI_API_KEY / ANTHROPIC_API_KEY / FUIGO_API_KEY
fuigo                              # opens the terminal UI in the current folder
fuigo -p "Summarise this repo"     # same engine, one answer, no UI
```

On first launch Fuigo asks for a key, or offers one it finds in your environment. Every model route, including subscriptions, gateways and local servers, is covered in [Connect a model](https://github.com/FerroxLabs/fuigo/blob/main/docs/connect-a-model.md).

## Three ways to work

- **Terminal UI.** Run `fuigo` in a project. Fuigo reads files, runs commands and edits code, asking for permission first. Switch the permission mode with `Shift+Tab` and models with `/model`. See [getting started](https://github.com/FerroxLabs/fuigo/blob/main/crates/codegen/fuigo-pager/docs/user-guide/01-getting-started.md).
- **Headless CLI.** `fuigo -p "..." --output-format json` returns text or JSON for scripts and CI. See [headless mode](https://github.com/FerroxLabs/fuigo/blob/main/crates/codegen/fuigo-pager/docs/user-guide/14-headless-mode.md).
- **ACP agent.** `fuigo agent stdio` runs Fuigo as an agent for an editor, an SDK or your own application, over [ACP](https://agentclientprotocol.com). See [agent mode](https://github.com/FerroxLabs/fuigo/blob/main/crates/codegen/fuigo-pager/docs/user-guide/15-agent-mode.md).

To bundle the engine with an application, pin a Fuigo version and include the matching `@fuigo` platform package. The Rust workspace is implementation source, not a separately versioned public SDK. Preserve the included license and attribution files when redistributing.

## Memory

Workspace memory is local and on by default; global sharing, remote embeddings and background model processing are opt-in. Use `/remember`, `/flush`, `/dream` and `/memory` to manage it, or set `[memory] enabled = false` to turn it off. See the [memory guide](https://github.com/FerroxLabs/fuigo/blob/main/crates/codegen/fuigo-pager/docs/user-guide/13-memory.md).

## Documentation

Run `/docs` in the terminal, or read the [user guide](https://github.com/FerroxLabs/fuigo/blob/main/crates/codegen/fuigo-pager/docs/user-guide/README.md): [permissions and safety](https://github.com/FerroxLabs/fuigo/blob/main/crates/codegen/fuigo-pager/docs/user-guide/22-permissions-and-safety.md), [custom models](https://github.com/FerroxLabs/fuigo/blob/main/crates/codegen/fuigo-pager/docs/user-guide/11-custom-models.md), [MCP servers](https://github.com/FerroxLabs/fuigo/blob/main/crates/codegen/fuigo-pager/docs/user-guide/07-mcp-servers.md), [sandbox](https://github.com/FerroxLabs/fuigo/blob/main/crates/codegen/fuigo-pager/docs/user-guide/18-sandbox.md).

## License and lineage

Fuigo is licensed under Apache-2.0. See the included `LICENSE`, `NOTICE`, and third-party notices for origin, modification, and dependency attribution. Fuigo originated as a modified derivative of Grok Build and is independently maintained by Ferrox Labs; it is not affiliated with or endorsed by xAI or SpaceXAI.

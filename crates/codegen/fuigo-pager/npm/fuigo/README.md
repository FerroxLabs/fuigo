# Fuigo

**An engine for AI that can act, collaborate, and remember.**

Fuigo is a general-purpose, multi-provider AI agent engine for research, analysis, creation, and work across connected tools. Its Rust runtime provides execution, persistent sessions, subagents, permission controls, and workspace-scoped cross-session memory. Built-in tools work with files, search, and terminal commands; configured MCP servers extend its reach into external services.

Work alongside it in the terminal, request files or structured outputs from a script, or use ACP to build your own application interface. Specialized document formats and external operations depend on the tools you connect.

[Source and full setup guide](https://github.com/FerroxLabs/fuigo) · [Documentation](https://github.com/FerroxLabs/fuigo/tree/main/crates/codegen/fuigo-pager/docs/user-guide)

## Install

Requires Node.js 20 or newer:

```sh
npm install -g fuigo@latest
fuigo --version
```

The launcher selects your platform binary. Packages target macOS, Linux, and Windows on arm64 and x64.

## Connect a model

| Route | Supported connection |
| --- | --- |
| OpenAI directly | API key; Chat Completions or Responses |
| Anthropic directly | API key; Messages API |
| Flux Router and compatible gateways | Supported API protocol and gateway credentials |
| Local models, including Ollama | OpenAI-compatible endpoint |
| ChatGPT and Grok subscriptions | Explicit provider login and entitled models |

### Direct API keys

Set `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` in your environment, then add the corresponding entry to `~/.fuigo/config.toml`. Replace model placeholders with IDs available to your account:

```toml
[model.openai]
model = "REPLACE_WITH_YOUR_OPENAI_MODEL_ID"
base_url = "https://api.openai.com/v1"
api_backend = "responses" # or "chat_completions"
env_key = "OPENAI_API_KEY"

[model.anthropic]
model = "REPLACE_WITH_YOUR_CLAUDE_MODEL_ID"
base_url = "https://api.anthropic.com/v1"
api_backend = "messages"
auth_scheme = "x_api_key"
env_key = "ANTHROPIC_API_KEY"
extra_headers = { "anthropic-version" = "2023-06-01" }
```

Run `fuigo -m openai` or `fuigo -m anthropic`. The Anthropic configuration sends the key as `x-api-key`. Set context and output limits for your selected model; use `env_http_headers` for additional secret gateway headers.

### Subscriptions

```sh
fuigo login --provider chatgpt
fuigo models --provider chatgpt
```

Add a named model to `~/.fuigo/config.toml`, replacing the placeholder with a model ID from the list:

```toml
[auth_provider.chatgpt-subscription]
subscription = "chatgpt"

[model.chatgpt-subscription]
model = "REPLACE_WITH_MODEL_ID_FROM_LIST"
base_url = "https://chatgpt.com/backend-api/codex"
auth_provider = "chatgpt-subscription"
```

```sh
# Work interactively in your project
fuigo -m chatgpt-subscription

# Return structured output from a bounded task
fuigo -m chatgpt-subscription -p "Compare the proposals in this folder" --output-format json --max-turns 4

# Run as an agent for an ACP-capable client
fuigo agent --model chatgpt-subscription stdio
```

For Grok subscriptions, Flux Router, and compatible gateways, follow the [full setup guide](https://github.com/FerroxLabs/fuigo#connect-a-model). The [custom-model guide](https://github.com/FerroxLabs/fuigo/blob/main/crates/codegen/fuigo-pager/docs/user-guide/11-custom-models.md) also includes local Ollama configuration. Features depend on the selected model and protocol. Subscription login does not import other applications' credentials, and a subscription denial does not silently fall back to a paid API key.

Fuigo 1.0.8 enables local workspace memory by default. Global sharing, remote embeddings and automatic background model processing are opt-in. Use `/remember`, `/flush`, `/dream`, and `/memory` to manage it; set `[memory] enabled = false` to disable it. Applications can choose their own policy. Lexical search needs no embedding service.

## Update

```sh
npm install -g fuigo@latest
```

## Bundle the engine

Pin a Fuigo version and include the matching `@fuigo` platform package when distributing it with an application. Your application can launch `fuigo agent stdio` and handle the ACP interface. The Rust workspace is implementation source, not a separately versioned public SDK. Preserve the included license and attribution files when redistributing the engine.

## Documentation and licensing

Run `/docs` in the terminal or read the [source documentation](https://github.com/FerroxLabs/fuigo/tree/main/crates/codegen/fuigo-pager/docs/user-guide) for permissions, sandboxing, model configuration, MCP, headless tasks, and ACP integration.

Fuigo is licensed under Apache-2.0. See the included `LICENSE`, `NOTICE`, and third-party notices for origin, modification, and dependency attribution. Fuigo originated as a modified derivative of Grok Build and is independently maintained by Ferrox Labs; it is not affiliated with or endorsed by xAI or SpaceXAI.

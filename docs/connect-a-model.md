# Connect a model

Fuigo reads user configuration from `~/.fuigo/config.toml`, or from `$FUIGO_HOME/config.toml` when you set a separate home. Each model is a named `[model.<name>]` entry; start Fuigo against one with `fuigo -m <name>`, or switch inside the UI with `/model <name>`. Model IDs and supported features depend on the provider and your account.

On first launch with no configuration, Fuigo asks for a Flux Router key or offers a supported key it finds in your environment, and stores it in `~/.fuigo/auth.json`. The recipes below are for everything beyond that default. The [custom-model guide](../crates/codegen/fuigo-pager/docs/user-guide/11-custom-models.md) covers context-window limits, default headers, query parameters and credential resolution in full; the [authentication guide](../crates/codegen/fuigo-pager/docs/user-guide/02-authentication.md) covers OIDC and external identity providers.

## OpenAI API key

Set `OPENAI_API_KEY` in your shell and add a named model:

```sh
export OPENAI_API_KEY="YOUR_OPENAI_API_KEY"
```

```toml
[model.openai]
model = "REPLACE_WITH_YOUR_OPENAI_MODEL_ID"
base_url = "https://api.openai.com/v1"
api_backend = "responses"
env_key = "OPENAI_API_KEY"
```

```sh
fuigo -m openai
```

For a model that speaks Chat Completions, set `api_backend = "chat_completions"` instead.

## Anthropic API key

```sh
export ANTHROPIC_API_KEY="YOUR_ANTHROPIC_API_KEY"
```

```toml
[model.anthropic]
model = "REPLACE_WITH_YOUR_CLAUDE_MODEL_ID"
base_url = "https://api.anthropic.com/v1"
api_backend = "messages"
auth_scheme = "x_api_key"
env_key = "ANTHROPIC_API_KEY"
extra_headers = { "anthropic-version" = "2023-06-01" }
```

```sh
fuigo -m anthropic
```

`auth_scheme = "x_api_key"` sends the environment-supplied key as `x-api-key`; no key is written into the config file. Set context and output limits to match the model you select. For gateway-specific secret headers, use `env_http_headers`.

## ChatGPT and Grok subscriptions

Sign in, then list the model IDs your account can use:

```sh
fuigo login --provider chatgpt
fuigo models --provider chatgpt
```

Add a named model, replacing the placeholder with an ID from the list:

```toml
[auth_provider.chatgpt-subscription]
subscription = "chatgpt"

[model.chatgpt-subscription]
model = "REPLACE_WITH_MODEL_ID_FROM_LIST"
base_url = "https://chatgpt.com/backend-api/codex"
auth_provider = "chatgpt-subscription"
```

```sh
cd /path/to/project
fuigo -m chatgpt-subscription
```

Grok subscription login is `fuigo login --provider xai`; list its models with `fuigo models --provider xai`. The [authentication guide](../crates/codegen/fuigo-pager/docs/user-guide/02-authentication.md#chatgpt-and-grok-subscriptions) has the matching named-model configuration plus account selection, `--status` and `logout`.

Subscription credentials live in Fuigo's own store; login does not import another application's session. Access depends on your account's entitlements, and a subscription denial never falls back to a paid API key or to Flux Router.

## Flux Router and other gateways

Set your Flux Router key in the shell, then define an explicit route:

```sh
export FUIGO_API_KEY="YOUR_FLUX_ROUTER_API_KEY"
```

```toml
[model.flux]
model = "REPLACE_WITH_YOUR_FLUX_ROUTER_MODEL_ID"
base_url = "https://api.fluxrouter.ai/v1"
env_key = "FUIGO_API_KEY"
```

```sh
fuigo -m flux
```

For any other OpenAI-compatible or Anthropic-compatible gateway, add a separate named model with its own `base_url`, `api_backend` and credentials. Protocol compatibility does not mean every model behind a gateway supports every agent feature (tool calls, streaming, reasoning effort).

## Local models

Any server that speaks the OpenAI Chat Completions protocol works, Ollama included. Point a named model at it:

```toml
[model.ollama-codellama]
model = "codellama"
base_url = "http://localhost:11434/v1"
name = "CodeLlama (Ollama)"
```

```sh
ollama serve && ollama pull codellama
fuigo -m ollama-codellama
```

Chat Completions is the default backend, so `api_backend` can be omitted. The [Ollama example](../crates/codegen/fuigo-pager/docs/user-guide/11-custom-models.md#ollama-local-models) and the [local server section](../crates/codegen/fuigo-pager/docs/user-guide/11-custom-models.md#local-openai-compatible-server) of the custom-model guide show the remaining options, such as `temperature` and a display `name`.

## Checking a route

```sh
fuigo -m <name> -p "Reply with the single word ok" --max-turns 1
```

A reply means the route, credentials and protocol all work. If Fuigo reports a model or authentication error, the guide's [credential resolution](../crates/codegen/fuigo-pager/docs/user-guide/11-custom-models.md#credential-resolution) section lists the order in which keys are looked up.

# Connect a model

Fuigo asks one question on first launch, and again whenever you type `/login`: **Choose how Fuigo reaches a model.** Pick a row and sign in. That is the whole setup: Fuigo finds the account's models itself, picks a default if you have not set one, and lists them in `/model`. You do not edit a config file.

```
Choose how Fuigo reaches a model.

  1  Flux Router: one key, every model (recommended)
  2  ChatGPT subscription (Plus/Pro)
  3  Grok subscription
  4  Provider API key...
  q  Quit
```

An **Enterprise SSO** row appears below the provider key row only when your deployment configured an issuer or an external sign-in command. In `/login`, the last row reads **Cancel**, and each row shows its state ("signed in", "key ••••1234"), so `/login` also switches accounts.

## The ways in

| Row | What it does | Where the credential lives |
|-----|--------------|----------------------------|
| **Flux Router** | One key reaches every model. Paste a key (get one at fluxrouter.ai), or take the `FLUX_API_KEY` Fuigo found in your environment. | `~/.fuigo/auth.json`, owner-only |
| **ChatGPT subscription** | Browser sign-in with your ChatGPT Plus or Pro account. | `~/.fuigo/subscriptions/`, owner-only |
| **Grok subscription** | Browser sign-in with your Grok account. If the page shows a code instead of redirecting, paste it into the box on the screen. | `~/.fuigo/subscriptions/`, owner-only |
| **Provider API key...** | OpenAI, Anthropic, Google and the other providers Fuigo knows. The key stays in your environment; see below. | your shell environment |

From a script or over SSH, skip the picker with a flag:

```sh
fuigo login                       # the picker (on a terminal)
fuigo login --provider flux       # paste a Flux Router key, hidden
fuigo login --provider flux < keyfile   # or pipe it in: one line on stdin, never echoed
fuigo login --provider chatgpt    # browser sign-in
fuigo login --provider xai        # browser sign-in (alias: grok)
fuigo login --status              # every connection and its state, with no network call
fuigo logout --provider chatgpt   # remove one subscription from this machine
```

Without a terminal, `fuigo login` prints the options and the command for each, and exits with status 2. When it finishes, `fuigo login --provider chatgpt` says `Signed in to ChatGPT subscription (with your email or name when the provider shares one, never an account id). Default model: <model>. Run fuigo. If you already have a default from another provider, it says "Your default model stays <model>; use /model to pick a ChatGPT subscription model" instead.` and nothing more is needed.

## Which route Fuigo uses

If the same model is reachable more than one way, Fuigo chooses by a fixed ranking and shows the choice:

1. **Flux Router**, when it is set up and serves the model.
2. A signed-in **subscription** that includes the model.
3. A direct **provider key**.

`/model` lists a model once, with the route it will use and a short badge: "via Flux Router", "included in your ChatGPT subscription", "your OpenAI key". Models that some route reaches come first; the others follow, each saying what to connect ("connect: needs a Flux Router key (fluxrouter.ai)"). To see the other ways of reaching a model, press Right-arrow or Tab on its row (or type `via ` after its name, as in `/model Grok 4.7 via `): each route is listed with a one-line reason (the price per 1M tokens where the model catalogue publishes one, "included" for a subscription), and Enter on one switches to it.

The status line names the route ("Grok 4.7 · Grok subscription"), and the footer on the welcome screen names the credential ("Logged in with Grok subscription"), never a generic "API key". Fuigo never falls back from one route to another on an error: a denied subscription does not jump to a paid key or to Flux Router. The error names the route, and `/model` switches.

When you have never chosen a default model and Flux Router is not set up, Fuigo starts on the best model of your first signed-in subscription. A default you set yourself is never replaced.

## Provider API keys

Fuigo does not store a third-party key. Export it in your shell (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY` ...), then bind a model to it from inside Fuigo:

```
/provider                          every connection and whether it is ready
/provider openai gpt-5             route a model through your OpenAI key
/provider grok-subscription        list the signed-in Grok account's models
/provider grok-subscription grok-4 switch to one
```

When a provider key is found, Fuigo asks that provider's standard `/models` endpoint for the models the key can use (once a day, in the background, and when you run `fuigo login --provider openai`), keeps only the model IDs under `~/.fuigo/provider-keys/`, and lists them in `/model` with no setup. A model the key and Flux Router both reach is one row, Flux Router first. `/provider` is still there for a model you want to name yourself: it writes the provider's endpoint and the **name** of the environment variable to `~/.fuigo/config.toml`, never the key.

If the default model you set yourself cannot be used (for example it is a Flux Router model and no Flux key is set), the welcome screen says why and shows "Pick a model:" with the models you can use. Choosing one starts on it for that session and leaves your default alone; switch on "Make my pick the default model" first to save it.

## Checking a route

```sh
fuigo -m <name> -p "Reply with the single word ok" --max-turns 1
```

A reply means the route, credentials and protocol all work. The custom-model guide's [credential resolution](../crates/codegen/fuigo-pager/docs/user-guide/11-custom-models.md#credential-resolution) section lists the order in which keys are looked up.

## Advanced: write the routes by hand

Everything above is automatic. The recipes below are for pinning an exact configuration, for CI images, or for gateways the picker does not know. Fuigo reads `~/.fuigo/config.toml`, or `$FUIGO_HOME/config.toml` when you set a separate home. Each model is a named `[model.<name>]` entry; start Fuigo against one with `fuigo -m <name>`. The [custom-model guide](../crates/codegen/fuigo-pager/docs/user-guide/11-custom-models.md) covers context-window limits, headers, query parameters and credential resolution, and the [authentication guide](../crates/codegen/fuigo-pager/docs/user-guide/02-authentication.md) covers single sign-on and external identity providers.

### OpenAI API key

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

For a model that speaks Chat Completions, set `api_backend = "chat_completions"` instead.

### Anthropic API key

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

`auth_scheme = "x_api_key"` sends the environment-supplied key as `x-api-key`; no key is written into the config file. Set context and output limits to match the model you select.

### Subscription model, pinned to an account

A signed-in subscription's models are already in `/model`. Write a table only to pin one to a specific account:

```toml
[auth_provider.chatgpt-subscription]
subscription = "chatgpt"
account = "ACCOUNT_ID_FROM_fuigo_login_--status"

[model.chatgpt-pinned]
model = "REPLACE_WITH_MODEL_ID"
base_url = "https://chatgpt.com/backend-api/codex"
auth_provider = "chatgpt-subscription"
```

Grok uses `subscription = "xai"` and `base_url = "https://api.x.ai/v1"`. A subscription denial never falls back to a paid API key or to Flux Router.

### Flux Router key from the environment

Fuigo reads the Flux Router key from the first of these environment variables that is set and not blank: `FUIGO_API_KEY`, then `FUIGO_CODE_API_KEY`, then `FLUX_API_KEY` (Flux Router's own name for its key). Every way of running Fuigo agrees on this: the interactive app, `fuigo -p`, `fuigo models`, the model list fetch, an ACP client, and `fuigo login --status`. None of the three is passed on to programs Fuigo starts.

### Flux Router with an explicit route

```sh
export FUIGO_API_KEY="YOUR_FLUX_ROUTER_API_KEY"
```

```toml
[model.flux]
model = "REPLACE_WITH_YOUR_FLUX_ROUTER_MODEL_ID"
base_url = "https://api.fluxrouter.ai/v1"
env_key = "FUIGO_API_KEY"
```

For any other OpenAI-compatible or Anthropic-compatible gateway, add a separate named model with its own `base_url`, `api_backend` and credentials. Protocol compatibility does not mean every model behind a gateway supports every agent feature (tool calls, streaming, reasoning effort).

### Local models

Any server that speaks the OpenAI Chat Completions protocol works, Ollama included:

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

Chat Completions is the default backend, so `api_backend` can be omitted. The [Ollama example](../crates/codegen/fuigo-pager/docs/user-guide/11-custom-models.md#ollama-local-models) and the [local server section](../crates/codegen/fuigo-pager/docs/user-guide/11-custom-models.md#local-openai-compatible-server) of the custom-model guide show the remaining options.

# Fuigo 1.0.22 release notes

This release follows 1.0.21. It is a focused fix release for two problems with subscription sign-ins: repeated
replies from ChatGPT, and Grok and ChatGPT subscription models being refused. Nothing else changes.

## Before you upgrade

- **Close every running Fuigo session first** (TUI, `fuigo -p`, editor and desktop-app sessions, leaders).
- If you set `FUIGO_ALLOW_UPSTREAM_HOSTS=1` to make an xAI or ChatGPT subscription work, remove it after you
  upgrade. It is no longer needed for a model you set up in your own `~/.fuigo/config.toml` (F2).
- Install with `npm i -g fuigo`, or update with `fuigo update`. If you install by hand with npm while Fuigo is
  running, run `fuigo leader kill` afterwards so the shared session restarts on the new version.

---

## Fixes

- **F1. A reply that failed partway through and was resent no longer shows two or three times.** When a model
  request failed after it had already streamed some text and Fuigo resent it, the text of the failed attempt stayed on
  screen and the new reply was added after it. The TUI and `fuigo -p` now drop the failed attempt. Editors and apps
  connected over ACP are told to drop it too (see "For ACP clients"). A ChatGPT subscription reply that finishes with
  an empty final message now keeps the text it streamed instead of being sent again.
- **F2. Grok and ChatGPT subscription models are no longer refused.** A model you set up in `~/.fuigo/config.toml`
  with the provider's own endpoint (`https://api.x.ai/v1` for xAI, or `https://chatgpt.com/backend-api/codex` for
  ChatGPT) and no key, header or query parameters of its own now uses your subscription sign-in. Before, every turn
  failed with "fuigo refuses to contact upstream vendor host". A model with its own key or headers (or with global
  `[models].extra_headers` set) is not switched to the subscription and works as before.
- **F3. ChatGPT subscription models set up as the guide shows now work.** They failed every turn with "subscription
  endpoint or protocol mismatch". Fuigo now always uses the protocol that endpoint accepts.
- **F4. Fuigo no longer opens a connection to xAI or ChatGPT when a session starts.** The early connection went
  through the wrong client and did nothing useful.

## Security

- **S1. Only your own config can use your subscription.** Only a model in your own `~/.fuigo/config.toml` can use
  your xAI or ChatGPT subscription sign-in. Settings from a managed or organisation config, a requirements file,
  device management, a downloaded model list or a remote settings patch cannot point a model at xAI or ChatGPT with
  your subscription, change a subscription model's endpoint, or change how it connects (provider, protocol, query
  parameters). A project's `.fuigo/config.toml` cannot define models at all.
  Your subscription token is only ever sent to the provider's own endpoint, and a FluxRouter key (`FUIGO_API_KEY`)
  is never sent to xAI or ChatGPT.

## For ACP clients

- A resent request now arrives as a `retry_state` update (type `retrying`) on `_fuigo/session_notification` with
  `discardEmitted: true` and `streamStartMs` when the failed attempt had already streamed text. Drop the
  `agent_message_chunk` and `agent_thought_chunk` updates whose `_meta.streamStartMs` matches. Replays from
  `session/load` carry the same update on `_fuigo/session/update` with `_meta.isReplay: true`. Clients can detect the
  feature with `agentCapabilities._meta["fuigo/capabilities"].retryDiscard` (`{"version": 1}`).
- `-m` is not applied to a session you load. Call `session/set_model` after `session/load` to pick the model.

## Known limits

- If an xAI hosted search finishes inside an attempt that later fails, that attempt's earlier text can stay in the
  saved history. 1.0.21 behaves the same way.
- Tool-call delta updates carry no `streamStartMs`, so ACP clients cannot match them to an attempt.
- Text from a dropped attempt can remain in the session search index.

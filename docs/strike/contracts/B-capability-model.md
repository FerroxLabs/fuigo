# Contract B: the session capability model

This document states how a session answers "what can this session do?".

## B.1 One model, one owner, session-scoped

There is exactly one capability model. It is computed once per session, owned by `fuigo-shell`, and
every consumer reads it instead of re-deriving it:

- the startup gate (may this session run at all?);
- `/capabilities` and the capability tool the model itself calls;
- `/provider` and `/model`;
- the TUI's ambient display;
- the gate for foreign agents.

No surface computes capabilities independently. A surface that needs something the model does not
carry adds a field to the model; it does not grow its own probe.

The `fuigo/capabilities` ACP surface is an extension interface embedders may bind to, so it falls
under Contract E: it keeps the wire-name rule of E.5a, and the conformance suite covers it.

## B.2 What the model carries

Five axes, each with a provenance and a freshness, never a bare boolean:

1. **Identity**: who the session is authenticated as, by which method, from which source (environment
   key, saved OIDC login, subscription).
2. **Models**: which models this identity is entitled to, with the catalog's own context window and
   backend rather than a hardcoded default.
3. **Tools and commands**: what the session can invoke, including built-ins, discovered MCP tools,
   skills and plugins. A model asked what it can do here answers from this.
4. **Permissions and trust**: the permission mode, the folder-trust verdict, and what each currently
   forbids.
5. **Execution limits**: turn budget, token budget, and whether usage is knowable. With unknown usage
   and a token budget set, admission is denied (Contract D.4); the model says so rather than letting a
   surface discover it at call time.

## B.3 Provenance is part of the value

Every axis records where its answer came from and how fresh it is, in one of three classes:

- **observed**: read from a live authoritative source this session (a catalog fetch, a probe);
- **configured**: declared by the user in `~/.fuigo/config.toml` or a project config;
- **assumed**: a built-in default.

A surface may show an assumed value but must be able to say it is assumed. A hardcoded context-window
default once displayed as fact silently drove auto-compaction on a much larger model; provenance is the
fix. **Missing data is "unavailable": never zero and never a plausible-looking default.**

## B.4 What this enables

`/providers` and `/models` can say what is logged in, what is connected and which environment keys are
usable, because one model knows all three. A foreign agent gets a capability matrix per pinned adapter
version. The TUI header has something truthful to display.

## B.5 Acceptance

Every consumer above reads the single model; `/capabilities` and the capability tool give the same
answer the TUI shows; each axis carries provenance and freshness; and a session with no catalog access
reports "unavailable" instead of inventing defaults.

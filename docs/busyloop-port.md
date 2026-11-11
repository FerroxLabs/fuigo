A2.1/A2.2 refusal port
================

The executable reference is vendored in `fuigo-sampling-types/tests/fixtures`.
`busyloop_expected.tsv` holds the 126 expected rows; SHA-256:
`691fb460e66023bd7c2dd4699ed6ba41d99a2b6b09ae3d8e03015e6930e6c035`.
The Rust test opens that TSV directly and checks all 126 current rows and the original 124-row A2.1 fixture, fixture completeness,
raw/typed response-path parity, and the manifest. It loads W1–W25 from
`busyloop_reference.json`. The response/message fixtures are source-rendered and are not live captures.

`refusal.rs` follows the reference vocabulary and action/text precedence. Unknown
429s on Flux-routed requests are PAUSE; other hosts retain existing retry/backoff behavior.
Routing comes from the sent request URL and the configured Flux endpoint, never response signals. STOP and PAUSE veto sampler retry and shell recovery. The one
exception is a bare 401 on a refreshable session-token configuration; one refresh
and one resubmit are permitted. Every refusal after that resubmit ends the prompt.
A fresh user prompt starts a fresh state machine.

The frozen `data.upstream` object adds `code`, `codes`, `hold_reason`, `limit`,
`retry_after_s`, and `resets_at`. Waits are integer 0..7200, excluding booleans;
the wire parser is separate from the existing internal retry timing cap.
State, type, code and codes pass through one fixed vocabulary at wire and persistence
boundaries; unknown strings become `other`. Provider types and the exact
[documented LiteLLM exception names](https://docs.litellm.ai/docs/exception_mapping)
are retained. Error readers skip unrelated JSON values with `IgnoredAny`, including
million-element arrays, while preserving the eight-wrapper bound.
HTTP 401 and SSE failures carry the same upstream facts through cloning, actor
mirrors, terminal errors and retry notices. Workflow child failures keep those
facts with no legacy top-level HTTP status.

The permitted flux-fast side call originates at `SummaryGenerator::update` in
`fuigo-shell/src/session/summary.rs`, which calls `generate_session_summary`.
Its own failure does not terminate the main prompt. The existing dispatch gate
rejects all late calls after a main-turn terminal refusal, including calls with
new models or compacted bodies.

Verification commands (inside an isolated container):

```
cargo test -p fuigo-sampling-types --test busyloop_parity --test flux_parser
cargo test -p fuigo-sampler --test flux_refusal
cargo test -p fuigo-shell --lib busyloop_
python3 scripts/strike/test-flux-refusal.py --binary TARGET/debug/fuigo-pager --evidence EVIDENCE --resume
python3 scripts/strike/test-busyloop-traces.py --binary TARGET/debug/fuigo-pager --evidence EVIDENCE
```

`scripts/strike/mutate-busyloop.py` mutates the real Rust source, runs the same
TSV/trace test through the supplied container runner, retains each failing log,
and restores the original source even on failure. A compiler failure does not
count as a killed mutant.

The original 124-row TSV is retained as `busyloop_expected_v21.tsv`, with SHA-256
`0cbb945cbc3b45d4c7477a80e847e6a67b897f4802950f1c4e054bdac9d3977e`.
Target-654 fixtures are absent; these checks establish current-fixture parity only.

# Memory ownership and inexpensive evaluation

Standalone Fuigo owns its workspace memory. Murage owns persistent memory inside
Murage and launches Fuigo with root `--no-memory`, even when Murage memory is off.
This does not disable conversation history or modify existing stores/configs.
The accompanying Murage patch targets the isolated integration checkout; it is
not a new installed app or published release.

The Apache-2.0 synthetic corpus comes from Murage, with its exact hash in
`provenance.json`. It has 240 queries across six balanced families. Reuse these
as a regression corpus, not as a hidden test set after inspecting its results.
Do not tune thresholds on all its labels and then claim independent quality.
The subsequent live cohort is not used to tune these retrieval settings.

## Local retrieval (no paid inference)

From the Fuigo repository:

```sh
rtk proxy cargo run -p fuigo-memory --features test-support --example memory_eval -- scripts/memory-bench/corpus.json /tmp/fuigo-lexical.json
rtk proxy node --experimental-strip-types scripts/memory-bench/export-vectors.mjs /path/to/murage /path/to/verified/local/model scripts/memory-bench/corpus.json /tmp/fuigo-vectors.json
rtk proxy cargo run -p fuigo-memory --features test-support --example memory_eval -- scripts/memory-bench/corpus.json /tmp/fuigo-semantic.json /tmp/fuigo-vectors.json
rtk proxy python3 scripts/memory-bench/summarize.py /tmp/fuigo-lexical.json /tmp/fuigo-semantic.json
```

The vector export uses Murage's actual local ONNX pipeline, verifies model file
hashes and forbids remote model downloads. Use Node 24 and a Murage checkout with
its dependencies installed. Missing/invalid assets fail before evaluation.
Rust replays exact-text vectors through production Fuigo indexing, vector search,
source validation and ranking. Vector mode rejects missing sqlite-vec and missing
vectors. Each row records vector insertions/candidates. Lexical mode is labeled.

Each query gets synthetic private storage. Authorized donor scopes are projected
into one Fuigo workspace; foreign files must fail indexing. Retired sources are
indexed and then removed, exercising stale-source rejection. This is **file-backed
scope/invalidation behavior**, not Murage's record approval or migration protocol.
Corpus distractors are synthetic inventory notes. Metrics are retrieval-only;
empty results cannot establish useful recall, and no generation quality is implied.

## Native DeepSeek preparation

```sh
rtk proxy python3 -m unittest discover -s scripts/memory-bench -p test_bench.py -v
rtk proxy python3 scripts/memory-bench/native_smoke.py --binary /path/to/fuigo --out /tmp/fuigo-native-smoke
rtk proxy python3 scripts/memory-bench/deepseek_bench.py --prepare --out /tmp/fuigo-deepseek-plan
```

The native smoke runs real Fuigo capture, fresh-session tool retrieval and the
CLI override against a scripted loopback model. It is not live model quality.
The live runner uses the same native entry point and actual memory tools, with
20 scenarios (four families, five variants), two repetitions and memory on/off:
80 task runs, up to four prompts each. Corrections, arithmetic using remembered
facts, negation, poisoning and foreign/global canaries have deterministic judges.
The model has memory tools only; this is a memory benchmark, not a coding score.

Live execution remains pending a private key file and explicit spending cap:

```sh
rtk proxy python3 scripts/memory-bench/deepseek_bench.py --binary /path/to/fuigo --key-file /private/path/deepseek-key --cap-usd 5 --out /tmp/fuigo-deepseek-live
```

The key file must be owned by the current user, mode 0600, regular and not a
symlink. The key stays in the supervising loopback proxy, never the agent's
arguments, environment, config or receipts. No paid fallback; no automatic retry.
Requests go only to the direct DeepSeek HTTPS endpoint; redirects and ambient
HTTP proxies are disabled. Use a new output directory per explicitly authorized
run; existing directories and ledgers cannot silently restart/reset.

Each request reserves conservative input bytes plus framing and 2048 output
tokens, with a durable ledger before dispatch and no refunds on failure. Six
calls per prompt, 90-second engine limit and 100-second process deadline apply.
The runner stops after a provider failure. Rates are the direct V4 Flash peak
rates checked 2026-09-08; recheck the official table before a future paid run.
These are local reservations, not a provider-side dollar cap. Actual usage is
recorded separately; no cost claims are inferred from tokens alone.

DeepSeek thinking is explicitly disabled for this inexpensive baseline. Its
OpenAI-compatible tool calls, actual direct entitlement and answer quality remain
live verification gates. No Astra judge is required.

References: https://api-docs.deepseek.com/quick_start/pricing/ and
https://api-docs.deepseek.com/guides/thinking_mode/ .

## Recall completion and calibrated semantic admission

Fuigo reserves its last available bounded turn/model-call slot for a final answer
after recall. Memory-only tasks get at most two consecutive memory tool rounds
before a final answer request with no action or hosted tools. Parallel memory
calls count as one round. General workflows retain non-memory tools; consecutive recall is suppressed
until other work advances the loop. Unsolicited action calls during finalization fail closed; cancellation
and existing process budgets remain authoritative. A one-call limit cannot both
retrieve new evidence and generate a subsequent answer. Concurrent consumption
of a shared call budget can still prevent finalization; limits are never exceeded.

Lexical `min_score` remains unchanged. Optional local
`[memory.search] semantic_min_score` admits vector-supported candidates on their
cosine scale; it does not lower the lexical threshold or enable embeddings.
A distinct per-call minimum overrides the calibrated route. Source validation,
workspace boundaries and stale-source rejection apply before either route.

`local-model-profile.json` records the pinned model and development selection.
The selected 0.55 threshold achieved 12/12 relevant recall and 12/12 abstentions on
24 frozen heldout cases, versus 1/12 relevant recall with the unchanged default.
Development recall remained 37.5%: the heldout set is small and this is not a
universal quality claim. Use this profile only with the recorded model and local
embedding preprocessing; recalibrate separately when those change. No profile
is enabled automatically.

Rubric v2 separates substantive accuracy/boundaries from JSON-only formatting.
Equivalent numbers are accepted for factual scoring; contradictory explicit
current-value claims fail. All v1 baseline receipts remain unchanged. `--focused`
runs 12 memory-on cases and four memory-off controls across all four task families
with the original prompts and caps. It does not replay the full 80-run baseline.

Research reference for separate retrieval measures and cosine scoring: https://www.sbert.net/docs/package_reference/sentence_transformer/evaluation.html .

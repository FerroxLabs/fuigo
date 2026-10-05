# Packet proposals handed back from P12b-R

**Source:** P12b-R (the reopen of P12b for the silent-tool-argument BLOCKER) · **Status:** PROPOSED
**Raised by:** the P12b-R agent, 2026-09-30 · **Receipt:** `R009-p12br-silent-tool-argument-alteration.md`

> **HARD RULE — builds run on Hetzner, never on the Mac.** `ssh hetzner-dsm`, own lane, own
> `CARGO_TARGET_DIR`. `df -h` first, delete the target dir after. Peers' dirs are DO-NOT-TOUCH.
> Never build under `/Volumes/Mando`.

Four things were found while fixing the BLOCKER that are outside P12b-R's declared file ownership, or
outside the finding it was reopened for. Per the strike rule, none were fixed as drive-bys. Numbering is
deliberately kept off the P-series to avoid colliding with the packets in flight; assign real numbers at
triage.

---

## P-1 — The non-streaming Messages path drops a whole unmodelled block from an assembled response

**Severity:** HIGH, but **latent, not live.** **Est:** 45 min.

`crates/codegen/fuigo-sampling-types/src/conversation/messages.rs:357-384`,
`impl From<MessagesResponse> for ConversationItem`:

```rust
for block in resp.content {            // Vec<Open<ContentBlock>>
    match block.into_known() {
        Some(ContentBlock::ToolUse { id, name, input, .. }) => { tool_calls.push(...) }
        ...
        Some(_) | None => {}           // <-- an unmodelled block contributes nothing, silently
    }
}
```

This is the **same class as the P12b-R BLOCKER on a different surface**, and materially different in
kind: the streaming path lost a *fragment of one call's arguments*; this loses *an entire block*. If a
provider ships a new tool-bearing block type, the returned `AssistantItem` carries **fewer tool calls
than the model emitted**, the turn reads as complete, and nothing reports it. P12b's own design note
(`serde_helpers.rs:34-37`) forbids exactly this outcome — "lose a tool call with no diagnostic at all
— strictly worse than today's loud abort" — and this is the code that does it.

**Why it is only latent, verified:** the impl is reached only through `create_message` /
`conversation_messages`, and `grep -rn 'conversation_messages\|create_message\b'` over `crates/` finds
**no production caller** — only `fuigo-sampler/tests/proxy_dispatch.rs:43` and
`fuigo-sampler/tests/fluxrouter_cache_bypass.rs:89`. The other `.map(ConversationItem::from)` sites
(`fuigo-shell/src/session/storage/jsonl/mod.rs:1023,1028`) are `From<ChatRequestMessage>`, unrelated.

**Why it should still be fixed:** it is a loaded gun with a natural trigger. The obvious way to write
the first real caller is `.filter_map(Open::known)`, which reintroduces the BLOCKER on a path that has
no per-block accumulation to guard, and the streaming fix does not cover it.

**Proposed shape:** make the silent drop unwriteable rather than merely fixed — e.g.
`fn into_all_known(self) -> Result<Vec<ContentBlock>, UnmodelledBlock>` on the content collection, so
assembling an assistant message has to *state* what it does about an unmodelled block; or a
`clippy.toml` `disallowed_methods` entry on `Open::known` for the assistant-content path. Not owned by
P12b-R (`conversation/messages.rs` is outside its declared files).

---

## P-2 — The refusal / safety stop family is still collapsed to `Stop`

**Severity:** MEDIUM. **Est:** 60 min, most of it tests.

P12b-R closed the **token-limit** family (`is_length_stop_alias`, `types.rs`) because `Length` drives
truncation handling and compaction, which is the consequence the audit named. The identical
silent-wrong remains for the refusal family: Gemini's `SAFETY`, `RECITATION`, `PROHIBITED_CONTENT`,
`BLOCKLIST`, `SPII` and Bedrock's `guardrail_intervened` all arrive as `FinishReason::Unknown` /
`messages::StopReason::Unknown` and normalize to `StopReason::Stop` — a content-policy stop presented to
the user as a clean completion.

**Deliberately not fixed here, and why.** `StopReason::ContentFilter` is not inert: it changes what the
shell shows, and it interacts with the "completed tool_use blocks win over Refusal" precedence at
`messages.rs:515-517`. That is a behaviour change beyond the reopen's finding and needs its own
activation tests across the pager and shell surfaces — a packet, not a line. The recognizer is already
factored in `types.rs`, so a sibling `is_content_filter_stop_alias` drops in beside it.

---

## P-3 — Measure `Open::deserialize` before claiming anything about its cost

**Severity:** LOW. **Est:** 30 min. **Blocks nothing.**

P12b-R reordered `Open::deserialize` to try the modelled parse first, so the tag probe and its
`json!({"type": …})` allocation leave the success path: three passes become two, with no clone. The
residual `serde_json::Value` buffering is inherent to "probe the tag alone" and cannot be removed
without a peeking `Deserializer` that reads the tag without materializing the payload and then replays —
a real design change with its own hostile-shape matrix, not something to attempt inside a BLOCKER
reopen.

**The honest position: nobody has benchmarked any version of this.** The audit's "hottest loop in the
product" and P12b-R's "this is a win" are both inferences. This packet is to **measure first** — one
streamed turn's worth of `content_block_delta` at 1.0.20, at `74b0941`, and at the reorder — and only
build the peeker if the number justifies it. Optimising an unmeasured path is how the previous three
mechanism hunts in this strike went wrong (R007 §5).

---

## P-4 — `cargo fmt --check` is not a usable gate on this tree, and should stop being implied

**Severity:** LOW, process. **Est:** a decision, then either 5 min or one large merge slot.

`cargo fmt --all -- --check` at `8e11724` exits 1 with **381 dirty files**
(`/root/fuigo-builds/p12br-B-fmt.log`). The tree has never been rustfmt-clean during this strike, so any
packet asserting "fmt clean" is asserting something it cannot have checked, and any agent who runs the
check wastes time deciding whether the noise is theirs. P12b-R inspected every hunk inside its five
files, found all but two pre-existing, and fixed only its own two.

**Recommendation: drop fmt from the gate and say so in Contract A.2.** The alternative — one repo-wide
`cargo fmt` commit — is a 381-file diff that would conflict with every packet in flight and buys nothing
a reviewer can see. If the tree is to be normalized, it needs its own merge slot after the queue drains,
never a slot inside a release gate.

---

## P-5 — "failing set is a strict subset of HEAD's" is not satisfiable for `-p fuigo-shell`

**Severity:** MEDIUM, process, and it affects **every packet in the queue**. **Est:** a measurement, then
a contract edit.

P12b-R measured `-p fuigo-shell`'s run-to-run variance at a **fixed commit** and it is larger than the
effect any single packet produces:

| comparison | commits | symmetric difference of the failing sets |
|---|---|---|
| the `p09` recording vs P12b-R's own BASE run | **same** (`8e11724`) | **5** |
| P12b-R's BASE run vs P12b-R's B run | different | **7** |

14 of 16/17 entries are shared between the two same-commit runs; the five that differ churn in **both**
directions. One of them,
`agent::config::tests::configured_endpoints_become_the_trusted_origins`, **fails at `8e11724` in the p09
recording and passes at `8e11724` in P12b-R's run**. Three of the five entries that distinguish P12b-R's
B run from its BASE run pass at BASE when run one-per-invocation with `--test-threads=1`.

So the acceptance criterion as written cannot be met by this suite: an agent obeying it must either
report a failure it cannot attribute, or draw a lucky sample and report a subset it has not earned.
Contract A.2's prohibition on rerun-until-green is exactly right and makes the situation worse — the only
honest options are to report the non-subset or to stop.

**Recommendation, in order.** First **name the churning population** — it is concentrated in
`session::worktree::tests`, `session::storage::jsonl::{copy,worktree_heal}`, `auth::manager::lock` and
`agent::config`, all of which touch the real filesystem, real git worktrees or wall-clock timing — and
quarantine it behind a marker so the gate compares a stable set. Second, restate the criterion against
that stable set, so "strict subset" means something. Do **not** simply widen the tolerance: a five-test
allowance would hide a real five-test regression, which is the same evidence laundering A.2 forbids,
wearing a different hat. Note that Contract A.2's own headline criterion ("full workspace test suite
green") is already unreachable while this population churns, so this is not only a per-packet problem.

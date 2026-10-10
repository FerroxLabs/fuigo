# P161 Astra round 1 (gpt-6-astra, read-only), final answer only
Full transcript (file-read log, 875 KB) dropped; sha256 0420c439a29917695f785fb15ceb2575a4a8181723e80827e26a47a31a40aba9.

**FIXED for both (a) frame-read cancellation and (b) channel-receive cancellation. No BLOCKER, HIGH, or MEDIUM findings.**

Reviewed `532e9137..55bd8eed1`, all four individual commits, and upstream `97f190f6`. No files changed; no cargo, builds, or tests run. `git diff --check` passed.

Two **LOW** findings:

- **Higher bounded memory use.** `FrameReader` retains its backing allocation and copies completed frames into a `Vec`. A maximum-sized frame therefore temporarily occupies roughly 128 MiB before JSON decoding, potentially more from allocation slack, versus the old reader’s single 64 MiB frame allocation. This matches upstream; it is not unbounded accumulation, but literal allocation parity with the old implementation is false. Evidence: [protocol.rs:102](/Volumes/Mando/WaylandBots/Fuigo/wt-p161/crates/codegen/fuigo-shell/src/leader/protocol.rs:102), [protocol.rs:106](/Volumes/Mando/WaylandBots/Fuigo/wt-p161/crates/codegen/fuigo-shell/src/leader/protocol.rs:106).
- **Integration-test synchronization is imperfect.** The server regression assumes a partial read has parked after 200 ms. Under unusual scheduling, the outbound branch could win before any bytes were consumed, letting a regressed server pass. The coalesced-registration fixture likewise depends on socket read boundaries. Explicit read-progress synchronization would strengthen these tests. Evidence: [server_tests.rs:5947](/Volumes/Mando/WaylandBots/Fuigo/wt-p161/crates/codegen/fuigo-shell/src/leader/server_tests.rs:5947), [test_support.rs:183](/Volumes/Mando/WaylandBots/Fuigo/wt-p161/crates/codegen/fuigo-shell/src/leader/test_support.rs:183).

**1. Socket/channel `select!` inventory**

| Site | Selected socket/channel operation | Cancel-safe now? |
|---|---|---|
| [server.rs:1163](/Volumes/Mando/WaylandBots/Fuigo/wt-p161/crates/codegen/fuigo-shell/src/leader/server.rs:1163) | Auth watch `wait_for` | Yes; unchanged. |
| [server.rs:1870](/Volumes/Mando/WaylandBots/Fuigo/wt-p161/crates/codegen/fuigo-shell/src/leader/server.rs:1870) | Listener `accept`; `event_rx.recv`; `response_rx.recv`; relay-refusal and notice watches | Yes. Events now use mpsc; responses already did. Watch receives are safe. Listener acceptance retains its existing cancellation protection. |
| [server.rs:2780](/Volumes/Mando/WaylandBots/Fuigo/wt-p161/crates/codegen/fuigo-shell/src/leader/server.rs:2780) | Registration readiness watch `changed` | Yes; unchanged. |
| [server.rs:2809](/Volumes/Mando/WaylandBots/Fuigo/wt-p161/crates/codegen/fuigo-shell/src/leader/server.rs:2809) | `server_rx.recv` and socket `reader.read_message` | **Yes; both fixed.** Persistent `FrameReader` plus mpsc. |
| [client.rs:433](/Volumes/Mando/WaylandBots/Fuigo/wt-p161/crates/codegen/fuigo-shell/src/leader/client.rs:433) | Socket `reader.read_message` | **Yes; fixed.** Reader lives outside the loop. |
| [client.rs:497](/Volumes/Mando/WaylandBots/Fuigo/wt-p161/crates/codegen/fuigo-shell/src/leader/client.rs:497) | `outbound_rx.recv` | Yes; already mpsc. |
| [agent/app.rs:812](/Volumes/Mando/WaylandBots/Fuigo/wt-p161/crates/codegen/fuigo-shell/src/agent/app.rs:812) | Leader relay-demand watch `changed` | Yes; unchanged. |
| [leader_bridge.rs:261](/Volumes/Mando/WaylandBots/Fuigo/wt-p161/crates/codegen/fuigo-pager/src/acp/leader_bridge.rs:261) | Leader receive channel and injected-response channel | Yes; both already mpsc. |

The protocol tests’ selects at `protocol.rs:587/622` use `FrameReader`; the fake leader’s select at `test_support.rs:91` selects listener acceptance. The remaining leader-module selects concern cancellation/timers, not socket/channel reads.

The pager bridge also selects a local ACP pipe’s `read_line` at [leader_bridge.rs:344](/Volumes/Mando/WaylandBots/Fuigo/wt-p161/crates/codegen/fuigo-pager/src/acp/leader_bridge.rs:344). That primitive is not cancel-safe, but its competing branch terminates the writer rather than resuming the partially consumed stream. It is unchanged and is not the P161 framing defect.

Tokio explicitly guarantees that losing an mpsc `recv()` selection receives no message. [Tokio cancellation contract](https://docs.rs/tokio/1.52.3/tokio/sync/mpsc/struct.UnboundedReceiver.html#method.recv).

**2. FrameReader correctness**

The implementation matches upstream after removing comments and whitespace.

- Four-byte big-endian framing and zero-length frames are correct.
- EOF with fewer than four buffered prefix bytes returns `ConnectionClosed`; an incomplete body returns `Io(UnexpectedEof)`.
- The 64 MiB length check precedes the length-driven reservation. An oversized prefix cannot request an oversized body allocation.
- Before another read, the buffer contains an incomplete frame; after that read, complete frames are extracted before reading again. Thus buffered data cannot accumulate an unlimited sequence of complete frames. Read-ahead and allocator capacity are not a strict 64 MiB total-memory limit.
- The only read suspension point appends into persistent storage. Extraction and JSON decoding have no intervening suspension point that could discard a completed frame.

Evidence: [protocol.rs:67](/Volumes/Mando/WaylandBots/Fuigo/wt-p161/crates/codegen/fuigo-shell/src/leader/protocol.rs:67), [protocol.rs:92](/Volumes/Mando/WaylandBots/Fuigo/wt-p161/crates/codegen/fuigo-shell/src/leader/protocol.rs:92).

Both connections retain one reader through registration and normal processing. The client moves the entire reader into its task; the server keeps it in the same session function. Buffered subsequent frames survive both handoffs. Evidence: [client.rs:342](/Volumes/Mando/WaylandBots/Fuigo/wt-p161/crates/codegen/fuigo-shell/src/leader/client.rs:342), [server.rs:2715](/Volumes/Mando/WaylandBots/Fuigo/wt-p161/crates/codegen/fuigo-shell/src/leader/server.rs:2715).

**3. Kanal → mpsc behavior**

No functional regression found.

- **Removed `Ok(false)` arms:** both former channels were unbounded. Kanal’s unbounded capacity is `usize::MAX`; those full-channel branches did not provide practical back-pressure.
- **P142 acceptance:** `accepted |= send(...).is_ok()` preserves “advance only if at least one eligible client accepted the notice.” `|=` still evaluates every eligible client’s send. Acceptance remains queue acceptance, not acknowledgement of display. Evidence: [server.rs:1771](/Volumes/Mando/WaylandBots/Fuigo/wt-p161/crates/codegen/fuigo-shell/src/leader/server.rs:1771).
- **Synchronous shutdown broadcast:** still enqueues `ShuttingDown` before `Shutdown` for each client. Removing awaits from unbounded sends adds no delivery wait or acknowledgement. Evidence: [server.rs:2910](/Volumes/Mando/WaylandBots/Fuigo/wt-p161/crates/codegen/fuigo-shell/src/leader/server.rs:2910).
- **Drain:** retains the ten-yield/try-receive algorithm. Crucially, cancelling a pending receive now leaves its message available to the drain. Evidence: [server.rs:2844](/Volumes/Mando/WaylandBots/Fuigo/wt-p161/crates/codegen/fuigo-shell/src/leader/server.rs:2844).
- **Ordering/back-pressure:** FIFO enqueue order and unbounded queues remain. Biased branch priority is unchanged.

The drain remains best effort: messages arriving after it observes an empty queue can miss shutdown delivery. That limitation predates P161. The fix removes loss caused by dropping the receive future; it does not establish universal delivery across connection shutdown.

**4. Security properties**

Preserved relative to both baselines:

- Transport binding, socket-path handling and permission behavior are unchanged. The Unix bind itself does **not** explicitly enforce mode `0600`; this review should not be read as proving owner-only socket permissions. Evidence: [server.rs:1851](/Volumes/Mando/WaylandBots/Fuigo/wt-p161/crates/codegen/fuigo-shell/src/leader/server.rs:1851).
- The first message must still be `Register`; server registration retains its **30-second** timeout. Client confirmation retains **10 seconds**, and readiness retains its existing timeout. Evidence: [server.rs:2717](/Volumes/Mando/WaylandBots/Fuigo/wt-p161/crates/codegen/fuigo-shell/src/leader/server.rs:2717), [client.rs:354](/Volumes/Mando/WaylandBots/Fuigo/wt-p161/crates/codegen/fuigo-shell/src/leader/client.rs:354).
- Registration remains a protocol handshake, not a new credential-authentication mechanism. Existing startup auth/readiness sequencing is unchanged.
- P142 still requires registered clients advertising `leader_notices`.
- Protocol metadata and control-version/capability checks remain intact. Evidence: [client.rs:187](/Volumes/Mando/WaylandBots/Fuigo/wt-p161/crates/codegen/fuigo-shell/src/leader/client.rs:187).

**5. Test strength and red/green evidence**

Eight added tests cover frame cancellation, message cancellation, coalescing/order, EOF, size limits, server outbound-winning cancellation, outbound draining, and client registration handoff.

The two paused-clock cancellation tests strongly exercise the original failure: they force consumption before cancellation and verify the interrupted frame plus its successor. The outbound-cancel test uses the production session and default single-thread runtime, queues the message and cancels without an intervening await.

`df8a45741` contains the old-reader stub; `1c1d739f2` contains the Kanal cancellation regression before replacement. Their source supports the expected red failures. **I cannot certify executed red-before/green-after results:** no P161 run receipt was found, and execution was prohibited.

Coverage gaps are direct cancellation of the server’s `event_rx` against another winning branch, server registration coalescing, and allocation bounds. The size-prefix test also lacks a surrounding timeout, so a regression that waits for a body could hang. Evidence: [protocol.rs:699](/Volumes/Mando/WaylandBots/Fuigo/wt-p161/crates/codegen/fuigo-shell/src/leader/protocol.rs:699).

**6. New regressions**

No new functional or security regression identified against `532e9137`. The bounded memory increase above is the concrete resource-cost change.

There is no local `v1.0.21` tag. I used the recorded v1.0.21 source baseline, `de6ca7dd`; the reviewed leader sources and dependency inputs are identical between that baseline and `532e9137`, so the same conclusions apply.

LAND-OK
ASTRA_EXIT 0

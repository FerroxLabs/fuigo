# Fuigo 1.0.28 release notes

This release follows 1.0.27. It fixes problems that could happen when two Fuigo sessions message each other.

## Messages between sessions

- The sending session is now told when the other session really refuses a message that was delivered, even if the sender did not ask to be told when the other session is idle. This covers the `refuse_peer_message` tool in the receiving session. Before, the sender heard nothing, although the guide said it would.
- A reply that only contains text is no longer treated as a refusal when the sender did not ask to be told when the other session is idle. The sender is not told, and the receiving session no longer shows a "refused" line for it. A message sent with `notify_when_idle` behaves as in 1.0.27.
- A held message that you released is never refused automatically because the model answered with text only. Before, you could see a "refused" line right after releasing a message.
- The line in the receiving session now says what happened. "Peer message from X was refused; the sender is told." appears only when the sender really was told; otherwise it says "Peer message from X was refused." It no longer starts with "Held" for a message that was already delivered.
- A session whose model refused a peer message with `refuse_peer_message` no longer fails every later request with "each tool_use must have a single result" (400). Fuigo now saves its peer bookkeeping without disturbing a tool call that is still waiting for its result, so no second result is made for it. The same 400 could also follow a permission denial recorded in the middle of a batch, and that is fixed too; the denial is still saved straight away. This bug was also in 1.0.25 to 1.0.27.

## Permission mode

- Changing the permission mode with Shift+Tab in a session that has read a peer message no longer shows the "protected file changed" warning for `config.toml` and no longer holds further peer messages. Fuigo remembers the exact content of the `config.toml` it wrote for you and accepts only that file, and only when it differs from before in `[ui] permission_mode` alone. A mode change made any other way (by the model, by a command it ran, by another program) still raises the warning and the hold, as does any other change to that file, a file that cannot be read or parsed, or a change to any other protected file.

## Known limits

- A refusal by the receiving session's model reaches the sender only while the receiving turn is running or queued. A message that has already finished its turn can no longer be refused.
- If the session runs in a separate process from the window (a shared leader), Fuigo cannot tell your Shift+Tab from another write to `config.toml`: under peer influence it still raises the warning and the hold once. Run `/peers clear-influence` as before.

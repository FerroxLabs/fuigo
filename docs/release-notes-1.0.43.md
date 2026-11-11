# Fuigo 1.0.43 release notes

## Rate limits and provider errors

- **Provider errors keep their code.** In agent mode, a failed request's JSON-RPC error and every retry notice now carry
  a typed `data.upstream` object. It holds the HTTP status, the provider's error `type` and `state`, the Flux `code`
  and `codes`, `hold_reason`, `limit`, `retry_after_s` and `resets_at`. Before, only the message text survived, cut to
  280 characters. Existing fields keep their meaning. The agent-mode guide documents `data.upstream` as a stable wire
  format.
- **Only known values are reported.** `type`, `state` and `code` carry values from a fixed vocabulary: Flux codes,
  supported provider error types and LiteLLM exception names. Anything else is reported as `"other"`, so a value a
  provider echoes back, such as a key, never reaches the wire or a saved session.
- **Errors rewrapped by a gateway keep their code.** A provider error quoted inside another error's message, for
  example by LiteLLM, is read for its code and reset time, including on a rejected sign-in and on errors that arrive
  mid-stream.
- **A Flux refusal that retrying cannot fix ends the prompt.** A revoked or unknown key, a used-up allowance, budget or
  plan cap, or a Flux rate limit with no known wait now stops the turn with its reason instead of retrying in a loop. A
  rate limit with a known wait still backs off. Other providers keep their existing rate-limit retries, including
  `Retry-After`.
- **One sign-in refresh, then stop.** A bare 401 on a session that can refresh its token refreshes once and resends
  once. A second refusal ends the prompt. A new prompt starts fresh.
- **A failed session-summary call no longer ends the main prompt.**

# Fuigo 1.0.38 release notes

## Folder trust

- **Trusting a folder during a session now brings in its project instructions.** Before, a folder trusted after a
  session started left that session without the folder's `AGENTS.md` and other project instruction files, even after
  a later load, while a new session had them. Now the files arrive at the session's next turn and stay there through
  later loads, resumes, compaction, rewinds and forks, with any agent. Each file reaches the model once.
- **A trust answer that arrives just after the first prompt still counts.** When a client's trust request is
  outstanding, the first prompt of a session waits up to 2 seconds for the answer, so the instructions land in that
  first request. Sessions in a folder that is already trusted never wait.
- **A client can trust a folder for this run only.** A client that shows the folder trust request can reply
  `{"outcome":"trust","scope":"configAndCommands","duration":"process"}`. The trust lasts until Fuigo exits and nothing
  is written to disk. It grants no more than a normal answer, and a saved or earlier "no" still wins. Any other
  `duration` value is a rejection. Older Fuigo versions reject this reply, so they stay untrusted.

Two limits remain:

- Sessions saved by an earlier version are not repaired. If one is missing its project instructions, start a new
  session.
- A session that gets trust part way through receives the top-level project instruction files. Nested `AGENTS.md`
  files and project skills arrive with the next new session.

## Rate limit messages

- **The retry count now matches what Fuigo does.** A rate-limited request now shows "(1/2)" while it waits, and "failed after 2
  attempts" when it gives up, instead of counting against a limit it never reaches. A subagent that runs out of
  retries also reports the number of calls it really made. Retry behaviour itself is unchanged.

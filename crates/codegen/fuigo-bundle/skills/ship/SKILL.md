---
name: ship
description: Commit and push your work and open a pull request if the branch has none, review it in this session, fix the real problems, then watch the pull request (CI failures, conflicts and review comments) until it is merged or closed. Never merges. Only a line the user types starts it; if asked in other words, tell the user to type /ship.
argument-hint: "[low|medium|high|xhigh|max] | stop"
disable-model-invocation: true
---

# Ship

Take the work in this session from uncommitted changes to a watched pull request. Arguments: `$ARGUMENTS`

## Never-merge rule (always)

You never merge the pull request, approve it, enable auto-merge, or force-push. The user merges. While this watch
is armed, Fuigo itself refuses those commands and GitHub MCP tools on any turn the user did not type (a wake from a
background command or monitor) and in any subagent such a turn starts, so do not try them or work around the refusal. Never change git config.

## If the argument is `stop`

Read `${SKILL_DIR}/../steward/SKILL.md` and do what it says for `stop`: end the watch and do nothing else. (If a
project or user `steward` skill overrides the bundled one, read that one instead.)

## 1. Preconditions

- `git` repository with a remote; `gh` installed and signed in (`gh auth status`). If the remote is not GitHub,
  you can still commit and push, but say that the review-and-watch part needs GitHub and stop after pushing.
- Public repository (`gh repo view --json visibility --jq .visibility` is `PUBLIC`): do not commit. Say that /ship
  does not commit in public repositories; if there is already a pushed branch with an open PR, continue at step 3.
- If the current branch's PR belongs to someone else (`gh pr view --json author`), say so and stop.

## 2. Commit, push, open the pull request

1. On the default branch: create a new branch named after the change (`git switch -c <short-topic>`).
2. Uncommitted work (`git status --porcelain`): before staging, list the files. If any name looks like a secret
   (`.env`, `.env.*`, `*.pem`, `*.key`, `id_rsa*`, `credentials*`, `*secret*`), do not commit those files: leave them
   out, and say which ones you left out and why. Stage the rest, and write the commit message from what this session
   changed and why (follow the repo's commit convention from AGENTS.md / CLAUDE.md or `git log`).
   Before committing, print one line `Committing <n> files to <branch>.`; before pushing, print
   `Pushing <branch> to <remote>.` Then go ahead: there is no confirmation prompt, the user can press Esc.
3. Push: `git push -u origin <branch>` (never `--force`).
4. If the branch has no PR (`gh pr view` fails), open one: `gh pr create --fill` or a title and body you write from
   the commits (what changed, why, how it was tested). Use the repo's PR template if it has one. Not a draft unless
   the user asked.

## 3. Review in this session

Run the `review` skill on the PR at the effort given in the arguments (default `high`), i.e. follow its steps with
the PR number as the target. For every finding you verified as real, fix it, run the relevant tests, commit and push.
Do not post the findings as PR comments. Say in a few lines what you found and fixed.

## 4. Watch

Read `${SKILL_DIR}/../steward/SKILL.md` (or the project or user `steward` skill that overrides it) and follow its
sections 1 to 3 for this PR until the PR is merged or closed, the branch changes,
7 days pass, or the user types `/ship stop`.

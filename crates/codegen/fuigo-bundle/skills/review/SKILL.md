---
name: review
description: Review the current diff, or a PR number, branch, path or revision range, for correctness bugs. Verifies each finding before reporting and ranks them. Pass an effort level first (low|medium|high|xhigh|max), --fix to apply the findings to the working tree, --comment to post them as inline PR comments, --max-findings <n|all>.
argument-hint: "[low|medium|high|xhigh|max] [PR#|branch|path|range] [--fix] [--comment] [--max-findings n|all]"
---

# Review

Review code changes for real correctness bugs and report ranked, verified findings. Arguments: `$ARGUMENTS`

## 1. Parse the arguments

- Effort: the first word if it is `low`, `medium`, `high`, `xhigh` or `max`; default `high`.
  `low` = only a few findings you are highly confident in; each step up = broader, may include less certain ones
  (label those). `max` may use reviewer subagents in parallel, one per area of the diff.
- Target (optional, first non-flag word after the effort):
  - none: everything on this branch that is not upstream yet, plus uncommitted work. Base = the upstream branch
    (`git rev-parse --abbrev-ref @{upstream}`), else the default branch (`origin/HEAD`), and use
    `git diff <base>...HEAD` plus `git diff HEAD`.
  - a number: a pull request. `gh pr diff <n>` and `gh pr view <n> --json title,body,baseRefName,headRefName`.
  - a revision range (`a..b`, `a...b`): `git diff <range>`.
  - a branch name: `git diff <default-branch>...<branch>`.
  - a path: review the uncommitted and branch changes under that path only.
- Flags: `--fix`, `--comment`, `--max-findings <n|all|default>` (default: 10 at `high`, fewer at lower effort).

If there is nothing to review, say so and stop.

## 2. Review

1. Read the whole diff, then read enough of the surrounding code (callers, callees, tests, types) to judge each
   change in context. Follow the project's AGENTS.md / CLAUDE.md rules.
2. Look for correctness bugs: wrong logic, off-by-one, unhandled errors or edge cases, broken callers, race
   conditions, resource leaks, security holes (injection, secrets, unchecked input at a trust boundary), data loss,
   API misuse, tests that do not test what they claim. Also report a broken project rule from AGENTS.md / CLAUDE.md.
   Do not report style, naming or formatting unless a project rule requires it.
3. Verify every candidate before reporting it: re-read the code path, check that no other code already handles the
   case, and where cheap, prove it (run the relevant test, write a tiny reproduction, or trace concrete values).
   Drop anything you cannot support. Never invent line numbers.

## 3. Report

Ranked most severe first. For each finding:

- **Severity** (high / medium / low) and **confidence** (verified / likely), `file:line`
- What is wrong, in one or two sentences, and a concrete input or path that triggers it
- The smallest fix

End with one line: how many findings, and what you did not check. If you found nothing, say so plainly.

## 4. Optional actions

- `--fix`: after the report, apply the fixes for the findings yourself, through the normal permission flow, smallest
  change each. Run the affected tests. Do not commit.
- `--comment` (a PR target only): post each finding as an inline review comment on the PR's latest commit:
  `gh api repos/{owner}/{repo}/pulls/<n>/comments -f body=... -f commit_id=<head sha> -f path=<file> -F line=<n> -f side=RIGHT`.
  Never approve and never request changes.

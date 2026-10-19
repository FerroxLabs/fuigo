# Benchmark: Fuigo, Claude Code and Grok Build on the same model

Run 2026-10-13, re-graded 2026-10-14. Fuigo 1.0.26, Claude Code 2.1.287, Grok Build 1.0.45 (commit 2bdd1d6a).

## Result

| Agent | Solved | Pass rate | Cost per solved task | Timeouts |
| --- | --- | --- | --- | --- |
| **Fuigo 1.0.26** | **43 / 48** | 89.6% | **$0.29** | 0 |
| Claude Code 2.1.287 | 41 / 48 | 85.4% | $0.36 | 1 |
| Grok Build 1.0.45 | 41 / 48 | 85.4% | $0.40 | 2 |

**How to read it.** A two-task difference is inside the statistical noise at 48 runs (exact McNemar test on matched pairs, p ≥ 0.73), so on solve rate the three agents are level, with Fuigo slightly ahead. Cost is the clear difference: Fuigo spent 18–27% less per solved task, and it was the only agent with no timeouts.

## What was tested

- **24 tasks, each run twice per agent** (48 runs per agent). They are private, unpublished engineering tasks taken from real production codebases, so no agent can have seen them in training: 10 bug fixes, 6 features, 4 multi-step orchestration tasks and 4 "trap" tasks whose code contains planted misleading information, such as a stale comment that describes behaviour the code does not have.
- **Same model for everyone:** every agent ran `claude-sonnet-5-5` through the same metering gateway, which allowed only that model. Hosted tools and web search were off for all three.
- **Hidden tests decide the result:** the agent never sees the grading tests. After the run, its final working copy is copied into a fresh container, the hidden tests are added, and the task's grader runs with no network. A run passes only if the grader exits 0.

## Conditions

| Item | Setting |
| --- | --- |
| Per-run limits | 20 minutes, 200 turns, 400 model calls |
| Sandbox | container with a read-only root, all capabilities dropped, no network except the model gateway, fresh home directory |
| Permissions | each agent in its own auto-approve mode, project trusted |
| Order | the three agents and two repeats interleaved per task in a seeded shuffle |
| Cost | the gateway's metered cost of every model call, including calls cancelled mid-stream and the agents' own helper calls |
| Statistics | Wilson 95% intervals per agent, exact McNemar test on the 48 matched pairs, task-clustered bootstrap for the difference in pass rate |

## Re-grade

Ten of the 144 runs (Fuigo 4, Claude Code 4, Grok Build 2) first failed because of a crash in the grading environment, not in the agent's work. Every affected run was graded again in the same rebuilt environment for all three agents; a run counted as a pass only if every re-grade passed. The table above is the corrected result. Before the re-grade the solve counts were Fuigo 39, Claude Code 38 and Grok Build 40.

## Limits

- 24 tasks is a meaningful but small sample; treat the solve rates as "level", not as a ranking.
- One model was used. Results on other models may differ.
- The tasks are private, so the run cannot be reproduced exactly by others. This page publishes the method and the totals instead.
- The run measured Fuigo 1.0.26. We will re-run it on newer versions and update this page.

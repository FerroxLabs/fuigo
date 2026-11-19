# Contract D: headless denial

This document states what happens when a headless run (`fuigo -p`, ACP-driven runs without an operator)
is refused a permission.

## D.1 The defect this prevents

If a headless run denies a permission request quietly, the run continues, the model is told no, and
nothing distinguishes "the work finished" from "the work was blocked". A CI job or script cannot tell the
difference from outside.

## D.2 What a denial does

A headless permission denial is a first-class outcome, not a log line.

- **D.2.1 Exit code.** A run that ended because a permission was denied exits with a dedicated,
  documented, non-zero code, distinct from both success and a crash. It is stable across releases;
  scripts branch on it. A run that failed to start for another reason (for example a runtime that could
  not be created) uses a different code, so the two are never confused.
- **D.2.2 Machine-readable record.** On the structured output stream, a terminal record names the
  denial: what was requested, which rule refused it, and what the operator would have to change (a
  permission mode, a config key, a trust grant). It is data, not prose, and it appears in every
  `--output-format`.
- **D.2.3 Human output.** One line on stderr says the same thing in English, including the remedy.
- **D.2.4 Side effects.** Bounded and enumerated: what is written, what is left behind and what is
  rolled back. A denial never leaves a half-applied edit.

## D.3 What a denial must not do

- Silently approve. No change turns a denial into an approval to make a test pass.
- Be indistinguishable from success.
- Depend on TTY detection to decide whether to report.

## D.4 Interaction with the execution budget

The execution budget refuses a model request when any of these hold: total tokens reached the total
limit; output tokens reached the output limit; usage is unknown and any token limit is set. The model
call count is checked independently.

**Unknown usage fails closed.** While a token budget is set, unknown usage denies every admission, so
a mode whose usage is not yet mapped (external agents) cannot spend under a token budget. A budget
refusal is reported through the same contract as D.2: a typed denial naming the clause that refused,
reaching clients as data (an ACP error with a stable shape) rather than as provider-failure prose.

## D.5 Acceptance

A headless run that hits a denial can be told apart from success by a script reading only the exit code,
and the reason can be recovered from the structured output without parsing English.

# Contract A: release acceptance and platform support

This document states what must be true before a Fuigo release is called acceptable, and how test
evidence is judged. It exists so that "done" has one definition.

## A.1 Six states, never conflated

A change, a release and a deploy are different things. Each state is earned separately, in order:

1. **implementation**: code exists and focused proof is green at a named commit.
2. **fixture acceptance**: hostile tests and fixtures replayed through the real consumer.
3. **packaging**: the version bump builds and publishes artifacts.
4. **deployment**: the artifacts land on the package registry and unpack to a binary that runs.
5. **live canary**: the maintainers' own machines run the release for a defined soak.
6. **release acceptance**: the owner says ship.

States 1 to 4 may proceed on green evidence. States 5 and 6 need an explicit human decision.

## A.2 Release acceptance criteria

A release is acceptable when all of the following hold at the exact integrated commit:

- The full workspace test suite is green on the build box, judged by the counting rules in A.2.1.
- No HIGH or BLOCKER finding from the independent cross-audit of that same commit is open.
- The downstream embedder conformance suite (Contract E) is green.
- The published registry artifact is verified by unpacking it and running `--version`
  (a launcher shim or a registry listing alone proves nothing).
- The rollback has been executed for real once, with a receipt; documented rollback does not count.
- Every new default-on behaviour has an activation test (clean profile; environment variable absent,
  `0`, `1` and malformed; 24-row terminal; resize; no-color; screen-reader mode; idle CPU and redraw).
- The release notes name every behaviour change a user will notice.

A flaky test is a defect, not a rerun. Rerunning until green is evidence laundering and is prohibited.

### A.2.1 Counting rules

1. **Completeness before correctness.** A run is admissible only if all of these hold:
   - every test target started and finished. The number of cargo `Running` and `Doc-tests` header
     lines (cargo writes them to stderr, so the log captures `2>&1`) equals the count derived from
     the candidate (rule 2), and every header is finished;
   - the cargo exit status is recorded and is neither a signal (137, 143, ...) nor a timeout (124);
   - the gate script's own `DONE` marker is present.

   A header is finished only if, before the next header or the end of the log: the target's own first
   `running N tests` line appears; N equals the count the binary itself reports under `--list`
   (supplied by the gate; a missing, empty or unreadable expectation makes the run inadmissible); the
   last well-formed `test result:` line after it has passed + failed + ignored + measured equal to N;
   and no `running` line follows that last result. Result lines before the target's own `running`
   line, malformed lines, and ANSI- or CR-decorated variants never count. Doc-test sections instead
   pair each `running N` with a following well-formed result for the same N (one or two pairs). When
   in doubt the judge fails closed.

   A killed run can look green (orphaned test binaries keep appending and the `failures:` block is
   absent) and a hung run yields no failing set. An inadmissible run is not evidence of anything and
   is not reported as a result. The normative implementation is `scripts/strike/gate-verify.sh`,
   proven by `scripts/strike/gate-selftest.sh`.
2. **Derive the expected count from the candidate**, never from a remembered number: a change that
   adds a test binary changes it. Use `cargo test --locked -p <pkg> --no-run --message-format=json`
   (test executables, plus one doc-test run where the library has doc-tests; `scripts/strike/derive.py`).
3. **The failing set comes from the `failures:` block**, not from counting `FAILED` lines, because a
   `FAILED` line interleaved with another test's output is missed.
4. **Neither `running N tests` nor `test result:` lines count targets.** Tests that drive child test
   processes print both again, so both exceed the target count. Only the cargo headers count targets.
5. **Two controls, each labelled with its exact commit.** The immediate parent attributes a change's
   own effect; the accepted baseline catches a regression an earlier change introduced, which the
   parent cannot show.
6. **Every complete run is reported**, not the best one. If a command ran more than once at one
   commit, all admissible runs appear in the receipt.
7. **Suite stability is a separate claim.** "The suite is stable" needs consecutive full runs with
   byte-identical failing sets (three unless stated). A named target set, or `--test-threads=1`, is
   evidence only for the narrower claim it tests and is labelled so.

## A.3 Receipts, not prose

"All tests pass" is a claim. A receipt records: the exact commit, the exact command verbatim, the exit
code, the sha256 of the full log, an ISO 8601 UTC timestamp and the toolchain digest. It is valid only
if re-running that command at that commit in that environment reproduces it.

## A.4 Platform support claim

Linux CI cannot establish macOS or Windows parity: keychain access, browser login, PTY behaviour,
`.cmd` wrappers, path quoting and process-tree kill all differ. The claim is therefore narrowed rather
than pretended:

- **Linux**: fully qualified; the build box gates every release.
- **macOS**: qualified by a scripted manual gate run on a Mac before release acceptance.
- **Windows**: community, unqualified, until a named runner exists.

## A.5 Authorization

Merging to the integration branch with a green post-rebase proof and a complete receipt is routine.
Merging to the main branch, releasing, publishing to the registry, promoting a canary, and any breach
of Contract E need an explicit human decision. Passing the gates earns a request for that decision;
it is never the decision.

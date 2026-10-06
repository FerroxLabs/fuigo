# P110 Astra round 1 brief

You are auditing the diff `d1b6ba580eb587594d52b5a2550c1bd82a8bcd60..b1234f13` on branch `strike/p110` in this repository
(read-only; do not build). Read `git diff d1b6ba58..b1234f13` and the surrounding code.

Context: three findings of an independent audit of the Fuigo 1.0.21 release candidate.
- M1: `crates/codegen/fuigo-memory/src/storage.rs` `migrate_legacy_workspace_dirs` returned early when the host-qualified
  memory folder existed, so notes a 1.0.20 run wrote under the recreated legacy `org/repo` folder after P91's move were
  stranded silently. Claim: when the new folder exists and a legacy folder holds notes beyond what an old version
  creates on start (template MEMORY.md, index files, `.memory-write.lock`, empty `sessions/`), a one-time notice names
  both folders (own marker `.legacy-stranded-notice-*`, removed when the legacy folder is absent so a recreation is
  announced again); a folder already announced by P97 as not adopted is not announced twice; nothing is merged or
  moved; P91's adoption rule is unchanged.
- U1: `crates/codegen/fuigo-update/src/auto_update.rs` gh-release installer used `gh release download --clobber` onto
  the file the live `bin/fuigo` resolves to. Claim: it now downloads to a unique temp sibling, fetches the release's
  `SHA256SUMS`, checks non-empty + sha256 entry + executable bit, fsyncs, and renames into place; temp files are
  removed on failure; a release without `SHA256SUMS` or without an entry is refused.
- U2: `crates/codegen/fuigo-update/src/version.rs` took the newest CREATED release as latest. Claim: latest is now the
  highest semver among non-draft (and, for stable, non-prerelease) releases; gh-release automatic updates never install
  a lower version than running (installer_allows_downgrade("gh-release") = false); `fuigo update --version X` and
  `--force` can still go down (installer_allows_forced_downgrade). npm and internal behaviour unchanged.
Tests: `crates/codegen/fuigo-memory/src/p91_identity_tests.rs` (4 new), `crates/codegen/fuigo-update/tests/test_gh_release_install.rs`
(new), updated `test_downgrade_matrix.rs`, `test_concurrent_convergence.rs` (fake gh serves SHA256SUMS), unit tests.

Find defects: correctness, regressions of existing behaviour (leader relaunch, convergence, cleanup sweep of temp
names, Windows paths, alpha channel), data loss, false or repeated notices, races, tests that do not exercise the
production path. For each: severity BLOCKER/HIGH/MEDIUM/LOW, file:line, a concrete scenario, and whether a test
catches it. End with exactly one of LAND / LAND-WITH-FOLLOWUPS / DO-NOT-LAND.

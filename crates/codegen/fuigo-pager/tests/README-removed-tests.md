# Tests removed because upstream never published their inputs

`registered_features_are_documented.rs` asserted that every entry in
`FEATURES` has a row in `docs/internal/25-enterprise.md` and
`docs/internal/22-environment-variables.md`.

Neither file exists. `docs/internal/` is stripped from xAI's public sync of
Grok Build, so the test's `include_str!` failed at compile time and took the
entire `fuigo-pager` test target with it — including all 246 PTY/e2e tests.

The invariant it checked is worth having. Restoring it means writing our own
operator docs first, then reinstating the test against those. Tracked for P5.

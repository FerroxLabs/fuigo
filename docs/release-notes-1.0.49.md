# Fuigo 1.0.49 release notes

## Release builds are reproducible

- **Two builds of the same source now give the same bytes.** Before this release, two release builds of the same commit
  came out slightly different. That made it impossible to check a published binary against an independent build. Two
  things caused it, and both are fixed:
  - **A code-obfuscation macro picked new random numbers on every compile.** It wrapped one config assignment, and that
    value was never secret. The macro and its two dependencies (`cryptify`, `labyrinth_macros`) are removed, and
    behaviour is unchanged.
  - **The version string carried the commit id.** A dry run and the tagged release build the same code from different
    commits. The suffix is now the git tree id of the source, so the same source gives the same version string.
    `FUIGO_BUILD_ID` still overrides it.
- **How to check:** build the tagged source on Linux (the release builds in `/work`) and compare it with the published
  `unsigned-*` or Linux artifact. Signed macOS and Windows binaries carry a signing timestamp, so compare their unsigned
  builds instead.

## Behaviour changes

- **`fuigo --version` shows the source tree id**, for example `fuigo 1.0.49 (c20113d37924)`, where it used to show the
  commit id. On GitHub, find the commit with `git log --format='%h %T' | grep <id>`; the id no longer opens as a commit
  link.

## Verification

- **Three clean release builds give one binary.** `cargo build --profile release-dist -p fuigo-pager-bin` (the release
  build command) was run three times from an empty target directory: twice on the same commit and once on a different
  commit with the same source tree. All three binaries are byte-identical (sha256 `d09eb8df…5f853e`). Before the fix, two
  builds of the same commit already differed.
- The binary reports the tree id: `fuigo --version` printed the 12-character prefix of `git rev-parse HEAD^{tree}`.
- `cryptify` and `labyrinth_macros` are gone from `Cargo.lock`; `fuigo-pager-bin` tests and its clippy `-D warnings` pass.

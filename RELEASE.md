# Releasing Fuigo

Fuigo ships to npm as seven packages: the meta package `fuigo`
and six platform binary packages under `@fuigo` (for example,
`@fuigo/darwin-arm64`) listed as its exact-version `optionalDependencies`.
Local platform directories retain names such as `fuigo-darwin-arm64`; their
package manifests define the scoped published names. npm
downloads only the one matching the host's `os`/`cpu`, so a user pulls one
~42 MB package, not six.

---

## The version has exactly one source

`crates/codegen/fuigo-version/Cargo.toml` is the one place the number is
written. Three things derive from it, and all three are checked:

| derivation | mechanism | what catches drift |
|---|---|---|
| `fuigo_version::VERSION` | that crate's own `CARGO_PKG_VERSION` | — |
| the binary's `<version> (<source tree id>)` stamp | `fuigo-pager-bin/build.rs` reads the manifest above | `the_stamped_version_is_the_one_source_of_truth` |
| the seven npm packages | `sync-version.js` | `npm run check-version`, `prepublishOnly` |

**This section used to claim the same thing while it was false.** `build.rs`
stamped `fuigo-pager-bin`'s *own* `CARGO_PKG_VERSION`, so the version lived in
two manifests that had to be bumped together and nothing noticed when only one
was. v1.0.2 was tagged and pushed with the binary reporting `1.0.1`; the CI
smoke test caught it after the tag, which is the last place it could still be
caught for free. `build.rs` now reads the manifest directly and panics if it
cannot — there is no fallback, because a wrong version is not a degraded build,
it is a build that lies about which one it is.

To cut a version, edit `fuigo-version/Cargo.toml` and run `sync-version`:

```sh
cd crates/codegen/fuigo-pager/npm/fuigo
npm run sync-version      # stamp meta + 6 pins + 6 platform packages
npm run check-version     # verify only; non-zero exit on drift
```

Do not hand-edit any npm `version` or `optionalDependencies` pin. They drifted
once — the meta package said `0.1.220-alpha.4`, copied from an unrelated
internal crate, while the binary said `1.0.1`. npm publishes the meta package's
number, so users would have installed an alpha-looking version of a release
build.

Three guards now make that unpublishable:

| guard | when it fires |
|---|---|
| `sync-version.js` refuses a non-`x.y.z` version | any run without `--allow-prerelease` |
| `assemble-platform-packages.js` runs `--check` first | every assemble |
| `prepublishOnly` runs `--check` | every `npm publish` |

---

## Building the six binaries

The assemble step reads one binary per target. Point it at them with env vars —
this is the only supported way to supply cross-built artifacts, because the
default paths assume an internal cross toolchain that is not public.

| env var | target triple |
|---|---|
| `FUIGO_DARWIN_ARM64` | `aarch64-apple-darwin` |
| `FUIGO_DARWIN_X64` | `x86_64-apple-darwin` |
| `FUIGO_LINUX_ARM64` | `aarch64-unknown-linux-gnu` |
| `FUIGO_LINUX_X64` | `x86_64-unknown-linux-gnu` |
| `FUIGO_WIN32_ARM64` | `aarch64-pc-windows-msvc` |
| `FUIGO_WIN32_X64` | `x86_64-pc-windows-msvc` |

Native build for the host:

```sh
CARGO_TARGET_DIR=/tmp/fuigo-bin cargo build --release -p fuigo-pager-bin
# -> /tmp/fuigo-bin/release/fuigo-pager   (166 MB, ~42 MB brotli)
```

**Do not assemble with a partial set.** Every one of the six env vars must point
at a binary built for *that* triple. The script cannot tell a Mach-O arm64
binary from a Windows PE — it just compresses bytes — so a placeholder there
publishes a package that installs cleanly and then fails to execute, on a
platform you probably cannot test from.

`.github/workflows/release.yml` produces all six and is the supported path.
Building them by hand is for debugging, not for shipping.

Runner availability was probed 2026-09-01 and is worth knowing before editing
that matrix: `ubuntu-24.04`, `ubuntu-24.04-arm`, `windows-latest`,
`windows-11-arm` and `macos-14` all schedule. **`macos-13` does not** — the job
queues indefinitely rather than failing, which is the worst way to find out at
the end of a two-hour build. GitHub retired `macos-14` on 2026-11-02, so the
macOS jobs now run on `macos-15`. `darwin-x64` therefore cross-compiles on
`macos-15`; aws-lc-sys builds its C for x86_64 there in under a minute, and
Rosetta 2 on the image means the smoke test still executes the binary.

---

## Assembling and publishing

```sh
cd crates/codegen/fuigo-pager/npm/fuigo

FUIGO_DARWIN_ARM64=… FUIGO_DARWIN_X64=… \
FUIGO_LINUX_ARM64=…  FUIGO_LINUX_X64=…  \
FUIGO_WIN32_ARM64=…  FUIGO_WIN32_X64=…  \
UV_THREADPOOL_SIZE=6 npm run assemble
```

`UV_THREADPOOL_SIZE=6` matters: brotli runs on the libuv thread pool, whose
default size is 4, so without it two of the six compressions serialise.

Then publish the six platform packages **first**, the meta package **last** —
the meta package's `optionalDependencies` pin exact versions, so publishing it
first leaves a window where `npm i` resolves nothing installable:

```sh
cd ../fuigo-darwin-arm64 && npm publish --access public
# … the other five platform directories, published as @fuigo/<platform> …
cd ../fuigo             && npm publish --access public
```

Assembly also copies the repository LICENSE, NOTICE and comprehensive
THIRD-PARTY-NOTICES, tool attribution and vendored notices into all seven
packages. `node scripts/package-notices.js --check` verifies exact source
bytes before meta publication. Keep these files in each manifest's `files`
list; the release archives must contain them alongside their actual binaries.

The workflow publishes with the configured npm token and requests provenance attestations
(`npm publish --access public --provenance` on every publish). `FerroxLabs/fuigo` is public, so
npm accepts provenance from it. Three things work together: each of the seven `package.json`
files carries a `repository` field naming `git+https://github.com/FerroxLabs/fuigo.git` (with
its own `directory`; `sync-version.js` stamps it and `--check` fails on drift, and
`verify-package-archives.js` and `verify-published-platform.js` require it in the packed and
the published manifest, and, under Actions, equal to `GITHUB_REPOSITORY`, because npm refuses a
provenance publish whose `repository.url` does not match the repository that built it),
`id-token: write` on the publish job only, and `--provenance` on both publish commands.
Nothing proves the attestation itself until a real tagged run publishes, and no step verifies
it afterwards: the `github-release` job trusts the registry tarballs after the `dist.integrity`
match and the signature identity check, not after an attestation check.

The post-publish verifier downloads through the same pinned public npm as
`scripts/release/registry-release-inputs.sh` (empty environment, no npmrc, both registries
pinned; `scripts/pinned-npm.js`). Each verify job uploads its digests (tarball sha512 and raw
executable sha256), and the `github-release` job compares all six with the release assets it
laid out (`scripts/release/verify-release-digests.js`) before creating the release.

Nothing else in the release path depends on the repository's visibility: the
publish job downloads the build artifacts of its own run (no token), publishes
with `--access public` (the scoped `@fuigo/*` packages need it on every first
publish, whatever the repository is) and uses no submodules. Users install from
the public npm registry without credentials.

---

## GitHub Release

From 1.0.21 on, a tag push also publishes a GitHub Release `v<version>`
(decision D20). Users who installed through the gh-release path
(`installer = "gh-release"` in `~/.fuigo/config.toml`) update with two `gh`
commands from `crates/codegen/fuigo-update`:

```sh
gh release list --repo FerroxLabs/fuigo --limit 1 --exclude-drafts --exclude-pre-releases \
  --json tagName --jq '.[0].tagName'                       # newest by creation date
gh release download v<version> --repo FerroxLabs/fuigo \
  --pattern fuigo-<version>-<os>-<arch> --output … --clobber
```

`<os>-<arch>` is one of `macos-aarch64`, `macos-x86_64`, `linux-aarch64`,
`linux-x86_64`, `windows-aarch64`, `windows-x86_64`. No release before 1.0.21
carried an asset under that name (v1.0.7 to v1.0.11 shipped only the npm
tarballs), so that path had stopped updating at 1.0.11.

The `github-release` job in `release.yml` runs last, after `verify-published`,
only on a tag ref, and is the only job with `contents: write`. It uses the
runner's `gh` CLI, no third-party action. `scripts/release/github-release-assets.sh`
lays out 15 assets:

| asset | source |
|---|---|
| `fuigo-<version>-<os>-<arch>` (6) | the executable decompressed from the matching npm tarball that the registry serves (never this run's own build; a build that differs is only reported as drift). `registry-release-inputs.sh` checks the macOS and Windows ones for the release signing identity with `check-signed-binary.py` |
| `fuigo-<version>.tgz`, `fuigo-<platform>-<version>.tgz` (7) | the npm tarballs, exactly what npm received |
| `release-manifest.json` | `verify-package-archives.js`: name, version, integrity, shasum, size per tarball |
| `SHA256SUMS` | sha256 of the other 14 assets, the v1.0.11 format |

Release notes come from `docs/release-notes-<version>.md`; without that file the
body is a short install line. A version with a `-` suffix is marked prerelease,
so stable installers skip it. The publish job runs the same layout script on
every run, dry runs included, so a broken layout fails before anything ships.

**Re-running** is supported. An existing release for the tag, draft or not, is
completed rather than duplicated: missing assets are uploaded, assets already
present with the same sha256 (GitHub's asset `digest`) are left alone, a draft is
published, and existing notes are never overwritten. An asset whose content
differs fails the job; to replace it on purpose, run the workflow by hand on the
tag with `dry_run` off and `replace_release_assets` on. After publishing, the job
reads the release back, runs the installer's `gh release list` query and fails if
it does not return this tag while this tag is the newest stable release, then
downloads `fuigo-<version>-linux-x86_64` with the installer's command and checks
it against SHA256SUMS.

**Recovering when `verify-published` fails after npm published.** `github-release`
needs all six verify jobs, so a failed one leaves npm complete and the release
missing. Do **not** publish again: `publish` skips versions npm already has, and the
tag cannot be moved. A "Re-run failed jobs" or a `workflow_dispatch` on the tag runs the
tag's own copy of the workflow and scripts, so it only helps when the failure was a
flaky runner, not a script bug. For a script bug, finish by hand from a checkout of the
fixed scripts whose `crates/codegen/fuigo-pager/npm/fuigo/package.json` version equals
the release version (the verifier reads its version from that file). Needs node 22,
npm, `gh` (write access), `jq`, and Linux or macOS for the shell scripts:

```sh
V=1.0.21; W=$(mktemp -d)
# 1. Run the verifier for every platform on a machine of that platform (the two win32
#    ones need Windows; the others can run anywhere that platform is available):
node crates/codegen/fuigo-pager/npm/fuigo/scripts/verify-published-platform.js <platform> \
  --digest-out "$W/verified/verified-<platform>.json"      # all six JSON files into one dir
# 2. Lay the assets out from the registry bytes and compare them with what was executed:
scripts/release/registry-release-inputs.sh "$V" "$W/bin" "$W/npm"
scripts/release/github-release-assets.sh "$V" "$W/bin" "$W/npm" "$W/gh-release"
node scripts/release/verify-release-digests.js "$V" "$W/verified" "$W/gh-release"
# 3. Create the release, exactly as the workflow does (add --prerelease for a "-" version).
#    The notes file is optional: without docs/release-notes-$V.md the notes are the short install line the workflow writes.
NOTES=(--notes "## Fuigo $V

Install or update: \`npm install -g fuigo@$V\`

SHA256SUMS lists the sha256 of every asset.")
[ -s "docs/release-notes-$V.md" ] && NOTES=(--notes-file "docs/release-notes-$V.md")
gh release create "v$V" --repo FerroxLabs/fuigo --verify-tag --title "Fuigo $V" \
  "${NOTES[@]}" "$W"/gh-release/*
```

If a release or draft for the tag already exists, `gh release upload` the missing assets
and `gh release edit "v$V" --draft=false` instead of `create`. Do not skip step 1 or 2:
they are what proves the release carries the bytes that executed.

The client and the script agree on asset names through
`gh_release_asset_names_match_release_layout_script` in
`crates/codegen/fuigo-update/src/auto_update_tests.rs`; change both together.
The gh-release installer checks the downloaded asset against `SHA256SUMS` before it
installs it (`verify_gh_asset` in `crates/codegen/fuigo-update/src/auto_update.rs`).
`SHA256SUMS` comes from the same release as the binary, so it proves the download is intact,
not who published it; the signature checks in the sign job and above cover origin.

---

## Code signing

**npx needs none.** npm never sets `com.apple.quarantine` or Windows'
Mark-of-the-Web, so neither Gatekeeper nor SmartScreen assesses the file. The
release binaries are signed anyway (below).

Two places that *do* need real signing:

- **Bundled inside a `.app`** (e.g. Murage's Electron build): the binary must
  carry the same Developer ID as the app and be inside the notarised bundle, or
  `codesign --verify` fails on the app and notarization is rejected.
- **GitHub Releases direct download**: browser-downloaded files are quarantined,
  so macOS needs Developer ID + notarization and Windows wants Authenticode.
  The release workflow's `sign` job signs the macOS binaries with a Developer ID
  and notarizes them, and Authenticode-signs the Windows binaries (Azure Artifact
  Signing); tag pushes always sign macOS. The raw binaries on the GitHub Release
  are those signed bytes. The gh-release installer fetches them with `gh`, not a browser.

If you strip to save size, note the trade: 166 MB → 141 MB raw, 42 MB → 43 MB
brotli, so roughly 10% compressed for the loss of symbols in crash reports.
Xcode's `strip` re-signs automatically; `llvm-strip` and GNU binutils do not,
and an invalidated signature on arm64 is `Killed: 9` with no diagnostic.

## Internal installer base (per-binary digest)

The built-in internal CLI base URLs (`CLI_BASE_URL_PRIMARY` and `CLI_BASE_URL_FALLBACK` in
`crates/codegen/fuigo-update/src/version.rs`) are empty in the public tree, so the internal updater downloads nothing
and this section changes no behaviour today. Once a base is set, the updater requires `<binary>.sha256` (for example
`fuigo-1.2.3-linux-x86_64.sha256`, a bare 64-digit hex digest or `<digest>  <binary>`) next to every binary it
downloads from a non-loopback base, and refuses the update, before running the file, when that digest is missing or
malformed. The error names the file. Publish the digest in the same step as the binary so a base never serves one
without the other. The digest is read from the same base as the binary, so it catches a corrupt or half-published
upload, not a compromised base: signing or pinning the digest is a separate step and is not done yet.

---

## Preflight: run it before any dry run

**Run preflight before any dry run.** A dry run is hours of build matrix; in 1.0.45 one shellcheck info in
`scripts/release/test-release-scripts.sh` failed the run at "assemble and publish" -> "Check versions", after
everything else had built. The preflight runs the cheap checks of that job (and of the build jobs' script tests)
in about 20 minutes:

- GitHub: Actions -> preflight -> Run workflow, or push the candidate to a `release/*` branch
  (`.github/workflows/preflight.yml`). It publishes and signs nothing.
- Locally, no GitHub needed: `scripts/release/preflight-local.sh [--compile-check] [--require-shellcheck]`.
  The same script runs in the workflow, and `pr-ci-replay.sh` (the pre-squash replay) calls it.

It covers the npm layout and provenance tests, `test-release-scripts.sh`, the version check, the same-version
reinstall test, the signed-binary and Linux-floor checker tests, shellcheck, that every action in `release.yml`
is pinned to a commit SHA, and the **leak guard**. The workflow adds a linux-x64 `cargo check --profile
release-dist -p fuigo-pager-bin` (type-check only; a full LTO link does not fit 20 minutes).

**Leak guard** (`scripts/release/check-token-leaks.py`, also run by `public-squash.sh` on the release tree):
fails on an unsplit vendor-shaped token in tracked source (`sk_live_`, `rk_live_`, `shpat_`, `ghp_`, `gho_`,
`github_pat_`, `xoxb-`, `AKIA`, `AIza`, `glpat-`, `npm_`, `sk-ant-`, ...). Fake fixtures must be split, for
example `concat!("sk_", "live_...")`, so push protection never sees a token. Lines that predate the guard are
listed by hash in `scripts/release/token-leak-baseline.txt`; editing one puts it back under the guard.

---

## Benchmark gate

Protects the edge: a release fails when it solves more than 2 fewer tasks than the previous one; a rise in cost per
solved task is reported as a warning (see Verdict below). The gate
runs a fixed 12-task subset of the 2026-10-13 hardbench suite (`scripts/bench/subset12.txt`, with the reasoning for the
choice in its header) on the Docker host, N=2 repeats per arm, same model (`claude-sonnet-5-5`, effort medium), same
provider key and same limits for both arms; the arms differ only by the fuigo binary.

```sh
# On hetzner-dsm, once: stage the hardbench subset (tasks/, deps/, harness-1028/) under $HB_ROOT and build the deps
HB_ROOT=/root/hardbench scripts/bench/stage-deps.sh <any gate image>
# Per release (about 3 h, about 10 USD; provider key from the environment only, never argv):
FUIGO_API_KEY=... HB_ROOT=/root/hardbench scripts/bench/run-gate.sh <candidate> <baseline>
#   <candidate>/<baseline>: npm:<version> or the path of a linux-x64 fuigo-native binary
```

Verdict (`verdict.md` / `verdict.json` in the run dir; exit 0 PASS, 1 FAIL, 2 INCOMPLETE): FAIL when candidate solved
tasks drop by more than 2 against the baseline. A rise in cost per solved task is reported as a warning, not a
failure: the same binary measured a 21% spread between runs, so a cost rule would fail at random. A task counts
as solved when both repeats pass. Blocked or unrun attempts make the gate INCOMPLETE, never a pass. Rerunning until
green is not allowed: record every run; a FAIL is investigated, not retried. The same-binary variance run (baseline =
candidate) is the noise floor and is recorded in the lane notes.

---

## Pre-release checklist

- [ ] `cargo test --workspace` — see `HANDOFF.md` §11 for the known-inherited
      failures and the required `RUST_MIN_STACK=16777216`
- [ ] **benchmark gate** PASS (`scripts/bench/run-gate.sh <candidate> <previous release>`, see "Benchmark gate"
      below); attach `verdict.md` to the release PR
- [ ] `python3 tools/acp-probe.py --key …` against the **release** binary, not
      just the debug one
- [ ] fuzz the parsers: `scripts/fuzz/run-all.sh 60` on the build box (needs nightly + cargo-fuzz; see the script header);
      no crash artifacts, and every input in `fuzz/regressions/` still replays clean. The sanitizer target follows the
      safety contract (header of `fuzz/fuzz_targets/sanitizer.rs`): BLOCKING = a panic; a secret still visible (known
      shape, URL userinfo, a credential the independent `url`-crate oracle or the assignment oracle finds); super-linear
      time (the 10 s `-timeout`, output over `4 * input + 256`); a regression against the frozen 1.0.45 redactor (gated
      by `cargo test -p fuigo-secrets` and one `SANITIZER_DIFFERENTIAL_INPUTS=100000` run, not the fuzz target). NOT
      blocking = idempotence (`redact(redact(x)) != redact(x)`): each case prints `IDEMPOTENCE_WARN <hex16> <function>`
      and the summary reports the count per target; record it in the release notes. It fails safe: the callers that
      re-scrub treat a second pass that still changes the text as "still secret" (fuigo-telemetry `sentry.rs` replaces
      the group or breadcrumbs with the marker, fuigo-memory `safety.rs` refuses a text that gains a marker)
- [ ] `fuigo --version` prints the intended version with no channel suffix
      (a `[alpha]` suffix means `derive_channel` found a stable pointer ahead of
      you — check the update channel pointers)
- [ ] `npm run check-version` clean
- [ ] all six binaries built for their own triple
- [ ] `npm pack --dry-run` in the meta package shows `bin/` and nothing unexpected
- [ ] tag the commit; `fuigo --version` embeds the short hash
- [ ] `docs/release-notes-<version>.md` committed before tagging (the GitHub
      Release body)
- [ ] after the run: the `github-release` job is green and
      `gh release view v<version> --repo FerroxLabs/fuigo` lists 15 assets

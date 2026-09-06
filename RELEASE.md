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
| the binary's `<version> (<commit>)` stamp | `fuigo-pager-bin/build.rs` reads the manifest above | `the_stamped_version_is_the_one_source_of_truth` |
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
the end of a two-hour build. `darwin-x64` therefore cross-compiles on
`macos-14`; aws-lc-sys builds its C for x86_64 there in under a minute, and
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

No `--provenance`. npm has refused provenance attestations from private source
repositories since 2023-07-25, and `FerroxLabs/fuigo` is private; asking for
one fails the publish. If the repo is ever made public, add the flag back
along with `id-token: write` in the workflow.

---

## Code signing

**npx needs none.** The linker already applies an ad-hoc signature, which is
what the arm64 kernel requires, and npm never sets `com.apple.quarantine` or
Windows' Mark-of-the-Web — so neither Gatekeeper nor SmartScreen assesses the
file.

Two places that *do* need real signing:

- **Bundled inside a `.app`** (e.g. Murage's Electron build): the binary must
  carry the same Developer ID as the app and be inside the notarised bundle, or
  `codesign --verify` fails on the app and notarization is rejected.
- **GitHub Releases direct download**: browser-downloaded files are quarantined,
  so macOS needs Developer ID + notarization and Windows wants Authenticode.

If you strip to save size, note the trade: 166 MB → 141 MB raw, 42 MB → 43 MB
brotli, so roughly 10% compressed for the loss of symbols in crash reports.
Xcode's `strip` re-signs automatically; `llvm-strip` and GNU binutils do not,
and an invalidated signature on arm64 is `Killed: 9` with no diagnostic.

---

## Pre-release checklist

- [ ] `cargo test --workspace` — see `HANDOFF.md` §11 for the known-inherited
      failures and the required `RUST_MIN_STACK=16777216`
- [ ] `python3 tools/acp-probe.py --key …` against the **release** binary, not
      just the debug one
- [ ] `fuigo --version` prints the intended version with no channel suffix
      (a `[alpha]` suffix means `derive_channel` found a stable pointer ahead of
      you — check the update CDN config)
- [ ] `npm run check-version` clean
- [ ] all six binaries built for their own triple
- [ ] `npm pack --dry-run` in the meta package shows `bin/` and nothing unexpected
- [ ] tag the commit; `fuigo --version` embeds the short hash

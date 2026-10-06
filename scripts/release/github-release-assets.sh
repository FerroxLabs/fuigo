#!/usr/bin/env bash
# Lay out the GitHub Release assets for one Fuigo version.
#
#   github-release-assets.sh <version> <binaries-dir> <npm-packages-dir> <out-dir>
#
# <binaries-dir>      the release workflow's downloaded build artifacts:
#                     fuigo-<npm-platform>/fuigo-pager[.exe], one per platform
# <npm-packages-dir>  the seven npm tarballs plus release-manifest.json, as
#                     written by verify-package-archives.js
# <out-dir>           created empty; receives exactly the files the release gets
#
# The github-release job passes registry-derived inputs here, written by
# registry-release-inputs.sh from the tarballs npm serves (finding RL-01); the
# publish job's dry-run check passes this run's build and local tarballs.
#
# The release carries two sets of files:
#
# 1. The format used by v1.0.7 to v1.0.11: the seven npm tarballs,
#    release-manifest.json and SHA256SUMS.
# 2. One raw binary per platform, named the way the gh-release installer in
#    crates/codegen/fuigo-update/src/auto_update.rs asks for it:
#    `fuigo-<version>-<os>-<arch>`, with <os>-<arch> from `detect_platform()`.
#    The installer runs `gh release download v<version> --pattern <that name>`,
#    and no release up to v1.0.11 had such an asset, so set 1 alone does not
#    serve it. Every client since at least 1.0.11 uses this same name.
#
# Each raw binary must be byte-identical to the brotli-compressed binary inside
# the npm tarball for the same platform, so the GitHub Release ships exactly
# what npm ships. SHA256SUMS covers every other file in <out-dir>.
#
# The platform table below is pinned by a unit test in
# crates/codegen/fuigo-update/src/auto_update_tests.rs
# (`gh_release_asset_names_match_release_layout_script`). Change both together.
set -euo pipefail

if [ "$#" -ne 4 ]; then
  echo "usage: $0 <version> <binaries-dir> <npm-packages-dir> <out-dir>" >&2
  exit 2
fi
VERSION=$1
BIN_DIR=$2
NPM_DIR=$3
OUT=$4

case "$VERSION" in
  *[!0-9A-Za-z.+-]*|'') echo "error: unexpected version string '$VERSION'" >&2; exit 1 ;;
esac

if [ -e "$OUT" ] && [ -n "$(ls -A "$OUT")" ]; then
  echo "error: $OUT exists and is not empty" >&2
  exit 1
fi
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)

if command -v sha256sum >/dev/null; then
  sha256() { sha256sum "$@"; }
else
  sha256() { shasum -a 256 "$@"; }
fi

# Decompress the npm tarball's executable and compare it with the raw binary.
same_as_npm() { # <tgz> <member> <raw-binary>
  # shellcheck disable=SC2016 # JavaScript, not shell: the ${...} are template literals
  node -e '
    const fs = require("fs"), zlib = require("zlib"), {execFileSync} = require("child_process");
    const [tgz, member, raw] = process.argv.slice(1);
    const br = execFileSync("tar", ["-xOzf", tgz, member], {maxBuffer: 1 << 30});
    const unpacked = zlib.brotliDecompressSync(br);
    const built = fs.readFileSync(raw);
    if (!unpacked.equals(built)) {
      console.error(`error: ${raw} differs from ${member} in ${tgz}`);
      process.exit(1);
    }
  ' "$1" "$2" "$3"
}

PLATFORMS="darwin-arm64 darwin-x64 linux-arm64 linux-x64 win32-arm64 win32-x64"
for npm_platform in $PLATFORMS; do
  case "$npm_platform" in
    darwin-arm64) asset_platform=macos-aarch64 ;;
    darwin-x64) asset_platform=macos-x86_64 ;;
    linux-arm64) asset_platform=linux-aarch64 ;;
    linux-x64) asset_platform=linux-x86_64 ;;
    win32-arm64) asset_platform=windows-aarch64 ;;
    win32-x64) asset_platform=windows-x86_64 ;;
    *) echo "error: no asset name for $npm_platform" >&2; exit 1 ;;
  esac
  case "$npm_platform" in
    win32-*) built=fuigo-pager.exe; member=package/bin/fuigo.exe.br ;;
    *) built=fuigo-pager; member=package/bin/fuigo.br ;;
  esac
  raw="$BIN_DIR/fuigo-$npm_platform/$built"
  tgz="$NPM_DIR/fuigo-$npm_platform-$VERSION.tgz"
  [ -s "$raw" ] || { echo "error: missing build artifact $raw" >&2; exit 1; }
  [ -s "$tgz" ] || { echo "error: missing npm tarball $tgz" >&2; exit 1; }
  same_as_npm "$tgz" "$member" "$raw"
  cp "$raw" "$OUT/fuigo-$VERSION-$asset_platform"
  cp "$tgz" "$OUT/"
  echo "fuigo-$VERSION-$asset_platform  <- $raw (matches $member in $(basename "$tgz"))"
done

[ -s "$NPM_DIR/fuigo-$VERSION.tgz" ] || { echo "error: missing npm tarball fuigo-$VERSION.tgz" >&2; exit 1; }
cp "$NPM_DIR/fuigo-$VERSION.tgz" "$OUT/"

# The manifest must describe this version and exactly the seven tarballs copied above.
# shellcheck disable=SC2016 # JavaScript, not shell: the ${...} are template literals
node -e '
  const fs = require("fs"), path = require("path");
  const [manifestPath, version, out] = process.argv.slice(1);
  const m = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
  if (m.version !== version) { console.error(`error: manifest version ${m.version} != ${version}`); process.exit(1); }
  if (!Array.isArray(m.packages) || m.packages.length !== 7) { console.error("error: manifest must list 7 packages"); process.exit(1); }
  for (const p of m.packages) {
    const f = path.join(out, p.filename);
    if (!fs.existsSync(f) || fs.statSync(f).size !== p.size) { console.error(`error: manifest entry ${p.filename} does not match ${f}`); process.exit(1); }
  }
' "$NPM_DIR/release-manifest.json" "$VERSION" "$OUT"
cp "$NPM_DIR/release-manifest.json" "$OUT/"

# Same SHA256SUMS shape as v1.0.11: "<sha256>  <name>", C-sorted, every asset except itself.
(
  cd "$OUT"
  # shellcheck disable=SC2012 # names are fixed above and contain no whitespace
  names=$(LC_ALL=C ls)
  for f in $names; do sha256 "$f"; done > "$OUT.SHA256SUMS.tmp"
  mv "$OUT.SHA256SUMS.tmp" SHA256SUMS
)

count=$(find "$OUT" -mindepth 1 -maxdepth 1 | wc -l | tr -d ' ')
[ "$count" = 15 ] || { echo "error: expected 15 release assets, laid out $count" >&2; ls -l "$OUT" >&2; exit 1; }
echo "laid out $count GitHub Release assets for $VERSION in $OUT"

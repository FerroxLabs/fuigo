#!/usr/bin/env bash
# Fetch the npm packages actually published for one Fuigo version and turn them
# into the inputs github-release-assets.sh expects.
#
#   registry-release-inputs.sh <version> <binaries-out> <npm-packages-out> [<fresh-binaries-dir>]
#
# <binaries-out>        created empty; receives fuigo-<npm-platform>/fuigo-pager[.exe],
#                       each decompressed from the brotli executable in the
#                       REGISTRY tarball for that platform
# <npm-packages-out>    created empty; receives the seven tarballs exactly as the
#                       registry serves them, plus a release-manifest.json in the
#                       shape verify-package-archives.js writes, describing them
# <fresh-binaries-dir>  optional: this run's build artifacts, same layout as
#                       <binaries-out>. Each is compared with the registry binary
#                       and any difference is reported. They are never used as
#                       release bytes.
#
# Why (finding RL-01): the publish job skips any npm version that already
# exists, so after a partial publish a re-run leaves npm serving the bytes of an
# EARLIER build while this run's build artifacts hold a fresh build. Laying the
# GitHub Release out from the fresh build would ship different binaries and
# SHA256SUMS on the two channels. Deriving every release asset from the registry
# tarballs makes both channels ship the same bytes on every run, first or retry,
# and they are the bytes the verify-published job has executed natively.
#
# Each tarball's sha512 is computed here and must equal the registry's
# dist.integrity for that exact version, read separately with `npm view`.
set -euo pipefail

if [ "$#" -lt 3 ] || [ "$#" -gt 4 ]; then
  echo "usage: $0 <version> <binaries-out> <npm-packages-out> [<fresh-binaries-dir>]" >&2
  exit 2
fi
VERSION=$1
BIN_OUT=$2
NPM_OUT=$3
FRESH=${4:-}

case "$VERSION" in
  *[!0-9A-Za-z.+-]*|'') echo "error: unexpected version string '$VERSION'" >&2; exit 1 ;;
esac

for d in "$BIN_OUT" "$NPM_OUT"; do
  if [ -e "$d" ] && [ -n "$(ls -A "$d")" ]; then
    echo "error: $d exists and is not empty" >&2
    exit 1
  fi
  mkdir -p "$d"
done
BIN_OUT=$(cd "$BIN_OUT" && pwd)
NPM_OUT=$(cd "$NPM_OUT" && pwd)
if [ -n "$FRESH" ]; then
  [ -d "$FRESH" ] || { echo "error: $FRESH is not a directory" >&2; exit 1; }
  FRESH=$(cd "$FRESH" && pwd)
fi

# The release bytes must be what the public npm registry serves (Astra P112 r1): no project,
# user, global or environment npm configuration may choose the registry. npm runs from an empty
# directory with an empty environment (only PATH, and HOME pointing at that directory), the global
# config pointed at a file that does not exist, and both the default registry and the @fuigo scope
# pinned on the command line.
REGISTRY=https://registry.npmjs.org/
NPM_HOME=$(mktemp -d)
trap 'rm -rf "$NPM_HOME"' EXIT
public_npm() {
  (cd "$NPM_HOME" && env -i PATH="$PATH" HOME="$NPM_HOME" \
    NPM_CONFIG_GLOBALCONFIG="$NPM_HOME/no-global-npmrc" NPM_CONFIG_USERCONFIG="$NPM_HOME/no-user-npmrc" \
    npm --registry="$REGISTRY" --@fuigo:registry="$REGISTRY" "$@")
}

PLATFORMS="darwin-arm64 darwin-x64 linux-arm64 linux-x64 win32-arm64 win32-x64"
drift=0
for p in $PLATFORMS ""; do
  if [ -n "$p" ]; then spec="@fuigo/$p@$VERSION"; file="fuigo-$p-$VERSION.tgz"
  else spec="fuigo@$VERSION"; file="fuigo-$VERSION.tgz"; fi

  integrity=$(public_npm view "$spec" dist.integrity)
  [ -n "$integrity" ] || { echo "error: $spec has no dist.integrity on the registry" >&2; exit 1; }
  public_npm pack "$spec" --ignore-scripts --json --pack-destination "$NPM_OUT" > "$NPM_OUT/.pack.json"
  # shellcheck disable=SC2016 # JavaScript, not shell: the ${...} are template literals
  node -e '
    const fs = require("fs"), path = require("path"), crypto = require("crypto");
    const [packJson, dir, file, integrity, name, version] = process.argv.slice(1);
    const [packed] = JSON.parse(fs.readFileSync(packJson, "utf8"));
    const fail = m => { console.error(`error: ${m}`); process.exit(1); };
    if (packed.name !== name || packed.version !== version) fail(`npm pack returned ${packed.name}@${packed.version}`);
    if (packed.filename !== file) fail(`npm pack wrote ${packed.filename}, expected ${file}`);
    const bytes = fs.readFileSync(path.join(dir, file));
    const got = "sha512-" + crypto.createHash("sha512").update(bytes).digest("base64");
    if (got !== integrity) fail(`${file} is ${got}, the registry says ${integrity}`);
  ' "$NPM_OUT/.pack.json" "$NPM_OUT" "$file" "$integrity" "${spec%@*}" "$VERSION"
  rm "$NPM_OUT/.pack.json"
  echo "$file  <- registry $spec ($integrity)"

  [ -n "$p" ] || continue
  case "$p" in
    win32-*) built=fuigo-pager.exe; member=package/bin/fuigo.exe.br ;;
    *) built=fuigo-pager; member=package/bin/fuigo.br ;;
  esac
  mkdir "$BIN_OUT/fuigo-$p"
  # shellcheck disable=SC2016 # JavaScript, not shell: the ${...} are template literals
  node -e '
    const fs = require("fs"), zlib = require("zlib"), crypto = require("crypto");
    const {execFileSync} = require("child_process");
    const [tgz, member, out, fresh] = process.argv.slice(1);
    const br = execFileSync("tar", ["-xOzf", tgz, member], {maxBuffer: 1 << 30});
    const raw = zlib.brotliDecompressSync(br, {maxOutputLength: 512 * 1024 * 1024});
    if (raw.length === 0) { console.error(`error: ${member} in ${tgz} is empty`); process.exit(1); }
    fs.writeFileSync(out, raw, {mode: 0o755});
    const sum = b => crypto.createHash("sha256").update(b).digest("hex");
    console.log(`  ${out}  sha256 ${sum(raw)}`);
    if (fresh) {
      if (!fs.existsSync(fresh)) { console.log(`  no fresh build at ${fresh} to compare`); process.exit(0); }
      const built = fs.readFileSync(fresh);
      if (built.equals(raw)) { console.log("  the fresh build is byte-identical"); process.exit(0); }
      console.log(`::warning::${fresh} (sha256 ${sum(built)}) differs from the published npm executable; the release uses the npm bytes`);
      process.exit(3);
    }
  ' "$NPM_OUT/$file" "$member" "$BIN_OUT/fuigo-$p/$built" "${FRESH:+$FRESH/fuigo-$p/$built}" || {
    rc=$?
    [ "$rc" = 3 ] || exit "$rc"
    drift=$((drift + 1))
  }
done

# Same shape as verify-package-archives.js, describing the registry tarballs.
# shellcheck disable=SC2016 # JavaScript, not shell: the ${...} are template literals
node -e '
  const fs = require("fs"), path = require("path"), crypto = require("crypto");
  const [dir, version] = process.argv.slice(1);
  const platforms = ["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64", "win32-arm64", "win32-x64"];
  const packages = [...platforms, null].map(p => {
    const filename = p ? `fuigo-${p}-${version}.tgz` : `fuigo-${version}.tgz`;
    const bytes = fs.readFileSync(path.join(dir, filename));
    return {name: p ? `@fuigo/${p}` : "fuigo", version, filename,
      integrity: "sha512-" + crypto.createHash("sha512").update(bytes).digest("base64"),
      shasum: crypto.createHash("sha1").update(bytes).digest("hex"), size: bytes.length};
  });
  fs.writeFileSync(path.join(dir, "release-manifest.json"), JSON.stringify({
    sourceCommit: process.env.GITHUB_SHA || null, version, packages,
  }, null, 2) + "\n");
' "$NPM_OUT" "$VERSION"

echo "fetched 7 published npm packages for $VERSION into $NPM_OUT, executables in $BIN_OUT"
if [ "$drift" -gt 0 ]; then
  echo "::warning::$drift of 6 freshly built binaries differ from what npm serves for $VERSION (an earlier run published them); the release ships the npm bytes"
fi

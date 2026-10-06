#!/usr/bin/env bash
# Tests for the release layout scripts against a fake npm registry (packet P126). Nothing is
# published and the network is never touched.
#
#   scripts/release/test-release-scripts.sh
#
# Covers registry-release-inputs.sh (pinned public npm, integrity check), github-release-assets.sh,
# and verify-release-digests.js fed the layout those two produce. Needs bash, node and tar.
# The node-side tests are crates/codegen/fuigo-pager/npm/fuigo/scripts/test-release-provenance.js.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
VERSION=1.2.3
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
pass=0; fail=0
ok() { echo "  ok   $1"; pass=$((pass + 1)); }
bad() { echo "  FAIL $1"; fail=$((fail + 1)); }
check() { # <name> <command...>: passes when the command succeeds
  local name=$1; shift
  if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name"; fi
}
refuses() { # <name> <stderr-pattern> <command...>: passes when it fails and says why
  local name=$1 pattern=$2; shift 2
  local out rc=0
  out=$("$@" 2>&1) || rc=$?
  if [ "$rc" != 0 ] && printf '%s' "$out" | grep -q -- "$pattern"; then ok "$name"; else bad "$name (rc=$rc: $out)"; fi
}

# ---- fixtures: seven tarballs like the registry serves, and a fake npm over them ----
FX=$WORK/registry
mkdir -p "$FX"
# shellcheck disable=SC2016 # JavaScript, not shell: the ${...} are template literals
node -e '
  const fs = require("fs"), path = require("path"), zlib = require("zlib"), crypto = require("crypto");
  const {execFileSync} = require("child_process");
  const [fx, version] = process.argv.slice(1);
  for (const p of ["darwin-arm64", "darwin-x64", "linux-arm64", "linux-x64", "win32-arm64", "win32-x64", ""]) {
    const base = p ? `fuigo-${p}-${version}` : `fuigo-${version}`;
    const stage = path.join(fx, "stage-" + base, "package");
    fs.mkdirSync(path.join(stage, "bin"), {recursive: true});
    fs.writeFileSync(path.join(stage, "package.json"), JSON.stringify({name: p ? `@fuigo/${p}` : "fuigo", version}));
    if (p) fs.writeFileSync(path.join(stage, "bin", p.startsWith("win32") ? "fuigo.exe.br" : "fuigo.br"),
      zlib.brotliCompressSync(Buffer.from(`executable for ${p}`)));
    execFileSync("tar", ["-czf", path.join(fx, base + ".tgz"), "-C", path.dirname(stage), "package"]);
    fs.writeFileSync(path.join(fx, base + ".integrity"),
      "sha512-" + crypto.createHash("sha512").update(fs.readFileSync(path.join(fx, base + ".tgz"))).digest("base64"));
    fs.rmSync(path.dirname(stage), {recursive: true});
  }
' "$FX" "$VERSION"

make_shim() { # <dir> <registry-dir>
  mkdir -p "$1"
  cat > "$1/npm" <<SHIM
#!/bin/sh
# Fake npm: logs how it was called, serves tarballs from $2.
{ echo "== \$(pwd)"; echo "ARGS \$*"; env | sort; } >> "$1/calls.log"
while [ "\$#" -gt 0 ]; do
  case "\$1" in --registry=*|--@fuigo:registry=*) shift ;; *) break ;; esac
done
cmd=\$1; spec=\$2
base=\$(printf '%s' "\$spec" | sed -e 's|^@fuigo/|fuigo-|' -e 's|@|-|')
name=\${spec%@*}; version=\${spec##*@}
case "\$cmd" in
  view) cat "$2/\$base.integrity"; echo ;;
  pack)
    shift 2
    dest=
    while [ "\$#" -gt 0 ]; do [ "\$1" = --pack-destination ] && dest=\$2; shift; done
    [ -f "$2/\$base.tgz" ] || { echo "E404 \$spec" >&2; exit 1; }
    cp "$2/\$base.tgz" "\$dest/"
    printf '[{"name":"%s","version":"%s","filename":"%s.tgz"}]\n' "\$name" "\$version" "\$base"
    ;;
  *) echo "fake npm: unsupported \$cmd" >&2; exit 1 ;;
esac
SHIM
  chmod +x "$1/npm"
}
make_shim "$WORK/shim" "$FX"

# A caller whose environment and project/user npm config all point somewhere hostile.
export npm_config_registry=https://evil.example/ NPM_CONFIG_REGISTRY=https://evil.example/
export NODE_AUTH_TOKEN=sekret-token HTTPS_PROXY=http://evil.example:3128
POISON_HOME=$WORK/poison-home; mkdir -p "$POISON_HOME"
echo 'registry=https://evil.example/' > "$POISON_HOME/.npmrc"
export HOME=$POISON_HOME
mkdir -p "$WORK/cwd"; echo 'registry=https://evil.example/' > "$WORK/cwd/.npmrc"
cd "$WORK/cwd"
export PATH="$WORK/shim:$PATH"

echo "registry-release-inputs.sh + github-release-assets.sh"
# shellcheck disable=SC2016 # the single-quoted script is expanded by the inner bash
check "fetches the seven packages and lays out the release" \
  bash -c '"$0" "$1" "$2/bin" "$2/npm" && "$3/github-release-assets.sh" "$1" "$2/bin" "$2/npm" "$2/release"' \
  "$HERE/registry-release-inputs.sh" "$VERSION" "$WORK/ok" "$HERE"
check "all 15 release assets exist" test "$(find "$WORK/ok/release" -mindepth 1 | wc -l | tr -d ' ')" = 15

LOG=$WORK/shim/calls.log
check "every npm call pinned both registries" test "$(grep -c '^ARGS ' "$LOG")" -gt 0
check "no npm call missed the registry pins" \
  test "$(grep '^ARGS ' "$LOG" | grep -c -- '--registry=https://registry.npmjs.org/ --@fuigo:registry=https://registry.npmjs.org/')" = "$(grep -c '^ARGS ' "$LOG")"
check "no hostile environment reached npm" test "$(grep -c -e evil.example -e sekret-token "$LOG")" = 0
# shellcheck disable=SC2016 # the single-quoted script is expanded by the inner bash
check "npm saw its own empty HOME and nonexistent npmrc files" \
  bash -c 'grep -q "^NPM_CONFIG_USERCONFIG=.*/no-user-npmrc$" "$0" && grep -q "^NPM_CONFIG_GLOBALCONFIG=.*/no-global-npmrc$" "$0" && ! grep -q "^HOME=$1\$" "$0"' "$LOG" "$POISON_HOME"
check "npm ran from a directory other than the caller's" test "$(grep -c "^== $WORK/cwd\$" "$LOG")" = 0

# integrity: the registry advertises one digest and serves different bytes
cp -R "$FX" "$WORK/registry-lie"
echo "sha512-AAAA" > "$WORK/registry-lie/fuigo-linux-x64-$VERSION.integrity"
make_shim "$WORK/shim-lie" "$WORK/registry-lie"
refuses "refuses a tarball that does not match dist.integrity" "the registry says sha512-AAAA" \
  env PATH="$WORK/shim-lie:$PATH" "$HERE/registry-release-inputs.sh" "$VERSION" "$WORK/lie/bin" "$WORK/lie/npm"

echo "verify-release-digests.js on that layout"
mkdir -p "$WORK/verified"
# shellcheck disable=SC2016 # JavaScript, not shell: the ${...} are template literals
node -e '
  const fs = require("fs"), crypto = require("crypto"), path = require("path");
  const [rel, out, version] = process.argv.slice(1);
  const asset = {"darwin-arm64": "macos-aarch64", "darwin-x64": "macos-x86_64", "linux-arm64": "linux-aarch64",
    "linux-x64": "linux-x86_64", "win32-arm64": "windows-aarch64", "win32-x64": "windows-x86_64"};
  for (const [p, a] of Object.entries(asset)) {
    const tgz = fs.readFileSync(path.join(rel, `fuigo-${p}-${version}.tgz`));
    const raw = fs.readFileSync(path.join(rel, `fuigo-${version}-${a}`));
    fs.writeFileSync(path.join(out, `verified-${p}.json`), JSON.stringify({platform: p, name: `@fuigo/${p}`, version,
      integrity: "sha512-" + crypto.createHash("sha512").update(tgz).digest("base64"),
      sha256: crypto.createHash("sha256").update(raw).digest("hex")}));
  }
' "$WORK/ok/release" "$WORK/verified" "$VERSION"
check "accepts the layout the verifiers executed" node "$HERE/verify-release-digests.js" "$VERSION" "$WORK/verified" "$WORK/ok/release"
cp -R "$WORK/ok/release" "$WORK/tampered"
printf x >> "$WORK/tampered/fuigo-$VERSION-linux-x86_64"
refuses "rejects a raw binary that is not what the verifier ran" "linux-x86_64 is sha256" \
  node "$HERE/verify-release-digests.js" "$VERSION" "$WORK/verified" "$WORK/tampered"
cp -R "$WORK/ok/release" "$WORK/tampered2"
printf x >> "$WORK/tampered2/fuigo-darwin-x64-$VERSION.tgz"
refuses "rejects a tarball that is not what the verifier ran" "darwin-x64-$VERSION.tgz is sha512" \
  node "$HERE/verify-release-digests.js" "$VERSION" "$WORK/verified" "$WORK/tampered2"
rm "$WORK/verified/verified-win32-arm64.json"
refuses "rejects a platform whose verifier never reported" "no verified digests for win32-arm64" \
  node "$HERE/verify-release-digests.js" "$VERSION" "$WORK/verified" "$WORK/ok/release"

echo "lint"
if command -v shellcheck >/dev/null; then
  check "shellcheck is clean" shellcheck "$HERE/registry-release-inputs.sh" "$HERE/github-release-assets.sh" "$HERE/test-release-scripts.sh"
else
  echo "  skip shellcheck (not installed)"
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]

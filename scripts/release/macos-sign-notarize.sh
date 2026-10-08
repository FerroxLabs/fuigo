#!/usr/bin/env bash
# Sign (Developer ID, hardened runtime), verify, then notarize one bare Mach-O. Usage: <binary> <expected-arch>
# Required env: APPLE_API_KEY_ID APPLE_API_ISSUER_ID APPLE_API_KEY_P8_BASE64 RUNNER_TEMP GITHUB_ENV
# No entitlements: the pager is a plain Rust CLI/TUI (no JIT, no allow-unsigned-executable-memory;
# no .entitlements/.plist in the repo), so the default hardened runtime is sufficient.
set +x
set -euo pipefail
BIN=$1; ARCH=$2
IDENTITY="Developer ID Application: Ferrox Labs, LLC (PX6SP9GPWJ)"
for v in APPLE_API_KEY_ID APPLE_API_ISSUER_ID APPLE_API_KEY_P8_BASE64; do
  [ -n "${!v:-}" ] || { echo "::error::secret $v is empty or missing; refusing to notarize (mac_sign is on)"; exit 1; }
done
archs=$(lipo -archs "$BIN"); [ "$archs" = "$ARCH" ] || { echo "::error::expected $ARCH, got $archs"; exit 1; }

codesign --force --options runtime --timestamp --sign "$IDENTITY" "$BIN"
codesign --verify --strict --verbose=2 "$BIN"
info=$(codesign -dv --verbose=4 "$BIN" 2>&1); echo "$info"
echo "$info" | grep -q '^TeamIdentifier=PX6SP9GPWJ$' || { echo "::error::TeamIdentifier is not PX6SP9GPWJ"; exit 1; }
echo "$info" | grep -Eq 'flags=0x[0-9a-f]+\(.*runtime' || { echo "::error::hardened runtime flag missing"; exit 1; }
echo "$info" | grep -q 'Signature=adhoc' && { echo "::error::signature is ad-hoc"; exit 1; }

API_KEY_PATH="$RUNNER_TEMP/fuigo-apple-api.p8"
echo "API_KEY_PATH=$API_KEY_PATH" >> "$GITHUB_ENV"
printf '%s' "$APPLE_API_KEY_P8_BASE64" | base64 --decode > "$API_KEY_PATH"
ZIP="$RUNNER_TEMP/fuigo-notarize.zip"
rm -f "$ZIP"; ditto -c -k --keepParent "$BIN" "$ZIP"
OUT="$RUNNER_TEMP/notary-$ARCH.json"
set +e
xcrun notarytool submit "$ZIP" --key "$API_KEY_PATH" --key-id "$APPLE_API_KEY_ID" \
  --issuer "$APPLE_API_ISSUER_ID" --wait --output-format json > "$OUT"
rc=$?
set -e
cat "$OUT" || true
STATUS=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("status",""))' "$OUT" 2>/dev/null || true)
ID=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("id",""))' "$OUT" 2>/dev/null || true)
echo "notarization submission id: $ID status: $STATUS"
if [ "$STATUS" != "Accepted" ]; then
  if [ -n "$ID" ]; then
    xcrun notarytool log "$ID" --key "$API_KEY_PATH" --key-id "$APPLE_API_KEY_ID" --issuer "$APPLE_API_ISSUER_ID" || true
  fi
  echo "::error::notarization status '$STATUS' (rc=$rc), expected Accepted"; exit 1
fi
# A bare Mach-O executable cannot be stapled (stapler needs an app/pkg/dmg bundle), so no
# `stapler` here: Gatekeeper checks the notarization ticket online. spctl is informational only:
# it reports "does not seem to be an app" for bare CLI binaries, so it is not a gate.
spctl --assess --type execute --verbose=2 "$BIN" 2>&1 || echo "(spctl informational only for bare CLI binaries)"
codesign --verify --strict --verbose=2 "$BIN"

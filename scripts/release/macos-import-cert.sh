#!/usr/bin/env bash
# Import the Developer ID certificate into a throwaway keychain. Secrets arrive via env only.
# Required env: MAC_CERT_P12_BASE64 MAC_CERT_PASSWORD RUNNER_TEMP GITHUB_ENV
set +x
set -euo pipefail
for v in MAC_CERT_P12_BASE64 MAC_CERT_PASSWORD; do
  [ -n "${!v:-}" ] || { echo "::error::secret $v is empty or missing; refusing to sign (mac_sign is on)"; exit 1; }
done
KC_PASS=$(openssl rand -hex 24)
echo "::add-mask::$KC_PASS"
KC="$RUNNER_TEMP/fuigo-sign.keychain-db"
P12="$RUNNER_TEMP/fuigo-devid.p12"
echo "KEYCHAIN_PATH=$KC" >> "$GITHUB_ENV"
echo "P12_PATH=$P12" >> "$GITHUB_ENV"
printf '%s' "$MAC_CERT_P12_BASE64" | base64 --decode > "$P12"
security create-keychain -p "$KC_PASS" "$KC"
security set-keychain-settings -lut 3600 "$KC"
security unlock-keychain -p "$KC_PASS" "$KC"
security import "$P12" -k "$KC" -P "$MAC_CERT_PASSWORD" -T /usr/bin/codesign >/dev/null
security set-key-partition-list -S apple-tool:,apple: -s -k "$KC_PASS" "$KC" >/dev/null
# shellcheck disable=SC2046
security list-keychains -d user -s "$KC" $(security list-keychains -d user | tr -d '"')
security find-identity -v -p codesigning "$KC" | grep -c "PX6SP9GPWJ" >/dev/null \
  || { echo "::error::no PX6SP9GPWJ code-signing identity in the imported certificate"; exit 1; }
echo "imported Developer ID identity (team PX6SP9GPWJ)"

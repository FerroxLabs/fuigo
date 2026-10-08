#!/usr/bin/env bash
# Always-run cleanup: delete the throwaway keychain, the p12 and the API key file.
set +x
[ -n "${KEYCHAIN_PATH:-}" ] && security delete-keychain "$KEYCHAIN_PATH" 2>/dev/null
[ -n "${P12_PATH:-}" ] && rm -f "$P12_PATH"
[ -n "${API_KEY_PATH:-}" ] && rm -f "$API_KEY_PATH"
rm -f "${RUNNER_TEMP:-/nonexistent}"/fuigo-notarize.zip
exit 0

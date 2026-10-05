# P112 Astra round 1 report (gpt-6-astra, read-only, coordinator run on eff64cf9)

Raw transcript sha256: 115db6c9c688993c9fa0d671a2cbc39e158fabdb15266a9fc5cbfb0961e16cde

**HIGH — Attacker-controlled npm configuration can determine GitHub release bytes.** [registry-release-inputs.sh:63](/Volumes/Mando/WaylandBots/Fuigo/wt-p112/scripts/release/registry-release-inputs.sh:63), [release.yml:666](/Volumes/Mando/WaylandBots/Fuigo/wt-p112/.github/workflows/release.yml:666).

Both `npm view` and `npm pack` inherit registry configuration; neither enforces the public npm registry. An attacker-controlled `.npmrc`, scoped `@fuigo:registry`, or npm environment configuration can supply replacement tarballs with the expected names, versions, and matching SHA-512 values. The checksum check then authenticates consistency with the attacker’s metadata, while public npm still serves different bytes.

The preceding verification does not close this gap. Its download runs from a temporary directory ([verify-published-platform.js:19](/Volumes/Mando/WaylandBots/Fuigo/wt-p112/crates/codegen/fuigo-pager/npm/fuigo/scripts/verify-published-platform.js:19)), whereas the release fetch runs from the checkout. A checkout-level `.npmrc` can therefore redirect the latter independently. Verification hashes are only logged, and differences from fresh binaries merely produce warnings. GitHub can publish the substituted binaries and matching checksums successfully.

**Required correction:** isolate npm configuration and enforce `https://registry.npmjs.org` for both default and `@fuigo` registry resolution. Bind the release downloads to the digests accepted by native verification.

No additional confirmed findings: the normal trusted-registry path removes rebuilt binaries from publication; inspected expansions are safely quoted; download, integrity, and extraction errors stop publication; `contents: write` is confined to the release job. Identical assets are skipped, and replacement requires the explicit manual option.

Static review of clean `strike/p112` at `eff64cf9`; no builds, tests, network commands, or file modifications performed.

DO-NOT-LAND

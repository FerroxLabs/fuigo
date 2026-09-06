# GCS authentication transport patch

Imported unmodified registry sources:

| Package | Version | crates.io archive checksum from Cargo.lock |
|---|---|---|
| gcloud-auth | 1.3.0 | b43924e3df02cb3b846ca66a7ee58e8c13eb2556d0308c71f6154083f6980365 |
| gcloud-metadata | 1.0.2 | bd3152612316be627be52fe9ca72331eb48425059b3a6a700e7adde223e061d5 |

All 30 imported source/manifest/readme/licence files were compared byte-for-byte
with the pinned Cargo registry sources before modifications. Cargo registry
metadata and per-package lockfiles are excluded. Original MIT licences are kept
in each package. Upstream: https://github.com/yoshidan/google-cloud-rust.

Purpose: inject Fuigo's guarded HTTP transport into authentication and metadata
requests while preserving upstream credential modes and refresh semantics.
Wired through [patch.crates-io]. Metadata owns a one-time process policy hook;
auth and metadata dispatch consult it before network contact. Fuigo installs its
TLS/redirect/destination policy before GCS credential discovery. Clients retain
their upstream timeouts, credential modes and payloads; construction is fallible.
Standalone SDK use without hook installation retains its default transport.
Focused verification and final acceptance are pending. The local-modification
notices are included in the root THIRD-PARTY-NOTICES packaged with future releases.

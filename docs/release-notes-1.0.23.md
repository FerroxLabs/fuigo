# Fuigo 1.0.23 release notes

This release follows 1.0.22. It changes how Fuigo is built and shipped, not what it does: the Windows and macOS
programs are now code-signed, the Linux programs run on older distributions again, and the Linux ARM program no
longer crashes on common ARM servers. There are no feature or behaviour changes.

## Before you upgrade

- **Close every running Fuigo session first** (TUI, `fuigo -p`, editor and desktop-app sessions, leaders).
- Install with `npm i -g fuigo`, or update with `fuigo update`. If you install by hand with npm while Fuigo is
  running, run `fuigo leader kill` afterwards so the shared session restarts on the new version.

---

## Fixed

- **F1. Windows: Fuigo is now code-signed.** `fuigo-pager.exe` (x64 and ARM64) carries an Authenticode signature
  from Ferrox Labs with a trusted timestamp. Windows Smart App Control and SmartScreen blocked the unsigned program
  in 1.0.22 and earlier; they accept the signed one.
- **F2. macOS: Fuigo is signed with a Developer ID and notarized by Apple.** Both the Apple silicon and the Intel
  program are signed by Ferrox Labs, LLC (team `PX6SP9GPWJ`) with the hardened runtime, and notarized. Earlier
  releases shipped an ad-hoc signature on Apple silicon and no signature on Intel.
- **F3. Linux on ARM: no more "Illegal instruction" on Neoverse N1, AWS Graviton2 and Ampere Altra/A1.** The
  `linux-arm64` program of 1.0.20 to 1.0.22 was built for a newer CPU and crashed at start on these machines. It is
  now built for any 64-bit ARM (ARMv8.0) processor.
- **F4. Linux: Fuigo runs on Ubuntu 22.04, Debian 12 and other distributions with glibc 2.28 or newer.** The Linux
  programs of earlier releases required glibc 2.39 and failed to start with a `GLIBC_2.39 not found` error. Both
  Linux programs (x64 and ARM64) are now built against glibc 2.28.

## For packagers and integrators

- Every download channel carries the same signed files: the npm platform packages, the GitHub Release assets, and
  the checksums in `SHA256SUMS` and `release-manifest.json`.
- The release pipeline now refuses to publish a Linux program that needs a newer glibc than 2.28, or a Linux ARM
  program that contains SVE or SME instructions.
- The wire protocol, configuration files and command-line interface are unchanged from 1.0.22.

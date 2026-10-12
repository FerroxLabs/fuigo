# R-reinstall: same-version reinstall replaces the binary

Branch `strike/reinstall` (base `hub/strike/integration` 4c9b5136). JavaScript only (npm package), no Rust, no cargo.

## What changed (`crates/codegen/fuigo-pager/npm/fuigo`)
- Bug: `postinstall.js` and `fuigo-bootstrap.js` both did `if (!fs.existsSync(versionedPath) && !writeVendorBinary(...))`,
  so `npm i -g fuigo@X` over an existing X kept the old `~/.fuigo/bin/fuigo-X`.
- New `bin/fuigo-replace.js` (`installVendorBinary`), used by both callers in place of that line. It ships with `bin/`.

## Comparison rule
Decode the vendored binary (brotli or raw), compare its length with the installed file; only when equal compare the
bytes (`Buffer.equals`, exact, so no hash is needed). Same content: nothing is written (inode and mtime stay).
Different: replace. Why not a sidecar or mtime: npm normalises mtimes of tarball files, so mtime says nothing. The cost
is paid only at install time and on a launch where the `~/.fuigo/bin/fuigo` link is missing (`resolveBinary` returns
early when it exists), so the common launch path is unchanged and does no hashing or reading.

## Replace mechanics
- Unique temp `<dest>.tmp.<pid>.<random>` opened `wx` with mode 0755, chmod 0755 on unix, then atomic `rename`.
  Never truncates or writes in place (macOS exit 137). Temp removed in `finally`.
- Destination is a symlink or not a regular file (`lstat`): left untouched, launch continues.
- Any failure (read-only dir, Windows binary in use) keeps the existing file and returns usable; no error exit. One
  stderr line only when `FUIGO_BOOTSTRAP_DEBUG` is set (new; the bootstrap had no debug variable).
- Missing vendored binary with an existing file: kept. Neither present: returns false as before.

## Per OS
- Linux: tested. macOS: rename-over design only; NOT run. Windows: rename over an in-use `.exe` fails and keeps the old
  file until the next start; NOT run.

## Tests
`node scripts/test-reinstall.js` (new, wired into `release.yml` Check versions): 9 passed, 0 failed, 0 skipped
(fresh install 0755; same content keeps inode and mtime; same-size different content replaced; different content new
inode, 0755, no temp left; raw vendored; symlink untouched; read-only dir keeps old file; missing vendor; 6 concurrent
processes leave a complete 8 MB file). The read-only case is skipped when running as root (not skipped in this run, uid 1000).
`node scripts/test-postinstall.js`: 39 passed, 0 failed (the harness now also copies `fuigo-replace.js`).

## Round 2 (audit `grok-reinstall-r1`)

- An empty vendored file (compressed or raw) never replaces an installed binary; with nothing installed the
  result is "not installed", as for a missing file. Test `empty vendored binary never replaces a good one`, red
  without the fix (the good binary was replaced by a zero-length file).
- The temp file is removed in `finally` only when this call created it.
- The release workflow is NOT changed by this packet (adding the test step there is an owner decision).
- Not done, stated: temp files left by a crash between write and rename are not swept; Windows and macOS were not
  run; two older call sites (`fuigo-bootstrap.js` about 142, `postinstall.js` about 218) still use
  `writeVendorBinary` for the first-install path and are unchanged.
- Round 2 audit (`grok-reinstall-r2`): the older first-install helper `writeVendorBinary` (in `postinstall.js` and
  `fuigo-bootstrap.js`, not changed by round 1) would still put an empty vendored file in place of the link target.
  It now refuses a zero-length result (the temp file is removed, the old target stays). No new test: the helper is
  not exported; both node test files pass unchanged (10 and 39).

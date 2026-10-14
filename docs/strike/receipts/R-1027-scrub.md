# R-1027 (b27-2) SCRUB: public-squash.sh redacts the Mac volume and build-box prefixes

Base 8a04062f (1.0.26 RC). Script only, no Rust. Applies to future releases.

## Sweep of the tree at base (hit counts are pre-squash, include raw audits that the squash drops)

| Prefix (described) | Hits | Call |
|---|---|---|
| Owner's Mac home | 93,077 | REAL, already redacted. 192 files, all under docs/, 0 source files. |
| Mac volume, project folder | 42,723 | REAL. 0 source files. |
| Mac volume, other sibling folders (4 of them) and bare volume | ~140 | REAL. 0 source files. |
| Mac volume, two paths that are really `/Volumes/AGENTS.md` lookups probing the root | 65 | Probe strings in raw transcripts; covered by the volume prefix. |
| Build-box lane prefix | 1,517 in 264 files | REAL. 179 docs files, 9 scripts/strike files (50 hits), 0 crates. |
| Peer build-box dirs (`w15-`, `waylandcore-stabilization-`) | 2 | Name fragments in docs, not redacted (not ours). |
| Owner's Windows user dir (`/mnt/c/Users/<name>`, `C:\Users\<name>`) | 19 hits, 16 files | REAL. Added by coordinator decision (see Addendum). |
| Dashed temp-dir form of the project path (`-Volumes-...`) | 126 hits, 2 files | REAL but a different shape; not in chosen set, in raw audits that are dropped. |
| `/tmp/claude-501/...` | 2 hits, 1 file (raw audit) | Dropped with the audit. Not redacted. |
| WSL home of the owner (`/home/<WSL user>`) | 0 | Not found; nothing to add. |
| `/Users/{alice,me,bob,bobby,test,user,foo,u,dev,janedoe,alicia,Shared,...}` | ~600 | FIXTURES, must not be redacted. |
| `/home/{user,u,me,alice,dev,agent,bob,rowan,sean,someone,test,...}` | ~1,150 | FIXTURES (tests use `/home/rowan` in compiled test constants). |
| `/root/.fuigo`, `/root/.cargo`, `/root/{a,b,c1,sub,solo,...}` | ~170 | FIXTURES or container paths, not redacted. |
| `C:\Users\{a,me,Alice,r,x,...}` | ~38 | FIXTURES. |

## Chosen set and replacements (longest first)

1. project folder under the Mac volume -> `<project>`
2. remaining Mac volume prefix -> `<volume>`
3. build-box lane prefix -> `<build>` (docs/ only, see below)
4. the home path, as before -> `~`

All literals are built from pieces; the script contains none of them and does not match itself.

## Safety question: does redaction touch anything the public tree builds or tests?

Tested by running the script on a throwaway clone at the commit (candidate = HEAD, parent = HEAD~1).

- Home path and Mac volume prefix: 0 non-doc files touched. Source files touched by the pre-existing home redaction: 0 (all 192 are docs/).
- Build-box prefix: 9 non-doc files contain it, all under scripts/strike/ (abort-lib.sh 1, final-gate.sh 3, doctest fixture log 1, gate-mutants.py 2, gate-selftest.sh 30, iso.sh 2, lane.sh 2, rp.sh 4, testlane.sh 5). These are live paths (the gate and its selftest/fixture read them), so by default they are NOT rewritten: the build-box redaction is scoped to docs/ via `build_scope`, and its FAIL check uses the same scope. After the squash those 9 files still contain the build prefix. NEEDS COORDINATOR DECISION: leave (build-box path in shipped scripts is low sensitivity) or parameterise those scripts.
- Crates, Cargo files, snapshots, CI: 0 files contain any of the three prefixes. Result of `git diff --name-only candidate squash-tree`: 0 non-docs files changed.
- Binary files: 0 binary blobs contain any of the prefixes (`git grep -a` and `-I` file counts are equal for each). Only matching blobs are rewritten, through `LC_ALL=C sed` (byte-wise, no locale mangling); GNU sed keeps a missing final newline, BSD sed appends one, which only matters for a matching text file.

## Test evidence (throwaway clone, deleted afterwards)

- Run: 188 DROP, 393 REDACT, rc 0, ~6 s.
- Result tree: 0 files match the home prefix; 0 match the Mac volume prefix; build prefix 0 in docs/, 9 in scripts/strike (the scoped exception above). Placeholders present: `<project>` 212 files, `<volume>` 3, `<build>` 179.
- Idempotent: running the script again on the squash output gives dropped=0 redacted=0 and the identical tree.
- FAIL path proven: a copy of the script with the build pass disabled exits 1 with `FAIL: build path still present`; a copy with the home/volume pass disabled exits 1 with `FAIL: home path still present`.
- Portability: bash 3.2 constructs only (indexed array, no mapfile/associative arrays), `sed` script uses `s###g` with no GNU extensions; `set -euo pipefail` and the blob-to-file SIGPIPE guard are unchanged. Not run on macOS from here.

## Decisions for the coordinator

1. The 9 scripts/strike files keep the build prefix (recommended: leave).
2. (Resolved, see Addendum.) The 9 scripts/strike files stay as they are, per the coordinator.

## Addendum: Windows user directory (coordinator decision 2)

Docs-only redaction with its own FAIL check (`FAIL: windows user path still present`, scope docs/), replacement `~`.

- Spellings found in docs/ (pre-squash): WSL mount form 11 hits in 11 files; single-backslash form 8 hits in 5 files; forward-slash form 0; doubled-backslash form 0 (neither is handled because neither occurs). 0 hits outside docs/.
- What follows the name in every hit: a path separator (11 times `/`, 8 times a backslash). So the pattern is the narrowest: the name must be followed by the separator of its own form, captured and kept (`\(/\)` style BRE group, no GNU/BSD-specific syntax). A name that only starts with the same letters (the Mac home name, or any longer name) is not matched, and fixtures with other names (`a`, `me`, `Alice`, ...) are untouched.
- Examples after redaction: `~/p49-tip...`, `~\p05c-src`, `~\p17f1-wincheck`.
- Backslashes: the literal is built from pieces with a single backslash variable; the sed copy has each backslash doubled. Proven by test (the backslash-form files come out as `~\...`).
- Fresh throwaway clone, full run: 188 dropped, 398 redacted, rc 0. Result tree: 0 matches for the home, volume, build (docs/) and both Windows spellings (docs/); the build prefix remains in the 9 scripts/strike files by decision 1. 0 non-docs files differ from the candidate tree. Second run on the squash output: dropped=0 redacted=0, identical tree. A copy with the Windows pass disabled exits 1 with `FAIL: windows user path still present`. The three earlier FAIL checks are unchanged.

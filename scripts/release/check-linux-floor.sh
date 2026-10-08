#!/usr/bin/env bash
# Release floor check for the Linux binaries (P199 + P202).
# Thin wrapper: the check is scripts/release/check_linux_floor.py, a direct ELF parser
# (no readelf/objdump/awk text parsing). Same arguments as before, plus
# --allow-no-version-requirements. Exit 0 pass, 1 floor violated, 2 could not inspect.
#   check-linux-floor.sh [--max-glibc 2.28] [--max-glibcxx 3.4.25] [--max-cxxabi 1.3.11]
#                        [--no-sve auto|yes|no] BINARY
#   check-linux-floor.sh --self-test
# Needs python3 (3.6+, standard library only).
here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
command -v python3 >/dev/null 2>&1 || { echo "check-linux-floor: python3 not found" >&2; exit 2; }
exec python3 "$here/check_linux_floor.py" "$@"

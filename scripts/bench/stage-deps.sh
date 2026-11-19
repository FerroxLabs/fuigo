#!/usr/bin/env bash
# Build the read-only dependency trees the gate tasks grade against (needs network once). Run on the Docker host.
#   HB_ROOT=/root/hardbench scripts/bench/stage-deps.sh <run-image>      (any gate image; its toolchains build the deps)
# Expects $HB_ROOT/deps/<deps_id>/{build.sh,src/}. Writes <deps_id>/out and a .built marker; idempotent.
set -euo pipefail
HB_ROOT=${HB_ROOT:-/root/hardbench}; IMG=${1:?image}
for D in "$HB_ROOT"/deps/*/; do
  [ -f "$D/build.sh" ] || continue
  [ -f "$D/out/.built" ] && { echo "built: $D"; continue; }
  rm -rf "$D/out"; mkdir -p "$D/out"; chown 1000:1000 "$D/out"
  docker run --rm --user 1000:1000 -e HOME=/tmp -v "$D/src:/src:ro" -v "$D/out:/deps" -v "$D/build.sh:/build.sh:ro" \
    --entrypoint bash "$IMG" /build.sh && touch "$D/out/.built" && du -sh "$D/out"
done

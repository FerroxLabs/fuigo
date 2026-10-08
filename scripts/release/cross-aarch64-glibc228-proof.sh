#!/usr/bin/env bash
# PROOF ARTEFACT ONLY (P199/P202). NOT used by release.yml, which builds aarch64 natively.
# Cross-builds fuigo-pager-bin for aarch64-unknown-linux-gnu on an x86_64 host inside ONE
# debian:10 (pinned by digest below; buster, glibc 2.28) container using the distro's aarch64 cross gcc and
# libc6-dev-arm64-cross (glibc 2.28), then runs check-linux-floor.sh on the result.
# Output binary: $CARGO_TARGET_DIR/aarch64-unknown-linux-gnu/release/fuigo-pager
# Env: CARGO_TARGET_DIR (required), CARGO_CACHE_HOST, EXTRA_CARGO_ARGS, CONTAINER_NAME,
set -euo pipefail
inner() {
  set -euo pipefail
  cd /work
  printf '%s\n' "deb http://archive.debian.org/debian buster main" \
    "deb http://archive.debian.org/debian buster-updates main" \
    "deb http://archive.debian.org/debian-security buster/updates main" > /etc/apt/sources.list
  rm -f /etc/apt/sources.list.d/*.list
  apt-get -o Acquire::Check-Valid-Until=false update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    ca-certificates curl unzip python3 build-essential cmake git perl pkg-config \
    gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross binutils-aarch64-linux-gnu >/dev/null
  ldd --version | sed -n 1p
  aarch64-linux-gnu-gcc --version | sed -n 1p
  channel=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml | head -1)
  # Same rustup pin as build-linux-glibc228.sh (release 1.28.2, committed sha256).
  curl -fsSL -o /tmp/rustup-init https://static.rust-lang.org/rustup/archive/1.28.2/x86_64-unknown-linux-gnu/rustup-init
  echo "20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c  /tmp/rustup-init" | sha256sum -c -
  chmod +x /tmp/rustup-init
  /tmp/rustup-init -y --profile minimal --default-toolchain "$channel" --no-modify-path
  export PATH=/root/.cargo/bin:$PATH
  rustup target add aarch64-unknown-linux-gnu
  curl -fsSL -o /tmp/protoc.zip https://github.com/protocolbuffers/protobuf/releases/download/v29.3/protoc-29.3-linux-x86_64.zip
  echo "3e866620c5be27664f3d2fa2d656b5f3e09b5152b42f1bedbf427b333e90021a  /tmp/protoc.zip" | sha256sum -c -
  mkdir -p /tmp/protoc && unzip -q /tmp/protoc.zip -d /tmp/protoc
  export PROTOC=/tmp/protoc/bin/protoc
  git config --global --add safe.directory /work
  export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
  export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++
  export AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar
  FUIGO_VERSION=$(grep -m1 '^version' crates/codegen/fuigo-version/Cargo.toml | cut -d'"' -f2); export FUIGO_VERSION
  rc=0
  # shellcheck disable=SC2086
  cargo build --release --target aarch64-unknown-linux-gnu -p fuigo-pager-bin ${EXTRA_CARGO_ARGS:-} \
    || rc=$?
  chown -R "$HOST_UID:$HOST_GID" "$CARGO_TARGET_DIR" /root/.cargo/registry /root/.cargo/git 2>/dev/null || true
  [ $rc = 0 ] || exit $rc
  # Always write the receipt (a stale floor-check.exit must never survive a failing check).
  rm -f "$CARGO_TARGET_DIR/floor-check.exit" "$CARGO_TARGET_DIR/floor-check.txt"
  fc=0
  /work/scripts/release/check-linux-floor.sh "$CARGO_TARGET_DIR/aarch64-unknown-linux-gnu/release/fuigo-pager" \
    > "$CARGO_TARGET_DIR/floor-check.txt" 2>&1 || fc=$?
  echo "$fc" > "$CARGO_TARGET_DIR/floor-check.exit"
  cat "$CARGO_TARGET_DIR/floor-check.txt"
  exit "$fc"
}
if [ "${1:-}" = "--inner" ]; then inner; exit; fi
repo=$(cd "$(dirname "$0")/../.." && pwd)
: "${CARGO_TARGET_DIR:?set CARGO_TARGET_DIR}"
cache=${CARGO_CACHE_HOST:-$HOME/.cargo}
mkdir -p "$CARGO_TARGET_DIR" "$cache/registry" "$cache/git"
# docker -v needs absolute host paths.
CARGO_TARGET_DIR=$(cd "$CARGO_TARGET_DIR" && pwd); export CARGO_TARGET_DIR
cache=$(cd "$cache" && pwd)
docker run --rm --name "${CONTAINER_NAME:-fuigo-cross-aarch64}" \
  -v "$repo:/work" -v "$CARGO_TARGET_DIR:$CARGO_TARGET_DIR" \
  -v "$cache/registry:/root/.cargo/registry" -v "$cache/git:/root/.cargo/git" \
  -e CARGO_TARGET_DIR -e CARGO_INCREMENTAL=0 -e CARGO_TERM_COLOR -e CARGO_BUILD_JOBS -e RUST_MIN_STACK \
  -e EXTRA_CARGO_ARGS -e RUSTFLAGS -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  debian:10@sha256:58ce6f1271ae1c8a2006ff7d3e54e9874d839f573d8009c20154ad0f2fb0a225 bash /work/scripts/release/cross-aarch64-glibc228-proof.sh --inner

#!/usr/bin/env bash
# Build fuigo-pager-bin for a Linux gnu target inside a glibc-2.28 container (P199).
#
#   build-linux-glibc228.sh <x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu>
#
# Why a container: a binary needs the glibc of the machine that LINKED it, so the
# release runners (ubuntu-24.04, glibc 2.39) produced binaries that need GLIBC_2.39.
# manylinux_2_28 (AlmaLinux 8, glibc 2.28, gcc-toolset-14) is the oldest maintained
# native image for both arches, so the build stays native (no cross toolchain; see the
# header of .github/workflows/release.yml) and only the libc underneath changes.
#
# Run from the repo root on a host of the SAME architecture as the target. The same
# script is what release.yml runs and what the packet proof ran on the build box.
# Env (all optional):
#   CARGO_TARGET_DIR   target dir on the host (default: <repo>/target)
#   CARGO_CACHE_HOST   host dir holding registry/ and git/ (default: $HOME/.cargo)
#   EXTRA_CARGO_ARGS   e.g. "--locked"
#   CONTAINER_NAME     docker container name (default: fuigo-linux-build)
#   CARGO_BUILD_JOBS, RUST_MIN_STACK  passed through
set -euo pipefail

# Pinned by digest: a moving :latest tag would make the release floor drift silently.
# Bump deliberately: docker pull quay.io/pypa/manylinux_2_28_<arch>:latest, read the
# digest from `docker image inspect`, run check-linux-floor.sh on a build, then edit here.
IMG_X86_64='quay.io/pypa/manylinux_2_28_x86_64@sha256:39df0042d5cc900b085aa25a0659368b42a0006c54c474299b785b44c1b4ff82'
IMG_AARCH64='quay.io/pypa/manylinux_2_28_aarch64@sha256:f5f03dedf61b47d69d0742d36047db78adeee3bdb7a9910ff52304750ecf2514'

inner() {
  set -euo pipefail
  target=$1
  cd /work
  ldd --version | sed -n 1p
  # Pinned toolchain from rust-toolchain.toml (rustup would pick it up anyway).
  channel=$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml | head -1)
  case "$(uname -m)" in
    x86_64)  rtriple=x86_64-unknown-linux-gnu ;;
    aarch64) rtriple=aarch64-unknown-linux-gnu ;;
    *) echo "unsupported host $(uname -m)"; exit 1 ;;
  esac
  # rustup-init pinned to a release (archive URL, not the moving /dist/ endpoint) with
  # sha256 values committed here (from the same release's published .sha256 files and an
  # independent sha256sum of the downloaded bytes, 2026-10-07). Bump both together.
  rustup_ver=1.28.2
  case "$rtriple" in
    x86_64-unknown-linux-gnu)  rustup_sha=20a06e644b0d9bd2fbdbfd52d42540bdde820ea7df86e92e533c073da0cdd43c ;;
    aarch64-unknown-linux-gnu) rustup_sha=e3853c5a252fca15252d07cb23a1bdd9377a8c6f3efa01531109281ae47f841c ;;
  esac
  curl -fsSL -o /tmp/rustup-init "https://static.rust-lang.org/rustup/archive/$rustup_ver/$rtriple/rustup-init"
  echo "$rustup_sha  /tmp/rustup-init" | sha256sum -c -
  chmod +x /tmp/rustup-init
  /tmp/rustup-init -y --profile minimal --default-toolchain "$channel" --no-modify-path
  export PATH=/root/.cargo/bin:$PATH
  rustup target add "$target"
  rustc -vV | sed -n '1p;2p;$p'

  command -v cmake >/dev/null || { echo "::error::cmake missing in the build image"; exit 1; }
  cmake --version | sed -n 1p

  # protoc 29.3, same pins as the workflow's host step (bin/protoc's dotslash table).
  case "$(uname -m)" in
    x86_64)  asset=linux-x86_64   sha=3e866620c5be27664f3d2fa2d656b5f3e09b5152b42f1bedbf427b333e90021a ;;
    aarch64) asset=linux-aarch_64 sha=6427349140e01f06e049e707a58709a4f221ae73ab9a0425bc4a00c8d0e1ab32 ;;
  esac
  curl -fsSL -o /tmp/protoc.zip "https://github.com/protocolbuffers/protobuf/releases/download/v29.3/protoc-29.3-$asset.zip"
  echo "$sha  /tmp/protoc.zip" | sha256sum -c -
  mkdir -p /tmp/protoc && unzip -q /tmp/protoc.zip -d /tmp/protoc
  export PROTOC=/tmp/protoc/bin/protoc
  "$PROTOC" --version

  git config --global --add safe.directory /work
  FUIGO_VERSION=$(grep -m1 '^version' crates/codegen/fuigo-version/Cargo.toml | cut -d'"' -f2)
  export FUIGO_VERSION
  rc=0
  # shellcheck disable=SC2086
  cargo build --release --target "$target" -p fuigo-pager-bin ${EXTRA_CARGO_ARGS:-} || rc=$?
  # Hand every file written as root back to the host user.
  chown -R "$HOST_UID:$HOST_GID" "${CARGO_TARGET_DIR:-/work/target}" /root/.cargo/registry /root/.cargo/git 2>/dev/null || true
  exit $rc
}

if [ "${1:-}" = "--inner" ]; then shift; inner "$@"; fi

target=${1:?usage: $0 <x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu>}
case "$target" in
  x86_64-unknown-linux-gnu)  image=$IMG_X86_64;  want=x86_64 ;;
  aarch64-unknown-linux-gnu) image=$IMG_AARCH64; want=aarch64 ;;
  *) echo "unsupported target $target" >&2; exit 1 ;;
esac
[ "$(uname -m)" = "$want" ] || { echo "host is $(uname -m); $target must build natively on $want" >&2; exit 1; }

repo=$(cd "$(dirname "$0")/../.." && pwd)
tdir=${CARGO_TARGET_DIR:-$repo/target}
cache=${CARGO_CACHE_HOST:-$HOME/.cargo}
mkdir -p "$tdir" "$cache/registry" "$cache/git"
# docker -v needs absolute host paths (a relative CARGO_TARGET_DIR would become an invalid mount).
tdir=$(cd "$tdir" && pwd)
cache=$(cd "$cache" && pwd)

docker run --rm --name "${CONTAINER_NAME:-fuigo-linux-build}" \
  -v "$repo:/work" -v "$tdir:$tdir" \
  -v "$cache/registry:/root/.cargo/registry" -v "$cache/git:/root/.cargo/git" \
  -e CARGO_TARGET_DIR="$tdir" -e CARGO_INCREMENTAL=0 -e CARGO_TERM_COLOR \
  -e CARGO_BUILD_JOBS -e RUST_MIN_STACK -e EXTRA_CARGO_ARGS \
  -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  "$image" bash /work/scripts/release/build-linux-glibc228.sh --inner "$target"

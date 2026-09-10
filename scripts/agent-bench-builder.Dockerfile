# Task-owned Linux build environment; does not modify the shared buildbox host.
FROM wayland-core-ci:rust-1.95-slim-bookworm
USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    make cmake protobuf-compiler clang libclang-dev nasm ninja-build meson \
    libssl-dev libdbus-1-dev libudev-dev libasound2-dev
# Rust 1.94 is mounted read-only from the buildbox's existing toolchain.
ENV PATH="/opt/fuigo-rust/bin:${PATH}"
ENV CARGO_HOME=/build/cargo CARGO_TARGET_DIR=/build/target
ENV PROTOC=/usr/bin/protoc CARGO_BUILD_JOBS=4 CARGO_INCREMENTAL=0
WORKDIR /src

#!/usr/bin/env bash
# Type-check/lint the project without requiring bpf-linker.
#
# The eBPF object is *not* linked here; use a Linux build with bpf-linker for
# that. This script is intended for CI lint jobs and non-Linux workstations.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> cargo fmt"
cargo fmt --all -- --check

echo "==> shared ABI tests"
cargo test -p aya-app-common

echo "==> userspace type check (Linux target, embedded object skipped)"
AYA_BUILD_SKIP=1 cargo check -p aya-app --target x86_64-unknown-linux-gnu

echo "==> eBPF type check (all scenario bins, build-std=core, no link)"
RUSTC_BOOTSTRAP=1 cargo +nightly check -p aya-app-ebpf \
    --bins --target bpfel-unknown-none -Z build-std=core

echo "==> demo target"
cargo check -p aya-app-demo

echo "==> clippy (userspace)"
AYA_BUILD_SKIP=1 cargo clippy -p aya-app \
    --target x86_64-unknown-linux-gnu -- -D warnings

echo "all checks passed"

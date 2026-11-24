#!/usr/bin/env bash
# Linux system test entry point.
#
# Default: type checks, unit tests, ABI tests, and all eBPF scenario bins.
# FULL_BUILD=1: also build the release CLI (requires bpf-linker).
# RUN_RUNTIME=1: also run a small XDP smoke test as root (best-effort).
#
# Usage:
#   bash scripts/test-linux.sh
#   FULL_BUILD=1 bash scripts/test-linux.sh
#   sudo -E RUN_RUNTIME=1 FULL_BUILD=1 bash scripts/test-linux.sh
set -euo pipefail

cd "$(dirname "$0")/.."

echo "==> cargo fmt"
cargo fmt --all -- --check

echo "==> shared ABI tests"
cargo test -p aya-app-common

echo "==> userspace unit tests (Linux target, placeholder object)"
AYA_BUILD_SKIP=1 cargo test -p aya-app --target x86_64-unknown-linux-gnu

echo "==> userspace type check (Linux target, placeholder object)"
AYA_BUILD_SKIP=1 cargo check -p aya-app --target x86_64-unknown-linux-gnu

echo "==> userspace clippy"
AYA_BUILD_SKIP=1 cargo clippy -p aya-app \
    --target x86_64-unknown-linux-gnu -- -D warnings

echo "==> all eBPF scenario bins (no final link)"
RUSTC_BOOTSTRAP=1 cargo +nightly check -p aya-app-ebpf \
    --bins --target bpfel-unknown-none -Z build-std=core

echo "==> demo target"
cargo test -p aya-app-demo

if [[ "${FULL_BUILD:-0}" == "1" ]]; then
    if ! command -v bpf-linker >/dev/null 2>&1; then
        echo "FULL_BUILD=1 requires bpf-linker on PATH" >&2
        exit 1
    fi
    echo "==> full release build (11 eBPF objects + CLI)"
    cargo build -p aya-app --release
    ./target/release/aya-app --version
    ./target/release/aya-app --help >/dev/null
fi

if [[ "${RUN_RUNTIME:-0}" == "1" ]]; then
    if [[ "$(id -u)" != "0" ]]; then
        echo "RUN_RUNTIME=1 must run as root (use sudo -E)" >&2
        exit 1
    fi
    if [[ ! -x ./target/release/aya-app ]]; then
        echo "RUN_RUNTIME=1 requires a release binary; set FULL_BUILD=1" >&2
        exit 1
    fi
    echo "==> XDP runtime smoke (lo, generic/SKB)"
    # Best-effort: some kernels/containers do not allow XDP on lo.
    if timeout 5 ./target/release/aya-app xdp \
        --iface lo --mode skb --block-icmp --stats-interval 1; then
        echo "XDP runtime smoke passed"
    else
        echo "XDP runtime smoke skipped/failed (kernel or permissions)" >&2
    fi
fi

echo "Linux system tests passed"

# Changelog

All notable changes to this project are documented here.

## [Unreleased]

### Added

- CLI integration tests for help/version and early argument validation.
- `scripts/install.sh` with SHA-256 verification.
- `deny.toml` for `cargo deny`.
- Non-x86_64 architecture notes.
- Privileged runtime smoke script and self-hosted workflow.

## [0.1.0] - 2026-11-25

### Added

- 11 Linux eBPF scenarios: XDP, TC, kprobe/kretprobe, uprobe/uretprobe,
  tracepoint, socket filter/SOCK_OPS/connect4, LSM, fentry/fexit,
  raw tracepoint, cgroup_skb, cgroup_sysctl.
- Per-scenario eBPF objects built as 11 separate bins in one `aya-build --bins`
  invocation.
- Ring-buffer events, per-CPU statistics, sampling and Ctrl-C lifecycle handling.
- Shared ABI crate with compile-time layout assertions and runtime ABI tests.
- Dynamic tracepoint offset resolution from tracefs.
- Chinese usage guide, design document, troubleshooting guide, scenario docs,
  code reference and Linux test report.
- Linux CI matrix (Ubuntu 22.04/24.04) and local Linux test script.

### Fixed

- In-place ring-buffer reservation for older verifiers (Linux 6.1/6.6).
- cgroup_skb compatibility on 6.6 by avoiding unavailable current-task helpers.
- cgroup attach mode compatibility (`Single` instead of `AllowMultiple`).
- raw tracepoint default syscall number for BusyBox/musl `open`.

### Known limitations

- eBPF runtime is Linux-only; no macOS/Windows runtime support.
- QEMU TCG timings are not production benchmarks.
- `cgroup_skb` event pid/tgid/comm are zero/empty on kernels without the
  required helper allowlist.
- Native/hardware-offloaded XDP, TC hardware offload and privileged runtime CI
  are not covered yet.

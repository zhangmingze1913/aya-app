# Contributing

## Scope

`aya-app` is a Linux eBPF toolkit. Changes should preserve the distinction
between **observation** hooks (kprobe, uprobe, tracepoint, fentry, raw
tracepoint) and **enforcement** hooks (XDP, TC, socket filter, connect4, LSM,
cgroup_skb, cgroup_sysctl).

## Development

```bash
rustup toolchain install stable nightly --component rust-src
rustup component add rustfmt clippy
cargo install bpf-linker
```

Build and check:

```bash
cargo fmt --all -- --check
AYA_BUILD_SKIP=1 cargo check -p aya-app --target x86_64-unknown-linux-gnu
RUSTC_BOOTSTRAP=1 cargo +nightly check -p aya-app-ebpf \
    --bins --target bpfel-unknown-none -Z build-std=core
cargo test -p aya-app-common
cargo clippy -p aya-app --all-targets --target x86_64-unknown-linux-gnu -- -D warnings
```

On Linux:

```bash
bash scripts/test-linux.sh
FULL_BUILD=1 bash scripts/test-linux.sh   # requires bpf-linker
```

## Adding a scenario

1. Add `#[repr(C)]` ABI types and `size_of` assertions in `aya-app-common`.
2. Add `aya-app-ebpf/src/programs/<name>.rs`.
3. Add `aya-app-ebpf/src/bin/<name>.rs` and a `[[bin]]` entry.
4. Add CLI/command/object selection in `aya-app`.
5. Add docs and a Linux verification path.
6. Run the checks above.

## Pull requests

- Keep changes focused; avoid unrelated formatting churn.
- Explain verifier-sensitive changes and include the kernel version used.
- Do not describe observation-only hooks as enforcement.
- Update `CHANGELOG.md` for user-visible changes.

## Security

Do not open a public issue for a suspected privilege-escalation or verifier
bypass. See [SECURITY.md](SECURITY.md).

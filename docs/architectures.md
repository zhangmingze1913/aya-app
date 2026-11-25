# 架构兼容性

## 已验证

| 架构 | 状态 | 说明 |
|---|---|---|
| `x86_64` | ✅ | QEMU/Alpine 6.1/6.6/6.18；eBPF 对象与运行时均已验证 |
| `aarch64` | ⚠️ 仅交叉编译 | `cargo check -p aya-app --target aarch64-unknown-linux-gnu` 通过；未实机运行 |

## aarch64 注意事项

### 1. syscall 号

`raw-tp` 默认使用 x86_64 legacy `open`（2）。aarch64 的 `openat` 通常是 56，
`open` 可能不存在。请显式指定：

```bash
sudo ./aya-app raw-tp --syscall-nr 56
```

具体号以目标内核 `unistd.h`/`ausyscall` 为准，不要照搬 x86_64。

### 2. tracepoint 偏移

tracepoint 字段偏移由 tracefs `format` 动态解析，不依赖构建架构；
但 `prev_state` 等字段宽度、`rwbs` 宽度可能不同，程序已用
`require_min`/`require_one_of` 处理已知差异。

### 3. kprobe/uprobe 符号与 ABI

- 函数名、参数位置由内核版本和架构 ABI 决定；
- `do_sys_openat2` 在非 x86_64 上可能不存在或参数不同；
- 先用 `bpftrace -l 'kprobe:*openat*'` / `nm` 确认符号。

### 4. 构建

```bash
rustup target add aarch64-unknown-linux-musl
cargo build -p aya-app --release --target aarch64-unknown-linux-musl
```

eBPF 目标仍是 `bpfel-unknown-none`；`bpf-linker` 与宿主架构无关。
交叉构建用户态时需要对应的 C 链接器/`rust-lld`。

### 5. 未验证项

- native XDP 网卡驱动路径；
- TC hardware offload；
- BPF LSM 在不同发行版内核的配置；
- 非 4K 页大小内核；
- big-endian 架构（当前代码假定 little-endian packet 表示）。

## 结论

发布资产只提供 `x86_64-unknown-linux-musl`。其他架构请从源码构建，并在目标内核
按 [USAGE.md](../USAGE.md) 与 [scenarios/](scenarios/) 逐项验证，不要假定
x86_64 的 syscall 号/符号名可直接使用。

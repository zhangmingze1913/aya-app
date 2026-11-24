# 开发与验证

本文面向修改/扩展 `aya-app` 的开发者，说明工具链、构建链、类型检查、verifier 调试、实验环境和新增场景的步骤。使用步骤见根目录 `README.md` 和 `docs/scenarios/`。

---

## 1. 工具链

### 1.1 必需

| 组件 | 版本/说明 |
|---|---|
| stable Rust | ≥ 1.98（aya 0.16 的 MSRV） |
| nightly Rust | 用于 `-Z build-std=core` |
| `rust-src` | nightly 组件，提供 BPF 目标的 `core` 源码 |
| `bpf-linker` | 链接 BPF 目标文件并生成 BTF |
| LLVM | `bpf-linker` 依赖；按 bpf-linker 文档安装 |
| Linux 内核头/工具 | `libelf-dev`、`pkg-config`、`bpftool`、`tc` |
| LSM（可选） | `CONFIG_BPF_LSM=y`、BTF、启动参数 `lsm=...bpf` |

Ubuntu/Debian：

```bash
sudo apt update
sudo apt install -y build-essential clang llvm libelf-dev pkg-config \
    linux-tools-common linux-tools-generic iproute2 trace-cmd

rustup toolchain install stable nightly --component rust-src
rustup component add rustfmt clippy
cargo install bpf-linker
```

确认：

```bash
rustc --version
cargo +nightly --version
bpf-linker --version
ls /sys/kernel/btf/vmlinux
```

### 1.2 为什么需要 nightly

`bpfel-unknown-none` 是 tier 3 目标，没有预编译的 `core`。`aya-build` 使用：

```text
cargo +nightly build ... --target bpfel-unknown-none -Z build-std=core
```

stable 只用于用户态和日常 `cargo check`。

---

## 2. 构建

```bash
# 开发构建（仍会编译 release eBPF 对象）
cargo build

# 发布构建
cargo build --release

# 只构建 demo 目标
cargo build --release -p aya-app-demo
```

`aya-app/build.rs` 会：

1. 检查 `bpf-linker`；
2. 定位 `../aya-app-ebpf`；
3. 调用一次 `aya_build::build_ebpf`，用 `--bins` 编译 11 个场景 bin；
4. 把每个 `OUT_DIR/<scenario>` 复制为 `OUT_DIR/aya-app-<scenario>`；
5. 用户态编译时按命令用 `include_bytes_aligned!` 嵌入对应对象。

### 2.1 跳过 eBPF 构建

```bash
AYA_BUILD_SKIP=1 cargo check -p aya-app --target x86_64-unknown-linux-gnu
```

或：

```bash
AYA_APP_SKIP_EBPF_BUILD=1 cargo check ...
```

`build.rs` 会写一个占位对象。此模式只用于编辑器/CI 类型检查；生成的二进制运行时会报“加载 eBPF 对象失败”。

### 2.2 交叉类型检查（本仓库开发环境）

```bash
# 用户态（Linux ABI，但不需要 Linux 链接器）
AYA_BUILD_SKIP=1 cargo check -p aya-app --target x86_64-unknown-linux-gnu

# eBPF（不链接，不需要 bpf-linker）
RUSTC_BOOTSTRAP=1 cargo +nightly check -p aya-app-ebpf \
    --target bpfel-unknown-none -Z build-std=core

# demo（宿主平台）
cargo check -p aya-app-demo

# 格式/风格
cargo fmt --all -- --check
AYA_BUILD_SKIP=1 cargo clippy -p aya-app --target x86_64-unknown-linux-gnu
```

`scripts/check.sh` 执行这些检查。

> `cargo check` 不链接，因此不能替代 verifier 校验；它只能证明 Rust 类型和 API 正确。

---

## 3. verifier 调试

加载失败时：

```bash
RUST_LOG=debug sudo -E ./target/release/aya-app xdp --iface lo --mode skb
```

`aya` 会把 verifier log 打到 `debug`。常见输出：

```text
invalid bpf_context access off=... size=...
R1 type=ctx expected=fp
invalid mem access 'map_value_or_null'
The sequence of 8193 jumps is too complex
```

排查顺序：

1. **上下文访问**：是否直接解引用了未验证的指针？改用 helper。
2. **map 值空指针**：`get_ptr_mut` 返回 `Option`，是否检查？
3. **越界**：包访问是否先做 `data + size <= data_end`？
4. **循环**：是否有编译期上界？动态 map 值是否 `min` 到常量？
5. **栈**：局部结构是否超过 512 字节？
6. **helper 可用性**：程序类型是否支持该 helper？
7. **对齐**：ring buffer 事件最大对齐是否 ≤8？

查看程序/map：

```bash
sudo bpftool prog show
sudo bpftool map show
sudo bpftool prog dump xlated name xdp_firewall
sudo bpftool prog dump jited name xdp_firewall
```

单独加载对象（绕过 CLI）：

```bash
sudo bpftool prog load target/bpfel-unknown-none/release/aya-app /sys/fs/bpf/aya_test
```

> 该路径取决于 `aya-build` 的 target-dir；也可以在 `OUT_DIR/aya-build/target/...` 下找。

---

## 4. 实验环境

### 4.1 netns + veth

```bash
sudo ip netns add aya-lab
sudo ip link add veth-host type veth peer name veth-lab
sudo ip link set veth-lab netns aya-lab
sudo ip addr add 10.20.0.1/24 dev veth-host
sudo ip link set veth-host up
sudo ip netns exec aya-lab ip addr add 10.20.0.2/24 dev veth-lab
sudo ip netns exec aya-lab ip link set veth-lab up
sudo ip netns exec aya-lab ip link set lo up
```

清理：

```bash
sudo ip netns del aya-lab
sudo ip link del veth-host 2>/dev/null || true
```

### 4.2 cgroup v2

```bash
mount | grep cgroup2
cat /sys/fs/cgroup/cgroup.controllers
sudo mkdir -p /sys/fs/cgroup/aya-demo
```

把测试进程放入：

```bash
sudo sh -c 'echo $$ > /sys/fs/cgroup/aya-demo/cgroup.procs; exec bash'
```

移出：

```bash
echo $$ | sudo tee /sys/fs/cgroup/cgroup.procs
```

### 4.3 tracefs

```bash
mount | grep tracefs
# 没有则：
sudo mount -t tracefs tracefs /sys/kernel/tracing
# 或
sudo mount -t debugfs debugfs /sys/kernel/debug
```

### 4.4 LSM（可选）

```bash
grep CONFIG_BPF_LSM /boot/config-$(uname -r)
cat /sys/kernel/security/lsm     # 必须包含 bpf
test -e /sys/kernel/btf/vmlinux && echo "BTF ok"
```

如果 `lsm` 列表没有 `bpf`，修改 GRUB 的 `lsm=...` 并重启；仅修改代码无法让 LSM hook 生效。

### 4.5 fentry / raw tracepoint / cgroup 扩展

```bash
# fentry/fexit：需要 BTF + function tracer/trampoline
test -e /sys/kernel/btf/vmlinux && echo BTF
cat /sys/kernel/tracing/available_tracers   # 不能只有 nop

# raw tracepoint：sys_enter 必须存在
test -d /sys/kernel/tracing/events/syscalls/sys_enter && echo raw_tp

# cgroup_skb / cgroup_sysctl
test -f /sys/fs/cgroup/cgroup.controllers && echo cgroup_v2
grep -E 'CONFIG_CGROUP_BPF|CONFIG_CGROUP_SYSCTL' /boot/config-$(uname -r)
```

`cgroup_sysctl` 的返回值语义与常见 0/1 相反：**1 允许、0 拒绝**；修改程序时务必保留。

---

## 5. 新增一个场景

以“cgroup/connect6”为例：

### 5.1 共享 ABI

`aya-app-common/src/lib.rs`：

```rust
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Connect6Config { /* ... */ }

// 编译期断言
const _: () = { assert!(size_of::<Connect6Config>() == ...); };
```

并在 `pod` 模块的 `impl_pod!` 列表中加入。

### 5.2 eBPF 程序

`aya-app-ebpf/src/programs/connect6.rs`：

```rust
#[map(name = "connect6_config")]
static CONFIG: Array<Connect6Config> = Array::with_max_entries(1, 0);

#[cgroup_sock_addr(connect6)]
pub fn connect6_guard(ctx: SockAddrContext) -> i32 {
    // 读 (*ctx.sock_addr).user_ip6 / user_port
    // 返回 1 允许，0 拒绝
}
```

在 `aya-app-ebpf/src/bin/connect6.rs` 新建入口（include `programs/connect6.rs`、`utils`、
`panic`），并在 `aya-app-ebpf/Cargo.toml` 增加 `[[bin]]`。

### 5.3 CLI

`aya-app/src/cli.rs` 增加子命令/参数；`aya-app/src/commands/` 增加 `run`；`main.rs` 分发。

### 5.4 文档与测试

- 在 `docs/scenarios/` 增加案例；
- 更新 `README.md` 的能力矩阵和 map 清单；
- 更新 `docs/design.md` 的程序/map 表；
- 运行 `scripts/check.sh`；
- 在 Linux 上做 verifier + 行为验证。

### 5.5 约束清单

- [ ] 程序名/map 名唯一；
- [ ] 事件结构 `#[repr(C)]`、无隐式 padding、大小 8 的倍数；
- [ ] 所有循环有固定上界；
- [ ] 包访问有边界检查；
- [ ] 用户/内核指针只通过 helper 读取；
- [ ] 配置在 attach 前写入；
- [ ] 失败路径 fail-open（除非明确是拒绝策略）；
- [ ] 文档说明能否拦截。

---

## 6. 代码风格

- `cargo fmt --all`；
- `cargo clippy` 用户态目标无 warning（eBPF 目标暂不做 clippy）；
- 模块顶部写设计意图、权衡和安全性说明；
- `unsafe` 块必须写 `SAFETY` 注释；
- 事件结构字段注释说明单位/字节序；
- 错误信息包含对象名（map/program/symbol/interface）；
- 不在热路径做 `println!`；用户态打印可以。

---

## 7. 性能分析

```bash
# CPU/事件采样
sudo perf top -p $(pgrep -f 'aya-app xdp')
sudo perf record -g -p $(pgrep -f 'aya-app xdp') -- sleep 10
sudo perf report

# bpftool 查看运行时间/指令数（部分内核支持）
sudo bpftool prog show --json | jq '.[] | {name, run_time_ns, run_cnt}'

# 网络
sar -n DEV 1
ethtool -S eth0 | grep -E 'xdp|drop'
tc -s qdisc show dev eth0
```

压测建议：

- XDP：`pktgen`/`trex`/`iperf3 UDP`，逐步提高 PPS，观察 `xdp_stats` 与网卡丢包；
- TC：`iperf3` + `tc -s`，观察 backlog/drops；
- kprobe/uprobe：高频调用（如 `open` 循环）下观察 `perf top` 与事件丢失；
- tracepoint：`stress-ng`/`fio`，观察 `switches`/`issues` 与 ring buffer。

---

## 8. 系统测试与 CI

仓库提供两个入口：

```bash
# Linux：格式、ABI 测试、用户态单测、clippy、全部 eBPF bin 检查
bash scripts/test-linux.sh

# 完整构建（需要 bpf-linker）
FULL_BUILD=1 bash scripts/test-linux.sh

# 可选 XDP 运行时冒烟（root + 支持 XDP 的 lo）
sudo -E RUN_RUNTIME=1 FULL_BUILD=1 bash scripts/test-linux.sh
```

Linux 多版本/多内核矩阵由 `.github/workflows/ci.yml` 执行；eBPF 运行时只在 Linux。
实际内核兼容性/性能结果见 [Linux 实测报告](test-report.md)。

GitHub Actions workflow 位于 `.github/workflows/ci.yml`：

- Linux job 下载静态 `bpf-linker`，执行 `FULL_BUILD=1 scripts/test-linux.sh`；
- 矩阵中的每个版本都安装 stable + nightly（rust-src），并运行共享 ABI 测试。

最小 CI（无 bpf-linker 的快速 lint）：

```bash
cargo fmt --all -- --check
cargo test -p aya-app-common
AYA_BUILD_SKIP=1 cargo check -p aya-app --target x86_64-unknown-linux-gnu
RUSTC_BOOTSTRAP=1 cargo +nightly check -p aya-app-ebpf \
    --bins --target bpfel-unknown-none -Z build-std=core
cargo test -p aya-app-demo
AYA_BUILD_SKIP=1 cargo clippy -p aya-app \
    --target x86_64-unknown-linux-gnu -- -D warnings
```

完整运行时 CI 仍建议特权 runner/自托管 runner，并用 netns 隔离，避免污染宿主网络。

---

## 9. 发布

```bash
cargo build --release
strip target/release/aya-app
```

运行时只需：

```text
aya-app             # 用户态 + 嵌入的 eBPF 对象
```

如果目标机器内核版本差异较大：

- 先在同一内核上构建（推荐）；
- tracepoint offset 是运行时解析的，不依赖构建内核；
- 结构体 ABI 是 UAPI 稳定的，但 BTF/helper 可用性随内核变化；
- 在目标环境执行 `bpftool prog show` 和场景文档中的验证命令。

---

## 10. 参考

- Aya 文档：<https://aya-rs.dev/>
- Linux BPF 文档：`Documentation/bpf/`
- `bpftool` 文档：`man bpftool`
- `tc-bpf(8)`、`tc(8)`
- Linux Socket Filtering：`Documentation/networking/filter.rst`
- `bpf_skb_load_bytes_relative` / `bpf_probe_read_*` helper 文档

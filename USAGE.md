# aya-app 使用说明

`aya-app` 是基于 Rust + [Aya](https://aya-rs.dev/) 的 eBPF 实验工具集，覆盖 11 个场景：

| # | 场景 | 命令 | 能力 |
|---|---|---|---|
| 1 | XDP | `aya-app xdp` | ICMP 过滤、单 IP 限速 |
| 2 | TC | `aya-app tc` | P2P 丢包、视频流 mark |
| 3 | kprobe / kretprobe | `aya-app kprobe` | openat 路径与延迟观测 |
| 4 | uprobe / uretprobe | `aya-app uprobe` | 用户态函数参数与延迟 |
| 5 | tracepoint | `aya-app tracepoint` | sched / block I/O 观测 |
| 6 | socket | `aya-app socket-filter` | SOCK_OPS、SYN 白名单、connect4 白名单 |
| 7 | LSM | `aya-app lsm` | `socket_connect` 端口拦截 |
| 8 | fentry / fexit | `aya-app fentry` | BTF trampoline 跟踪 openat |
| 9 | raw tracepoint | `aya-app raw-tp` | `sys_enter` syscall 过滤 |
| 10 | cgroup_skb | `aya-app cgroup-skb` | cgroup 级 ingress/egress 过滤 |
| 11 | cgroup_sysctl | `aya-app cgroup-sysctl` | 阻止 cgroup 写 sysctl |

> 每个场景有独立 eBPF object；命令只加载自己的对象，只创建自己的 map。
> 详细的原理、字段和排错见 [docs/usage.md](docs/usage.md) 与
> [docs/scenarios/](docs/scenarios/)。

## 1. 环境要求

| 项目 | 要求 |
|---|---|
| 系统 | Linux，推荐 5.15+；ring buffer 最低 5.8 |
| 架构 | x86_64 已测试；其他架构需注意 syscall 号和 tracepoint 布局 |
| Rust | stable ≥ 1.98；eBPF 构建需要 nightly + `rust-src` |
| 链接器 | `bpf-linker`，并确保在 `PATH` |
| 权限 | root，或 `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_PERFMON` |
| 内核 | BTF（`/sys/kernel/btf/vmlinux`）、BPF JIT、tracefs |
| cgroup | cgroup v2（socket/cgroup 场景） |
| LSM | `CONFIG_BPF_LSM=y`，启动参数 `lsm=...bpf` |
| fentry | 函数跟踪/trampoline（`CONFIG_FUNCTION_TRACER` 等） |

检查：

```bash
uname -r
test -e /sys/kernel/btf/vmlinux && echo "BTF ok"
mount | grep -E 'tracefs|cgroup2'
cat /sys/kernel/security/lsm
cat /sys/kernel/tracing/available_tracers
```

## 2. 构建

```bash
# 安装工具链（Ubuntu/Debian 示例）
sudo apt update
sudo apt install -y build-essential clang llvm libelf-dev pkg-config

rustup toolchain install stable nightly --component rust-src
rustup component add rustfmt clippy
cargo install bpf-linker

# 构建 11 个场景 object + CLI
cargo build --release

sudo -E ./target/release/aya-app --help
```

构建脚本一次调用 `aya-build --bins`，编译 `aya-app-ebpf` 的 11 个场景 bin，
生成 `OUT_DIR/aya-app-<scenario>` 并嵌入 CLI。最终仍然只有一个用户态二进制。

### 只做类型检查

```bash
# 用户态：写占位 object，不链接 eBPF
AYA_BUILD_SKIP=1 cargo check -p aya-app --target x86_64-unknown-linux-gnu

# eBPF：检查全部场景，不链接
RUSTC_BOOTSTRAP=1 cargo +nightly check -p aya-app-ebpf \
    --bins --target bpfel-unknown-none -Z build-std=core

# 一键检查
bash scripts/check.sh
```

## 3. 通用约定

- 所有命令建议使用 `sudo -E` 保留环境变量；
- 统计默认每 5 秒打印一次，`--stats-interval` 可调；
- 事件是采样输出，per-CPU 计数是精确值；
- Ctrl-C 会关闭 link/程序，自动 detach；
- cgroup 场景建议使用**专用子 cgroup**，不要直接挂根 cgroup；
- LSM 是全局钩子，先用 `--uid` 缩小范围。

## 4. 场景命令

以下命令在仓库根目录执行，二进制路径为 `./target/release/aya-app`。

### 4.1 XDP

```bash
# lo 上使用 generic XDP 做冒烟
sudo -E ./target/release/aya-app xdp \
    --iface lo --mode skb \
    --block-icmp \
    --protected-ip 127.0.0.1 --protected-prefix-len 32

# 另一个终端
ping -c 5 127.0.0.1
```

预期：`ping` 丢包，统计出现 `drop icmp=...`。限速示例：

```bash
sudo -E ./target/release/aya-app xdp \
    --iface lo --mode skb --rate-limit 20
```

> `xdp_rate` 默认 16384 个源 IP；生产大流量可在
> `aya-app-ebpf/src/programs/xdp.rs` 调整 `XDP_RATE_ENTRIES`。

### 4.2 TC

```bash
sudo -E ./target/release/aya-app tc \
    --iface lo --direction egress \
    --drop-port 6881 --video-port 1935 --video-mark 16

# 另一个终端
nc -l -p 6881
nc 127.0.0.1 6881
```

预期：出现 `[tc-drop]` 和 `drop p2p` 统计。视频流 mark 需要配合
`tc filter ... fw`/`prio` qdisc，详见 [02-tc.md](docs/scenarios/02-tc.md)。

### 4.3 kprobe / kretprobe

```bash
sudo -E ./target/release/aya-app kprobe \
    --symbol do_sys_openat2 \
    --path-prefix /etc/shadow \
    --latency-threshold-us 500

# 另一个终端
cat /etc/shadow >/dev/null
```

预期：`[open] path=/etc/shadow`、`[latency] ...` 以及 `opens/sensitive` 统计。

### 4.4 uprobe / uretprobe

```bash
# 先构建 demo 目标
cargo build --release -p aya-app-demo

sudo -E ./target/release/aya-app uprobe \
    --binary ./target/release/aya-app-demo \
    --symbol demo_handle_request

# 另一个终端
./target/release/aya-app-demo 30
```

预期：`[enter] request_id=... path=...` 和 `[exit] ... ret=0`。

### 4.5 tracepoint

```bash
sudo -E ./target/release/aya-app tracepoint \
    --event all --sched-sample 64 --block-sample 1
```

预期：`[sched] ...`、`[block] ...`，以及 sched/block 统计。tracepoint
字段通过 tracefs `format` 动态解析，不硬编码内核结构体。

### 4.6 socket-filter

```bash
# SOCK_OPS：只观测，不拦截
sudo -E ./target/release/aya-app socket-filter sockops \
    --cgroup /sys/fs/cgroup --watch-port 443

# socket filter：入站 SYN 源 IP 白名单
sudo -E ./target/release/aya-app socket-filter skfilter \
    --listen 127.0.0.1:8080 --allow-ip 127.0.0.1

# cgroup/connect4：出站端口白名单（用专用 cgroup）
sudo -E ./target/release/aya-app socket-filter connect4 \
    --cgroup /sys/fs/cgroup/aya-demo --allow-port 80 --allow-port 443
```

注意：

- `SOCK_OPS` 回调返回值被内核忽略，**不能拦截连接**；
- 入站 SYN 白名单用 `skfilter`；
- 出站白名单用 `connect4`，挂错 cgroup 可能断网。

### 4.7 LSM

```bash
# 只拦截当前 UID 对 8080 的连接
sudo -E ./target/release/aya-app lsm \
    --block-port 8080 --uid "$(id -u)"

# 另一个终端
nc -l 127.0.0.1 8080
nc 127.0.0.1 8080       # Operation not permitted
```

需要 `CONFIG_BPF_LSM=y`、BTF，且 `lsm=` 启动参数包含 `bpf`。
`socket_connect` 是 sleepable hook，程序必须用 `#[lsm(sleepable, ...)]`。

### 4.8 fentry / fexit

```bash
sudo -E ./target/release/aya-app fentry \
    --symbol do_sys_openat2 --latency-threshold-us 0

# 另一个终端
cat /etc/hosts >/dev/null
```

需要 BTF 和函数跟踪/trampoline；精简内核可能只有 `nop` tracer，会 attach 失败。

### 4.9 raw tracepoint

```bash
# 默认 x86_64 open=2（BusyBox/musl cat 使用）
sudo -E ./target/release/aya-app raw-tp

# 现代 glibc 程序通常使用 openat=257
sudo -E ./target/release/aya-app raw-tp --syscall-nr 257

# 另一个终端
cat /etc/hosts >/dev/null
```

aarch64 的 `openat` 是 56。raw tracepoint 不解析 tracefs format。

### 4.10 cgroup_skb

```bash
mkdir -p /sys/fs/cgroup/aya-skb

sudo -E ./target/release/aya-app cgroup-skb \
    --cgroup /sys/fs/cgroup/aya-skb \
    --direction egress --block-port 18080

# 另一个终端
nc -l -p 18080
sh -c 'echo $$ > /sys/fs/cgroup/aya-skb/cgroup.procs; nc 127.0.0.1 18080'
```

预期：`[cgroup-skb drop]` 和 `drop` 统计；策略边界是 cgroup 而不是网卡。

### 4.11 cgroup_sysctl

```bash
mkdir -p /sys/fs/cgroup/aya-sysctl

sudo -E ./target/release/aya-app cgroup-sysctl \
    --cgroup /sys/fs/cgroup/aya-sysctl

# 另一个终端
sh -c 'echo $$ > /sys/fs/cgroup/aya-sysctl/cgroup.procs; sysctl -w net.ipv4.ip_forward=1'
# Operation not permitted
```

只观测：

```bash
sudo -E ./target/release/aya-app cgroup-sysctl \
    --cgroup /sys/fs/cgroup/aya-sysctl --observe
```

返回值语义特殊：**程序返回 1 允许，返回 0 被内核转换为 `-EPERM`**。

## 5. 验证与清理

```bash
# 查看程序/map/link
sudo bpftool prog show
sudo bpftool map show
sudo bpftool link show

# cgroup 程序
sudo bpftool cgroup tree

# TC 残留
tc qdisc show
tc filter show dev <iface> egress
```

一般 Ctrl-C 即可 detach。异常残留时：

```bash
# XDP
sudo ip link set dev <iface> xdp off

# TC
sudo tc qdisc del dev <iface> clsact

# cgroup
# 关闭 agent 后 link 自动 detach；必要时把进程移回根 cgroup
```

## 6. 常见问题

| 现象 | 处理 |
|---|---|
| `bpf-linker not found` | 安装 `bpf-linker` 并加入 `PATH` |
| `AYA_BUILD_SKIP` 构建的二进制无法加载 | 在 Linux 上 `cargo build --release` |
| `Operation not permitted` | 使用 `sudo -E`；检查 `CAP_BPF`/`CAP_NET_ADMIN` |
| `failed to load ... EINVAL` | 检查 BTF、`CONFIG_BPF_LSM`、hook 名称 |
| fentry `EBUSY` | 检查 `available_tracers` 是否有 function/trampoline |
| LSM 没有事件 | `/sys/kernel/security/lsm` 是否包含 `bpf` |
| cgroup 场景无事件 | 进程是否在目标 cgroup（`/proc/<pid>/cgroup`） |
| raw-tp 匹配数为 0 | syscall 号是否与架构/工具链一致 |
| TC 没有流量 | 检查接口、方向、`tc qdisc` 是否挂载 |

更完整的排错见 [docs/troubleshooting.md](docs/troubleshooting.md)。

## 7. 系统测试

```bash
# Linux：类型检查/单测/ABI/clippy/全部 eBPF bin
bash scripts/test-linux.sh

# Linux：额外完整构建（需要 bpf-linker）
FULL_BUILD=1 bash scripts/test-linux.sh

# Linux：额外 XDP 运行时冒烟（root）
sudo -E RUN_RUNTIME=1 FULL_BUILD=1 bash scripts/test-linux.sh
```

Linux 多版本/多内核矩阵由 `.github/workflows/ci.yml` 执行；eBPF 运行时只在 Linux。

## 8. 文档索引

- [关键代码参考](docs/code-reference.md)
- [全场景详解](docs/usage.md)
- [设计文档](docs/design.md)
- [开发与验证](docs/development.md)
- [排错手册](docs/troubleshooting.md)
- [结构与性能评估](docs/review-structure-performance.md)
- [Linux 实测报告](docs/test-report.md)
- [Aya 缺口分析](docs/aya-gaps.md)
- 场景文档：[01 XDP](docs/scenarios/01-xdp.md)、[02 TC](docs/scenarios/02-tc.md)、[03 kprobe](docs/scenarios/03-kprobe.md)、[04 uprobe](docs/scenarios/04-uprobe.md)、[05 tracepoint](docs/scenarios/05-tracepoint.md)、[06 socket](docs/scenarios/06-socket-filter.md)、[07 LSM](docs/scenarios/07-lsm.md)、[08 fentry](docs/scenarios/08-fentry-fexit.md)、[09 raw-tp](docs/scenarios/09-raw-tracepoint.md)、[10 cgroup_skb](docs/scenarios/10-cgroup-skb.md)、[11 cgroup_sysctl](docs/scenarios/11-cgroup-sysctl.md)

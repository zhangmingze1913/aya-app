# aya-app

基于 [Aya](https://aya-rs.dev/)（Rust eBPF 框架）的十一个场景实验项目：**XDP、TC、kprobe/kretprobe、uprobe/uretprobe、tracepoint、socket filter / SOCK_OPS、LSM、fentry/fexit、raw tracepoint、cgroup_skb、cgroup_sysctl**。

项目不是“能加载就算成功”的玩具：每个场景都包含可配置策略、ring buffer 事件、per-CPU 统计、生命周期管理、中文使用文档和设计说明。代码同时面向两个编译目标：

- `aya-app`：Linux 用户态 CLI，负责加载、配置、附加和读取 eBPF；
- `aya-app-ebpf`：`bpfel-unknown-none` eBPF 程序，由构建脚本交叉编译并嵌入 CLI。

> 已完成两个目标的交叉类型检查，并在 **QEMU + Alpine Linux 6.18** 上完成 eBPF 最终链接、加载、verifier 和运行时测试。完整结果见 [Linux 实测报告](docs/test-report.md)。
>
> **第一次使用请先读 [使用说明](USAGE.md)**：包含环境、构建、11 个场景的命令、预期输出、验证和清理；更深入的原理与字段说明见 [全场景详解](docs/usage.md)。

---

## 1. 全场景总览

| # | 场景 | CLI 命令 | eBPF 程序 | 挂钩点 | 能否拦截 | 详细文档 |
|---|---|---|---|---|---|---|
| 1 | XDP | `aya-app xdp` | `xdp_firewall` | 网卡驱动 / generic XDP | ✅ `XDP_DROP` | [01-xdp.md](docs/scenarios/01-xdp.md) |
| 2 | TC | `aya-app tc` | `tc_qos` | clsact ingress / egress | ✅ `TC_ACT_SHOT` | [02-tc.md](docs/scenarios/02-tc.md) |
| 3 | kprobe | `aya-app kprobe` | `kprobe_openat` / `kretprobe_openat` | 内核函数入口 / 返回 | ❌ 只观测 | [03-kprobe.md](docs/scenarios/03-kprobe.md) |
| 4 | uprobe | `aya-app uprobe` | `uprobe_request` / `uretprobe_request` | 用户态 ELF 符号 | ❌ 只观测 | [04-uprobe.md](docs/scenarios/04-uprobe.md) |
| 5 | tracepoint | `aya-app tracepoint` | `tracepoint_sched_switch` / `tracepoint_block_rq` | 稳定 tracepoint | ❌ 只观测 | [05-tracepoint.md](docs/scenarios/05-tracepoint.md) |
| 6 | socket | `aya-app socket-filter` | `sockops_guard` / `skfilter_guard` / `connect4_guard` | cgroup / socket / cgroup | ✅ 部分子命令 | [06-socket-filter.md](docs/scenarios/06-socket-filter.md) |
| 7 | LSM | `aya-app lsm` | `lsm_socket_connect` | LSM `socket_connect` | ✅ 返回 `-EPERM` | [07-lsm.md](docs/scenarios/07-lsm.md) |
| 8 | fentry/fexit | `aya-app fentry` | `fentry_openat` / `fexit_openat` | BTF trampoline | ❌ 只观测 | [08-fentry-fexit.md](docs/scenarios/08-fentry-fexit.md) |
| 9 | raw tracepoint | `aya-app raw-tp` | `rawtp_sys_enter` | `sys_enter` raw TP | ❌ 只观测 | [09-raw-tracepoint.md](docs/scenarios/09-raw-tracepoint.md) |
| 10 | cgroup_skb | `aya-app cgroup-skb` | `cgskb_ingress` / `cgskb_egress` | cgroup 内 socket | ✅ 返回 1 | [10-cgroup-skb.md](docs/scenarios/10-cgroup-skb.md) |
| 11 | cgroup_sysctl | `aya-app cgroup-sysctl` | `cgsysctl_guard` | cgroup sysctl 读写 | ✅ 拒绝写入 | [11-cgroup-sysctl.md](docs/scenarios/11-cgroup-sysctl.md) |

每个场景的具体策略：

1. **XDP**：丢弃 ICMP echo request；按源 IP 做固定窗口限速；保护指定目的前缀；per-CPU 统计；采样丢弃事件。
2. **TC**：按目的端口丢弃 P2P 流量；给视频端口写 `skb->mark`，配合 `tc filter ... fw` 选择高优先级 qdisc band。
3. **kprobe**：监控 `do_sys_openat2` 的敏感路径访问；用 kretprobe 统计调用延迟和返回值。
4. **uprobe**：剖析自带 demo 程序的 `demo_handle_request(request_id, path)`；捕获参数、路径和返回延迟。
5. **tracepoint**：从 tracefs `format` 文件动态解析字段偏移，观测 `sched_switch` 和 `block_rq_issue`，避免硬编码内核结构体布局。
6. **socket**：
   - `sockops`：连接生命周期遥测，演示 SOCK_OPS 字段与状态回调；
   - `skfilter`：在监听 socket 上对入站 SYN 做源 IP 白名单；
   - `connect4`：在 cgroup 上做出站目的端口白名单。
7. **LSM**：在 `socket_connect` 安全钩子上拒绝指定目的端口；可选按 UID 限制作用域；返回 `-EPERM` 拦截连接。
8. **fentry/fexit**：用 BTF trampoline 跟踪 `do_sys_openat2`，记录入口时间戳并在出口计算延迟，对比 kprobe 的机制差异。
9. **raw tracepoint**：在 `sys_enter` 上按系统调用号过滤，直接读取 `TP_PROTO` 参数，不解析 tracefs format。
10. **cgroup_skb**：在 cgroup 的 ingress/egress 上按目的端口丢包，策略边界是进程组而不是网卡。
11. **cgroup_sysctl**：阻止 cgroup 内进程写 `/proc/sys/*`，读操作放行；返回 1 允许、0 拒绝。

> **重要事实**：`BPF_PROG_TYPE_SOCK_OPS` 的 `*_CB` 回调返回值会被内核忽略，SOCK_OPS **不能**拦截连接。真正的出站白名单由 `cgroup/connect4` 完成；入站 SYN 白名单由经典 socket filter 完成。文档不会把“观测”说成“拦截”。

---

## 2. 项目结构

```text
aya-app/
├── Cargo.toml                 # workspace 与共享依赖
├── USAGE.md                   # 快速使用说明（环境/构建/11 场景命令）
├── aya-app/                   # 用户态 CLI
│   ├── build.rs               # 调 aya-build 一次构建 11 个 bin 并嵌入
│   └── src/
│       ├── main.rs            # 命令分发
│       ├── cli.rs             # clap 定义与默认值
│       ├── ebpf.rs            # Object 选择、加载嵌入对象、memlock、CString
│       ├── event.rs           # AsyncFd<RingBuf> 事件流
│       ├── stats.rs           # per-CPU 统计求和
│       ├── tracefs.rs         # tracepoint format 解析
│       └── commands/          # 十一个场景的用户态生命周期 + 统一 runner
├── aya-app-common/            # 用户态/eBPF 共享 ABI
│   └── src/lib.rs             # #[repr(C)] 事件、配置、统计；Pod 实现
├── aya-app-ebpf/              # eBPF 程序（11 个 [[bin]]，每个场景一个）
│   ├── src/bin/               # 每个场景的入口 + panic handler
│   ├── src/net.rs             # 以太网/IP/TCP/UDP/ICMP 头
│   ├── src/utils.rs           # 采样、字符串读取、emit_event! 宏
│   └── src/programs/          # 十一个场景的 eBPF 程序与 map
├── aya-app-demo/              # uprobe 的目标程序（C ABI、no_mangle）
├── docs/
│   ├── design.md              # 架构与实现设计
│   ├── development.md         # 构建、检查、调试、扩展
│   ├── troubleshooting.md     # 常见错误与排查
│   ├── usage.md               # 十一个场景的统一使用说明
│   ├── aya-gaps.md            # Aya 未封装的场景与后续候选
│   ├── test-report.md         # Linux 实测记录
│   └── scenarios/             # 十一个场景的详细案例
└── scripts/check.sh           # CI 风格的类型检查
```

---

## 3. 环境要求

| 项目 | 要求 |
|---|---|
| 操作系统 | Linux（推荐 5.15+，最低 5.8，因为使用 ring buffer） |
| 架构 | x86_64（其他架构可编译，tracepoint 偏移会运行时适配） |
| Rust | stable ≥ 1.98；eBPF 构建需要 nightly + `rust-src` |
| 链接器 | `bpf-linker`（`cargo install bpf-linker`，需 LLVM） |
| 权限 | root，或 `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_PERFMON`（按内核版本） |
| 内核配置 | `CONFIG_BPF_SYSCALL`、`CONFIG_BPF_JIT`、`CONFIG_BPF_EVENTS`、`CONFIG_DEBUG_INFO_BTF`、`CONFIG_FTRACE`、`CONFIG_KPROBE_EVENTS`、`CONFIG_UPROBE_EVENTS`、tracefs |
| XDP/TC | 网卡驱动支持 XDP/TC；veth/lo 上优先使用 `--mode skb` |
| socket 场景 | cgroup v2（`/sys/fs/cgroup/cgroup.controllers` 存在） |
| LSM 场景 | `CONFIG_BPF_LSM=y`、BTF，且启动参数 `lsm=...bpf`（见 `/sys/kernel/security/lsm`） |
| fentry/fexit | BTF + 函数跟踪/trampoline（`CONFIG_FUNCTION_TRACER`、`CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS`） |
| cgroup_skb / cgroup_sysctl | cgroup v2、`CONFIG_CGROUP_BPF`；sysctl 还需要 `CONFIG_CGROUP_SYSCTL` |

安装工具链（Ubuntu/Debian 示例）：

```bash
sudo apt update
sudo apt install -y build-essential clang llvm libelf-dev pkg-config linux-tools-common

rustup toolchain install stable nightly --component rust-src
rustup component add rustfmt clippy
cargo install bpf-linker
```

检查 tracefs 和 BTF：

```bash
mount | grep -E 'tracefs|debugfs'
ls /sys/kernel/btf/vmlinux
ls /sys/kernel/tracing/events/sched/sched_switch/format

# LSM：确认内核编译了 BPF LSM，且 bpf 已在 lsm= 列表中
grep CONFIG_BPF_LSM /boot/config-$(uname -r)
cat /sys/kernel/security/lsm
```

---

## 4. 构建与运行

```bash
git clone <your-repo> aya-app
cd aya-app

# 构建 CLI；build.rs 自动用 nightly 编译 aya-app-ebpf 并嵌入对象
cargo build --release

# 需要 root 的 BPF 操作
sudo -E ./target/release/aya-app --help
```

`cargo build` 会一次调用 `aya-build --bins` 构建 11 个场景 bin：

```text
cargo +nightly build -p aya-app-ebpf --bins --release \
    --target bpfel-unknown-none -Z build-std=core
```

产物复制为 `OUT_DIR/aya-app-<scenario>`，由 `include_bytes_aligned!` 按命令嵌入。部署时仍然是
一个用户态二进制，但运行时只加载当前场景的对象，只创建该场景的 map。

### 4.1 只做类型检查（无 bpf-linker / 非 Linux）

```bash
# 生成占位对象，检查用户态代码；生成的二进制不能真正加载
AYA_BUILD_SKIP=1 cargo check -p aya-app --target x86_64-unknown-linux-gnu

# 检查全部 eBPF 场景代码（不链接，不需要 bpf-linker）
RUSTC_BOOTSTRAP=1 cargo +nightly check -p aya-app-ebpf \
    --bins --target bpfel-unknown-none -Z build-std=core
```

`scripts/check.sh` 封装了上述检查。

### 4.2 运行位置

`ebpf::load(Object::X)` 只加载对应场景的 eBPF 对象；map 创建、program 解析和 verifier 都只针对
该场景。`xdp` 命令不会再创建 LSM/ring buffer/HashMap 等其他场景的 map。

---

## 5. 快速体验

以下命令假设在仓库根目录，使用 `sudo -E` 保留 `RUST_LOG` 等环境变量。接口名请按实际环境替换。

### 5.1 XDP：丢弃 ICMP + 单 IP 限速

```bash
# 在 lo 上使用 generic XDP（最兼容）
sudo -E ./target/release/aya-app xdp \
    --iface lo --mode skb \
    --block-icmp \
    --rate-limit 20 \
    --protected-ip 127.0.0.1 --protected-prefix-len 32

# 另一个终端
ping -c 5 127.0.0.1
ping -f -c 200 127.0.0.1
```

预期：ICMP echo request 被丢弃；超过 20 pkt/s 的包被限速；终端周期打印 `pass/drop` 统计，并采样打印 `[drop] ... reason=icmp|rate`。

> 在真实网卡上把 `--iface` 换成 `eth0`，先尝试默认模式；失败再 `--mode skb`。驱动模式需要网卡支持。`lo` 上的 XDP 路径受内核版本影响，只建议做冒烟；稳定的 XDP 实验环境见 [01-xdp.md](docs/scenarios/01-xdp.md) 的 veth 小节。

### 5.2 TC：P2P 丢包 + 视频优先级

```bash
sudo -E ./target/release/aya-app tc \
    --iface lo --direction egress \
    --drop-port 6881 --drop-port 6882 \
    --video-port 1935 --video-mark 16

# 另一个终端：6881 的连接会卡住/失败；1935 的包会被打 mark
nc -l 127.0.0.1 6881 &
nc 127.0.0.1 6881
```

按命令输出安装 `prio` qdisc 与 `fw` 规则后，`skb->mark=16` 的包会进入 `1:1` 高优先级 band。验证：

```bash
tc -s qdisc show dev lo
tc filter show dev lo egress
```

### 5.3 kprobe：敏感路径 + openat 延迟

```bash
grep -w do_sys_openat2 /proc/kallsyms

sudo -E ./target/release/aya-app kprobe \
    --symbol do_sys_openat2 \
    --path-prefix /etc/shadow \
    --path-prefix /etc/passwd \
    --latency-threshold-us 500

# 另一个终端
cat /etc/shadow >/dev/null
```

预期输出：

```text
[open]    t=... pid=... tid=... comm=cat uid=1000 path=/etc/shadow
[latency] t=... pid=... tid=... comm=cat 1.23ms     ret=-13
```

### 5.4 uprobe：用户态函数剖析

```bash
cargo build --release -p aya-app-demo

# 先启动目标（或先 attach 再启动；默认 scope 是所有进程）
./target/release/aya-app-demo 200 &

sudo -E ./target/release/aya-app uprobe \
    --binary ./target/release/aya-app-demo \
    --symbol demo_handle_request
```

预期：每个请求打印 `[enter] request_id=... path=/api/v1/orders/...`，返回时打印 `[exit] ... 3.42ms`。

### 5.5 tracepoint：调度与块 I/O

```bash
sudo -E ./target/release/aya-app tracepoint --event all --sched-sample 64

# 另一个终端制造负载
dd if=/dev/zero of=/tmp/aya-test.bin bs=1M count=64 oflag=direct
stress-ng --cpu 2 --timeout 10s
rm -f /tmp/aya-test.bin
```

预期：`[sched]` 采样输出任务切换；`[block]` 输出块请求；统计中 `switches`/`issues` 为精确值，事件数为采样值。

### 5.6 socket：SOCK_OPS / socket filter / connect4

**SOCK_OPS 遥测**（不拦截）：

```bash
sudo -E ./target/release/aya-app socket-filter sockops \
    --cgroup /sys/fs/cgroup --watch-port 443

# 另一个终端
curl -s https://example.com >/dev/null
```

**入站 SYN 白名单**：

```bash
sudo -E ./target/release/aya-app socket-filter skfilter \
    --listen 127.0.0.1:8080 --allow-ip 127.0.0.1

# 另一个终端：可以完成三次握手（随后被关闭）
curl -v --max-time 2 http://127.0.0.1:8080/
```

**出站端口白名单**（先创建专用 cgroup，避免影响整机）：

```bash
sudo mkdir -p /sys/fs/cgroup/aya-demo
# 把测试 shell 放进该 cgroup（不要把 agent 自己放进去）
sudo sh -c 'echo $$ > /sys/fs/cgroup/aya-demo/cgroup.procs; exec bash'

# 在 agent 终端（仍在根 cgroup）附加策略：只允许 80/443
sudo -E ./target/release/aya-app socket-filter connect4 \
    --cgroup /sys/fs/cgroup/aya-demo \
    --allow-port 80 --allow-port 443

# 在测试 shell 中
curl -s --max-time 3 http://1.1.1.1 >/dev/null       # 允许
curl -s --max-time 3 https://1.1.1.1 >/dev/null      # 允许
curl -s --max-time 3 http://1.1.1.1:8080/ >/dev/null # 立即失败（EPERM）
```

> `connect4` 只匹配 IPv4；DNS(53) 不在白名单时，按域名访问会先失败，请用 IP 测试或把 53 加入白名单。

### 5.7 LSM：全局 socket_connect 端口拦截

```bash
# 只拦截当前 UID 对 8080 的连接（先缩小作用域）
sudo -E ./target/release/aya-app lsm \
    --block-port 8080 \
    --uid "$(id -u)"

# 另一个终端：监听 8080，然后连接
nc -l 127.0.0.1 8080
nc 127.0.0.1 8080       # 返回 Operation not permitted
```

预期：

```text
[lsm-deny] t=... pid=... uid=1000 comm=nc dst=127.0.0.1:8080
--- LSM stats ---
connects :            3  (       0.6/s)
allowed  :            1    denied:            2 (0.4 deny/s)
```

> LSM 是**全局**安全钩子，不绑定 cgroup。共享主机上务必用 `--uid` 限制，或改用 `cgroup/connect4`；不要随手在生产机上 `--block-port`。需要 `CONFIG_BPF_LSM=y`、BTF，且 `lsm=` 启动参数包含 `bpf`。

### 5.8 fentry/fexit：BTF trampoline 跟踪 openat

```bash
sudo -E ./target/release/aya-app fentry \
    --symbol do_sys_openat2 \
    --latency-threshold-us 0

# 另一个终端
cat /etc/hosts >/dev/null
```

预期看到 `[fexit] ... ret=3` 和 `enters/exits/slow` 统计。需要 BTF 和函数跟踪支持；
精简内核可能只有 `nop` tracer，此时会 attach 失败。

### 5.9 raw tracepoint：过滤 sys_enter

```bash
sudo -E ./target/release/aya-app raw-tp

# 另一个终端
cat /etc/hosts >/dev/null
```

预期看到 `[sys_enter] ... nr=2`。x86_64 的 `openat` 是 257，aarch64 的 `openat` 是 56。

### 5.10 cgroup_skb：按 cgroup 丢弃端口

```bash
mkdir -p /sys/fs/cgroup/aya-skb
sudo -E ./target/release/aya-app cgroup-skb \
    --cgroup /sys/fs/cgroup/aya-skb \
    --direction egress --block-port 18080

# 另一个终端：把客户端放入该 cgroup
nc -l -p 18080
sh -c 'echo $$ > /sys/fs/cgroup/aya-skb/cgroup.procs; nc 127.0.0.1 18080'
```

预期 `drop p2p` 类似的 `[cgroup-skb drop]` 事件和 `drop` 统计。

### 5.11 cgroup_sysctl：阻止 cgroup 写 sysctl

```bash
mkdir -p /sys/fs/cgroup/aya-sysctl
sudo -E ./target/release/aya-app cgroup-sysctl \
    --cgroup /sys/fs/cgroup/aya-sysctl

# 另一个终端
sh -c 'echo $$ > /sys/fs/cgroup/aya-sysctl/cgroup.procs; sysctl -w net.ipv4.ip_forward=1'
# 预期：Operation not permitted
```

> cgroup_sysctl 的返回值语义与常见“0 允许”不同：程序返回 **1 允许**，返回 0 被内核转换为
> `-EPERM`。详见 [11-cgroup-sysctl.md](docs/scenarios/11-cgroup-sysctl.md)。

---

## 6. CLI 速查

```text
aya-app xdp
  --iface <IFACE>                 默认 lo
  --mode default|skb|driver|hw    默认 default
  --block-icmp
  --rate-limit <PPS>              0 = 关闭
  --protected-ip <ADDR>
  --protected-prefix-len <LEN>    默认 32
  --event-sample <N>              默认 64
  --stats-interval <SECS>         默认 5

aya-app tc
  --iface <IFACE>                 默认 lo
  --direction ingress|egress      默认 egress
  --drop-port <PORT>...           默认 6881,6882,6883
  --video-port <PORT>...          默认 1935,8080
  --video-mark <MARK>             默认 16
  --event-sample <N>              默认 64

aya-app kprobe
  --symbol <FUNC>                 默认 do_sys_openat2
  --path-prefix <PREFIX>...       默认 /etc/shadow,/etc/passwd
  --latency-threshold-us <US>     默认 1000

aya-app uprobe
  --binary <PATH>                 必填
  --symbol <SYMBOL>               默认 demo_handle_request
  --pid <PID>                     可选，默认所有进程
  --latency-threshold-us <US>     默认 1000

aya-app tracepoint
  --event all|sched|block         默认 all
  --sched-sample <N>              默认 64
  --block-sample <N>              默认 1

aya-app socket-filter sockops
  --cgroup <PATH>                 默认 /sys/fs/cgroup
  --watch-port <PORT>...
  --attach-mode single|multi

aya-app socket-filter skfilter
  --listen <ADDR>                 默认 127.0.0.1:8080
  --allow-ip <ADDR>...

aya-app socket-filter connect4
  --cgroup <PATH>                 必填
  --allow-port <PORT>...          至少一个
  --attach-mode single|multi

aya-app lsm
  --block-port <PORT>...          必填，至少一个
  --uid <UID>                     可选，默认整机
  --event-sample <N>              默认 16
  --stats-interval <SECS>         默认 5

aya-app fentry
  --symbol <FUNC>                 默认 do_sys_openat2
  --latency-threshold-us <US>     默认 0
  --event-sample <N>              默认 1

aya-app raw-tp
  --syscall-nr <NR>               默认 2（x86_64 open；openat=257）
  --event-sample <N>              默认 1

aya-app cgroup-skb
  --cgroup <PATH>                 必填
  --direction ingress|egress      默认 egress
  --block-port <PORT>             默认 8080，0 = 只观测
  --event-sample <N>              默认 64

aya-app cgroup-sysctl
  --cgroup <PATH>                 必填
  --observe                       只观测，不拒绝
  --event-sample <N>              默认 16
```

所有命令都支持 `--help`。统计间隔统一为 `--stats-interval`（秒）。

---

## 7. 实现要点

- **共享 ABI**：所有事件/配置/统计都在 `aya-app-common` 中以 `#[repr(C)]` 定义，并有编译期 `size_of` 断言，避免用户态与 eBPF 结构体漂移。
- **字节序**：端口在事件中统一为主机序；IPv4 地址保留“网络序整数的原始表示”，用户态用 `to_ne_bytes()`/`from_ne_bytes()` 转换。原因见 `aya-app-common/src/lib.rs` 顶部注释。
- **per-CPU 统计**：热路径不做原子操作；用户态每秒求和。XDP/TC 的统计是精确值，事件是采样值。
- **Ring buffer**：256 KiB，`AsyncFd` 驱动，Tokio `select!` 与 Ctrl-C/统计定时器并行。
- **配置 map**：单元素 `Array`，attach 前由用户态写入；eBPF 侧只读。
- **动态 tracepoint 偏移**：解析 `/sys/kernel/tracing/events/<cat>/<name>/format`，把字段 `offset/size` 写入 map；避免硬编码内核结构体。
- **LSM BTF 参数**：`LsmContext::arg(n)` 读取 BTF 参数；`socket_connect` 的 arg 1 是内核 `sockaddr`，arg 3 是前一个 LSM 的返回值；命中黑名单返回 `-EPERM`。`socket_connect` 是 sleepable hook，程序使用 `#[lsm(sleepable, ...)]`。
- **fentry/fexit**：用 `#[fentry(function = "...")]` / `#[fexit(function = "...")]` 生成 BTF trampoline section；入口 map 记录时间戳，出口用 `bpf_get_func_ret` 读取返回值。
- **raw tracepoint**：`#[raw_tracepoint(tracepoint = "sys_enter")]`，`arg(1)` 是 syscall 号；不经过 tracefs format。
- **cgroup_skb**：`cgroup_skb/ingress|egress` 程序直接解析 `__sk_buff` 的 IPv4 头（无 Ethernet 头），命中端口返回 1。
- **cgroup_sysctl**：读取 `bpf_sysctl.write`；返回 1 允许，返回 0 由内核转成 `-EPERM`。
- **共享状态**：kprobe/uprobe/fentry 共用一个 `probe_start` HashMap（每个对象内只保留一份），减少重复 map；采样率是 2 的幂时用位掩码代替取模。
- **统一 runner**：`commands/runner.rs` 统一事件读取、统计定时器、Ctrl-C 和 detach；各命令只保留配置、attach 和打印差异。
- **安全默认值**：XDP 默认 `lo` + generic；`connect4` 拒绝空白名单；SOCK_OPS 明确标注“不拦截”；LSM 要求显式 `--block-port`，并支持 `--uid` 缩小作用域；cgroup 场景要求显式 `--cgroup`。

---

## 8. 验证状态与限制

### 8.1 系统测试入口

| 系统 | 命令 | 内容 |
|---|---|---|
| Linux | `bash scripts/test-linux.sh` | fmt、ABI 测试、用户态单测、clippy、全部 eBPF feature 检查 |
| Linux（完整构建） | `FULL_BUILD=1 bash scripts/test-linux.sh` | 额外构建 11 个 eBPF object + CLI |
| Linux（运行时冒烟） | `sudo -E RUN_RUNTIME=1 FULL_BUILD=1 bash scripts/test-linux.sh` | 额外在 `lo` 上跑 XDP 冒烟 |
| CI | `.github/workflows/ci.yml` | Linux 多版本/多内核矩阵 |

`aya-app-common` 的 ABI 测试在 Linux 上运行；eBPF 运行时只在 Linux。

已执行：

```text
Alpine 3.24 / Linux 6.18：11 场景（含 LSM）
Alpine 3.20 / Linux 6.6 ：核心场景 + cgroup（LSM 内核未启用）
Alpine 3.18 / Linux 6.1 ：核心 tracing 场景（LSM 内核未启用）

cargo fmt --all -- --check                                      ✅
cargo test -p aya-app-common                                    ✅
AYA_BUILD_SKIP=1 cargo check -p aya-app \
    --target x86_64-unknown-linux-gnu                           ✅
cargo +nightly check -p aya-app-ebpf \
    --bins --target bpfel-unknown-none -Z build-std=core ✅
cargo check -p aya-app-demo --release                           ✅
cargo clippy -p aya-app \
    --target x86_64-unknown-linux-gnu -- -D warnings            ✅
```

并在 **QEMU + Alpine Linux 3.24（内核 6.18.35）** 上做了实际运行测试：

- eBPF 对象用 `bpf-linker 0.13.0` 完成最终链接；
- 生成静态 musl 用户态二进制并在 Linux 中运行；
- XDP（lo / SKB 模式）、TC（lo / egress）、kprobe、uprobe、tracepoint（sched + block）、socket filter、SOCK_OPS、cgroup/connect4 均已实际触发并看到事件/统计；
- LSM 在 Alpine **linux-lts** 内核上完成 attach，并成功拒绝对黑名单端口的 `connect()`；Alpine `linux-virt` 内核缺少 `CONFIG_FUNCTION_TRACER`，BPF LSM attach 返回 `EBUSY`，属于内核能力限制，不是程序错误；
- fentry/fexit、raw tracepoint、cgroup_skb、cgroup_sysctl 在 **linux-lts** 上完成 attach 和触发验证（见测试报告）。

完整命令、输出和问题记录见 **[Linux 实测报告](docs/test-report.md)**。

未覆盖：

- 物理网卡上的 native XDP / TC offload；
- 生产发行版内核、真实容器/多租户 cgroup 层级；
- 高并发/长时间稳定性与性能基准。

已知边界：

- 仅支持 IPv4（socket/TC/XDP 的 L3 解析）；IPv6 默认放行。
- XDP 限速是固定窗口而非严格令牌桶，窗口边界最坏可到 2 倍配置值。
- kprobe 的路径读取假设 `--symbol` 的第二个参数是 `const char __user *`；换符号需自行调整。
- tracepoint 字段缺失或大小不匹配会拒绝启动；`rwbs` 已兼容新内核的 10 字节布局（只读取前 8 字节）。
- socket filter 的源 IP 是 NAT 后的地址；容器场景需按实际源地址配置。
- LSM 场景只解析 IPv4 `sockaddr_in`；IPv6 放行。`socket_connect` 是 sleepable hook，程序必须用 `#[lsm(sleepable, ...)]`。LSM 是全局钩子，生产环境应优先用 `--uid` 或 cgroup 方案。
- fentry/fexit 需要 BTF + 函数跟踪/trampoline；嵌套调用会覆盖同一线程的起始时间，`missing_starts` 会增长。
- raw tracepoint 的 syscall 号与架构/工具链相关；默认 `open`=2，x86_64 `openat`=257，aarch64 `openat`=56。
- `cgroup_sysctl` 只能按 cgroup 拒绝所有写，不能按 sysctl 名称过滤；返回值 1 允许、0 拒绝。
- 当前 eBPF 事件结构使用固定上限（路径 128 字节、comm 16 字节、最多 8 个端口/4 个前缀）。

---

## 9. 文档索引

| 文档 | 内容 |
|---|---|
| [使用说明](USAGE.md) | **快速上手**：环境、构建、11 场景命令、验证、清理、常见问题 |
| [关键代码参考](docs/code-reference.md) | 用户态/eBPF 关键函数、方法、调用链与扩展步骤 |
| [GitHub 发布就绪评估](docs/release-readiness.md) | LICENSE、仓库元数据、CI、Release 检查清单 |
| [全场景使用说明](docs/usage.md) | **统一操作手册**：环境、十一个场景的逐项命令、预期输出、验证与清理 |
| [设计文档](docs/design.md) | 架构、map/program 清单、数据流、构建链、并发与性能、扩展方式 |
| [开发与验证](docs/development.md) | 工具链、构建、类型检查、verifier 调试、添加新场景、CI |
| [排错手册](docs/troubleshooting.md) | 权限、BTF、XDP/TC、kprobe/uprobe、tracefs、ring buffer、cgroup |
| [XDP 案例](docs/scenarios/01-xdp.md) | ICMP 防护、单 IP 限速、模式选择、veth 实验 |
| [TC 案例](docs/scenarios/02-tc.md) | clsact、P2P 丢包、mark + prio qdisc、QoS 验证 |
| [kprobe 案例](docs/scenarios/03-kprobe.md) | openat 路径监控、延迟统计、符号与参数约定 |
| [uprobe 案例](docs/scenarios/04-uprobe.md) | ELF 符号、demo 目标、MySQL/Redis/gRPC 实际案例 |
| [tracepoint 案例](docs/scenarios/05-tracepoint.md) | tracefs format、动态偏移、调度/块 I/O 观测 |
| [socket 案例](docs/scenarios/06-socket-filter.md) | SOCK_OPS 语义、socket filter 入站白名单、connect4 出站白名单 |
| [LSM 案例](docs/scenarios/07-lsm.md) | LSM `socket_connect`、全局端口拦截、UID 限制、BPF LSM 启用条件 |
| [fentry/fexit 案例](docs/scenarios/08-fentry-fexit.md) | BTF trampoline、openat 延迟、与 kprobe 对比 |
| [raw tracepoint 案例](docs/scenarios/09-raw-tracepoint.md) | `sys_enter`、syscall 过滤、与普通 tracepoint 对比 |
| [cgroup_skb 案例](docs/scenarios/10-cgroup-skb.md) | cgroup 级 ingress/egress 端口过滤 |
| [cgroup_sysctl 案例](docs/scenarios/11-cgroup-sysctl.md) | 阻止 cgroup 写 sysctl、返回值语义 |
| [Aya 缺口分析](docs/aya-gaps.md) | Aya 0.16 没有封装的 netfilter/struct_ops/tcx 等，以及后续候选 |
| [结构与性能评估](docs/review-structure-performance.md) | map/内存实测、启动成本、共享 ring/start map 建议与优先级 |
| [Linux 系统测试](scripts/test-linux.sh) | fmt、ABI、单元测试、clippy、全部 eBPF feature、可选完整构建 |
| [Linux 实测报告](docs/test-report.md) | QEMU + Alpine 上的多场景运行结果、发现的问题与修复、未覆盖项 |

---

## 10. 许可

[MIT](LICENSE-MIT) OR [Apache-2.0](LICENSE-APACHE)。示例代码用于教学与实验；在生产环境使用前请完成权限、最小化挂载范围、回滚与监控设计。

# aya-app eBPF 全场景使用说明

本文是 `aya-app` 十一个 eBPF 场景的**统一操作手册**，面向第一次在 Linux 上运行本项目的使用者。内容覆盖：

- 环境准备、构建、权限和通用约定；
- XDP、TC、kprobe/kretprobe、uprobe/uretprobe、tracepoint、socket filter / SOCK_OPS / connect4、LSM、fentry/fexit、raw tracepoint、cgroup_skb、cgroup_sysctl 的逐场景使用步骤；
- 每个场景的参数、预期输出、验证命令、退出清理和常见问题；
- 一条命令速查表和首轮运行建议。

架构、map/program 清单和实现取舍见 [设计文档](design.md)；每个场景的深入原理见 [场景文档](scenarios/)。

> 本文假设命令在仓库根目录（包含 `Cargo.toml` 的 `aya-app/` 目录）执行，二进制路径为 `./target/release/aya-app`。所有需要 BPF 权限的命令都使用 `sudo -E`。

---

## 0. 场景与能力总览

| 场景 | 命令 | 挂钩点 | 是否能拦截 | 主要用途 |
|---|---|---|---|---|
| XDP | `aya-app xdp` | 网卡驱动 / generic XDP | ✅ `XDP_DROP` | ICMP 防护、单 IP 限速、DDoS 前端 |
| TC | `aya-app tc` | clsact ingress/egress | ✅ `TC_ACT_SHOT` | P2P 限制、视频优先级、QoS |
| kprobe | `aya-app kprobe` | 内核函数入口/返回 | ❌ 只观测 | 敏感路径监控、调用延迟 |
| uprobe | `aya-app uprobe` | 用户态 ELF 符号 | ❌ 只观测 | 应用函数剖析、参数/延迟 |
| tracepoint | `aya-app tracepoint` | 稳定 tracepoint | ❌ 只观测 | 调度/块 I/O 可观测性 |
| socket | `aya-app socket-filter` | SOCK_OPS / socket / cgroup | ✅ 部分子命令 | 连接遥测、入站/出站白名单 |
| LSM | `aya-app lsm` | LSM `socket_connect` | ✅ 返回 `-EPERM` | 全局出站端口拦截、安全策略 |
| fentry/fexit | `aya-app fentry` | BTF trampoline | ❌ 只观测 | 高频函数延迟、与 kprobe 对比 |
| raw tracepoint | `aya-app raw-tp` | `sys_enter` raw TP | ❌ 只观测 | 低开销 syscall 过滤 |
| cgroup_skb | `aya-app cgroup-skb` | cgroup 内 socket | ✅ 返回 1 | 容器/租户网络策略 |
| cgroup_sysctl | `aya-app cgroup-sysctl` | cgroup sysctl | ✅ 拒绝写入 | 阻止容器修改 sysctl |

**能力边界（务必先读）**：

- `SOCK_OPS` 的 `*_CB` 回调返回值会被内核忽略，**不能拦截连接**；出站白名单用 `connect4`，入站 SYN 白名单用 `skfilter`。
- 只有 XDP、TC、`skfilter`、`connect4`、LSM、`cgroup_skb`、`cgroup_sysctl` 能改变转发/连接/写入结果；kprobe、uprobe、tracepoint、sockops、fentry、raw tracepoint 只观测。
- LSM 是**全局**钩子，不是 cgroup 作用域；共享主机上优先用 `--uid` 限制，或改用 `connect4`。
- `cgroup_sysctl` 的返回值语义特殊：**返回 1 允许**，返回 0 被内核转换为 `-EPERM`。
- 所有程序默认 fail-open：解析失败、配置缺失时放行，避免误伤；`connect4` 的用户态 CLI 会拒绝空 allowlist，LSM 要求显式 `--block-port`。

---

## 1. 通用准备

### 1.1 系统要求

| 项目 | 建议 |
|---|---|
| 内核 | ≥ 5.8（ring buffer），推荐 ≥ 5.15 |
| 架构 | x86_64；其他架构可编译，tracepoint 偏移运行时适配 |
| Rust | stable ≥ 1.98；eBPF 构建需要 nightly + `rust-src` |
| 链接器 | `bpf-linker`（需 LLVM） |
| 权限 | root，或 `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_PERFMON` |
| 文件系统 | `tracefs`（tracepoint）、cgroup v2（socket 场景）、`/sys/kernel/btf/vmlinux` |
| LSM | `CONFIG_BPF_LSM=y`、BTF，且 `lsm=` 启动参数包含 `bpf` |
| fentry/fexit | BTF + 函数跟踪/trampoline（`CONFIG_FUNCTION_TRACER`、`CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS`） |
| cgroup 扩展 | cgroup v2、`CONFIG_CGROUP_BPF`；sysctl 还需要 `CONFIG_CGROUP_SYSCTL` |

快速检查：

```bash
uname -r
test -e /sys/kernel/btf/vmlinux && echo "BTF ok"
mount | grep -E 'tracefs|debugfs'
test -f /sys/fs/cgroup/cgroup.controllers && echo "cgroup v2 ok"

# LSM
grep CONFIG_BPF_LSM /boot/config-$(uname -r)
cat /sys/kernel/security/lsm
```

### 1.2 安装与构建

```bash
# Rust
rustup toolchain install stable nightly --component rust-src
rustup component add rustfmt clippy

# BPF 链接器（需要 LLVM，按 bpf-linker 文档安装依赖）
cargo install bpf-linker

# 构建 CLI + eBPF 对象 + demo 目标
cargo build --release
```

构建脚本会自动用 nightly 编译 `aya-app-ebpf`，并把对象嵌入用户态二进制。部署时只需要 `target/release/aya-app`（uprobe 场景另需 demo 目标）。

确认：

```bash
./target/release/aya-app --help
./target/release/aya-app xdp --help
```

> 在无 `bpf-linker` 的开发机上只能做类型检查：
> `AYA_BUILD_SKIP=1 cargo check -p aya-app --target x86_64-unknown-linux-gnu`。
> 这种二进制不能真正加载，详见 [开发与验证](development.md)。

### 1.3 权限与 memlock

```bash
# 推荐：root + 保留环境变量
sudo -E ./target/release/aya-app ...

# 旧内核可能需要放大 memlock；程序启动时也会尝试设置
ulimit -l unlimited
```

如果使用 systemd 服务：

```ini
[Service]
LimitMEMLOCK=infinity
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_PERFMON
```

### 1.4 通用约定

- **Ctrl-C 退出**：所有命令都会在退出时 drop link，自动 detach。
- **统计间隔**：`--stats-interval <SECS>`，默认 5 秒。
- **采样**：XDP/TC 的丢包事件、tracepoint 的 sched 事件、connect4/LSM 的拒绝事件是采样输出；per-CPU 统计是精确值。
- **时间戳**：事件里的 `t=` 是 `bpf_ktime_get_ns()` 的 uptime 秒数，不是墙上时间。
- **字节序**：IPv4 地址在事件中保留原始网络序表示，用户态正确打印；端口统一主机序。
- **调试**：所有命令支持 `RUST_LOG=debug sudo -E ...` 查看 verifier log 和附加细节。
- **查看内核状态**：
  ```bash
  sudo bpftool prog show
  sudo bpftool map show
  sudo bpftool net show          # XDP/TC
  sudo bpftool perf show         # kprobe/uprobe/tracepoint
  sudo bpftool cgroup tree       # sockops/connect4
  sudo bpftool link show         # LSM 等 raw tracepoint link
  ```

---

## 2. 场景 1：XDP

### 2.1 功能

`xdp_firewall` 在 XDP 层：

- 丢弃匹配保护前缀的 ICMP echo request（只丢 type 8，不丢所有 ICMP）；
- 按源 IPv4 做固定 1 秒窗口限速；
- 支持目的前缀保护；
- 精确 per-CPU 统计 + 采样丢弃事件。

### 2.2 前置检查

```bash
ip link show                 # 找到要附加的接口
ethtool -i <iface>           # 查看驱动
```

在 `lo` 上优先用 `--mode skb`；真实网卡先试默认模式，失败再 `--mode skb`。

### 2.3 推荐实验：veth + netns

```bash
sudo bash scripts/lab-veth.sh up
```

脚本会创建：

- 宿主侧 `veth-host`：`10.20.0.1/24`
- netns `aya-lab` 内 `veth-lab`：`10.20.0.2/24`

附加 XDP：

```bash
sudo -E ./target/release/aya-app xdp \
    --iface veth-host \
    --mode driver \
    --block-icmp \
    --rate-limit 20 \
    --protected-ip 10.20.0.1 \
    --protected-prefix-len 32
```

如果 `driver` 失败，改用：

```bash
sudo -E ./target/release/aya-app xdp \
    --iface veth-host --mode skb \
    --block-icmp --rate-limit 20 \
    --protected-ip 10.20.0.1 --protected-prefix-len 32
```

### 2.4 触发

```bash
# ICMP 丢弃
sudo ip netns exec aya-lab ping -c 5 10.20.0.1

# 限速：flood ping
sudo ip netns exec aya-lab ping -f -c 200 10.20.0.1
```

### 2.5 预期输出

```text
=== XDP firewall ===
  interface      : veth-host
  mode           : Driver
  block ICMP echo: true
  rate limit     : 20 pkt/s per source IP
  protected      : 10.20.0.1/32
  event sampling : 1/64
Ctrl-C 退出；XDP link 会随进程关闭自动 detach。

[drop] t=12.345s 10.20.0.2 -> 10.20.0.1 len=98 reason=icmp
...
--- XDP stats ---
pass :         1234  (   246.8 pkt/s,   123456.7 B/s)
drop : icmp=98           rate=176        (54.8 drop/s, 12.3 KiB/s)
bytes: pass=1.2 MiB      drop=34.5 KiB
```

`pass`/`drop` 精确；`[drop]` 事件是采样值。

### 2.6 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--iface` | `lo` | 接口名 |
| `--mode` | `default` | `skb` / `driver` / `hw` |
| `--block-icmp` | 关闭 | 丢弃保护范围内的 ICMP echo request |
| `--rate-limit` | `0` | 每源 IP 每秒包数，0 关闭 |
| `--protected-ip` | 无 | 受保护目的 IPv4；不填 = 所有目的 |
| `--protected-prefix-len` | `32` | 前缀长度 0–32 |
| `--event-sample` | `64` | 每 N 个丢弃事件输出 1 条 |
| `--stats-interval` | `5` | 统计间隔 |

### 2.7 验证与清理

```bash
sudo bpftool net show
sudo bpftool prog show | grep -A5 xdp_firewall
sudo bpftool map show | grep -E 'xdp_(config|stats|rate|events)'
```

Ctrl-C 后 link 自动 detach。若残留：

```bash
sudo ip link set dev veth-host xdp off
```

清理实验环境：

```bash
sudo bash scripts/lab-veth.sh down
```

### 2.8 注意事项

- 固定窗口限速在窗口边界最坏可到 2 倍配置值；需要严格速率请改成令牌桶。
- 不处理 IPv6；非 IPv4、非首片段、截断包一律放行。
- `lo` 上的 XDP 路径受内核版本影响，**只建议冒烟**；稳定实验用 veth/真实网卡。
- 生产上把 `--event-sample` 调大（如 1024），避免 ring buffer 成为瓶颈。

更多： [01-xdp.md](scenarios/01-xdp.md)。

---

## 3. 场景 2：TC

### 3.1 功能

`tc_qos` 在 clsact ingress/egress：

- 按目的端口丢弃 P2P 流量；
- 给视频端口写 `skb->mark`；
- 配合 `prio` qdisc + `fw` 规则选择高优先级 band；
- per-CPU 统计 + 采样丢包事件。

### 3.2 实验：loopback 端口丢包

```bash
# 终端 A：监听 P2P 端口 6881
nc -l 127.0.0.1 6881

# 终端 B：附加 TC egress
sudo -E ./target/release/aya-app tc \
    --iface lo --direction egress \
    --drop-port 6881 --drop-port 6882 \
    --video-port 1935 --video-mark 16

# 终端 C：连接 6881
nc 127.0.0.1 6881
```

预期：连接卡住/失败；终端 B 输出：

```text
[tc-drop] t=... 127.0.0.1:54321 -> 127.0.0.1:6881 len=60
```

> 某些内核的 loopback 路径可能不经过 clsact；若没有效果，用 `scripts/lab-veth.sh` 创建 veth，把 `--iface` 换成 `veth-host`。

### 3.3 配置优先级并验证

```bash
# 根 qdisc：3 个 band
sudo tc qdisc replace dev lo root handle 1: prio bands 3

# 把 mark 16 映射到最高优先级 band
sudo tc filter replace dev lo parent 1: protocol ip handle 0x10 fw flowid 1:1

# 查看
tc -s qdisc show dev lo
tc filter show dev lo parent 1:
```

然后对视频端口制造流量：

```bash
nc -l 127.0.0.1 1935       # 终端 A
nc 127.0.0.1 1935          # 终端 C
```

`tc -s qdisc` 的 band 0 计数应增长。

### 3.4 预期统计

```text
--- TC stats ---
pass        :         1234  (   246.8/s,   123456.7 B/s)
drop p2p    :           98  (    19.6/s, 12.3 KiB/s, total 34.5 KiB)
prioritized :           20  (     4.0/s)
```

### 3.5 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--iface` | `lo` | 接口名 |
| `--direction` | `egress` | `ingress` / `egress` |
| `--drop-port` | `6881,6882,6883` | 目的端口，最多 8 个 |
| `--video-port` | `1935,8080` | 目的端口，最多 8 个 |
| `--video-mark` | `16` | 写入 `skb->mark`，必须非 0 |
| `--event-sample` | `64` | 丢包事件采样 |
| `--stats-interval` | `5` | 统计间隔 |

### 3.6 验证与清理

```bash
sudo bpftool net show
sudo bpftool prog show | grep -A5 tc_qos
tc filter show dev lo egress
```

Ctrl-C 只 detach BPF 程序；**qdisc 会保留**：

```bash
sudo tc qdisc del dev lo clsact
sudo tc qdisc del dev lo root
```

### 3.7 注意事项

- mark 只有在 egress + 已配置 qdisc 时才有队列意义；ingress 的 mark 只对入向策略有用。
- `prio` 只是优先级排队，不是带宽保证；需要带宽保证请用 `htb`/`tbf`。
- 新内核（6.6+）aya 可能用 TCX；执行点与 clsact 相同，但请以目标内核的 `tc` 行为为准。

更多： [02-tc.md](scenarios/02-tc.md)。

---

## 4. 场景 3：kprobe / kretprobe

### 4.1 功能

监控 `do_sys_openat2`：

- 入口记录开始时间、读取用户态路径；
- 路径匹配前缀时发 `[open]` 事件；
- 返回时计算延迟，超过阈值发 `[latency]` 事件；
- 统计 opens/sensitive/latency/slow。

### 4.2 确认符号

```bash
grep -w do_sys_openat2 /proc/kallsyms
```

如果没有该符号：

```bash
grep -E ' (__x64_sys_openat|do_filp_open|vfs_open)$' /proc/kallsyms
```

注意：当前 eBPF 实现假设 **arg1 是 `const char __user *` 路径指针**；更换符号需要同步修改 `aya-app-ebpf/src/programs/kprobe.rs`。

### 4.3 运行

```bash
sudo -E ./target/release/aya-app kprobe \
    --symbol do_sys_openat2 \
    --path-prefix /etc/shadow \
    --path-prefix /etc/passwd \
    --latency-threshold-us 500
```

默认前缀就是 `/etc/shadow` 和 `/etc/passwd`；传了 `--path-prefix` 会替换默认值。

### 4.4 触发

```bash
cat /etc/shadow >/dev/null
# 或
sudo -u nobody cat /etc/shadow >/dev/null
```

### 4.5 预期输出

```text
[open]    t=123.456s pid=12345 tid=12345 comm=cat uid=1000 path=/etc/shadow
[latency] t=123.457s pid=12345 tid=12345 comm=cat 1.23ms     ret=-13
```

- `pid` 是线程组 id，`tid` 是线程 id；
- `ret=-13` 表示 `EACCES`；
- 延迟事件不带路径（返回时用户缓冲区可能已失效）。

### 4.6 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--symbol` | `do_sys_openat2` | 被挂钩的内核函数 |
| `--path-prefix` | `/etc/shadow,/etc/passwd` | 最多 4 个，每个 ≤63 字节 |
| `--latency-threshold-us` | `1000` | 只上报超过该值的返回 |
| `--stats-interval` | `5` | 统计间隔 |

### 4.7 验证与清理

```bash
sudo bpftool perf show
sudo bpftool prog show | grep -A8 -E 'kprobe_openat|kretprobe_openat'
```

Ctrl-C 自动 detach。若没有事件，先检查符号、前缀和 `/proc/kallsyms`。

更多： [03-kprobe.md](scenarios/03-kprobe.md)。

---

## 5. 场景 4：uprobe / uretprobe

### 5.1 功能

剖析自带 demo：

```c
void demo_handle_request(uint64_t request_id, const char *path);
```

- 入口捕获 `request_id` 和 `path`；
- 返回计算延迟；
- 统计 enter/exit/slow。

### 5.2 构建并确认符号

```bash
cargo build --release -p aya-app-demo
nm -C target/release/aya-app-demo | grep demo_
```

应看到：

```text
0000000000001234 T demo_handle_request
00000000000012a0 T demo_slow_query
```

### 5.3 运行

```bash
# 终端 A：启动 demo（约 20ms 一个请求）
./target/release/aya-app-demo 500

# 终端 B：附加
sudo -E ./target/release/aya-app uprobe \
    --binary ./target/release/aya-app-demo \
    --symbol demo_handle_request
```

也可以先 attach 再启动（默认 scope 是所有进程）；`--pid` 模式要求目标进程已存在。

### 5.4 预期输出

```text
=== uprobe function tracing ===
  binary            : /path/aya-app-demo
  symbol            : demo_handle_request
  scope             : all processes
  latency threshold : 1000 us

[enter] t=12.345s pid=4242 tid=4242 comm=aya-app-demo request_id=0 path=/api/v1/orders/0
[exit]  t=12.349s pid=4242 tid=4242 comm=aya-app-demo 4.01ms     ret=0
```

### 5.5 指定 PID

```bash
./target/release/aya-app-demo 1000 &
DEMO_PID=$!
sudo -E ./target/release/aya-app uprobe \
    --binary ./target/release/aya-app-demo \
    --symbol demo_handle_request \
    --pid "$DEMO_PID"
```

### 5.6 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--binary` | 必填 | 目标 ELF 路径（canonicalize） |
| `--symbol` | `demo_handle_request` | ELF 符号名，精确匹配，不做 demangle |
| `--pid` | 无 | 只挂钩指定 PID |
| `--latency-threshold-us` | `1000` | 只上报超过该值的返回 |
| `--stats-interval` | `5` | 统计间隔 |

### 5.7 注意事项

- C++ 目标需要先用 `nm -C` 找到 demangle 名，再确认 ELF 原始符号名；
- PIE/共享库/容器要使用实际加载的文件路径；
- 被 strip 的二进制没有符号，只能使用偏移；
- 高频函数不适合逐个事件上报，应加采样或改用 USDT/应用埋点；
- demo 的 ABI 是 `(u64, char*)`；钩其他函数必须修改参数读取逻辑。

更多： [04-uprobe.md](scenarios/04-uprobe.md)。

---

## 6. 场景 5：tracepoint

### 6.1 功能

观测：

- `sched:sched_switch`：上下文切换、前后任务、优先级、状态；
- `block:block_rq_issue`：块 I/O 请求、设备、扇区、字节数、读写标志。

字段偏移在启动时从 tracefs `format` 文件动态解析，不硬编码内核结构体布局。

### 6.2 确认 tracefs

```bash
ls /sys/kernel/tracing/events/sched/sched_switch/format
ls /sys/kernel/tracing/events/block/block_rq_issue/format
```

没有 tracefs：

```bash
sudo mount -t tracefs tracefs /sys/kernel/tracing
# 或
sudo mount -t debugfs debugfs /sys/kernel/debug
```

### 6.3 运行

```bash
# 调度 + 块 I/O
sudo -E ./target/release/aya-app tracepoint --event all --sched-sample 64

# 只看调度
sudo -E ./target/release/aya-app tracepoint --event sched --sched-sample 64

# 只看块 I/O
sudo -E ./target/release/aya-app tracepoint --event block --block-sample 1
```

### 6.4 制造负载

```bash
# 调度
stress-ng --cpu 2 --timeout 10s

# 块 I/O（/var/tmp 通常不是 tmpfs；不支持 O_DIRECT 时去掉 oflag=direct）
dd if=/dev/zero of=/var/tmp/aya-io-test.bin bs=1M count=64 oflag=direct
rm -f /var/tmp/aya-io-test.bin
```

### 6.5 预期输出

```text
=== Tracepoints ===
  tracefs        : /sys/kernel/tracing
  events         : sched_switch + block_rq_issue
  sched sampling : 1/64
  block sampling : 1/1
  sched offsets  : prev_comm=8 prev_pid=24 prev_state=8B next_comm=40
  block offsets  : dev=8 sector=16 bytes=28 rwbs=32

[sched] t=... bash:1234 [120] -> kworker/0:1:5678 [120] state=S
[block] t=... dev=8:0 sector=123456 bytes=131072 rwbs=W comm=dd
...
--- sched stats ---
switches :      1234567  (  123456.7/s)
emitted  :         1928  (     192.8/s)
--- block stats ---
issues :          512  (      51.2/s)
bytes  :      64.00 MiB  (6.40 MiB/s)
read   :          100    write: 412
```

### 6.6 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--event` | `all` | `sched` / `block` / `all` |
| `--sched-sample` | `64` | 每 N 个 sched 事件输出 1 条 |
| `--block-sample` | `1` | 每 N 个 block 事件输出 1 条 |
| `--stats-interval` | `5` | 统计间隔 |

### 6.7 注意事项

- `switches`/`issues` 精确；事件是采样值；
- tracefs 只使用标准挂载点（aya 的 `TracePoint::attach` 也按这两个路径查找）；
- 字段缺失或大小不匹配会拒绝启动，而不是“猜”；
- 事件中的 `bytes` 在没有该字段的旧内核上为 0；
- `prev_state` 支持 4 字节/8 字节。

更多： [05-tracepoint.md](scenarios/05-tracepoint.md)。

---

## 7. 场景 6：Socket Filter / SOCK_OPS

### 7.1 先理解三个子命令

| 子命令 | 挂钩点 | 能力 |
|---|---|---|
| `sockops` | cgroup SOCK_OPS | 连接生命周期遥测；**不能拦截** |
| `skfilter` | 监听 socket 的经典 filter | 入站 SYN 源 IP 白名单；**能丢弃** |
| `connect4` | cgroup/connect4 | 出站 IPv4 目的端口白名单；**能拒绝** |

### 7.2 SOCK_OPS 遥测

```bash
sudo -E ./target/release/aya-app socket-filter sockops \
    --cgroup /sys/fs/cgroup \
    --watch-port 443
```

另一个终端：

```bash
curl -s https://example.com >/dev/null
```

预期：

```text
[sockops] t=... op=tcp_connect          pid=... comm=curl 10.0.0.5:54321 -> 93.184.216.34:443 srtt=0ns acked=0 B recv=0 B state=...
[sockops] t=... op=active_established   pid=... comm=curl ... srtt=12.3ms ...
[sockops] t=... op=state                pid=... comm=curl ... state=...
```

参数：

| 参数 | 默认 | 说明 |
|---|---|---|
| `--cgroup` | `/sys/fs/cgroup` | cgroup v2 路径 |
| `--watch-port` | 空 | 只观察本地/远端端口匹配的连接 |
| `--attach-mode` | `single` | `single`/`multi` |
| `--stats-interval` | `5` | 统计间隔 |

如果 `EBUSY`，说明同一 cgroup 已有 `single` 模式程序：用 `--attach-mode multi`，或先卸载旧程序。

### 7.3 入站 SYN 白名单（socket filter）

启动监听并附加：

```bash
sudo -E ./target/release/aya-app socket-filter skfilter \
    --listen 127.0.0.1:8080 \
    --allow-ip 127.0.0.1
```

允许的客户端：

```bash
curl -v --max-time 2 http://127.0.0.1:8080/
```

预期：

```text
[accept] peer=127.0.0.1:54321 (SYN passed the filter)
```

（demo 不实现 HTTP，所以 curl 会收到连接关闭，这是正常的。）

拒绝的客户端——用另一个 loopback 源地址：

```bash
sudo ip addr add 127.0.0.2/8 dev lo 2>/dev/null || true
curl --interface 127.0.0.2 -v --max-time 2 http://127.0.0.1:8080/
```

预期：连接超时；`skfilter_stats.dropped_syn` 增长。

参数：

| 参数 | 默认 | 说明 |
|---|---|---|
| `--listen` | `127.0.0.1:8080` | 监听地址 |
| `--allow-ip` | 空 | 为空 = 只观测；非空 = 强制白名单 |
| `--stats-interval` | `5` | 统计间隔 |

注意：

- 只对**该监听 socket**的入站 SYN 生效；不是全机防火墙；
- 只处理 IPv4；IPv6 放行；
- 源 IP 是 NAT/代理后的地址；
- 非 SYN 包和 ICMP 错误放行，避免破坏已建立连接；
- 过滤器看到的是 TCP 头；程序用 `BPF_HDR_START_NET` 相对读取 IP 头，这是实现中的关键点。

### 7.4 出站端口白名单（connect4）

**安全第一**：不要直接挂到根 cgroup。使用专用子 cgroup。

```bash
# 1. 创建专用 cgroup
sudo mkdir -p /sys/fs/cgroup/aya-demo

# 2. 把测试 shell 放进去（agent 不要放进去！）
sudo sh -c 'echo $$ > /sys/fs/cgroup/aya-demo/cgroup.procs; exec bash'
```

在**另一个终端**（仍在根 cgroup）附加策略：

```bash
sudo -E ./target/release/aya-app socket-filter connect4 \
    --cgroup /sys/fs/cgroup/aya-demo \
    --allow-port 80 --allow-port 443
```

在测试 shell 中：

```bash
curl -s --max-time 3 http://1.1.1.1 >/dev/null       # 允许
curl -s --max-time 3 https://1.1.1.1 >/dev/null      # 允许
curl -s --max-time 3 http://1.1.1.1:8080/ >/dev/null # 立即失败
```

预期：

```text
[connect4-deny] t=... pid=... comm=curl dst=1.1.1.1:8080
```

参数：

| 参数 | 默认 | 说明 |
|---|---|---|
| `--cgroup` | 必填 | 策略作用的 cgroup |
| `--allow-port` | 必填，至少 1 个 | 允许的 IPv4 目的端口（最多 8 个） |
| `--attach-mode` | `single` | `single`/`multi` |
| `--stats-interval` | `5` | 统计间隔 |

清理：

```bash
# 在测试 shell 中移回根 cgroup
echo $$ | sudo tee /sys/fs/cgroup/cgroup.procs

# agent 终端 Ctrl-C 后
sudo rmdir /sys/fs/cgroup/aya-demo
```

注意：

- 只匹配 IPv4；IPv6 需要 `connect6`；
- DNS(53) 不在白名单时，按域名访问会先失败；用 IP 测试或把 53 加入白名单；
- 失败时 connect 返回 `EPERM`；
- 如果误配置导致断网：Ctrl-C agent（link detach），把 shell 移回根 cgroup，再重新设计白名单；
- 拒绝事件按 1/16 采样，统计精确。

更多： [06-socket-filter.md](scenarios/06-socket-filter.md)。

---

## 8. 场景 7：LSM

### 8.1 功能与能力边界

`lsm_socket_connect` 在 LSM `socket_connect` 钩子上：

- 解析内核 `sockaddr_in`；
- 拒绝连接指定目的端口，返回 `-EPERM`；
- 可选只对某个 UID 生效；
- per-CPU 统计 + 采样拒绝事件。

与 `connect4` 的差别：

| | `connect4` | LSM `socket_connect` |
|---|---|---|
| 作用域 | 某个 cgroup | 全局（可用 `--uid` 缩小） |
| 挂钩点 | cgroup/connect4 | LSM 安全钩子 |
| 依赖 | cgroup v2 | `CONFIG_BPF_LSM`、BTF、`lsm=...bpf` |
| 适合 | 容器出站白名单 | 主机级安全策略 |

> LSM 是全局钩子。共享主机上先用 `--uid` 限制到测试用户；不要在生产机上随意 `--block-port`。

### 8.2 前置检查

```bash
# 内核配置（路径可能因发行版不同）
grep CONFIG_BPF_LSM /boot/config-$(uname -r)

# 当前启用的 LSM 列表必须包含 bpf
cat /sys/kernel/security/lsm

# BTF 必须存在
test -e /sys/kernel/btf/vmlinux && echo "BTF ok"
```

如果 `/sys/kernel/security/lsm` 中没有 `bpf`，需要修改启动参数并重启，例如：

```text
lsm=lockdown,yama,integrity,apparmor,bpf
```

### 8.3 运行

```bash
# 只拦截当前 UID 对 8080 的连接（推荐）
sudo -E ./target/release/aya-app lsm \
    --block-port 8080 \
    --uid "$(id -u)"
```

如果想拦截整机所有用户（谨慎）：

```bash
sudo -E ./target/release/aya-app lsm --block-port 8080
```

### 8.4 触发

```bash
# 终端 A：监听 8080（bind 不受 connect 钩子影响）
nc -l 127.0.0.1 8080

# 终端 B：连接（应与 8.3 使用同一 UID）
nc 127.0.0.1 8080
```

预期客户端失败：

```text
nc: connect to 127.0.0.1 port 8080 (tcp) failed: Operation not permitted
```

### 8.5 预期输出

```text
=== LSM socket_connect policy ===
  hook          : socket_connect
  blocked ports : [8080]
  uid filter    : uid 1000
  event sample  : 1/16
警告          : LSM 是全局钩子；共享主机上请用 --uid 缩小作用域

[lsm-deny] t=... pid=... uid=1000 comm=nc dst=127.0.0.1:8080

--- LSM stats ---
connects :            3  (       0.6/s)
allowed  :            1    denied:            2 (0.4 deny/s)
```

- `connects`：钩子调用次数（包括 IPv6/AF_UNIX）；
- `allowed`：未命中策略、UID 不匹配、非 IPv4；
- `denied`：命中黑名单端口。

### 8.6 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--block-port` | 必填，至少 1 个 | 拒绝的 IPv4 目的端口（最多 8 个） |
| `--uid` | 无 | 只对指定 UID 生效；不填 = 整机 |
| `--event-sample` | `16` | 每 N 个拒绝事件输出 1 条 |
| `--stats-interval` | `5` | 统计间隔 |

### 8.7 验证与清理

```bash
sudo bpftool prog show | grep -A8 lsm_socket_connect
sudo bpftool link show
sudo bpftool map show | grep -E 'lsm_(config|stats|events)'
cat /sys/kernel/security/lsm
```

Ctrl-C 自动 detach。若加载成功但没有任何事件，优先检查 `lsm=` 是否包含 `bpf`；如果 `CONFIG_BPF_LSM` 未开启，加载会直接失败。

### 8.8 注意事项

- 只解析 IPv4 `sockaddr_in`；IPv6/AF_UNIX 放行；
- 端口黑名单是主机级策略；生产上优先 cgroup 方案或明确的 allowlist；
- `socket_connect` 是 sleepable hook，程序必须用 `#[lsm(sleepable, ...)]`；非 sleepable 程序 load 成功但 attach 会返回 `EBUSY`；
- 先尊重前一个 LSM 的拒绝（BTF 参数最后一个 `retval`）；
- 容器/用户命名空间的 UID 映射需要按实际值配置；
- 需要 `CONFIG_BPF_LSM=y`、BTF，且 `lsm=` 中有 `bpf`；内核还需要可用的 ftrace/trampoline 支持。

更多： [07-lsm.md](scenarios/07-lsm.md)。

---

## 9. 场景 8：fentry / fexit

### 9.1 功能

用 BTF trampoline 跟踪 `do_sys_openat2`：

- fentry 记录线程入口时间戳；
- fexit 计算延迟、读取返回值；
- 事件采样，per-CPU 统计。

### 9.2 前置检查

```bash
test -e /sys/kernel/btf/vmlinux && echo "BTF ok"
cat /sys/kernel/tracing/available_tracers
# 期望包含 function/function_graph，而不是只有 nop
```

### 9.3 运行

```bash
sudo -E ./target/release/aya-app fentry \
    --symbol do_sys_openat2 \
    --latency-threshold-us 0
```

### 9.4 触发

```bash
cat /etc/hosts >/dev/null
```

### 9.5 预期输出

```text
[fexit] t=... pid=2101 tid=2101 comm=cat uid=0 1.20ms     ret=3

--- fentry/fexit stats ---
enters :            1  (       0.2/s)
exits  :            1  (       0.2/s)
slow   :            1  (       0.2/s)  missing_starts=0
```

### 9.6 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--symbol` | `do_sys_openat2` | BTF 函数名 |
| `--latency-threshold-us` | `0` | 只输出超过阈值的退出事件 |
| `--event-sample` | `1` | 退出事件采样率 |
| `--stats-interval` | `5` | 统计间隔 |

### 9.7 注意

- 需要 BTF 和函数跟踪/trampoline；精简内核可能只有 `nop` tracer；
- 嵌套 open 会覆盖同一线程的起始时间，`missing_starts` 会增加；
- 更详细的原理见 [08-fentry-fexit.md](scenarios/08-fentry-fexit.md)。

---

## 10. 场景 9：raw tracepoint

### 10.1 功能

在 `sys_enter` raw tracepoint 上按 syscall 号过滤，直接读取 `TP_PROTO` 参数，不解析 tracefs format。

### 10.2 运行

```bash
# 默认 x86_64 open=2（BusyBox/musl cat 使用）
sudo -E ./target/release/aya-app raw-tp

# 现代 glibc 程序通常使用 openat=257
sudo -E ./target/release/aya-app raw-tp --syscall-nr 257

# aarch64 openat = 56
sudo -E ./target/release/aya-app raw-tp --syscall-nr 56
```

### 10.3 触发

```bash
cat /etc/hosts >/dev/null
```

### 10.4 预期输出

```text
[sys_enter] t=... pid=2105 tid=2105 comm=cat uid=0 nr=2

--- raw tracepoint stats ---
matches :            1  (       0.2/s)
emitted :            1  (       0.2/s)
```

### 10.5 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--syscall-nr` | `2` | 系统调用号，架构相关（`open`=2，`openat`=257） |
| `--event-sample` | `1` | 匹配事件采样率 |
| `--stats-interval` | `5` | 统计间隔 |

### 10.6 注意

- raw tracepoint 不解析 tracefs format，也不要求挂载 tracefs；它直接使用内核 raw tracepoint 表；
- 系统调用号因架构不同；不确定时先 `strace -e openat cat /etc/hosts`。

更多：[09-raw-tracepoint.md](scenarios/09-raw-tracepoint.md)。

---

## 11. 场景 10：cgroup_skb

### 11.1 功能

在 cgroup 的 ingress/egress 上按目的端口丢包，策略边界是进程组而不是网卡。

### 11.2 准备

```bash
mount | grep cgroup2
mkdir -p /sys/fs/cgroup/aya-skb
```

### 11.3 运行

```bash
sudo -E ./target/release/aya-app cgroup-skb \
    --cgroup /sys/fs/cgroup/aya-skb \
    --direction egress \
    --block-port 18080
```

### 11.4 触发

```bash
# 终端 A：cgroup 外监听
nc -l -p 18080

# 终端 B：cgroup 内连接
sh -c 'echo $$ > /sys/fs/cgroup/aya-skb/cgroup.procs; nc 127.0.0.1 18080'
```

### 11.5 预期输出

```text
[cgroup-skb drop] t=... pid=0 tid=0 comm= 127.0.0.1:40122 -> 127.0.0.1:18080 len=60

--- cgroup_skb stats ---
pass  :            1  (       0.5/s,        0 B/s)
drop  :            1  (       0.5/s,       60 B/s)
bytes : pass=0 B  drop=60 B
```

> 6.6 的 cgroup_skb 不允许 `bpf_get_current_pid_tgid` / `bpf_get_current_comm`，
> 因此 `pid`/`tid`/`comm` 为 0/空；地址、端口和统计仍然准确。

### 11.6 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--cgroup` | 必填 | cgroup v2 路径 |
| `--direction` | `egress` | `ingress` / `egress` |
| `--block-port` | `8080` | 目的端口；`0` = 只观测 |
| `--event-sample` | `64` | 丢弃事件采样率 |
| `--stats-interval` | `5` | 统计间隔 |

更多：[10-cgroup-skb.md](scenarios/10-cgroup-skb.md)。

---

## 12. 场景 11：cgroup_sysctl

### 12.1 功能

阻止一个 cgroup 内的进程写 `/proc/sys/*`；读操作放行。返回值语义：

- 返回 `1`：允许；
- 返回 `0`：内核转换为 `-EPERM`。

### 12.2 准备

```bash
mkdir -p /sys/fs/cgroup/aya-sysctl
```

### 12.3 运行

```bash
sudo -E ./target/release/aya-app cgroup-sysctl \
    --cgroup /sys/fs/cgroup/aya-sysctl
```

只观测：

```bash
sudo -E ./target/release/aya-app cgroup-sysctl \
    --cgroup /sys/fs/cgroup/aya-sysctl --observe
```

### 12.4 触发

```bash
sh -c 'echo $$ > /sys/fs/cgroup/aya-sysctl/cgroup.procs; sysctl -w net.ipv4.ip_forward=1'
# 预期：Operation not permitted
```

### 12.5 预期输出

```text
[sysctl-deny] t=... pid=... tid=... comm=sysctl uid=0 write=1

--- cgroup_sysctl stats ---
calls   :            2  (       0.4/s)
writes  :            1  (       0.2/s)
blocked :            1  (       0.2/s)  reads=1
```

### 12.6 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--cgroup` | 必填 | cgroup v2 路径 |
| `--observe` | false | 只观测，不拒绝 |
| `--event-sample` | `16` | 拒绝事件采样率 |
| `--stats-interval` | `5` | 统计间隔 |

### 12.7 限制

- 上下文没有 sysctl 名称，策略是“该 cgroup 的所有写”；
- 影响整个 cgroup 子树；
- 需要 `CONFIG_CGROUP_SYSCTL=y`。

更多：[11-cgroup-sysctl.md](scenarios/11-cgroup-sysctl.md)。

---

## 13. 命令速查

```bash
# 1. XDP
sudo -E ./target/release/aya-app xdp \
    --iface veth-host --mode driver --block-icmp \
    --rate-limit 100 --protected-ip 10.20.0.1 --protected-prefix-len 32

# 2. TC
sudo -E ./target/release/aya-app tc \
    --iface lo --direction egress \
    --drop-port 6881 --video-port 1935 --video-mark 16

# 3. kprobe
sudo -E ./target/release/aya-app kprobe \
    --symbol do_sys_openat2 --path-prefix /etc/shadow \
    --latency-threshold-us 500

# 4. uprobe
cargo build --release -p aya-app-demo
sudo -E ./target/release/aya-app uprobe \
    --binary ./target/release/aya-app-demo \
    --symbol demo_handle_request

# 5. tracepoint
sudo -E ./target/release/aya-app tracepoint \
    --event all --sched-sample 64 --block-sample 1

# 6a. SOCK_OPS
sudo -E ./target/release/aya-app socket-filter sockops \
    --cgroup /sys/fs/cgroup --watch-port 443

# 6b. socket filter
sudo -E ./target/release/aya-app socket-filter skfilter \
    --listen 127.0.0.1:8080 --allow-ip 127.0.0.1

# 6c. connect4（务必用专用 cgroup）
sudo -E ./target/release/aya-app socket-filter connect4 \
    --cgroup /sys/fs/cgroup/aya-demo --allow-port 80 --allow-port 443

# 7. LSM（全局钩子；先用 --uid 缩小作用域）
sudo -E ./target/release/aya-app lsm \
    --block-port 8080 --uid "$(id -u)"

# 8. fentry/fexit
sudo -E ./target/release/aya-app fentry \
    --symbol do_sys_openat2 --latency-threshold-us 0

# 9. raw tracepoint（默认 x86_64 open=2；openat=257；aarch64=56）
sudo -E ./target/release/aya-app raw-tp

# 10. cgroup_skb
sudo -E ./target/release/aya-app cgroup-skb \
    --cgroup /sys/fs/cgroup/aya-skb --direction egress --block-port 18080

# 11. cgroup_sysctl（去掉 --observe 即拒绝写入）
sudo -E ./target/release/aya-app cgroup-sysctl \
    --cgroup /sys/fs/cgroup/aya-sysctl
```

所有命令都支持 `--help`；参数默认值见 [README](../README.md) 和 `aya-app/src/cli.rs`。

---

## 14. 退出与清理对照表

| 场景 | Ctrl-C 后自动清理 | 需要手动清理 |
|---|---|---|
| XDP | link detach | 无（若异常：`ip link set dev <iface> xdp off`） |
| TC | BPF 程序 detach | `clsact` qdisc、根 qdisc |
| kprobe | perf event link detach | 无 |
| uprobe | perf event link detach | 无 |
| tracepoint | perf event link detach | 无 |
| sockops | cgroup link detach | 无 |
| cgroup_skb | cgroup link detach | 无 |
| cgroup_sysctl | cgroup link detach | 无 |
| fentry/fexit | trampoline link detach | 无 |
| raw tracepoint | raw TP link detach | 无 |
| skfilter | 关闭监听 socket 后失效 | 无 |
| connect4 | cgroup link detach | 测试 shell 移回根 cgroup、删除子 cgroup |
| LSM | raw tracepoint link detach | 无 |

检查残留：

```bash
sudo bpftool net show
sudo bpftool perf show
sudo bpftool cgroup tree
sudo bpftool prog show
tc qdisc show
```

---

## 15. 常见问题快速定位

| 现象 | 先检查 |
|---|---|
| `Operation not permitted` | 是否 root/有 CAP_BPF、CAP_NET_ADMIN、CAP_PERFMON |
| `failed to load ... verifier` | `RUST_LOG=debug` 重新运行，看 verifier log |
| XDP attach 失败 | 换 `--mode skb`；`ip link show`；`bpftool net show` |
| TC 没效果 | 方向/接口；`tc filter show dev <iface> egress` |
| kprobe 没有事件 | `grep -w <symbol> /proc/kallsyms`；前缀；arg1 约定 |
| uprobe 没有事件 | `nm -C <binary>`；PID/scope；函数是否内联 |
| tracepoint 启动失败 | tracefs 是否挂载；`format` 字段是否存在 |
| sockops 没有事件 | cgroup 成员；`--watch-port`；是否 TCP |
| skfilter 不生效 | 监听 socket、源 IP、NAT、是否 SYN |
| connect4 断网 | Ctrl-C；把 shell 移回根 cgroup；检查 allowlist |
| LSM 没有事件 | `cat /sys/kernel/security/lsm` 是否含 `bpf`；内核是否 `CONFIG_BPF_LSM`；UID 是否匹配 |
| ring buffer 事件少 | 采样率；ring buffer 满；用户态读取 |

完整排错： [troubleshooting.md](troubleshooting.md)。

---

## 16. 首轮运行建议

1. **先构建并看帮助**：`cargo build --release`、`aya-app --help`。
2. **从观测场景开始**：`tracepoint` → `kprobe` → `uprobe`，不需要改动网络。
3. **再做 XDP**：用 `scripts/lab-veth.sh` 隔离，先 `--mode skb` 成功后再试 `driver`。
4. **TC 用 loopback/veth**：先确认丢包，再配置 qdisc 观察优先级。
5. **socket 场景最后做**：`sockops` 只读；`skfilter` 只影响一个监听 socket；`connect4` 一定要用专用 cgroup。
6. **LSM 最后做，且先加 `--uid`**：确认 `lsm=` 含 `bpf`，用测试用户/测试端口验证，再考虑扩大范围。
7. **生产前**：缩小作用域、加大采样间隔、准备回滚命令、确认 IPv6/协议覆盖范围。

---

## 17. 安全与生产检查清单

- [ ] 是否只在目标接口/cgroup/socket 上附加？
- [ ] `connect4` 是否使用专用 cgroup，而不是根 cgroup？
- [ ] LSM 是否使用 `--uid` 或明确接受全局作用域？`lsm=` 是否包含 `bpf`？
- [ ] 白名单是否包含 DNS/健康检查/监控所需端口？
- [ ] kprobe 是否只匹配必要前缀，避免采集敏感路径？
- [ ] uprobe 是否只挂目标进程/符号，避免高频函数？
- [ ] tracepoint 采样率是否与磁盘/CPU 预算匹配？
- [ ] 是否准备了 Ctrl-C/`tc qdisc del`/cgroup 回滚步骤？
- [ ] 是否确认 IPv6 行为（当前多数场景只处理 IPv4）？
- [ ] 是否在预发环境验证过 verifier/内核版本差异？

---

## 18. 相关文档

- [README：项目总览、构建、CLI 速查](../README.md)
- [快速使用说明：USAGE.md](../USAGE.md)
- [设计文档：架构、map/program、数据流](design.md)
- [开发与验证：工具链、verifier 调试、扩展](development.md)
- [排错手册](troubleshooting.md)
- [XDP 场景](scenarios/01-xdp.md)
- [TC 场景](scenarios/02-tc.md)
- [kprobe 场景](scenarios/03-kprobe.md)
- [uprobe 场景](scenarios/04-uprobe.md)
- [tracepoint 场景](scenarios/05-tracepoint.md)
- [socket 场景](scenarios/06-socket-filter.md)
- [LSM 场景](scenarios/07-lsm.md)
- [fentry/fexit 场景](scenarios/08-fentry-fexit.md)
- [raw tracepoint 场景](scenarios/09-raw-tracepoint.md)
- [cgroup_skb 场景](scenarios/10-cgroup-skb.md)
- [cgroup_sysctl 场景](scenarios/11-cgroup-sysctl.md)
- [Aya 缺口分析](aya-gaps.md)
- [结构与性能评估：map/内存实测](review-structure-performance.md)
- [Linux 实测报告：QEMU + Alpine 结果](test-report.md)

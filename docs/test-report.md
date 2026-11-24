# Linux 实测报告

本报告记录 `aya-app` 十一个场景在真实 Linux 内核上的运行结果。测试在 QEMU 中完成，目的是覆盖
`bpf-linker` 最终链接、内核 verifier、程序 attach、事件读取和统计路径；不是性能基准。

## 1. 测试环境

| 项目 | 值 |
|---|---|
| 宿主 | Windows，QEMU 11.1.0（TCG，无 KVM/WHPX） |
| Guest | Alpine Linux 3.24 / 3.20 / 3.18 |
| 内核 A | `6.18.35-0-lts`（Alpine 3.24，全场景） |
| 内核 B | `6.6.31-0-lts`（Alpine 3.20） |
| 内核 C | `6.1.27-2-lts`（Alpine 3.18） |
| 内核 D | `6.18.35-0-virt`（Alpine 3.24，功能受限） |
| 用户态 | `x86_64-unknown-linux-musl` 静态二进制 |
| eBPF | Rust nightly + `bpf-linker 0.13.0` |
| 权限 | guest root，`/sys/kernel/btf/vmlinux` 可用 |

> `linux-virt` 内核没有 function tracer/direct calls，BPF LSM、fentry/fexit 无法 attach；
> 3.20/3.18 内核没有启用 `CONFIG_BPF_LSM`，LSM 场景只在 3.24 LTS 上验证。
> 3.20/3.18 LTS 都具备 BTF 和 function tracer。

## 2. 构建结果

```bash
# eBPF 对象（build.rs 一次 --bins 构建 11 个场景）
cargo build -p aya-app --release --target x86_64-unknown-linux-musl

# uprobe demo
cargo build -p aya-app-demo --release --target x86_64-unknown-linux-musl
```

结果：

- eBPF 对象：11 个场景对象，单个约 80–150 KB，合计约 1.2 MB；
- `aya-app`：约 4.41 MB（静态 musl，嵌入 11 个场景对象）；
- `aya-app-demo`：约 0.5 MB。

`#[lsm(sleepable, ...)]` 生成的 section 为 `lsm.s/socket_connect`，可由 `strings`/readelf 确认。

## 3. 场景结果

### 3.0 内核兼容性矩阵

| 场景 | 6.18.35 LTS | 6.6.31 LTS | 6.1.27 LTS |
|---|---|---|---|
| XDP | ✅ | ✅ | ✅ |
| TC | ✅ | 未覆盖 | 未覆盖 |
| kprobe/kretprobe | ✅ | ✅（修复后） | ✅（修复后） |
| uprobe/uretprobe | ✅ | ✅ | ✅（修复后） |
| tracepoint | ✅ | ✅（sched） | ✅（sched） |
| socket filter / connect4 | ✅ | ✅（skfilter/connect4） | 未覆盖 |
| SOCK_OPS | ✅ | 未覆盖 | 未覆盖 |
| LSM | ✅ | ❌ 内核无 BPF LSM | ❌ 内核无 BPF LSM |
| fentry/fexit | ✅ | ✅ | ✅（修复后） |
| raw tracepoint | ✅ | ✅ | ✅（修复后） |
| cgroup_skb | ✅ | ✅（修复后，pid/comm 为 0） | 未覆盖 |
| cgroup_sysctl | ✅ | ✅ | 未覆盖 |

“未覆盖”是测试范围限制，不是已确认失败；3.20/3.18 的 LSM 失败是内核
`CONFIG_BPF_LSM`/`lsm=bpf` 不可用，应用层会明确报错。

性能对比（同一个 XDP 命令）：

| 内核 | XDP map memlock | 说明 |
|---|---:|---|
| 6.18.35 LTS | 1,727,712 B ≈ 1.65 MiB | 1 个 ring + 16k LRU |
| 6.6.31 LTS | 1,719,240 B ≈ 1.64 MiB | 与 6.18 基本一致 |
| 6.1.27 LTS | 未单独测 | 同一份 map 定义，预期一致 |

6.18 上 XDP 启动时间约 **0.37s（QEMU TCG）**；6.1/6.6 的绝对时间受 TCG 和串口
交互影响，不用于横向性能排名。可以确认的是：map 内存不随内核版本明显变化，
兼容性差异主要来自 verifier 规则和 helper allowlist。

### 3.1 XDP（`lo`，SKB 模式）

```bash
timeout 7 ./aya-app xdp --iface lo --mode skb --block-icmp \
    --protected-ip 127.0.0.1 --protected-prefix-len 32 --stats-interval 2
ping -c 3 127.0.0.1
```

结果：

```text
3 packets transmitted, 0 packets received, 100% packet loss

--- XDP stats ---
drop : icmp=3            rate=0             (1.0 drop/s, 98 B/s)
bytes: pass=0 B          drop=294 B
```

结论：XDP 附加、ICMP 丢弃、per-CPU 统计和字节计数均正常。

### 3.2 TC（`lo`，egress）

```bash
timeout 7 ./aya-app tc --iface lo --direction egress \
    --drop-port 8080 --stats-interval 2
# 另开终端
nc -l -p 8080
nc 127.0.0.1 8080
```

结果：

```text
[tc-drop] t=... 127.0.0.1:38129 -> 127.0.0.1:8080 len=74
--- TC stats ---
drop p2p    :            5  (       1.5/s, 111 B/s, total 370 B)
```

结论：clsact 附加、端口解析、skb drop 和统计正常。

### 3.3 kprobe / kretprobe

```bash
timeout 7 ./aya-app kprobe --path-prefix /etc/shadow \
    --latency-threshold-us 0 --stats-interval 2
cat /etc/shadow >/dev/null
```

结果：

```text
[open]    t=... pid=1993 comm=cat uid=0 path=/etc/shadow
[latency] t=... pid=1993 comm=cat 1.81ms     ret=3
--- kprobe stats ---
opens      :            5
sensitive  :            1
latency    : calls=3          slow=3
```

结论：入口路径、`kretprobe` 返回值和延迟统计正常。

### 3.4 uprobe / uretprobe

```bash
timeout 8 ./aya-app uprobe --binary /tmp/aya-app-demo \
    --symbol demo_handle_request --latency-threshold-us 0
/tmp/aya-app-demo 30
```

结果：

```text
[enter] t=... pid=2002 comm=aya-app-demo request_id=23 path=/api/v1/orders/23
[exit]  t=... pid=2002 comm=aya-app-demo 6.08ms     ret=0
```

结论：用户态符号解析、uprobe/uretprobe 和参数读取正常。

### 3.5 tracepoint

```bash
timeout 6 ./aya-app tracepoint --event all \
    --sched-sample 1 --block-sample 1 --stats-interval 1
```

sched 结果：

```text
[sched] t=784.451s aya-app:1967 [120] -> swapper/0:0 [120] state=S
--- sched stats ---
switches :         4274  (     620.0/s)
```

block 结果（使用 `dd` 制造 I/O）：

```text
[block] t=347.913s dev=0:1792 sector=0 bytes=557056 rwbs=RA comm=dd
--- block stats ---
issues :           13  (      13.0/s)
bytes  :    12.50 MiB  (12.50 MiB/s)
read   :           13    write: 0
```

结论：tracefs 格式解析、动态 offset、sched/block 两个事件的 RingBuf 输出正常。

> Linux 6.18 的 `block_rq_issue` 中 `rwbs` 是 `char[10]`，旧代码按 8 字节严格校验会拒绝启动。
> 现已改为“至少 8 字节，只读取前 8 字节”，并加了单元测试。

### 3.6 Socket Filter / SOCK_OPS / cgroup connect4

Socket Filter 允许：

```bash
timeout 8 ./aya-app socket-filter skfilter \
    --listen 127.0.0.1:18080 --allow-ip 127.0.0.1
nc 127.0.0.1 18080
```

```text
[accept] peer=127.0.0.1:39597 (SYN passed the filter)
seen=4          syn=1          allowed=1          dropped=0
```

Socket Filter 拒绝：

```bash
timeout 6 ./aya-app socket-filter skfilter \
    --listen 127.0.0.1:18082 --allow-ip 192.0.2.1
nc 127.0.0.1 18082
```

```text
seen=2          syn=2          allowed=0          dropped=2
```

SOCK_OPS：

```bash
timeout 8 ./aya-app socket-filter sockops \
    --cgroup /sys/fs/cgroup --watch-port 18081
```

```text
[sockops] t=... op=passive_established pid=2071 comm=nc ...
--- SOCK_OPS stats ---
established :          1
```

cgroup/connect4：

```bash
mkdir -p /sys/fs/cgroup/aya-demo
timeout 8 ./aya-app socket-filter connect4 \
    --cgroup /sys/fs/cgroup/aya-demo --allow-port 80
sh -c 'echo $$ > /sys/fs/cgroup/aya-demo/cgroup.procs; nc 127.0.0.1 8080'
```

```text
--- connect4 stats ---
connects :          1
allowed  :          0    denied:          1
```

结论：socket filter 的 SYN 放行/丢弃、SOCK_OPS 事件、cgroup v2 的 `connect4` 拒绝均正常。

### 3.7 LSM

启用方式：

```text
lsm=lockdown,capability,landlock,yama,bpf
```

Alpine `linux-virt` 上：

```text
Error: failed to attach the LSM program
Caused by: bpf_raw_tracepoint_open failed: Resource busy (os error 16)
```

此时 `available_tracers` 只有 `nop`，说明该精简内核没有函数跟踪/trampoline 支持；这不是
LSM 程序逻辑错误。同一二进制换到 `linux-lts` 后：

```bash
timeout 8 ./aya-app lsm --block-port 18080 --uid 0 \
    --event-sample 1 --stats-interval 2
nc -l -p 18080
nc 127.0.0.1 18080
```

```text
[lsm-deny] t=221.322s pid=2109 uid=0 comm=nc dst=127.0.0.1:18080
--- LSM stats ---
connects :            3
allowed  :            2    denied:            1
```

结论：`socket_connect` 策略成功 attach，命中端口返回 `EPERM`，事件和统计正常。

### 3.8 fentry / fexit

```bash
timeout 8 ./aya-app fentry --symbol do_sys_openat2 \
    --latency-threshold-us 0 --event-sample 1
cat /etc/hosts >/dev/null
```

结果：

```text
[fexit] t=190.464s pid=2113 tid=2113 comm=cat uid=0 370.9us    ret=3
--- fentry/fexit stats ---
enters :            5  (       2.5/s)
exits  :            5  (       2.5/s)
slow   :            5  (       2.5/s)  missing_starts=0
```

结论：BTF trampoline 的 fentry/fexit 加载、attach、参数/返回值读取和延迟计算均正常。

### 3.9 raw tracepoint

```bash
timeout 6 ./aya-app raw-tp --event-sample 1
cat /etc/hosts >/dev/null
```

结果：

```text
[sys_enter] t=... pid=2212 tid=2212 comm=cat uid=0 nr=2

--- raw tracepoint stats ---
matches :            3  (       1.5/s)
emitted :            3  (       1.5/s)
```

说明：BusyBox/musl 的 `cat` 使用 legacy `open`（x86_64 nr=2）；现代 glibc 程序通常使用
`openat`（257）。CLI 默认值因此设为 `2`，同时给出 `--syscall-nr 257` 的用法。

### 3.10 cgroup_skb

```bash
mkdir -p /sys/fs/cgroup/aya-skb
timeout 9 ./aya-app cgroup-skb --cgroup /sys/fs/cgroup/aya-skb \
    --direction egress --block-port 18080 --event-sample 1
nc -l -p 18080
sh -c 'echo $$ > /sys/fs/cgroup/aya-skb/cgroup.procs; nc 127.0.0.1 18080'
```

结果：

```text
[cgroup-skb drop] t=962.070s pid=2189 tid=2189 comm=nc 127.0.0.1:43725 -> 127.0.0.1:18080 len=60
--- cgroup_skb stats ---
drop  :            4  (       0.5/s,       26 B/s)
bytes : pass=0 B  drop=216 B
```

结论：cgroup_skb egress 能按 cgroup 内 socket 的目的端口丢包，事件和字节统计正常。

### 3.11 cgroup_sysctl

```bash
mkdir -p /sys/fs/cgroup/aya-sysctl
timeout 8 ./aya-app cgroup-sysctl --cgroup /sys/fs/cgroup/aya-sysctl --event-sample 1
sh -c 'echo $$ > /sys/fs/cgroup/aya-sysctl/cgroup.procs; sysctl -w net.ipv4.ip_forward=1'
```

结果：

```text
sysctl: write error: Operation not permitted

[sysctl-deny] t=1081.913s pid=2201 tid=2201 comm=sysctl uid=0 write=1
--- cgroup_sysctl stats ---
calls   :            1  (       0.5/s)
writes  :            1  (       0.5/s)
blocked :            1  (       0.5/s)  reads=0
```

结论：cgroup_sysctl 的返回值语义（1 允许、0 拒绝）正确，写入被转换为 `EPERM`。

## 4. 测试中发现并修复的问题

### 4.1 `block_rq_issue.rwbs` 从 8 字节增长到 10 字节

Linux 6.18 的格式：

```text
field:char rwbs[10];  offset:34; size:10; signed:0;
```

原解析器要求恰好 8 字节，启动时报：

```text
field `rwbs` has size 10, expected 8; kernel tracepoint layout is incompatible
```

修复：新增 `Format::require_min`，允许 `rwbs` 为 8/10/16 等长度，BPF 事件只保留前 8 字节；
新增单元测试 `accepts_grown_text_array`。

### 4.2 LSM `socket_connect` 是 sleepable hook

内核 `sleepable_lsm_hooks` 包含 `bpf_lsm_socket_connect`。原程序使用普通
`#[lsm(hook = "socket_connect")]`，程序可以 load，但 attach 返回 `EBUSY`。修复：

```rust
#[lsm(sleepable, hook = "socket_connect")]
pub fn lsm_socket_connect(ctx: LsmContext) -> i32 { ... }
```

生成 `lsm.s/socket_connect`，aya 会设置 `BPF_F_SLEEPABLE`。

### 4.3 LSM 返回值范围

原实现把 BTF 参数 3（前一个 LSM 的返回值）原样返回。verifier 日志：

```text
At program exit the register R0 has smin=0 smax=4294967295
should have been in [-4095, 0]
```

修复：前一个 LSM 已拒绝时统一返回 `-EPERM`，否则返回 0；保证 verifier 能证明返回范围。

### 4.4 cgroup 程序使用 `AllowMultiple` 导致 `EINVAL`

首次测试 `cgroup-skb`：

```text
Error: failed to attach cgroup_skb ...
Caused by: bpf_link_create failed: Invalid argument (os error 22)
```

`CgroupSkb::attach(..., CgroupAttachMode::AllowMultiple)` 在该内核/链接路径下返回 `EINVAL`。
改为 `CgroupAttachMode::Single` 后 attach 成功；`cgroup_sysctl` 同样改为 `Single`。

### 4.5 raw tracepoint 的 syscall 号与架构相关

默认 `openat`=257 在 Alpine BusyBox/musl 上匹配不到（`cat` 使用 legacy `open`=2），
最初统计为 0。确认 `arg(1)` 读取正确后，把默认值改为 2，并在文档中说明
`openat`=257、aarch64 `openat`=56 的差异，避免把“工具链 syscall 选择”误判为程序错误。

### 4.6 旧内核的 ring buffer 栈限制（6.1 / 6.6）

在 6.6 上，kprobe 首次加载失败：

```text
combined stack size of 2 calls is 544. Too large
```

在 6.1 上，fentry/raw-tp 等事件程序失败：

```text
invalid indirect read from stack R2 off -80+52 size 56
```

原因是 `RingBuf::output(&event)` 会先在 BPF 栈上构造完整事件，旧 verifier 的
512 字节栈限制/间接读检查更严格。修复方式：

- kprobe/uprobe/fentry/raw-tp/LSM/TC/XDP/socket/tracepoint/cgroup 事件全部改为
  `RingBuf::reserve::<T>()` + `entry.write(...)`，直接在 ring buffer 预留区写字段；
- 事件 ABI 不变，userspace 解析不变。

### 4.7 cgroup_skb 的 current-task helper 不可用（6.6）

cgroup_skb 在 6.6 的 verifier 日志：

```text
unknown func bpf_get_current_pid_tgid#14
unknown func bpf_get_current_comm#16
```

这两个 helper 不在该内核 cgroup_skb 的 allowlist 中。修复：

- 事件中的 `pid`/`tgid` 固定为 0，`comm` 固定为空；
- 地址、端口、长度和统计仍然正常；
- 6.18 上也不再依赖这两个 helper，保证同一对象跨内核可加载。

这是功能取舍：旧内核无法在 cgroup_skb 事件里提供进程元数据，但丢包策略不受影响。

## 5. 未覆盖项

- 物理网卡 native XDP、TC hardware offload；
- 生产发行版内核（Ubuntu/Debian/RHEL）与真实容器 cgroup 层级；
- 长时间运行、内存增长、高并发压力；
- 多 LSM 程序叠加顺序和策略冲突；
- 非 x86_64 架构。

这些项目建议在目标 Linux 主机上按 `docs/scenarios/*.md` 的“验证”小节继续执行。

## 6. Linux 测试入口

| 系统 | 命令 | 覆盖 |
|---|---|---|
| Linux | `bash scripts/test-linux.sh` | fmt、ABI 单测、用户态单测、clippy、全部 eBPF bin |
| Linux 完整 | `FULL_BUILD=1 bash scripts/test-linux.sh` | 额外构建 11 个对象 + CLI |
| Linux 运行时 | `sudo -E RUN_RUNTIME=1 FULL_BUILD=1 bash scripts/test-linux.sh` | 额外 XDP `lo` 冒烟 |
| CI | `.github/workflows/ci.yml` | Linux 多版本/多内核矩阵 |

当前只保留 Linux 多版本矩阵；eBPF 运行时只在 Linux。

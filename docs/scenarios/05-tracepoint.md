# 场景 5：Tracepoint — 调度与块设备 I/O 可观测性

## 1. 应用场景

Tracepoint 是内核预置的静态探针，接口稳定、无符号依赖、开销低，适合长期运行的观测：

- 调度：`sched:sched_switch` 观察上下文切换、任务延迟、CPU 争用；
- 块 I/O：`block:block_rq_issue` 观察请求大小、读写比例、设备分布；
- 网络：`net:net_dev_queue`、`tcp:tcp_retransmit_skb` 等；
- 文件系统：`filemap:*`、`writeback:*`。

与 kprobe 的差别：

| | kprobe | tracepoint |
|---|---|---|
| 接口 | 内核函数符号，可能变化 | 预置事件，ABI 稳定 |
| 参数 | 寄存器/栈，需知道函数签名 | 事件结构，字段固定 |
| 开销 | 依赖函数调用频率 | 内核已埋点，通常更低 |
| 可用性 | 需要符号 | 需要内核编译了 tracepoint |

Aya 的优势：

- `TracePoint::attach(category, name)` 直接附加；
- `TracePointContext::read_at` 从原始事件记录读字段；
- 与 ring buffer/per-CPU map 结合。

## 2. 本案例的难点：布局会变

`tracepoint` 的字段布局由内核的 `trace_event_raw_*` 结构决定。以 `sched_switch` 为例，常见布局是：

```c
struct trace_event_raw_sched_switch {
    struct trace_entry ent;   // 8 字节
    char prev_comm[16];       // offset 8
    pid_t prev_pid;           // offset 24
    int prev_prio;            // offset 28
    long prev_state;          // offset 32（64 位）
    char next_comm[16];       // offset 40
    pid_t next_pid;           // offset 56
    int next_prio;            // offset 60
};
```

但 offset 会随内核版本、配置、架构变化。硬编码 offset 是 tracepoint 工具“换内核就坏”的最常见原因。

### 2.1 运行时解析 `format`

tracefs 为每个事件提供格式描述：

```text
$ cat /sys/kernel/tracing/events/sched/sched_switch/format
name: sched_switch
ID: 314
format:
    field:unsigned short common_type;    offset:0;    size:2;    signed:0;
    ...
    field:char prev_comm[16];            offset:8;    size:16;   signed:1;
    field:pid_t prev_pid;                offset:24;   size:4;    signed:1;
    field:long prev_state;               offset:32;   size:8;    signed:1;
    ...
```

用户态 `tracefs.rs`：

1. 定位 tracefs（`/sys/kernel/tracing` 或 `/sys/kernel/debug/tracing`）；
2. 读取 `format`；
3. 对每行 `field:` 提取字段名（去掉数组/指针修饰）、`offset:`、`size:`；
4. 校验必需字段大小；
5. 把 offset 写入 `tp_offsets` map，把采样率写入 `tp_control` map。

eBPF 侧只读 offset，用 `bpf_probe_read_kernel` 读取；即使 offset 不匹配，helper 返回错误，程序跳过事件，不会崩溃。

### 2.2 必需字段与可选字段

`sched_switch` 必需：

| 字段 | 大小 | 用途 |
|---|---|---|
| `prev_comm` | 16 | 前一个任务名 |
| `prev_pid` | 4 | 前一个 PID |
| `prev_prio` | 4 | 前一个静态优先级 |
| `prev_state` | 4 或 8 | 前一个任务状态（`long`） |
| `next_comm` | 16 | 下一个任务名 |
| `next_pid` | 4 | 下一个 PID |
| `next_prio` | 4 | 下一个静态优先级 |

`block_rq_issue` 必需：

| 字段 | 大小 | 用途 |
|---|---|---|
| `dev` | 4 | 设备号 |
| `sector` | 8 | 起始扇区 |
| `nr_sector` | 4 | 扇区数 |
| `rwbs` | 8（新内核可能为 10/16，只读取前 8 字节） | 读写标志文本 |
| `comm` | 16 | 发起进程 |

`bytes` 在旧内核可能缺失，缺失时事件中记 0，不阻止 attach。`rwbs` 在部分新内核中从 8 字节扩展为 10 字节；解析器只要求“至少 8 字节”，事件仍保留前 8 字节。

### 2.3 采样

- `sched_switch` 每次上下文切换都触发，繁忙机器可达数十万次/秒；
- 默认 `--sched-sample 64`，统计精确、事件采样；
- `block_rq_issue` 默认全量；
- 采样在 eBPF 内用 `bpf_get_prandom_u32()`，不消耗 ring buffer 的无效带宽。

### 2.4 数据结构

```rust
struct TracepointOffsets {
    sched_prev_comm: u32, sched_prev_pid: u32, ...
    sched_prev_state_size: u32,
    block_dev: u32, block_sector: u32, ...
    sched_valid: u32, block_valid: u32,
}

struct SchedEvent {
    timestamp_ns: u64,
    prev_pid: u32, next_pid: u32,
    prev_prio: u32, next_prio: u32,
    prev_state: u64,
    prev_comm: [u8; 16],
    next_comm: [u8; 16],
}

struct BlockEvent {
    timestamp_ns: u64, sector: u64,
    nr_sector: u32, bytes: u32, dev: u32,
    rwbs: [u8; 8], comm: [u8; 16],
}
```

## 3. 实验

### 3.1 确认 tracefs 与事件

```bash
ls /sys/kernel/tracing/events/sched/sched_switch/format
ls /sys/kernel/tracing/events/block/block_rq_issue/format
```

如果 `/sys/kernel/tracing` 不存在：

```bash
sudo mount -t tracefs tracefs /sys/kernel/tracing
# 或使用 debugfs
ls /sys/kernel/debug/tracing/events
```

### 3.2 运行

```bash
sudo -E ./target/release/aya-app tracepoint --event all --sched-sample 64
```

### 3.3 制造调度/IO 负载

```bash
# 调度
stress-ng --cpu 4 --timeout 10s
# 块 I/O（oflag=direct 绕过 page cache）
dd if=/dev/zero of=/tmp/aya-test.bin bs=1M count=128 oflag=direct
rm -f /tmp/aya-test.bin
```

### 3.4 预期输出

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

- `switches` 是精确值；`emitted` 是实际写入 ring buffer 的采样数；
- `block` 的 `bytes` 来自事件字段，若内核缺失则为 0；
- `dev` 使用 Linux `new_encode_dev` 解码。

## 4. 参数说明

| 参数 | 默认 | 说明 |
|---|---|---|
| `--event` | `all` | `sched` / `block` / `all` |
| `--sched-sample` | `64` | 每 N 个 sched 事件输出 1 条 |
| `--block-sample` | `1` | 每 N 个 block 事件输出 1 条 |
| `--stats-interval` | `5` | 统计间隔 |

> tracefs 只使用标准挂载点（`/sys/kernel/tracing` 或 `/sys/kernel/debug/tracing`），因为 aya 的 `TracePoint::attach` 也按这两个路径查找。自定义路径请 bind-mount 到标准位置。

## 5. 验证

```bash
# tracepoint 程序
sudo bpftool prog show | grep -A8 tracepoint
sudo bpftool perf show

# map
sudo bpftool map show | grep -E 'tp_(offsets|control|sched|block)'

# 直接看 tracefs 事件计数
cat /sys/kernel/tracing/events/sched/sched_switch/enable
```

如果 attach 失败，先确认：

```bash
cat /sys/kernel/tracing/events/sched/sched_switch/format
cat /sys/kernel/tracing/events/block/block_rq_issue/format
```

## 6. 生产化建议

1. **采样率**：sched 在繁忙机器上默认 1/64；需要全量时评估 ring buffer 和用户态处理能力。
2. **长期运行**：tracepoint ABI 稳定，但仍建议在升级内核后跑一次 `format` 校验。
3. **字段选择**：只读需要的字段；`read_at` 每次都是 helper 调用。
4. **数据量**：把事件聚合到 per-CPU 直方图/计数器，而不是全部送用户态。
5. **时间**：事件时间戳是单调 uptime；需要墙上时间时在用户态做一次偏移换算。
6. **多实例**：多个 agent 同时 attach 同一 tracepoint 会重复采样；用 cgroup/CPU 过滤或集中采集。
7. **替代**：BTF tracepoint（`tp_btf`）可以用 CO-RE 字段访问，类型更安全；本项目刻意使用经典 tracepoint，展示动态 offset 方案。

## 7. 排错

| 现象 | 原因 | 处理 |
|---|---|---|
| `tracefs not found` | 未挂载/路径不同 | `mount -t tracefs tracefs /sys/kernel/tracing`，或挂载 debugfs |
| `field ... not found` | 内核没有该字段/版本不同 | 查看 `format`；当前程序只支持列出的字段 |
| `field ... size` | 布局不兼容（如 32 位 `long`） | `prev_state` 支持 4/8；其他字段需适配 |
| 没有事件 | 采样率过低/负载不足 | 调小 `--sched-sample`；制造负载 |
| 事件乱码 | offset 不匹配 | 检查 `format`，不要硬编码 |
| `perf_event_open` 失败 | 权限/PMU 限制 | root/CAP_PERFMON；检查 `/proc/sys/kernel/perf_event_paranoid` |

## 8. 代码导读

| 文件 | 内容 |
|---|---|
| `aya-app-ebpf/src/programs/tracepoint.rs` | 两个 tracepoint 程序、offset 读取、采样 |
| `aya-app/src/tracefs.rs` | format 解析、字段校验、offset 构建 |
| `aya-app/src/commands/tracepoint.rs` | 选择事件、配置、attach、双 ring buffer |
| `aya-app-common/src/lib.rs` | `TracepointOffsets`/`SchedEvent`/`BlockEvent` |

## 9. 延伸

- 增加 `sched:sched_wakeup`，计算 runqueue 延迟；
- 增加 `block:block_rq_complete`，计算 I/O 延迟；
- 用 `tp_btf` + BTF 做类型安全字段访问；
- 用 `BPF_MAP_TYPE_HISTOGRAM`（数组）做延迟直方图；
- 用 `bpf_get_stackid` 采集内核栈。

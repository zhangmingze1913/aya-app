# 关键代码参考

本文按“用户态调用链 → 通用模块 → eBPF 运行时 → 场景入口”说明关键方法/函数，
便于二次开发时快速定位。使用命令见 [USAGE.md](../USAGE.md)，架构与数据流见
[design.md](design.md)。

## 1. 一次命令的调用链

```text
main.rs::main
  -> cli.rs (clap 解析)
  -> commands::<scenario>::run(args)
       -> ebpf::load(Object::<Scenario>)
       -> 写 config map
       -> program.load() + program.attach(...)
       -> take_percpu / EventStream::take
       -> commands::runner::run_events(...)
            -> EventStream::for_each::<Event>(print_event)
            -> sum_percpu(...) + print_stats(...)
            -> Ctrl-C / detach
```

关键原则：

- `ebpf::load` 只加载当前场景的 object；
- config 在 attach 前写入；
- 事件/统计读取在 attach 后；
- link 由 `Ebpf` 拥有，`drop(bpf)` 即 detach。

## 2. 用户态通用模块

### 2.1 `aya-app/src/main.rs`

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()>
```

初始化日志、提高 memlock、分发 `Cli::Command`。

### 2.2 `aya-app/src/ebpf.rs`

```rust
pub enum Object { Xdp, Tc, Kprobe, Uprobe, Tracepoint, Socket, Lsm, Fentry, RawTp, CgroupSkb, CgroupSysctl }

pub fn load(object: Object) -> anyhow::Result<Ebpf>
pub fn raise_memlock_limit()
pub fn cstring(value: &str) -> anyhow::Result<CString>
```

- `Object`：场景选择器，每个变体对应一个嵌入的 ELF；
- `load`：`include_bytes_aligned!` 选对象，`Ebpf::load` 创建 map；
- `raise_memlock_limit`：启动时把 `RLIMIT_MEMLOCK` 调到 infinity；
- `cstring`：接口名等 C 字符串转换，拒绝内嵌 NUL。

### 2.3 `aya-app/src/event.rs`

```rust
pub struct EventStream { /* AsyncFd<RingBuf<MapData>> */ }

impl EventStream {
    pub fn take(bpf: &mut Ebpf, name: &str) -> anyhow::Result<Self>
    pub async fn for_each<T: Copy>(&mut self, on_event: impl FnMut(T)) -> std::io::Result<()>
}

pub fn decode<T: Copy>(bytes: &[u8]) -> Option<T>
```

- `take`：从 `Ebpf` 取走 ring buffer，注册到 Tokio `AsyncFd`；
- `for_each`：一次 drain 当前所有记录，空后清 readiness；
- `decode`：检查长度后用 `read_unaligned` 解码 `repr(C)` 事件。

### 2.4 `aya-app/src/stats.rs`

```rust
pub fn take_percpu<T: Pod>(bpf: &mut Ebpf, name: &str) -> anyhow::Result<PerCpuArray<MapData, T>>
pub fn sum_percpu<T, F>(map: &PerCpuArray<MapData, T>, merge: F) -> anyhow::Result<T>
where T: Pod + Copy + Default, F: FnMut(&mut T, &T)
```

eBPF 侧所有统计都是 per-CPU，用户态求和得到精确总量；热路径不需要原子操作。

### 2.5 `aya-app/src/format.rs`

| 函数 | 用途 |
|---|---|
| `ipv4(u32) -> String` | 网络序整数 → 点分 IPv4 |
| `ipv4_to_raw(Ipv4Addr) -> u32` | 点分 IPv4 → 网络序整数 |
| `prefix_mask(u8) -> u32` | 前缀长度 → 掩码 |
| `fixed_string(&[u8]) -> String` | NUL 结尾/定长字符串清理 |
| `comm(&[u8;16]) -> String` | 进程名 |
| `path(&[u8;128]) -> String` | 路径 |
| `rwbs(&[u8;8]) -> String` | 块 I/O 标志 |
| `duration_ns(u64) -> String` | ns → 人类可读延迟 |
| `bytes(u64) -> String` | 字节数格式化 |
| `uptime(u64) -> String` | `bpf_ktime_get_ns` → 相对秒 |
| `banner/stats_header` | CLI 输出标题 |
| `eventln!` / `event` / `flush_events` | 高频事件缓冲输出与刷新 |

### 2.6 `aya-app/src/tracefs.rs`

```rust
pub struct Field { pub offset: u32, pub size: u32, /* ... */ }
pub struct Format { /* 字段名 -> Field */ }

impl Format {
    pub fn parse(content: &str) -> anyhow::Result<Self>
    pub fn field(&self, name: &str) -> anyhow::Result<Field>
    pub fn require(&self, name: &str, expected_size: u32) -> anyhow::Result<u32>
    pub fn require_min(&self, name: &str, min_size: u32) -> anyhow::Result<u32>
    pub fn require_one_of(&self, name: &str, sizes: &[u32]) -> anyhow::Result<Field>
}

pub fn find_tracefs(explicit: Option<&Path>) -> anyhow::Result<PathBuf>
pub fn fill_sched_offsets(offsets: &mut TracepointOffsets, tracefs: &Path) -> anyhow::Result<()>
pub fn fill_block_offsets(offsets: &mut TracepointOffsets, tracefs: &Path) -> anyhow::Result<()>
```

用途：从 `/sys/kernel/tracing/events/.../format` 读取字段偏移，避免硬编码内核结构体；
`rwbs` 在 6.1/6.18 上宽度不同，`require_min` 处理这种兼容性。

### 2.7 `aya-app/src/commands/runner.rs`

```rust
pub async fn run_events<S, E>(
    stats: PerCpuArray<MapData, S>,
    events: EventStream,
    interval_secs: u64,
    on_event: impl FnMut(E),
    read_stats: impl FnMut(&PerCpuArray<MapData, S>) -> anyhow::Result<S>,
    print_stats: impl FnMut(&S, &S, u64),
    detach: &str,
) -> anyhow::Result<()>
where S: Pod + Copy + Default, E: Copy
```

统一处理 `tokio::select!` 的 Ctrl-C、事件读取、统计 ticker 和 detach 文案。
`skfilter` 因需要 `accept()`、`tracepoint` 因双 ring，保留专用循环。

### 2.8 `aya-app/src/commands/socket/`

| 文件 | 入口 | 关键动作 |
|---|---|---|
| `mod.rs` | `run(SocketFilterCommand)` | 分发；`attach_mode`/`open_cgroup` |
| `sockops.rs` | `run(SockOpsArgs)` | `SockOps` attach；事件/统计 |
| `skfilter.rs` | `run(SkFilterArgs)` | `TcpListener` + `SocketFilter` attach；accept 循环 |
| `connect4.rs` | `run(Connect4Args)` | `CgroupSockAddr` attach；deny 事件 |

### 2.9 `aya-app/src/commands/tracepoint/`

| 文件 | 入口 | 关键动作 |
|---|---|---|
| `mod.rs` | `run(TracepointArgs)` | tracefs 偏移解析、写 map、双 attach |
| `sched.rs` | `drain` / `read_stats` / `print_stats` | `SchedEvent` |
| `block.rs` | `drain` / `read_stats` / `print_stats` | `BlockEvent` |

## 3. eBPF 通用模块

### 3.1 `aya-app-ebpf/src/utils.rs`

```rust
#[macro_export]
macro_rules! emit_event { ... }

pub fn now_ns() -> u64
pub fn sample(every: u32) -> bool
pub fn read_user_string(ptr: u64, dest: &mut [u8]) -> usize
pub fn comm<C: EbpfContext>(ctx: &C) -> [u8; TASK_COMM_LEN]
pub fn cpu_stats<T>(map: &PerCpuArray<T>) -> Option<&mut T>
pub fn port_in(ports: &[u16; MAX_PORTS], count: u32, port: u16) -> bool
pub fn path_matches_prefixes(path: &[u8; PATH_LEN], prefixes: &[[u8; PREFIX_LEN]; MAX_PREFIXES], prefix_lens: &[u8; MAX_PREFIXES], prefix_count: u8) -> bool
```

- `emit_event!`：`reserve + write + submit`，避免旧内核栈拷贝；
- `sample`：2 的幂用位掩码，否则取模；
- `read_user_string`：`bpf_probe_read_user_str_bytes` 的封装；
- `cpu_stats`：取当前 CPU 的统计槽；
- `port_in`/`path_matches_prefixes`：有界循环匹配。

### 3.2 `aya-app-ebpf/src/net.rs`

| 类型 | 用途 |
|---|---|
| `EthHdr` | 以太网头，含 VLAN 判断 |
| `VlanHdr` | 802.1Q |
| `Ipv4Hdr` | IHL、protocol、分片检查 |
| `TcpHdr` / `UdpHdr` | 端口、TCP 标志 |
| `L4Ports` | 仅 TCP/UDP 端口（4 字节，cgroup_skb 快路径） |
| `Ipv4Ports` | IPv4 + 端口一次读取（24 字节） |
| `IcmpHdr` | type/code |

所有直接包访问都先做 `data..data_end` 边界检查；XDP 使用 `read_packet`，
TC/cgroup 使用 `SkBuffContext::load`。

### 3.3 `aya-app-ebpf/src/bin/<scenario>.rs`

每个入口只做：

```rust
#![no_std]
#![no_main]
#[path = "../utils.rs"] mod utils;
#[path = "../programs/<scenario>.rs"] mod <scenario>;
#[path = "../panic.rs"] mod panic;
```

因此每个 ELF 只包含本场景的 program/map，命令只创建这些 map。

## 4. 典型场景链路

### 4.1 XDP

```text
xdp.rs::run -> Object::Xdp -> xdp_config
  -> xdp_firewall.load/attach
  -> xdp_stats + xdp_events -> runner
```

eBPF：`cgskb` 无 Ethernet 头，XDP 从 `EthHdr` 开始；`xdp_rate` 是 16k LRU。

### 4.2 kprobe

```text
try_kprobe_openat
  -> PROBE_START.insert(pid_tgid, now)
  -> read_user_string(arg1)
  -> path_matches_prefixes
  -> emit_event!(KPROBE_EVENTS, KprobeEvent, ...)
kretprobe
  -> PROBE_START.get_ptr/remove
  -> latency -> KPROBE_KIND_LATENCY
```

`PROBE_START` 由 kprobe/uprobe/fentry 共享，键是 `bpf_get_current_pid_tgid()`。

### 4.3 fentry/fexit

```text
fentry_openat -> PROBE_START.insert
fexit_openat  -> get_ptr/remove -> latency -> FentryEvent
```

BTF trampoline，不需要 kprobe 事件；`<5.5` 或无 BTF 的内核会 attach 失败。

### 4.4 cgroup_skb

```text
cgskb_ingress/egress -> handle
  -> ctx.load(0) Ipv4Hdr
  -> ctx.load(ihl) TcpHdr/UdpHdr
  -> dport == block_port -> 1 (drop)
```

6.6 的 cgroup_skb 不允许 `bpf_get_current_pid_tgid`/`bpf_get_current_comm`，
事件中的 pid/tgid/comm 固定为 0/空；地址/端口/统计仍准确。

## 5. 扩展新场景

1. `aya-app-common` 增加 `#[repr(C)]` 类型和 `size_of` 断言；
2. `aya-app-ebpf/src/programs/<name>.rs` 写 program/map；
3. `aya-app-ebpf/src/bin/<name>.rs` include 模块；
4. `aya-app-ebpf/Cargo.toml` 增加 `[[bin]]`；
5. `aya-app/src/cli.rs` 增加参数；
6. `aya-app/src/commands/` 增加配置/attach/事件；
7. `ebpf.rs` 增加 `Object` 分支；
8. 更新 USAGE/README/场景文档；
9. 运行 `bash scripts/check.sh` 和 Linux 运行时验证。

## 6. 相关文档

- [USAGE.md](../USAGE.md)：环境、构建、11 场景命令；
- [design.md](design.md)：架构、map/program 表、数据流；
- [development.md](development.md)：工具链、构建、扩展、CI；
- [troubleshooting.md](troubleshooting.md)：权限、BTF、XDP/TC、cgroup；
- [usage.md](usage.md)：逐场景详细操作；
- [test-report.md](test-report.md)：Linux 多内核实测。

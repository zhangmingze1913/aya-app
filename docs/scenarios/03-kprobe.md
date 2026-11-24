# 场景 3：kprobe / kretprobe — 内核函数追踪与 openat 监控

## 1. 应用场景

kprobe 可以在**不修改内核源码、不加载内核模块**的前提下，把 eBPF 程序挂到几乎任意内核函数的入口；kretprobe 挂到函数返回。典型用途：

- 安全监控：谁打开了敏感文件、谁调用了危险系统调用；
- 性能分析：系统调用/文件系统/网络函数的耗时分布；
- 故障定位：观察某个内核函数的参数、返回值、调用频率；
- 兼容性探测：确认某内核路径是否存在、参数是否符合预期。

Aya 的优势：

- 通过符号名 attach，不需要写内核模块；
- `ProbeContext::arg(n)` 读取函数参数，`RetProbeContext::ret()` 读取返回值；
- 与 ring buffer/per-CPU map 结合，开销可控；
- 同一套 Rust 代码定义 map 和事件，不需要 C + 单独的用户态。

## 2. 本案例的策略

`kprobe_openat` + `kretprobe_openat` 监控 `do_sys_openat2`：

1. 入口：
   - 用 `bpf_get_current_pid_tgid()` 作为 key，把 `bpf_ktime_get_ns()` 写入 `probe_start`；
   - 读取 arg1（`const char __user *filename`），用 `bpf_probe_read_user_str_bytes` 拷贝到栈上；
   - 如果路径匹配任一前缀，发 `KPROBE_KIND_OPEN` 事件（pid/tgid/uid/comm/path）；
   - 统计 `opens`、`sensitive`。
2. 返回：
   - 从 `probe_start` 取出并删除开始时间；
   - 计算延迟，读取返回值（fd 或 `-errno`）；
   - 超过 `--latency-threshold-us` 时发 `KPROBE_KIND_LATENCY` 事件；
   - 统计 `latency_calls`、`slow_calls`。

### 2.1 为什么是 `do_sys_openat2`

`openat(2)` 在 x86_64 上的调用链大致是：

```text
syscall openat
  → __x64_sys_openat(const struct pt_regs *regs)
  → do_sys_openat2(int dfd, const char __user *filename, struct open_how *how)
  → do_filp_open / vfs_open ...
```

`do_sys_openat2` 是较新内核中多个 open 变体的公共实现，参数稳定、路径是用户指针，适合做路径监控。不同内核可能：

- 没有该符号（被内联/改名）；
- 有 `__x64_sys_openat`，但它的 arg0 是 `pt_regs *`，参数布局不同；
- 有 `do_filp_open`，但参数是 `struct filename *`，需要不同的读取方式。

因此 CLI 暴露 `--symbol`，但**默认符号的参数约定是固定的**：arg1 必须是 `const char __user *`。换成其他符号时，需要同步修改 eBPF 参数解析，不能指望通用。

### 2.2 数据结构

```rust
struct KprobeConfig {
    prefixes: [[u8; 64]; 4],
    prefix_lens: [u8; 4],
    prefix_count: u8,
    latency_threshold_ns: u64,
}

struct KprobeEvent {
    timestamp_ns: u64,
    pid: u32, tgid: u32, uid: u32, kind: u32,
    latency_ns: u64,
    ret: i64,
    path: [u8; 128],
    comm: [u8; 16],
}

struct KprobeStats {
    opens: u64,
    sensitive: u64,
    latency_calls: u64,
    slow_calls: u64,
}
```

### 2.3 前缀匹配与 map 上限

- 最多 4 个前缀，每个 63 字节（数组 64 含 NUL 余量）；
- 匹配是字节级、大小写敏感；
- 循环有固定上界，verifier 可以证明终止；
- `probe_start` 最多 16384 个在途调用；表满时 `insert` 失败，返回事件找不到开始时间，但入口统计仍准确；
- 路径读取失败（坏指针/缺页）时 `read == 0`，不发路径事件。

## 3. 实验

### 3.1 确认符号

```bash
grep -w do_sys_openat2 /proc/kallsyms
```

有输出（地址可能为 0，取决于 `kptr_restrict`）即可。若没有：

```bash
grep -E ' (__x64_sys_openat|do_filp_open|vfs_open)$' /proc/kallsyms
```

此时需要修改程序参数解析，或只做延迟观测（见 3.4）。

### 3.2 运行

```bash
sudo -E ./target/release/aya-app kprobe \
    --symbol do_sys_openat2 \
    --path-prefix /etc/shadow \
    --path-prefix /etc/passwd \
    --latency-threshold-us 500
```

### 3.3 触发路径事件

```bash
cat /etc/shadow >/dev/null
# 或
sudo -u nobody cat /etc/shadow >/dev/null
```

预期：

```text
[open]    t=123.456s pid=12345 tid=12345 comm=cat uid=1000 path=/etc/shadow
[latency] t=123.457s pid=12345 tid=12345 comm=cat 1.23ms     ret=-13
```

- `pid` 是线程组 id，`tid` 是线程 id；
- `uid` 是打开时刻的 uid；
- `ret=-13` 表示 `EACCES`；慢失败和慢成功可区分；
- 延迟事件不带路径（返回时用户缓冲区可能已失效），需要路径请关联入口事件。

### 3.4 只观测延迟

把前缀设为空是不可行的（默认值会生效），可以传一个几乎不会匹配的前缀：

```bash
sudo -E ./target/release/aya-app kprobe \
    --symbol do_sys_openat2 \
    --path-prefix /nonexistent-aya-prefix \
    --latency-threshold-us 100
```

此时只会有 `[latency]` 事件（所有 open 都会计时，只有超过阈值的才上报）。

### 3.5 统计

```text
--- kprobe stats ---
opens      :         1234  (     246.8/s)
sensitive  :            2  (       0.4/s)
latency    : calls=1234     slow=3       (0.6 slow/s)
```

- `opens` 是所有被挂钩的 open 调用；
- `sensitive` 是路径匹配数；
- `latency_calls` 是成功配对的返回数；
- `slow_calls` 是超过阈值的数。

## 4. 参数说明

| 参数 | 默认 | 说明 |
|---|---|---|
| `--symbol` | `do_sys_openat2` | 被挂钩的内核函数 |
| `--path-prefix` | `/etc/shadow,/etc/passwd` | 最多 4 个，每个 ≤63 字节 |
| `--latency-threshold-us` | `1000` | 只上报超过该值的返回 |
| `--stats-interval` | `5` | 统计间隔 |

## 5. 验证与观测

```bash
# 查看已加载的 kprobe 程序
sudo bpftool prog show | grep -A8 -E 'kprobe_openat|kretprobe_openat'

# 查看 perf event / kprobe 链接
sudo bpftool perf show

# 查看 map
sudo bpftool map show | grep -E 'kprobe_(config|stats|events|start)'
```

Aya 使用 `perf_event_open` + `perf_attach` 挂 kprobe，而不是写 tracefs 的 `kprobe_events`。因此 `cat /sys/kernel/tracing/kprobe_events` 可能为空，这是正常的。

## 6. 性能与生产化

1. **过滤在 eBPF 内完成**：只在路径匹配时构造 184 字节事件，避免把所有 open 都送到用户态。
2. **延迟阈值**：只上报慢调用，降低 ring buffer 压力。
3. **map 容量**：16384 个在途调用；高并发 open 场景可能不够，按需调整。
4. **符号稳定性**：内核升级可能改名/内联；生产上优先使用 fentry/fexit + BTF（参数类型安全），或使用 `vfs_open` 等更稳定的函数。
5. **参数安全**：`bpf_probe_read_user_str_bytes` 只读用户地址空间；不要把内核指针传给它。
6. **隐私**：路径可能包含敏感信息；限制前缀、缩短 `PATH_LEN`、控制访问权限。
7. **安全监控**：只监控路径不足以判断“是否成功”；结合返回值、uid、cgroup、父进程。
8. **开销**：每次 open 一次 map 更新 + 最多 128 字节字符串读；通常可接受，但在高 IOPS 文件服务器上要压测。

## 7. 排错

| 现象 | 原因 | 处理 |
|---|---|---|
| `failed to attach ... ENOENT` | 符号不存在/被内联 | `grep /proc/kallsyms`；换符号并改解析 |
| 没有 `[open]`，但有 `opens` | 路径不匹配 / 读取失败 | 换前缀；确认 arg1 是用户指针 |
| 没有 `[latency]` | 延迟低于阈值 / 返回未配对 | 降低阈值；检查 map 是否满 |
| `ret` 看起来是巨大正数 | 返回值被解释为有符号 64 位 | 负数即 `-errno`，用 `-ret` 查 errno |
| 事件路径乱码 | 符号参数不是字符串指针 | 当前实现只适用于 `do_sys_openat2` 约定 |
| 权限错误 | 缺少 CAP_PERFMON/CAP_BPF | root 或补能力 |

## 8. 代码导读

| 文件 | 内容 |
|---|---|
| `aya-app-ebpf/src/programs/kprobe.rs` | 入口/返回程序、map、路径匹配 |
| `aya-app-ebpf/src/utils.rs` | 用户字符串读取、前缀匹配 |
| `aya-app/src/commands/kprobe.rs` | 配置校验、attach、事件打印 |
| `aya-app-common/src/lib.rs` | `KprobeConfig`/`KprobeEvent`/`KprobeStats` |

## 9. 延伸

- 用 `--symbol vfs_open` 做文件打开延迟（需要不同的参数解析）；
- 用 fentry/fexit + BTF 获取类型安全的参数；
- 用 `bpf_get_current_task` / `task_struct` 读取 cgroup/父进程；
- 用 `bpf_get_stackid` 采集内核栈；
- 用 `BPF_MAP_TYPE_HASH` 按 cgroup 聚合延迟直方图。

# 场景 8：fentry / fexit（BTF trampoline）

## 1. 这个场景解决什么问题

`kprobe` 通过断点/探针机制挂到内核函数，兼容性好，但每次调用都有探针开销。  
`fentry`/`fexit` 使用 **BPF trampoline + BTF**，在函数入口/出口直接执行 JIT 代码，不需要
`kprobe_events`，适合高频函数的生产观测。

本案例跟踪：

```c
long do_sys_openat2(int dfd, const char __user *filename,
                    struct open_how *how)
```

- fentry 记录当前 `pid_tgid` 的时间戳；
- fexit 取出时间戳，计算调用延迟，并携带返回值（fd 或 `-errno`）；
- 事件采样只影响 ring buffer，计数器始终精确。

## 2. 前置条件

- Linux ≥ 5.5；
- 内核有 BTF：`/sys/kernel/btf/vmlinux`；
- 内核开启了函数跟踪/trampoline（`CONFIG_FUNCTION_TRACER`、
  `CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS` 等）；
- `do_sys_openat2` 在 BTF 中有 `FUNC` 记录。

检查：

```bash
test -e /sys/kernel/btf/vmlinux && echo "BTF ok"
cat /sys/kernel/tracing/available_tracers
# 期望包含 function/function_graph，而不是只有 nop
```

> 精简内核（例如 Alpine `linux-virt`）可能只有 `nop`，此时 fentry/fexit 无法 attach；
> 请换发行版的通用内核。

## 3. 运行

```bash
sudo -E ./target/release/aya-app fentry \
    --symbol do_sys_openat2 \
    --latency-threshold-us 0
```

另开终端触发：

```bash
cat /etc/hosts >/dev/null
cat /etc/passwd >/dev/null
```

## 4. 预期输出

```text
=== fentry/fexit tracing ===
  function          : do_sys_openat2
  latency threshold : 0 us
  event sample      : 1/1

[fexit] t=... pid=2101 tid=2101 comm=cat uid=0 1.20ms     ret=3
[fexit] t=... pid=2101 tid=2101 comm=cat uid=0 842.0us    ret=3

--- fentry/fexit stats ---
enters :            2  (       0.4/s)
exits  :            2  (       0.4/s)
slow   :            2  (       0.4/s)  missing_starts=0
```

## 5. 参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--symbol` | `do_sys_openat2` | BTF 中的函数名 |
| `--latency-threshold-us` | `0` | 只输出超过阈值的退出事件 |
| `--event-sample` | `1` | 退出事件采样率 |
| `--stats-interval` | `5` | 统计打印间隔（秒） |

## 6. 与 kprobe 的对比

| 维度 | kprobe | fentry/fexit |
|---|---|---|
| 挂载方式 | 断点/探针 | BTF trampoline |
| 对函数的要求 | 符号存在即可 | BTF FUNC + trampoline 支持 |
| 每个调用的开销 | 较高 | 接近零 |
| 参数读取 | `pt_regs`/寄存器约定 | BTF 类型化参数 |
| 典型用途 | 调试、兼容旧内核 | 生产高频观测 |

## 7. 排错

| 现象 | 原因 | 处理 |
|---|---|---|
| `failed to load ...` | 函数不在 BTF / 内核无 BTF | 换函数或换带 BTF 的内核 |
| `failed to attach ... EBUSY` | 缺少 trampoline/ftrace 支持 | 检查 `available_tracers`，换通用内核 |
| `missing_starts` 增长 | 同一线程嵌套 open，起始时间被覆盖 | 使用更细的 key，或只跟踪单层调用 |
| 没有事件 | 函数未命中/采样率过低 | 用 `--event-sample 1` 验证 |

## 8. 验证

```bash
sudo bpftool prog show | grep -E 'fentry|fexit'
sudo bpftool map show | grep fentry
cat /etc/hosts >/dev/null
```

需要看 verifier 日志时：

```bash
sudo RUST_LOG=debug ./target/release/aya-app fentry
```

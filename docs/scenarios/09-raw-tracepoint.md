# 场景 9：raw tracepoint（`sys_enter`）

## 1. 这个场景解决什么问题

普通 tracepoint 程序拿到的是内核预先展开的 `trace_event_raw_*` 记录，字段和偏移由
tracefs `format` 决定。**raw tracepoint** 直接拿 tracepoint 的 `TP_PROTO` 参数：

```c
TP_PROTO(struct pt_regs *regs, long id)
```

因此不需要解析 tracefs 格式，开销更低，适合高频系统调用观测。

本案例在 `sys_enter` 上过滤一个系统调用号（默认 x86_64 legacy `open` = 2，`cat` 会使用它；
现代 glibc 程序通常使用 `openat` = 257 或 `openat2` = 437），记录
`pid/tgid/uid/comm/syscall_nr`。

## 2. 前置条件

- Linux ≥ 4.17（raw tracepoint）；
- root 或 `CAP_PERFMON`/`CAP_BPF`（取决于内核）；
- `/sys/kernel/tracing/events/syscalls/sys_enter` 存在。

检查：

```bash
test -d /sys/kernel/tracing/events/syscalls/sys_enter && echo ok
```

## 3. 运行

```bash
sudo -E ./target/release/aya-app raw-tp
```

触发：

```bash
cat /etc/hosts >/dev/null
```

aarch64 上 `openat` 是 56；x86_64 的 `openat` 是 257：

```bash
sudo -E ./target/release/aya-app raw-tp --syscall-nr 56
sudo -E ./target/release/aya-app raw-tp --syscall-nr 257
```

## 4. 预期输出

```text
=== raw tracepoint sys_enter ===
  tracepoint     : sys_enter (TP_PROTO: pt_regs *, long id)
  syscall filter : 2 (open)
  event sample   : 1/1

[sys_enter] t=... pid=2105 tid=2105 comm=cat uid=0 nr=2

--- raw tracepoint stats ---
matches :            1  (       0.2/s)
emitted :            1  (       0.2/s)
```

## 5. 参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--syscall-nr` | `2` | 要过滤的系统调用号，架构相关（`open`=2，`openat`=257） |
| `--event-sample` | `1` | 匹配事件采样率 |
| `--stats-interval` | `5` | 统计打印间隔（秒） |

## 6. 与普通 tracepoint 的对比

| 维度 | tracepoint | raw tracepoint |
|---|---|---|
| 上下文 | `trace_event_raw_*` 记录 | `TP_PROTO` 原始参数 |
| 字段定位 | 解析 tracefs format | 直接按参数下标读取 |
| 依赖 tracefs | 需要 format | 不需要 format |
| 开销 | 有记录展开成本 | 更低 |
| 典型用途 | 观测稳定字段 | 高频 syscall/调度路径 |

## 7. 排错

| 现象 | 原因 | 处理 |
|---|---|---|
| `failed to attach ... ENOENT` | 内核没有该 raw tracepoint | 检查 `/sys/kernel/tracing/events` |
| 有匹配但没有事件 | 采样率/系统调用号不对 | 用 `--event-sample 1`，确认架构 |
| `matches=0` | 过滤的 syscall 没被触发 | 用 `strace -e openat` 或直接 `cat` 验证 |
| 权限错误 | 没有 `CAP_BPF`/`CAP_PERFMON` | 用 root 运行 |

## 8. 验证

```bash
sudo bpftool prog show | grep raw_tp
sudo bpftool link show
```

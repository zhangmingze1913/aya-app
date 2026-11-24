# 场景 4：uprobe / uretprobe — 用户态应用性能剖析

## 1. 应用场景

uprobe 把 eBPF 程序挂到用户态 ELF 文件的某个符号/偏移上；uretprobe 挂到函数返回。典型用途：

- 数据库/中间件调用链：MySQL `mysql_query`、Redis 命令处理、gRPC 服务方法；
- 应用性能剖析：函数耗时、请求参数、返回值；
- 故障定位：某个库函数被谁调用、调用频率、慢调用；
- 无需修改应用代码，也不需要重新编译（只要符号存在）。

与 kprobe 的差别：

| | kprobe | uprobe |
|---|---|---|
| 目标 | 内核函数 | 用户态 ELF 符号/偏移 |
| 参数读取 | 内核寄存器/栈 | 用户态寄存器/栈 + 用户内存 helper |
| 符号 | `/proc/kallsyms` | `nm`/`readelf`/ELF symbol table |
| 典型用途 | 内核路径/系统调用 | 应用函数/库函数 |

Aya 的优势：

- `UProbe::attach(points, target, scope)` 支持符号、符号+偏移、绝对偏移；
- `UProbeScope` 支持所有进程、当前进程、指定 PID；
- 与 ring buffer / per-CPU map 结合，用户态只负责配置和展示。

## 2. 本案例：自带 demo 目标

为了让示例可复现，项目包含 `aya-app-demo`，导出两个 C ABI 符号：

```c
void demo_handle_request(uint64_t request_id, const char *path);
void demo_slow_query(uint64_t ms);
```

- `#[unsafe(no_mangle)]` 保证符号名不被 Rust mangling；
- `#[inline(never)]` 保证 release 构建中仍是真实函数；
- `demo_handle_request` 内部 sleep 2–8ms，制造可观测延迟；
- `demo_slow_query` 可用于第二个 uprobe 目标。

### 2.1 程序逻辑

`uprobe_request`（入口）：

1. `pid_tgid` 作为 key，记录开始时间；
2. 读取 arg0（`request_id`，u64）；
3. 读取 arg1（`path`，`const char *`），用 `bpf_probe_read_user_str_bytes`；
4. 发 `UPROBE_KIND_ENTER` 事件（pid/tgid/comm/request_id/path）。

`uretprobe_request`（返回）：

1. 取出并删除开始时间；
2. 计算延迟；
3. `ctx.ret::<i64>()` 读取返回值（demo 返回 void，值为 0）；
4. 超过阈值时发 `UPROBE_KIND_EXIT` 事件。

### 2.2 数据结构

```rust
struct UprobeConfig {
    latency_threshold_ns: u64,
}

struct UprobeEvent {
    timestamp_ns: u64,
    pid: u32, tgid: u32, kind: u32,
    request_id: u64,
    latency_ns: u64,
    ret: i64,
    path: [u8; 128],
    comm: [u8; 16],
}

struct UprobeStats {
    enters: u64,
    exits: u64,
    slow_calls: u64,
}
```

## 3. 实验

### 3.1 构建 demo

```bash
cargo build --release -p aya-app-demo
nm -C target/release/aya-app-demo | grep demo_
```

应看到：

```text
0000000000001234 T demo_handle_request
00000000000012a0 T demo_slow_query
```

> `nm` 的地址是文件内偏移；aya 的 `UProbe::attach("symbol", path, scope)` 会解析符号表并计算实际地址，通常不需要手动加偏移。

### 3.2 启动目标并附加

```bash
# 终端 A：每 20ms 一次请求
./target/release/aya-app-demo 500

# 终端 B：附加
sudo -E ./target/release/aya-app uprobe \
    --binary ./target/release/aya-app-demo \
    --symbol demo_handle_request
```

也可以先附加、再启动目标（默认 `AllProcesses`）：

```bash
sudo -E ./target/release/aya-app uprobe \
    --binary ./target/release/aya-app-demo \
    --symbol demo_handle_request &
./target/release/aya-app-demo 100
```

### 3.3 预期输出

```text
=== uprobe function tracing ===
  binary            : /path/aya-app-demo
  symbol            : demo_handle_request
  scope             : all processes
  latency threshold : 1000 us
Ctrl-C 退出。示例：先运行 target/release/aya-app-demo，再执行本命令。

[enter] t=12.345s pid=4242 tid=4242 comm=aya-app-demo request_id=0 path=/api/v1/orders/0
[exit]  t=12.349s pid=4242 tid=4242 comm=aya-app-demo 4.01ms     ret=0
...
```

- `request_id` 只在 enter 事件中；exit 事件无法恢复参数；
- 默认阈值 1000us，demo sleep 2–8ms，因此每个调用都会出现 exit；
- 想只看慢调用，把 `--latency-threshold-us` 调大（如 5000）。

### 3.4 指定 PID

```bash
./target/release/aya-app-demo 1000 &
DEMO_PID=$!
sudo -E ./target/release/aya-app uprobe \
    --binary ./target/release/aya-app-demo \
    --symbol demo_handle_request \
    --pid "$DEMO_PID"
```

`--pid` 使用 `UProbeScope::OneProcess`，只对该进程生效。目标进程必须在 attach 时存在（uprobe 需要映射其地址空间）；先 attach 再启动不适用于 PID 模式。

## 4. 参数说明

| 参数 | 默认 | 说明 |
|---|---|---|
| `--binary` | 必填 | 目标 ELF 路径（会被 canonicalize） |
| `--symbol` | `demo_handle_request` | ELF 符号名（aya 精确匹配，不做 demangle） |
| `--pid` | 无 | 只挂钩指定进程 |
| `--latency-threshold-us` | `1000` | 只上报超过该值的返回 |
| `--stats-interval` | `5` | 统计间隔 |

> 当前 CLI 只传符号名，不暴露绝对偏移。需要偏移时可用 `UProbeAttachLocation::SymbolOffset/AbsoluteOffset` 扩展命令。

## 5. 真实世界案例

### 5.1 MySQL / MariaDB

常见目标：

```text
mysql_query(MYSQL *mysql, const char *query)
mysql_real_query(MYSQL *mysql, const char *query, unsigned long length)
```

- `mysql_query` 的 arg1 是 SQL 字符串（用户态指针），可以按本案例的方式读取；
- `mysql_real_query` 的 arg2 是长度，读取时应使用长度而不是 NUL 终止；
- 需要安装带符号的 `libmysqlclient`/`mariadb`，或使用 `mysqld` 的内部符号；
- 生产上不要把完整 SQL 写入日志（隐私/体积）；可只记录长度、指纹或前 N 字节。

### 5.2 Redis

Redis 的请求处理路径通常是：

```text
readQueryFromClient
  → processCommand
  → call(client *c, int flags)
```

`call` 的参数是 `client *` 和 flags，命令内容在 `client->argv` 中，需要按 `client` 结构体偏移读取（依赖版本）。更稳定的做法是挂 `processCommand` 并用 BTF/结构体偏移，或使用 Redis 的 `COMMAND` 统计。本案例的“读 arg 字符串”方法只适用于参数直接是 `char *` 的函数。

### 5.3 gRPC C++

gRPC 的方法符号通常是 C++ mangled name，例如：

```bash
nm -C /usr/lib/libgrpc.so | grep -i 'Server::RequestCall'
```

- 用 `nm -C` 找到 demangle 后的名字，再用 `nm` 的原始符号名传给 `--symbol`（aya 按 ELF 符号表精确匹配，不做 demangle）；
- C++ 成员函数的第一个参数是 `this`，后续参数按 ABI 传递；
- 需要处理异常/内联；`-fno-omit-frame-pointer` 和调试符号有帮助；
- 生产上优先使用 OpenTelemetry/gRPC interceptor，而不是对每个请求做 uprobe。

### 5.4 共享库与 PIE

- uprobe 按“文件 + 偏移”工作；共享库被多个进程映射时，`AllProcesses` 会对所有映射该文件的进程生效；
- PIE 可执行文件的符号地址是文件内偏移，aya 负责解析；
- 容器中使用时，`--binary` 必须是**容器内路径**对应的宿主路径（或进入容器命名空间执行）；
- 被 strip 的二进制没有符号表，只能用绝对偏移（需要自己计算）。

## 6. 性能与生产化

1. **阈值过滤**：只在慢调用时发 exit 事件；enter 事件仍会产生，若调用频率极高，可在 BPF 侧加采样。
2. **参数体积**：路径最多 128 字节；生产上可缩短或只记录 hash。
3. **map 容量**：16384 个在途调用；递归/高并发可能不够。
4. **符号稳定性**：升级库后符号名/ABI 可能变化；用 CI 做符号存在性检查。
5. **安全**：uprobe 可以读取目标进程的用户内存；遵守隐私与合规要求。
6. **替代方案**：应用内埋点、OpenTelemetry、perf、USDT 通常更稳定；uprobe 适合“无法改代码”的场景。
7. **开销**：每次函数调用一次 map 更新 + 一次用户字符串读；高频函数（如 malloc）不适合。

## 7. 排错

| 现象 | 原因 | 处理 |
|---|---|---|
| `failed to attach ... ENOENT` | 符号不存在/被 strip | `nm`/`readelf -s` 确认；用偏移 |
| 没有事件 | 目标没运行 / scope 不匹配 / 符号被内联 | 检查 PID、进程、`nm` |
| 路径乱码 | arg1 不是 `char *` | 当前 demo ABI 是 `(u64, char*)`；其他函数要改解析 |
| 事件很多但 exit 少 | 阈值过滤 / 返回未配对 | 降低阈值；检查 map |
| 容器内无效 | 路径是宿主视角 | 在容器命名空间内执行或传宿主路径 |
| `Operation not permitted` | 缺少 CAP_PERFMON/CAP_BPF | root 或补能力 |

## 8. 代码导读

| 文件 | 内容 |
|---|---|
| `aya-app-demo/src/main.rs` | 目标函数、C ABI、no_mangle |
| `aya-app-ebpf/src/programs/uprobe.rs` | 入口/返回程序、参数读取 |
| `aya-app/src/commands/uprobe.rs` | 路径校验、scope、attach |
| `aya-app-common/src/lib.rs` | `UprobeConfig`/`UprobeEvent`/`UprobeStats` |

## 9. 延伸

- 增加 `--offset` 支持绝对偏移和符号+偏移；
- 用 `bpf_get_stackid` 采集用户栈；
- 用 USDT（SystemTap SDT）替代 uprobe，获得稳定探针；
- 用 `uprobe_multi` 一次附加多个符号（aya 支持 `UProbeAttachPoint` 列表）；
- 用 uretprobe 读取返回值并做错误率统计。

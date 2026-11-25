# 代码结构与性能重新评估

评估对象：11 场景版本。本文记录评估结论、已执行的优化，以及仍然保留的取舍。

## 0. 执行摘要

本轮不是只写建议，已执行：

1. **按场景拆分 eBPF object**：每个命令只加载本场景的 object，只创建本场景的 map；
2. **XDP rate LRU 从 65,536 降到 16,384**（XDP object 仍有独立容量，可按需调大）；
3. **kprobe/uprobe/fentry 共享 `probe_start`**（每个 object 内只保留一份）；
4. **采样率 2 的幂时用位掩码替代取模**；
5. **抽取 `commands/runner.rs`**：统一事件/统计/Ctrl-C/detach 循环，命令只保留配置、attach 和打印差异。

结果（同一个 `xdp` 命令，QEMU/Alpine `6.18.35-0-lts`）：

| 指标 | 优化前 | 优化后 |
|---|---:|---:|
| map memlock | 13,381,440 B ≈ 12.76 MiB | 1,727,712 B ≈ 1.65 MiB |
| XDP 启动（TCG） | 1.42s | 0.37s |
| XDP 对象内 ring buffer | 13 个（全场景） | 1 个 |
| 静态 CLI | 3.7 MB | 4.41 MB（嵌入 11 个对象） |
| 冷构建 | 11 次 feature 构建 | 1 次 `--bins`；本机约 2m30，热构建约 1m23 |

> 启动时间受 QEMU TCG 影响，真实硬件会小很多；内存数据来自 `bpftool map show` 的
> `memlock` 字段，是内核实际值。

## 1. 结构现状

```text
aya-app-common   ── 共享 #[repr(C)] ABI + size_of 断言
aya-app-ebpf     ── 11 个 [[bin]]，每个 bin 生成一个独立 object
aya-app          ── clap CLI + 11 个 command + Object 选择 + EventStream/Stats
aya-app-demo     ── uprobe 目标
```

构建链：

```text
aya-app/build.rs
  aya-build --bins -> bpf-linker -> OUT_DIR/<scenario> (11 个)
  copy -> OUT_DIR/aya-app-<scenario>
  embed all objects into aya-app
```

运行时：

```text
command -> ebpf::load(Object::Xdp | Object::Lsm | ...)
        -> Ebpf::load(selected object)
        -> only that object's maps/programs
```

### 仍然存在的结构问题

| 问题 | 位置 | 影响 |
|---|---|---|
| 11 个 object 的构建/嵌入 | `build.rs` | 首次构建和 CLI 体积 |
| `socket.rs` / `tracepoint.rs` | 已拆为子模块 | 已缓解 |
| 11 个对象嵌入同一个 CLI | `aya-app` | 二进制约 4.41 MB；换来运行时按场景加载 |
| eBPF 解析器分散 | XDP/TC/cgroup_skb | 三套 L3/L4 解析逻辑 |

## 2. 性能数据

### 2.1 优化前基线

```text
TOTAL_MEMLOCK=13381440     # 12.76 MiB
ringbuf count=13
ringbuf bytes=3585088      # 3.42 MiB
hash bytes=4018240         # 3.83 MiB（3 × 16k start + skfilter）
lru_hash bytes=5768064     # 5.50 MiB（xdp_rate 65k）
xdp startup=1.42s（TCG）
```

### 2.2 优化后

```text
xdp map memlock=1727712    # 1.65 MiB
xdp ringbuf count=1
lsm map memlock=276480     # 270 KiB
xdp startup=0.37s（TCG）
```

`xdp` 对象现在只包含：

```text
xdp_config, xdp_stats, xdp_rate (16k), xdp_events
```

`lsm` 对象只包含：

```text
lsm_config, lsm_stats, lsm_events
```

### 2.3 XDP LRU 容量

`XDP_RATE_ENTRIES = 16_384`。容量是策略参数：

- 16k 适合实验和小规模防护；
- 生产大规模 DDoS 可在 `xdp.rs` 调大，或给 XDP 单独做更细的源前缀聚合；
- 由于已拆分 object，调大只影响 `xdp` 命令，不再拖累其他场景。

## 3. 已执行的优化细节

### 3.1 按场景拆分 eBPF object（单次多 bin 构建）

- `aya-app-ebpf/Cargo.toml` 声明 11 个 `[[bin]]`；
- `src/bin/<scenario>.rs` 只 include 本场景模块、`net/utils` 和 panic handler；
- `build.rs` 调用一次 `aya-build --bins`，一次 Cargo 调用构建全部 bin；
- 产物复制为 `OUT_DIR/aya-app-<scenario>`；
- `aya-app/src/ebpf.rs` 用 `Object` 枚举选择对象；
- `AYA_BUILD_SKIP` 为每个对象写占位文件，类型检查仍可用。

相比最初的 11 次 feature 构建，这减少了重复的 Cargo/`core` 启动成本，也移除了
`#[cfg(feature = ...)]` 的模块裁剪代码。

### 3.2 共享 `probe_start`

`programs/probe.rs` 中一个 `probe_start` HashMap 供 kprobe/uprobe/fentry 使用。
每个 object 内只有一份，避免三个 16k map。

### 3.3 采样位掩码

```rust
if every.is_power_of_two() {
    random & (every - 1) == 0
} else {
    random % every == 0
}
```

默认 1/16、1/64 不再执行 32 位除法。

### 3.4 统一 runner

新增 `aya-app/src/commands/runner.rs`：

- `run_events`：RingBuf + 定时统计 + Ctrl-C + detach；
- xdp/tc/kprobe/uprobe/lsm/fentry/raw-tp/cgroup_skb/cgroup_sysctl/sockops/connect4
  已迁移到该 runner；
- skfilter 保留自己的 accept 循环；tracepoint 保留两个事件流的专用循环。

这减少了命令中的重复 `tokio::select!`/ticker/previous 状态。

### 3.5 统一事件发射宏

`utils.rs` 新增 `emit_event!`：

- 所有场景的 ring buffer 事件统一走 `reserve + write + submit`；
- 避免每个模块重复 `if let Some...`，也避免回退到 `output(&event)` 的栈拷贝；
- 满 ring 时统一丢弃事件，per-CPU 统计仍然精确。

这既减少重复代码，也把“旧内核 verifier 栈限制”的兼容性修复集中到一处。

### 3.6 cgroup_skb 单次头部读取

`cgroup_skb` 原来先 `load::<Ipv4Hdr>(0)` 再 `load::<TcpHdr/UdpHdr>(ihl)`：

- 第一次 20 字节；
- TCP 情况第二次复制完整 20 字节 TCP 头，而只用到 4 字节端口。

现在 `net.rs` 增加 `L4Ports`（4 字节）和 `Ipv4Ports`（IPv4 20 + ports 4）：

- 常见 `IHL == 20`：一次 24 字节 helper 读取，拿到地址和端口；
- `IHL > 20`：回退到 `load::<L4Ports>(ihl)`，只复制 4 字节；
- 减少一次 helper 调用和 TCP 头复制，栈占用也更小。

这是热路径微优化，不改变过滤语义或事件 ABI。

### 3.7 高频事件输出缓冲

`println!` 在高频 tracepoint/sockops 场景会逐行锁 stdout。现在：

- `format::event` 使用进程级 `Mutex<BufWriter<Stdout>>`（避免 Tokio 多线程
  task 迁移导致 thread-local 缓冲丢失）；
- 事件打印统一走 `eventln!`；
- `runner`、`skfilter`、`tracepoint` 在每个统计周期和 detach 前
  `flush_events()`，保证事件与统计的顺序；
- banner/统计仍用 `println!`，不会被打乱。

这减少逐行写 syscall，同时避免把事件缓冲到进程退出而丢失。

## 4. 已完成的代码质量项

### 4.1 `socket` / `tracepoint` 拆分

- `commands/socket/{mod,sockops,skfilter,connect4}.rs`；
- `commands/tracepoint/{mod,sched,block}.rs`。

命令入口只负责分发/配置/attach，事件读取和打印各自独立。

### 4.2 多 bin 单次构建

`aya-app-ebpf` 从 11 次 feature 构建改为 11 个 `[[bin]]` + 一次
`aya-build --bins`，减少 Cargo 启动和重复 `core` 编译。

## 5. 剩余热路径优化

- `sample` 已优化；
- `cgroup_skb` 已改为单次 IPv4+端口前缀读取；进一步 direct packet access
  仍受 Aya `SkBuffContext` 安全 API 限制；
- 高频事件已使用 `BufWriter`；剩余可做的是按速率动态调整 flush 周期；
- 高频事件打印可改 `BufWriter`/批量输出；
- Linux 运行时绝对时间仍以目标硬件为准。

## 6. 结论

| 维度 | 评价 |
|---|---|
| 可读性/可维护性 | 良好；runner、socket/tracepoint 子模块、事件宏已收敛 |
| eBPF 热路径 | 良好：无分配、有界循环、per-CPU、采样、in-place ring 写入 |
| 内存效率 | 从“单命令 12.76 MiB”降到 XDP 1.65 MiB / LSM 270 KiB |
| 启动成本 | TCG 下 1.42s → 0.37s |
| 生产就绪度 | 明显提升；剩余主要是热路径微优化 |

## 7. 复现

```bash
# 构建 11 个对象 + CLI
cargo build --release

# guest root：观察单个场景的 map
killall aya-app 2>/dev/null
timeout 15 ./aya-app xdp --iface lo --mode skb --block-icmp &
sleep 2
bpftool map show | awk '/memlock/ {gsub(/B/,"",$NF); s+=$NF} END {print s}'
bpftool map show | grep -c ringbuf
killall aya-app
```

> 测量前清理旧 `aya-app`/`timeout`，否则旧进程的 map 会污染结果。

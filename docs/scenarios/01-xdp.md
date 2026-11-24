# 场景 1：XDP — 驱动层 DDoS 防护与单 IP 限速

## 1. 应用场景

XDP（eXpress Data Path）把 eBPF 程序挂在网卡驱动的接收路径上。数据包在进入内核协议栈之前就能被处理，**被丢弃的包不会分配 `sk_buff`，也不会走 netfilter/路由/传输层**。典型用途：

- DDoS 清洗：SYN flood、UDP flood、ICMP flood 的前端丢弃；
- 负载均衡前段：按五元组选择后端、快速转发或丢弃；
- 单 IP/单前缀限速：在最早的位置止损；
- 采集：把采样包送到 AF_XDP 或 ring buffer。

XDP 的优势来自位置，而不是“eBPF 一定比内核快”：

| 模式 | 执行位置 | 兼容性 | 性能 | 何时使用 |
|---|---|---|---|---|
| `skb`（generic） | 协议栈中，仍会分配 skb | 最好，lo/veth/大多数驱动 | 较低 | 实验、驱动不支持时 |
| `driver`（native） | 网卡驱动 receive path | 需要驱动支持 | 高 | 生产网卡 |
| `hw` | 网卡硬件 offload | 少数网卡 | 最高 | 特定硬件 |

多队列网卡上，XDP 程序会在每个 RX queue 上并行执行；本项目用 per-CPU 统计避免跨核争用。

> “延迟低于 1 微秒”是特定硬件/驱动的典型量级，不是本项目可保证的 SLA。请以目标机器的 `bpftool`/`perf`/压测结果为准。

## 2. 本案例的策略

`xdp_firewall` 实现三件事：

1. **ICMP echo 过滤**：只丢弃 ICMP type 8（echo request），不是丢弃所有 ICMP。这样不会破坏 PMTUD、traceroute、ICMP 错误传递。
2. **单源 IP 限速**：固定 1 秒窗口，`LruHashMap<u32, RateState>` 记录每个源 IP 的窗口起点和计数；超过 `--rate-limit` 的包返回 `XDP_DROP`。
3. **目的前缀保护**：`--protected-ip` + `--protected-prefix-len` 限定策略只对某个目的前缀生效，避免误伤其他流量。不填则作用于所有目的地址。

同时：

- **精确统计**：`PerCpuArray<XdpStats>` 记录 pass/drop/bytes，用户态每秒求和；
- **采样事件**：丢弃事件按 `--event-sample` 采样写入 ring buffer，避免高 PPS 下 ring buffer 成为瓶颈；
- **fail-open**：解析失败（非 IPv4、截断、非首片段、VLAN 过深）一律 `XDP_PASS`。

### 2.1 数据结构

```rust
struct XdpConfig {
    block_icmp: u32,
    rate_limit_pps: u32,
    protected_ip: u32,      // 原始网络序表示
    protected_mask: u32,
    event_sample: u32,
}

struct XdpStats {
    passed: u64,
    dropped_icmp: u64,
    dropped_rate: u64,
    passed_bytes: u64,
    dropped_bytes: u64,
}

struct RateState {
    window_start_ns: u64,
    count: u32,
}
```

### 2.2 处理流程

```text
XDP 入口
  ├─ 读配置；失败 → PASS
  ├─ 解析 Ethernet（最多 2 层 VLAN）+ IPv4
  │    ├─ 非 IPv4 / 截断 / 非首片段 → PASS + 计数
  │    └─ 提取 saddr/daddr/protocol/l4_offset
  ├─ 目的前缀不在保护范围 → PASS
  ├─ block_icmp && ICMP type 8 → 计数 + 采样事件 + DROP
  ├─ rate_limit_pps > 0 && 超过窗口配额 → 计数 + 采样事件 + DROP
  └─ PASS + 计数
```

### 2.3 为什么用固定窗口而不是令牌桶

严格令牌桶需要每包一次乘除/浮点或复杂的整数定标，且要在 XDP 的 64 位整数上小心溢出。固定窗口只需要一次减法/比较：

```text
now - window_start >= 1s  → 新窗口，count=1
count >= limit            → 丢弃
否则                       → count += 1
```

代价是窗口边界最坏允许 2 倍速率（例如 limit=100，可能在 1.01 秒内通过 200 个包）。对 DDoS 止损足够；如果需要严格速率，请改成 `tokens = min(cap, tokens + elapsed * rate)` 的定点令牌桶。

## 3. 实验：veth + netns

在 `lo` 上做 XDP 往往受 loopback 路径影响，最可靠的实验环境是两个 netns 之间的 veth。

```bash
# 1. 创建 netns 和 veth
sudo ip netns add aya-xdp
sudo ip link add veth-host type veth peer name veth-xdp
sudo ip link set veth-xdp netns aya-xdp

# 2. 配地址、起接口
sudo ip addr add 10.20.0.1/24 dev veth-host
sudo ip link set veth-host up
sudo ip netns exec aya-xdp ip addr add 10.20.0.2/24 dev veth-xdp
sudo ip netns exec aya-xdp ip link set veth-xdp up
sudo ip netns exec aya-xdp ip link set lo up
```

确认连通：

```bash
sudo ip netns exec aya-xdp ping -c 1 10.20.0.1
```

### 3.1 附加 XDP

```bash
sudo -E ./target/release/aya-app xdp \
    --iface veth-host \
    --mode driver \
    --block-icmp \
    --rate-limit 20 \
    --protected-ip 10.20.0.1 --protected-prefix-len 32
```

如果 `driver` 模式失败（`EINVAL`/`ENOTSUP`/`Operation not supported`），改用 generic：

```bash
sudo -E ./target/release/aya-app xdp \
    --iface veth-host --mode skb \
    --block-icmp --rate-limit 20 \
    --protected-ip 10.20.0.1 --protected-prefix-len 32
```

### 3.2 触发 ICMP 丢弃

```bash
sudo ip netns exec aya-xdp ping -c 5 10.20.0.1
```

预期：ping 全部超时；aya-app 终端出现：

```text
[drop] t=12.345s 10.20.0.2 -> 10.20.0.1 len=98 reason=icmp
```

### 3.3 触发限速

先只开限速（不 block ICMP），或同时开着也可以。用 flood ping：

```bash
sudo ip netns exec aya-xdp ping -f -c 200 10.20.0.1
```

预期：前 20 个左右通过，后续大量 `reason=rate`；统计中 `dropped_rate` 增长。注意固定窗口的边界效应。

### 3.4 统计输出

```text
--- XDP stats ---
pass :         1234  (   246.8 pkt/s,   123456.7 B/s)
drop : icmp=98           rate=176        (54.8 drop/s, 12.3 KiB/s)
bytes: pass=1.2 MiB      drop=34.5 KiB
```

- `pass`/`drop` 是精确值（per-CPU 求和）；
- 事件是采样值，默认 1/64，所以 `[drop]` 行数远少于实际丢包数；
- 事件中的 `t=` 是 `bpf_ktime_get_ns()` 的 uptime 秒数，不是墙上时间。

## 4. 参数说明

| 参数 | 默认 | 说明 |
|---|---|---|
| `--iface` | `lo` | 网卡名；veth 实验用 `veth-host` |
| `--mode` | `default` | `skb` / `driver` / `hw` |
| `--block-icmp` | 关闭 | 丢弃保护范围内的 ICMP echo request |
| `--rate-limit` | `0` | 每源 IP 每秒包数；0 = 关闭 |
| `--protected-ip` | 无 | 受保护目的 IPv4；不填 = 所有目的 |
| `--protected-prefix-len` | `32` | 与 `--protected-ip` 配合 |
| `--event-sample` | `64` | 每 N 个丢弃事件写 1 条 |
| `--stats-interval` | `5` | 统计打印间隔（秒） |

## 5. 验证

```bash
# 查看 XDP 程序/链接
sudo bpftool net show
sudo bpftool prog show | grep -A5 xdp_firewall
sudo ip link show veth-host

# 查看 map
sudo bpftool map show | grep -E 'xdp_(config|stats|rate|events)'

# 查看 per-CPU 统计（原始值）
sudo bpftool map dump name xdp_stats
```

退出 aya-app 后，XDP link 随进程关闭 detach；确认：

```bash
sudo bpftool net show
```

不再出现对应程序。

## 6. 性能与生产化建议

1. **优先 native XDP**：`--mode driver`；确认驱动支持（`ethtool -i`、厂商文档）。
2. **多队列**：XDP 在每个 RX queue 执行；`ethtool -L eth0 combined N` 与 CPU 亲和性要匹配。
3. **采样事件**：生产上把 `--event-sample` 调大（如 1024），只保留统计和少量样本。
4. **限速 map 容量**：`xdp_rate` 默认 16384；攻击源超过容量时 LRU 会淘汰，限速变为近似。需要更大容量时调大 `XDP_RATE_ENTRIES`；更严格的前缀聚合可改用 `LpmTrie`。
5. **避免误伤**：只对受保护前缀生效；ICMP 只丢 echo request；非首片段放行。
6. **DDoS 组合**：XDP 前端 + TC/iptables 后端 + 上游清洗；XDP 不应是唯一防线。
7. **监控**：把 `xdp_stats` 导出到 Prometheus；观察 `dropped_rate` 与网卡 `rx_dropped` 的差异。
8. **XDP 之外的选项**：需要重写/转发时考虑 `XDP_TX`、`XDP_REDIRECT`、AF_XDP；本项目只做过滤。

## 7. 排错

| 现象 | 原因 | 处理 |
|---|---|---|
| `failed to attach ... driver mode` | 驱动不支持 native XDP | 改 `--mode skb` |
| ping 仍然通 | 策略前缀不匹配 / 未开 `--block-icmp` / 包未经过该接口 | 检查 `--protected-ip`、抓包位置、veth 方向 |
| 所有包被丢 | `protected-ip` 配错、掩码过宽 | 先用 `/32`，仅保护单地址 |
| 没有事件只有统计 | 采样率过低 / ring buffer 满 | 调小 `--event-sample`；检查用户态读取 |
| `Operation not permitted` | 缺少 CAP_NET_ADMIN/CAP_BPF | 用 root 或补能力 |
| `map create failed` | memlock/BTF/内核配置 | 见 [排错手册](../troubleshooting.md) |

## 8. 代码导读

| 文件 | 内容 |
|---|---|
| `aya-app-ebpf/src/programs/xdp.rs` | 程序、map、解析、限速、事件 |
| `aya-app-ebpf/src/net.rs` | Ethernet/VLAN/IPv4/ICMP 头 |
| `aya-app-common/src/lib.rs` | `XdpConfig`/`XdpStats`/`XdpEvent` |
| `aya-app/src/commands/xdp.rs` | 配置、attach、事件循环、统计 |
| `aya-app/src/cli.rs` | `XdpArgs` 与默认值 |

## 9. 延伸

- 用 `LpmTrie<u32, u8>` 实现前缀黑名单，而不是精确 IP；
- 用 `bpf_xdp_adjust_head` 做包改写；
- 用 `DevMap`/`CpuMap` 做重定向和负载均衡；
- 用 `XDP_REDIRECT` + AF_XDP 把采样流量送到用户态；
- 用 cgroup/BPF 或 TC 做更细的应用层策略。

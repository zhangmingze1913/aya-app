# 场景 6：Socket Filter / SOCK_OPS — 连接白名单与容器网络策略

## 1. 应用场景

这一组三个挂钩点都在“socket / cgroup”层，但能力完全不同：

| 挂钩点 | eBPF 类型 | 触发时机 | 返回值 | 能否拦截 | 典型用途 |
|---|---|---|---|---|---|
| SOCK_OPS | `BPF_PROG_TYPE_SOCK_OPS` | TCP 连接生命周期回调/查询 | `_CB` 忽略；查询类用 `reply` | ❌ | 连接遥测、RTT/重传统计、per-socket 调优 |
| Socket Filter | `BPF_PROG_TYPE_SOCKET_FILTER` | socket 收到包 | 0=丢弃，len=通过，较小值=截断 | ✅ 入站 | 应用层协议过滤、SYN 白名单、抓包过滤 |
| cgroup/connect4 | `BPF_PROG_TYPE_CGROUP_SOCK_ADDR` | `connect(2)` | 1=允许，0=拒绝 | ✅ 出站 | 容器出站端口白名单 |

用户给出的典型用例是“仅允许容器访问 80/443 端口，阻止非法外联”。**这个用例不能用 SOCK_OPS 实现**：

- `BPF_SOCK_OPS_TCP_CONNECT_CB` 只是通知，内核忽略返回值；
- 查询类操作（`TIMEOUT_INIT`、`RWND_INIT`、`BASE_RTT` 等）通过 `reply` 返回参数，不是 allow/deny；
- 真正能拦截 `connect()` 的是 `cgroup/connect4`（或 `connect6`）。

因此本项目把场景 6 拆成三个子命令，分别演示“观测”“入站拦截”“出站拦截”，并在文档中明确能力边界。

## 2. SOCK_OPS：连接生命周期遥测

### 2.1 原理

SOCK_OPS 程序附加到 cgroup，内核在 TCP 连接的不同阶段调用：

| `op` | 值 | 时机 | 说明 |
|---|---|---|---|
| `BPF_SOCK_OPS_TCP_CONNECT_CB` | 3 | 主动 connect 发出 SYN | 通知；可设置 socket 选项 |
| `BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB` | 4 | 主动连接建立 | 通知 |
| `BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB` | 5 | 被动连接建立 | 通知 |
| `BPF_SOCK_OPS_STATE_CB` | 10 | TCP 状态变化 | 需要 `bpf_sock_ops_cb_flags_set` 开启 |
| `BPF_SOCK_OPS_TCP_LISTEN_CB` | 11 | listen | 通知 |

回调返回值被忽略；程序应返回 1（成功）。本项目：

- 读取 `op/family/local_port/remote_port/local_ip4/remote_ip4/srtt_us/bytes_acked/bytes_received/state`；
- 在 connect / passive established 回调里开启 `BPF_SOCK_OPS_STATE_CB_FLAG`，以便看到状态变化；
- 只对指定 `--watch-port` 的本地/远端端口上报；
- 发 `SockOpsEvent`，统计 connect/established/listen/state 次数。

### 2.2 能做什么/不能做什么

能：

- 观察连接建立、关闭、RTT、重传、字节数；
- 用 `bpf_setsockopt` 调整 per-socket 参数（本案例未启用）；
- 把 socket 加入 `sockmap`/`sockhash`，供 `sk_msg`/`sk_skb` 使用。

不能：

- 拒绝连接（返回值无效）；
- 修改目的地址/端口（那是 connect4 的 `user_ip4/user_port` 可写字段，SOCK_OPS 不是该钩子）；
- 替代防火墙。

## 3. Socket Filter：入站 SYN 白名单

### 3.1 原理与偏移陷阱

经典 socket filter 附加到某个 socket（本项目是 `TcpListener`）。它在 socket 收到包时执行，返回值：

- `0`：丢弃；
- `>= skb->len`：通过；
- `0 < ret < len`：截断到 ret 字节。

**关键陷阱**：对 `AF_INET/TCP` socket，`skb->data` 指向 **TCP 头**，不是 IP 头。Linux Socket Filter 文档明确说明：对 `PF_INET/SOCK_STREAM`，过滤器从 TCP 头开始；要访问 IP 头需要 `SKF_NET_OFF`。eBPF 的 `__sk_buff` 没有经典负偏移，但 `bpf_skb_load_bytes_relative(skb, offset, ..., BPF_HDR_START_NET)` 可以从网络头开始读。

本项目：

1. 用 `load_relative` 读 IPv4 头（网络头 offset 0）；
2. 校验 version=4、protocol=TCP、ihl≥20；
3. 用 `load_relative` 在网络头 + ihl 读 TCP 头；
4. 只处理 `SYN && !ACK`；
5. 如果 `enforce=1`，查 `skfilter_allowed` 源 IP 表：存在则通过，否则返回 0；
6. 非 SYN/非 TCP/解析失败一律通过，避免误伤已建立连接和 ICMP 错误。

### 3.2 适用范围

- 只对**该监听 socket** 的入站包生效；
- 源 IP 是 NAT/代理后的地址；
- IPv4 only；IPv6 直接放行；
- 适合“应用层前置防护”，不适合做全机防火墙；
- SYN 被丢弃时，客户端看到的是连接超时（不是 RST），这是预期行为。

## 4. cgroup/connect4：出站端口白名单

### 4.1 原理

`BPF_CGROUP_INET4_CONNECT` 在进程调用 `connect(2)` 时执行，上下文是 `struct bpf_sock_addr`：

- `user_family`：`AF_INET`；
- `user_ip4`：目的 IPv4（网络序）；
- `user_port`：目的端口（网络序，低 16 位有效）；
- 返回 1 允许，0 拒绝（`EPERM`）。

本项目：

1. 校验 `family == AF_INET`（IPv6 放行）；
2. `dport = u16::from_be(user_port as u16)`；
3. 查 `connect4_config.allow_ports`；
4. 允许/拒绝并统计；
5. 拒绝事件按 1/16 采样写入 ring buffer。

### 4.2 安全边界

- 附加到 **根 cgroup** 会影响整机，包括你的 shell、SSH、监控 agent；
- 生产/实验都应使用专用子 cgroup；
- 白名单至少一个端口；CLI 拒绝空列表；
- BPF 内部配置为空时 fail-open（返回 allow），防止用户态错误导致断网；
- DNS(53) 不在白名单时，按域名访问会先失败；用 IP 测试或把 53 加入白名单；
- 只匹配 IPv4；IPv6 需要 `connect6` 程序。

## 5. 实验

### 5.1 SOCK_OPS 遥测

```bash
sudo -E ./target/release/aya-app socket-filter sockops \
    --cgroup /sys/fs/cgroup --watch-port 443
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

如果要观察被动连接：

```bash
# 终端 A
nc -l 127.0.0.1 8443
# 终端 B
nc 127.0.0.1 8443
# agent 加 --watch-port 8443
```

### 5.2 入站 SYN 白名单

```bash
sudo -E ./target/release/aya-app socket-filter skfilter \
    --listen 127.0.0.1:8080 \
    --allow-ip 127.0.0.1
```

另一个终端：

```bash
curl -v --max-time 2 http://127.0.0.1:8080/
```

预期：

```text
[accept] peer=127.0.0.1:54321 (SYN passed the filter)
```

（demo 不实现 HTTP，curl 会收到连接关闭。）

要验证“拒绝”，需要从另一个源 IP 发起连接。Linux 的 `127.0.0.0/8` 都是 loopback，可以用 `curl --interface` 指定源地址：

```bash
# 源地址 127.0.0.2 不在 allow-ip 中
curl --interface 127.0.0.2 -v --max-time 2 http://127.0.0.1:8080/
```

预期：SYN 被丢弃，`curl` 报 `Connection timed out`；`skfilter_stats.dropped_syn` 增长。若本机没有 127.0.0.2，先 `sudo ip addr add 127.0.0.2/8 dev lo`。

也可以从另一台机器/容器访问本机 8080，且不把其 IP 加入 `--allow-ip`。

### 5.3 出站端口白名单

```bash
# 1. 创建专用 cgroup
sudo mkdir -p /sys/fs/cgroup/aya-demo

# 2. 把测试 shell 放进去（agent 不要放进去）
sudo sh -c 'echo $$ > /sys/fs/cgroup/aya-demo/cgroup.procs; exec bash'

# 3. 在另一个终端（根 cgroup）附加策略
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

统计：

```text
--- connect4 stats ---
connects :          3 (     0.6/s)
allowed  :          2    denied:          1 (0.2 deny/s)
```

清理：

```bash
# 退出 agent 会 detach；
# 把测试 shell 移回根 cgroup（在新 shell 中）
echo $$ | sudo tee /sys/fs/cgroup/cgroup.procs
sudo rmdir /sys/fs/cgroup/aya-demo
```

## 6. 参数说明

### SOCK_OPS

| 参数 | 默认 | 说明 |
|---|---|---|
| `--cgroup` | `/sys/fs/cgroup` | cgroup v2 路径 |
| `--watch-port` | 空 | 只观察本地/远端端口匹配的连接 |
| `--attach-mode` | `single` | `single`/`multi` |
| `--stats-interval` | `5` | 统计间隔 |

### Socket Filter

| 参数 | 默认 | 说明 |
|---|---|---|
| `--listen` | `127.0.0.1:8080` | 监听地址 |
| `--allow-ip` | 空 | 为空 = 只观测；非空 = 强制白名单 |
| `--stats-interval` | `5` | 统计间隔 |

### connect4

| 参数 | 默认 | 说明 |
|---|---|---|
| `--cgroup` | 必填 | 策略作用的 cgroup |
| `--allow-port` | 必填，至少 1 个 | 允许的 IPv4 目的端口（最多 8 个） |
| `--attach-mode` | `single` | `single`/`multi` |
| `--stats-interval` | `5` | 统计间隔 |

## 7. 验证

```bash
# cgroup v2
mount | grep cgroup2
cat /sys/fs/cgroup/cgroup.controllers

# SOCK_OPS / connect4 链接
sudo bpftool cgroup tree
sudo bpftool prog show | grep -A8 -E 'sockops_guard|connect4_guard|skfilter_guard'

# socket filter 统计
sudo bpftool map show | grep skfilter

# 连接观察
ss -tnp
```

## 8. 生产化建议

1. **出站策略用 connect4/connect6 或 nftables**：不要在 SOCK_OPS 上做“假拦截”。
2. **cgroup 作用域**：只对容器/工作负载子 cgroup 附加；根 cgroup 会影响宿主。
3. **DNS**：允许 53，或使用 DoH/DoT 端口，或预解析；否则按域名访问会失败。
4. **IPv6**：如果需要，增加 `connect6`/`sendmsg6` 程序；不要默认放行而不自知。
5. **NAT**：socket filter 的源 IP 是 NAT 后的地址；按实际拓扑配置。
6. **高可用**：connect4 附加失败（EBUSY/EPERM）时应告警，不要静默降级。
7. **可观测性**：导出 connects/allowed/denied；拒绝事件采样，避免连接扫描打爆 ring buffer。
8. **替代/组合**：Cilium 用 cgroup BPF 做容器网络策略；传统环境可用 nftables/iptables；socket filter 适合应用内前置防护。

## 9. 排错

| 现象 | 原因 | 处理 |
|---|---|---|
| SOCK_OPS attach `EBUSY` | 同 cgroup 已有程序且 mode=single | 用 `--attach-mode multi` 或先卸载 |
| 没有 SOCK_OPS 事件 | 连接不在该 cgroup / 端口过滤 / 未建立 TCP | 检查 cgroup 成员、`--watch-port` |
| socket filter 不生效 | 过滤器附加到了别的 socket / 源 IP 不匹配 | 确认 listener、`--allow-ip`、NAT |
| 所有连接被拒 | connect4 白名单太窄 / 附加到根 cgroup | 立即 Ctrl-C；把 shell 移出 cgroup；重新设计白名单 |
| `EPERM` on connect | connect4 拒绝（预期） | 加入允许端口 |
| cgroup 打开失败 | cgroup v2 未挂载/路径错 | `mount -t cgroup2`；检查路径 |
| IPv6 不受控 | 只实现了 connect4 | 增加 connect6 或明确接受风险 |

## 10. 代码导读

| 文件 | 内容 |
|---|---|
| `aya-app-ebpf/src/programs/socket.rs` | SOCK_OPS、socket filter、connect4 三个程序 |
| `aya-app-ebpf/src/utils.rs` | 端口匹配、采样 |
| `aya-app/src/commands/socket.rs` | 三个子命令的配置/attach/事件循环 |
| `aya-app-common/src/lib.rs` | `SockOps*`/`Skfilter*`/`Connect4*` 类型 |

## 11. 延伸

- 增加 `connect6`，覆盖 IPv6；
- 用 `bpf_setsockopt` 按连接设置 `SO_MAX_PACING_RATE`/拥塞控制；
- 用 `sockmap`/`sockhash` + `sk_msg` 做 L7 代理；
- 用 `cgroup/getsockopt`/`setsockopt` 做更细的应用策略；
- 用 LSM BPF 做文件/网络联合策略。

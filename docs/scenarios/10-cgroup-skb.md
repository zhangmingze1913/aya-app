# 场景 10：cgroup_skb（按 cgroup 的网络过滤）

## 1. 这个场景解决什么问题

XDP/TC 的边界是**网卡**，socket filter 的边界是**单个 socket**。  
`cgroup_skb` 的边界是**一个 cgroup 里的所有 socket**，适合容器/租户级别的网络策略：

- 不关心流量走哪张网卡；
- 不需要在每张网卡上挂 TC；
- 策略跟着进程组走。

本案例在 egress 方向丢弃目的端口等于 `--block-port` 的 TCP/UDP 包；ingress 方向同理。

## 2. 原理

程序 section：

```text
cgroup_skb/ingress
cgroup_skb/egress
```

`__sk_buff.data` 在 cgroup_skb 中从 **IPv4 头**开始（没有 Ethernet 头）。程序：

1. 检查 `skb->protocol` 是 IPv4；
2. 解析 IPv4 头、IHL、分片标志；
3. 解析 TCP/UDP 目的端口；
4. 命中端口返回 `1`（drop），否则返回 `0`（allow）。

## 3. 前置条件

- cgroup v2 已挂载；
- 内核开启 `CONFIG_CGROUP_BPF=y`；
- root 或 `CAP_NET_ADMIN` + `CAP_BPF`；
- 建议创建**专用子 cgroup**，不要把策略挂到根 cgroup。

```bash
mount | grep cgroup2
mkdir -p /sys/fs/cgroup/aya-skb
```

## 4. 运行

终端 A：

```bash
sudo -E ./target/release/aya-app cgroup-skb \
    --cgroup /sys/fs/cgroup/aya-skb \
    --direction egress \
    --block-port 18080
```

终端 B：在目标 cgroup 中启动客户端：

```bash
# 先在 cgroup 外启动监听端
nc -l -p 18080

# 在 cgroup 内连接（连接会被 egress 丢弃）
sh -c 'echo $$ > /sys/fs/cgroup/aya-skb/cgroup.procs; nc 127.0.0.1 18080'
```

## 5. 预期输出

```text
=== cgroup_skb port filter ===
  cgroup      : /sys/fs/cgroup/aya-skb
  direction   : Egress
  block port  : 18080
  event sample: 1/64

[cgroup-skb drop] t=... pid=0 tid=0 comm= 127.0.0.1:40122 -> 127.0.0.1:18080 len=60

--- cgroup_skb stats ---
pass  :            1  (       0.5/s,      0 B/s)
drop  :            1  (       0.5/s,     60 B/s)
bytes : pass=0 B  drop=60 B
```

> 兼容性：Linux 6.6 的 cgroup_skb helper allowlist 不包含
> `bpf_get_current_pid_tgid` / `bpf_get_current_comm`，因此事件的 `pid`/`tgid`/`comm`
> 固定为 0/空；地址、端口、长度和统计仍然准确。Linux 6.18 同样使用这一兼容形式。
>
> 性能：`IHL=20` 时一次读取 24 字节 IPv4+端口前缀；带 IPv4 options 时才回退到
> 4 字节端口读取，避免每次复制完整 TCP 头。

## 6. 参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--cgroup` | 必填 | cgroup v2 路径 |
| `--direction` | `egress` | `ingress` 或 `egress` |
| `--block-port` | `8080` | 目的端口，`0` 表示只观测 |
| `--event-sample` | `64` | 丢弃事件采样率 |
| `--stats-interval` | `5` | 统计间隔（秒） |

## 7. 与 XDP/TC/socket filter 的边界

| 方案 | 作用域 | 典型用途 |
|---|---|---|
| XDP | 网卡接收路径 | DDoS、最早丢包 |
| TC | 网卡 ingress/egress | 分类、QoS、mark |
| cgroup_skb | cgroup 内 socket | 容器/租户网络策略 |
| socket filter | 单个监听 socket | SYN 白名单 |
| connect4 | cgroup 出站连接 | 目的端口 allowlist |

## 8. 排错

| 现象 | 原因 | 处理 |
|---|---|---|
| `failed to attach ... EINVAL` | cgroup v2 路径错误/未挂载 | `mount | grep cgroup2` |
| 没有 drop | 进程不在该 cgroup | 检查 `/proc/<pid>/cgroup` |
| 所有流量被 drop | `--block-port` 命中面过大 | 先用 `--block-port 0` 观测，再启用 |
| 只有部分包被 drop | 非 TCP/UDP 或非首片 | 程序只处理 TCP/UDP 首片 |

## 9. 验证

```bash
cat /proc/<pid>/cgroup
sudo bpftool prog show | grep cgskb
sudo bpftool link show
```

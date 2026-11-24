# 场景 11：cgroup_sysctl（阻止 cgroup 修改 sysctl）

## 1. 这个场景解决什么问题

容器/sandbox 默认可能拥有修改 `/proc/sys/*` 的权限。内核的 `cgroup_sysctl` BPF 钩子
可以在**不依赖 LSM** 的情况下，阻止某个 cgroup 内的进程写入 sysctl。

本案例：

- 读操作放行；
- 写操作按策略拒绝；
- 事件携带 pid/tgid/uid/comm；
- 计数器区分 calls/writes/blocked/reads。

## 2. 内核返回值语义

`__cgroup_bpf_run_filter_sysctl` 的约定与常见“0 允许、非 0 拒绝”相反：

- 返回 `1`：允许，并允许程序替换写入缓冲区；
- 返回其他值：内核转换为 `-EPERM`。

因此本程序：

- 允许时返回 `1`；
- 拒绝时返回 `0`。

用户态看到的是 `EPERM`（Operation not permitted）。

## 3. 前置条件

- cgroup v2；
- 内核开启 `CONFIG_CGROUP_SYSCTL=y`；
- root 或对应 cgroup 管理权限；
- 建议使用专用子 cgroup。

```bash
mkdir -p /sys/fs/cgroup/aya-sysctl
```

## 4. 运行

终端 A：

```bash
sudo -E ./target/release/aya-app cgroup-sysctl \
    --cgroup /sys/fs/cgroup/aya-sysctl
```

终端 B：在该 cgroup 内写 sysctl：

```bash
sh -c 'echo $$ > /sys/fs/cgroup/aya-sysctl/cgroup.procs; sysctl -w net.ipv4.ip_forward=1'
# sysctl: setting key "net.ipv4.ip_forward": Operation not permitted
```

只观测、不拒绝：

```bash
sudo -E ./target/release/aya-app cgroup-sysctl \
    --cgroup /sys/fs/cgroup/aya-sysctl --observe
```

## 5. 预期输出

```text
=== cgroup_sysctl guard ===
  cgroup      : /sys/fs/cgroup/aya-sysctl
  mode        : deny writes
  event sample: 1/16

[sysctl-deny] t=... pid=2110 tid=2110 comm=sysctl uid=0 write=1

--- cgroup_sysctl stats ---
calls   :            2  (       0.4/s)
writes  :            1  (       0.2/s)
blocked :            1  (       0.2/s)  reads=1
```

## 6. 参数

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--cgroup` | 必填 | cgroup v2 路径 |
| `--observe` | false | 只观测，不拒绝写入 |
| `--event-sample` | `16` | 拒绝事件采样率 |
| `--stats-interval` | `5` | 统计间隔（秒） |

## 7. 限制

- 上下文只有 `write` 和 `file_pos`，**没有 sysctl 名称**，因此策略是“该 cgroup 的所有写”；
- 需要更细的路径/键策略时，应使用 LSM 或其他机制；
- 该策略影响整个 cgroup 子树。

## 8. 排错

| 现象 | 原因 | 处理 |
|---|---|---|
| `failed to attach ... EINVAL` | 内核没有 `CONFIG_CGROUP_SYSCTL` | 检查内核配置 |
| 没有事件 | 进程不在 cgroup / 只读了 sysctl | 检查 `/proc/<pid>/cgroup` |
| 写入仍成功 | 用了 `--observe`，或进程在子 cgroup 外 | 去掉 `--observe`，确认 cgroup 归属 |
| 读取也被拒绝 | 程序逻辑被改坏 | 只应在 `write != 0` 时拒绝 |

## 9. 验证

```bash
cat /proc/<pid>/cgroup
sudo bpftool prog show | grep sysctl
sudo bpftool link show
```

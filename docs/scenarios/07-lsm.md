# 场景 7：LSM — 全局 socket_connect 端口拦截

## 1. 应用场景

LSM（Linux Security Module）BPF 把 eBPF 程序附加到内核安全钩子上，可以：

- 实现强制访问控制（MAC）策略；
- 对文件打开、执行、socket 连接等操作做**拒绝/放行**决策；
- 与 SELinux/AppArmor 等 LSM 共存，按 LSM 顺序组合决策。

与前面的场景相比：

| 场景 | 作用域 | 是否可拦截 | 典型用途 |
|---|---|---|---|
| kprobe/uprobe/tracepoint | 观测点 | ❌ | 审计、性能 |
| `cgroup/connect4` | 某个 cgroup | ✅ | 容器出站白名单 |
| **LSM `socket_connect`** | **全局（或按 UID 限制）** | ✅ 返回负 errno | 主机级连接策略、安全基线 |

本案例实现一个最小但完整的 LSM 策略：

- 在 `socket_connect` 钩子上解析 IPv4 `sockaddr_in`；
- 拒绝连接指定目的端口；
- 可选只对某个 UID 生效，缩小影响范围；
- 记录精确 per-CPU 统计和采样拒绝事件。

> 本案例是**全局端口黑名单**，不是完整的防火墙。生产环境应优先使用 cgroup BPF、nftables 或专门的策略引擎；LSM 适合做“必须在内核安全钩子上表达”的策略。

## 2. 原理

### 2.1 LSM 钩子与返回值

内核通过 `LSM_HOOK` 宏声明安全钩子。`socket_connect` 的定义类似：

```c
LSM_HOOK(int, 0, socket_connect,
         struct socket *sock, struct sockaddr *address, int addrlen)
```

BPF LSM 程序的返回值：

- `0`：允许（继续后续 LSM/操作）；
- 负 errno（如 `-EPERM`、`-EACCES`）：拒绝；
- 正数通常不是有效的拒绝语义，应避免。

`attach` 不是挂到某个 cgroup，而是挂到内核的 LSM hook 列表；默认对整个系统生效。

### 2.2 `socket_connect` 是 sleepable hook

`kernel/bpf/bpf_lsm.c` 的 `sleepable_lsm_hooks` 包含 `bpf_lsm_socket_connect`。因此：

- eBPF 程序必须用 `#[lsm(sleepable, hook = "socket_connect")]` 编译，产生 `lsm.s/socket_connect` section；
- aya 会把该 section 识别为 sleepable，并在 `BPF_PROG_LOAD` 时设置 `BPF_F_SLEEPABLE`；
- 如果误用非 sleepable 的 `#[lsm(hook = "socket_connect")]`，程序可以加载，但 `bpf_raw_tracepoint_open` 附加会返回 `EBUSY`（Resource busy）。

这是本项目在 Linux 6.18 上实际验证出的差异；不要用“能 load 就能 attach”来判断。

### 2.3 BPF LSM 的启用条件

需要同时满足：

1. 内核编译了 `CONFIG_BPF_LSM=y`；
2. 内核有 BTF（`CONFIG_DEBUG_INFO_BTF=y`，`/sys/kernel/btf/vmlinux`）；
3. 启动参数 `lsm=` 中包含 `bpf`，例如：
   ```text
   lsm=lockdown,yama,integrity,apparmor,bpf
   ```
4. 内核 ≥ 5.7（BPF LSM）。

检查：

```bash
grep CONFIG_BPF_LSM /boot/config-$(uname -r)
cat /sys/kernel/security/lsm
test -e /sys/kernel/btf/vmlinux && echo "BTF ok"
```

`/sys/kernel/security/lsm` 中没有 `bpf` 时，程序可以加载但不会收到回调；需要修改启动参数并重启。

### 2.4 BTF 参数约定

Aya 的 `LsmContext::arg(n)` 读取 BTF 参数数组。对于 `socket_connect`：

| 索引 | 内容 |
|---|---|
| 0 | `struct socket *sock` |
| 1 | `struct sockaddr *address`（内核中的副本） |
| 2 | `int addrlen` |
| 3 | 前一个 LSM 程序的返回值（phony，总是最后一个） |

本案例：

- 先检查 `arg(3)`；如果前一个 LSM 已拒绝，直接返回 `-EPERM`，不覆盖；
- 用 `arg(1)` 读取内核 `sockaddr_in`；
- 只处理 `AF_INET`；其他 family 放行；
- 可选 UID 过滤；
- 命中黑名单端口返回 `-EPERM`。

### 2.5 数据结构

```rust
struct LsmConfig {
    blocked_ports: [u16; 8],
    blocked_port_count: u32,
    target_uid: u32,
    enforce_uid: u32,
    event_sample: u32,
}

struct LsmEvent {
    timestamp_ns: u64,
    pid: u32,
    uid: u32,
    daddr: u32,     // 原始网络序
    dport: u16,     // 主机序
    family: u16,
    action: u32,    // LSM_ACTION_DENY
    comm: [u8; 16],
}

struct LsmStats {
    connects: u64,
    allowed: u64,
    denied: u64,
}
```

## 3. 实验

### 3.1 运行

```bash
# 只拦截当前用户的 8080 连接（推荐先这样缩小范围）
sudo -E ./target/release/aya-app lsm \
    --block-port 8080 \
    --uid "$(id -u)"
```

或者拦截所有用户的 8080：

```bash
sudo -E ./target/release/aya-app lsm --block-port 8080
```

### 3.2 触发

```bash
# 终端 A：监听 8080（bind 不受 connect 钩子影响）
nc -l 127.0.0.1 8080

# 终端 B：连接
nc 127.0.0.1 8080
```

预期：

```text
[lsm-deny] t=... pid=... uid=1000 comm=nc dst=127.0.0.1:8080
```

客户端报：

```text
nc: connect to 127.0.0.1 port 8080 (tcp) failed: Operation not permitted
```

用 `curl` 也可以：

```bash
curl -v --max-time 2 http://127.0.0.1:8080/
```

### 3.3 统计输出

```text
--- LSM stats ---
connects :            3  (       0.6/s)
allowed  :            1    denied:            2 (0.4 deny/s)
```

- `connects`：`socket_connect` 钩子调用次数（包括 IPv6/AF_UNIX 等）；
- `allowed`：未命中策略、UID 不匹配、非 IPv4 等；
- `denied`：命中黑名单端口。

### 3.4 UID 过滤

```bash
# 只拦截 uid 1000
sudo -E ./target/release/aya-app lsm --block-port 8080 --uid 1000

# 作为 uid 1000 连接：被拒绝
nc 127.0.0.1 8080

# 作为 root 连接：允许（如果监听端仍在）
sudo nc 127.0.0.1 8080
```

注意：`bpf_get_current_uid_gid()` 返回的是当前任务凭证中的 UID；容器/用户命名空间中的 UID 映射需要按实际值配置。

## 4. 参数

| 参数 | 默认 | 说明 |
|---|---|---|
| `--block-port` | 必填，至少 1 个 | 拒绝的目的端口，最多 8 个 |
| `--uid` | 无 | 只对指定 UID 生效；不填 = 整机 |
| `--event-sample` | `16` | 每 N 个拒绝事件输出 1 条 |
| `--stats-interval` | `5` | 统计间隔 |

## 5. 验证

```bash
# 程序与 link
sudo bpftool prog show | grep -A8 lsm_socket_connect
sudo bpftool link show

# BTF/LSM 状态
cat /sys/kernel/security/lsm
test -e /sys/kernel/btf/vmlinux && echo BTF

# map
sudo bpftool map show | grep -E 'lsm_(config|stats|events)'
```

如果 `/sys/kernel/security/lsm` 没有 `bpf`，即使程序加载成功也不会触发。修改 GRUB 的 `lsm=` 后重启，例如：

```text
GRUB_CMDLINE_LINUX="... lsm=lockdown,yama,integrity,apparmor,bpf"
```

然后：

```bash
sudo update-grub && sudo reboot
```

## 6. 生产化建议

1. **作用域**：LSM 是全局钩子。共享主机上必须用 `--uid` 或改用 cgroup/connect4；不要在生产机上随手 `--block-port`。
2. **黑名单 vs 白名单**：本案例是黑名单。安全基线通常需要白名单/默认拒绝，但要非常小心，避免把管理通道、DNS、监控打挂。
3. **IPv6**：当前只解析 `AF_INET`，IPv6 放行；需要 IPv6 策略时增加 `AF_INET6` 解析或 `socket_connect` 的 IPv6 分支。
4. **LSM 顺序**：本程序尊重前一个 LSM 的拒绝；如果前一个 LSM 返回 0，本程序继续判断。
5. **其他 LSM 钩子**：文件访问可用 `file_open`/`inode_permission`/`bprm_check_security`，但需要按 BTF 结构读取路径/凭据；比 socket 场景复杂。
6. **性能**：每个 `connect()` 一次 hook + 一次 `sockaddr_in` 读取；开销很低，但全局策略要评估对高频连接服务的影响。
7. **回滚**：Ctrl-C 会 detach；如果策略导致业务异常，先停止 agent，再检查 `bpftool link show`。
8. **与 cgroup 方案的关系**：容器场景优先 cgroup/connect4；LSM 适合主机级、与 cgroup 无关的策略。

## 7. 排错

| 现象 | 原因 | 处理 |
|---|---|---|
| `failed to load ... EINVAL` | 内核没有 `CONFIG_BPF_LSM` 或 BTF | 检查内核配置/BTF；换内核 |
| `failed to attach ... EBUSY` | 非 sleepable 程序附加到 sleepable hook，或 trampoline 冲突 | 确认使用 `#[lsm(sleepable, ...)]`；检查 `available_tracers` 是否支持函数跟踪 |
| 加载成功但无事件 | `lsm=` 未包含 `bpf` | 修改启动参数并重启 |
| `Btf::from_sys_fs` 失败 | 没有 `/sys/kernel/btf/vmlinux` | 安装带 BTF 的内核 |
| 所有连接被拒 | `--block-port` 命中关键端口 / 未加 `--uid` | Ctrl-C；缩小端口/UID |
| IPv6 不受控 | 只解析 AF_INET | 增加 IPv6 解析或明确接受 |
| 监听端也失败 | 只 hook 了 connect；检查是否误把端口用于客户端 | 换测试端口 |
| 权限不足 | 不是 root/CAP_BPF/CAP_PERFMON | `sudo -E` 或补能力 |

## 8. 代码导读

| 文件 | 内容 |
|---|---|
| `aya-app-ebpf/src/programs/lsm.rs` | `#[lsm(hook = "socket_connect")]`、sockaddr 解析、策略、事件 |
| `aya-app/src/commands/lsm.rs` | BTF 加载、`Lsm::load/attach`、统计/事件 |
| `aya-app-common/src/lib.rs` | `LsmConfig`/`LsmEvent`/`LsmStats` |
| `aya-app/src/cli.rs` | `LsmArgs` |

## 9. 延伸

- 用 `file_open` 阻止未授权进程打开敏感文件（需要 BTF 读取 `struct file`/`dentry` 路径，或用 `bpf_d_path`）；
- 用 `bprm_check_security` 审计/阻止执行特定二进制；
- 用 `inode_permission` 做更细的文件权限策略；
- 用 `lsm_cgroup`（aya 支持）把 LSM 策略绑定到 cgroup；
- 与 SELinux/AppArmor 组合，明确 LSM 顺序和“谁先拒绝”。

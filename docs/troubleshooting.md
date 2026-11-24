# 排错手册

按“构建 → 加载 → 场景 → 运行时”分类。每条包含现象、原因、处理。

---

## 1. 构建

### 1.1 `bpf-linker not found`

```text
bpf-linker not found. Install it with `cargo install bpf-linker`
```

原因：`aya-app/build.rs` 在 PATH 中找不到 `bpf-linker`。

处理：

```bash
cargo install bpf-linker
which bpf-linker
# 确保 build script 继承 PATH（sudo -E 或 cargo 直接运行）
```

`bpf-linker` 依赖 LLVM；如果安装失败，先按 bpf-linker 文档安装 LLVM 19/20 和 `llvm-config`。

### 1.2 `can't find crate for core` / `can't find crate for compiler_builtins`

原因：没有 nightly/`rust-src`，或手动构建时漏了 `-Z build-std=core`。

处理：

```bash
rustup toolchain install nightly --component rust-src
cargo +nightly build --target bpfel-unknown-none -Z build-std=core
```

### 1.3 `linker 'bpf-linker' not found` / `unknown argument --btf`

原因：`bpf-linker` 版本过旧或不在 PATH。

处理：

```bash
cargo install bpf-linker --force
bpf-linker --version
```

### 1.4 `AYA_BUILD_SKIP` 构建的二进制无法加载

现象：

```text
failed to load the embedded eBPF object; if it was built with AYA_BUILD_SKIP...
```

原因：占位对象不是合法 ELF。

处理：在 Linux 上重新 `cargo build --release`，不要设置 `AYA_BUILD_SKIP`。

### 1.5 `failed to load manifest for workspace member`

原因：目录不完整（缺少 `aya-app-ebpf` 或 `aya-app-demo`），或 `Cargo.toml` 被移动。

处理：保持仓库完整结构；`workspace.members` 必须能找到四个成员。

### 1.6 `unused field authors in workspace.package`

旧版本遗留警告；当前 `Cargo.toml` 已移除。若出现，删除 workspace 中未使用的字段，或在成员中引用。

---

## 2. 加载/权限

### 2.1 `Operation not permitted` / `EPERM`

原因：

- 不是 root，且缺少 `CAP_BPF`/`CAP_NET_ADMIN`/`CAP_PERFMON`；
- 容器没有 `--privileged` 或相应 capability；
- `kernel.unprivileged_bpf_disabled=1`。

处理：

```bash
sudo -E ./target/release/aya-app ...
# 或给二进制加 capability（按内核版本选择）
sudo setcap cap_bpf,cap_net_admin,cap_perfmon+ep ./target/release/aya-app
```

> `setcap` 对脚本/嵌入对象不一定适用；优先用 root 或特权容器。

### 2.2 `RLIMIT_MEMLOCK` / `map create failed: Operation not permitted`

原因：旧内核把 BPF map 内存计入 memlock；当前 rlimit 太小。

处理：

```bash
ulimit -l unlimited
# 或
sudo sh -c 'ulimit -l unlimited; exec ./target/release/aya-app ...'
```

程序启动时也会尝试把 `RLIMIT_MEMLOCK` 设为 infinity；如果失败会打 debug 日志。systemd 服务需要 `LimitMEMLOCK=infinity`。

### 2.3 `BTF: failed to parse` / `No such file or directory: /sys/kernel/btf/vmlinux`

原因：

- 内核未开启 `CONFIG_DEBUG_INFO_BTF`；
- 精简发行版没有 BTF。

处理：

- 安装带 BTF 的内核（`linux-image-...` 通常包含 `/sys/kernel/btf/vmlinux`）；
- 或在支持的发行版安装 `linux-tools`/`bpftool` 包；
- 某些程序（如 fentry）必须有 BTF；本项目主要用 legacy map/程序，BTF 缺失时部分加载可能仍可工作，但建议补齐。

### 2.4 `map ... not found` / `program ... not found`

原因：

- eBPF 对象是旧版本（map/程序名不匹配）；
- `AYA_BUILD_SKIP` 占位对象；
- 程序名被 Rust 优化/mangling 改变（本项目用 `#[no_mangle]` 宏生成，正常不会）。

处理：重新构建；`bpftool prog show`/`strings` 检查对象；确认 `aya-app-common` 与 `aya-app-ebpf` 版本一致。

### 2.5 `invalid bpf_context access`

原因：直接解引用了上下文指针/未验证的 map 值。

处理：使用 aya 提供的上下文方法或 helper；检查 `unsafe` 块；看 verifier log 的指令号。本项目所有包/用户指针访问都经过 helper/边界检查；如果你新增代码，遵循同样规则。

### 2.6 `The sequence of ... jumps is too complex` / `loop is not bounded`

原因：循环次数来自 map/包内容，verifier 无法证明上界。

处理：用 `min(CONST)` 夹紧，或改成固定上界的循环（本项目 `MAX_PORTS`/`MAX_PREFIXES` 就是为此）。

---

## 3. XDP

### 3.1 `failed to attach ... driver mode`

现象：

```text
failed to attach XDP to `eth0` in Driver mode; try `--mode skb`
```

原因：网卡/驱动不支持 native XDP，或接口是 lo/veth 的某些组合。

处理：

```bash
# 先 generic
sudo -E ./target/release/aya-app xdp --iface eth0 --mode skb ...
# 确认驱动
ethtool -i eth0
```

### 3.2 `Operation not supported` / `EINVAL`

原因：

- 接口不存在/拼写错误；
- 已有 XDP 程序占用（netlink 模式可能冲突）；
- 驱动不支持请求的模式。

处理：

```bash
ip link show
sudo bpftool net show
sudo ip link set dev eth0 xdp off   # 清理遗留 XDP
```

### 3.3 ping 仍然通

排查：

1. `--protected-ip` 是否匹配目的地址？先用 `/32`；
2. 包是否经过该接口？veth 方向是否反了？
3. 是否 `--mode skb` 但驱动/路径未执行 XDP？
4. ICMP 类型是否 echo request（type 8）？其他 ICMP 不丢；
5. 是否有其他 XDP 程序先返回了 PASS？

### 3.4 所有包被丢

原因：`protected-ip`/掩码配置过宽，或限速值太小（如 1）。

处理：先用 `--protected-ip <单地址>/32`，把 `--rate-limit` 设为 0 验证；再逐步加策略。

### 3.5 统计增长但无事件

原因：`--event-sample` 太大；ring buffer 满；用户态读取阻塞。

处理：调小采样；检查 `bpftool map show name xdp_events`；确认用户态循环在运行（Ctrl-C 能否退出）。

---

## 4. TC

### 4.1 `tc` attach 失败 / `No such file or directory`

原因：没有 `clsact` qdisc，或接口不存在。

处理：

```bash
sudo tc qdisc add dev eth0 clsact
sudo tc qdisc show dev eth0
```

aya 会尝试自动添加；失败时看 `RUST_LOG=debug` 的 `qdisc_add_clsact` 日志。

### 4.2 丢包不生效

原因：

- 方向反了（ingress vs egress）；
- 接口不对；
- 端口不匹配；
- loopback 路径不经过 clsact（换 veth/真实网卡）。

处理：

```bash
tc filter show dev eth0 egress
tc filter show dev eth0 ingress
```

### 4.3 mark 设置了但优先级不变

原因：

- 根 qdisc 不是 `prio`，或 band 配置不对；
- `fw` 规则 handle 与 `--video-mark` 不一致；
- 方向是 ingress（mark 不影响本地发送队列）；
- TCX/clsact 执行点与 qdisc 顺序不符合预期。

处理：

```bash
tc qdisc show dev eth0
tc filter show dev eth0 parent 1:
# 确保 handle 0x10 == --video-mark 16
```

### 4.4 `tc qdisc del ... clsact` 报错

原因：qdisc 不存在/已被删除。

处理：忽略；或先 `tc qdisc show` 确认。

---

## 5. kprobe

### 5.1 `failed to attach ... ENOENT`

原因：符号不存在、被内联、名字不对。

处理：

```bash
grep -w do_sys_openat2 /proc/kallsyms
grep -E ' (__x64_sys_openat|do_filp_open|vfs_open)$' /proc/kallsyms
```

换符号时必须同步修改参数解析（默认实现假设 arg1 是用户路径指针）。

### 5.2 没有路径事件，但 `opens` 增长

原因：

- 路径不匹配前缀；
- `read_user_string` 失败（坏指针/缺页）；
- 符号参数不是 `const char __user *`。

处理：换前缀；确认符号签名；只做延迟观测。

### 5.3 延迟事件缺失

原因：低于阈值；返回未配对（map 满/进程退出）；kretprobe 未 attach。

处理：降低阈值；增大 `probe_start` 容量；检查两个程序都已 attach。

### 5.4 `ret` 是巨大正数

原因：返回值按有符号 64 位解释；错误是 `-errno`。

处理：负值取 `-ret` 查 errno；例如 `-13` = EACCES。

### 5.5 高频 open 下丢事件

原因：ring buffer 满/map 满/采样不足。

处理：只监控敏感前缀；增大 ring buffer；降低事件字段；生产上考虑 fentry + 采样。

---

## 6. uprobe

### 6.1 `failed to attach ... ENOENT`

原因：符号不存在、被 strip、路径错误、目标未运行（PID 模式）。

处理：

```bash
nm -C target/release/aya-app-demo | grep demo_
readelf -sW target/release/aya-app-demo | grep demo_
```

### 6.2 没有事件

原因：

- 目标没有执行到该函数；
- scope 不匹配（`--pid` 错/进程已退出）；
- 函数被内联（`#[inline(never)]` 缺失）；
- 二进制路径不是实际加载的文件（容器/符号链接）。

处理：`--pid` 确认；用 `nm` 确认；去掉 `--pid` 测试。

### 6.3 参数乱码

原因：目标 ABI 不是 `(u64, char*)`；C++ 成员函数第一个参数是 `this`。

处理：按目标函数签名修改 eBPF 参数读取；C++ 用 demangle 后的签名确认参数顺序。

### 6.4 uprobe 对共享库/容器无效

原因：路径是宿主视角；共享库映射地址不同；容器命名空间不同。

处理：在目标命名空间内执行 agent，或使用容器内路径对应的宿主路径；用 `--pid` 限定。

### 6.5 高频函数开销大

原因：每次调用 map 更新 + 事件。

处理：只挂低频函数；加采样/阈值；用 USDT/应用埋点替代。

---

## 7. tracepoint

### 7.1 `tracefs not found`

处理：

```bash
sudo mount -t tracefs tracefs /sys/kernel/tracing
# 或
sudo mount -t debugfs debugfs /sys/kernel/debug
ls /sys/kernel/debug/tracing/events
```

### 7.2 `field ... not found` / `field ... size`

原因：内核版本/配置不同，字段缺失或大小变化。

处理：

```bash
cat /sys/kernel/tracing/events/sched/sched_switch/format
```

本项目只支持文档列出的字段；`prev_state` 支持 4/8 字节；`bytes` 可选。其他变化需要改 `tracefs.rs` 和 eBPF 读取逻辑。

### 7.3 没有 sched 事件

原因：采样率太低、负载不足、程序未 attach。

处理：`--sched-sample 1`；跑 `stress-ng`；检查 `bpftool prog show`。

### 7.4 事件乱码/字段错位

原因：offset 不匹配（内核/架构/格式变化）；`prev_state` 大小判断错误。

处理：不要硬编码；重新解析 `format`；对比 `bpftool`/`trace-cmd` 输出。

### 7.5 `perf_event_open` 失败

原因：`perf_event_paranoid` 限制、缺少 CAP_PERFMON、PMU 被禁用。

处理：

```bash
cat /proc/sys/kernel/perf_event_paranoid
sudo sysctl kernel.perf_event_paranoid=1
```

---

## 8. socket / cgroup

### 8.1 `failed to open cgroup ... is cgroup v2 mounted?`

处理：

```bash
mount | grep cgroup2
cat /sys/fs/cgroup/cgroup.controllers
```

容器内需要挂载 cgroup2；路径必须在当前命名空间可见。

### 8.2 `EBUSY` / `another program may already be attached`

原因：同 cgroup 的 `single` 模式已有程序。

处理：

```bash
sudo bpftool cgroup tree
# 用 --attach-mode multi，或卸载旧程序
```

### 8.3 SOCK_OPS 没有事件

原因：

- 连接不在该 cgroup；
- `--watch-port` 不匹配；
- 不是 TCP；
- `_CB` 未触发（连接未建立）。

处理：检查 cgroup 成员、端口、`ss -tnp`。

### 8.4 SOCK_OPS 不能拦截连接

这是设计事实，不是 bug：

- `_CB` 返回值被忽略；
- 出站白名单请用 `connect4`；
- 入站白名单请用 `skfilter`。

### 8.5 socket filter 不生效

原因：

- 过滤器附加在别的 socket；
- 源 IP 不在白名单；
- NAT 改变了源 IP；
- 非 IPv4/非 TCP/非 SYN 被放行（设计如此）；
- 客户端复用了已建立的连接（SYN 已经通过）。

处理：`--allow-ip` 加正确源；用 `ss` 确认连接；从新客户端测试。

### 8.6 connect4 导致断网

处理：

1. 在另一个终端 Ctrl-C agent，link 随进程退出 detach；
2. 如果 shell 在受限 cgroup，先把 shell 移回根 cgroup：

```bash
echo $$ | sudo tee /sys/fs/cgroup/cgroup.procs
```

3. 重新设计白名单：至少包含 80/443/53，且只对专用子 cgroup 生效；
4. 不要把 agent 自己放进被限制的 cgroup。

### 8.7 IPv6 不受控

当前只实现 `connect4`、`skfilter` 和 LSM 的 IPv4 解析；IPv6 默认放行。需要 IPv6 策略时增加 `connect6`/`sendmsg6` 程序或明确接受风险。

---

## 9. LSM

### 9.1 `failed to load ... EINVAL`

原因：

- 内核没有 `CONFIG_BPF_LSM=y`；
- 内核没有 BTF（`CONFIG_DEBUG_INFO_BTF`）；
- 内核版本低于 5.7；
- hook 名称与内核 BTF 不匹配（本项目固定 `socket_connect`）。

处理：

```bash
grep CONFIG_BPF_LSM /boot/config-$(uname -r)
test -e /sys/kernel/btf/vmlinux && echo BTF
cat /sys/kernel/security/lsm
```

需要换内核或重新编译内核；单独修改用户态程序无法解决。

### 9.2 `failed to attach ... EBUSY`

原因：

- `socket_connect` 是 **sleepable LSM hook**，但程序没有用 `#[lsm(sleepable, ...)]` 编译；load 会成功，attach 返回 `EBUSY`；
- 内核没有可用的函数跟踪/trampoline 支持（例如 `available_tracers` 只有 `nop`）；
- 该 hook 已被同类型的其他 trampoline/程序占用。

处理：

```bash
# 确认程序 section 是 lsm.s/socket_connect
# 确认源码使用 #[lsm(sleepable, hook = "socket_connect")]
cat /sys/kernel/tracing/available_tracers
```

如果只有 `nop`，说明内核没有 `CONFIG_FUNCTION_TRACER`/direct calls 支持，BPF LSM 无法附加；换通用内核（如发行版的 `linux-lts`/`generic`）。

### 9.3 加载成功但没有事件

原因：`lsm=` 启动参数没有包含 `bpf`，BPF LSM 未启用。

处理：

```bash
cat /sys/kernel/security/lsm
# 期望包含 bpf，例如 lockdown,yama,integrity,apparmor,bpf
```

修改 GRUB 的 `GRUB_CMDLINE_LINUX`，加入 `bpf`，`update-grub` 后重启。

### 9.4 `Btf::from_sys_fs` 失败

原因：没有 `/sys/kernel/btf/vmlinux`。

处理：安装带 BTF 的内核；不要在无 BTF 的内核上使用 LSM。

### 9.5 没有拒绝，但连接正常

原因：

- `--uid` 与客户端 UID 不匹配；
- 目的端口不在 `--block-port`；
- 连接是 IPv6/AF_UNIX（当前放行）；
- 客户端复用了已有连接；
- 另一个 LSM 先返回了 0，本程序应继续判断（若前一个 LSM 返回非 0，本程序直接尊重它）。

处理：用 `--uid "$(id -u)"` 和 IPv4 重新测试；检查 `ss -tnp`；确认端口。

### 9.6 所有连接被拒/业务异常

原因：全局 LSM 黑名单命中关键端口，或未加 `--uid`。

处理：

1. Ctrl-C 停止 agent，link 随进程退出 detach；
2. `bpftool link show` 确认没有残留；
3. 重新设计：只用 `--uid` 限制测试用户，或改用 cgroup/connect4。

### 9.7 IPv6 不受控

当前 LSM 只解析 `AF_INET`；IPv6 放行。需要 IPv6 时扩展 `sockaddr_in6` 解析，或明确接受风险。

---

## 10. 运行时

### 10.1 ring buffer 丢事件

现象：统计增长，但事件数少/不连续。

原因：用户态处理慢、采样率低、ring buffer 太小。

处理：调大 `--event-sample` 的间隔（减少事件）、增大 ring buffer、减少字段、拆分处理任务。

### 10.2 统计为 0

原因：

- 程序未 attach；
- 流量不经过挂钩点；
- map 读取失败（名称/类型不匹配）；
- per-CPU 读取的 CPU 数量不对。

处理：`bpftool map dump`；确认 attach；检查 `RUST_LOG=debug`。

### 10.3 Ctrl-C 后程序仍附加

原因：

- 进程被 `SIGKILL`（link 由内核关闭 fd 时清理，通常会 detach）；
- socket filter 绑定在 listener 上，listener 仍被其他进程持有；
- TC qdisc 残留。

处理：`bpftool net show`、`bpftool cgroup tree`、`tc qdisc show`；手动清理。

### 10.4 时间戳看起来很大

原因：事件用 `bpf_ktime_get_ns()`（boot 以来的单调时间），不是 Unix epoch。

处理：需要墙上时间时，在用户态读取 `/proc/uptime` 或 `clock_gettime(CLOCK_BOOTTIME)` 做偏移换算。

---

## 11. fentry / raw tracepoint / cgroup

### 11.1 fentry/fexit attach 返回 `EBUSY` 或 `ENOENT`

原因：

- 内核没有函数跟踪/trampoline（`available_tracers` 只有 `nop`）；
- 函数不在 BTF 中，或名称写错；
- 内核版本低于 5.5。

处理：

```bash
cat /sys/kernel/tracing/available_tracers
sudo bpftool btf dump file /sys/kernel/btf/vmlinux | grep 'do_sys_openat2'
```

精简的 Alpine `linux-virt` 可能不支持；换 `linux-lts`/发行版通用内核。

### 11.2 raw tracepoint 匹配数为 0

原因：syscall 号与架构/工具链不匹配。BusyBox/musl 的 `cat` 使用 `open`=2，现代 glibc 程序
通常使用 `openat`=257。

处理：

```bash
# 先用 guaranteed 的 read(0) 验证 raw TP 本身
sudo ./target/release/aya-app raw-tp --syscall-nr 0
# 再按实际 syscall 过滤
strace -e openat,open cat /etc/hosts
```

### 11.3 cgroup_skb attach 返回 `EINVAL`

原因：

- cgroup v2 未挂载；
- `CgroupAttachMode::AllowMultiple` 在当前内核的 link 路径不被接受；
- 程序 direction 与 section 不匹配。

处理：挂载 cgroup2；使用 `CgroupAttachMode::Single`（本项目已使用）；检查
`bpftool cgroup tree`。

### 11.4 cgroup_sysctl 返回 `EPERM` 但程序没有日志

原因：返回值语义反了。`cgroup_sysctl` 程序返回 **1 允许**，返回 0 被内核转换为 `-EPERM`。

处理：确认 eBPF 程序在允许路径返回 1、拒绝路径返回 0。

### 11.5 cgroup 场景没有事件

原因：进程不在目标 cgroup；cgroup 路径写错；策略挂到了根 cgroup。

处理：

```bash
cat /proc/<pid>/cgroup
cat /sys/fs/cgroup/<name>/cgroup.procs
```

---

## 12. 快速诊断命令

```bash
# 内核/权限
uname -a
id
cat /proc/sys/kernel/unprivileged_bpf_disabled
ulimit -l

# BPF 状态
sudo bpftool prog show
sudo bpftool map show
sudo bpftool net show
sudo bpftool cgroup tree
sudo bpftool perf show
sudo bpftool link show

# LSM
cat /sys/kernel/security/lsm
test -e /sys/kernel/btf/vmlinux && echo BTF

# 网络
ip link show
tc qdisc show
tc filter show dev <iface> egress
ss -tnp

# tracefs
ls /sys/kernel/tracing/events/sched/sched_switch/format
cat /sys/kernel/tracing/events/sched/sched_switch/format

# 构建
rustc --version
cargo +nightly --version
bpf-linker --version
```

如果问题仍无法定位，附上：

- `uname -a`、发行版、内核配置（`zcat /proc/config.gz | grep BPF`）；
- `RUST_LOG=debug` 的完整 verifier log；
- `bpftool prog show`/`bpftool map show`；
- 触发的命令、接口、cgroup、tracepoint 路径；
- 期望行为与实际行为。

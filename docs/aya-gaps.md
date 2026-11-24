# Aya 场景覆盖与缺口分析

本文回答两个问题：

1. 原项目缺了哪些 **Aya 已经支持** 的场景？
2. 哪些 eBPF 场景是 **Aya 0.16 本身没有封装** 的？

## 1. 本轮新增的四个场景

这四个场景 Aya 0.16 都支持，但原项目没有覆盖：

| 场景 | 命令 | Aya 类型 | 作用 |
|---|---|---|---|
| fentry/fexit | `fentry` | `FEntry` / `FExit` | BTF trampoline 函数跟踪 |
| raw tracepoint | `raw-tp` | `RawTracePoint` | 直接读取 `TP_PROTO` 参数 |
| cgroup_skb | `cgroup-skb` | `CgroupSkb` | 按 cgroup 过滤 ingress/egress |
| cgroup_sysctl | `cgroup-sysctl` | `CgroupSysctl` | 阻止 cgroup 内写 sysctl |

加上原有 XDP、TC、kprobe、uprobe、tracepoint、socket、LSM，项目共覆盖 **11 个场景**。

## 2. Aya 0.16 本身没有封装的场景

截至 `aya 0.16.0` 的 `aya::programs::Program` 枚举和公开 API，以下类型没有对应封装。
它们不是本项目“不想写”，而是需要绕过 Aya 直接发 `bpf(2)`/netlink，已经超出
“基于 Aya” 的项目边界。

| 内核类型/机制 | 引入版本 | Aya 0.16 状态 | 说明/替代 |
|---|---|---|---|
| `BPF_PROG_TYPE_NETFILTER` | 6.4 | 无 `Netfilter` 程序类型 | 需要 netfilter link API（`BPF_LINK_CREATE` + `bpf_netfilter`） |
| `BPF_PROG_TYPE_STRUCT_OPS` | 5.6 | 无 `StructOps` 封装 | TCP 拥塞控制、sched_ext 等依赖 struct_ops |
| `BPF_PROG_TYPE_SCHED_EXT` | 6.12 | 通过 struct_ops 使用 | Aya 无 sched_ext 支持 |
| `tcx` | 6.6 | 无 `Tcx` 链接 API | 可用 TC clsact（本项目 `tc`）替代 |
| `BPF_MODIFY_RETURN` | 5.5 | Aya 源码注明“not supported yet” | 可用 fentry/fexit + 返回值判断替代 |
| `BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE` | 5.2 | 无独立封装 | 普通 raw tracepoint 只能读 |
| `BPF_PROG_TYPE_SYSCALL` | 5.14 | `Program` 枚举无 `Syscall` | 一般由 libbpf 的 syscall 程序使用 |
| `netkit` 链接 | 6.7 | 无 `Netkit` 链接 API | 可用 TC/XDP 替代 |

> 这张表只描述 **Aya 0.16**。升级 Aya 后应重新核对 `Program` 枚举和
> `programs` 模块，避免把“版本缺口”误写成“永久缺口”。

## 3. Aya 支持、但本项目还没做的场景

这些是后续可以继续补的（按实现成本排序）：

| 场景 | Aya 类型 | 典型用途 | 备注 |
|---|---|---|---|
| cgroup_device | `CgroupDevice` | 限制设备访问 | 需要 major/minor 策略 |
| sk_msg + sockmap | `SkMsg` + `SockMap` | TCP 重定向/代理 | 需要维护 socket map |
| sk_lookup | `SkLookup` | 透明端口重定向 | 需要 netns FD 和 `bpf_sk_assign` |
| sk_reuseport | `SkReuseport` | SO_REUSEPORT 负载均衡 | 需要多 listener |
| perf_event | `PerfEvent` | CPU 采样 profiler | 需要 perf event 设置 |
| iter | `Iter` | 导出内核对象 | 需要 iterator 读端 |
| flow_dissector | `FlowDissector` | 自定义流解析 | 需要 flow dissector 挂载 |
| lsm_cgroup | `LsmCgroup` | cgroup 级 LSM | 需要 `BPF_LSM_CGROUP` |
| extension | `Extension` | 替换/扩展 BPF 程序 | 需要目标 prog FD |

## 4. 为什么不用“手写 syscall”硬补

- `struct_ops` 需要注册 `bpf_struct_ops` 描述符、trampoline 和内核 BTF 类型，用户态
  还要处理 map 的 `BPF_MAP_TYPE_STRUCT_OPS` 生命周期；
- `netfilter` 需要 `bpf_netfilter` 的 link/attach 参数和 netns 语义；
- `tcx` 需要新的 netlink 属性与 link 类型。

在本项目里硬编码这些路径会失去 Aya 的类型安全/生命周期管理，也会让文档和测试
偏离“Aya 示例”的定位。因此采用：

1. Aya 支持的场景 → 正常实现；
2. Aya 不支持的场景 → 在本文记录缺口，并给出替代方案；
3. 需要时再单独立项做 raw-syscall 扩展。

## 5. 参考资料

- Aya 0.16 `Program` 枚举：`aya/src/programs/mod.rs`
- Aya 0.16 源码注释：`BPF_MODIFY_RETURN` “not supported yet”
- 内核 UAPI：`include/uapi/linux/bpf.h` 的 `bpf_prog_type` / `bpf_attach_type`
- 内核文档：`Documentation/bpf/`、`Documentation/networking/filter.rst`

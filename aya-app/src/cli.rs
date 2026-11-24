//! Command-line interface.
//!
//! The CLI mirrors the eleven scenario modules one-to-one. Every command loads
//! the same BPF object and only attaches the programs it needs; the object is
//! shared so all programs and maps are visible to `bpftool` in one place.
//!
//! Defaults are chosen to be safe and useful in a lab:
//!
//! * `xdp` defaults to loopback and generic (SKB) mode, which works everywhere;
//! * `tc` defaults to loopback/egress with a small P2P port list;
//! * `kprobe` defaults to `do_sys_openat2` and the two classic sensitive paths;
//! * `uprobe` requires an explicit binary, because attaching to the wrong file
//!   is both useless and noisy;
//! * `tracepoint` defaults to both events with `sched_switch` sampling;
//! * `socket-filter` requires explicit cgroup/allowlist arguments where a
//!   mistake could affect the whole host.

use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Aya eBPF 十一场景实验工具集。
#[derive(Debug, Parser)]
#[command(
    name = "aya-app",
    version,
    about = "aya-app: 用 Aya 实现的 XDP / TC / kprobe / uprobe / tracepoint / socket / LSM / fentry / raw-tp / cgroup 示例",
    long_about = None,
    propagate_version = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// 场景 1：XDP 层 ICMP 过滤 + 单 IP 限速。
    Xdp(XdpArgs),
    /// 场景 2：TC 层 P2P 丢包 + 视频流优先级标记。
    Tc(TcArgs),
    /// 场景 3：kprobe/kretprobe 监控 openat 与调用延迟。
    Kprobe(KprobeArgs),
    /// 场景 4：uprobe/uretprobe 剖析用户态函数。
    Uprobe(UprobeArgs),
    /// 场景 5：tracepoint 观测调度与块设备 I/O。
    Tracepoint(TracepointArgs),
    /// 场景 6：SOCK_OPS 遥测、socket filter 入站白名单、connect4 出站白名单。
    SocketFilter {
        #[command(subcommand)]
        command: SocketFilterCommand,
    },
    /// 场景 7：LSM socket_connect 目的端口拦截。
    Lsm(LsmArgs),
    /// 场景 8：fentry/fexit 基于 BTF 的零开销函数跟踪。
    Fentry(FentryArgs),
    /// 场景 9：raw tracepoint `sys_enter` 系统调用过滤。
    RawTp(RawTpArgs),
    /// 场景 10：cgroup_skb 按 cgroup 的入站/出站端口过滤。
    CgroupSkb(CgroupSkbArgs),
    /// 场景 11：cgroup_sysctl 阻止 cgroup 内的 sysctl 写入。
    CgroupSysctl(CgroupSysctlArgs),
}

/// XDP 附加模式。
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum XdpModeArg {
    /// 让内核选择（通常是 native，失败时回退到 generic）。
    Default,
    /// Generic XDP：在协议栈中执行，兼容性最好，性能最低。
    Skb,
    /// Native XDP：在网卡驱动的 receive path 执行。
    Driver,
    /// Hardware offload：由支持 XDP 的网卡执行。
    Hw,
}

#[derive(Debug, Args)]
pub struct XdpArgs {
    /// 网卡名称，例如 eth0；在 lo 上测试请用 --mode skb。
    #[arg(short, long, default_value = "lo")]
    pub iface: String,

    /// XDP 附加模式。
    #[arg(long, value_enum, default_value_t = XdpModeArg::Default)]
    pub mode: XdpModeArg,

    /// 丢弃匹配保护前缀的 ICMP echo request。
    #[arg(long)]
    pub block_icmp: bool,

    /// 每个源 IP 每秒允许的包数，0 表示关闭限速。
    #[arg(long, value_name = "PPS", default_value_t = 0)]
    pub rate_limit: u32,

    /// 受保护的目的 IPv4 地址（不填表示所有目的地址）。
    #[arg(long, value_name = "ADDR")]
    pub protected_ip: Option<Ipv4Addr>,

    /// 受保护前缀长度，默认 /32。
    #[arg(
        long,
        value_name = "LEN",
        default_value_t = 32,
        value_parser = clap::value_parser!(u8).range(0..=32)
    )]
    pub protected_prefix_len: u8,

    /// 每多少个丢弃事件向 ring buffer 写一条，降低高 PPS 下的开销。
    #[arg(long, value_name = "N", default_value_t = 64, value_parser = clap::value_parser!(u32).range(1..))]
    pub event_sample: u32,

    /// 统计信息打印间隔（秒）。
    #[arg(long, value_name = "SECS", default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub stats_interval: u64,
}

/// TC 方向。
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum DirectionArg {
    Ingress,
    Egress,
}

#[derive(Debug, Args)]
pub struct TcArgs {
    /// 网卡名称。
    #[arg(short, long, default_value = "lo")]
    pub iface: String,

    /// 附加到 ingress 还是 egress；QoS 标记通常使用 egress。
    #[arg(long, value_enum, default_value_t = DirectionArg::Egress)]
    pub direction: DirectionArg,

    /// 要丢弃的目的端口，可重复指定（最多 8 个）。
    #[arg(long = "drop-port", value_name = "PORT", default_values_t = [6881u16, 6882, 6883])]
    pub drop_port: Vec<u16>,

    /// 要打高优先级 mark 的目的端口，可重复指定（最多 8 个）。
    #[arg(long = "video-port", value_name = "PORT", default_values_t = [1935u16, 8080])]
    pub video_port: Vec<u16>,

    /// 写入 skb->mark 的值，需与 `tc filter ... fw` 的 handle 一致。
    #[arg(long, value_name = "MARK", default_value_t = 16)]
    pub video_mark: u32,

    /// 每多少个丢包事件写一条 ring buffer 记录。
    #[arg(long, value_name = "N", default_value_t = 64, value_parser = clap::value_parser!(u32).range(1..))]
    pub event_sample: u32,

    /// 统计信息打印间隔（秒）。
    #[arg(long, value_name = "SECS", default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub stats_interval: u64,
}

#[derive(Debug, Args)]
pub struct KprobeArgs {
    /// 要挂钩的内核函数；默认是 openat(2) 的现代实现。
    #[arg(long, default_value = "do_sys_openat2", value_name = "FUNC")]
    pub symbol: String,

    /// 敏感路径前缀，最多 4 个；重复指定会替换默认值。
    #[arg(long = "path-prefix", value_name = "PREFIX", default_values = ["/etc/shadow", "/etc/passwd"])]
    pub path_prefix: Vec<String>,

    /// 只上报超过该阈值的调用延迟（微秒）。
    #[arg(long, value_name = "US", default_value_t = 1000)]
    pub latency_threshold_us: u64,

    /// 统计信息打印间隔（秒）。
    #[arg(long, value_name = "SECS", default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub stats_interval: u64,
}

#[derive(Debug, Args)]
pub struct UprobeArgs {
    /// 目标 ELF 文件（例如 target/release/aya-app-demo）。
    #[arg(short, long, value_name = "PATH")]
    pub binary: PathBuf,

    /// 目标符号名；demo 使用 demo_handle_request。
    #[arg(long, default_value = "demo_handle_request", value_name = "SYMBOL")]
    pub symbol: String,

    /// 只挂钩指定 PID；不填表示所有进程。
    #[arg(long, value_name = "PID")]
    pub pid: Option<u32>,

    /// 只上报超过该阈值的返回延迟（微秒）。
    #[arg(long, value_name = "US", default_value_t = 1000)]
    pub latency_threshold_us: u64,

    /// 统计信息打印间隔（秒）。
    #[arg(long, value_name = "SECS", default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub stats_interval: u64,
}

/// Tracepoint 选择。
#[derive(Debug, Clone, Copy, ValueEnum, PartialEq, Eq)]
pub enum TraceEventArg {
    All,
    Sched,
    Block,
}

#[derive(Debug, Args)]
pub struct TracepointArgs {
    /// 要观测的 tracepoint 集合。
    #[arg(long, value_enum, default_value_t = TraceEventArg::All)]
    pub event: TraceEventArg,

    /// sched_switch 事件采样率：每 N 个事件输出 1 条。
    #[arg(long, value_name = "N", default_value_t = 64, value_parser = clap::value_parser!(u32).range(1..))]
    pub sched_sample: u32,

    /// block_rq_issue 事件采样率：每 N 个事件输出 1 条。
    #[arg(long, value_name = "N", default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
    pub block_sample: u32,

    /// 统计信息打印间隔（秒）。
    #[arg(long, value_name = "SECS", default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub stats_interval: u64,
}

#[derive(Debug, Subcommand)]
pub enum SocketFilterCommand {
    /// 只观测 TCP 连接生命周期，并演示 SOCK_OPS 字段；不会拦截连接。
    Sockops(SockOpsArgs),
    /// 在监听 socket 上附加经典 socket filter，对入站 SYN 做源 IP 白名单。
    Skfilter(SkFilterArgs),
    /// 在 cgroup 上附加 connect4 程序，对出站连接做端口白名单。
    Connect4(Connect4Args),
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CgroupModeArg {
    /// 同一 cgroup 只允许一个程序（默认，最安全）。
    Single,
    /// 允许与其它程序共存。
    Multi,
}

#[derive(Debug, Args)]
pub struct SockOpsArgs {
    /// cgroup v2 挂载点或子 cgroup 路径。
    #[arg(long, default_value = "/sys/fs/cgroup", value_name = "PATH")]
    pub cgroup: PathBuf,

    /// 只观测本地或远端端口在列表中的连接，可重复指定。
    #[arg(long = "watch-port", value_name = "PORT")]
    pub watch_port: Vec<u16>,

    /// cgroup 附加模式。
    #[arg(long, value_enum, default_value_t = CgroupModeArg::Single)]
    pub attach_mode: CgroupModeArg,

    /// 统计信息打印间隔（秒）。
    #[arg(long, value_name = "SECS", default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub stats_interval: u64,
}

#[derive(Debug, Args)]
pub struct SkFilterArgs {
    /// 监听地址；过滤器附加到这个监听 socket 上。
    #[arg(long, default_value = "127.0.0.1:8080", value_name = "ADDR")]
    pub listen: SocketAddr,

    /// 允许建立连接的源 IPv4，可重复指定；为空表示只观测、不拦截。
    #[arg(long = "allow-ip", value_name = "ADDR")]
    pub allow_ip: Vec<Ipv4Addr>,

    /// 统计信息打印间隔（秒）。
    #[arg(long, value_name = "SECS", default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub stats_interval: u64,
}

#[derive(Debug, Args)]
pub struct Connect4Args {
    /// 要施加策略的 cgroup v2 路径；建议使用专用子 cgroup，而不是根 cgroup。
    #[arg(long, value_name = "PATH")]
    pub cgroup: PathBuf,

    /// 允许的出站目的端口，必须至少指定一个。
    #[arg(long = "allow-port", value_name = "PORT", required = true)]
    pub allow_port: Vec<u16>,

    /// cgroup 附加模式。
    #[arg(long, value_enum, default_value_t = CgroupModeArg::Single)]
    pub attach_mode: CgroupModeArg,

    /// 统计信息打印间隔（秒）。
    #[arg(long, value_name = "SECS", default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub stats_interval: u64,
}

#[derive(Debug, Args)]
pub struct LsmArgs {
    /// 要拦截的目的端口，必须至少指定一个；LSM 是全局钩子，请谨慎选择。
    #[arg(long = "block-port", value_name = "PORT", required = true)]
    pub block_port: Vec<u16>,

    /// 只对指定 UID 生效；不填表示对整机所有进程生效。
    #[arg(long, value_name = "UID")]
    pub uid: Option<u32>,

    /// 拒绝事件采样率：每 N 个拒绝事件输出 1 条。
    #[arg(long, value_name = "N", default_value_t = 16, value_parser = clap::value_parser!(u32).range(1..))]
    pub event_sample: u32,

    /// 统计信息打印间隔（秒）。
    #[arg(long, value_name = "SECS", default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub stats_interval: u64,
}

#[derive(Debug, Args)]
pub struct FentryArgs {
    /// 要跟踪的内核函数；必须在 /sys/kernel/btf/vmlinux 中有 BTF 记录。
    #[arg(long, default_value = "do_sys_openat2", value_name = "FUNC")]
    pub symbol: String,

    /// 只上报超过该阈值的调用延迟（微秒）。
    #[arg(long, value_name = "US", default_value_t = 0)]
    pub latency_threshold_us: u64,

    /// 退出事件采样率：每 N 个事件输出 1 条。
    #[arg(long, value_name = "N", default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
    pub event_sample: u32,

    /// 统计信息打印间隔（秒）。
    #[arg(long, value_name = "SECS", default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub stats_interval: u64,
}

#[derive(Debug, Args)]
pub struct RawTpArgs {
    /// 要过滤的系统调用号；x86_64 的 open=2，openat=257；aarch64 的 openat=56。
    #[arg(long, value_name = "NR", default_value_t = 2)]
    pub syscall_nr: u32,

    /// 事件采样率：每 N 个匹配输出 1 条。
    #[arg(long, value_name = "N", default_value_t = 1, value_parser = clap::value_parser!(u32).range(1..))]
    pub event_sample: u32,

    /// 统计信息打印间隔（秒）。
    #[arg(long, value_name = "SECS", default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub stats_interval: u64,
}

#[derive(Debug, Args)]
pub struct CgroupSkbArgs {
    /// 要施加策略的 cgroup v2 路径；建议使用专用子 cgroup。
    #[arg(long, value_name = "PATH")]
    pub cgroup: PathBuf,

    /// 在 ingress 还是 egress 方向过滤。
    #[arg(long, value_enum, default_value_t = DirectionArg::Egress)]
    pub direction: DirectionArg,

    /// 要丢弃的目的端口（host order）；0 表示只观测。
    #[arg(long, value_name = "PORT", default_value_t = 8080)]
    pub block_port: u16,

    /// 丢弃事件采样率。
    #[arg(long, value_name = "N", default_value_t = 64, value_parser = clap::value_parser!(u32).range(1..))]
    pub event_sample: u32,

    /// 统计信息打印间隔（秒）。
    #[arg(long, value_name = "SECS", default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub stats_interval: u64,
}

#[derive(Debug, Args)]
pub struct CgroupSysctlArgs {
    /// 要施加策略的 cgroup v2 路径；建议使用专用子 cgroup。
    #[arg(long, value_name = "PATH")]
    pub cgroup: PathBuf,

    /// 只观测，不拒绝 sysctl 写入。
    #[arg(long)]
    pub observe: bool,

    /// 拒绝事件采样率。
    #[arg(long, value_name = "N", default_value_t = 16, value_parser = clap::value_parser!(u32).range(1..))]
    pub event_sample: u32,

    /// 统计信息打印间隔（秒）。
    #[arg(long, value_name = "SECS", default_value_t = 5, value_parser = clap::value_parser!(u64).range(1..=3600))]
    pub stats_interval: u64,
}

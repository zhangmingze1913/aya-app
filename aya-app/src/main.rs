//! `aya-app` — Aya eBPF 十一场景实验工具集。
//!
//! # 场景与命令
//!
//! | 场景 | 命令 | 挂钩点 | 是否可拦截 |
//! |---|---|---|---|
//! | 1 | `xdp` | 网卡驱动 / generic XDP | 是（XDP_DROP） |
//! | 2 | `tc` | clsact ingress/egress | 是（TC_ACT_SHOT） |
//! | 3 | `kprobe` | `do_sys_openat2` 等内核函数 | 否（观测） |
//! | 4 | `uprobe` | 用户态 ELF 符号 | 否（观测） |
//! | 5 | `tracepoint` | sched / block tracepoint | 否（观测） |
//! | 6 | `socket-filter` | SOCK_OPS / socket filter / connect4 | 视子命令而定 |
//! | 7 | `lsm` | LSM `socket_connect` | 是（返回 `-EPERM`） |
//! | 8 | `fentry` | fentry/fexit BTF trampoline | 否（观测） |
//! | 9 | `raw-tp` | raw tracepoint `sys_enter` | 否（观测） |
//! | 10 | `cgroup-skb` | cgroup_skb ingress/egress | 是（返回 1） |
//! | 11 | `cgroup-sysctl` | cgroup_sysctl 读写钩子 | 是（拒绝写入） |
//!
//! # 运行前提
//!
//! * Linux 内核 ≥ 5.8（ring buffer）。推荐 ≥ 5.15。
//! * root 或 `CAP_BPF` + `CAP_NET_ADMIN` + `CAP_PERFMON`（具体取决于内核）。
//! * tracefs 已挂载（tracepoint 场景）。
//! * cgroup v2（socket-filter 的 sockops/connect4 子命令）。
//! * `CONFIG_BPF_LSM=y`、BTF，且 `lsm=` 启动参数包含 `bpf`（lsm 场景）。
//!
//! 详细说明见仓库 `README.md` 与 `docs/`。

mod cli;
mod commands;
mod ebpf;
mod event;
mod format;
mod stats;
mod tracefs;

/// Writes one buffered event line. Use for per-event output only; stats and
/// banners must go through normal `println!` after `format::flush_events()`.
#[macro_export]
macro_rules! eventln {
    ($($arg:tt)*) => {
        $crate::format::event(format_args!($($arg)*))
    };
}

use clap::Parser;

use crate::cli::{Cli, Command};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    // Older kernels account BPF memory against RLIMIT_MEMLOCK. Do this before
    // loading any object; failure is non-fatal and reported at debug level.
    ebpf::raise_memlock_limit();

    let cli = Cli::parse();
    match cli.command {
        Command::Xdp(args) => commands::xdp::run(args).await,
        Command::Tc(args) => commands::tc::run(args).await,
        Command::Kprobe(args) => commands::kprobe::run(args).await,
        Command::Uprobe(args) => commands::uprobe::run(args).await,
        Command::Tracepoint(args) => commands::tracepoint::run(args).await,
        Command::SocketFilter { command } => commands::socket::run(command).await,
        Command::Lsm(args) => commands::lsm::run(args).await,
        Command::Fentry(args) => commands::fentry::run(args).await,
        Command::RawTp(args) => commands::raw_tp::run(args).await,
        Command::CgroupSkb(args) => commands::cgroup_skb::run(args).await,
        Command::CgroupSysctl(args) => commands::cgroup_sysctl::run(args).await,
    }
}

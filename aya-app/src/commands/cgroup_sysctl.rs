//! `aya-app cgroup-sysctl` — deny `/proc/sys` writes from a cgroup.
//!
//! Lifecycle: open the target cgroup, load the cgroup_sysctl-only object, write
//! the observe/deny config, attach the hook, then run the shared loop.
//! The BPF context has no sysctl name, so the policy is deliberately coarse:
//! all writes in this cgroup are denied unless `--observe` is used.

use std::{fs::File, path::Path};

use anyhow::Context as _;
use aya::{
    maps::{Array, MapData, PerCpuArray},
    programs::{CgroupAttachMode, CgroupSysctl},
};
use aya_app_common::{CgSysctlConfig, CgSysctlEvent, CgSysctlStats};

use crate::{
    cli::CgroupSysctlArgs,
    commands::runner,
    ebpf,
    event::EventStream,
    format::{banner, comm, stats_header, uptime},
    stats::{sum_percpu, take_percpu},
};

pub async fn run(args: CgroupSysctlArgs) -> anyhow::Result<()> {
    let cgroup = open_cgroup(&args.cgroup)?;

    let config = CgSysctlConfig {
        block_writes: u32::from(!args.observe),
        event_sample: args.event_sample,
    };

    let mut bpf = ebpf::load(ebpf::Object::CgroupSysctl)?;

    {
        let map = bpf
            .map_mut("cgsysctl_config")
            .context("map `cgsysctl_config` missing from the eBPF object")?;
        let mut config_map = Array::<_, CgSysctlConfig>::try_from(map)
            .context("`cgsysctl_config` is not an Array<CgSysctlConfig>")?;
        config_map
            .set(0, &config, 0)
            .context("failed to write cgsysctl_config")?;
    }

    {
        let program: &mut CgroupSysctl = bpf
            .program_mut("cgsysctl_guard")
            .context("program `cgsysctl_guard` missing")?
            .try_into()
            .context("`cgsysctl_guard` is not a CgroupSysctl program")?;
        program.load().context(
            "failed to load cgroup_sysctl; check CONFIG_CGROUP_SYSCTL and CONFIG_CGROUP_BPF",
        )?;
        program
            .attach(&cgroup, CgroupAttachMode::Single)
            .with_context(|| {
                format!(
                    "failed to attach cgroup_sysctl to {}",
                    args.cgroup.display()
                )
            })?;
    }

    let stats = take_percpu::<CgSysctlStats>(&mut bpf, "cgsysctl_stats")?;
    let events = EventStream::take(&mut bpf, "cgsysctl_events")?;

    banner(
        "cgroup_sysctl guard",
        &[
            format!("cgroup      : {}", args.cgroup.display()),
            format!(
                "mode        : {}",
                if args.observe {
                    "observe only"
                } else {
                    "deny writes"
                }
            ),
            format!("event sample: 1/{}", args.event_sample),
            "说明        : 读操作放行；写操作返回 0，内核转换为 EPERM".to_string(),
        ],
    );
    println!("Ctrl-C 退出。测试：把 shell 放入该 cgroup，再执行 sysctl -w net.ipv4.ip_forward=1。");
    println!("注意：策略是 cgroup 级的，会影响该子树内所有进程。");

    runner::run_events(
        stats,
        events,
        args.stats_interval,
        print_event,
        read_stats,
        print_stats,
        "cgroup_sysctl",
    )
    .await?;

    drop(bpf);
    println!("已退出。");
    Ok(())
}

fn open_cgroup(path: &Path) -> anyhow::Result<File> {
    File::open(path).with_context(|| {
        format!(
            "failed to open cgroup {}; is cgroup v2 mounted?",
            path.display()
        )
    })
}

fn read_stats(map: &PerCpuArray<MapData, CgSysctlStats>) -> anyhow::Result<CgSysctlStats> {
    sum_percpu(map, |total, value| {
        total.calls += value.calls;
        total.writes += value.writes;
        total.blocked += value.blocked;
        total.reads += value.reads;
    })
}

fn print_event(event: CgSysctlEvent) {
    println!(
        "[sysctl-deny] t={} pid={} tid={} comm={} uid={} write={}",
        uptime(event.timestamp_ns),
        event.tgid,
        event.pid,
        comm(&event.comm),
        event.uid,
        event.write
    );
}

fn print_stats(now: &CgSysctlStats, previous: &CgSysctlStats, interval_secs: u64) {
    let dt = interval_secs.max(1) as f64;
    let d_calls = now.calls.saturating_sub(previous.calls);
    let d_writes = now.writes.saturating_sub(previous.writes);
    let d_blocked = now.blocked.saturating_sub(previous.blocked);

    stats_header("cgroup_sysctl stats");
    println!(
        "calls   : {:>12}  ({:>9.1}/s)",
        now.calls,
        d_calls as f64 / dt
    );
    println!(
        "writes  : {:>12}  ({:>9.1}/s)",
        now.writes,
        d_writes as f64 / dt
    );
    println!(
        "blocked : {:>12}  ({:>9.1}/s)  reads={}",
        now.blocked,
        d_blocked as f64 / dt,
        now.reads
    );
}

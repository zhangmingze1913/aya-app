//! `aya-app cgroup-skb` — per-cgroup ingress/egress port filtering.
//!
//! Lifecycle: open the target cgroup, load the cgroup_skb-only object, write
//! the port/sampling config, attach the ingress or egress program, then run
//! the shared loop. The policy boundary is the cgroup, not a NIC.

use std::{fs::File, path::Path};

use anyhow::Context as _;
use aya::{
    maps::{Array, MapData, PerCpuArray},
    programs::{CgroupAttachMode, CgroupSkb, CgroupSkbAttachType},
};
use aya_app_common::{CgSkbConfig, CgSkbEvent, CgSkbStats};

use crate::{
    cli::{CgroupSkbArgs, DirectionArg},
    commands::runner,
    ebpf,
    event::EventStream,
    format::{banner, bytes, comm, ipv4, stats_header, uptime},
    stats::{sum_percpu, take_percpu},
};

pub async fn run(args: CgroupSkbArgs) -> anyhow::Result<()> {
    let cgroup = open_cgroup(&args.cgroup)?;
    let (program_name, attach_type) = match args.direction {
        DirectionArg::Ingress => ("cgskb_ingress", CgroupSkbAttachType::Ingress),
        DirectionArg::Egress => ("cgskb_egress", CgroupSkbAttachType::Egress),
    };

    let config = CgSkbConfig {
        block_port: args.block_port,
        event_sample: args.event_sample,
        ..Default::default()
    };

    let mut bpf = ebpf::load(ebpf::Object::CgroupSkb)?;

    {
        let map = bpf
            .map_mut("cgskb_config")
            .context("map `cgskb_config` missing from the eBPF object")?;
        let mut config_map = Array::<_, CgSkbConfig>::try_from(map)
            .context("`cgskb_config` is not an Array<CgSkbConfig>")?;
        config_map
            .set(0, &config, 0)
            .context("failed to write cgskb_config")?;
    }

    {
        let program: &mut CgroupSkb = bpf
            .program_mut(program_name)
            .with_context(|| format!("program `{program_name}` missing"))?
            .try_into()
            .context("program is not a CgroupSkb program")?;
        program
            .load()
            .context("failed to load cgroup_skb; check CONFIG_CGROUP_BPF and CAP_NET_ADMIN")?;
        program
            .attach(&cgroup, attach_type, CgroupAttachMode::Single)
            .with_context(|| {
                format!(
                    "failed to attach cgroup_skb to {}; check cgroup v2 and permissions",
                    args.cgroup.display()
                )
            })?;
    }

    let stats = take_percpu::<CgSkbStats>(&mut bpf, "cgskb_stats")?;
    let events = EventStream::take(&mut bpf, "cgskb_events")?;

    banner(
        "cgroup_skb port filter",
        &[
            format!("cgroup      : {}", args.cgroup.display()),
            format!("direction   : {:?}", args.direction),
            format!(
                "block port  : {}",
                if args.block_port == 0 {
                    "disabled (observe only)".to_string()
                } else {
                    args.block_port.to_string()
                }
            ),
            format!("event sample: 1/{}", args.event_sample),
        ],
    );
    println!("Ctrl-C 退出。测试：把客户端进程放入该 cgroup，再连接被拦截的端口。");
    println!("注意：cgroup_skb 作用于该 cgroup 的 socket，不是单张网卡。");

    runner::run_events(
        stats,
        events,
        args.stats_interval,
        print_event,
        read_stats,
        print_stats,
        "cgroup_skb",
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

fn read_stats(map: &PerCpuArray<MapData, CgSkbStats>) -> anyhow::Result<CgSkbStats> {
    sum_percpu(map, |total, value| {
        total.passed += value.passed;
        total.dropped += value.dropped;
        total.passed_bytes += value.passed_bytes;
        total.dropped_bytes += value.dropped_bytes;
    })
}

fn print_event(event: CgSkbEvent) {
    println!(
        "[cgroup-skb drop] t={} pid={} tid={} comm={} {}:{} -> {}:{} len={}",
        uptime(event.timestamp_ns),
        event.tgid,
        event.pid,
        comm(&event.comm),
        ipv4(event.saddr),
        event.sport,
        ipv4(event.daddr),
        event.dport,
        event.pkt_len
    );
}

fn print_stats(now: &CgSkbStats, previous: &CgSkbStats, interval_secs: u64) {
    let dt = interval_secs.max(1) as f64;
    let d_passed = now.passed.saturating_sub(previous.passed);
    let d_dropped = now.dropped.saturating_sub(previous.dropped);

    stats_header("cgroup_skb stats");
    println!(
        "pass  : {:>12}  ({:>9.1}/s, {:>10}/s)",
        now.passed,
        d_passed as f64 / dt,
        bytes((now.passed_bytes.saturating_sub(previous.passed_bytes)) / interval_secs.max(1))
    );
    println!(
        "drop  : {:>12}  ({:>9.1}/s, {:>10}/s)",
        now.dropped,
        d_dropped as f64 / dt,
        bytes((now.dropped_bytes.saturating_sub(previous.dropped_bytes)) / interval_secs.max(1))
    );
    println!(
        "bytes : pass={}  drop={}",
        bytes(now.passed_bytes),
        bytes(now.dropped_bytes)
    );
}

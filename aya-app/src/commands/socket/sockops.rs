use anyhow::{Context as _, bail};
use aya::{
    maps::{Array, MapData, PerCpuArray},
    programs::SockOps,
};
use aya_app_common::{MAX_PORTS, SockOpsConfig, SockOpsEvent, SockOpsStats};

use crate::{
    cli::SockOpsArgs,
    commands::runner,
    ebpf,
    event::EventStream,
    format::{banner, bytes, comm, duration_ns, ipv4, stats_header, uptime},
    stats::{sum_percpu, take_percpu},
};

use super::{attach_mode, open_cgroup};

pub(super) async fn run(args: SockOpsArgs) -> anyhow::Result<()> {
    if args.watch_port.len() > MAX_PORTS {
        bail!(
            "at most {MAX_PORTS} --watch-port values are supported (got {})",
            args.watch_port.len()
        );
    }

    let cgroup = open_cgroup(&args.cgroup)?;
    let mut bpf = ebpf::load(ebpf::Object::Socket)?;

    let mut config = SockOpsConfig::default();
    for (slot, port) in config.watch_ports.iter_mut().zip(args.watch_port.iter()) {
        *slot = *port;
    }
    config.watch_port_count = args.watch_port.len() as u32;

    {
        let map = bpf
            .map_mut("sockops_config")
            .context("map `sockops_config` missing from the eBPF object")?;
        let mut config_map = Array::<_, SockOpsConfig>::try_from(map)
            .context("`sockops_config` is not an Array<SockOpsConfig>")?;
        config_map
            .set(0, &config, 0)
            .context("failed to write sockops_config")?;
    }

    {
        let program: &mut SockOps = bpf
            .program_mut("sockops_guard")
            .context("program `sockops_guard` missing")?
            .try_into()
            .context("`sockops_guard` is not a SockOps program")?;
        program.load().context(
            "failed to load the SOCK_OPS program; run with RUST_LOG=debug for the verifier log",
        )?;
        program
            .attach(&cgroup, attach_mode(args.attach_mode))
            .with_context(|| {
                format!(
                    "failed to attach SOCK_OPS to {}; another program may already be attached",
                    args.cgroup.display()
                )
            })?;
    }

    let stats = take_percpu::<SockOpsStats>(&mut bpf, "sockops_stats")?;
    let events = EventStream::take(&mut bpf, "sockops_events")?;

    banner(
        "SOCK_OPS telemetry",
        &[
            format!("cgroup       : {}", args.cgroup.display()),
            format!("watch ports  : {:?}", args.watch_port),
            format!("attach mode  : {:?}", args.attach_mode),
            "提醒         : SOCK_OPS 回调的返回值被内核忽略，本命令不会拦截连接".to_string(),
        ],
    );
    println!("Ctrl-C 退出。请在 cgroup 内发起 TCP 连接（例如 curl https://example.com）。");

    runner::run_events(
        stats,
        events,
        args.stats_interval,
        print_event,
        read_stats,
        print_stats,
        "SOCK_OPS",
    )
    .await?;

    drop(bpf);
    println!("已退出。");
    Ok(())
}

fn sock_op_name(op: u32) -> &'static str {
    match op {
        1 => "timeout_init",
        2 => "rwnd_init",
        3 => "tcp_connect",
        4 => "active_established",
        5 => "passive_established",
        6 => "needs_ecn",
        7 => "base_rtt",
        8 => "rto",
        9 => "retrans",
        10 => "state",
        11 => "tcp_listen",
        12 => "rtt",
        _ => "other",
    }
}

fn print_event(event: SockOpsEvent) {
    crate::eventln!(
        "[sockops] t={} op={:<20} pid={} comm={} {}:{} -> {}:{} srtt={} acked={} recv={} state={}",
        uptime(event.timestamp_ns),
        sock_op_name(event.op),
        event.pid,
        comm(&event.comm),
        ipv4(event.local_ip4),
        event.local_port,
        ipv4(event.remote_ip4),
        event.remote_port,
        duration_ns(u64::from(event.srtt_us) * 1_000),
        bytes(event.bytes_acked),
        bytes(event.bytes_received),
        event.state
    );
}

fn read_stats(map: &PerCpuArray<MapData, SockOpsStats>) -> anyhow::Result<SockOpsStats> {
    sum_percpu(map, |total, value| {
        total.connect_events += value.connect_events;
        total.established_events += value.established_events;
        total.listen_events += value.listen_events;
        total.state_events += value.state_events;
    })
}

fn print_stats(now: &SockOpsStats, previous: &SockOpsStats, interval_secs: u64) {
    let dt = interval_secs.max(1) as f64;
    let d_connect = now.connect_events.saturating_sub(previous.connect_events);
    let d_established = now
        .established_events
        .saturating_sub(previous.established_events);
    stats_header("SOCK_OPS stats");
    println!(
        "connect     : {:>10} ({:>8.1}/s)",
        now.connect_events,
        d_connect as f64 / dt
    );
    println!(
        "established : {:>10} ({:>8.1}/s)",
        now.established_events,
        d_established as f64 / dt
    );
    println!(
        "listen      : {:>10}    state: {}",
        now.listen_events, now.state_events
    );
}

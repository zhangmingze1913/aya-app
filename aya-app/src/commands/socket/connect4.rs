use anyhow::{Context as _, bail};
use aya::{
    maps::{Array, MapData, PerCpuArray},
    programs::CgroupSockAddr,
};
use aya_app_common::{Connect4Config, Connect4Event, Connect4Stats, MAX_PORTS};

use crate::{
    cli::Connect4Args,
    commands::runner,
    ebpf,
    event::EventStream,
    format::{banner, comm, ipv4, stats_header, uptime},
    stats::{sum_percpu, take_percpu},
};

use super::{attach_mode, open_cgroup};

pub(super) async fn run(args: Connect4Args) -> anyhow::Result<()> {
    if args.allow_port.is_empty() {
        bail!("--allow-port is required; refusing to deny all egress traffic");
    }
    if args.allow_port.len() > MAX_PORTS {
        bail!(
            "at most {MAX_PORTS} --allow-port values are supported (got {})",
            args.allow_port.len()
        );
    }
    if args.allow_port.contains(&0) {
        bail!("port numbers must be in 1..=65535");
    }

    let cgroup = open_cgroup(&args.cgroup)?;
    let mut bpf = ebpf::load(ebpf::Object::Socket)?;

    let mut config = Connect4Config::default();
    for (slot, port) in config.allow_ports.iter_mut().zip(args.allow_port.iter()) {
        *slot = *port;
    }
    config.allow_port_count = args.allow_port.len() as u32;

    {
        let map = bpf
            .map_mut("connect4_config")
            .context("map `connect4_config` missing from the eBPF object")?;
        let mut config_map = Array::<_, Connect4Config>::try_from(map)
            .context("`connect4_config` is not an Array<Connect4Config>")?;
        config_map
            .set(0, &config, 0)
            .context("failed to write connect4_config")?;
    }

    {
        let program: &mut CgroupSockAddr = bpf
            .program_mut("connect4_guard")
            .context("program `connect4_guard` missing")?
            .try_into()
            .context("`connect4_guard` is not a CgroupSockAddr program")?;
        program.load().context(
            "failed to load the connect4 program; run with RUST_LOG=debug for the verifier log",
        )?;
        program
            .attach(&cgroup, attach_mode(args.attach_mode))
            .with_context(|| {
                format!(
                    "failed to attach connect4 to {}; another program may already be attached",
                    args.cgroup.display()
                )
            })?;
    }

    let stats = take_percpu::<Connect4Stats>(&mut bpf, "connect4_stats")?;
    let events = EventStream::take(&mut bpf, "connect4_events")?;

    banner(
        "cgroup/connect4 egress allowlist",
        &[
            format!("cgroup      : {}", args.cgroup.display()),
            format!("allow ports : {:?}", args.allow_port),
            format!("attach mode : {:?}", args.attach_mode),
            "警告        : 该策略影响 cgroup 内所有进程；不要在生产环境直接挂到根 cgroup"
                .to_string(),
        ],
    );
    println!(
        "Ctrl-C 退出。测试：在目标 cgroup 内执行 `curl http://example.com` 与 `curl http://example.com:8080`。"
    );
    println!("注意：DNS(53) 不在白名单时，按域名访问会先失败；请用 IP 测试或把 53 加入白名单。");

    runner::run_events(
        stats,
        events,
        args.stats_interval,
        print_event,
        read_stats,
        print_stats,
        "connect4",
    )
    .await?;

    drop(bpf);
    println!("已退出。");
    Ok(())
}

fn print_event(event: Connect4Event) {
    println!(
        "[connect4-deny] t={} pid={} comm={} dst={}:{}",
        uptime(event.timestamp_ns),
        event.pid,
        comm(&event.comm),
        ipv4(event.daddr),
        event.dport
    );
}

fn read_stats(map: &PerCpuArray<MapData, Connect4Stats>) -> anyhow::Result<Connect4Stats> {
    sum_percpu(map, |total, value| {
        total.connects += value.connects;
        total.allowed += value.allowed;
        total.denied += value.denied;
    })
}

fn print_stats(now: &Connect4Stats, previous: &Connect4Stats, interval_secs: u64) {
    let dt = interval_secs.max(1) as f64;
    let d_connects = now.connects.saturating_sub(previous.connects);
    let d_denied = now.denied.saturating_sub(previous.denied);
    stats_header("connect4 stats");
    println!(
        "connects : {:>10} ({:>8.1}/s)",
        now.connects,
        d_connects as f64 / dt
    );
    println!(
        "allowed  : {:>10}    denied: {:>10} ({:.1} deny/s)",
        now.allowed,
        now.denied,
        d_denied as f64 / dt
    );
}

//! `aya-app xdp` — DDoS / ICMP / per-IP rate limiting at the driver edge.
//!
//! Lifecycle: convert CLI knobs into `XdpConfig`, load the XDP-only object,
//! attach the program, then hand the ring buffer and per-CPU stats to the
//! shared runner. No other scenario's maps are created by this command.

use anyhow::Context as _;
use aya::{
    maps::{Array, MapData, PerCpuArray},
    programs::{Xdp, XdpMode},
};
use aya_app_common::{XDP_DROP_ICMP, XDP_DROP_RATE, XdpConfig, XdpEvent, XdpStats};

use crate::{
    cli::{XdpArgs, XdpModeArg},
    commands::runner,
    ebpf,
    event::EventStream,
    format::{self, banner, bytes, ipv4, stats_header, uptime},
    stats::{sum_percpu, take_percpu},
};

pub async fn run(args: XdpArgs) -> anyhow::Result<()> {
    let iface = ebpf::cstring(&args.iface)?;
    let mode = match args.mode {
        XdpModeArg::Default => XdpMode::default(),
        XdpModeArg::Skb => XdpMode::Skb,
        XdpModeArg::Driver => XdpMode::Driver,
        XdpModeArg::Hw => XdpMode::Hardware,
    };

    // The object was built with only the `xdp` feature, so it contains the
    // firewall program and the four XDP maps.
    let mut bpf = ebpf::load(ebpf::Object::Xdp)?;

    // XDP receives addresses in the raw network-order representation used by
    // the packet headers; convert the CLI dotted-quad to the same form.
    let protected_ip = args.protected_ip.map(format::ipv4_to_raw).unwrap_or(0);
    let protected_mask = if args.protected_ip.is_some() {
        format::prefix_mask(args.protected_prefix_len)
    } else {
        0
    };

    let config = XdpConfig {
        block_icmp: u32::from(args.block_icmp),
        rate_limit_pps: args.rate_limit,
        protected_ip,
        protected_mask,
        event_sample: args.event_sample,
        _pad: 0,
    };

    {
        // Configuration must be written before attach: the eBPF program treats
        // it as read-only and may run as soon as the link is installed.
        let map = bpf
            .map_mut("xdp_config")
            .context("map `xdp_config` missing from the eBPF object")?;
        let mut config_map = Array::<_, XdpConfig>::try_from(map)
            .context("`xdp_config` is not an Array<XdpConfig>")?;
        config_map
            .set(0, &config, 0)
            .context("failed to write xdp_config")?;
    }

    {
        let program: &mut Xdp = bpf
            .program_mut("xdp_firewall")
            .context("program `xdp_firewall` missing from the eBPF object")?
            .try_into()
            .context("`xdp_firewall` is not an XDP program")?;
        program.load().context(
            "failed to load the XDP program; run with RUST_LOG=debug to see the verifier log",
        )?;
        program.attach(iface.as_c_str(), mode).with_context(|| {
            format!(
                "failed to attach XDP to `{}` in {mode:?} mode; try `--mode skb` for loopback/veth",
                args.iface
            )
        })?;
        // The fd link is stored inside `bpf`; dropping `bpf` detaches it.
    }

    // Ring buffer and stats maps are owned by userspace after this point. The
    // attached programs keep their own file descriptors to the same maps.
    let stats = take_percpu::<XdpStats>(&mut bpf, "xdp_stats")?;
    let events = EventStream::take(&mut bpf, "xdp_events")?;

    let protected = match args.protected_ip {
        Some(ip) => format!("{}/{}", ip, args.protected_prefix_len),
        None => "all destinations".to_string(),
    };
    banner(
        "XDP firewall",
        &[
            format!("interface      : {}", args.iface),
            format!("mode           : {mode:?}"),
            format!("block ICMP echo: {}", args.block_icmp),
            format!("rate limit     : {} pkt/s per source IP", args.rate_limit),
            format!("protected      : {protected}"),
            format!("event sampling : 1/{}", args.event_sample),
        ],
    );
    println!("Ctrl-C 退出；XDP link 会随进程关闭自动 detach。");

    runner::run_events(
        stats,
        events,
        args.stats_interval,
        print_event,
        read_stats,
        print_stats,
        "XDP 程序",
    )
    .await?;

    drop(bpf);
    println!("已退出。");
    Ok(())
}

fn read_stats(map: &PerCpuArray<MapData, XdpStats>) -> anyhow::Result<XdpStats> {
    sum_percpu(map, |total, value| {
        total.passed += value.passed;
        total.dropped_icmp += value.dropped_icmp;
        total.dropped_rate += value.dropped_rate;
        total.passed_bytes += value.passed_bytes;
        total.dropped_bytes += value.dropped_bytes;
    })
}

fn print_event(event: XdpEvent) {
    let reason = match event.reason {
        XDP_DROP_ICMP => "icmp",
        XDP_DROP_RATE => "rate",
        _ => "unknown",
    };
    println!(
        "[drop] t={} {} -> {} len={} reason={}",
        uptime(event.timestamp_ns),
        ipv4(event.saddr),
        ipv4(event.daddr),
        event.pkt_len,
        reason
    );
}

fn print_stats(now: &XdpStats, previous: &XdpStats, interval_secs: u64) {
    let dt = interval_secs.max(1) as f64;
    let d_passed = now.passed.saturating_sub(previous.passed);
    let d_icmp = now.dropped_icmp.saturating_sub(previous.dropped_icmp);
    let d_rate = now.dropped_rate.saturating_sub(previous.dropped_rate);
    let d_dropped_bytes = now.dropped_bytes.saturating_sub(previous.dropped_bytes);
    let d_passed_bytes = now.passed_bytes.saturating_sub(previous.passed_bytes);

    stats_header("XDP stats");
    println!(
        "pass : {:>12}  ({:>10.1} pkt/s, {:>10.1} B/s)",
        now.passed,
        d_passed as f64 / dt,
        d_passed_bytes as f64 / dt
    );
    println!(
        "drop : icmp={:<12} rate={:<12}  ({:.1} drop/s, {}/s)",
        now.dropped_icmp,
        now.dropped_rate,
        (d_icmp + d_rate) as f64 / dt,
        bytes((d_dropped_bytes as f64 / dt) as u64)
    );
    println!(
        "bytes: pass={:<12} drop={:<12}",
        bytes(now.passed_bytes),
        bytes(now.dropped_bytes)
    );
}

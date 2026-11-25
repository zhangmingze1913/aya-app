//! `aya-app tc` — P2P drop and video prioritisation in the TC datapath.
//!
//! Lifecycle: validate port/lists, load the TC-only object, write the
//! classifier config, ensure `clsact`, attach, then run the shared loop.

use anyhow::{Context as _, bail};
use aya::{
    maps::{Array, MapData, PerCpuArray},
    programs::{SchedClassifier, TcAttachType, tc},
};
use aya_app_common::{MAX_PORTS, TcConfig, TcEvent, TcStats};

use crate::{
    cli::{DirectionArg, TcArgs},
    commands::runner,
    ebpf,
    event::EventStream,
    format::{banner, bytes, ipv4, stats_header, uptime},
    stats::{sum_percpu, take_percpu},
};

pub async fn run(args: TcArgs) -> anyhow::Result<()> {
    if args.drop_port.len() > MAX_PORTS {
        bail!(
            "at most {MAX_PORTS} --drop-port values are supported (got {})",
            args.drop_port.len()
        );
    }
    if args.video_port.len() > MAX_PORTS {
        bail!(
            "at most {MAX_PORTS} --video-port values are supported (got {})",
            args.video_port.len()
        );
    }
    if args.video_mark == 0 {
        bail!("--video-mark must be non-zero (0 is the default skb mark)");
    }
    if args.drop_port.contains(&0) || args.video_port.contains(&0) {
        bail!("port numbers must be in 1..=65535");
    }

    let iface = ebpf::cstring(&args.iface)?;
    // The TC-only object contains the classifier and its three maps.
    let mut bpf = ebpf::load(ebpf::Object::Tc)?;

    // The classifier reads this map on every packet; write it before attach.
    let config = build_config(&args);
    {
        let map = bpf
            .map_mut("tc_config")
            .context("map `tc_config` missing from the eBPF object")?;
        let mut config_map =
            Array::<_, TcConfig>::try_from(map).context("`tc_config` is not an Array<TcConfig>")?;
        config_map
            .set(0, &config, 0)
            .context("failed to write tc_config")?;
    }

    // `clsact` is idempotent from aya's perspective; EEXIST is not an error.
    // The qdisc is a kernel resource; Ctrl-C detaches the classifier but does
    // not remove the qdisc, so docs give the cleanup command.
    if let Err(err) = tc::qdisc_add_clsact(iface.as_c_str()) {
        log::debug!("qdisc_add_clsact: {err} (may already exist)");
    }

    let attach_type = match args.direction {
        DirectionArg::Ingress => TcAttachType::Ingress,
        DirectionArg::Egress => TcAttachType::Egress,
    };

    {
        let program: &mut SchedClassifier = bpf
            .program_mut("tc_qos")
            .context("program `tc_qos` missing from the eBPF object")?
            .try_into()
            .context("`tc_qos` is not a SchedClassifier program")?;
        program.load().context(
            "failed to load the TC classifier; run with RUST_LOG=debug for the verifier log",
        )?;
        program
            .attach(iface.as_c_str(), attach_type)
            .with_context(|| {
                format!(
                    "failed to attach TC classifier to `{}` ({:?})",
                    args.iface, args.direction
                )
            })?;
    }

    let stats = take_percpu::<TcStats>(&mut bpf, "tc_stats")?;
    let events = EventStream::take(&mut bpf, "tc_events")?;

    banner(
        "TC QoS",
        &[
            format!("interface    : {}", args.iface),
            format!("direction    : {:?}", args.direction),
            format!("drop ports   : {:?}", args.drop_port),
            format!("video ports  : {:?}", args.video_port),
            format!(
                "video mark   : {:#x} ({})",
                args.video_mark, args.video_mark
            ),
            format!("event sample : 1/{}", args.event_sample),
        ],
    );

    if matches!(args.direction, DirectionArg::Egress) {
        println!("\n把 mark 映射到高优先级 band（示例，可按需调整）：");
        println!(
            "  tc qdisc replace dev {} root handle 1: prio bands 3",
            args.iface
        );
        println!(
            "  tc filter replace dev {} parent 1: protocol ip handle {:#x} fw flowid 1:1",
            args.iface, args.video_mark
        );
        println!("  tc -s qdisc show dev {}", args.iface);
    } else {
        println!("\n注意：ingress 上设置的 skb->mark 只对入向策略有效，不会影响本地发送队列。");
    }
    println!(
        "Ctrl-C 退出；clsact qdisc 会保留，可用 `tc qdisc del dev {} clsact` 清理。",
        args.iface
    );

    runner::run_events(
        stats,
        events,
        args.stats_interval,
        print_event,
        read_stats,
        print_stats,
        "TC 程序",
    )
    .await?;

    drop(bpf);
    println!("已退出。");
    Ok(())
}

fn build_config(args: &TcArgs) -> TcConfig {
    let mut config = TcConfig::default();
    for (slot, port) in config.drop_ports.iter_mut().zip(args.drop_port.iter()) {
        *slot = *port;
    }
    for (slot, port) in config.video_ports.iter_mut().zip(args.video_port.iter()) {
        *slot = *port;
    }
    config.drop_port_count = args.drop_port.len() as u32;
    config.video_port_count = args.video_port.len() as u32;
    config.video_mark = args.video_mark;
    config.event_sample = args.event_sample;
    config
}

fn read_stats(map: &PerCpuArray<MapData, TcStats>) -> anyhow::Result<TcStats> {
    sum_percpu(map, |total, value| {
        total.passed += value.passed;
        total.dropped_p2p += value.dropped_p2p;
        total.prioritized += value.prioritized;
        total.passed_bytes += value.passed_bytes;
        total.dropped_bytes += value.dropped_bytes;
    })
}

fn print_event(event: TcEvent) {
    crate::eventln!(
        "[tc-drop] t={} {}:{} -> {}:{} len={}",
        uptime(event.timestamp_ns),
        ipv4(event.saddr),
        event.sport,
        ipv4(event.daddr),
        event.dport,
        event.pkt_len
    );
}

fn print_stats(now: &TcStats, previous: &TcStats, interval_secs: u64) {
    let dt = interval_secs.max(1) as f64;
    let d_passed = now.passed.saturating_sub(previous.passed);
    let d_dropped = now.dropped_p2p.saturating_sub(previous.dropped_p2p);
    let d_prioritized = now.prioritized.saturating_sub(previous.prioritized);
    let d_passed_bytes = now.passed_bytes.saturating_sub(previous.passed_bytes);
    let d_dropped_bytes = now.dropped_bytes.saturating_sub(previous.dropped_bytes);

    stats_header("TC stats");
    println!(
        "pass        : {:>12}  ({:>10.1}/s, {:>10.1} B/s)",
        now.passed,
        d_passed as f64 / dt,
        d_passed_bytes as f64 / dt
    );
    println!(
        "drop p2p    : {:>12}  ({:>10.1}/s, {}/s, total {})",
        now.dropped_p2p,
        d_dropped as f64 / dt,
        bytes((d_dropped_bytes as f64 / dt) as u64),
        bytes(now.dropped_bytes)
    );
    println!(
        "prioritized : {:>12}  ({:>10.1}/s)",
        now.prioritized,
        d_prioritized as f64 / dt
    );
}

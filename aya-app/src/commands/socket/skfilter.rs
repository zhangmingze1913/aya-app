use std::time::Duration;

use anyhow::Context as _;
use aya::{
    maps::{Array, HashMap as BpfHashMap, MapData, PerCpuArray},
    programs::SocketFilter,
};
use aya_app_common::{SkfilterConfig, SkfilterStats};
use tokio::net::TcpListener;

use crate::{
    cli::SkFilterArgs,
    ebpf,
    format::{self, banner, stats_header},
    stats::{sum_percpu, take_percpu},
};

pub(super) async fn run(args: SkFilterArgs) -> anyhow::Result<()> {
    let listener = TcpListener::bind(args.listen)
        .await
        .with_context(|| format!("failed to bind {}", args.listen))?;
    let local = listener
        .local_addr()
        .context("failed to read local address")?;

    let enforce = !args.allow_ip.is_empty();
    let mut bpf = ebpf::load(ebpf::Object::Socket)?;

    {
        let map = bpf
            .map_mut("skfilter_config")
            .context("map `skfilter_config` missing from the eBPF object")?;
        let mut config_map = Array::<_, SkfilterConfig>::try_from(map)
            .context("`skfilter_config` is not an Array<SkfilterConfig>")?;
        config_map
            .set(
                0,
                &SkfilterConfig {
                    enforce: u32::from(enforce),
                    _pad: 0,
                },
                0,
            )
            .context("failed to write skfilter_config")?;
    }

    if enforce {
        let map = bpf
            .map_mut("skfilter_allowed")
            .context("map `skfilter_allowed` missing")?;
        let mut allowlist = BpfHashMap::<_, u32, u8>::try_from(map)
            .context("`skfilter_allowed` is not a HashMap<u32, u8>")?;
        for ip in &args.allow_ip {
            allowlist
                .insert(&format::ipv4_to_raw(*ip), &1u8, 0)
                .with_context(|| format!("failed to insert {ip} into skfilter_allowed"))?;
        }
    }

    {
        let program: &mut SocketFilter = bpf
            .program_mut("skfilter_guard")
            .context("program `skfilter_guard` missing")?
            .try_into()
            .context("`skfilter_guard` is not a SocketFilter program")?;
        program.load().context(
            "failed to load the socket filter; run with RUST_LOG=debug for the verifier log",
        )?;
        program
            .attach(&listener)
            .context("failed to attach the socket filter to the listener")?;
    }

    let stats = take_percpu::<SkfilterStats>(&mut bpf, "skfilter_stats")?;

    banner(
        "Socket filter: inbound SYN allowlist",
        &[
            format!("listen      : {local}"),
            format!(
                "mode        : {}",
                if enforce {
                    "enforce source-IP allowlist"
                } else {
                    "observe only (no --allow-ip)"
                }
            ),
            format!("allow IPs   : {:?}", args.allow_ip),
            "提示        : 过滤器只对入站 SYN 生效；非 SYN 包与 ICMP 错误不会被误伤".to_string(),
        ],
    );
    println!("Ctrl-C 退出。测试：curl http://{local}/  （非白名单源会一直卡在 connect）");

    let period = Duration::from_secs(args.stats_interval);
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    let mut previous = SkfilterStats::default();

    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.context("failed to install Ctrl-C handler")?;
                break;
            }
            accepted = listener.accept() => {
                let (stream, peer) = accepted.context("accept failed")?;
                println!("[accept] peer={peer} (SYN passed the filter)");
                // The demo does not speak HTTP; closing immediately is enough
                // to show that the handshake completed.
                drop(stream);
            }
            _ = ticker.tick() => {
                let total = read_stats(&stats)?;
                print_stats(&total, &previous, args.stats_interval);
                previous = total;
            }
        }
    }

    println!("\n正在关闭监听 socket（socket filter 随之失效）...");
    drop(listener);
    drop(bpf);
    println!("已退出。");
    Ok(())
}

fn read_stats(map: &PerCpuArray<MapData, SkfilterStats>) -> anyhow::Result<SkfilterStats> {
    sum_percpu(map, |total, value| {
        total.seen += value.seen;
        total.syn += value.syn;
        total.allowed_syn += value.allowed_syn;
        total.dropped_syn += value.dropped_syn;
        total.non_tcp += value.non_tcp;
        total.other += value.other;
    })
}

fn print_stats(now: &SkfilterStats, previous: &SkfilterStats, interval_secs: u64) {
    let dt = interval_secs.max(1) as f64;
    let d_dropped = now.dropped_syn.saturating_sub(previous.dropped_syn);
    let d_syn = now.syn.saturating_sub(previous.syn);
    stats_header("socket filter stats");
    println!(
        "seen={:<10} syn={:<10} allowed={:<10} dropped={:<10} ({:.1} drop/s)",
        now.seen,
        now.syn,
        now.allowed_syn,
        now.dropped_syn,
        d_dropped as f64 / dt
    );
    println!(
        "non_tcp={:<10} other={:<10} syn_rate={:.1}/s",
        now.non_tcp,
        now.other,
        d_syn as f64 / dt
    );
}

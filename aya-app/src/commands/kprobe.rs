//! `aya-app kprobe` — sensitive openat monitoring and syscall latency.
//!
//! Lifecycle: load the probe-only object, write path/latency config, attach the
//! entry and return probes to the same symbol, then run the shared loop.
//! The two probes share `probe_start` keyed by `pid_tgid`.

use anyhow::{Context as _, bail};
use aya::{
    maps::{Array, MapData, PerCpuArray},
    programs::KProbe,
};
use aya_app_common::{
    KPROBE_KIND_LATENCY, KPROBE_KIND_OPEN, KprobeConfig, KprobeEvent, KprobeStats, MAX_PREFIXES,
    PREFIX_LEN,
};

use crate::{
    cli::KprobeArgs,
    commands::runner,
    ebpf,
    event::EventStream,
    format::{banner, comm, duration_ns, path, stats_header, uptime},
    stats::{sum_percpu, take_percpu},
};

pub async fn run(args: KprobeArgs) -> anyhow::Result<()> {
    let config = build_config(&args)?;
    let mut bpf = ebpf::load(ebpf::Object::Kprobe)?;

    {
        let map = bpf
            .map_mut("kprobe_config")
            .context("map `kprobe_config` missing from the eBPF object")?;
        let mut config_map = Array::<_, KprobeConfig>::try_from(map)
            .context("`kprobe_config` is not an Array<KprobeConfig>")?;
        config_map
            .set(0, &config, 0)
            .context("failed to write kprobe_config")?;
    }

    {
        let entry: &mut KProbe = bpf
            .program_mut("kprobe_openat")
            .context("program `kprobe_openat` missing")?
            .try_into()
            .context("`kprobe_openat` is not a KProbe program")?;
        entry.load().context(
            "failed to load the kprobe program; run with RUST_LOG=debug for the verifier log",
        )?;
        entry.attach(&args.symbol, 0).with_context(|| {
            format!(
                "failed to attach kprobe to `{}`; check /proc/kallsyms",
                args.symbol
            )
        })?;
    }

    {
        let exit: &mut KProbe = bpf
            .program_mut("kretprobe_openat")
            .context("program `kretprobe_openat` missing")?
            .try_into()
            .context("`kretprobe_openat` is not a KProbe program")?;
        exit.load()
            .context("failed to load the kretprobe program")?;
        exit.attach(&args.symbol, 0)
            .with_context(|| format!("failed to attach kretprobe to `{}`", args.symbol))?;
    }

    let stats = take_percpu::<KprobeStats>(&mut bpf, "kprobe_stats")?;
    let events = EventStream::take(&mut bpf, "kprobe_events")?;

    banner(
        "kprobe openat",
        &[
            format!("symbol            : {}", args.symbol),
            format!("path prefixes     : {:?}", args.path_prefix),
            format!("latency threshold : {} us", args.latency_threshold_us),
            "说明              : 入口参数 1 必须是 const char __user * 路径指针".to_string(),
        ],
    );
    println!("Ctrl-C 退出。触发示例：cat /etc/shadow >/dev/null");
    println!("注意：延迟事件在返回时无法恢复路径，只携带 pid/comm/ret。");

    runner::run_events(
        stats,
        events,
        args.stats_interval,
        print_event,
        read_stats,
        print_stats,
        "kprobe/kretprobe",
    )
    .await?;

    drop(bpf);
    println!("已退出。");
    Ok(())
}

fn build_config(args: &KprobeArgs) -> anyhow::Result<KprobeConfig> {
    if args.path_prefix.len() > MAX_PREFIXES {
        bail!(
            "at most {MAX_PREFIXES} --path-prefix values are supported (got {})",
            args.path_prefix.len()
        );
    }

    let mut config = KprobeConfig::default();
    for (index, prefix) in args.path_prefix.iter().enumerate() {
        let bytes = prefix.as_bytes();
        if bytes.is_empty() {
            bail!("--path-prefix must not be empty");
        }
        if bytes.len() >= PREFIX_LEN {
            bail!(
                "path prefix `{prefix}` is too long (max {} bytes)",
                PREFIX_LEN - 1
            );
        }
        if bytes.contains(&0) {
            bail!("path prefix `{prefix}` contains a NUL byte");
        }
        config.prefixes[index][..bytes.len()].copy_from_slice(bytes);
        config.prefix_lens[index] = bytes.len() as u8;
    }
    config.prefix_count = args.path_prefix.len() as u8;
    config.latency_threshold_ns = args.latency_threshold_us.saturating_mul(1_000);
    Ok(config)
}

fn read_stats(map: &PerCpuArray<MapData, KprobeStats>) -> anyhow::Result<KprobeStats> {
    sum_percpu(map, |total, value| {
        total.opens += value.opens;
        total.sensitive += value.sensitive;
        total.latency_calls += value.latency_calls;
        total.slow_calls += value.slow_calls;
    })
}

fn print_event(event: KprobeEvent) {
    match event.kind {
        KPROBE_KIND_OPEN => crate::eventln!(
            "[open]    t={} pid={} tid={} comm={} uid={} path={}",
            uptime(event.timestamp_ns),
            event.tgid,
            event.pid,
            comm(&event.comm),
            event.uid,
            path(&event.path)
        ),
        KPROBE_KIND_LATENCY => crate::eventln!(
            "[latency] t={} pid={} tid={} comm={} {:<10} ret={}",
            uptime(event.timestamp_ns),
            event.tgid,
            event.pid,
            comm(&event.comm),
            duration_ns(event.latency_ns),
            event.ret
        ),
        other => crate::eventln!("[kprobe?] unknown kind={other}"),
    }
}

fn print_stats(now: &KprobeStats, previous: &KprobeStats, interval_secs: u64) {
    let dt = interval_secs.max(1) as f64;
    let d_opens = now.opens.saturating_sub(previous.opens);
    let d_sensitive = now.sensitive.saturating_sub(previous.sensitive);
    let d_slow = now.slow_calls.saturating_sub(previous.slow_calls);

    stats_header("kprobe stats");
    println!(
        "opens      : {:>12}  ({:>10.1}/s)",
        now.opens,
        d_opens as f64 / dt
    );
    println!(
        "sensitive  : {:>12}  ({:>10.1}/s)",
        now.sensitive,
        d_sensitive as f64 / dt
    );
    println!(
        "latency    : calls={:<10} slow={:<10} ({:.1} slow/s)",
        now.latency_calls,
        now.slow_calls,
        d_slow as f64 / dt
    );
}

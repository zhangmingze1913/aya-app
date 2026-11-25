//! `aya-app uprobe` — userspace function tracing with uprobe/uretprobe.
//!
//! Lifecycle: resolve the target ELF, load the uprobe-only object, write the
//! latency config, attach entry/return probes with the requested scope, then
//! run the shared loop.

use std::num::NonZeroU32;

use anyhow::{Context as _, bail};
use aya::{
    maps::{Array, MapData, PerCpuArray},
    programs::{UProbe, uprobe::UProbeScope},
};
use aya_app_common::{UPROBE_KIND_ENTER, UPROBE_KIND_EXIT, UprobeConfig, UprobeEvent, UprobeStats};

use crate::{
    cli::UprobeArgs,
    commands::runner,
    ebpf,
    event::EventStream,
    format::{banner, comm, duration_ns, path, stats_header, uptime},
    stats::{sum_percpu, take_percpu},
};

pub async fn run(args: UprobeArgs) -> anyhow::Result<()> {
    let binary = args
        .binary
        .canonicalize()
        .with_context(|| format!("failed to resolve {}", args.binary.display()))?;
    if !binary.is_file() {
        bail!("{} is not a regular file", binary.display());
    }

    let scope = match args.pid {
        Some(0) => bail!("--pid must be greater than 0"),
        Some(pid) => {
            UProbeScope::OneProcess(NonZeroU32::new(pid).expect("pid > 0 was checked above"))
        }
        None => UProbeScope::AllProcesses,
    };

    let mut bpf = ebpf::load(ebpf::Object::Uprobe)?;

    let config = UprobeConfig {
        latency_threshold_ns: args.latency_threshold_us.saturating_mul(1_000),
        _pad: 0,
    };
    {
        let map = bpf
            .map_mut("uprobe_config")
            .context("map `uprobe_config` missing from the eBPF object")?;
        let mut config_map = Array::<_, UprobeConfig>::try_from(map)
            .context("`uprobe_config` is not an Array<UprobeConfig>")?;
        config_map
            .set(0, &config, 0)
            .context("failed to write uprobe_config")?;
    }

    {
        let program: &mut UProbe = bpf
            .program_mut("uprobe_request")
            .context("program `uprobe_request` missing")?
            .try_into()
            .context("`uprobe_request` is not a UProbe program")?;
        program.load().context(
            "failed to load the uprobe program; run with RUST_LOG=debug for the verifier log",
        )?;
        program
            .attach([args.symbol.as_str()], binary.as_path(), scope)
            .with_context(|| {
                format!(
                    "failed to attach uprobe to `{}` in {}",
                    args.symbol,
                    binary.display()
                )
            })?;
    }

    {
        let program: &mut UProbe = bpf
            .program_mut("uretprobe_request")
            .context("program `uretprobe_request` missing")?
            .try_into()
            .context("`uretprobe_request` is not a UProbe program")?;
        program
            .load()
            .context("failed to load the uretprobe program")?;
        program
            .attach([args.symbol.as_str()], binary.as_path(), scope)
            .with_context(|| {
                format!(
                    "failed to attach uretprobe to `{}` in {}",
                    args.symbol,
                    binary.display()
                )
            })?;
    }

    let stats = take_percpu::<UprobeStats>(&mut bpf, "uprobe_stats")?;
    let events = EventStream::take(&mut bpf, "uprobe_events")?;

    let scope_text = match scope {
        UProbeScope::AllProcesses => "all processes".to_string(),
        UProbeScope::CallingProcess => "calling process".to_string(),
        UProbeScope::OneProcess(pid) => format!("pid {}", pid.get()),
    };

    banner(
        "uprobe function tracing",
        &[
            format!("binary            : {}", binary.display()),
            format!("symbol            : {}", args.symbol),
            format!("scope             : {scope_text}"),
            format!("latency threshold : {} us", args.latency_threshold_us),
        ],
    );
    println!("Ctrl-C 退出。示例：先运行 target/release/aya-app-demo，再执行本命令。");

    runner::run_events(
        stats,
        events,
        args.stats_interval,
        print_event,
        read_stats,
        print_stats,
        "uprobe/uretprobe",
    )
    .await?;

    drop(bpf);
    println!("已退出。");
    Ok(())
}

fn read_stats(map: &PerCpuArray<MapData, UprobeStats>) -> anyhow::Result<UprobeStats> {
    sum_percpu(map, |total, value| {
        total.enters += value.enters;
        total.exits += value.exits;
        total.slow_calls += value.slow_calls;
    })
}

fn print_event(event: UprobeEvent) {
    match event.kind {
        UPROBE_KIND_ENTER => crate::eventln!(
            "[enter] t={} pid={} tid={} comm={} request_id={} path={}",
            uptime(event.timestamp_ns),
            event.tgid,
            event.pid,
            comm(&event.comm),
            event.request_id,
            path(&event.path)
        ),
        UPROBE_KIND_EXIT => crate::eventln!(
            "[exit]  t={} pid={} tid={} comm={} {:<10} ret={}",
            uptime(event.timestamp_ns),
            event.tgid,
            event.pid,
            comm(&event.comm),
            duration_ns(event.latency_ns),
            event.ret
        ),
        other => crate::eventln!("[uprobe?] unknown kind={other}"),
    }
}

fn print_stats(now: &UprobeStats, previous: &UprobeStats, interval_secs: u64) {
    let dt = interval_secs.max(1) as f64;
    let d_enters = now.enters.saturating_sub(previous.enters);
    let d_exits = now.exits.saturating_sub(previous.exits);
    let d_slow = now.slow_calls.saturating_sub(previous.slow_calls);

    stats_header("uprobe stats");
    println!(
        "enter : {:>12}  ({:>10.1}/s)",
        now.enters,
        d_enters as f64 / dt
    );
    println!(
        "exit  : {:>12}  ({:>10.1}/s)",
        now.exits,
        d_exits as f64 / dt
    );
    println!(
        "slow  : {:>12}  ({:>10.1}/s)",
        now.slow_calls,
        d_slow as f64 / dt
    );
}

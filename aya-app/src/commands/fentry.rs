//! `aya-app fentry` — BTF-based fentry/fexit tracing of `do_sys_openat2`.
//!
//! Lifecycle: load the fentry-only object, write the latency/sampling config,
//! resolve the function in kernel BTF, attach fentry and fexit, then run the
//! shared loop. No kprobe event is created.

use anyhow::Context as _;
use aya::{
    Btf,
    maps::{Array, MapData, PerCpuArray},
    programs::{FEntry, FExit},
};
use aya_app_common::{FentryConfig, FentryEvent, FentryStats};

use crate::{
    cli::FentryArgs,
    commands::runner,
    ebpf,
    event::EventStream,
    format::{banner, comm, duration_ns, stats_header, uptime},
    stats::{sum_percpu, take_percpu},
};

pub async fn run(args: FentryArgs) -> anyhow::Result<()> {
    let config = FentryConfig {
        latency_threshold_ns: args.latency_threshold_us.saturating_mul(1_000),
        event_sample: args.event_sample,
        ..Default::default()
    };

    let mut bpf = ebpf::load(ebpf::Object::Fentry)?;

    {
        let map = bpf
            .map_mut("fentry_config")
            .context("map `fentry_config` missing from the eBPF object")?;
        let mut config_map = Array::<_, FentryConfig>::try_from(map)
            .context("`fentry_config` is not an Array<FentryConfig>")?;
        config_map
            .set(0, &config, 0)
            .context("failed to write fentry_config")?;
    }

    let btf = Btf::from_sys_fs().context(
        "failed to load /sys/kernel/btf/vmlinux; fentry/fexit require CONFIG_DEBUG_INFO_BTF",
    )?;

    {
        let program: &mut FEntry = bpf
            .program_mut("fentry_openat")
            .context("program `fentry_openat` missing")?
            .try_into()
            .context("`fentry_openat` is not an FEntry program")?;
        program.load(&args.symbol, &btf).with_context(|| {
            format!(
                "failed to load fentry for `{}`; check the BTF function name",
                args.symbol
            )
        })?;
        program
            .attach()
            .context("failed to attach fentry trampoline")?;
    }

    {
        let program: &mut FExit = bpf
            .program_mut("fexit_openat")
            .context("program `fexit_openat` missing")?
            .try_into()
            .context("`fexit_openat` is not an FExit program")?;
        program
            .load(&args.symbol, &btf)
            .context("failed to load fexit")?;
        program
            .attach()
            .context("failed to attach fexit trampoline")?;
    }

    let stats = take_percpu::<FentryStats>(&mut bpf, "fentry_stats")?;
    let events = EventStream::take(&mut bpf, "fentry_events")?;

    banner(
        "fentry/fexit tracing",
        &[
            format!("function          : {}", args.symbol),
            format!("latency threshold : {} us", args.latency_threshold_us),
            format!("event sample      : 1/{}", args.event_sample),
            "说明              : BTF trampoline，无 kprobe 断点/事件开销".to_string(),
        ],
    );
    println!("Ctrl-C 退出。触发示例：cat /etc/hosts >/dev/null");
    println!("注意：嵌套调用会覆盖同一线程的起始时间，并通过 missing_starts 计数。");

    runner::run_events(
        stats,
        events,
        args.stats_interval,
        print_event,
        read_stats,
        print_stats,
        "fentry/fexit",
    )
    .await?;

    drop(bpf);
    println!("已退出。");
    Ok(())
}

fn read_stats(map: &PerCpuArray<MapData, FentryStats>) -> anyhow::Result<FentryStats> {
    sum_percpu(map, |total, value| {
        total.enters += value.enters;
        total.exits += value.exits;
        total.slow_calls += value.slow_calls;
        total.missing_starts += value.missing_starts;
    })
}

fn print_event(event: FentryEvent) {
    crate::eventln!(
        "[fexit] t={} pid={} tid={} comm={} uid={} {:<10} ret={}",
        uptime(event.timestamp_ns),
        event.tgid,
        event.pid,
        comm(&event.comm),
        event.uid,
        duration_ns(event.latency_ns),
        event.ret
    );
}

fn print_stats(now: &FentryStats, previous: &FentryStats, interval_secs: u64) {
    let dt = interval_secs.max(1) as f64;
    let d_enters = now.enters.saturating_sub(previous.enters);
    let d_exits = now.exits.saturating_sub(previous.exits);
    let d_slow = now.slow_calls.saturating_sub(previous.slow_calls);

    stats_header("fentry/fexit stats");
    println!(
        "enters : {:>12}  ({:>10.1}/s)",
        now.enters,
        d_enters as f64 / dt
    );
    println!(
        "exits  : {:>12}  ({:>10.1}/s)",
        now.exits,
        d_exits as f64 / dt
    );
    println!(
        "slow   : {:>12}  ({:>10.1}/s)  missing_starts={}",
        now.slow_calls,
        d_slow as f64 / dt,
        now.missing_starts
    );
}

//! `aya-app raw-tp` — raw `sys_enter` tracepoint with syscall filtering.
//!
//! Lifecycle: load the raw-tracepoint-only object, write the syscall/sampling
//! config, attach `sys_enter`, then run the shared loop. No tracefs format is
//! parsed: `arg(1)` is the syscall number from `TP_PROTO`.

use anyhow::Context as _;
use aya::{
    maps::{Array, MapData, PerCpuArray},
    programs::RawTracePoint,
};
use aya_app_common::{RawTpConfig, RawTpEvent, RawTpStats};

use crate::{
    cli::RawTpArgs,
    commands::runner,
    ebpf,
    event::EventStream,
    format::{banner, comm, stats_header, uptime},
    stats::{sum_percpu, take_percpu},
};

pub async fn run(args: RawTpArgs) -> anyhow::Result<()> {
    let config = RawTpConfig {
        syscall_nr: args.syscall_nr,
        event_sample: args.event_sample,
        ..Default::default()
    };

    let mut bpf = ebpf::load(ebpf::Object::RawTp)?;

    {
        let map = bpf
            .map_mut("rawtp_config")
            .context("map `rawtp_config` missing from the eBPF object")?;
        let mut config_map = Array::<_, RawTpConfig>::try_from(map)
            .context("`rawtp_config` is not an Array<RawTpConfig>")?;
        config_map
            .set(0, &config, 0)
            .context("failed to write rawtp_config")?;
    }

    {
        let program: &mut RawTracePoint = bpf
            .program_mut("rawtp_sys_enter")
            .context("program `rawtp_sys_enter` missing")?
            .try_into()
            .context("`rawtp_sys_enter` is not a RawTracePoint program")?;
        program.load().context(
            "failed to load raw tracepoint; run with RUST_LOG=debug for the verifier log",
        )?;
        program
            .attach("sys_enter")
            .context("failed to attach raw tracepoint `sys_enter`")?;
    }

    let stats = take_percpu::<RawTpStats>(&mut bpf, "rawtp_stats")?;
    let events = EventStream::take(&mut bpf, "rawtp_events")?;

    banner(
        "raw tracepoint sys_enter",
        &[
            "tracepoint     : sys_enter (TP_PROTO: pt_regs *, long id)".to_string(),
            format!(
                "syscall filter : {} ({})",
                args.syscall_nr,
                syscall_name(args.syscall_nr)
            ),
            format!("event sample   : 1/{}", args.event_sample),
            "说明           : 直接读取 TP_PROTO 参数，不解析 tracefs format".to_string(),
        ],
    );
    println!("Ctrl-C 退出。触发示例：cat /etc/hosts >/dev/null");
    println!("提示：syscall 号与架构相关；x86_64 open=2、openat=257，aarch64 openat=56。");

    runner::run_events(
        stats,
        events,
        args.stats_interval,
        print_event,
        read_stats,
        print_stats,
        "raw tracepoint",
    )
    .await?;

    drop(bpf);
    println!("已退出。");
    Ok(())
}

fn syscall_name(nr: u32) -> &'static str {
    match nr {
        0 => "read",
        1 => "write",
        2 => "open",
        3 => "close",
        56 => "openat (aarch64)",
        59 => "execve",
        257 => "openat (x86_64)",
        262 => "newfstatat (x86_64)",
        _ => "unknown",
    }
}

fn read_stats(map: &PerCpuArray<MapData, RawTpStats>) -> anyhow::Result<RawTpStats> {
    sum_percpu(map, |total, value| {
        total.matches += value.matches;
        total.emitted += value.emitted;
    })
}

fn print_event(event: RawTpEvent) {
    println!(
        "[sys_enter] t={} pid={} tid={} comm={} uid={} nr={}",
        uptime(event.timestamp_ns),
        event.tgid,
        event.pid,
        comm(&event.comm),
        event.uid,
        event.syscall_nr
    );
}

fn print_stats(now: &RawTpStats, previous: &RawTpStats, interval_secs: u64) {
    let dt = interval_secs.max(1) as f64;
    let d_matches = now.matches.saturating_sub(previous.matches);
    let d_emitted = now.emitted.saturating_sub(previous.emitted);

    stats_header("raw tracepoint stats");
    println!(
        "matches : {:>12}  ({:>10.1}/s)",
        now.matches,
        d_matches as f64 / dt
    );
    println!(
        "emitted : {:>12}  ({:>10.1}/s)",
        now.emitted,
        d_emitted as f64 / dt
    );
}

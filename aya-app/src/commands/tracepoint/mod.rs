//! `aya-app tracepoint` — scheduling and block I/O observability.
//!
//! The interesting part of this command is not the attach call: it is the
//! runtime discovery of tracepoint field offsets from tracefs before attaching.
//! See `crate::tracefs`.

use std::time::Duration;

use anyhow::Context as _;
use aya::{maps::Array, programs::TracePoint};
use aya_app_common::{BlockStats, SchedStats, TracepointControl, TracepointOffsets};

use crate::{
    cli::{TraceEventArg, TracepointArgs},
    ebpf,
    event::EventStream,
    format::{banner, flush_events},
    stats::take_percpu,
    tracefs,
};

mod block;
mod sched;

/// Resolves only the requested tracepoint formats, attaches the programs, and
/// multiplexes the optional sched/block streams through one stats ticker.
pub async fn run(args: TracepointArgs) -> anyhow::Result<()> {
    let want_sched = matches!(args.event, TraceEventArg::All | TraceEventArg::Sched);
    let want_block = matches!(args.event, TraceEventArg::All | TraceEventArg::Block);

    let tracefs_path = tracefs::find_tracefs(None)?;

    // Resolve only the formats we are going to use. This makes `--event sched`
    // work on a kernel without block tracepoints and vice versa.
    let mut offsets = TracepointOffsets::default();
    if want_sched {
        tracefs::fill_sched_offsets(&mut offsets, &tracefs_path)
            .context("failed to resolve sched:sched_switch offsets")?;
    }
    if want_block {
        tracefs::fill_block_offsets(&mut offsets, &tracefs_path)
            .context("failed to resolve block:block_rq_issue offsets")?;
    }

    let control = TracepointControl {
        sched_sample_every: args.sched_sample,
        block_sample_every: args.block_sample,
    };

    let mut bpf = ebpf::load(ebpf::Object::Tracepoint)?;

    {
        let map = bpf
            .map_mut("tp_offsets")
            .context("map `tp_offsets` missing from the eBPF object")?;
        let mut offsets_map = Array::<_, TracepointOffsets>::try_from(map)
            .context("`tp_offsets` is not an Array<TracepointOffsets>")?;
        offsets_map
            .set(0, &offsets, 0)
            .context("failed to write tp_offsets")?;
    }
    {
        let map = bpf
            .map_mut("tp_control")
            .context("map `tp_control` missing from the eBPF object")?;
        let mut control_map = Array::<_, TracepointControl>::try_from(map)
            .context("`tp_control` is not an Array<TracepointControl>")?;
        control_map
            .set(0, &control, 0)
            .context("failed to write tp_control")?;
    }

    if want_sched {
        attach_tracepoint(&mut bpf, "tracepoint_sched_switch", "sched", "sched_switch")?;
    }
    if want_block {
        attach_tracepoint(&mut bpf, "tracepoint_block_rq", "block", "block_rq_issue")?;
    }

    let mut sched_events = if want_sched {
        Some(EventStream::take(&mut bpf, "tp_sched_events")?)
    } else {
        None
    };
    let mut block_events = if want_block {
        Some(EventStream::take(&mut bpf, "tp_block_events")?)
    } else {
        None
    };
    let sched_stats = if want_sched {
        Some(take_percpu::<SchedStats>(&mut bpf, "tp_sched_stats")?)
    } else {
        None
    };
    let block_stats = if want_block {
        Some(take_percpu::<BlockStats>(&mut bpf, "tp_block_stats")?)
    } else {
        None
    };

    banner(
        "Tracepoints",
        &[
            format!("tracefs        : {}", tracefs_path.display()),
            format!(
                "events         : {}",
                match args.event {
                    TraceEventArg::All => "sched_switch + block_rq_issue",
                    TraceEventArg::Sched => "sched_switch",
                    TraceEventArg::Block => "block_rq_issue",
                }
            ),
            format!("sched sampling : 1/{}", args.sched_sample),
            format!("block sampling : 1/{}", args.block_sample),
            format!(
                "sched offsets  : prev_comm={} prev_pid={} prev_state={}B next_comm={}",
                offsets.sched_prev_comm,
                offsets.sched_prev_pid,
                offsets.sched_prev_state_size,
                offsets.sched_next_comm
            ),
            format!(
                "block offsets  : dev={} sector={} bytes={} rwbs={}",
                offsets.block_dev, offsets.block_sector, offsets.block_bytes, offsets.block_rwbs
            ),
        ],
    );
    println!("Ctrl-C 退出。统计为精确值，事件为采样值。");

    let period = Duration::from_secs(args.stats_interval);
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    let mut previous_sched = SchedStats::default();
    let mut previous_block = BlockStats::default();

    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.context("failed to install Ctrl-C handler")?;
                break;
            }
            result = sched::drain(&mut sched_events) => {
                result.context("failed to read tp_sched_events ring buffer")?;
            }
            result = block::drain(&mut block_events) => {
                result.context("failed to read tp_block_events ring buffer")?;
            }
            _ = ticker.tick() => {
                flush_events();
                if let Some(stats) = &sched_stats {
                    let total = sched::read_stats(stats)?;
                    sched::print_stats(&total, &previous_sched, args.stats_interval);
                    previous_sched = total;
                }
                if let Some(stats) = &block_stats {
                    let total = block::read_stats(stats)?;
                    block::print_stats(&total, &previous_block, args.stats_interval);
                    previous_block = total;
                }
            }
        }
    }

    flush_events();
    println!("\n正在 detach tracepoints ...");
    drop(bpf);
    println!("已退出。");
    Ok(())
}

fn attach_tracepoint(
    bpf: &mut aya::Ebpf,
    program_name: &str,
    category: &str,
    name: &str,
) -> anyhow::Result<()> {
    let program: &mut TracePoint = bpf
        .program_mut(program_name)
        .with_context(|| format!("program `{program_name}` missing from the eBPF object"))?
        .try_into()
        .with_context(|| format!("`{program_name}` is not a TracePoint program"))?;
    program.load().with_context(|| {
        format!("failed to load `{program_name}`; run with RUST_LOG=debug for the verifier log")
    })?;
    program
        .attach(category, name)
        .with_context(|| format!("failed to attach {category}:{name}"))?;
    Ok(())
}

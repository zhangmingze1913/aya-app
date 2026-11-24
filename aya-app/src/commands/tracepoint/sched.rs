use anyhow::Context as _;
use aya_app_common::{SchedEvent, SchedStats};

use crate::{
    event::EventStream,
    format::{comm, stats_header, uptime},
    stats::sum_percpu,
};

pub(super) async fn drain(stream: &mut Option<EventStream>) -> anyhow::Result<()> {
    match stream {
        Some(stream) => stream
            .for_each::<SchedEvent>(print_event)
            .await
            .context("sched_switch event stream"),
        None => {
            std::future::pending::<()>().await;
            Ok(())
        }
    }
}

pub(super) fn read_stats(
    map: &aya::maps::PerCpuArray<aya::maps::MapData, SchedStats>,
) -> anyhow::Result<SchedStats> {
    sum_percpu(map, |total, value| {
        total.switches += value.switches;
        total.emitted += value.emitted;
    })
}

fn print_event(event: SchedEvent) {
    println!(
        "[sched] t={} {}:{} [{}] -> {}:{} [{}] state={}",
        uptime(event.timestamp_ns),
        comm(&event.prev_comm),
        event.prev_pid,
        event.prev_prio,
        comm(&event.next_comm),
        event.next_pid,
        event.next_prio,
        task_state(event.prev_state)
    );
}

pub(super) fn print_stats(now: &SchedStats, previous: &SchedStats, interval_secs: u64) {
    let dt = interval_secs.max(1) as f64;
    let d_switches = now.switches.saturating_sub(previous.switches);
    let d_emitted = now.emitted.saturating_sub(previous.emitted);
    stats_header("sched stats");
    println!(
        "switches : {:>12}  ({:>10.1}/s)",
        now.switches,
        d_switches as f64 / dt
    );
    println!(
        "emitted  : {:>12}  ({:>10.1}/s)",
        now.emitted,
        d_emitted as f64 / dt
    );
}

fn task_state(state: u64) -> &'static str {
    // `TASK_*` values from include/linux/sched.h. `prev_state` is a bitmask,
    // but for display the low byte is what task_state() reports.
    match state & 0xff {
        0 => "R",
        1 => "S",
        2 => "D",
        4 => "T",
        8 => "t",
        16 => "X",
        32 => "Z",
        64 => "P",
        128 => "I",
        _ => "?",
    }
}

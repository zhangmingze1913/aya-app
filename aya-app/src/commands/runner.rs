//! Shared event/statistics loop.
//!
//! Most scenarios have the same lifecycle after attach: wait for ring-buffer
//! events, print statistics on a timer, and stop on Ctrl-C. Keeping that loop
//! here leaves each command with only its scenario-specific configuration,
//! attach, event printer, and stats printer.
//!
//! The maps are moved in by value so the caller keeps ownership of `Ebpf` and
//! its link file descriptors; dropping the caller's `Ebpf` detaches links.

use std::time::Duration;

use anyhow::Context as _;
use aya::{
    Pod,
    maps::{MapData, PerCpuArray},
};

use crate::event::EventStream;

/// Runs a scenario with one ring-buffer event stream.
pub async fn run_events<S, E>(
    stats: PerCpuArray<MapData, S>,
    mut events: EventStream,
    interval_secs: u64,
    mut on_event: impl FnMut(E),
    mut read_stats: impl FnMut(&PerCpuArray<MapData, S>) -> anyhow::Result<S>,
    mut print_stats: impl FnMut(&S, &S, u64),
    detach: &str,
) -> anyhow::Result<()>
where
    S: Pod + Copy + Default,
    E: Copy,
{
    let period = Duration::from_secs(interval_secs);
    let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
    let mut previous = S::default();

    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.context("failed to install Ctrl-C handler")?;
                break;
            }
            result = events.for_each::<E>(&mut on_event) => {
                result.context("failed to read ring buffer")?;
            }
            _ = ticker.tick() => {
                let total = read_stats(&stats)?;
                print_stats(&total, &previous, interval_secs);
                previous = total;
            }
        }
    }

    println!("\n正在 detach {detach} ...");
    Ok(())
}

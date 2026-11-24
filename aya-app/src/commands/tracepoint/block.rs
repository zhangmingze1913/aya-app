use anyhow::Context as _;
use aya_app_common::{BlockEvent, BlockStats};

use crate::{
    event::EventStream,
    format::{bytes, comm, rwbs, stats_header, uptime},
    stats::sum_percpu,
};

pub(super) async fn drain(stream: &mut Option<EventStream>) -> anyhow::Result<()> {
    match stream {
        Some(stream) => stream
            .for_each::<BlockEvent>(print_event)
            .await
            .context("block_rq_issue event stream"),
        None => {
            std::future::pending::<()>().await;
            Ok(())
        }
    }
}

pub(super) fn read_stats(
    map: &aya::maps::PerCpuArray<aya::maps::MapData, BlockStats>,
) -> anyhow::Result<BlockStats> {
    sum_percpu(map, |total, value| {
        total.issues += value.issues;
        total.bytes += value.bytes;
        total.reads += value.reads;
        total.writes += value.writes;
    })
}

fn print_event(event: BlockEvent) {
    let (major, minor) = decode_dev(event.dev);
    println!(
        "[block] t={} dev={}:{} sector={} bytes={} rwbs={} comm={}",
        uptime(event.timestamp_ns),
        major,
        minor,
        event.sector,
        event.bytes,
        rwbs(&event.rwbs),
        comm(&event.comm)
    );
}

pub(super) fn print_stats(now: &BlockStats, previous: &BlockStats, interval_secs: u64) {
    let dt = interval_secs.max(1) as f64;
    let d_issues = now.issues.saturating_sub(previous.issues);
    let d_bytes = now.bytes.saturating_sub(previous.bytes);
    stats_header("block stats");
    println!(
        "issues : {:>12}  ({:>10.1}/s)",
        now.issues,
        d_issues as f64 / dt
    );
    println!(
        "bytes  : {:>12}  ({}/s)",
        bytes(now.bytes),
        bytes((d_bytes as f64 / dt) as u64)
    );
    println!("read   : {:>12}    write: {}", now.reads, now.writes);
}

/// Decodes a Linux `dev_t` produced by `new_encode_dev`.
fn decode_dev(dev: u32) -> (u32, u32) {
    let major = (dev & 0x000f_ff00) >> 8;
    let minor = (dev & 0x0000_00ff) | ((dev & 0xffff_f000) >> 12);
    (major, minor)
}

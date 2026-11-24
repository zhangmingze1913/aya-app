//! Tracepoint programs with runtime-resolved field offsets.
//!
//! # Why not hard-code the layout?
//!
//! `sched:sched_switch` and `block:block_rq_issue` are exposed through
//! `trace_event_raw_*` structures. Their layouts are stable in practice but
//! still differ across kernel versions and configuration options. Hard-coded
//! offsets are the most common reason a tracepoint eBPF tool breaks on a new
//! kernel.
//!
//! Instead, userspace parses the `format` file under tracefs, extracts the
//! `offset`/`size` of each field, and writes [`TracepointOffsets`] into a map
//! before attaching. The programs read the offsets from the map and use
//! `TracePointContext::read_at`, which is implemented with
//! `bpf_probe_read_kernel` and therefore tolerates a bad offset without
//! crashing the kernel.
//!
//! # Sampling
//!
//! `sched_switch` fires on every context switch (hundreds of thousands per
//! second on a busy host). Counters are exact; event output is sampled by a
//! configurable factor. `block_rq_issue` is usually lower rate and defaults to
//! emitting every request.

use aya_app_common::{
    BlockEvent, BlockStats, SchedEvent, SchedStats, TracepointControl, TracepointOffsets,
};
use aya_ebpf::{
    macros::{map, tracepoint},
    maps::{Array, PerCpuArray, RingBuf},
    programs::TracePointContext,
};

use crate::utils::{cpu_stats, now_ns, sample};

#[map(name = "tp_offsets")]
static TP_OFFSETS: Array<TracepointOffsets> = Array::with_max_entries(1, 0);

#[map(name = "tp_control")]
static TP_CONTROL: Array<TracepointControl> = Array::with_max_entries(1, 0);

#[map(name = "tp_sched_stats")]
static TP_SCHED_STATS: PerCpuArray<SchedStats> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "tp_block_stats")]
static TP_BLOCK_STATS: PerCpuArray<BlockStats> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "tp_sched_events")]
static TP_SCHED_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map(name = "tp_block_events")]
static TP_BLOCK_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[tracepoint(name = "sched_switch", category = "sched")]
pub fn tracepoint_sched_switch(ctx: TracePointContext) -> u32 {
    let _ = try_sched_switch(&ctx);
    0
}

/// Returns `None` when a map is missing, the offsets are not available, or a
/// field read failed. `None` is a normal "skip this event" condition.
fn try_sched_switch(ctx: &TracePointContext) -> Option<()> {
    let offsets = TP_OFFSETS.get(0)?;
    if offsets.sched_valid == 0 {
        return None;
    }

    // Counters are exact even when event output is sampled.
    if let Some(stats) = cpu_stats(&TP_SCHED_STATS) {
        stats.switches += 1;
    }

    let control = TP_CONTROL.get(0)?;
    if !sample(control.sched_sample_every) {
        return Some(());
    }

    // `read_at` performs a fault-tolerant `bpf_probe_read_kernel`. A short read
    // (for example because the offset came from a mismatched kernel) bails out
    // without emitting a partially initialised event.
    let prev_comm: [u8; 16] = unsafe { ctx.read_at(offsets.sched_prev_comm as usize) }.ok()?;
    let prev_pid: u32 = unsafe { ctx.read_at(offsets.sched_prev_pid as usize) }.ok()?;
    let prev_prio: u32 = unsafe { ctx.read_at(offsets.sched_prev_prio as usize) }.ok()?;
    // `prev_state` is `long`: 8 bytes on 64-bit kernels, 4 on 32-bit ones.
    let prev_state: u64 = if offsets.sched_prev_state_size == 4 {
        u64::from(unsafe { ctx.read_at::<u32>(offsets.sched_prev_state as usize) }.ok()?)
    } else {
        unsafe { ctx.read_at::<u64>(offsets.sched_prev_state as usize) }.ok()?
    };
    let next_comm: [u8; 16] = unsafe { ctx.read_at(offsets.sched_next_comm as usize) }.ok()?;
    let next_pid: u32 = unsafe { ctx.read_at(offsets.sched_next_pid as usize) }.ok()?;
    let next_prio: u32 = unsafe { ctx.read_at(offsets.sched_next_prio as usize) }.ok()?;

    crate::emit_event!(TP_SCHED_EVENTS, SchedEvent, {
        timestamp_ns: now_ns(),
        prev_pid: prev_pid,
        next_pid: next_pid,
        prev_prio: prev_prio,
        next_prio: next_prio,
        prev_state: prev_state,
        prev_comm: prev_comm,
        next_comm: next_comm,
    });
    if let Some(stats) = cpu_stats(&TP_SCHED_STATS) {
        stats.emitted += 1;
    }
    Some(())
}

#[tracepoint(name = "block_rq_issue", category = "block")]
pub fn tracepoint_block_rq(ctx: TracePointContext) -> u32 {
    let _ = try_block_rq(&ctx);
    0
}

fn try_block_rq(ctx: &TracePointContext) -> Option<()> {
    let offsets = TP_OFFSETS.get(0)?;
    if offsets.block_valid == 0 {
        return None;
    }

    let dev: u32 = unsafe { ctx.read_at(offsets.block_dev as usize) }.ok()?;
    let sector: u64 = unsafe { ctx.read_at(offsets.block_sector as usize) }.ok()?;
    let nr_sector: u32 = unsafe { ctx.read_at(offsets.block_nr_sector as usize) }.ok()?;
    let rwbs: [u8; 8] = unsafe { ctx.read_at(offsets.block_rwbs as usize) }.ok()?;
    let comm: [u8; 16] = unsafe { ctx.read_at(offsets.block_comm as usize) }.ok()?;

    // `bytes` is absent on some older kernels; the parser then leaves the offset
    // at zero, which can never be a valid field offset (the trace entry itself
    // occupies [0, 8)).
    let bytes: u32 = if offsets.block_bytes == 0 {
        0
    } else {
        unsafe { ctx.read_at(offsets.block_bytes as usize) }.unwrap_or(0)
    };

    // Counters are exact: they are updated before the sampling decision.
    if let Some(stats) = cpu_stats(&TP_BLOCK_STATS) {
        stats.issues += 1;
        stats.bytes += u64::from(bytes);
        match rwbs[0] {
            b'R' => stats.reads += 1,
            b'W' => stats.writes += 1,
            _ => {}
        }
    }

    let control = TP_CONTROL.get(0)?;
    if !sample(control.block_sample_every) {
        return Some(());
    }

    crate::emit_event!(TP_BLOCK_EVENTS, BlockEvent, {
        timestamp_ns: now_ns(),
        sector: sector,
        nr_sector: nr_sector,
        bytes: bytes,
        dev: dev,
        _pad: 0,
        rwbs: rwbs,
        comm: comm,
    });
    Some(())
}

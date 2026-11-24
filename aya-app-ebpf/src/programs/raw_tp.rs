//! Raw tracepoint on `sys_enter`.
//!
//! A raw tracepoint receives the tracepoint's `TP_PROTO` arguments directly,
//! without the `trace_event_raw_*` record and without tracefs format parsing.
//! The `sys_enter` tracepoint prototype is:
//!
//! ```text
//! TP_PROTO(struct pt_regs *regs, long id)
//! ```
//!
//! so `arg(1)` is the syscall number. Filtering in the BPF program keeps the
//! ring buffer and userspace off the hot path for every unrelated syscall.

use aya_app_common::{RawTpConfig, RawTpEvent, RawTpStats};
use aya_ebpf::{
    EbpfContext as _,
    macros::{map, raw_tracepoint},
    maps::{Array, PerCpuArray, RingBuf},
    programs::RawTracePointContext,
};

use crate::utils::{comm, cpu_stats, now_ns, sample};

#[map(name = "rawtp_config")]
static RAWT_CONFIG: Array<RawTpConfig> = Array::with_max_entries(1, 0);

#[map(name = "rawtp_stats")]
static RAWT_STATS: PerCpuArray<RawTpStats> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "rawtp_events")]
static RAWT_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn rawtp_sys_enter(ctx: RawTracePointContext) -> u32 {
    let cfg = match RAWT_CONFIG.get(0) {
        Some(cfg) => cfg,
        None => return 0,
    };

    // `sys_enter` TP_PROTO is `(struct pt_regs *regs, long id)`; the syscall
    // number is the second raw argument, not a tracefs record field.
    let syscall_nr: u64 = ctx.arg(1);
    if syscall_nr != u64::from(cfg.syscall_nr) {
        return 0;
    }

    if let Some(stats) = cpu_stats(&RAWT_STATS) {
        stats.matches += 1;
    }

    if !sample(cfg.event_sample) {
        return 0;
    }

    // In-place reservation avoids verifier stack-copy limits on 6.1.
    crate::emit_event!(RAWT_EVENTS, RawTpEvent, {
        timestamp_ns: now_ns(),
        pid: ctx.pid(),
        tgid: ctx.tgid(),
        uid: ctx.uid(),
        syscall_nr: cfg.syscall_nr,
        _pad: 0,
        comm: comm(&ctx),
    });
    if let Some(stats) = cpu_stats(&RAWT_STATS) {
        stats.emitted += 1;
    }
    0
}

//! fentry/fexit tracing pair for `do_sys_openat2`.
//!
//! fentry/fexit attach through BPF trampolines and BTF, so there is no
//! breakpoint instruction and no kprobe event registration. The entry program
//! records the current timestamp keyed by `pid_tgid`; the exit program pops it,
//! computes the latency, and samples an event.
//!
//! This is intentionally the same workload as the kprobe scenario so the
//! two mechanisms can be compared directly. The kernel must expose
//! `do_sys_openat2` in `/sys/kernel/btf/vmlinux`.

use aya_app_common::{FentryConfig, FentryEvent, FentryStats};
use aya_ebpf::{
    EbpfContext as _,
    helpers::bpf_get_current_pid_tgid,
    macros::{fentry, fexit, map},
    maps::{Array, PerCpuArray, RingBuf},
    programs::{FEntryContext, FExitContext},
};

use crate::{
    probe::PROBE_START,
    utils::{comm, cpu_stats, now_ns, sample},
};

#[map(name = "fentry_config")]
static FENTRY_CONFIG: Array<FentryConfig> = Array::with_max_entries(1, 0);

#[map(name = "fentry_stats")]
static FENTRY_STATS: PerCpuArray<FentryStats> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "fentry_events")]
static FENTRY_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[fentry(function = "do_sys_openat2")]
pub fn fentry_openat(_ctx: FEntryContext) -> i32 {
    let key = bpf_get_current_pid_tgid();
    let now = now_ns();
    let _ = PROBE_START.insert(&key, &now, 0);

    if let Some(stats) = cpu_stats(&FENTRY_STATS) {
        stats.enters += 1;
    }
    0
}

#[fexit(function = "do_sys_openat2")]
pub fn fexit_openat(ctx: FExitContext) -> i32 {
    let cfg = match FENTRY_CONFIG.get(0) {
        Some(cfg) => cfg,
        None => return 0,
    };

    let key = bpf_get_current_pid_tgid();
    let start = match PROBE_START.get_ptr(&key) {
        // Copy before removing: `remove` invalidates the borrowed pointer.
        Some(ptr) => unsafe { *ptr },
        None => {
            if let Some(stats) = cpu_stats(&FENTRY_STATS) {
                stats.missing_starts += 1;
            }
            return 0;
        }
    };
    let _ = PROBE_START.remove(&key);

    let now = now_ns();
    let latency = now.saturating_sub(start);

    if let Some(stats) = cpu_stats(&FENTRY_STATS) {
        stats.exits += 1;
        if latency >= cfg.latency_threshold_ns {
            stats.slow_calls += 1;
        }
    }

    if latency < cfg.latency_threshold_ns || !sample(cfg.event_sample) {
        return 0;
    }

    let ret: i32 = ctx.ret::<i32>().unwrap_or(-1);
    // Reserve in place: a stack copy of the event triggers
    // "invalid indirect read from stack" on older verifiers (6.1).
    crate::emit_event!(FENTRY_EVENTS, FentryEvent, {
        timestamp_ns: now,
        latency_ns: latency,
        pid: ctx.pid(),
        tgid: ctx.tgid(),
        uid: ctx.uid(),
        ret: ret,
        _pad: 0,
        comm: comm(&ctx),
    });
    0
}

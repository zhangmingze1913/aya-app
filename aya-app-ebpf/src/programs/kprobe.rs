//! kprobe/kretprobe pair for `do_sys_openat2` (the modern `openat(2)` path).
//!
//! # Entry probe
//!
//! * Records `bpf_ktime_get_ns()` in a hash map keyed by `pid_tgid`.
//! * Reads the second function argument as a **user-space** pathname pointer.
//!   `do_sys_openat2(int dfd, const char __user *filename, struct open_how *)`
//!   has this signature on 5.x/6.x kernels; the default symbol is chosen by the
//!   CLI and can be overridden with `--symbol`.
//! * Emits an event only when the path starts with one of the configured
//!   prefixes, so the hot path for unrelated opens is a map update plus a
//!   bounded string copy.
//!
//! # Return probe
//!
//! * Pops the start timestamp, computes the delta, and emits an event when the
//!   call crossed the latency threshold. The return value (`fd` or `-errno`)
//!   is included so slow failures can be distinguished from slow successes.
//!
//! The map is bounded (16k in-flight opens). If it fills up, the start entry is
//! simply missing and the return probe emits nothing; the entry probe's
//! counters still reflect the call.

use aya_app_common::{
    KPROBE_KIND_LATENCY, KPROBE_KIND_OPEN, KprobeConfig, KprobeEvent, KprobeStats, PATH_LEN,
};
use aya_ebpf::{
    EbpfContext as _,
    helpers::bpf_get_current_pid_tgid,
    macros::{kprobe, kretprobe, map},
    maps::{Array, PerCpuArray, RingBuf},
    programs::{ProbeContext, RetProbeContext},
};

use crate::{
    probe::PROBE_START,
    utils::{comm, cpu_stats, now_ns, path_matches_prefixes, read_user_string},
};

#[map(name = "kprobe_config")]
static KPROBE_CONFIG: Array<KprobeConfig> = Array::with_max_entries(1, 0);

#[map(name = "kprobe_stats")]
static KPROBE_STATS: PerCpuArray<KprobeStats> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "kprobe_events")]
static KPROBE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[kprobe]
pub fn kprobe_openat(ctx: ProbeContext) -> u32 {
    let _ = try_kprobe_openat(&ctx);
    0
}

fn try_kprobe_openat(ctx: &ProbeContext) -> Result<(), u32> {
    let cfg = KPROBE_CONFIG.get(0).ok_or(0u32)?;
    let key = bpf_get_current_pid_tgid();
    let now = now_ns();

    // The entry timestamp is recorded regardless of the path filter: the return
    // probe needs it for latency accounting on every call.
    let _ = PROBE_START.insert(&key, &now, 0);
    if let Some(stats) = cpu_stats(&KPROBE_STATS) {
        stats.opens += 1;
    }

    // Argument 1 is `const char __user *filename`. A missing argument or a
    // faulting user page yields an empty path and therefore no path event.
    let filename_ptr: u64 = match ctx.arg(1) {
        Some(ptr) => ptr,
        None => return Ok(()),
    };
    if filename_ptr == 0 {
        return Ok(());
    }

    let mut path = [0u8; PATH_LEN];
    let read = read_user_string(filename_ptr, &mut path);
    if read == 0 {
        return Ok(());
    }

    if !path_matches_prefixes(&path, &cfg.prefixes, &cfg.prefix_lens, cfg.prefix_count) {
        return Ok(());
    }

    if let Some(stats) = cpu_stats(&KPROBE_STATS) {
        stats.sensitive += 1;
    }

    // Reserve the event slot instead of building the 184-byte struct on the
    // BPF stack; older verifiers reject the stack copy.
    crate::emit_event!(KPROBE_EVENTS, KprobeEvent, {
        timestamp_ns: now,
        pid: ctx.pid(),
        tgid: ctx.tgid(),
        uid: ctx.uid(),
        kind: KPROBE_KIND_OPEN,
        latency_ns: 0,
        ret: 0,
        path: path,
        comm: comm(ctx),
    });
    Ok(())
}

#[kretprobe]
pub fn kretprobe_openat(ctx: RetProbeContext) -> u32 {
    let _ = try_kretprobe_openat(&ctx);
    0
}

fn try_kretprobe_openat(ctx: &RetProbeContext) -> Result<(), u32> {
    let cfg = KPROBE_CONFIG.get(0).ok_or(0u32)?;
    let key = bpf_get_current_pid_tgid();

    // Copy the timestamp out before removing the entry: `get_ptr` returns a
    // borrowed map value and `remove` would invalidate it.
    let start = match PROBE_START.get_ptr(&key) {
        // SAFETY: the pointer is valid until the map is modified; we copy
        // immediately and only remove after this statement.
        Some(ptr) => unsafe { *ptr },
        None => return Ok(()),
    };
    let _ = PROBE_START.remove(&key);

    let now = now_ns();
    let latency = now.saturating_sub(start);
    let ret: i64 = ctx.ret();

    if let Some(stats) = cpu_stats(&KPROBE_STATS) {
        stats.latency_calls += 1;
        if latency >= cfg.latency_threshold_ns {
            stats.slow_calls += 1;
        }
    }

    if latency < cfg.latency_threshold_ns {
        return Ok(());
    }

    // Same in-place reservation as the entry probe.
    crate::emit_event!(KPROBE_EVENTS, KprobeEvent, {
        timestamp_ns: now,
        pid: ctx.pid(),
        tgid: ctx.tgid(),
        uid: ctx.uid(),
        kind: KPROBE_KIND_LATENCY,
        latency_ns: latency,
        ret: ret,
        path: [0u8; PATH_LEN],
        comm: comm(ctx),
    });
    Ok(())
}

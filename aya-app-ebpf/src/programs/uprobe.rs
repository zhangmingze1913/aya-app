//! uprobe/uretprobe pair for the bundled `aya-app-demo` target.
//!
//! The demo exports an unmangled, non-inlined C-ABI function:
//!
//! ```c
//! void demo_handle_request(uint64_t request_id, const char *path);
//! ```
//!
//! The entry probe captures both arguments; the return probe pairs the call by
//! `pid_tgid`, measures latency, and reports the (void) return value as zero.
//!
//! Real-world targets often have C++ mangled names or no debug symbols. The
//! CLI accepts an arbitrary `--symbol`, and the scenario document explains how
//! to resolve mangled names and PIE offsets with `nm`/`readelf`.

use aya_app_common::{
    PATH_LEN, UPROBE_KIND_ENTER, UPROBE_KIND_EXIT, UprobeConfig, UprobeEvent, UprobeStats,
};
use aya_ebpf::{
    EbpfContext as _,
    helpers::bpf_get_current_pid_tgid,
    macros::{map, uprobe, uretprobe},
    maps::{Array, PerCpuArray, RingBuf},
    programs::{ProbeContext, RetProbeContext},
};

use crate::{
    probe::PROBE_START,
    utils::{comm, cpu_stats, now_ns, read_user_string},
};

#[map(name = "uprobe_config")]
static UPROBE_CONFIG: Array<UprobeConfig> = Array::with_max_entries(1, 0);

#[map(name = "uprobe_stats")]
static UPROBE_STATS: PerCpuArray<UprobeStats> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "uprobe_events")]
static UPROBE_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[uprobe]
pub fn uprobe_request(ctx: ProbeContext) -> u32 {
    let _ = try_uprobe_request(&ctx);
    0
}

fn try_uprobe_request(ctx: &ProbeContext) -> Result<(), u32> {
    let now = now_ns();
    let key = bpf_get_current_pid_tgid();
    let _ = PROBE_START.insert(&key, &now, 0);

    // `demo_handle_request(uint64_t request_id, const char *path)`
    let request_id: u64 = ctx.arg(0).unwrap_or(0);
    let path_ptr: u64 = ctx.arg(1).unwrap_or(0);

    let mut path = [0u8; PATH_LEN];
    let _ = read_user_string(path_ptr, &mut path);

    if let Some(stats) = cpu_stats(&UPROBE_STATS) {
        stats.enters += 1;
    }

    // Reserve in place: the 192-byte event exceeds the stack budget on older
    // verifiers when copied via `output`.
    crate::emit_event!(UPROBE_EVENTS, UprobeEvent, {
        timestamp_ns: now,
        pid: ctx.pid(),
        tgid: ctx.tgid(),
        kind: UPROBE_KIND_ENTER,
        _pad: 0,
        request_id: request_id,
        latency_ns: 0,
        ret: 0,
        path: path,
        comm: comm(ctx),
    });
    Ok(())
}

#[uretprobe]
pub fn uretprobe_request(ctx: RetProbeContext) -> u32 {
    let _ = try_uretprobe_request(&ctx);
    0
}

fn try_uretprobe_request(ctx: &RetProbeContext) -> Result<(), u32> {
    let cfg = UPROBE_CONFIG.get(0).ok_or(0u32)?;
    let key = bpf_get_current_pid_tgid();

    let start = match PROBE_START.get_ptr(&key) {
        // SAFETY: copy before removing the map entry, as in the kprobe pair.
        Some(ptr) => unsafe { *ptr },
        None => return Ok(()),
    };
    let _ = PROBE_START.remove(&key);

    let now = now_ns();
    let latency = now.saturating_sub(start);
    // `demo_handle_request` returns void; `ret` is therefore not meaningful,
    // but keeping it in the event makes the program reusable for functions
    // that do return an integer.
    let ret: i64 = ctx.ret();

    if let Some(stats) = cpu_stats(&UPROBE_STATS) {
        stats.exits += 1;
        if latency >= cfg.latency_threshold_ns {
            stats.slow_calls += 1;
        }
    }

    if latency < cfg.latency_threshold_ns {
        return Ok(());
    }

    // Same in-place write as the entry probe.
    crate::emit_event!(UPROBE_EVENTS, UprobeEvent, {
        timestamp_ns: now,
        pid: ctx.pid(),
        tgid: ctx.tgid(),
        kind: UPROBE_KIND_EXIT,
        _pad: 0,
        // The request id is not recoverable at return time; pair the enter and
        // exit events by tid if you need the full request.
        request_id: 0,
        latency_ns: latency,
        ret: ret,
        path: [0u8; PATH_LEN],
        comm: comm(ctx),
    });
    Ok(())
}

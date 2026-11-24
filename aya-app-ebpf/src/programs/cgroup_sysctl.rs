//! cgroup_sysctl write guard.
//!
//! The hook runs for reads and writes of `/proc/sys/*` performed by processes
//! in the attached cgroup. The `bpf_sysctl` context exposes the `write` flag
//! and the current file position, but not the sysctl name, so the policy is
//! intentionally coarse: either allow both directions or deny all writes.
//!
//! Kernel contract (`__cgroup_bpf_run_filter_sysctl`): returning `1` allows
//! the operation and lets the program replace the buffer; any other value is
//! turned into `-EPERM`. We return `0` to deny.

use aya_app_common::{CGSYSCTL_ACTION_DENY, CgSysctlConfig, CgSysctlEvent, CgSysctlStats};
use aya_ebpf::{
    EbpfContext as _,
    macros::{cgroup_sysctl, map},
    maps::{Array, PerCpuArray, RingBuf},
    programs::SysctlContext,
};

use crate::utils::{comm, cpu_stats, now_ns, sample};

#[map(name = "cgsysctl_config")]
static CGSYSCTL_CONFIG: Array<CgSysctlConfig> = Array::with_max_entries(1, 0);

#[map(name = "cgsysctl_stats")]
static CGSYSCTL_STATS: PerCpuArray<CgSysctlStats> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "cgsysctl_events")]
static CGSYSCTL_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[cgroup_sysctl]
pub fn cgsysctl_guard(ctx: SysctlContext) -> i32 {
    handle(&ctx)
}

fn handle(ctx: &SysctlContext) -> i32 {
    let cfg = match CGSYSCTL_CONFIG.get(0) {
        Some(cfg) => cfg,
        None => return 1,
    };
    if ctx.sysctl.is_null() {
        return 1;
    }

    // SAFETY: the kernel passes a valid `struct bpf_sysctl` for this program
    // type; the pointer is only read, never retained.
    let write = unsafe { (*ctx.sysctl).write } != 0;

    if let Some(stats) = cpu_stats(&CGSYSCTL_STATS) {
        stats.calls += 1;
        if write {
            stats.writes += 1;
        } else {
            stats.reads += 1;
        }
    }

    if !write || cfg.block_writes == 0 {
        return 1;
    }

    if let Some(stats) = cpu_stats(&CGSYSCTL_STATS) {
        stats.blocked += 1;
    }

    if sample(cfg.event_sample) {
        crate::emit_event!(CGSYSCTL_EVENTS, CgSysctlEvent, {
            timestamp_ns: now_ns(),
            pid: ctx.pid(),
            tgid: ctx.tgid(),
            uid: ctx.uid(),
            write: 1,
            action: CGSYSCTL_ACTION_DENY,
            _pad: 0,
            comm: comm(ctx),
        });
    }

    0
}

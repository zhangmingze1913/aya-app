//! Small eBPF helpers shared by all programs.
//!
//! Everything here is `#[inline(always)]`: each out-of-line call would become a
//! BPF-to-BPF call, increasing instruction count and making verifier logs
//! harder to read for no benefit.

use aya_app_common::{MAX_PORTS, MAX_PREFIXES, PATH_LEN, PREFIX_LEN, TASK_COMM_LEN};
use aya_ebpf::{
    EbpfContext,
    helpers::{bpf_get_prandom_u32, bpf_ktime_get_ns, bpf_probe_read_user_str_bytes},
    maps::PerCpuArray,
};

/// Emits a fixed-size event directly into a ring buffer reservation.
///
/// `RingBuf::output(&event)` copies from the BPF stack. Older verifiers
/// (6.1/6.6) reject that with `invalid indirect read from stack` or a
/// combined-stack-size error for the larger event structs. Reserving first
/// keeps the event out of the stack budget and centralizes the full-buffer
/// behavior: the event is dropped, counters stay exact.
#[macro_export]
macro_rules! emit_event {
    ($ring:expr, $ty:ident, { $($field:ident: $value:expr),* $(,)? }) => {{
        if let Some(mut entry) = $ring.reserve::<$ty>(0) {
            entry.write($ty { $($field: $value),* });
            entry.submit(0);
        }
    }};
}

/// Monotonic nanoseconds since boot. This is the clock used by all events and
/// by the token buckets; userspace must not interpret it as wall-clock time.
#[inline(always)]
pub fn now_ns() -> u64 {
    // SAFETY: `bpf_ktime_get_ns` has no arguments and cannot fail.
    unsafe { bpf_ktime_get_ns() }
}

/// Returns true when an event should be emitted for this invocation.
///
/// Sampling happens in the kernel to keep the ring buffer from becoming the
/// bottleneck on high-rate hooks (notably `sched_switch`). Counters are always
/// updated exactly; only the detailed event stream is sampled.
#[inline(always)]
pub fn sample(every: u32) -> bool {
    if every <= 1 {
        return true;
    }
    // SAFETY: no arguments; uniform random value.
    let random = unsafe { bpf_get_prandom_u32() };
    // The common configurations are powers of two (1/16, 1/64). Use a mask
    // instead of a 32-bit division in that case; keep modulo only for odd
    // sampling rates.
    if every.is_power_of_two() {
        random & (every - 1) == 0
    } else {
        random % every == 0
    }
}

/// Reads a NUL-terminated string from a **user** pointer into `dest`.
///
/// Returns the number of bytes written, excluding the terminator. Invalid
/// pointers and faulting pages simply yield 0; the verifier treats the helper
/// as fallible, so no exception can escape into the BPF program.
#[inline(always)]
pub fn read_user_string(ptr: u64, dest: &mut [u8]) -> usize {
    if ptr == 0 {
        return 0;
    }
    match unsafe { bpf_probe_read_user_str_bytes(ptr as *const u8, dest) } {
        Ok(bytes) => bytes.len(),
        Err(_) => 0,
    }
}

/// Shorthand for the current process name, zero-filled on failure.
#[inline(always)]
pub fn comm<C: EbpfContext>(ctx: &C) -> [u8; TASK_COMM_LEN] {
    ctx.command().unwrap_or([0; TASK_COMM_LEN])
}

/// Returns a mutable reference to this CPU's slot of a `PerCpuArray`.
///
/// The pointer points into the per-CPU map value, so no atomic operation is
/// required: only the current CPU can observe it. The returned reference must
/// not be held across another map operation that could sleep (BPF programs
/// cannot sleep anyway).
#[inline(always)]
pub fn cpu_stats<'a, T>(map: &'a PerCpuArray<T>) -> Option<&'a mut T> {
    // SAFETY: per-CPU array lookups return a pointer to this CPU's private
    // value. BPF programs are non-preemptible with respect to other BPF
    // programs on the same CPU, so exclusive access is guaranteed.
    unsafe { map.get_ptr_mut(0).map(|ptr| &mut *ptr) }
}

/// Returns true if `port` appears in the first `count` entries of `ports`.
///
/// The loop has a compile-time bound (`MAX_PORTS`), which is what lets the
/// verifier prove termination even though `count` comes from a map.
#[inline(always)]
pub fn port_in(ports: &[u16; MAX_PORTS], count: u32, port: u16) -> bool {
    let count = count.min(MAX_PORTS as u32);
    let mut i = 0usize;
    while i < MAX_PORTS {
        if (i as u32) < count && ports[i] == port {
            return true;
        }
        i += 1;
    }
    false
}

/// Returns true if `path` starts with any configured prefix.
///
/// Prefix matching is byte-exact and case-sensitive. Userspace refuses to
/// install prefixes containing NUL or exceeding `PREFIX_LEN - 1`, so a match
/// never depends on uninitialised tail bytes.
#[inline(always)]
pub fn path_matches_prefixes(
    path: &[u8; PATH_LEN],
    prefixes: &[[u8; PREFIX_LEN]; MAX_PREFIXES],
    prefix_lens: &[u8; MAX_PREFIXES],
    prefix_count: u8,
) -> bool {
    let count = (prefix_count as usize).min(MAX_PREFIXES);
    let mut p = 0usize;
    while p < count {
        let len = (prefix_lens[p] as usize).min(PREFIX_LEN - 1);
        let mut i = 0usize;
        let mut matches = len > 0;
        while i < len {
            if path[i] != prefixes[p][i] {
                matches = false;
                break;
            }
            i += 1;
        }
        if matches {
            return true;
        }
        p += 1;
    }
    false
}

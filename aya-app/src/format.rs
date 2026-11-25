//! Rendering helpers shared by all commands.
//!
//! The event structures keep IPv4 addresses in the raw network-order integer
//! representation used by packet headers. `Ipv4Addr::from(raw.to_ne_bytes())`
//! is therefore the correct conversion both for display and for comparing with
//! user-supplied addresses. Using `from_be` here would print every address
//! byte-swapped on little-endian hosts.

use std::{
    fmt,
    io::{self, BufWriter, Write},
    net::Ipv4Addr,
    sync::{Mutex, OnceLock},
};

fn event_out() -> &'static Mutex<BufWriter<io::Stdout>> {
    static EVENT_OUT: OnceLock<Mutex<BufWriter<io::Stdout>>> = OnceLock::new();
    EVENT_OUT.get_or_init(|| Mutex::new(BufWriter::new(io::stdout())))
}

/// Writes one event line to the buffered event stream.
///
/// A process-global buffer is used instead of a thread-local one because
/// Tokio's multi-thread runtime may move an async task between workers at an
/// await point; a thread-local buffer could then be flushed from a different
/// thread than the one that filled it.
pub fn event(args: fmt::Arguments<'_>) {
    let out = event_out();
    let mut out = out.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let _ = out.write_fmt(args);
    let _ = out.write_all(b"\n");
}

/// Flushes buffered events. Call before printing a stats block or detaching.
pub fn flush_events() {
    let out = event_out();
    let mut out = out.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let _ = out.flush();
}

/// Formats a raw network-order IPv4 value (as stored in packet headers).
pub fn ipv4(raw: u32) -> String {
    Ipv4Addr::from(raw.to_ne_bytes()).to_string()
}

/// Converts a user-supplied address into the raw representation used by BPF.
pub fn ipv4_to_raw(ip: Ipv4Addr) -> u32 {
    u32::from_ne_bytes(ip.octets())
}

/// Prefix mask in the same raw representation as [`ipv4_to_raw`].
pub fn prefix_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::from_ne_bytes((u32::MAX << (32 - u32::from(prefix_len))).to_be_bytes())
    }
}

/// Trims a fixed-size, NUL-padded byte string and lossily converts it to UTF-8.
pub fn fixed_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Process name (`comm`) from an event.
pub fn comm(bytes: &[u8; 16]) -> String {
    fixed_string(bytes)
}

/// Pathname from an event.
pub fn path(bytes: &[u8; 128]) -> String {
    fixed_string(bytes)
}

/// `rwbs` field from a block tracepoint event.
pub fn rwbs(bytes: &[u8; 8]) -> String {
    fixed_string(bytes)
}

/// Human-readable duration for latencies.
pub fn duration_ns(ns: u64) -> String {
    if ns < 1_000 {
        format!("{ns}ns")
    } else if ns < 1_000_000 {
        format!("{:.1}us", ns as f64 / 1_000.0)
    } else if ns < 1_000_000_000 {
        format!("{:.2}ms", ns as f64 / 1_000_000.0)
    } else {
        format!("{:.2}s", ns as f64 / 1_000_000_000.0)
    }
}

/// Human-readable byte count.
pub fn bytes(n: u64) -> String {
    const KIB: f64 = 1024.0;
    const MIB: f64 = KIB * 1024.0;
    const GIB: f64 = MIB * 1024.0;
    let n = n as f64;
    if n >= GIB {
        format!("{:.2} GiB", n / GIB)
    } else if n >= MIB {
        format!("{:.2} MiB", n / MIB)
    } else if n >= KIB {
        format!("{:.2} KiB", n / KIB)
    } else {
        format!("{n:.0} B")
    }
}

/// Seconds since boot, derived from a `bpf_ktime_get_ns()` timestamp.
///
/// eBPF's monotonic clock is not the wall clock. Printing uptime avoids a
/// misleading "1970-01-01" timestamp and makes event ordering obvious.
pub fn uptime(ns: u64) -> String {
    format!("{:.3}s", ns as f64 / 1_000_000_000.0)
}

/// Prints a consistent command banner.
pub fn banner(title: &str, lines: &[String]) {
    println!("\n=== {title} ===");
    for line in lines {
        println!("  {line}");
    }
}

/// Prints a section separator before periodic statistics.
pub fn stats_header(title: &str) {
    println!("\n--- {title} ---");
}

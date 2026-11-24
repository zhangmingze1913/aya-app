//! Shared state for latency probes.
//!
//! Only one of kprobe/uprobe/fentry is compiled into a given feature object,
//! but keeping the map here makes the key/value contract explicit and avoids
//! three near-identical declarations.

use aya_ebpf::{macros::map, maps::HashMap};

/// In-flight calls, keyed by `(tgid << 32) | pid`.
#[map(name = "probe_start")]
pub(crate) static PROBE_START: HashMap<u64, u64> = HashMap::with_max_entries(16_384, 0);

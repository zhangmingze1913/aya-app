//! Wire format shared by the `aya-app` userspace CLI and the `aya-app-ebpf`
//! programs.
//!
//! # Why a separate crate?
//!
//! eBPF programs and userspace run in two different compilation worlds:
//!
//! * the eBPF side is `no_std`, target `bpfel-unknown-none`, and has no
//!   `std::net`;
//! * the userspace side is a normal Linux binary and needs `aya` only to
//!   implement [`aya::Pod`] for map values.
//!
//! Keeping the event structures here guarantees that both sides agree on the
//! exact byte layout. Every type below is `#[repr(C)]`, has no implicit
//! padding, and is checked with compile-time size assertions at the bottom of
//! this file. That matters because a mismatch is not a type error: the kernel
//! would happily copy bytes and userspace would silently decode garbage.
//!
//! # Byte order
//!
//! * Ports in packet headers and in `sock_ops` are big-endian on the wire.
//!   The eBPF programs normalise them to host order before putting them into
//!   events, so userspace prints them as plain `u16`.
//! * IPv4 addresses are kept in their raw "network order as an integer"
//!   representation. On little-endian machines the integer value is therefore
//!   byte-swapped relative to the dotted-quad number. Userspace must use
//!   `Ipv4Addr::from(value.to_ne_bytes())` (not `from_be`) when printing, and
//!   `u32::from_ne_bytes(ip.octets())` when writing configuration. This sounds
//!   surprising, but it keeps the eBPF side to a single 32-bit compare and is
//!   the representation found in `iphdr::saddr` and `bpf_sock_ops::remote_ip4`.

#![no_std]

#[cfg(test)]
extern crate std;

/// Length of `task_struct::comm`, including the trailing NUL byte.
pub const TASK_COMM_LEN: usize = 16;

/// Maximum number of bytes captured for a pathname. Paths longer than this are
/// truncated by the `bpf_probe_read_*_str` helpers.
pub const PATH_LEN: usize = 128;

/// Maximum number of path prefixes configured for the kprobe scenario.
pub const MAX_PREFIXES: usize = 4;

/// Maximum length of one path prefix.
pub const PREFIX_LEN: usize = 64;

/// Maximum number of ports that can be configured in one TC / socket policy.
pub const MAX_PORTS: usize = 8;

// ---------------------------------------------------------------------------
// XDP
// ---------------------------------------------------------------------------

/// XDP configuration, written by userspace before the program is attached.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct XdpConfig {
    /// Non-zero: drop ICMP echo requests that match the protected prefix.
    pub block_icmp: u32,
    /// Per-source-IP packet-per-second budget. `0` disables rate limiting.
    pub rate_limit_pps: u32,
    /// Protected IPv4 prefix, in the raw network-order representation.
    /// `0` means "all destinations".
    pub protected_ip: u32,
    /// Mask applied to `protected_ip` and the packet destination.
    pub protected_mask: u32,
    /// Emit one ring-buffer event every `event_sample` drops. `0`/`1` means
    /// every drop.
    pub event_sample: u32,
    /// Explicit padding: keeps the struct's size stable across Rust versions
    /// and makes the absence of implicit padding obvious.
    pub _pad: u32,
}

/// Per-CPU counters for the XDP program. Summing all CPUs gives exact totals.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct XdpStats {
    /// Packets returned as `XDP_PASS`.
    pub passed: u64,
    /// ICMP packets dropped by the firewall rule.
    pub dropped_icmp: u64,
    /// Packets dropped by the per-IP token bucket.
    pub dropped_rate: u64,
    /// Bytes belonging to passed packets.
    pub passed_bytes: u64,
    /// Bytes belonging to dropped packets.
    pub dropped_bytes: u64,
}

/// Reason codes carried in [`XdpEvent::reason`].
pub const XDP_DROP_ICMP: u32 = 1;
/// See [`XDP_DROP_ICMP`].
pub const XDP_DROP_RATE: u32 = 2;

/// A sampled drop event delivered through the `xdp_events` ring buffer.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct XdpEvent {
    /// `bpf_ktime_get_ns()` at the drop.
    pub timestamp_ns: u64,
    /// Source IPv4 address, raw network-order representation.
    pub saddr: u32,
    /// Destination IPv4 address, raw network-order representation.
    pub daddr: u32,
    /// One of [`XDP_DROP_ICMP`] / [`XDP_DROP_RATE`].
    pub reason: u32,
    /// Length of the dropped frame, including the Ethernet header.
    pub pkt_len: u32,
}

// ---------------------------------------------------------------------------
// TC
// ---------------------------------------------------------------------------

/// TC classifier configuration.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TcConfig {
    /// Destination ports that are dropped (for example P2P traffic).
    pub drop_ports: [u16; MAX_PORTS],
    /// Destination ports that receive a high-priority `skb->mark`.
    pub video_ports: [u16; MAX_PORTS],
    /// Number of valid entries in `drop_ports`.
    pub drop_port_count: u32,
    /// Number of valid entries in `video_ports`.
    pub video_port_count: u32,
    /// Mark value written for prioritised flows. Userspace pairs this with a
    /// `tc filter ... fw` rule that maps the mark to a qdisc band.
    pub video_mark: u32,
    /// Ring-buffer sampling interval for drop events. `0`/`1` means every
    /// drop.
    pub event_sample: u32,
}

/// Per-CPU TC counters.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TcStats {
    /// Packets returned as `TC_ACT_OK`.
    pub passed: u64,
    /// P2P packets returned as `TC_ACT_SHOT`.
    pub dropped_p2p: u64,
    /// Video packets that had `skb->mark` rewritten.
    pub prioritized: u64,
    /// Bytes of passed packets.
    pub passed_bytes: u64,
    /// Bytes of dropped packets.
    pub dropped_bytes: u64,
}

/// TC event actions.
pub const TC_ACTION_DROP: u32 = 1;
/// See [`TC_ACTION_DROP`].
pub const TC_ACTION_PRIORITIZE: u32 = 2;

/// A sampled TC action event.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TcEvent {
    /// `bpf_ktime_get_ns()` when the classifier ran.
    pub timestamp_ns: u64,
    /// Source IPv4 address.
    pub saddr: u32,
    /// Destination IPv4 address.
    pub daddr: u32,
    /// Source L4 port, host order.
    pub sport: u16,
    /// Destination L4 port, host order.
    pub dport: u16,
    /// [`TC_ACTION_DROP`] or [`TC_ACTION_PRIORITIZE`].
    pub action: u32,
    /// Packet length in bytes.
    pub pkt_len: u32,
    /// Explicit tail padding.
    pub _pad: u32,
}

// ---------------------------------------------------------------------------
// Kprobe / kretprobe
// ---------------------------------------------------------------------------

/// Kprobe configuration.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KprobeConfig {
    /// NUL-padded path prefixes. A prefix matches when the captured path starts
    /// with the corresponding `prefix_lens[i]` bytes.
    pub prefixes: [[u8; PREFIX_LEN]; MAX_PREFIXES],
    /// Length of each valid prefix. A zero length is not a valid prefix.
    pub prefix_lens: [u8; MAX_PREFIXES],
    /// Number of valid entries in `prefixes` / `prefix_lens`.
    pub prefix_count: u8,
    /// Explicit padding.
    pub _pad: [u8; 3],
    /// Only emit a latency event when the call took at least this long.
    pub latency_threshold_ns: u64,
}

impl Default for KprobeConfig {
    fn default() -> Self {
        Self {
            prefixes: [[0; PREFIX_LEN]; MAX_PREFIXES],
            prefix_lens: [0; MAX_PREFIXES],
            prefix_count: 0,
            _pad: [0; 3],
            latency_threshold_ns: 0,
        }
    }
}

/// Kprobe event kinds.
pub const KPROBE_KIND_OPEN: u32 = 1;
/// See [`KPROBE_KIND_OPEN`].
pub const KPROBE_KIND_LATENCY: u32 = 2;

/// A kprobe/kretprobe event.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct KprobeEvent {
    /// `bpf_ktime_get_ns()`.
    pub timestamp_ns: u64,
    /// Thread id (kernel `pid`).
    pub pid: u32,
    /// Thread-group id (userspace `pid`).
    pub tgid: u32,
    /// Owner uid at the time of the probe.
    pub uid: u32,
    /// [`KPROBE_KIND_OPEN`] or [`KPROBE_KIND_LATENCY`].
    pub kind: u32,
    /// Measured latency for latency events, `0` for open events.
    pub latency_ns: u64,
    /// Return value of the probed function (`-errno` on failure).
    pub ret: i64,
    /// Captured pathname (only for open events).
    pub path: [u8; PATH_LEN],
    /// Process name.
    pub comm: [u8; TASK_COMM_LEN],
}

impl Default for KprobeEvent {
    fn default() -> Self {
        Self {
            timestamp_ns: 0,
            pid: 0,
            tgid: 0,
            uid: 0,
            kind: 0,
            latency_ns: 0,
            ret: 0,
            path: [0; PATH_LEN],
            comm: [0; TASK_COMM_LEN],
        }
    }
}

/// Per-CPU kprobe counters.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct KprobeStats {
    /// Number of `openat`-family calls observed by the entry probe.
    pub opens: u64,
    /// Calls whose path matched one of the configured prefixes.
    pub sensitive: u64,
    /// Return probes that found a matching start timestamp.
    pub latency_calls: u64,
    /// Calls whose latency exceeded the configured threshold.
    pub slow_calls: u64,
}

// ---------------------------------------------------------------------------
// Uprobe / uretprobe
// ---------------------------------------------------------------------------

/// Uprobe configuration.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UprobeConfig {
    /// Emit an exit-latency event only when the call took at least this long.
    pub latency_threshold_ns: u64,
    /// Explicit padding, also reserves room for future options.
    pub _pad: u64,
}

/// Uprobe event kinds.
pub const UPROBE_KIND_ENTER: u32 = 1;
/// See [`UPROBE_KIND_ENTER`].
pub const UPROBE_KIND_EXIT: u32 = 2;

/// A uprobe/uretprobe event for the bundled demo target.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct UprobeEvent {
    /// `bpf_ktime_get_ns()`.
    pub timestamp_ns: u64,
    /// Thread id.
    pub pid: u32,
    /// Thread-group id.
    pub tgid: u32,
    /// [`UPROBE_KIND_ENTER`] or [`UPROBE_KIND_EXIT`].
    pub kind: u32,
    /// Explicit padding.
    pub _pad: u32,
    /// First argument of `demo_handle_request`.
    pub request_id: u64,
    /// Latency for exit events, `0` for entry events.
    pub latency_ns: u64,
    /// Return value for exit events.
    pub ret: i64,
    /// Second argument of `demo_handle_request`, captured as a C string.
    pub path: [u8; PATH_LEN],
    /// Process name.
    pub comm: [u8; TASK_COMM_LEN],
}

impl Default for UprobeEvent {
    fn default() -> Self {
        Self {
            timestamp_ns: 0,
            pid: 0,
            tgid: 0,
            kind: 0,
            _pad: 0,
            request_id: 0,
            latency_ns: 0,
            ret: 0,
            path: [0; PATH_LEN],
            comm: [0; TASK_COMM_LEN],
        }
    }
}

/// Per-CPU uprobe counters.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct UprobeStats {
    /// Entry probes that fired.
    pub enters: u64,
    /// Return probes that completed.
    pub exits: u64,
    /// Exits whose latency exceeded the threshold.
    pub slow_calls: u64,
}

// ---------------------------------------------------------------------------
// Tracepoint
// ---------------------------------------------------------------------------

/// Byte offsets of the fields we consume from the two tracepoint formats.
///
/// Tracepoint layouts are part of the kernel's `trace_event_raw_*` structs and
/// change between kernel versions (and sometimes options). Instead of
/// hard-coding offsets, the CLI parses
/// `/sys/kernel/tracing/events/<cat>/<name>/format` and stores the result here.
/// A `*_valid` flag of zero tells the corresponding BPF program to bail out.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TracepointOffsets {
    // sched:sched_switch
    /// Offset of `prev_comm[16]`.
    pub sched_prev_comm: u32,
    /// Offset of `prev_pid`.
    pub sched_prev_pid: u32,
    /// Offset of `prev_prio`.
    pub sched_prev_prio: u32,
    /// Offset of `prev_state` (8 bytes on 64-bit kernels).
    pub sched_prev_state: u32,
    /// Offset of `next_comm[16]`.
    pub sched_next_comm: u32,
    /// Offset of `next_pid`.
    pub sched_next_pid: u32,
    /// Offset of `next_prio`.
    pub sched_next_prio: u32,
    /// Non-zero when all sched offsets were resolved.
    pub sched_valid: u32,

    // block:block_rq_issue
    /// Offset of `dev`.
    pub block_dev: u32,
    /// Offset of `sector` (8 bytes).
    pub block_sector: u32,
    /// Offset of `nr_sector`.
    pub block_nr_sector: u32,
    /// Offset of `bytes` (optional on very old kernels).
    pub block_bytes: u32,
    /// Offset of `rwbs[8]`.
    pub block_rwbs: u32,
    /// Offset of `comm[16]`.
    pub block_comm: u32,
    /// Non-zero when all required block offsets were resolved.
    pub block_valid: u32,
    /// Size of `prev_state` in bytes (4 or 8). Tracepoints on 64-bit kernels
    /// use `long`, but 32-bit kernels use 4 bytes.
    pub sched_prev_state_size: u32,
}

/// Runtime sampling controls for the tracepoint programs.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct TracepointControl {
    /// Emit one `sched_switch` event out of this many. `0`/`1` means all.
    pub sched_sample_every: u32,
    /// Emit one block event out of this many. `0`/`1` means all.
    pub block_sample_every: u32,
}

/// A sampled `sched:sched_switch` event.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SchedEvent {
    /// `bpf_ktime_get_ns()`.
    pub timestamp_ns: u64,
    /// PID of the task being switched out.
    pub prev_pid: u32,
    /// PID of the task being switched in.
    pub next_pid: u32,
    /// Static priority of the previous task.
    pub prev_prio: u32,
    /// Static priority of the next task.
    pub next_prio: u32,
    /// Task state of the previous task (kernel `long`).
    pub prev_state: u64,
    /// Name of the previous task.
    pub prev_comm: [u8; TASK_COMM_LEN],
    /// Name of the next task.
    pub next_comm: [u8; TASK_COMM_LEN],
}

/// A sampled `block:block_rq_issue` event.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockEvent {
    /// `bpf_ktime_get_ns()`.
    pub timestamp_ns: u64,
    /// First sector of the request.
    pub sector: u64,
    /// Number of sectors.
    pub nr_sector: u32,
    /// Number of bytes (0 when the field is unavailable).
    pub bytes: u32,
    /// Encoded device number.
    pub dev: u32,
    /// Explicit padding.
    pub _pad: u32,
    /// R/W/barrier flags as text, e.g. `"R"`, `"W"`, `"WS"`.
    pub rwbs: [u8; 8],
    /// Issuing process name.
    pub comm: [u8; TASK_COMM_LEN],
}

/// Per-CPU sched tracepoint counters.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SchedStats {
    /// Total number of context switches observed (not sampled).
    pub switches: u64,
    /// Number of events actually written to the ring buffer.
    pub emitted: u64,
}

/// Per-CPU block tracepoint counters.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct BlockStats {
    /// Total number of block requests observed (not sampled).
    pub issues: u64,
    /// Total bytes covered by those requests.
    pub bytes: u64,
    /// Requests whose `rwbs` starts with `R`.
    pub reads: u64,
    /// Requests whose `rwbs` starts with `W`.
    pub writes: u64,
}

// ---------------------------------------------------------------------------
// SOCK_OPS / socket filter / cgroup connect4
// ---------------------------------------------------------------------------

/// SOCK_OPS configuration.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SockOpsConfig {
    /// When non-empty, only connections involving one of these ports are
    /// reported. Ports are host order.
    pub watch_ports: [u16; MAX_PORTS],
    /// Number of valid entries in `watch_ports`.
    pub watch_port_count: u32,
    /// Explicit padding.
    pub _pad: u32,
}

/// A SOCK_OPS lifecycle event.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SockOpsEvent {
    /// `bpf_ktime_get_ns()`.
    pub timestamp_ns: u64,
    /// Thread id at the callback.
    pub pid: u32,
    /// Address family (`AF_INET` / `AF_INET6`).
    pub family: u32,
    /// Kernel `BPF_SOCK_OPS_*` operation code.
    pub op: u32,
    /// TCP state, when available.
    pub state: u32,
    /// Local port, host order.
    pub local_port: u32,
    /// Remote port, host order.
    pub remote_port: u32,
    /// Local IPv4 address, raw network-order representation.
    pub local_ip4: u32,
    /// Remote IPv4 address, raw network-order representation.
    pub remote_ip4: u32,
    /// Smoothed RTT in microseconds (0 when not a full socket).
    pub srtt_us: u32,
    /// Explicit padding.
    pub _pad0: u32,
    /// Bytes acknowledged on this socket.
    pub bytes_acked: u64,
    /// Bytes received on this socket.
    pub bytes_received: u64,
    /// Process name.
    pub comm: [u8; TASK_COMM_LEN],
}

/// Per-CPU SOCK_OPS counters.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SockOpsStats {
    /// `BPF_SOCK_OPS_TCP_CONNECT_CB` callbacks.
    pub connect_events: u64,
    /// Active/passive established callbacks.
    pub established_events: u64,
    /// `BPF_SOCK_OPS_TCP_LISTEN_CB` callbacks.
    pub listen_events: u64,
    /// `BPF_SOCK_OPS_STATE_CB` callbacks.
    pub state_events: u64,
}

/// Socket-filter configuration.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SkfilterConfig {
    /// Non-zero: apply the source-IP allowlist to inbound SYN packets.
    pub enforce: u32,
    /// Explicit padding.
    pub _pad: u32,
}

/// Per-CPU socket-filter counters.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct SkfilterStats {
    /// Packets seen by the filter.
    pub seen: u64,
    /// TCP SYN packets without ACK.
    pub syn: u64,
    /// SYN packets accepted by the allowlist.
    pub allowed_syn: u64,
    /// SYN packets dropped by the allowlist.
    pub dropped_syn: u64,
    /// Non-TCP packets (ICMP errors, etc.) passed through.
    pub non_tcp: u64,
    /// Established/non-SYN TCP packets passed through.
    pub other: u64,
}

/// cgroup/connect4 egress policy.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Connect4Config {
    /// Destination ports that are allowed. At least one entry must be valid.
    pub allow_ports: [u16; MAX_PORTS],
    /// Number of valid entries.
    pub allow_port_count: u32,
    /// Explicit padding.
    pub _pad: u32,
}

/// An egress connect4 decision event.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Connect4Event {
    /// `bpf_ktime_get_ns()`.
    pub timestamp_ns: u64,
    /// Thread id that called `connect()`.
    pub pid: u32,
    /// Destination IPv4 address, raw network-order representation.
    pub daddr: u32,
    /// Destination port, host order.
    pub dport: u16,
    /// 1 = allowed, 0 = denied.
    pub allowed: u16,
    /// Explicit padding.
    pub _pad: u32,
    /// Process name.
    pub comm: [u8; TASK_COMM_LEN],
}

/// Per-CPU connect4 counters.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Connect4Stats {
    /// Total connect4 invocations.
    pub connects: u64,
    /// Connections allowed by the port list.
    pub allowed: u64,
    /// Connections denied by the port list.
    pub denied: u64,
}

// ---------------------------------------------------------------------------
// LSM
// ---------------------------------------------------------------------------

/// LSM `socket_connect` policy configuration.
///
/// The LSM hook is global (not cgroup-scoped), so `target_uid`/`enforce_uid`
/// provide an optional blast-radius limit. With `enforce_uid = 0` the policy
/// applies to every process on the host.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct LsmConfig {
    /// Destination ports that are denied. At least one entry must be valid.
    pub blocked_ports: [u16; MAX_PORTS],
    /// Number of valid entries in `blocked_ports`.
    pub blocked_port_count: u32,
    /// UID to which the policy is restricted when `enforce_uid != 0`.
    pub target_uid: u32,
    /// Non-zero: only apply the policy to `target_uid`.
    pub enforce_uid: u32,
    /// Ring-buffer sampling interval for deny events. `0`/`1` means every
    /// deny.
    pub event_sample: u32,
    /// Explicit padding.
    pub _pad: u64,
}

/// LSM event actions.
pub const LSM_ACTION_DENY: u32 = 1;

/// An LSM `socket_connect` denial event.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct LsmEvent {
    /// `bpf_ktime_get_ns()`.
    pub timestamp_ns: u64,
    /// Thread id that called `connect()`.
    pub pid: u32,
    /// UID at the time of the hook.
    pub uid: u32,
    /// Destination IPv4 address, raw network-order representation.
    pub daddr: u32,
    /// Destination port, host order.
    pub dport: u16,
    /// Address family (`AF_INET` = 2; other families are only counted).
    pub family: u16,
    /// [`LSM_ACTION_DENY`].
    pub action: u32,
    /// Explicit padding.
    pub _pad: u32,
    /// Process name.
    pub comm: [u8; TASK_COMM_LEN],
}

/// Per-CPU LSM counters.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct LsmStats {
    /// Total `socket_connect` hook invocations.
    pub connects: u64,
    /// Connections allowed by the policy or by the UID filter.
    pub allowed: u64,
    /// Connections denied by the blocked-port list.
    pub denied: u64,
}

// ---------------------------------------------------------------------------
// fentry / fexit
// ---------------------------------------------------------------------------

/// fentry/fexit configuration.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FentryConfig {
    /// Only emit an exit event when the call took at least this long.
    pub latency_threshold_ns: u64,
    /// Emit one event out of this many exits. `0`/`1` means every exit.
    pub event_sample: u32,
    /// Explicit padding.
    pub _pad: u32,
}

/// A fentry/fexit latency event.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FentryEvent {
    /// `bpf_ktime_get_ns()` at function exit.
    pub timestamp_ns: u64,
    /// Entry-to-exit latency.
    pub latency_ns: u64,
    /// Thread id.
    pub pid: u32,
    /// Thread-group id.
    pub tgid: u32,
    /// Owner uid.
    pub uid: u32,
    /// Function return value (`do_sys_openat2`: fd or `-errno`).
    pub ret: i32,
    /// Explicit padding.
    pub _pad: u32,
    /// Process name.
    pub comm: [u8; TASK_COMM_LEN],
}

/// Per-CPU fentry/fexit counters.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct FentryStats {
    /// fentry invocations.
    pub enters: u64,
    /// fexit invocations.
    pub exits: u64,
    /// Exits whose latency crossed the configured threshold.
    pub slow_calls: u64,
    /// Exits without a matching entry timestamp (map full or nested call).
    pub missing_starts: u64,
}

// ---------------------------------------------------------------------------
// Raw tracepoint
// ---------------------------------------------------------------------------

/// Raw tracepoint configuration.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RawTpConfig {
    /// Syscall number to report from the `sys_enter` raw tracepoint.
    pub syscall_nr: u32,
    /// Emit one event out of this many matches. `0`/`1` means every match.
    pub event_sample: u32,
    /// Explicit padding / room for future fields.
    pub _pad: u64,
}

/// A sampled `sys_enter` raw-tracepoint event.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RawTpEvent {
    /// `bpf_ktime_get_ns()`.
    pub timestamp_ns: u64,
    /// Thread id.
    pub pid: u32,
    /// Thread-group id.
    pub tgid: u32,
    /// Owner uid.
    pub uid: u32,
    /// Syscall number.
    pub syscall_nr: u32,
    /// Explicit padding.
    pub _pad: u32,
    /// Process name.
    pub comm: [u8; TASK_COMM_LEN],
}

/// Per-CPU raw tracepoint counters.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct RawTpStats {
    /// Matching syscall entries observed.
    pub matches: u64,
    /// Events written to the ring buffer.
    pub emitted: u64,
}

// ---------------------------------------------------------------------------
// cgroup_skb
// ---------------------------------------------------------------------------

/// cgroup_skb egress/ingress policy.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CgSkbConfig {
    /// Destination port to drop, host order. `0` disables enforcement.
    pub block_port: u16,
    /// Explicit padding.
    pub _pad0: u16,
    /// Emit one event out of this many drops. `0`/`1` means every drop.
    pub event_sample: u32,
}

/// cgroup_skb drop event.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CgSkbEvent {
    /// `bpf_ktime_get_ns()`.
    pub timestamp_ns: u64,
    /// Source IPv4 address, raw network-order representation.
    pub saddr: u32,
    /// Destination IPv4 address, raw network-order representation.
    pub daddr: u32,
    /// Source L4 port, host order.
    pub sport: u16,
    /// Destination L4 port, host order.
    pub dport: u16,
    /// Packet length.
    pub pkt_len: u32,
    /// [`CGSKB_ACTION_DROP`].
    pub action: u32,
    /// Thread id. Currently zero for cgroup_skb: the helper is unavailable on
    /// older kernels (for example 6.6).
    pub pid: u32,
    /// Thread-group id. Currently zero for the same reason as [`Self::pid`].
    pub tgid: u32,
    /// Explicit padding.
    pub _pad: u32,
    /// Process name. Currently empty for the same helper-availability reason.
    pub comm: [u8; TASK_COMM_LEN],
}

/// Per-CPU cgroup_skb counters.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CgSkbStats {
    /// Packets allowed.
    pub passed: u64,
    /// Packets dropped by the port rule.
    pub dropped: u64,
    /// Bytes allowed.
    pub passed_bytes: u64,
    /// Bytes dropped.
    pub dropped_bytes: u64,
}

/// Action code for [`CgSkbEvent::action`].
pub const CGSKB_ACTION_DROP: u32 = 1;

// ---------------------------------------------------------------------------
// cgroup_sysctl
// ---------------------------------------------------------------------------

/// cgroup_sysctl configuration.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CgSysctlConfig {
    /// Non-zero: deny writes from processes in the attached cgroup.
    pub block_writes: u32,
    /// Emit one event out of this many writes. `0`/`1` means every write.
    pub event_sample: u32,
}

/// A sampled cgroup_sysctl event.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CgSysctlEvent {
    /// `bpf_ktime_get_ns()`.
    pub timestamp_ns: u64,
    /// Thread id.
    pub pid: u32,
    /// Thread-group id.
    pub tgid: u32,
    /// Owner uid.
    pub uid: u32,
    /// Non-zero for a write, zero for a read.
    pub write: u32,
    /// [`CGSYSCTL_ACTION_DENY`] or 0.
    pub action: u32,
    /// Explicit padding.
    pub _pad: u32,
    /// Process name.
    pub comm: [u8; TASK_COMM_LEN],
}

/// Per-CPU cgroup_sysctl counters.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct CgSysctlStats {
    /// Total hook invocations.
    pub calls: u64,
    /// Write operations.
    pub writes: u64,
    /// Writes denied by the policy.
    pub blocked: u64,
    /// Read operations.
    pub reads: u64,
}

/// Action code for [`CgSysctlEvent::action`].
pub const CGSYSCTL_ACTION_DENY: u32 = 1;

// ---------------------------------------------------------------------------
// Userspace `Pod` implementations and layout checks
// ---------------------------------------------------------------------------

#[cfg(feature = "user")]
mod pod {
    use super::*;

    macro_rules! impl_pod {
        ($($ty:ty),* $(,)?) => {
            $(
                // SAFETY: every type is `#[repr(C)]`, `Copy`, contains only
                // integers/arrays of integers, and is fully initialised. The
                // size assertions below pin the layout.
                unsafe impl aya::Pod for $ty {}
            )*
        };
    }

    impl_pod!(
        XdpConfig,
        XdpStats,
        XdpEvent,
        TcConfig,
        TcStats,
        TcEvent,
        KprobeConfig,
        KprobeEvent,
        KprobeStats,
        UprobeConfig,
        UprobeEvent,
        UprobeStats,
        TracepointOffsets,
        TracepointControl,
        SchedEvent,
        BlockEvent,
        SchedStats,
        BlockStats,
        SockOpsConfig,
        SockOpsEvent,
        SockOpsStats,
        SkfilterConfig,
        SkfilterStats,
        Connect4Config,
        Connect4Event,
        Connect4Stats,
        LsmConfig,
        LsmEvent,
        LsmStats,
        FentryConfig,
        FentryEvent,
        FentryStats,
        RawTpConfig,
        RawTpEvent,
        RawTpStats,
        CgSkbConfig,
        CgSkbEvent,
        CgSkbStats,
        CgSysctlConfig,
        CgSysctlEvent,
        CgSysctlStats,
    );
}

const _: () = {
    use core::mem::size_of;

    // These assertions are the contract with the kernel. If you change a
    // structure, update the assertion and bump the userspace decode logic.
    assert!(size_of::<XdpConfig>() == 24);
    assert!(size_of::<XdpStats>() == 40);
    assert!(size_of::<XdpEvent>() == 24);

    assert!(size_of::<TcConfig>() == 48);
    assert!(size_of::<TcStats>() == 40);
    assert!(size_of::<TcEvent>() == 32);

    assert!(size_of::<KprobeConfig>() == 272);
    assert!(size_of::<KprobeEvent>() == 184);
    assert!(size_of::<KprobeStats>() == 32);

    assert!(size_of::<UprobeConfig>() == 16);
    assert!(size_of::<UprobeEvent>() == 192);
    assert!(size_of::<UprobeStats>() == 24);

    assert!(size_of::<TracepointOffsets>() == 64);
    assert!(size_of::<TracepointControl>() == 8);
    assert!(size_of::<SchedEvent>() == 64);
    assert!(size_of::<BlockEvent>() == 56);
    assert!(size_of::<SchedStats>() == 16);
    assert!(size_of::<BlockStats>() == 32);

    assert!(size_of::<SockOpsConfig>() == 24);
    assert!(size_of::<SockOpsEvent>() == 80);
    assert!(size_of::<SockOpsStats>() == 32);
    assert!(size_of::<SkfilterConfig>() == 8);
    assert!(size_of::<SkfilterStats>() == 48);
    assert!(size_of::<Connect4Config>() == 24);
    assert!(size_of::<Connect4Event>() == 40);
    assert!(size_of::<Connect4Stats>() == 24);

    assert!(size_of::<LsmConfig>() == 40);
    assert!(size_of::<LsmEvent>() == 48);
    assert!(size_of::<LsmStats>() == 24);

    assert!(size_of::<FentryConfig>() == 16);
    assert!(size_of::<FentryEvent>() == 56);
    assert!(size_of::<FentryStats>() == 32);

    assert!(size_of::<RawTpConfig>() == 16);
    assert!(size_of::<RawTpEvent>() == 48);
    assert!(size_of::<RawTpStats>() == 16);

    assert!(size_of::<CgSkbConfig>() == 8);
    assert!(size_of::<CgSkbEvent>() == 56);
    assert!(size_of::<CgSkbStats>() == 32);

    assert!(size_of::<CgSysctlConfig>() == 8);
    assert!(size_of::<CgSysctlEvent>() == 48);
    assert!(size_of::<CgSysctlStats>() == 32);
};

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    /// Run on Linux CI: the ABI must not depend on the host.
    #[test]
    fn abi_layout_is_stable() {
        assert_eq!(size_of::<XdpConfig>(), 24);
        assert_eq!(size_of::<KprobeEvent>(), 184);
        assert_eq!(size_of::<UprobeEvent>(), 192);
        assert_eq!(size_of::<LsmEvent>(), 48);
        assert_eq!(size_of::<FentryEvent>(), 56);
        assert_eq!(size_of::<RawTpEvent>(), 48);
        assert_eq!(size_of::<CgSkbEvent>(), 56);
        assert_eq!(size_of::<CgSysctlEvent>(), 48);
    }

    #[test]
    fn defaults_are_zeroed() {
        let config = FentryConfig::default();
        assert_eq!(config.latency_threshold_ns, 0);
        assert_eq!(config.event_sample, 0);

        let event = CgSysctlEvent::default();
        assert_eq!(event.write, 0);
        assert_eq!(event.action, 0);
    }

    #[test]
    fn limits_are_consistent() {
        // These values are part of the eBPF/userspace contract.
        assert_eq!(TASK_COMM_LEN, 16);
        assert_eq!(PATH_LEN, 128);
        assert_eq!(MAX_PORTS, 8);
    }
}

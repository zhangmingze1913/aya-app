//! Socket-layer programs: SOCK_OPS telemetry, classic socket-filter SYN
//! guarding, and a cgroup/connect4 egress allowlist.
//!
//! # Why three programs?
//!
//! The three hooks answer different questions and have different powers:
//!
//! | Program | Attach point | Can it block? | Typical use |
//! |---|---|---|---|
//! | `sockops_guard` | cgroup `BPF_CGROUP_SOCK_OPS` | **No** (callback return values are ignored) | connection telemetry, per-socket tuning |
//! | `skfilter_guard` | `SO_ATTACH_BPF` on a socket | Yes, inbound packets | SYN allowlist / SYN-flood protection |
//! | `connect4_guard` | cgroup `BPF_CGROUP_INET4_CONNECT` | Yes, egress `connect()` | container egress allowlist |
//!
//! This distinction is important: a SOCK_OPS callback cannot deny a
//! connection. The `connect4` hook is the correct enforcement point for
//! "only allow ports 80/443" on outgoing connections; the socket filter is the
//! correct enforcement point for inbound SYNs to a listener.

use aya_app_common::{
    Connect4Config, Connect4Event, Connect4Stats, SkfilterConfig, SkfilterStats, SockOpsConfig,
    SockOpsEvent, SockOpsStats,
};
use aya_ebpf::{
    EbpfContext as _,
    bindings::{
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB, BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB,
        BPF_SOCK_OPS_STATE_CB, BPF_SOCK_OPS_STATE_CB_FLAG, BPF_SOCK_OPS_TCP_CONNECT_CB,
        BPF_SOCK_OPS_TCP_LISTEN_CB, bpf_hdr_start_off::BPF_HDR_START_NET,
    },
    helpers::bpf_skb_load_bytes_relative,
    macros::{cgroup_sock_addr, map, sock_ops, socket_filter},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{SkBuffContext, SockAddrContext, SockOpsContext},
};

use crate::{
    net::{IPPROTO_TCP, Ipv4Hdr, TcpHdr},
    utils::{comm, cpu_stats, now_ns, port_in, sample},
};

/// `AF_INET` from `linux/socket.h`; aya's bindings do not generate the family
/// constants because they are libc-defined.
const AF_INET: u32 = 2;

// ---------------------------------------------------------------------------
// SOCK_OPS
// ---------------------------------------------------------------------------

#[map(name = "sockops_config")]
static SOCKOPS_CONFIG: Array<SockOpsConfig> = Array::with_max_entries(1, 0);

#[map(name = "sockops_stats")]
static SOCKOPS_STATS: PerCpuArray<SockOpsStats> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "sockops_events")]
static SOCKOPS_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[sock_ops]
pub fn sockops_guard(ctx: SockOpsContext) -> u32 {
    // The kernel treats the return value of `*_CB` operations as "success" and
    // ignores it for policy. Always return 1.
    if try_sockops(&ctx).is_none() {
        // Nothing to do; still report success.
    }
    1
}

fn try_sockops(ctx: &SockOpsContext) -> Option<()> {
    let cfg = SOCKOPS_CONFIG.get(0)?;
    let op = ctx.op();

    let local_port = ctx.local_port();
    let remote_port = u16::from_be(ctx.remote_port() as u16) as u32;

    // Optional port filter: useful to focus on a service instead of recording
    // every connection on the host.
    if cfg.watch_port_count > 0
        && !port_in(&cfg.watch_ports, cfg.watch_port_count, local_port as u16)
        && !port_in(&cfg.watch_ports, cfg.watch_port_count, remote_port as u16)
    {
        return Some(());
    }

    // Enable state callbacks for this socket so we can report FIN/CLOSE
    // transitions. Both active connects and accepted connections need this;
    // the helper *sets* the flags, so preserve existing ones.
    if op == BPF_SOCK_OPS_TCP_CONNECT_CB as u32 || op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB as u32
    {
        let flags = (ctx.cb_flags() | BPF_SOCK_OPS_STATE_CB_FLAG as u32) as i32;
        let _ = ctx.set_cb_flags(flags);
    }

    if let Some(stats) = cpu_stats(&SOCKOPS_STATS) {
        match op {
            x if x == BPF_SOCK_OPS_TCP_CONNECT_CB as u32 => stats.connect_events += 1,
            x if x == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB as u32
                || x == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB as u32 =>
            {
                stats.established_events += 1;
            }
            x if x == BPF_SOCK_OPS_TCP_LISTEN_CB as u32 => stats.listen_events += 1,
            x if x == BPF_SOCK_OPS_STATE_CB as u32 => stats.state_events += 1,
            _ => {}
        }
    }

    // Only emit lifecycle events we care about. Other ops (TIMEOUT_INIT,
    // RWND_INIT, ...) are called for queries and would add noise.
    let interesting = op == BPF_SOCK_OPS_TCP_CONNECT_CB as u32
        || op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB as u32
        || op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB as u32
        || op == BPF_SOCK_OPS_TCP_LISTEN_CB as u32
        || op == BPF_SOCK_OPS_STATE_CB as u32;
    if !interesting {
        return Some(());
    }

    // SAFETY: `ctx.ops` is a valid `bpf_sock_ops *` provided by the kernel for
    // the duration of this program. Fields are plain integers.
    let (state, srtt_us, bytes_acked, bytes_received) = unsafe {
        let ops = &*ctx.ops;
        (
            ops.state,
            ops.srtt_us >> 3,
            ops.bytes_acked,
            ops.bytes_received,
        )
    };

    crate::emit_event!(SOCKOPS_EVENTS, SockOpsEvent, {
        timestamp_ns: now_ns(),
        pid: ctx.pid(),
        family: ctx.family(),
        op: op,
        state: state,
        local_port: local_port,
        remote_port: remote_port,
        local_ip4: ctx.local_ip4(),
        remote_ip4: ctx.remote_ip4(),
        srtt_us: srtt_us,
        _pad0: 0,
        bytes_acked: bytes_acked,
        bytes_received: bytes_received,
        comm: comm(ctx),
    });
    Some(())
}

// ---------------------------------------------------------------------------
// Classic socket filter: inbound SYN allowlist
// ---------------------------------------------------------------------------

#[map(name = "skfilter_config")]
static SKFILTER_CONFIG: Array<SkfilterConfig> = Array::with_max_entries(1, 0);

#[map(name = "skfilter_stats")]
static SKFILTER_STATS: PerCpuArray<SkfilterStats> = PerCpuArray::with_max_entries(1, 0);

/// Source IPv4 allowlist. The key is the raw network-order representation used
/// by the packet header (see the byte-order note in `aya-app-common`).
#[map(name = "skfilter_allowed")]
static SKFILTER_ALLOWED: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[socket_filter]
pub fn skfilter_guard(ctx: SkBuffContext) -> i64 {
    let len = ctx.len();
    match try_skfilter(&ctx) {
        Some(true) => i64::from(len),
        // A return value of 0 drops the packet; partial values would trim the
        // packet, which is not something a policy filter should do silently.
        Some(false) => 0,
        // Never drop traffic because parsing failed.
        None => i64::from(len),
    }
}

fn try_skfilter(ctx: &SkBuffContext) -> Option<bool> {
    let cfg = SKFILTER_CONFIG.get(0)?;

    if let Some(stats) = cpu_stats(&SKFILTER_STATS) {
        stats.seen += 1;
    }

    // A socket filter attached to an AF_INET TCP socket has `skb->data`
    // pointing at the **TCP header**, not the IP header. `load_relative` with
    // `BPF_HDR_START_NET` makes the offset relative to the network header, so
    // the same parsing works for TCP sockets, raw IP sockets, and packet
    // sockets alike.
    let ip: Ipv4Hdr = load_relative(ctx, 0)?;
    if ip.ver_ihl >> 4 != 4 {
        return Some(true);
    }

    if ip.protocol != IPPROTO_TCP {
        if let Some(stats) = cpu_stats(&SKFILTER_STATS) {
            stats.non_tcp += 1;
        }
        return Some(true);
    }

    let ihl = ip.ihl();
    if ihl < 20 {
        return Some(true);
    }
    let tcp: TcpHdr = load_relative(ctx, ihl as u32)?;

    // Only gate connection setup. Dropping non-SYN packets from a
    // non-allowlisted source would also break established connections and
    // ICMP error delivery.
    if !tcp.is_syn() || tcp.is_ack() {
        if let Some(stats) = cpu_stats(&SKFILTER_STATS) {
            stats.other += 1;
        }
        return Some(true);
    }

    if let Some(stats) = cpu_stats(&SKFILTER_STATS) {
        stats.syn += 1;
    }

    if cfg.enforce == 0 {
        if let Some(stats) = cpu_stats(&SKFILTER_STATS) {
            stats.allowed_syn += 1;
        }
        return Some(true);
    }

    if SKFILTER_ALLOWED.get_ptr(&ip.saddr).is_some() {
        if let Some(stats) = cpu_stats(&SKFILTER_STATS) {
            stats.allowed_syn += 1;
        }
        Some(true)
    } else {
        if let Some(stats) = cpu_stats(&SKFILTER_STATS) {
            stats.dropped_syn += 1;
        }
        Some(false)
    }
}

/// Reads a fixed-size header relative to the network header.
///
/// `skb->data` differs by socket type; `bpf_skb_load_bytes_relative` with
/// `BPF_HDR_START_NET` is the only stable way to reach the IP header from a
/// socket filter attached to a TCP socket.
#[inline(always)]
fn load_relative<T>(ctx: &SkBuffContext, offset: u32) -> Option<T> {
    let mut value = core::mem::MaybeUninit::<T>::uninit();
    // SAFETY: `ctx.as_ptr()` is the kernel-provided `__sk_buff *`; the
    // destination is a local, correctly sized buffer.
    let rc = unsafe {
        bpf_skb_load_bytes_relative(
            ctx.as_ptr().cast(),
            offset,
            value.as_mut_ptr().cast(),
            core::mem::size_of::<T>() as u32,
            BPF_HDR_START_NET,
        )
    };
    if rc == 0 {
        // SAFETY: the helper wrote exactly `size_of::<T>()` bytes on success.
        Some(unsafe { value.assume_init() })
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// cgroup/connect4: egress port allowlist
// ---------------------------------------------------------------------------

#[map(name = "connect4_config")]
static CONNECT4_CONFIG: Array<Connect4Config> = Array::with_max_entries(1, 0);

#[map(name = "connect4_stats")]
static CONNECT4_STATS: PerCpuArray<Connect4Stats> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "connect4_events")]
static CONNECT4_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[cgroup_sock_addr(connect4)]
pub fn connect4_guard(ctx: SockAddrContext) -> i32 {
    match try_connect4(&ctx) {
        // 1 = allow, 0 = deny. Failing open on an internal error is deliberate:
        // a missing config map should not silently break all egress traffic.
        Some(true) | None => 1,
        Some(false) => 0,
    }
}

fn try_connect4(ctx: &SockAddrContext) -> Option<bool> {
    let cfg = CONNECT4_CONFIG.get(0)?;
    if cfg.allow_port_count == 0 {
        return None;
    }

    // SAFETY: `sock_addr` is the kernel-provided context pointer, valid for the
    // duration of this program.
    let (family, daddr, raw_port) = unsafe {
        let addr = &*ctx.sock_addr;
        (addr.user_family, addr.user_ip4, addr.user_port)
    };

    // Only IPv4 is handled here; IPv6 falls through and is allowed.
    if family != AF_INET {
        return Some(true);
    }

    let dport = u16::from_be(raw_port as u16);
    let allowed = port_in(&cfg.allow_ports, cfg.allow_port_count, dport);

    if let Some(stats) = cpu_stats(&CONNECT4_STATS) {
        stats.connects += 1;
        if allowed {
            stats.allowed += 1;
        } else {
            stats.denied += 1;
        }
    }

    if !allowed {
        // Denied connects can be used for scanning / connection floods; sample
        // the event stream while keeping exact counters.
        if sample(16) {
            crate::emit_event!(CONNECT4_EVENTS, Connect4Event, {
                timestamp_ns: now_ns(),
                pid: ctx.pid(),
                daddr: daddr,
                dport: dport,
                allowed: 0,
                _pad: 0,
                comm: comm(ctx),
            });
        }
    }

    Some(allowed)
}

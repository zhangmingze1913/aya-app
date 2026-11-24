//! XDP firewall: ICMP echo suppression and per-source-IP rate limiting.
//!
//! # Design
//!
//! * The program runs in the driver's receive path when the NIC supports
//!   native XDP, otherwise in generic (SKB) mode. It never allocates an SKB for
//!   dropped packets, which is what makes XDP cheap for DDoS filtering.
//! * Configuration is a one-element `Array` written by userspace before
//!   attach. Arrays are lookup-only after creation, so no locking is needed.
//! * The fixed-window rate-limit state lives in an `LruHashMap` keyed by the
//!   source IPv4 address. LRU semantics bound memory under spoofed-source
//!   floods; exact accounting is sacrificed for predictable memory use.
//! * Counters are `PerCpuArray` values so the hot path performs no atomics.
//!   Userspace sums them every second.
//! * Detailed drop events are sampled to avoid turning the ring buffer into
//!   the next bottleneck under attack.

use aya_app_common::{XDP_DROP_ICMP, XDP_DROP_RATE, XdpConfig, XdpEvent, XdpStats};
use aya_ebpf::{
    bindings::xdp_action::{XDP_DROP, XDP_PASS},
    macros::{map, xdp},
    maps::{Array, LruHashMap, PerCpuArray, RingBuf},
    programs::XdpContext,
};

use crate::{
    net::{
        ETH_HDR_LEN, ETH_P_8021AD, ETH_P_8021Q, ETH_P_IP, EthHdr, ICMP_ECHO_REQUEST, IPPROTO_ICMP,
        IcmpHdr, Ipv4Hdr, VLAN_HDR_LEN,
    },
    utils::{cpu_stats, now_ns, sample},
};

/// One configuration entry (index 0).
#[map(name = "xdp_config")]
static XDP_CONFIG: Array<XdpConfig> = Array::with_max_entries(1, 0);

/// Per-CPU counters, indexed 0.
#[map(name = "xdp_stats")]
static XDP_STATS: PerCpuArray<XdpStats> = PerCpuArray::with_max_entries(1, 0);

/// Number of source-IP rate-limit entries. 16k is the lab default; raise this
/// for large-scale DDoS filtering (the XDP object is the only one that pays).
const XDP_RATE_ENTRIES: u32 = 16_384;

/// One fixed-window rate-limit entry per source IPv4 address.
#[map(name = "xdp_rate")]
static XDP_RATE: LruHashMap<u32, RateState> = LruHashMap::with_max_entries(XDP_RATE_ENTRIES, 0);

/// Sampled drop events. 256 KiB is a power-of-two multiple of the page size.
#[map(name = "xdp_events")]
static XDP_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

/// Fixed-window rate-limit state.
///
/// A true token bucket would need a float or a 64-bit multiply/divide per
/// packet. A one-second fixed window is cheaper, is precise enough for DDoS
/// mitigation, and has an obvious worst case: up to 2x the configured rate
/// around a window boundary. This trade-off is documented in the scenario doc.
#[repr(C)]
#[derive(Clone, Copy)]
struct RateState {
    window_start_ns: u64,
    /// Packets already admitted in this window.
    count: u32,
    _pad: u32,
}

/// Parsed packet metadata needed by the firewall.
struct Parsed {
    saddr: u32,
    daddr: u32,
    protocol: u8,
    /// Offset of the L4 header, relative to the start of the frame.
    l4_offset: usize,
    /// Total frame length in bytes.
    len: u32,
}

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    // XDP programs must always return an action. Parse failures are treated as
    // "pass" so that a malformed frame cannot be used to black-hole traffic.
    match try_xdp_firewall(&ctx) {
        Ok(action) => action,
        Err(_) => XDP_PASS,
    }
}

fn try_xdp_firewall(ctx: &XdpContext) -> Result<u32, u32> {
    let cfg = XDP_CONFIG.get(0).ok_or(XDP_PASS)?;
    let parsed = match parse_packet(ctx) {
        Some(parsed) => parsed,
        None => {
            count_passed(ctx);
            return Ok(XDP_PASS);
        }
    };

    // Restrict both protections to the configured destination prefix. A zero
    // `protected_ip` means "every destination".
    let mask = if cfg.protected_mask == 0 {
        u32::MAX
    } else {
        cfg.protected_mask
    };
    let in_scope = cfg.protected_ip == 0 || (parsed.daddr & mask) == (cfg.protected_ip & mask);
    if !in_scope {
        count_passed(ctx);
        return Ok(XDP_PASS);
    }

    // Only drop echo requests. Dropping all ICMP would break PMTUD and
    // traceroute, which is almost never what an operator wants.
    if cfg.block_icmp != 0 && parsed.protocol == IPPROTO_ICMP {
        if let Some(icmp) = read_icmp(ctx, parsed.l4_offset) {
            if icmp.icmp_type == ICMP_ECHO_REQUEST {
                count_dropped_icmp(parsed.len);
                emit_drop(cfg, &parsed, XDP_DROP_ICMP);
                return Ok(XDP_DROP);
            }
        }
    }

    if cfg.rate_limit_pps > 0 && !allow_packet(parsed.saddr, cfg.rate_limit_pps) {
        count_dropped_rate(parsed.len);
        emit_drop(cfg, &parsed, XDP_DROP_RATE);
        return Ok(XDP_DROP);
    }

    count_passed(ctx);
    Ok(XDP_PASS)
}

/// Parses Ethernet (with up to two VLAN tags) and IPv4.
///
/// Returns `None` for non-IPv4 traffic, truncated frames, invalid IHL, and
/// non-initial fragments. The caller passes those frames unchanged.
fn parse_packet(ctx: &XdpContext) -> Option<Parsed> {
    let len = ctx.data_end().saturating_sub(ctx.data()) as u32;
    if len < ETH_HDR_LEN as u32 {
        return None;
    }

    // SAFETY: `read_packet` bounds-checks against data..data_end. Copying out
    // with `read_unaligned` avoids creating references to unaligned packet
    // memory, which is UB in Rust even though BPF can often do such loads.
    let eth: EthHdr = unsafe { read_packet(ctx, 0)? };
    let mut l3 = ETH_HDR_LEN;
    let mut ether_type = u16::from_be(eth.ether_type);
    let mut tags = 0u8;

    // Support 802.1Q and 802.1ad (QinQ). More than two tags is unusual and
    // treated as non-IP by falling through to the `ETH_P_IP` check.
    while (ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD) && tags < 2 {
        let vlan = unsafe { read_packet::<crate::net::VlanHdr>(ctx, l3)? };
        ether_type = u16::from_be(vlan.ether_type);
        l3 += VLAN_HDR_LEN;
        tags += 1;
    }

    if ether_type != ETH_P_IP {
        return None;
    }

    let ip: Ipv4Hdr = unsafe { read_packet(ctx, l3)? };
    if ip.ver_ihl >> 4 != 4 {
        return None;
    }
    let ihl = ip.ihl();
    if ihl < 20 || !ip.is_first_fragment() {
        return None;
    }

    let l4_offset = l3.checked_add(ihl)?;
    // The L4 header may be beyond the captured frame (e.g. an IPv4 header with
    // options at the end of a tiny frame); only the protocol number is needed
    // for rate limiting, so do not require the L4 header to be present.
    Some(Parsed {
        saddr: ip.saddr,
        daddr: ip.daddr,
        protocol: ip.protocol,
        l4_offset,
        len,
    })
}

/// Reads the ICMP header if it is present in the linear frame.
#[inline(always)]
fn read_icmp(ctx: &XdpContext, offset: usize) -> Option<IcmpHdr> {
    unsafe { read_packet(ctx, offset) }
}

/// Bounds-checked packet read.
///
/// # Safety
///
/// The returned value is copied out; no reference to packet memory escapes.
/// Arithmetic uses `checked_add` so a malicious offset cannot wrap.
#[inline(always)]
unsafe fn read_packet<T>(ctx: &XdpContext, offset: usize) -> Option<T> {
    let start = ctx.data();
    let end = ctx.data_end();
    let ptr = start.checked_add(offset)?;
    let ptr_end = ptr.checked_add(core::mem::size_of::<T>())?;
    if ptr_end > end {
        return None;
    }
    Some(unsafe { core::ptr::read_unaligned(ptr as *const T) })
}

/// Fixed-window admission control for one source address.
fn allow_packet(saddr: u32, limit: u32) -> bool {
    let now = now_ns();

    if let Some(state) = XDP_RATE.get_ptr_mut(&saddr) {
        // SAFETY: `get_ptr_mut` returns a valid pointer into the map value.
        // The pointer is not held across an insert/remove, so the LRU cannot
        // evict it while we are using it.
        let window_start = unsafe { (*state).window_start_ns };
        let count = unsafe { (*state).count };

        if now.wrapping_sub(window_start) >= 1_000_000_000 {
            // New one-second window.
            unsafe {
                (*state).window_start_ns = now;
                (*state).count = 1;
            }
            return true;
        }

        if count >= limit {
            return false;
        }

        unsafe { (*state).count = count + 1 };
        return true;
    }

    // First packet from this source. If insertion fails (map full), fail open:
    // dropping legitimate traffic because the accounting map is exhausted is
    // worse than missing a rate-limit decision.
    let fresh = RateState {
        window_start_ns: now,
        count: 1,
        _pad: 0,
    };
    let _ = XDP_RATE.insert(&saddr, &fresh, 0);
    true
}

fn count_passed(ctx: &XdpContext) {
    let len = ctx.data_end().saturating_sub(ctx.data()) as u64;
    if let Some(stats) = cpu_stats(&XDP_STATS) {
        stats.passed += 1;
        stats.passed_bytes += len;
    }
}

fn count_dropped_icmp(len: u32) {
    if let Some(stats) = cpu_stats(&XDP_STATS) {
        stats.dropped_icmp += 1;
        stats.dropped_bytes += u64::from(len);
    }
}

fn count_dropped_rate(len: u32) {
    if let Some(stats) = cpu_stats(&XDP_STATS) {
        stats.dropped_rate += 1;
        stats.dropped_bytes += u64::from(len);
    }
}

fn emit_drop(cfg: &XdpConfig, parsed: &Parsed, reason: u32) {
    if !sample(cfg.event_sample) {
        return;
    }
    // A full ring buffer drops the event; the counters remain exact, so this is
    // a visibility loss rather than a policy failure.
    crate::emit_event!(XDP_EVENTS, XdpEvent, {
        timestamp_ns: now_ns(),
        saddr: parsed.saddr,
        daddr: parsed.daddr,
        reason: reason,
        pkt_len: parsed.len,
    });
}

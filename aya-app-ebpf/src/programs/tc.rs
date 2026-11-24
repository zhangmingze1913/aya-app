//! TC classifier: P2P drop and video prioritisation.
//!
//! The program is attached to the `clsact` ingress or egress hook. It parses
//! Ethernet (including VLAN) and IPv4/TCP/UDP, drops configured P2P
//! destination ports, and rewrites `skb->mark` for video ports.
//!
//! Marking rather than writing `skb->priority` is intentional:
//!
//! * `skb->priority` is not exposed by aya's `TcContext` (it is a context field
//!   with arch-specific write restrictions);
//! * `skb->mark` is writable from TC and can be consumed by a standard
//!   `tc filter ... fw` rule, which selects a `prio` qdisc band.
//!
//! The userspace command prints the exact `tc` commands to install that rule.

use aya_app_common::{TC_ACTION_DROP, TcConfig, TcEvent, TcStats};
use aya_ebpf::{
    bindings::{TC_ACT_OK, TC_ACT_SHOT},
    macros::{classifier, map},
    maps::{Array, PerCpuArray, RingBuf},
    programs::TcContext,
};

use crate::{
    net::{
        ETH_HDR_LEN, ETH_P_8021AD, ETH_P_8021Q, ETH_P_IP, EthHdr, IPPROTO_TCP, IPPROTO_UDP,
        Ipv4Hdr, TcpHdr, UdpHdr, VLAN_HDR_LEN, VlanHdr,
    },
    utils::{cpu_stats, now_ns, port_in, sample},
};

#[map(name = "tc_config")]
static TC_CONFIG: Array<TcConfig> = Array::with_max_entries(1, 0);

#[map(name = "tc_stats")]
static TC_STATS: PerCpuArray<TcStats> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "tc_events")]
static TC_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

struct Parsed {
    saddr: u32,
    daddr: u32,
    protocol: u8,
    sport: u16,
    dport: u16,
    len: u32,
}

#[classifier]
pub fn tc_qos(ctx: TcContext) -> i32 {
    match try_tc_qos(&ctx) {
        Ok(action) => action,
        // A malformed frame must not be dropped by a QoS policy.
        Err(_) => TC_ACT_OK as i32,
    }
}

fn try_tc_qos(ctx: &TcContext) -> Result<i32, i32> {
    let cfg = TC_CONFIG.get(0).ok_or(TC_ACT_OK as i32)?;
    let parsed = match parse_packet(ctx) {
        Some(parsed) => parsed,
        None => {
            count_passed(ctx.len());
            return Ok(TC_ACT_OK as i32);
        }
    };

    if parsed.protocol == IPPROTO_TCP || parsed.protocol == IPPROTO_UDP {
        if port_in(&cfg.drop_ports, cfg.drop_port_count, parsed.dport) {
            count_dropped(parsed.len);
            emit_drop(cfg, &parsed);
            return Ok(TC_ACT_SHOT as i32);
        }

        if port_in(&cfg.video_ports, cfg.video_port_count, parsed.dport) {
            // The mark is consumed by a `tc filter ... fw` rule installed by
            // userspace. It does not itself change queueing.
            ctx.set_mark(cfg.video_mark);
            if let Some(stats) = cpu_stats(&TC_STATS) {
                stats.prioritized += 1;
            }
        }
    }

    count_passed(parsed.len);
    Ok(TC_ACT_OK as i32)
}

/// Parses L2/L3/L4 headers using `bpf_skb_load_bytes` through `TcContext::load`.
///
/// `load` handles non-linear skbs (the helper copies from the skb), which is
/// why it is preferred over direct `data`/`data_end` access in TC. The cost is
/// a few helper calls per packet; header-only parsing stays within budget.
fn parse_packet(ctx: &TcContext) -> Option<Parsed> {
    let len = ctx.len();

    let eth: EthHdr = ctx.load(0).ok()?;
    let mut l3 = ETH_HDR_LEN;
    let mut ether_type = u16::from_be(eth.ether_type);
    let mut tags = 0u8;

    while (ether_type == ETH_P_8021Q || ether_type == ETH_P_8021AD) && tags < 2 {
        let vlan: VlanHdr = ctx.load(l3).ok()?;
        ether_type = u16::from_be(vlan.ether_type);
        l3 += VLAN_HDR_LEN;
        tags += 1;
    }

    if ether_type != ETH_P_IP {
        return None;
    }

    let ip: Ipv4Hdr = ctx.load(l3).ok()?;
    if ip.ver_ihl >> 4 != 4 || ip.ihl() < 20 || !ip.is_first_fragment() {
        return None;
    }

    let l4_offset = l3.checked_add(ip.ihl())?;
    let (sport, dport) = match ip.protocol {
        IPPROTO_TCP => {
            let tcp: TcpHdr = ctx.load(l4_offset).ok()?;
            (tcp.source(), tcp.dest())
        }
        IPPROTO_UDP => {
            let udp: UdpHdr = ctx.load(l4_offset).ok()?;
            (udp.source(), udp.dest())
        }
        _ => (0, 0),
    };

    Some(Parsed {
        saddr: ip.saddr,
        daddr: ip.daddr,
        protocol: ip.protocol,
        sport,
        dport,
        len,
    })
}

fn count_passed(len: u32) {
    if let Some(stats) = cpu_stats(&TC_STATS) {
        stats.passed += 1;
        stats.passed_bytes += u64::from(len);
    }
}

fn count_dropped(len: u32) {
    if let Some(stats) = cpu_stats(&TC_STATS) {
        stats.dropped_p2p += 1;
        stats.dropped_bytes += u64::from(len);
    }
}

fn emit_drop(cfg: &TcConfig, parsed: &Parsed) {
    if !sample(cfg.event_sample) {
        return;
    }
    crate::emit_event!(TC_EVENTS, TcEvent, {
        timestamp_ns: now_ns(),
        saddr: parsed.saddr,
        daddr: parsed.daddr,
        sport: parsed.sport,
        dport: parsed.dport,
        action: TC_ACTION_DROP,
        pkt_len: parsed.len,
        _pad: 0,
    });
}

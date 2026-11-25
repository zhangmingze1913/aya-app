//! cgroup_skb ingress/egress port filter.
//!
//! Unlike TC, cgroup_skb runs for every socket owned by the cgroup, regardless
//! of the interface. `__sk_buff.data` starts at the network header here (there
//! is no Ethernet header), so IPv4 parsing begins at offset 0.

use aya_app_common::{CGSKB_ACTION_DROP, CgSkbConfig, CgSkbEvent, CgSkbStats};
use aya_ebpf::{
    macros::{cgroup_skb, map},
    maps::{Array, PerCpuArray, RingBuf},
    programs::SkBuffContext,
};

use crate::{
    net::{ETH_P_IP, IPPROTO_TCP, IPPROTO_UDP, Ipv4Ports, L4Ports},
    utils::{cpu_stats, now_ns, sample},
};

#[map(name = "cgskb_config")]
static CGSKB_CONFIG: Array<CgSkbConfig> = Array::with_max_entries(1, 0);

#[map(name = "cgskb_stats")]
static CGSKB_STATS: PerCpuArray<CgSkbStats> = PerCpuArray::with_max_entries(1, 0);

#[map(name = "cgskb_events")]
static CGSKB_EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[cgroup_skb(ingress)]
pub fn cgskb_ingress(ctx: SkBuffContext) -> i32 {
    handle(&ctx).unwrap_or(0)
}

#[cgroup_skb(egress)]
pub fn cgskb_egress(ctx: SkBuffContext) -> i32 {
    handle(&ctx).unwrap_or(0)
}

fn handle(ctx: &SkBuffContext) -> Result<i32, ()> {
    let cfg = CGSKB_CONFIG.get(0).ok_or(())?;
    let protocol = u16::from_be(ctx.skb.protocol() as u16);
    if protocol != 0 && protocol != ETH_P_IP {
        count_passed(ctx);
        return Ok(0);
    }

    // cgroup_skb data starts at the IPv4 header. Read the IPv4 prefix and the
    // first four L4 bytes together: for the common IHL == 20 packet this is a
    // single helper call instead of separate IP/TCP/UDP loads.
    let header: Ipv4Ports = ctx.load(0).map_err(|_| ())?;
    let ip = header.ip;
    if ip.ver_ihl >> 4 != 4 {
        count_passed(ctx);
        return Ok(0);
    }
    let ihl = ip.ihl();
    if ihl < 20 || !ip.is_first_fragment() {
        count_passed(ctx);
        return Ok(0);
    }

    let ports = match ip.protocol {
        IPPROTO_TCP | IPPROTO_UDP => {
            if ihl == 20 {
                header.ports
            } else {
                ctx.load::<L4Ports>(ihl).map_err(|_| ())?
            }
        }
        _ => {
            count_passed(ctx);
            return Ok(0);
        }
    };
    let (sport, dport) = (ports.source(), ports.dest());

    if cfg.block_port != 0 && dport == cfg.block_port {
        if let Some(stats) = cpu_stats(&CGSKB_STATS) {
            stats.dropped += 1;
            stats.dropped_bytes += u64::from(ctx.len());
        }
        if sample(cfg.event_sample) {
            crate::emit_event!(CGSKB_EVENTS, CgSkbEvent, {
                timestamp_ns: now_ns(),
                saddr: ip.saddr,
                daddr: ip.daddr,
                sport: sport,
                dport: dport,
                pkt_len: ctx.len(),
                action: CGSKB_ACTION_DROP,
                // cgroup_skb on kernel 6.6 does not allow the current-task
                // helper set (`bpf_get_current_pid_tgid`,
                // `bpf_get_current_comm`), so process metadata is left zero.
                // The address/port fields still identify the dropped flow.
                pid: 0,
                tgid: 0,
                _pad: 0,
                comm: [0u8; aya_app_common::TASK_COMM_LEN],
            });
        }
        // cgroup_skb return convention: 1 = drop, 0 = allow.
        // This is different from cgroup_sysctl (1 = allow).
        return Ok(1);
    }

    count_passed(ctx);
    Ok(0)
}

#[inline(always)]
fn count_passed(ctx: &SkBuffContext) {
    if let Some(stats) = cpu_stats(&CGSKB_STATS) {
        stats.passed += 1;
        stats.passed_bytes += u64::from(ctx.len());
    }
}

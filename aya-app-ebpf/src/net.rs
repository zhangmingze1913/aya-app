//! Minimal packet header definitions.
//!
//! We deliberately avoid `network-types` or generated bindings here: the
//! layouts below are stable UAPI structs and keeping them local makes the
//! verifier's view of the code obvious. All multi-byte fields are read in
//! network order and converted explicitly at the call site.

/// Ethernet header length.
pub const ETH_HDR_LEN: usize = 14;
/// One 802.1Q VLAN tag is four bytes (TCI + inner EtherType).
pub const VLAN_HDR_LEN: usize = 4;

pub const ETH_P_IP: u16 = 0x0800;
pub const ETH_P_8021Q: u16 = 0x8100;
pub const ETH_P_8021AD: u16 = 0x88a8;

pub const IPPROTO_ICMP: u8 = 1;
pub const IPPROTO_TCP: u8 = 6;
pub const IPPROTO_UDP: u8 = 17;

/// ICMP echo request type.
pub const ICMP_ECHO_REQUEST: u8 = 8;

pub const TCP_FLAG_SYN: u16 = 0x02;
pub const TCP_FLAG_ACK: u16 = 0x10;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct EthHdr {
    pub dst: [u8; 6],
    pub src: [u8; 6],
    pub ether_type: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VlanHdr {
    pub tci: u16,
    pub ether_type: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ipv4Hdr {
    pub ver_ihl: u8,
    pub tos: u8,
    pub tot_len: u16,
    pub id: u16,
    pub frag_off: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub check: u16,
    pub saddr: u32,
    pub daddr: u32,
}

impl Ipv4Hdr {
    /// Header length in bytes. Callers must reject values below 20.
    #[inline(always)]
    pub fn ihl(&self) -> usize {
        ((self.ver_ihl & 0x0f) as usize) * 4
    }

    /// True when this is the first fragment (offset 0).
    #[inline(always)]
    pub fn is_first_fragment(&self) -> bool {
        (u16::from_be(self.frag_off) & 0x1fff) == 0
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct TcpHdr {
    pub sport: u16,
    pub dport: u16,
    pub seq: u32,
    pub ack_seq: u32,
    pub data_off_flags: u16,
    pub window: u16,
    pub check: u16,
    pub urg: u16,
}

impl TcpHdr {
    #[inline(always)]
    pub fn source(&self) -> u16 {
        u16::from_be(self.sport)
    }

    #[inline(always)]
    pub fn dest(&self) -> u16 {
        u16::from_be(self.dport)
    }

    /// TCP flags (the low 12 bits of the data-offset/flags word).
    #[inline(always)]
    pub fn flags(&self) -> u16 {
        u16::from_be(self.data_off_flags) & 0x0fff
    }

    #[inline(always)]
    pub fn is_syn(&self) -> bool {
        self.flags() & TCP_FLAG_SYN != 0
    }

    #[inline(always)]
    pub fn is_ack(&self) -> bool {
        self.flags() & TCP_FLAG_ACK != 0
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct UdpHdr {
    pub sport: u16,
    pub dport: u16,
    pub len: u16,
    pub check: u16,
}

impl UdpHdr {
    #[inline(always)]
    pub fn source(&self) -> u16 {
        u16::from_be(self.sport)
    }

    #[inline(always)]
    pub fn dest(&self) -> u16 {
        u16::from_be(self.dport)
    }
}

/// The first four bytes shared by TCP, UDP and other L4 headers: ports.
///
/// `cgroup_skb` only needs the ports, so loading this 4-byte struct avoids
/// copying a full TCP header (20 bytes) on every packet.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct L4Ports {
    pub sport: u16,
    pub dport: u16,
}

impl L4Ports {
    #[inline(always)]
    pub fn source(&self) -> u16 {
        u16::from_be(self.sport)
    }

    #[inline(always)]
    pub fn dest(&self) -> u16 {
        u16::from_be(self.dport)
    }
}

/// IPv4 header plus the first four L4 bytes in one helper read.
///
/// The common IPv4 case (IHL == 20) needs only one `bpf_skb_load_bytes` call:
/// both the addresses and the ports are available in this 24-byte prefix.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ipv4Ports {
    pub ip: Ipv4Hdr,
    pub ports: L4Ports,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IcmpHdr {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub rest: u32,
}

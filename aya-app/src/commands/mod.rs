//! One module per scenario. Each `run` function owns the full lifecycle:
//! load maps, configure, attach, stream events, print statistics, detach.

pub mod cgroup_skb;
pub mod cgroup_sysctl;
pub mod fentry;
pub mod kprobe;
pub mod lsm;
pub mod raw_tp;
pub mod runner;
pub mod socket;
pub mod tc;
pub mod tracepoint;
pub mod uprobe;
pub mod xdp;

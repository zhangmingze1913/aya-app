//! `aya-app socket-filter` — SOCK_OPS, classic socket filter, cgroup/connect4.
//!
//! All three subcommands share the socket-only object but load/attach different
//! programs. They intentionally demonstrate the difference between observing
//! (SOCK_OPS) and enforcing (SYN filter / connect4).
//!
//! * `sockops` is read-only telemetry (plus optional state callbacks);
//! * `skfilter` enforces an inbound SYN source-IP allowlist;
//! * `connect4` enforces an outbound destination-port allowlist.
//!
//! Read `docs/scenarios/06-socket-filter.md` before attaching `connect4` to a
//! cgroup that contains your shell: a bad allowlist can break networking for
//! every process in that subtree.

use std::{fs::File, path::Path};

use anyhow::Context as _;
use aya::programs::links::CgroupAttachMode;

use crate::cli::{CgroupModeArg, SocketFilterCommand};

mod connect4;
mod skfilter;
mod sockops;

pub async fn run(command: SocketFilterCommand) -> anyhow::Result<()> {
    match command {
        SocketFilterCommand::Sockops(args) => sockops::run(args).await,
        SocketFilterCommand::Skfilter(args) => skfilter::run(args).await,
        SocketFilterCommand::Connect4(args) => connect4::run(args).await,
    }
}

/// Maps the CLI attach policy to the kernel link mode.
fn attach_mode(mode: CgroupModeArg) -> CgroupAttachMode {
    match mode {
        CgroupModeArg::Single => CgroupAttachMode::Single,
        CgroupModeArg::Multi => CgroupAttachMode::AllowMultiple,
    }
}

/// Opens a cgroup v2 directory for `SockOps`/`CgroupSockAddr` attach.
fn open_cgroup(path: &Path) -> anyhow::Result<File> {
    File::open(path).with_context(|| {
        format!(
            "failed to open cgroup {}; is cgroup v2 mounted?",
            path.display()
        )
    })
}

//! Loading the embedded eBPF objects and process-level setup.
//!
//! `aya-app/build.rs` cross-compiles `aya-app-ebpf` for
//! `bpfel-unknown-none`, copies the 11 scenario objects into `OUT_DIR` as
//! `aya-app-<scenario>`, and `include_bytes_aligned!` embeds them into the
//! userspace binary. Deployment is still a single file, but a command only
//! loads its own object.
//!
//! For IDE/type-check-only workflows on a machine without `bpf-linker`:
//!
//! ```text
//! AYA_BUILD_SKIP=1 cargo check --target x86_64-unknown-linux-gnu
//! ```
//!
//! The build script then writes placeholder objects; the resulting binary is
//! not runnable (loading it fails), but all Rust code is checked.

use std::ffi::CString;

use anyhow::Context as _;
use aya::Ebpf;

/// One embedded eBPF object. Each object contains only its scenario's programs
/// and maps; the build script compiles one bin per scenario.
#[derive(Clone, Copy, Debug)]
pub enum Object {
    Xdp,
    Tc,
    Kprobe,
    Uprobe,
    Tracepoint,
    Socket,
    Lsm,
    Fentry,
    RawTp,
    CgroupSkb,
    CgroupSysctl,
}

impl Object {
    const fn name(self) -> &'static str {
        match self {
            Self::Xdp => "xdp",
            Self::Tc => "tc",
            Self::Kprobe => "kprobe",
            Self::Uprobe => "uprobe",
            Self::Tracepoint => "tracepoint",
            Self::Socket => "socket",
            Self::Lsm => "lsm",
            Self::Fentry => "fentry",
            Self::RawTp => "raw_tp",
            Self::CgroupSkb => "cgroup_skb",
            Self::CgroupSysctl => "cgroup_sysctl",
        }
    }
}

/// Loads the scenario-specific embedded object and creates only its maps.
///
/// Each match arm embeds a separate ELF file. Keeping the selection here means
/// a command never accidentally loads another scenario's maps or programs.
pub fn load(object: Object) -> anyhow::Result<Ebpf> {
    let bytes: &[u8] = match object {
        Object::Xdp => aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/aya-app-xdp")),
        Object::Tc => aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/aya-app-tc")),
        Object::Kprobe => aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/aya-app-kprobe")),
        Object::Uprobe => aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/aya-app-uprobe")),
        Object::Tracepoint => {
            aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/aya-app-tracepoint"))
        }
        Object::Socket => aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/aya-app-socket")),
        Object::Lsm => aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/aya-app-lsm")),
        Object::Fentry => aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/aya-app-fentry")),
        Object::RawTp => aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/aya-app-raw_tp")),
        Object::CgroupSkb => {
            aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/aya-app-cgroup_skb"))
        }
        Object::CgroupSysctl => {
            aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/aya-app-cgroup_sysctl"))
        }
    };
    Ebpf::load(bytes).with_context(|| {
        format!(
            "failed to load the embedded `{}` eBPF object; if it was built with AYA_BUILD_SKIP, rebuild on Linux",
            object.name()
        )
    })
}

/// Raises `RLIMIT_MEMLOCK` for kernels that still account BPF maps against it.
///
/// Kernels with memcg-based accounting (5.11+) do not need this, but older
/// distribution kernels do. Failure is non-fatal: the subsequent BPF syscall
/// will produce the authoritative error.
pub fn raise_memlock_limit() {
    let limit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    // SAFETY: `setrlimit` reads the provided struct and does not retain it.
    let rc = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) };
    if rc != 0 {
        log::debug!(
            "failed to raise RLIMIT_MEMLOCK: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Converts a user-supplied interface name into a `CString` for aya's
/// `NetworkInterface` conversions, which take `&CStr`.
pub fn cstring(value: &str) -> anyhow::Result<CString> {
    CString::new(value).with_context(|| format!("string contains NUL: {value:?}"))
}

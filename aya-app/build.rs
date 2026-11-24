//! Builds one eBPF object per scenario and embeds all of them into the CLI.
//!
//! `aya-app-ebpf` has one `[[bin]]` per scenario. A single `aya-build --bins`
//! invocation compiles all 11 bins, avoiding 11 separate Cargo feature builds.
//! Each bin includes only its scenario module, so each ELF contains only that
//! scenario's programs and maps.
//!
//! `AYA_BUILD_SKIP=1` (or `AYA_APP_SKIP_EBPF_BUILD=1`) writes placeholders for
//! every object; `cargo check` can then type-check userspace without a BPF
//! toolchain.

use std::{env, fs, path::PathBuf, process::Command};

use anyhow::{Context as _, bail};

const EBPF_PACKAGE: &str = "aya-app-ebpf";

/// Bin name = object suffix. The CLI embeds `OUT_DIR/aya-app-<name>`.
const OBJECTS: &[&str] = &[
    "xdp",
    "tc",
    "kprobe",
    "uprobe",
    "tracepoint",
    "socket",
    "lsm",
    "fentry",
    "raw_tp",
    "cgroup_skb",
    "cgroup_sysctl",
];

fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-changed=../aya-app-ebpf/src");
    println!("cargo:rerun-if-changed=../aya-app-ebpf/Cargo.toml");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=AYA_BUILD_SKIP");
    println!("cargo:rerun-if-env-changed=AYA_APP_SKIP_EBPF_BUILD");

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").context("OUT_DIR is not set")?);

    if skip_requested() {
        for name in OBJECTS {
            let path = object_path(&out_dir, name);
            fs::write(&path, format!("aya-app: eBPF build skipped ({name})")).with_context(
                || format!("failed to write placeholder object {}", path.display()),
            )?;
        }
        println!(
            "cargo:warning=AYA_BUILD_SKIP is set; wrote placeholder eBPF objects. \
             The resulting binary is only useful for type-checking."
        );
        return Ok(());
    }

    check_bpf_linker()?;

    let manifest_dir =
        PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR is not set")?);
    let ebpf_root = manifest_dir.join("../aya-app-ebpf");
    let ebpf_root = ebpf_root.canonicalize().with_context(|| {
        format!(
            "failed to resolve eBPF package directory {}",
            ebpf_root.display()
        )
    })?;
    let ebpf_root = ebpf_root
        .to_str()
        .context("eBPF package path is not valid UTF-8")?;

    let package = aya_build::Package {
        name: EBPF_PACKAGE,
        root_dir: ebpf_root,
        no_default_features: false,
        features: &[],
    };
    aya_build::build_ebpf([package], aya_build::Toolchain::default())
        .context("failed to build the eBPF bins")?;

    for name in OBJECTS {
        let built = out_dir.join(name);
        if !built.is_file() {
            bail!(
                "aya-build completed but bin `{name}` was not produced at {}",
                built.display()
            );
        }
        let dst = object_path(&out_dir, name);
        fs::copy(&built, &dst)
            .with_context(|| format!("failed to copy {} to {}", built.display(), dst.display()))?;
    }

    Ok(())
}

fn object_path(out_dir: &std::path::Path, name: &str) -> PathBuf {
    out_dir.join(format!("aya-app-{name}"))
}

/// Both names are accepted so users can use either aya-build's own switch or a
/// project-specific one.
fn skip_requested() -> bool {
    for key in ["AYA_BUILD_SKIP", "AYA_APP_SKIP_EBPF_BUILD"] {
        if let Some(value) = env::var_os(key) {
            let value = value.to_string_lossy();
            if value == "1" || value.eq_ignore_ascii_case("true") {
                return true;
            }
        }
    }
    false
}

/// Gives a much better error than the linker's "No such file or directory".
fn check_bpf_linker() -> anyhow::Result<()> {
    let output = Command::new("bpf-linker")
        .arg("--version")
        .output()
        .context(
            "bpf-linker not found. Install it with `cargo install bpf-linker` \
             (and ensure it is on PATH for build scripts)",
        )?;
    if !output.status.success() {
        bail!(
            "bpf-linker --version failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(())
}

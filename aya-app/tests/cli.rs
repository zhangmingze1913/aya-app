//! CLI contract tests that do not require BPF privileges.
//!
//! These tests run the real `aya-app` binary via `CARGO_BIN_EXE_aya-app`:
//! only clap parsing, help/version text and early argument validation.
//! Attach/verifier paths remain covered by `scripts/test-linux-runtime.sh`.

use std::process::Command;

fn cmd() -> Command {
    Command::new(env!("CARGO_BIN_EXE_aya-app"))
}

#[test]
fn help_lists_all_scenarios() {
    let output = cmd().arg("--help").output().expect("run --help");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    for command in [
        "xdp",
        "tc",
        "kprobe",
        "uprobe",
        "tracepoint",
        "socket-filter",
        "lsm",
        "fentry",
        "raw-tp",
        "cgroup-skb",
        "cgroup-sysctl",
    ] {
        assert!(
            text.contains(command),
            "missing `{command}` in --help:\n{text}"
        );
    }
}

#[test]
fn version_matches_package() {
    let output = cmd().arg("--version").output().expect("run --version");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    let expected = format!("aya-app {}", env!("CARGO_PKG_VERSION"));
    assert!(
        text.trim().starts_with(&expected),
        "unexpected version output: {text:?}"
    );
}

#[test]
fn missing_subcommand_is_a_usage_error() {
    let output = cmd().output().expect("run without subcommand");
    assert!(!output.status.success());
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("Usage"), "expected clap usage error:\n{text}");
}

#[test]
fn invalid_prefix_length_is_rejected_before_attach() {
    let output = cmd()
        .args(["xdp", "--protected-prefix-len", "33"])
        .output()
        .expect("run invalid prefix");
    assert!(!output.status.success());
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(
        text.contains("33") || text.to_lowercase().contains("invalid"),
        "expected clap validation error:\n{text}"
    );
}

#[test]
fn connect4_requires_allow_port_before_touching_cgroup() {
    let output = cmd()
        .args(["socket-filter", "connect4", "--cgroup", "/sys/fs/cgroup"])
        .output()
        .expect("run connect4 without --allow-port");
    assert!(!output.status.success());
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(
        text.contains("--allow-port"),
        "expected allow-port validation error:\n{text}"
    );
}

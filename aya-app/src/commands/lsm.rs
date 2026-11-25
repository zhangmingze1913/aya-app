//! `aya-app lsm` — global LSM `socket_connect` port policy.
//!
//! Lifecycle: load the LSM-only object, write the blocked-port/UID config,
//! resolve `bpf_lsm_socket_connect` in kernel BTF, load the sleepable program,
//! attach the raw-tracepoint link, then run the shared loop.
//!
//! This command demonstrates an enforcing LSM hook. Unlike `cgroup/connect4`,
//! the LSM hook is **not scoped to a cgroup**: by default it applies to every
//! process on the host. Use `--uid` to restrict the blast radius, and choose a
//! port that is safe to block in your environment.

use anyhow::{Context as _, bail};
use aya::{
    Btf,
    maps::{Array, MapData, PerCpuArray},
    programs::Lsm,
};
use aya_app_common::{LSM_ACTION_DENY, LsmConfig, LsmEvent, LsmStats, MAX_PORTS};

use crate::{
    cli::LsmArgs,
    commands::runner,
    ebpf,
    event::EventStream,
    format::{banner, comm, ipv4, stats_header, uptime},
    stats::{sum_percpu, take_percpu},
};

pub async fn run(args: LsmArgs) -> anyhow::Result<()> {
    if args.block_port.is_empty() {
        bail!("at least one --block-port is required");
    }
    if args.block_port.len() > MAX_PORTS {
        bail!(
            "at most {MAX_PORTS} --block-port values are supported (got {})",
            args.block_port.len()
        );
    }
    if args.block_port.contains(&0) {
        bail!("port numbers must be in 1..=65535");
    }

    let mut config = LsmConfig::default();
    for (slot, port) in config.blocked_ports.iter_mut().zip(args.block_port.iter()) {
        *slot = *port;
    }
    config.blocked_port_count = args.block_port.len() as u32;
    config.target_uid = args.uid.unwrap_or(0);
    config.enforce_uid = u32::from(args.uid.is_some());
    config.event_sample = args.event_sample;

    let mut bpf = ebpf::load(ebpf::Object::Lsm)?;

    {
        let map = bpf
            .map_mut("lsm_config")
            .context("map `lsm_config` missing from the eBPF object")?;
        let mut config_map = Array::<_, LsmConfig>::try_from(map)
            .context("`lsm_config` is not an Array<LsmConfig>")?;
        config_map
            .set(0, &config, 0)
            .context("failed to write lsm_config")?;
    }

    // LSM programs are BTF-typed: aya resolves `bpf_lsm_socket_connect` in the
    // kernel BTF and passes its BTF id when loading.
    let btf = Btf::from_sys_fs().context(
        "failed to load /sys/kernel/btf/vmlinux; BPF LSM requires CONFIG_DEBUG_INFO_BTF",
    )?;

    {
        let program: &mut Lsm = bpf
            .program_mut("lsm_socket_connect")
            .context("program `lsm_socket_connect` missing")?
            .try_into()
            .context("`lsm_socket_connect` is not an LSM program")?;
        program.load("socket_connect", &btf).context(
            "failed to load the LSM program; check CONFIG_BPF_LSM and that `bpf` is in the lsm= boot parameter",
        )?;
        program
            .attach()
            .context("failed to attach the LSM program")?;
    }

    let stats = take_percpu::<LsmStats>(&mut bpf, "lsm_stats")?;
    let events = EventStream::take(&mut bpf, "lsm_events")?;

    banner(
        "LSM socket_connect policy",
        &[
            "hook          : socket_connect".to_string(),
            format!("blocked ports : {:?}", args.block_port),
            format!(
                "uid filter    : {}",
                match args.uid {
                    Some(uid) => format!("uid {uid}"),
                    None => "all processes".to_string(),
                }
            ),
            format!("event sample  : 1/{}", args.event_sample),
            "警告          : LSM 是全局钩子；共享主机上请用 --uid 缩小作用域".to_string(),
        ],
    );
    println!(
        "Ctrl-C 退出。测试：先 `nc -l 127.0.0.1 <blocked-port>`，再 `nc 127.0.0.1 <blocked-port>`。"
    );
    println!("被拒绝的 connect() 会返回 EPERM（Operation not permitted）。");

    runner::run_events(
        stats,
        events,
        args.stats_interval,
        print_event,
        read_stats,
        print_stats,
        "LSM 程序",
    )
    .await?;

    drop(bpf);
    println!("已退出。");
    Ok(())
}

fn read_stats(map: &PerCpuArray<MapData, LsmStats>) -> anyhow::Result<LsmStats> {
    sum_percpu(map, |total, value| {
        total.connects += value.connects;
        total.allowed += value.allowed;
        total.denied += value.denied;
    })
}

fn print_event(event: LsmEvent) {
    if event.action == LSM_ACTION_DENY {
        crate::eventln!(
            "[lsm-deny] t={} pid={} uid={} comm={} dst={}:{}",
            uptime(event.timestamp_ns),
            event.pid,
            event.uid,
            comm(&event.comm),
            ipv4(event.daddr),
            event.dport
        );
    }
}

fn print_stats(now: &LsmStats, previous: &LsmStats, interval_secs: u64) {
    let dt = interval_secs.max(1) as f64;
    let d_connects = now.connects.saturating_sub(previous.connects);
    let d_denied = now.denied.saturating_sub(previous.denied);

    stats_header("LSM stats");
    println!(
        "connects : {:>12}  ({:>10.1}/s)",
        now.connects,
        d_connects as f64 / dt
    );
    println!(
        "allowed  : {:>12}    denied: {:>12} ({:.1} deny/s)",
        now.allowed,
        now.denied,
        d_denied as f64 / dt
    );
}

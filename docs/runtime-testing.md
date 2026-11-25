# 特权运行时测试

普通 CI 只做构建、类型检查、ABI 测试和用户态单测；真正的 eBPF attach 需要
root/`CAP_BPF` 和目标内核。运行时测试分为两层。

## 1. 本地冒烟

```bash
cargo build -p aya-app --release

# 建议在一次性 VM 或 netns 中
sudo -E AYA_APP=./target/release/aya-app \
    bash scripts/test-linux-runtime.sh
```

脚本覆盖：

- XDP `lo` ICMP drop；
- kprobe openat；
- raw tracepoint；
- fentry（仅当 function tracer 可用）；
- LSM（仅当 `lsm=` 包含 `bpf`）。

不适用的内核能力会记为 SKIP，不会伪造 PASS。

## 2. GitHub Actions

`.github/workflows/runtime.yml` 是 **workflow_dispatch**，要求自托管 runner：

```text
runs-on: [self-hosted, linux, x64, ebpf]
```

runner 必须是隔离的 Linux VM/主机，并允许 root eBPF。不要在共享生产主机上运行。

## 3. netns 建议

XDP/TC 场景建议在独立 netns 中运行，避免污染宿主：

```bash
sudo ip netns add aya-test
sudo ip netns exec aya-test ip link set lo up
sudo ip netns exec aya-test ./target/release/aya-app xdp \
    --iface lo --mode skb --block-icmp
```

cgroup 场景使用专用子树：

```bash
sudo mkdir -p /sys/fs/cgroup/aya-test
```

结束后删除子 cgroup，确认没有残留 `bpftool link`。

## 4. 安全边界

- 不要在根 cgroup 上测试 `connect4`/LSM；
- 不要在管理网卡上测试 native XDP；
- 测试结束执行 `sudo bpftool link show`，确认没有残留；
- QEMU TCG 时间只用于同环境对比。

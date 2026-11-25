# GitHub 发布就绪评估

评估日期：2026-11-25  
评估对象：`aya-app` 0.1.0（11 场景、Linux-only eBPF 工具）

## 0. 结论

**`v0.1.0` 已正式发布，发布流程完成。**

- 正式 Release: <https://github.com/zhangmingze1913/aya-app/releases/tag/v0.1.0>
- RC Release: <https://github.com/zhangmingze1913/aya-app/releases/tag/v0.1.0-rc.1>
- Release workflow (v0.1.0): <https://github.com/zhangmingze1913/aya-app/actions/runs/45572017707>
- tag CI (v0.1.0): <https://github.com/zhangmingze1913/aya-app/actions/runs/45572017769>

## 1. 发布资产

| 资产 | 大小 | SHA-256（GitHub digest） |
|---|---:|---|
| `aya-app` | 3,864,672 B | `f88b5dd888bb97d3a2eea3883d32ef075aff2d1ce7a7ee48202036370f073325` |
| `aya-app-demo` | 425,304 B | `d722c42fc2fda7c2a5db8c3e687b26a8bcd184fd152e71f3dc9621c44cbbfeaa` |
| `SHA256SUMS` | 153 B | `25a887072ec67589b92e0633c69a30141793bd6e3381e08736cc1490a51fb5e5` |

RC 的 `aya-app` 已在 QEMU/Alpine 6.18 上验证：

- `--version` → `aya-app 0.1.0`；
- XDP `lo` ICMP drop；
- kprobe openat 事件/延迟。

## 2. 验证证据

| 项目 | 状态 |
|---|---|
| `cargo fmt --check` | ✅ |
| `cargo clippy --all-targets -D warnings` | ✅ |
| `cargo test -p aya-app-common` | ✅ 3 passed |
| `cargo +nightly check -p aya-app-ebpf --bins` | ✅ |
| `cargo doc -p aya-app --no-deps` | ✅ |
| 静态 musl CLI | ✅ |
| 11 个 eBPF object 嵌入 | ✅ |
| Linux 运行时矩阵 | ✅ 6.1 / 6.6 / 6.18 |
| GitHub Actions Ubuntu 22.04 | ✅ success |
| GitHub Actions Ubuntu 24.04 | ✅ success |
| Release workflow v0.1.0-rc.1 | ✅ success |
| Release workflow v0.1.0 | ✅ success |
| `SHA256SUMS` | ✅ RC 本地校验通过 |

## 3. 发布文件

```text
LICENSE-MIT
LICENSE-APACHE
CHANGELOG.md
CONTRIBUTING.md
SECURITY.md
.github/workflows/ci.yml
.github/workflows/release.yml
.github/ISSUE_TEMPLATE/bug_report.md
.github/ISSUE_TEMPLATE/feature_request.md
.github/PULL_REQUEST_TEMPLATE.md
```

## 4. 使用

```bash
sudo ./aya-app --help
```

完整环境、构建和 11 场景命令见 [USAGE.md](../USAGE.md)；关键函数见
[code-reference.md](code-reference.md)。

## 5. 后续 P2

本轮已补充并验证：

- CLI 集成测试：`aya-app/tests/cli.rs`（CI 中运行）；
- `deny.toml` + CI `cargo-deny` job；本地 `cargo deny check` 通过；
- Release 安装脚本：`scripts/install.sh`，已在 Alpine 3.24 上安装
  `v0.1.0` 并校验 SHA-256；
- 非 x86_64 说明：`docs/architectures.md`；
- 特权运行时：`scripts/test-linux-runtime.sh` + `runtime.yml`；
  在 Alpine 6.18 上得到 `pass=5 fail=0`（XDP/kprobe/raw-tp/fentry/LSM）；
- QEMU TCG 数据已标注为非生产基准。

仍可继续：

- 非 x86_64 实机验证；
- 特权 runner/netns 的自动化矩阵；
- 安装脚本的包管理器支持。

## 6. 最终判断

```text
代码质量：      可发布
文档完整度：    可发布
CI 证据：       Linux 22.04/24.04 成功
RC 发布：       成功
正式发布：      v0.1.0 成功
合规/元数据：   已补齐
Release 自动化：已验证
```

**状态：已完成 GitHub 发布规划。**

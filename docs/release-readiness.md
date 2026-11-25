# GitHub 发布就绪评估

评估日期：2026-11-25  
评估对象：`aya-app` 0.1.0（11 场景、Linux-only eBPF 工具）

## 0. 结论

**已通过 GitHub CI，达到发布 `v0.1.0-rc.1` 的条件。**

本地和远端已完成：

- `LICENSE-MIT`、`LICENSE-APACHE`；
- 真实 `repository`、git remote、首次开源提交；
- Linux CI（Ubuntu 22.04/24.04）实际运行并成功；
- CI badge、CHANGELOG、CONTRIBUTING、SECURITY；
- Issue/PR 模板；
- tag 触发的 Release workflow（静态 CLI + demo + SHA256SUMS）。

剩余是发布动作本身：

1. 打 `v0.1.0-rc.1` tag；
2. 等待 Release workflow 产出附件；
3. 验证附件/校验和；
4. 视结果打正式 `v0.1.0`。

## 1. 验证证据

| 项目 | 状态 |
|---|---|
| `cargo fmt --check` | ✅ |
| `cargo clippy --all-targets -D warnings` | ✅ |
| `cargo test -p aya-app-common` | ✅ 3 passed |
| `cargo +nightly check -p aya-app-ebpf --bins` | ✅ |
| `cargo doc -p aya-app --no-deps` | ✅ |
| 静态 musl CLI | ✅ 约 4.41 MB |
| 11 个 eBPF object 嵌入 | ✅ |
| Linux 运行时矩阵 | ✅ 6.1 / 6.6 / 6.18 |
| GitHub Actions Ubuntu 22.04 | ✅ success |
| GitHub Actions Ubuntu 24.04 | ✅ success |

CI run:

```text
https://github.com/zhangmingze1913/aya-app/actions/runs/45570301600
```

## 2. 已补齐的发布文件

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

## 3. 发布步骤

### 3.1 发布 RC

```bash
git tag -a v0.1.0-rc.1 -m "aya-app 0.1.0-rc.1"
git push origin v0.1.0-rc.1
```

`release.yml` 会：

- 构建静态 `x86_64-unknown-linux-musl` CLI；
- 构建 `aya-app-demo`；
- 生成 `SHA256SUMS`；
- 创建 GitHub Pre-release。

### 3.2 验证 RC

```bash
sha256sum -c SHA256SUMS
./aya-app --version
./aya-app --help
```

在测试机按 [USAGE.md](../USAGE.md) 跑至少：

- XDP `lo` 冒烟；
- kprobe；
- fentry 或 tracepoint；
- 一个 cgroup 场景。

### 3.3 发布正式版

```bash
git tag -a v0.1.0 -m "aya-app 0.1.0"
git push origin v0.1.0
```

## 4. P2：后续增强

- 增加 CLI 集成测试（`--help`、参数校验、错误信息）；
- `cargo audit` / `cargo deny`；
- Release 安装脚本；
- 非 x86_64 架构说明；
- 特权 runner/netns 上的自动运行时 CI；
- QEMU TCG 数据明确标注为非生产基准。

## 5. 最终判断

```text
代码质量：      可发布
文档完整度：    可发布
CI 证据：       Ubuntu 22.04/24.04 成功
合规/元数据：   已补齐
Release 自动化： 已配置
```

**当前状态：可以打 `v0.1.0-rc.1`。**

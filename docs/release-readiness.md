# GitHub 发布就绪评估

评估日期：2026-11-25  
评估对象：`aya-app` 0.1.0（11 场景、Linux-only eBPF 工具）

## 0. 结论

**已达到并完成 `v0.1.0-rc.1` 发布；RC 资产和 Release workflow 均验证通过。**

RC：

- Release: <https://github.com/zhangmingze1913/aya-app/releases/tag/v0.1.0-rc.1>
- 资产：`aya-app`、`aya-app-demo`、`SHA256SUMS`
- Release workflow: <https://github.com/zhangmingze1913/aya-app/actions/runs/45570765284>
- tag CI: <https://github.com/zhangmingze1913/aya-app/actions/runs/45570765258>

下一步是打正式 `v0.1.0`。

## 1. 验证证据

| 项目 | 状态 |
|---|---|
| `cargo fmt --check` | ✅ |
| `cargo clippy --all-targets -D warnings` | ✅ |
| `cargo test -p aya-app-common` | ✅ 3 passed |
| `cargo +nightly check -p aya-app-ebpf --bins` | ✅ |
| `cargo doc -p aya-app --no-deps` | ✅ |
| 静态 musl CLI | ✅ 约 4.41 MB（release 资产 strip 后 3.86 MB） |
| 11 个 eBPF object 嵌入 | ✅ |
| Linux 运行时矩阵 | ✅ 6.1 / 6.6 / 6.18 |
| GitHub Actions Ubuntu 22.04 | ✅ success |
| GitHub Actions Ubuntu 24.04 | ✅ success |
| Release workflow | ✅ success |
| SHA256SUMS 校验 | ✅ 本地下载校验通过 |
| RC 二进制 Linux 冒烟 | ✅ `--version` / XDP / kprobe |

## 2. 发布文件

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

## 3. RC 资产

```text
aya-app        3,864,672 B
aya-app-demo     425,304 B
SHA256SUMS           153 B
```

`SHA256SUMS` 已在本地下载并核对 `aya-app` 哈希。

## 4. 正式版发布

```bash
git tag -a v0.1.0 -m "aya-app 0.1.0"
git push origin v0.1.0
```

Release workflow 会创建正式 Release；`contains(github.ref_name, 'rc')`
对 `v0.1.0` 为 false，因此不是 prerelease。

## 5. 发布后验证

```bash
sha256sum -c SHA256SUMS
./aya-app --version
./aya-app --help
```

再按 [USAGE.md](../USAGE.md) 在目标 Linux 上做 XDP/kprobe/cgroup 冒烟。

## 6. 后续 P2

- CLI 集成测试（`--help`、参数校验、错误信息）；
- `cargo audit` / `cargo deny`；
- Release 安装脚本；
- 非 x86_64 架构说明；
- 特权 runner/netns 运行时 CI；
- QEMU TCG 数据标注为非生产基准。

## 7. 最终判断

```text
代码质量：      可发布
文档完整度：    可发布
CI 证据：       Linux 22.04/24.04 成功
RC 发布：       成功
合规/元数据：   已补齐
Release 自动化：已配置
```

**当前状态：可以发布正式 `v0.1.0`。**

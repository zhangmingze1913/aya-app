# GitHub 发布就绪评估

评估日期：2026-11-25  
评估对象：`aya-app` 0.1.0（11 场景、Linux-only eBPF 工具）

## 0. 结论

**本地代码、许可证和仓库元数据已达到 release candidate 水平；还不能直接打正式
`v0.1.0`，因为 CI 尚未在 GitHub 上实际运行，且本轮修复尚未提交。**

当前本地已处理：

- 添加 `LICENSE-MIT`、`LICENSE-APACHE`；
- `Cargo.toml` 的 `repository` 改为真实仓库
  `https://github.com/zhangmingze1913/aya-app`；
- 恢复 `.github/workflows/ci.yml`（Ubuntu 22.04/24.04）；
- 代码、文档、构建脚本保持可检查状态。

发布前仍需：

1. 审阅许可证版权人并提交；
2. `git add/commit` 本轮修复；
3. 推送后让 GitHub Actions 实际跑绿；
4. 打 `v0.1.0-rc.1`，再视结果打 `v0.1.0`。

## 1. 已达标的项目

| 项目 | 状态 | 证据 |
|---|---|---|
| `cargo fmt --check` | ✅ | 全部 workspace |
| `cargo clippy --all-targets -D warnings` | ✅ | 用户态 |
| `cargo test -p aya-app-common` | ✅ | 3 个 ABI 测试 |
| `cargo +nightly check -p aya-app-ebpf --bins` | ✅ | 11 个场景 bin |
| `cargo doc -p aya-app --no-deps` | ✅ | rustdoc 可生成 |
| 静态 musl CLI | ✅ | 约 4.41 MB |
| 11 个真实 object 嵌入 | ✅ | `strings` 验证程序名 |
| Linux 运行时 | ✅ | QEMU 6.1/6.6/6.18 矩阵 |
| 文档 | ✅ | README/USAGE/design/development/code-reference |
| 测试脚本 | ✅ | `scripts/test-linux.sh` |
| Windows 测试残留 | ✅ 已删除 | 只保留 Linux |
| 许可证文件 | ✅ 本地已添加 | MIT + Apache-2.0 |
| repository 元数据 | ✅ 已改为真实地址 | `zhangmingze1913/aya-app` |
| git 仓库/remote | ✅ | origin 已配置 |

## 2. 发布前必须确认

### 2.1 许可证版权人

已添加：

```text
LICENSE-MIT     Copyright (c) 2026 aya-app contributors
LICENSE-APACHE  Apache License 2.0
```

“aya-app contributors”是通用署名。若仓库属于个人/公司，请改成明确的版权主体，
再提交。

### 2.2 提交本轮修复

当前工作区有未提交的修改：

```bash
git status
git add Cargo.toml LICENSE-MIT LICENSE-APACHE .github/workflows/ci.yml docs/
git commit -m "Prepare initial GitHub release"
```

### 2.3 CI 实际运行

`.github/workflows/ci.yml` 已恢复，但尚未在 GitHub 上执行。发布前确认：

- Ubuntu 22.04 runner 仍可用；
- 静态 `bpf-linker` 下载成功；
- `FULL_BUILD=1 scripts/test-linux.sh` 全绿；
- 11 个 bin 在 Ubuntu 24.04 上完成最终链接。

### 2.4 推送/tag

```bash
git push origin main
git tag -a v0.1.0-rc.1 -m "aya-app 0.1.0-rc.1"
git push origin v0.1.0-rc.1
```

## 3. P1：建议发布前处理

| 项目 | 建议 |
|---|---|
| `CHANGELOG.md` | 增加 0.1.0 场景/修复/已知限制 |
| `CONTRIBUTING.md` | 构建、测试、提交规范 |
| `SECURITY.md` | eBPF/root 工具的安全报告渠道 |
| Issue/PR 模板 | `.github/ISSUE_TEMPLATE/`、`PULL_REQUEST_TEMPLATE.md` |
| CI 缓存 | 减少 Ubuntu 矩阵构建时间 |
| bpf-linker 校验 | 下载后加 SHA-256 |
| Release workflow | tag 触发，产出静态 CLI + SHA-256 |
| `publish = false` | 避免误发 crates.io（含 path 依赖） |

## 4. P2：后续增强

- 增加 CLI 集成测试（`--help`、参数校验、错误信息）；
- 增加 `cargo audit` / `cargo deny`；
- 增加 GitHub Release 的安装脚本；
- 补充非 x86_64 架构说明；
- 运行时 CI 使用特权 runner/自托管 runner + netns；
- QEMU TCG 数据标注为非生产基准。

## 5. 发布检查清单

```text
[x] LICENSE-MIT / LICENSE-APACHE 存在
[x] Cargo.toml repository 指向真实仓库
[x] 本地 git remote 已配置
[ ] 审阅版权人并提交本轮修复
[ ] git push origin main
[ ] GitHub Actions 全绿（Ubuntu 22.04/24.04）
[ ] CHANGELOG.md 写好 0.1.0
[ ] tag v0.1.0-rc.1
[ ] 验证 tag 构建 / Release 附件
[ ] 打正式 v0.1.0
```

## 6. 最终判断

```text
代码质量：      可发布候选
文档完整度：    可发布候选
测试覆盖：      中上（构建/ABI/多内核运行时；缺自动化运行时 CI）
合规/元数据：   本地已补齐，待提交
CI 证据：       未运行
```

**建议：提交当前修复，推送后先发布 `v0.1.0-rc.1`；CI 全绿再发 `v0.1.0`。**

# GitHub 发布就绪评估

评估日期：2026-11-24  
评估对象：`aya-app` 0.1.0（11 场景、Linux-only eBPF 工具）

## 0. 结论

**代码与文档达到 release candidate 水平，但当前还不能直接公开 `v0.1.0`。**

主要原因不是代码质量，而是发布合规与仓库元数据：

1. `Cargo.toml`/README 声明 `MIT OR Apache-2.0`，但仓库没有 LICENSE 文件；
2. `repository = "https://github.com/example/aya-app"` 是占位 URL；
3. 当前目录不是 git 仓库，无法直接 push/tag；
4. CI 尚未在 GitHub 上实际跑过，也没有 release artifact/checksum 流程。

完成下面的 P0 后，可以作为 `v0.1.0-rc.1` 或 `v0.1.0` 发布。

## 1. 已达标的项目

| 项目 | 状态 | 证据 |
|---|---|---|
| `cargo fmt --check` | ✅ | 全部 workspace |
| `cargo clippy --all-targets -D warnings` | ✅ | 用户态 |
| `cargo test -p aya-app-common` | ✅ | 3 个 ABI 测试 |
| `cargo +nightly check -p aya-app-ebpf --bins` | ✅ | 11 个场景 bin |
| 静态 musl CLI | ✅ | 约 4.41 MB |
| 11 个真实 object 嵌入 | ✅ | `strings` 验证程序名 |
| Linux 运行时 | ✅ | QEMU 6.1/6.6/6.18 矩阵 |
| 文档 | ✅ | README/USAGE/design/development/code-reference |
| 测试脚本 | ✅ | `scripts/test-linux.sh` |
| Windows 测试残留 | ✅ 已删除 | 只保留 Linux |
| `.gitignore` | ✅ | target/object/IDE |

## 2. P0：发布前必须处理

### 2.1 LICENSE 文件

当前：

```toml
license = "MIT OR Apache-2.0"
```

README 也写了同样内容，但仓库根目录没有：

```text
LICENSE-MIT
LICENSE-APACHE
```

必须：

- 添加完整的 MIT 和 Apache-2.0 文本；或
- 二选一，并同步修改 `Cargo.toml`/README。

这是法律合规问题，不能用 README 一句话替代。

### 2.2 repository URL

当前：

```toml
repository = "https://github.com/example/aya-app"
```

必须替换为真实仓库地址，并同步：

- README badge / clone URL；
- Cargo.toml 的 `repository`；
- 可选 `homepage`；
- CI badge（如果加）。

### 2.3 git 仓库与首次提交

当前目录没有 `.git`：

```text
fatal: not a git repository
```

发布前：

```bash
git init
git add .
git commit -m "Initial aya-app 0.1.0"
git branch -M main
git remote add origin <真实仓库 URL>
git push -u origin main
```

### 2.4 CI 实际运行

`.github/workflows/ci.yml` 已配置 Ubuntu 22.04/24.04，但尚未在 GitHub 上执行。
发布前至少确认：

- Ubuntu 22.04 runner 仍可用；
- 静态 `bpf-linker` 下载成功；
- `FULL_BUILD=1 scripts/test-linux.sh` 全绿；
- `ubuntu-24.04` 上 11 个 bin 都能链接。

## 3. P1：建议发布前处理

| 项目 | 建议 |
|---|---|
| `CHANGELOG.md` | 增加 0.1.0 场景/Bugfix/已知限制 |
| `CONTRIBUTING.md` | 构建、测试、提交规范、DCO/CLA 选择 |
| `SECURITY.md` | eBPF/root 工具的安全报告渠道 |
| Issue/PR 模板 | `.github/ISSUE_TEMPLATE/`、`PULL_REQUEST_TEMPLATE.md` |
| CI 权限 | `permissions: contents: read` |
| CI 缓存 | `Swatinem/rust-cache` 或 cargo cache |
| bpf-linker 校验 | 下载后加 SHA-256 校验 |
| Release workflow | tag 触发，产出静态 CLI + SHA-256 |
| `publish = false` | 避免误发 crates.io（当前含 path 依赖） |
| 版本策略 | `0.1.0-rc.1` → `0.1.0` |

## 4. P2：后续增强

- 增加 CLI 集成测试（`--help`/参数校验/错误信息）；
- 增加 `cargo audit` / `cargo deny`；
- 增加 GitHub Release 的 `install.sh`；
- 补充非 x86_64 架构说明；
- 运行时 CI 使用特权 runner/自托管 runner + netns；
- 文档中的 QEMU TCG 数据标注为非生产基准。

## 5. 发布检查清单

```text
[ ] LICENSE-MIT / LICENSE-APACHE 存在
[ ] Cargo.toml repository 指向真实仓库
[ ] README clone URL / badge 更新
[ ] git init + 首次提交 + remote
[ ] GitHub Actions 全绿
[ ] CHANGELOG.md 写好 0.1.0
[ ] tag v0.1.0-rc.1 或 v0.1.0
[ ] Release 附件包含静态 CLI + SHA-256
[ ] README 标注 Linux-only、root/权限、已知限制
```

## 6. 最终判断

```text
代码质量：      可发布候选
文档完整度：    可发布候选
测试覆盖：      中上（构建/ABI/多内核运行时；缺自动化运行时 CI）
合规/元数据：   未达发布门槛
```

**建议：先完成 P0，再打 `v0.1.0-rc.1`；不要直接把当前目录作为正式 release 发布。**

# Codex 项目配置

## Git 提交信息

- 使用已配置的 `origin` remote。
- 使用当前仓库的本地 Git identity；不要把个人提交身份写入 tracked 文件。

## 提交流程

提交到 GitHub 时使用仓库本地配置，无需再次询问。

## 分支收口规则

- `v0.9-neutron-agent` 是本功能线唯一开发和交付分支；所有功能、修复、测试和文档都直接提交到该分支。
- 默认只比较本地 `v0.9-neutron-agent` 与 `origin/v0.9-neutron-agent`，每次开发前先确认工作区干净并同步远端。
- 禁止为本功能线创建新的 `codex/*`、stacked、兄弟功能分支或独立交付 PR；只有用户明确要求例外时才能创建。
- 禁止用临时 worktree 形成另一条开发方向；已有分支合入 `v0.9-neutron-agent` 并通过 CI 后必须停止使用并清理。
- 没有现场环境时，现场证据必须记录为 `deferred/pending`，不得伪造为通过；允许将其设为生产启用门槛，但代码合并时必须保持相关能力默认关闭并保留未验证状态。

## 编译规则

- **禁止本地编译**：不要在本地运行 `cargo build`、`cargo check` 等编译命令
- 代码修改完成后直接 commit + push 到 GitHub，由 GitHub Actions CI 负责编译验证
- 如果 CI 失败，根据 CI 日志修复问题

## 多会话并行协作规则（2026-08-15 起）

同一工作目录可能同时有多个 agent 会话开发同一分支（当前：Batch 3 修复线与
Phase B 可解释性计数器线）。所有会话必须遵守：

1. **工作树瞬时干净**：每个逻辑改动完成后立即 commit + push，不把未提交修改
   留在工作树里跨消息/跨轮次；开始新改动前先 `git fetch origin &&
   git pull --ff-only` 并确认 `git status` 干净。
2. **只做加法，不重写历史**：禁止 `git reset --hard`、force push、
   `git checkout` 覆盖他人改动、rebase 已推送的提交。push 被拒
   （non-fast-forward）时先 pull --ff-only 再 push。
3. **文件所有权**：动文件前先 `git log --oneline -5 -- <file>` 看对方是否在途。
   两个会话避免同时编辑同一文件；共享文件（如 `ci/check_neutron_stage1.py`）
   只做追加式修改。当前分工：Batch 3 会话负责 backlog 与 remediation 设计文档
   的闭合记录；Phase B 会话负责 counters 相关代码与自身 spec。
4. **CI 单门归属**：分支只有一个 CI 门，运行失败先按提交哈希归属
   （`gh run list` + `gh run view <id> --log-failed`）。失败来自对方在途提交时，
   **不要修改对方的文件**，等对方修复后重跑自己的验证；自己的 RED/GREEN 证据
   必须来自日志中自己的测试名。
5. **验证重跑**：自己的验证被对方 broken 提交染红时，等分支转绿后用
   `gh workflow run build.yml --ref v0.9-neutron-agent`（workflow_dispatch 默认
   强制 Rust 构建）重跑一次，并以该运行的日志作为证据。

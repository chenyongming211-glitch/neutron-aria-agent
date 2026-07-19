# Codex 项目配置

## Git 提交信息

- Remote: git@github.com:chenyongming211-glitch/aria-firewall.git
- 用户名: netmouser
- 邮箱: chenyongming211@gmail.com

## 提交流程

提交到 GitHub 时自动使用以上信息，无需再次询问。

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

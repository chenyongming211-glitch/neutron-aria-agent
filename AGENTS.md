# Codex 项目配置

## Git 提交信息

- Remote: git@github.com:chenyongming211-glitch/aria-firewall.git
- 用户名: netmouser
- 邮箱: chenyongming211@gmail.com

## 提交流程

提交到 GitHub 时自动使用以上信息，无需再次询问。

## 分支收口规则

- 同一修复链只能有一个活跃集成分支和一个交付 PR，后续批次必须从该集成分支继续，禁止从主分支创建包含重叠代码的兄弟分支。
- 临时 worktree 只用于隔离编辑，不得形成第二套实现方向；完成后必须合回唯一集成分支，再开始下一批工作。
- 主分支前进时，在唯一集成分支上同步最新基线并重新跑 exact-head CI，不得用新的平行分支规避冲突。
- 旧 PR 或旧分支只有在统一 PR 已证明完整包含其提交且 CI 通过后，才能标记 superseded 或删除。
- 没有现场环境时，现场证据必须记录为 `deferred/pending`，不得伪造为通过；允许将其设为生产启用门槛，但代码合并时必须保持相关能力默认关闭并保留未验证状态。

## 编译规则

- **禁止本地编译**：不要在本地运行 `cargo build`、`cargo check` 等编译命令
- 代码修改完成后直接 commit + push 到 GitHub，由 GitHub Actions CI 负责编译验证
- 如果 CI 失败，根据 CI 日志修复问题

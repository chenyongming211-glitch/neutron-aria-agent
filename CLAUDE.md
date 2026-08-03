# Claude Code 项目配置

## Git 提交信息

- 使用已配置的 `origin` remote。
- 使用当前仓库的本地 Git identity；不要把个人提交身份写入 tracked 文件。

## 提交流程

提交到 GitHub 时使用仓库本地配置，无需再次询问。

## 编译规则

- **禁止本地编译**：不要在本地运行 `cargo build`、`cargo check` 等编译命令
- 代码修改完成后直接 commit + push 到 GitHub，由 GitHub Actions CI 负责编译验证
- 如果 CI 失败，根据 CI 日志修复问题

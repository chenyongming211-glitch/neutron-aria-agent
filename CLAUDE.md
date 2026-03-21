# Claude Code 项目配置

## Git 提交信息

- Remote: git@github.com:chenyongming211-glitch/aria-firewall.git
- 用户名: netmouser
- 邮箱: chenyongming211@gmail.com

## 提交流程

提交到 GitHub 时自动使用以上信息，无需再次询问。

## 编译规则

- **禁止本地编译**：不要在本地运行 `cargo build`、`cargo check` 等编译命令
- 代码修改完成后直接 commit + push 到 GitHub，由 GitHub Actions CI 负责编译验证
- 如果 CI 失败，根据 CI 日志修复问题

# Codex 项目配置

## Git 提交信息

- 使用已配置的 `origin` remote。
- 使用当前仓库的本地 Git identity；不要把个人提交身份写入 tracked 文件。

## 提交流程

提交到 GitHub 时使用仓库本地配置，无需再次询问。

## 分支收口规则

- `main` 是本项目唯一开发和交付分支；所有功能、修复、测试和文档都直接提交到该分支。
- 默认只比较本地 `main` 与 `origin/main`，每次开发前先确认工作区干净并同步远端。
- 禁止为本功能线创建新的 `codex/*`、stacked、兄弟功能分支或独立交付 PR；只有用户明确要求例外时才能创建。
- 禁止用临时 worktree 形成另一条开发方向；已有分支合入 `main` 并通过 CI 后必须停止使用并清理。
- 没有现场环境时，现场证据必须记录为 `deferred/pending`，不得伪造为通过；允许将其设为生产启用门槛，但代码合并时必须保持相关能力默认关闭并保留未验证状态。

## 编译规则

- **禁止本地编译**：不要在本地运行 `cargo build`、`cargo check` 等编译命令
- 代码修改完成后直接 commit + push 到 GitHub，由 GitHub Actions CI 负责编译验证
- 如果 CI 失败，根据 CI 日志修复问题

## eBPF 数据面产品代际约束

当前交付代际服务于低版本内核上的 IPv4/IPv6 ACL，继续使用已有的 bounded
monolithic TC 数据面。固定、版本化的 tail-call 流水线是后续产品代际的设计储备，
不作为当前 IPv6 ACL 交付前置条件。正式决策见
`docs/superpowers/specs/2026-08-16-ipv6-acl-legacy-kernel-temporary-stack-exception.md`。

- 当前代际只允许完成、修复和验证 ACL/CT/fragment 及其必要状态、统计和控制面契约；
  禁止向 monolithic TC 热路径新增或扩展 Mirror、QoS、负载均衡、DDoS、广播风暴或
  其他非 ACL 数据面能力。仓库中已存在的能力不得借本约束顺手删除或改语义。
- 当前 linked artifact 的 `tc_ingress`、`tc_egress` 最坏组合调用路径上限为 480
  verifier-charged bytes，必须保留距离 512-byte 内核硬上限至少 32 bytes 的余量。
  480 是 ACL-only 产品例外，不是可以继续消耗的普通容量预算；达到 480 后禁止用提高
  门槛、隐藏入口或删除检查的方式接纳任何新路径增长。
- 每次 eBPF 修改都必须继续分析 release linked artifact 的完整调用图；源码形状、局部
  变量大小和单函数栈不能代替组合路径测量。IPv4、IPv6、ingress、egress 都在门禁内。
- `4.18.0-553.5.1.el8_10.x86_64` 真实环境的 verifier load/attach、allow/drop 和回滚
  证据仍是可部署前置条件；GitHub 编译和 480-byte 静态报告不能冒充现场 PASS。
- 当前 IPv6 ACL 能力保持默认关闭，直到上述现场证据完成。加载或 scratch 失败继续
  fail-open，不得影响 OVS 的正常 port 转发。
- 一旦产品要求新增 Mirror、QoS、负载均衡、DDoS、广播风暴等数据面能力，必须停止
  扩展当前 monolithic artifact，先重新确认最低内核版本，再启用并复核
  `docs/superpowers/specs/2026-08-16-tail-call-datapath-architecture-design.md`。
- 静态源码字符串检查不能代替公开接口行为测试、linked artifact 检查或目标内核验证。

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
   `gh workflow run build.yml --ref main`（workflow_dispatch 默认
   强制 Rust 构建）重跑一次，并以该运行的日志作为证据。

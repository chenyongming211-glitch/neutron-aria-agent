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

## eBPF 数据面长期架构约束

本项目只维护一套长期数据面：固定、版本化的 tail-call 流水线。正式设计见
`docs/superpowers/specs/2026-08-16-tail-call-datapath-architecture-design.md`。

- `tc_ingress`、`tc_egress` 以及未来 XDP entry 只允许负责解析、接口/端口身份、
  完整上下文初始化和 tail-call 调度；禁止直接加入 ACL、CT 策略、QoS、Mirror、
  负载均衡、DDoS 或广播风暴业务逻辑。
- 新数据面功能必须声明所属 plane、hook、stage、IPv4/IPv6/non-IP 行为、
  ingress/egress 行为、失败语义、ABI、统计、升级和回滚；不能归入既有 stage 时，
  必须先完成新的架构设计和 pipeline ABI 版本升级。
- family 和 direction 在热路径程序中优先采用结构化常量；禁止在已经族化/方向化的
  程序中继续通过嵌套 helper 或临时结构传播动态 family/direction 来构造策略、CT、
  drop 或 counter key。
- 固定 program-array 槽必须全部装载真实程序或 no-op pass-through 程序；禁止用空槽
  表示功能关闭。意外 tail-call miss、stage ABI 不匹配或上下文不完整必须放行流量、
  记录降级并使 readiness 失败，不能提交 pending drop。
- 只有 FINALIZE 类终结 stage 可以正常提交 pending drop。任何修改报文的 stage 必须
  在设计中证明后续链完整，或提供 tail-call 失败时的有界 preimage/rollback；禁止
  转发半修改报文。
- 每个 attached/tail-called 程序都必须进入 linked-artifact 栈分析：448 bytes 为硬门，
  超过 416 bytes 必须架构复核；禁止提高门槛、隐藏程序或用 `inline` 注解替代测量。
  单包 tail-call 深度默认不得超过 8。
- 产品代码不保留 monolithic/tail-call 双运行模式。双 program bank 只用于同一架构的
  原子升级和回滚；部署级回滚使用上一版完整已接受制品。
- 新能力在目标 4.18 内核完成 load、行为、缺槽和回滚验证前必须默认关闭，现场证据
  只能记录为真实 PASS 或 `deferred/pending`。
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

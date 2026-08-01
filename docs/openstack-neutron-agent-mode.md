# OpenStack Neutron Agent Mode 详细方案

状态：Draft
基线分支：`v0.9.0`
目标分支：`v0.9-neutron-agent`

ACL 产品化独立 Neutron 扩展的详细设计见：[Aria ACL Neutron 独立扩展产品化设计](aria-acl-neutron-extension-product-design.md)。

> 2026-07-11 当前实现边界：本轮只交付 ACL enhancement。Python agent
> 仅接受 `managed_domains=acl`，Rust UDS capabilities 仅公布已经实现的
> `attach` 和 `acl`。QoS/Mirror 继续作为后续规划和 bug 记录存在；当前
> 配置或 UDS 请求包含这些未实现 domain 时必须明确拒绝，不能静默忽略，
> 也不能因此把 ACL 标记为 ready。

## 1. 目标与结论

### 1.1 建设目标

把 `aria-firewall` 放到 OpenStack compute node 中使用，让 OpenStack 继续以 Neutron 作为唯一网络控制入口，同时让 Aria 的 eBPF datapath 在第一阶段只承接两个 Neutron 驱动的功能模块：ACL enhancement 和 QoS。

第一阶段目标不是完整替代 OVS 的 L2 datapath，而是做 Neutron Agent Mode：

- Neutron 仍然是唯一 source of truth。
- OpenStack 用户继续通过 Neutron API、Horizon、Terraform、Heat 等入口配置网络对象。
- `neutron-aria-agent` 消费 Neutron 本 host 状态，生成本机声明式 snapshot。
- `aria-datapath` 接收 Neutron snapshot，负责本机 group、ACL、QoS、runtime status、WAL、Netlink、Pinned Maps 和 eBPF map apply。
- 第一阶段新增功能模块只有 ACL/QoS；其它已有能力代码保留，但不进入 `neutron-aria-agent`、Neutron snapshot、translator、feature flag、status domain、smoke 或 PR gate。

### 1.2 核心结论

`v0.9.0` 分支没有 `aria-controller` 中央控制面，只有本机 `aria-agent`、REST API、WAL 和 eBPF datapath。这个分支比 v0.10 控制面分支更适合做 OpenStack / Neutron agent mode。

推荐架构：

```text
OpenStack user / Horizon / Terraform
        |
        v
Neutron API / Neutron Server / ML2
        |
        | Neutron RPC + full resync + agent heartbeat
        v
neutron-aria-agent          Python Neutron adapter, compute node
        |
        | Unix socket: /run/aria/aria-agent.sock
        | PUT /api/v1/neutron/snapshot
        v
aria-datapath               Rust datapath runtime, compute node
                            runs existing aria-agent binary
        |
        | WAL + Netlink + Pinned Maps + eBPF map apply
        v
eBPF datapath               XDP / TC
```

第一阶段保留 OVS 的基础 L2 connectivity。Aria 只新增两个节点侧功能模块，不替代原有 OVS 转发：

- ACL enhancement：只消费显式 Aria ACL enhancement 输入，映射为 Aria Firewall 现有的 `group + policy` 模型；不消费 Neutron Security Group、remote group、port security 或 allowed address pairs，不作为默认转发门槛。
- QoS：对应 Neutron QoS policy。
- Group：作为 ACL、QoS 和统计归因的共同编译中间层。
- Conntrack：作为 Aria ACL 状态化、连接跟踪、fast-path 和 flow 统计的基础能力；不是 Neutron ACL mapping 输入，但状态化 ACL enhancement 需要它 ready。
- Monitoring：作为 ACL/QoS/flow/group 统计和 metrics 的基础能力。
- WAL / Netlink / Pinned Maps：作为 OpenStack 模式的必选运行时支撑能力。

除 ACL enhancement 和 QoS 之外，任何能力都不能写成第一阶段新增功能模块。Group、Conntrack、Monitoring、WAL、Netlink、Pinned Maps 只能作为支撑能力进入方案；Mirror、TCPrt、Trace、Drops、SSL、Diagnose、Service Chain、Route、NAT、L4 LB、Service 都不进入第一阶段功能交付。

### 1.3 第一阶段明确不做

第一阶段不做这些事情：

- 不引入 `aria-controller`。
- 不迁移 v0.10 Controller / RFC 体系到该分支。
- 不让用户绕过 Neutron 创建 OpenStack 网络对象。
- 不替代 OVS 的 L2 bridge、tunnel、local switching、VLAN/VXLAN/GENEVE 管理。
- 不实现 Neutron Security Group projection、remote group 展开、anti-spoof 或 port security enforcement。
- 不新增 `trace`、`drops`、`ssl`、`diagnose`、`service chain` 等功能模块，也不把它们扩成 Neutron tenant API。
- 不把 Mirror 或 TCPrt 接入 Neutron Agent Mode；Rust 既有 Mirror/TCPrt 本机能力保留，但不进入 Neutron snapshot、translator、feature flag、status domain、smoke 或 PR gate。

### 1.4 能力分类边界

当前 `aria-firewall` 代码里，很多能力在 CLI/API 上是平铺的，但 OpenStack agent mode 不能继续按“功能菜单”理解它们。后续设计和实现统一按下面分层处理：

| 分类 | 能力 | 定位 | OpenStack 暴露方式 |
| --- | --- | --- | --- |
| 基础运行能力 | tap attach、ifindex、WAL、Netlink、Pinned Maps、runtime status | 保证 eBPF runtime 可挂载、可恢复、可对账 | 必选，不作为租户 feature |
| 身份与选择器基础 | Group / address-set / port identity | ACL、QoS 和统计归因的共同输入 | 由 Neutron snapshot 投影生成，本机不能手动创建 Neutron-managed 权威 group |
| 有状态基础 | Conntrack / CT config / CT stats | ACL 状态化、连接表、fast-path 和 flow 统计的运行基础 | operator 基础配置；状态化 ACL 需要时失败必须 degraded/bypass |
| 观测基础 | Monitoring / stats / metrics | rule、flow、group、QoS 统计和 Prometheus 输出 | operator 基础配置；关闭后相关统计不可用 |
| 第一阶段功能模块 | ACL、QoS | Neutron snapshot 驱动的可开关功能面 | 只暴露这两个 feature flags |
| 非第一阶段功能 | Mirror、TCPrt、Trace、Drops、SSL、Diagnose、Service Chain | standalone/local legacy 或本机排障能力 | Rust 代码保留，但第一阶段不新增、不接入 Neutron Agent Mode |
| 后续平台能力 | Route、NAT、L4 LB、Service | IaaS 数据面扩展能力 | 不进入第一阶段 Neutron Agent Mode |

关键规则：

- `Group / Conntrack / Monitoring / WAL / Netlink / Pinned Maps` 必须有，但不是租户可配置功能。
- 第一阶段功能模块白名单只有 `acl/qos`；任何新增功能模块都必须被显式排除，不能默认跟随 Rust 现有代码进入 OpenStack scope。
- `feature_flags` 只允许表达 `acl/qos`。
- `runtime_foundations` 只允许表达 `conntrack/monitoring` 这类运行基础要求，不得表达租户 feature。
- `Mirror / TCPrt / Trace / Drops / SSL / Diagnose` 可以保留代码和本机管理员入口，但不能变成 Neutron tenant feature。
- `Route / NAT / L4 LB / Service` 不进入当前 `v0.9-neutron-agent` 第一阶段范围。
- 现有本地 CLI/API 兼容保留，但新 snapshot/status domain 不能照搬旧平铺菜单。

### 1.5 本轮方案优化落地清单

本方案以当前 `v0.9.0` 代码事实为基础。凡是 Neutron snapshot DTO、Unix socket Neutron router、Python `neutron-aria-agent`、OpenStack authority state、Neutron WAL entry 等内容，除非在源码表中明确列为现有文件，否则均为本分支待实现内容。

本轮优化统一落地为以下约束，后续开发和评审按这些约束验收。阶段 gate 只看这些约束是否被测试、CI、smoke 或文档证据证明。

日常开发先读短版合同 [Neutron Managed Domains Contract](neutron-managed-domains-contract.md)；上线启用和回滚步骤见 [OpenStack Deployment Runbook](openstack-deployment-runbook.md)。本文保留完整设计背景、阶段 gate 和详细验收。

| 分类 | 约束 |
| --- | --- |
| 范围边界 | 第一阶段新增功能模块白名单固定为 ACL enhancement 和 QoS；其它能力只能作为支撑能力或保留代码出现，不能作为功能模块、feature flag、status domain、smoke 或 PR gate |
| 范围边界 | 当前阶段固定为 OVS enhancement mode；不支持 OVN；不做 Neutron Security Group projection、remote group 展开、anti-spoof 或 port security enforcement |
| 范围边界 | ACL 正式输入源固定为独立 `aria_acl` Neutron service plugin/API/DB；`fixture` 只用于 CI/smoke；历史 tag + 本机 mapping 仅允许作为 lab/bootstrap/迁移辅助，不作为生产控制面契约；不消费 Security Group、remote group、port security 或 allowed address pairs |
| 范围边界 | Trace、Drops、SSL、Diagnose、Service Chain 等既有能力保留为 admin/operator-only，不进入 `neutron-aria-agent` schema |
| Snapshot 语义 | Snapshot request 必须有 `runtime_foundations`；`feature_flags` 只允许表达 `acl/qos` |
| Snapshot 语义 | response/status domain 顺序固定为 `runtime -> groups -> conntrack -> monitoring -> acl -> qos` |
| 状态机 | `DomainStatus` 只允许表达 `ready/degraded/blocked/not_requested`；`bypass`、`unsupported`、`ignored optional field`、`agent alive` 必须放到各自维度，不能混成一个状态字符串 |
| 状态机 | WAL 以 `intent -> apply -> commit -> status` 为准；`commit exists but status missing` 必须从校验通过的 durable commit 重建 RAM/status，不能依据旧 RAM 推进或回滚 accepted |
| 状态机 | Aria readiness 与 OVS connectivity ready 必须分离；Aria readiness=false 或 `DomainStatus=degraded` 不能自动停止 OVS 转发 |
| 运行边界 | `agent_mode = "openstack"` 是本机配置；`integration_mode = "coexist"` 是 snapshot 字段；两者不得混用 |
| 运行边界 | inert/bypass runtime 只允许提前完成物理 attach 和基础观测，不能提前启用 feature、写 accepted state 或宣称 ready |
| UDS 契约 | UDS snapshot/status/capabilities/delete 不进入 TCP OpenAPI paths，但必须进入 Local Unix API Contract 和 `neutron-uds-contract.json` |
| UDS 契约 | `neutron-uds-contract.json` 必须包含 contract version、body 上限、timeout、error code hash 和 peer auth policy |
| UDS 契约 | Python UDS client 必须实现 `get_capabilities()`，启动、重连、datapath restart 和 capability hash 变化都走同一握手路径 |
| 安全 | Unix socket 除文件权限外必须有 peer credential 校验和 audit log，且配置来源明确 |
| 控制权 | Neutron 通过 `managed_domains` 声明每个 port/instance 的 domain authority；本机 `ariactl` 对 Neutron-managed domain 的持久写入必须在 Rust/API 层返回 `LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_DOMAIN`，未被列入 `managed_domains` 的 domain 继续允许本机写入 |
| 可观测性 | 告警必须配套 runbook；accepted generation lag、ACL degraded with bypass action、WAL blocked、full resync loop、socket permission denied 都必须可报警 |
| N0.5 | N0.5-lite 是 schema freeze gate；完整 N0.5 是 N3 feature gate；PR-6A/PR-6B 是 deployment smoke gate，三类 gate 不得混用 |
| N0.5 | 发现结果必须写入 `docs/openstack-target-env-discovery.md`，没有命令、期望、实际和证据不得计为完成 |
| 性能 | 首阶段性能预算绑定固定 fixture，并在 N1/N2 固化 mock scale 输入；N6 不能重新定义输入语义 |
| 性能 | 性能预算必须配套 measurement protocol、`perf-summary.json` 和 `perf-baseline.json` |
| CI | GitHub Actions 必须包含 Rust API/schema/router/apply/WAL tests、UDS contract drift check、Python client contract tests 和 container packaging |
| PR 拆分 | PR-5A 只做 ACL enhancement，PR-5B 只做 QoS；ACL 安全边界验证和 QoS 调试不得混在一个 PR |
| Work Package | 每个 Work Package 保留 5-8 条硬验收 checklist；长解释留在实现要求或测试要求里 |
| 文档一致性 | README、主方案、报告、代码注释、测试名和 PR 描述必须使用统一口径，不使用安全组替代表述 |

### 1.6 当前阶段统一语义合同

后续 README、方案文档、报告、代码注释、测试名和 PR 描述都必须遵守下面的统一语义：

| 主题 | 当前阶段唯一口径 |
| --- | --- |
| 总体模式 | OVS enhancement mode；OVS 继续负责原有 L2 转发 |
| ACL | ACL enhancement domain；未启用时 `DomainStatus=not_requested,effective_action=bypass`；配置错误或 apply 失败时 `DomainStatus=degraded,effective_action=bypass` |
| ACL 输入源 | 正式产品路径为 `aria_acl` Neutron service plugin/API/DB；`neutron-aria-agent` 从 Neutron 读取 effective ACL 并下发 snapshot；`fixture` 只用于 CI/smoke；tag + 本机 mapping 只保留为 lab/bootstrap/迁移辅助，不作为生产主路径；不消费 Security Group、remote group、port security 或 allowed address pairs |
| Security Group | 不做 projection，不展开 remote group，不承担 Neutron SG enforcement |
| anti-spoof / port security | 当前阶段不实现；只记录为未来独立阶段候选 |
| N3 | 只做 ACL enhancement 最小闭环：默认 bypass、显式策略生效、失败不影响 OVS |
| N0.5 | 只确认目标环境事实和 OVS 转发保护；不要求关闭或旁路任何 OVS/SG/firewall flow |
| Ready | Aria ready 只代表增强域状态；OVS connectivity ready 独立判断 |
| Snapshot accepted | 代表 snapshot 通过 schema/authority 校验、WAL durable、且各请求 domain 有结构化终态；不代表 ACL 一定生效 |
| Smoke | 先验证 Aria 故障不影响原 OVS 转发，再验证显式 ACL enhancement policy |

现有 datapath 在 ACL 未启用或未命中策略时会 pass。后续实现要保证 Neutron mode 只有在 ACL enhancement accepted 后才启用对应 feature flag；任何未 accepted 或 degraded 状态都不能改变原有 OVS 转发。

### 1.7 语义词典与不变量

本节是后续文档、DTO、测试和 PR 描述的语义基线。若后文出现同义词，以本节为准。

#### 1.7.1 环境事实状态

目标环境相关描述只允许使用三种状态：

| 状态 | 含义 | 允许写入位置 |
| --- | --- | --- |
| `assumption` | 方案设计假设，尚未完成 N0.5 证据闭环 | 主方案、PR-0、PR-1A 前置说明 |
| `verified` | discovery 表中已有命令、实际结果和证据路径 | 主方案、README、PR 描述、smoke 报告 |
| `failed` | discovery 验证失败，当前阶段降级、延期或不支持 | discovery 表、阶段 gate、risk/runbook |

主方案不得把 `assumption` 写成“已确认”。只有 [OpenStack Target Environment Discovery](openstack-target-env-discovery.md) 中对应行从“未执行”变成实际结果和证据路径后，才允许把该结论提升为 `verified`。

#### 1.7.2 阶段 Gate

阶段 gate 只分三类：

| Gate | 阻塞点 | 判定依据 |
| --- | --- | --- |
| `schema_freeze_gate` | PR-1A schema freeze | N0.5-lite 完成，至少验证 OVS/tap/direction 对 DTO 字段无破坏 |
| `feature_gate` | N3/N4 目标环境功能闭环 | 完整 N0.5 完成，对应 feature 的输入源、方向、unsupported 处理和 OVS 保护已验证 |
| `deployment_smoke_gate` | PR-6A 容器骨架 smoke 与 PR-6B 完整 feature smoke | PR-6A 验证容器、host mounts、socket 权限、默认 bypass；PR-6B 在 ACL/QoS feature gate 通过后验证完整功能 smoke |

Discovery gate、feature gate 和 deployment smoke gate 不能互相替代。mock smoke 可以支持 PR-1 到 PR-4，但不能替代完整 N0.5 的目标环境证据。

#### 1.7.3 状态维度

实现和文档禁止使用 `bypass/degraded`、`blocked/degraded`、`degraded 或 ignored` 这类组合状态。必须拆成结构化字段：

| 维度 | 合法值 | 用途 |
| --- | --- | --- |
| `DomainStatus` | `ready`、`degraded`、`blocked`、`not_requested` | 表达 domain 本次请求或当前承诺的执行结果 |
| `effective_action` | `enforce`、`bypass`、`unchanged`、`cleanup`、`no_op` | 表达 datapath 对业务流量或本机状态采取的动作 |
| `support_disposition` | `supported`、`unsupported`、`unknown`、`not_applicable` | 表达 port 类型、feature、optional field 或规则能力是否受支持 |
| `AgentHealth` | `alive`、`degraded`、`down` | 表达 Neutron agent 进程/heartbeat 状态 |
| `RuntimeAttachmentState` | `observed_tap`、`unmanaged_bypass`、`neutron_bound_pending`、`managed_ready`、`managed_degraded` | 表达 tap/ifindex/eBPF attach 与 Neutron ownership 的关系 |
| `OverallReadiness` | `ready`、`degraded`、`blocked`、`unknown` | status response 的聚合摘要，不替代 per-domain status |

`ignored_optional_fields` 和 `unsupported_features` 是 status/capabilities 的观测字段，不是 `DomainStatus`。`bypass` 是 `effective_action`，不是 `DomainStatus`。`alive` 是 `AgentHealth`，不是 feature readiness。`overall_readiness` 是聚合字段，只能由 per-domain status 和 `AgentHealth` 推导，不能作为唯一验收依据。

#### 1.7.4 Generation 语义

| 字段 | 唯一含义 |
| --- | --- |
| `last_submitted_generation` | Python agent 最近一次尝试提交的 desired state generation |
| `accepted_generation` | 通过 schema/host/authority 校验、WAL durable，且所有请求 domain 都有结构化终态的 generation |
| `applied_generation` | 完成 apply 尝试并产出 domain status 的 generation，可包含 degraded 或 blocked domain |
| `last_classified_generation` | 最近一次没有未分类失败、status/capability/WAL 语义都可解释的 generation；不要求所有 enhancement domain 都 ready |
| `last_feature_ready_generation_by_domain` | 按 ACL/QoS enhancement domain 记录最近一次该 domain 已过 feature gate 且 ready 的 generation；只用于功能 ready 判断 |

`accepted_generation` 不等于所有 feature 生效，`last_classified_generation` 不等于所有 domain ready。功能是否生效必须看对应 domain 的 `DomainStatus` 和 `effective_action`；只有 `last_feature_ready_generation_by_domain.<domain>` 可以表达“该功能域最近一次 ready”。本文档不再使用旧的 good 命名，避免把“可解释的降级状态”误读成“功能良好”。

#### 1.7.5 ACL Group 命名

为避免回流到 Neutron Security Group 语义，当前阶段统一使用：

- `explicit_acl_group`：operator-admin 在 `aria_acl` policy/rule/address-set 中定义的显式地址组。
- `address_set`：Rust 编译后的本机地址集合。
- `groups` domain：Aria 编译中间层 domain，服务 ACL/QoS/统计归因。

禁止把 `explicit_acl_group` 写成 Neutron `remote group`。当前阶段不消费 Neutron Security Group remote group，也不做 Security Group projection。

#### 1.7.6 `unknown` 使用边界

`support_disposition=unknown` 只允许出现在对应 feature gate 之前，用于表达目标环境或 extension 尚未完成 discovery。进入对应 gate 后必须收敛为：

- `supported`：目标环境与当前实现都支持。
- `unsupported`：目标环境或当前实现明确不支持。
- `not_applicable`：本次请求没有该 feature 或该对象不适用。

延期能力不能继续写成 `support_disposition=unknown` 来通过 deployment smoke。延期只能写在 PR/roadmap 的 scope 说明中；DTO/status 中要么不请求该 feature，要么按 `not_applicable` 或 `unsupported` 表达。

#### 1.7.7 AgentHealth 与 Neutron 可见状态

`AgentHealth` 只表达 `neutron-aria-agent` 进程和上报通道状态，不表达 feature 是否 ready。Neutron 可见状态按下表转换：

| 输入状态 | `AgentHealth` | `overall_readiness` | Neutron `alive` | Neutron `admin_state_up` | `configurations/status` 要求 |
| --- | --- | --- | --- | --- | --- |
| 进程运行、heartbeat 正常、无阻塞 domain | `alive` | `ready` 或 `degraded` | true | true | 必须带 `accepted_generation`、`last_classified_generation`、`last_feature_ready_generation_by_domain` 和 per-domain status |
| datapath UDS socket 暂时不可达、ACL/conntrack blocked、runtime blocked、`rejoin_pending`，但 Neutron heartbeat 正常 | `degraded` | `degraded` 或 `blocked` | true | true | 必须带 last error、full resync reason、affected domains |
| Neutron RPC/RabbitMQ/heartbeat 通道不可达，但 agent 进程仍在运行 | `degraded` | `degraded` | 最后一次上报可能短暂为 true；超过 Neutron heartbeat timeout 后为 false | 保持配置值 | 本地日志必须记录 RPC 断开原因；恢复后第一次 heartbeat 必须带 full resync reason |
| 进程退出或 heartbeat 停止 | `down` | unknown | false | 保持配置值 | Neutron 只能看到 agent down，不推断 OVS connectivity |

`AgentHealth=degraded` 不能被翻译成 OVS 停止转发；`AgentHealth=alive` 也不能被翻译成 ACL/QoS ready。

#### 1.7.8 OverallReadiness 聚合规则

`overall_readiness` 只服务 status 摘要，不能替代 `domains` 明细：

- 任一 mandatory domain 为 `blocked`，或 `AgentHealth=down` 时，`overall_readiness=blocked`。
- 任一请求的 enhancement domain 为 `degraded` 或 `blocked`，或 `AgentHealth=degraded` 时，`overall_readiness=degraded`。
- 所有 mandatory domain ready，且所有请求的 enhancement domain ready，且 `AgentHealth=alive` 时，`overall_readiness=ready`。
- agent 刚启动、尚未完成第一次 capabilities/status 握手时，`overall_readiness=unknown`。

### 1.8 单一事实源

后续段落如果与本表冲突，以本表和 1.7 语义词典为准；重复段落只允许引用，不重新定义。

| 主题 | 单一事实源 | 后文允许做什么 | 后文禁止做什么 |
| --- | --- | --- | --- |
| 状态词与 generation | 1.7 语义词典 | 引用字段名和合法值 | 重新定义 ready/degraded/bypass/generation |
| N0.5 / feature / deployment gate | 1.7.2 与 Phase N0.5 | 引用 gate 名称、补 evidence | 用 PR-6A/PR-6B smoke 替代 N0.5 discovery |
| UDS 契约 | 5.1.1 Local Unix API Contract | 增加测试、artifact、安装路径 | 把 UDS path 注册到 TCP OpenAPI paths |
| Status response | 5.3 Snapshot 返回结构 | 增加样例和测试断言 | 省略 `effective_action` 或 `support_disposition` |
| AgentHealth 映射 | 1.7.7 与 Work Package 7 | 增加 Neutron adapter 测试 | 用 alive/degraded 表达 feature ready |
| 性能 fixture | 13.4.1 固定规模 Fixture | 增加生成器和 CI 阈值 | 在 N6 重新定义输入规模 |
| PR 拆分 | 16.5 推荐 PR 顺序 | 引用依赖和 gate | 在 Work Package 中改写依赖关系 |

## 2. 组件边界

### 2.1 Neutron

Neutron 拥有 OpenStack 网络对象和用户语义：

- project / tenant
- network / subnet
- port
- port binding host
- fixed IP / MAC 仅用于 port 归属、接口匹配和观测归因，不作为 ACL policy 输入。
- Neutron Security Group / remote group / port security / allowed address pairs 等 Neutron 原生安全语义继续由 Neutron 保留；当前阶段 Aria 不读取、不投影、不替代、不展开这些对象。
- QoS policy
- port status

Aria 不为这些对象新增独立 northbound 写入口。

### 2.2 OVS

当前设计假设目标 OpenStack 环境采用 OVS，不采用 OVN，不采用 Linux bridge / hybrid plug，VM tap 口直接挂到 OVS `br-int`，没有 `qvo`、`qvb`、`veth` 这类 Linux bridge 中间设备。该假设属于 `assumption`，必须通过 N0.5 discovery 证据提升为 `verified` 后，才能冻结 direction、attach 点和目标环境 smoke 结论。

第一阶段 OVS 继续负责基础 L2 connectivity：

- VM tap/vif plug。
- bridge/tunnel/local switching。
- underlay/overlay 网络连通。
- 与现有 OpenStack 部署流程兼容。

OpenStack 模式必须处理和现有 OVS 转发的边界：

- 目标环境是否没有启用原 Neutron SG 过滤链路、是否没有 Linux bridge / `qvo/qvb/veth` 路径、VM tap 是否直接接入 OVS `br-int`，都必须由 N0.5 discovery 记录证据；证据缺失时只能作为设计假设。
- 当前阶段 Aria 不作为安全组替代链路，也不消费 Neutron Security Group projection，只做 OVS 旁路上的增强能力。
- Aria ACL 未 ready、ACL apply 失败或 `aria-datapath` 异常时，默认 `effective_action=bypass`，并按原因返回 `DomainStatus=not_requested`、`degraded` 或 `blocked`，不能阻断原有 OVS 转发。
- 如果后续要做 Security Group replacement mode 或 Security Group projection，必须作为独立阶段显式设计，不能复用当前 N3 验收标准。

### 2.3 neutron-aria-agent

`neutron-aria-agent` 是 OpenStack 适配层，建议使用 Python 编写。

职责：

- 向 Neutron 注册本 host 上的 Aria agent。
- 维持 agent heartbeat。
- 消费 Neutron port、QoS 和 `aria_acl` 显式 ACL enhancement 对象，生成 ACL/QoS 相关 snapshot。
- 在启动、重连、事件丢失、generation 不一致时执行 full resync。
- 只处理绑定到本 host 的 Neutron ports。
- 把 Neutron 对象翻译成本机 snapshot。
- 调用本机 datapath 的 Neutron snapshot API。
- 记录 latest desired generation、last applied generation、last error 和 domain status。

功能边界：

- 只把 ACL enhancement 和 QoS 翻译成 Neutron snapshot。
- 不读取、不翻译、不下发 Mirror、TCPrt、Trace、Drops、SSL、Diagnose、Service Chain、Route、NAT、L4 LB 或 Service。
- 不为其它 Rust 既有能力新增 Neutron RPC、配置项、translator 输入、feature flag、status domain 或 smoke。

不负责：

- 不直接写 eBPF map。
- 不管理 XDP/TC attach。
- 不读取或写入 Aria WAL。
- 不实现完整 OVS L2 datapath。
- 不暴露非 Neutron 同步对象。

建议使用 Python 的原因：

- Neutron agent、RPC、heartbeat、service launcher、配置、logging 都是 Python 生态。
- QoS、port binding 和 agent heartbeat 的事件模型可以复用 Neutron 原有模式；Security Group 事件不进入当前阶段主路径。
- 后续做 ML2 driver、agent extension 或 vendor extension 时接入成本更低；第一阶段不要求目标 Neutron 已有这些 extension。

### 2.4 aria-datapath

`aria-datapath` 是 Rust 本机 datapath runtime 的角色名和容器名。它运行现有 `aria-agent` 二进制，不改 binary、既有服务文件、配置目录、socket、日志路径和 CLI 兼容性。

职责：

- 接收本机声明式 snapshot。
- 编译本地 group/address-set/port-set。
- 编译并 apply Neutron snapshot 中的 ACL/QoS。
- 维护 tap/ifindex/tap_id 映射。
- 通过 Netlink 感知接口生命周期。
- 通过 WAL 保存本机状态变更。
- 通过 Pinned Maps / pinned links 保持 runtime。
- 提供 status、metrics、stats、diagnose、trace 等既有本机管理员能力；这些能力不因为本方案而新增 Neutron 对接。

不负责：

- 不访问 Neutron DB。
- 不消费 Neutron RPC。
- 不理解 Neutron server 内部对象生命周期。
- 不作为 OpenStack northbound。
- 不把 Rust 现有本机能力自动提升为第一阶段功能模块。

## 3. 工作模式

### 3.1 Coexist Mode

第一阶段采用 Coexist Mode：

```text
OVS              负责 L2 connectivity
neutron-aria-agent 负责 Neutron 状态同步与翻译
aria-datapath    负责节点侧 eBPF 执行
```

这个模式的好处是：

- 改动范围小。
- 可以先验证 Aria 的节点侧价值。
- 不需要一次性替换 OpenStack 现有 L2 绑定路径。
- 出问题时可以退回 OVS 原有能力。

### 3.2 不是完整 L2 Agent 替代

`neutron-aria-agent` 在部署形态上类似 `neutron-openvswitch-agent`，都是 compute node 上的本地 Neutron agent。但它不是 OVS L2 agent 的替代品，当前路线也不规划替代 OVS L2 agent。

`neutron-openvswitch-agent` 通常负责：

- port plug / bridge / tunnel
- local switching
- 原生安全能力插件
- QoS
- agent heartbeat
- port status

`neutron-aria-agent` 第一阶段只负责：

- agent heartbeat
- full resync
- port 归属判断
- 显式 ACL enhancement/QoS 翻译
- 调用本机 datapath snapshot API
- 上报 Aria runtime status

这里的“只负责”是功能 scope 边界：第一阶段新增功能模块只有 ACL/QoS。agent heartbeat、full resync、port 归属、runtime status、UDS、WAL、Netlink、Pinned Maps 都是为 ACL/QoS 服务的支撑能力，不是额外功能交付。

完整 L2 替代不是本路线目标。OVS 的 bridge、tunnel、local switching、port plug 和基础连通能力始终由 OVS 负责；`neutron-aria-agent` 只负责 ACL、QoS 这些节点侧功能的 Neutron 适配与下发。

## 4. 状态模型

### 4.1 Neutron 拥有的状态

Neutron 是 source of truth：

- 租户、网络、子网、端口。
- 端口绑定在哪个 host。
- 端口 fixed IP、MAC，仅用于 port 归属、接口匹配和观测归因。
- Security Group 和规则由 Neutron 保留；当前阶段不做 Aria projection。
- QoS policy 和 rule。
- port security。
- allowed address pairs。
- port status。

这些对象不允许通过 `aria-datapath` 或 `neutron-aria-agent` 另开一套 northbound 修改。

### 4.2 neutron-aria-agent 拥有的状态

`neutron-aria-agent` 只保存本机可重建投影：

- 本 host 绑定的 Neutron ports。
- 每个 port 的 fixed IP、MAC 观测归因字段；不作为 ACL policy 输入。
- 显式 ACL enhancement 输入投影。
- 每个 port 的 ACL enhancement 结果。
- 每个 port 的 QoS 结果。
- `desired_generation`。
- `last_submitted_generation`。
- `accepted_generation`。
- `last_classified_generation`。
- `last_feature_ready_generation_by_domain`。
- domain apply status。

该状态必须能通过 Neutron full resync 重建。磁盘缓存只能作为加速或诊断，不能成为权威来源。

### 4.3 aria-datapath 拥有的状态

`aria-datapath` 拥有本机运行态：

- tap/ifindex/tap_id 映射。
- group/address-set/port-set。
- ACL map。
- QoS map。
- feature flags，仅允许 `acl/qos`。
- WAL。
- Netlink 监听与接口对账。
- Pinned Maps / pinned links。
- metrics、stats、diagnose、trace 等既有本机管理员能力；不进入第一阶段 Neutron 功能模块。

`aria-datapath` 只接受本机 snapshot，不解释 Neutron RPC。

### 4.4 Generation 语义

每次 `neutron-aria-agent` 下发 snapshot 必须带 generation：

- `schema_version`：snapshot schema 版本。
- `local_generation`：本 host 本次 desired state 的单调 generation。
- `source_revision`：可选，记录 Neutron full resync 或事件批次来源。
- `host`：OpenStack compute host。
- `integration_mode`：Neutron 与 Aria 的集成形态，第一阶段固定为 `coexist`。

注意：`integration_mode` 是 snapshot schema 字段，表达“OVS 继续负责 L2、Aria 负责节点侧 feature”的集成形态；`agent_mode` 是 `aria-agent` 本机配置字段，表达进程是否进入 OpenStack 托管运行模式。两者不得混用。

除 snapshot 级别的 `source_revision` 外，所有从 Neutron 投影而来的对象只要上游支持 revision number，就必须携带对象级 `revision_number` 或等价 `source_revision`。`aria-datapath` 不用它替代 `local_generation`，但 `neutron-aria-agent` 必须用它丢弃乱序或过期事件，避免旧 port/rule/group 覆盖更新状态。

乱序和陈旧事件处理以 `neutron-aria-agent` 为主，`aria-datapath` 只做 generation 幂等和 schema/authority 防线：

| 输入场景 | Python adapter 处理 | Datapath 处理 |
| --- | --- | --- |
| full resync 完成 | 生成新的 `local_generation`，作为本 host authoritative state 下发 | 如果 generation 新于当前 accepted/applied，则按 snapshot apply |
| port/ACL/QoS event 带更旧 `revision_number` | 丢弃，不生成 snapshot | 不应收到；收到时按对象级 stale status 拒绝相关对象 |
| event source 不提供对象 revision | 只能进入 full resync 或使用 adapter-local `source_revision` 批次号 | 不用缺失 revision 推进对象状态 |
| port migration/rebind 多事件乱序 | 以最新 `binding_host` 和 source revision 为准，旧 host 生成 delete 或等待 full resync 清理 | host mismatch 的 port 不 apply，返回 `PORT_BINDING_HOST_MISMATCH` |
| 同一 `local_generation` 重放 | 原样重发，用于 socket retry 或恢复 | 幂等返回当前 status，不重复创建 map/group/rule |
| 更旧 `local_generation` 到达 | 不应发送；如果出现说明 adapter 状态回退 | 拒绝或 no-op，并保留当前 accepted/applied generation |

`aria-datapath` 必须保存：

- `accepted_generation`：最近一次通过 schema/host/authority 校验、WAL durable、且所有请求 domain 都有 `DomainStatus`、`effective_action` 和 `support_disposition` 的 generation；WAL 失败、preflight 阻断或 domain 状态缺失时不得推进。
- `applied_generation`：最近一次完成 apply 尝试并生成 `domain_status` 的 generation，可包含 independent domain degraded。
- `last_classified_generation`：最近一次状态、capability 和 WAL 语义完整可解释、没有未分类失败的 generation；不要求所有 enhancement domain 都 ready。
- `last_feature_ready_generation_by_domain`：按 `acl/qos` 分别记录最近一次已过 gate 且 ready 的 generation；任何 degraded、blocked 或未收敛 unknown 都不得推进对应 domain。
- `domain_status`：每个 domain 的 apply 结果。

同一个 generation 重放必须幂等。

### 4.5 控制权与本机管理员能力

OpenStack 模式必须把“Neutron 权威配置”和“本机管理员排障能力”分开。

Neutron 权威配置由 snapshot 中的 `managed_domains` 声明，当前代码路径是：

```text
NeutronPortSnapshot.managed_domains
  -> mark_neutron_port_authority()
  -> ensure_local_write_allowed()
  -> LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_DOMAIN
```

Neutron 权威配置包括：

- Neutron ports 对应的 group/address-set。
- ACL enhancement。
- QoS。
- 这些对象对应的 runtime status、generation 和 WAL 持久化状态。

这些状态只能由 `neutron-aria-agent` 通过 snapshot API 修改。本机 `ariactl` 或现有管理 API 不允许直接写入该 port/instance 的 Neutron-managed domain；未列入 `managed_domains` 的 domain 仍按本机模式处理。

本机管理员能力分成两类：

| 类型 | 例子 | OpenStack 模式策略 | 是否进入 WAL |
| --- | --- | --- | --- |
| 只读观测 | stats、metrics、diagnose、tcprt query | 作为既有本机管理员入口允许；不新增 Neutron 功能 | 否 |
| 临时排障 | trace start/stop/flush、drop stats flush | 作为既有本机管理员入口允许；不进入 Neutron schema | 否 |
| Neutron 权威配置写入 | group、policy、qos、ACL enable | 禁止本机手动写已列入 `managed_domains` 的 domain | 是，只能由 snapshot 写 |
| 非 Neutron 持久配置 | service chain、host-global ssl、手动 config toggle | OpenStack 模式默认不作为落地范围 | 不得混入 Neutron WAL 命名空间 |

因此，管理员可以在 compute node 上使用 trace 做临时排障；trace filter 不应被视为 Neutron desired state，也不应通过 WAL 持久化。`aria-datapath` 重启后，trace 需要重新开启。

相反，如果管理员用本机命令手动改已被 Neutron 纳管的 ACL/QoS 配置，这会和 Neutron snapshot 形成双写冲突。OpenStack 模式必须在 Rust/API 层按 domain 拒绝这类写入，返回明确错误 `LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_DOMAIN`。Mirror、TCPrt、Trace 等既有本机能力不删除；只要对应 domain 没有出现在该 port/instance 的 `managed_domains` 中，本机 `ariactl` 仍可写入或排障。若未来把 mirror 等 domain 纳入 Neutron snapshot，同一套 `managed_domains` 仲裁继续适用，不另起控制权模型。

### 4.6 Authority 状态机与重新接管

OpenStack mode 不能只用“通信是否成功”判断是否允许本机写入。通信失败不等于退出 OpenStack 托管。

必须区分以下状态：

| 状态 | 触发条件 | 权威来源 | 本机持久配置写入 | Datapath 行为 |
| --- | --- | --- | --- | --- |
| `openstack_managed` | 收到并成功接受 Neutron snapshot | Neutron | 拒绝已列入 `managed_domains` 的 domain | 执行最新 `last_classified_generation` |
| `openstack_degraded` | Neutron RPC、socket 或 status 暂时异常，但本机仍有托管标记 | Neutron | 拒绝已列入 `managed_domains` 的 domain | 继续执行最后一次成功 snapshot |
| `local_break_glass` | 管理员显式执行本机接管命令 | Local admin | 允许，写 local override WAL | 暂停 Neutron apply |
| `local_standalone` | 非 OpenStack 部署或管理员显式脱离 OpenStack | Local admin | 允许，写 local WAL | 按本机配置运行 |
| `rejoin_pending` | break-glass 后 Neutron 通信恢复 | Neutron pending | 拒绝新的本机持久写入 | 等待重新接管决策 |

默认规则：

- `openstack_managed` 和 `openstack_degraded` 都不能本机修改已列入 `managed_domains` 的 ACL/QoS/Mirror/group；未列入的 domain 保持本机可写。
- Neutron 通信失败时，datapath 继续使用 `last_classified_generation`，不能自动开放本机写入口。
- 只有管理员显式进入 `local_break_glass` 或 `local_standalone`，本机配置命令才可以写入并持久化。
- `local_break_glass` 必须有本机审计记录，包含操作者、时间、原因、影响 ports。
- `local_break_glass` 下写入的状态必须进入独立 local override WAL，不能混入 Neutron WAL 命名空间。

重新被 Neutron 接管时，默认采用 `Neutron wins`：

1. `neutron-aria-agent` 恢复通信后，先查询 datapath authority state。
2. 如果状态是 `openstack_degraded`，直接 full resync，Neutron snapshot 覆盖托管 domains。
3. 如果状态是 `local_break_glass`，进入 `rejoin_pending`，不得自动覆盖本机配置。
4. 管理员确认重新接管后，执行 `discard local overrides`。
5. `aria-datapath` 归档 local override WAL。
6. `neutron-aria-agent` 下发 full snapshot。
7. `aria-datapath` scrub Neutron-managed ports 上的 local policy state。
8. snapshot apply 成功后，authority state 回到 `openstack_managed`。

不支持自动 `local wins`。如果管理员希望保留本机 break-glass 配置，必须先把这些变更转换成 Neutron 对象，再重新接管。

### 4.7 多租户适配原则

OpenStack 多租户边界必须由 Neutron 对象关系驱动，不能由 `aria-datapath` 自行发明一套 tenant ACL。

基本原则：

- `neutron-aria-agent` 使用服务账号读取 Neutron 状态，不接受租户直接调用。
- Snapshot 是 host-scoped，但一个 host snapshot 可以同时包含多个 project 的 ports。
- `project_id` 是所有租户对象的必填元数据，至少覆盖 port、ACL enhancement rule 和 QoS policy。
- `aria-datapath` 内部对象 key 必须使用 scoped object key：`source/project_id/domain/object_id`。
- 不能只用 policy name、display name 或短 ID 做 key。
- 数据包本身不携带 project_id，实际 enforcement 仍按 ingress/egress port identity 和编译后的 per-port policy 执行。
- 不因为 project_id 不同就自动丢包；跨租户共享网络、路由、floating IP、provider/admin policy 是否允许，由 Neutron 对象关系和显式 ACL enhancement policy 决定。
- 所有跨 project 引用都必须来自 Neutron 明确授权的对象关系或 operator-admin 显式配置，例如 shared network、RBAC shared QoS policy 或 `aria_acl` binding / shared ACL policy。
- 未经 Neutron 表达的跨 project QoS 引用必须拒绝或标记 degraded。

多租户对象命名建议：

```text
port key          = neutron/{project_id}/port/{port_id}
group key         = neutron/{project_id}/group/{group_id}
address-set key   = neutron/{project_id}/address-set/{group_id}/{ethertype}
acl key           = neutron/{project_id}/acl/{acl_rule_id}
qos key           = neutron/{project_id}/qos/{policy_id}
```

如果 Neutron 对象是 shared/admin-owned，对象 key 仍保留 owner project 或 admin scope，同时在 binding 关系里记录实际 port project。`aria-datapath` 只消费已经解析好的 effective binding，不在 Rust 侧重新判断 Neutron RBAC。

两个功能域的多租户规则：

| 功能 | 多租户适配 |
| --- | --- |
| ACL | 显式 ACL enhancement rule 必须带 `project_id`；当前阶段不做 Security Group projection、remote group、port security、allowed address pairs 或 anti-spoof |
| QoS | policy 带 owner `project_id` 和 `scope`；shared QoS 由 `neutron-aria-agent` 解析成 port effective QoS，datapath 只按 port apply |

WAL 和 pinned map 也必须感知租户边界：

- WAL entry 记录 `source = "neutron"`、`project_id`、`domain`、`object_id` 和 scoped object key。
- refcount 按 scoped object key 计算，删除一个 project 的 port 不能释放另一个 project 的 group/address-set。
- pinned map 可以继续使用紧凑 numeric ID，但 numeric ID 分配必须由 scoped object key 派生或持久化映射，避免重启后跨租户串位。
- status 可以聚合输出 per-project domain counts，但不向租户暴露本机 snapshot API。

## 5. 本机 Snapshot API

### 5.1 API 列表

新增 API：

```text
PUT    /api/v1/neutron/snapshot
DELETE /api/v1/neutron/ports/{port_id}
GET    /api/v1/neutron/status
GET    /api/v1/neutron/capabilities
GET    /readyz
```

约束：

- OpenStack agent mode 只监听 Unix socket：`/run/aria/aria-agent.sock`。
- OpenStack agent mode 必须由显式配置启用，例如 `agent_mode = "openstack"`；不能仅因为配置了 `listen_unix_socket` 就推断进入 OpenStack 模式。
- Standalone 模式下 Netlink 可以按 `iface_pattern` 自动 attach 并进入本机配置路径。
- OpenStack 模式下 Netlink 可以触发 tap runtime attach，但 attach 后默认处于 inert/bypass；ACL/QoS 是否启用只能由 Neutron snapshot 决定。
- OpenStack 模式下不能仅凭 tap 名称创建 Neutron-managed policy state，也不能仅凭 tap 出现把 port 标记 Aria ready。
- 不作为租户 API。
- 只给 `neutron-aria-agent` 和本机管理员使用。
- 主路径必须是 full snapshot 或 port-scoped snapshot，不能依赖逐条 CRUD 叠加。
- 现有 `/{instance}/policies`、`/{instance}/qos`、`/{instance}/mirror` 等本机接口可以保留，但不是 OpenStack 主路径。

#### 5.1.1 Local Unix API Contract

Neutron snapshot API 不进入现有 TCP OpenAPI paths，但仍必须有稳定的本机契约：

- 传输：Unix socket HTTP，默认 `unix:///run/aria/aria-agent.sock`。
- 暴露路径固定为：
  - `PUT /api/v1/neutron/snapshot`
  - `GET /api/v1/neutron/status`
  - `GET /api/v1/neutron/capabilities`
  - `GET /readyz`
  - `DELETE /api/v1/neutron/ports/{port_id}`
- request/response schema 使用 `api` crate 中的 Neutron DTO，不能由 Python agent 另写一套私有字段。
- 错误响应必须包含稳定 `error_code`、`message`、`domain`、`local_generation` 和可选 `affected_ports`。
- required field 未知或缺失必须拒绝；optional field 未识别必须进入 ignored/compat status，不能静默改变 datapath。
- 本机 UDS contract 的版本跟随 `schema_version` 和 capability handshake；Rust/Python 版本不匹配时返回 typed error，而不是 fallback 到 TCP 或 best-effort apply。
- CI 必须生成或校验 `neutron-uds-contract.json`，内容包含 UDS paths、schema refs、capabilities response、错误码和兼容规则；该 artifact 不代表 TCP OpenAPI 暴露面。
- `neutron-uds-contract.json` 必须额外包含：
  - `contract_version`：UDS contract 自身版本，第一版固定为 `"2026-06-v0.9"`。
  - `body_max_bytes`：第一阶段固定为 `1048576`，对应 1 MiB body 上限。
  - `timeout_ms`：Python client 推荐请求超时，第一版固定为 `3000`。
  - `error_codes_hash`：稳定错误码集合的摘要，用于发现 Python/Rust 错误码漂移。
  - `peer_auth_policy`：允许的 Unix peer credential 策略，第一阶段固定为 `filesystem_permissions_then_peercred`。
- `agent/src/openapi.rs` 只注册 Neutron DTO components 和 TCP path 排除测试；UDS paths 由 `neutron-uds-contract.json` 固化，Python agent 测试必须读取该 contract 或等价 fixture 做请求/响应校验。
- 日志必须记录 peer uid/gid、请求路径、schema_version、local_generation、accepted/applied 结果和 error_code。

契约来源表：

| 契约项 | 唯一来源 | 产物 | 必测项 |
| --- | --- | --- | --- |
| DTO schema | `api/src/lib.rs` | OpenAPI components、UDS contract schema refs | serde roundtrip、component name stability |
| TCP path 排除 | `agent/src/openapi.rs` | TCP OpenAPI paths | Neutron UDS paths 不出现在 TCP OpenAPI paths |
| UDS path 列表 | `docs/neutron-uds-contract.json` + `ci/check_neutron_stage1.py` | `neutron-uds-contract.json` | 公开 route 清单与 Rust router、Python client 完全一致 |

#### 5.1.2 Liveness 与 Neutron Readiness

三个本机观测面不能互相替代：

- TCP `GET /api/v1/health` 是进程 liveness；只表示 `aria-agent` 能响应，
  不能证明 Neutron generation 或 ACL domain 已收敛。
- UDS `GET /api/v1/neutron/status` 是 Status V1 状态检查；只要响应可读就
  返回 HTTP 200，调用方必须检查 `overall_readiness`、`required_action`、
  generation 和 per-domain evidence。
- UDS `GET /readyz` 是严格的 Aria Neutron datapath readiness；它返回同一
  份完整 `NeutronStatusV1Response`，但仅当 `overall_readiness=ready` 时返回
  HTTP 200。`unknown`、`degraded`、`blocked` 均返回 HTTP 503。

`degraded + effective_action=bypass` 表示 Aria enhancement 未 ready，但 OVS
仍按可用性优先边界继续转发。`/readyz` 的 503 不能解释成 OVS forwarding
down，也不能作为重启 datapath 进程的默认理由。

该 UDS probe 证明 Rust datapath 当前可响应且 Status V1 已收敛，不证明独立
Python `neutron-aria-agent` 最近一次向 Neutron server 的 RPC heartbeat 已
成功。部署层最终启用 health-check 前必须组合这两个信号，并在目标环境
验证 pending、degraded、blocked 和 recovery 的处理策略。
| 错误码集合 | `api/src/lib.rs` / `docs/neutron-uds-contract.json` | `error_codes_hash` | Python/Rust hash 一致，不一致停止写路径 |
| capabilities response | `api/src/lib.rs` / `agent/src/neutron_api.rs` | `GET /api/v1/neutron/capabilities` | contract version、schema range、body/timeout、peer auth policy 与 artifact 一致 |
| Python 校验入口 | `neutron-aria-agent/neutron_aria_agent/local_client.py` | client startup/reconnect 检查 | request/response 校验、capability hash 变化触发 full resync |

#### 5.1.2 Capability Handshake Contract

`neutron-aria-agent` 必须在第一次 snapshot、UDS reconnect、`aria-datapath` restart、capability hash 变化后调用：

```text
GET /api/v1/neutron/capabilities
```

建议响应结构：

```json
{
  "api_version": "v1",
  "contract_version": "2026-06-v0.9",
  "schema_version_min": 1,
  "schema_version_max": 1,
  "attach_authority": "neutron_snapshot",
  "supports_full_snapshot": true,
  "supports_port_delete": true,
  "body_max_bytes": 1048576,
  "timeout_ms": 3000,
  "supported_domains": [
    "attach",
    "acl",
    "qos",
    "mirror"
  ],
  "mandatory_domains": [],
  "error_codes_hash": "v0.9-neutron-errors-2",
  "peer_auth_policy": "filesystem_permissions_then_peercred",
  "capability_hash": "v0.9-neutron-capabilities-3"
}
```

兼容规则：

- Python 侧提交的 `schema_version` 必须落在 `schema_version_min..schema_version_max` 内，否则 Rust 返回 `UDS_SCHEMA_MISMATCH`。
- Python 侧要求的 mandatory domain 或 required field 如果不在 Rust capability 中，Rust 返回 `UDS_CAPABILITY_MISMATCH`，不接受该 snapshot。
- enhancement domain 不支持时，Python 侧可以不下发该 feature；如果已下发但 Rust 不支持，相关 domain 必须返回 `DomainStatus=degraded,effective_action=bypass,support_disposition=unsupported`，并在 status 中暴露 `unsupported_features`。
- optional field 未识别时不能改变 datapath 行为，必须进入 status 的 `ignored_optional_fields` 或等价字段。
- `body_max_bytes` 是 Python client 的请求体上限来源；`timeout_ms` 是能力握手所约束的 mutation 请求级 ceiling，不得通过修改共享 client 默认值影响后续无关请求。
- `error_codes_hash` 变化时，Python 侧必须重新加载 contract；如果本地 contract 与 Rust 返回不一致，返回 `UDS_CONTRACT_DRIFT` 并停止写路径。
- `peer_auth_policy.require_peercred = true` 时，Rust 无法读取 peer credential 必须返回 `UDS_PEERCRED_UNAVAILABLE`，不能降级为只看文件权限。
- `capability_hash` 变化后，Python 侧必须触发 full resync；不能继续增量提交基于旧 capability 的 port-scoped snapshot。
- `GET /api/v1/neutron/status` 必须回显最近一次握手结果、`capability_hash`、ignored optional fields 和 unsupported features。

版本和摘要变化的决策表：

| 字段 | 变化含义 | Python 侧动作 | Rust 侧动作 | 错误码 |
| --- | --- | --- | --- | --- |
| `contract_version` | UDS contract 结构不兼容 | 停止写路径，agent degraded | capabilities 返回当前版本 | `UDS_CONTRACT_VERSION_UNSUPPORTED` |
| `schema_version_min/max` | snapshot DTO schema 范围不兼容 | 停止提交 snapshot，等待版本对齐 | 拒绝 snapshot | `UDS_SCHEMA_MISMATCH` |
| `capability_hash` | Rust runtime/domain 能力变化 | 重新握手并 full resync | status 回显新 hash | 无错误；若继续旧增量则 `UDS_CAPABILITY_MISMATCH` |
| `error_codes_hash` | 错误码集合漂移 | reload contract；仍不一致则停止写路径 | capabilities 回显当前 hash | `UDS_ERROR_CODES_HASH_MISMATCH` |
| `body_max_bytes` | body 上限变化 | 使用较严格上限；超限先本地拒绝 | 超限时拒绝请求 | `UDS_BODY_TOO_LARGE` |
| `timeout_ms` | 请求超时策略变化 | 对与本次握手耦合的 mutation 使用 `min(configured, advertised)`；不得永久更新共享 client timeout；超时进入 degraded/status reconcile | 不推进 generation | `UDS_REQUEST_TIMEOUT` |
| `peer_auth_policy` | 本机调用身份策略变化 | 校验本地运行身份和 group | 拒绝不合规 peer | `UDS_PEER_UNAUTHORIZED` |

### 5.2 Snapshot 请求结构

建议请求结构：

```json
{
  "schema_version": "1",
  "local_generation": "compute-01-000001",
  "host": "compute-01",
  "integration_mode": "coexist",
  "full": true,
  "tenant_model": {
    "scope_key": "source/project_id/domain/object_id",
    "shared_object_policy": "neutron_rbac_only"
  },
  "runtime_foundations": {
    "conntrack": {
      "required": true,
      "mode": "stateful_acl",
      "stats": true
    },
    "monitoring": {
      "required": true,
      "level": "rule_flow_group",
      "prometheus": true
    }
  },
  "ports": [
    {
      "port_id": "port-uuid",
      "revision_number": 12,
      "network_id": "network-uuid",
      "project_id": "project-uuid",
      "network_project_id": "network-owner-project-uuid",
      "device_id": "server-uuid",
      "binding_host": "compute-01",
      "if_name": "tapabcdef12-34",
      "ifindex": 123,
      "mac_address": "fa:16:3e:00:00:01",
      "fixed_ips": ["10.0.0.10"],
      "admin_state_up": true
    }
  ],
  "groups": [
    {
      "group_id": "acl-web",
      "revision_number": 7,
      "project_id": "project-uuid",
      "scope": "acl_group",
      "scope_id": "acl-web",
      "addresses": ["10.0.0.10", "10.0.0.11"]
    },
    {
      "group_id": "acl-db",
      "revision_number": 4,
      "project_id": "project-uuid",
      "scope": "acl_group",
      "scope_id": "acl-db",
      "addresses": ["10.0.0.20"]
    }
  ],
  "acl_policies": [
    {
      "port_id": "port-uuid",
      "revision_number": 9,
      "project_id": "project-uuid",
      "acl_policy_id": "acl-policy-uuid",
      "acl_rule_id": "acl-rule-uuid",
      "src_group_id": "acl-web",
      "dst_group_id": "acl-db",
      "direction": "ingress",
      "ethertype": "IPv4",
      "protocol": "tcp",
      "port_range_min": 80,
      "port_range_max": 80,
      "action": "allow"
    }
  ],
  "qos_policies": [
    {
      "policy_id": "qos-policy-uuid",
      "revision_number": 5,
      "port_id": "port-uuid",
      "project_id": "project-uuid",
      "scope": "port",
      "direction": "egress",
      "max_kbps": 100000,
      "max_burst_kbps": 10000,
      "mode": "shaping"
    }
  ],
  "feature_flags": {
    "default": {
      "acl": true,
      "qos": true
    },
    "ports": {
      "port-uuid": {
        "acl": true,
        "qos": true
      }
    }
  }
}
```

第一版可以先实现必要字段，但字段语义必须稳定。

字段边界：

- `runtime_foundations` 只表达 `conntrack` 和 `monitoring` 这类运行基础要求。
- `runtime_foundations.conntrack.required = true` 表示 Aria ACL 状态化、fast-path 或 flow 统计依赖 conntrack。Conntrack 不是 Neutron ACL mapping 输入，但状态化 ACL enhancement 必须把 conntrack ready 作为 feature ready 前提。
- `runtime_foundations.monitoring.required = true` 表示本 host 承诺输出 ACL/QoS/flow/group 统计；如果 monitoring 失败，转发不一定中断，但 Aria observability status 不得 ready。
- `feature_flags` 只表达 `acl/qos`；不能把 `group/conntrack/monitoring/wal/netlink/pinned` 做成租户 feature，也不能把 Mirror/TCPrt 放进 Neutron feature flags。
- 没有功能需求的 port 可以保持 `DomainStatus=not_requested,effective_action=bypass`；有 ACL 增强需求但 conntrack、`aria_acl` 输入、schema、compile 或 apply 未 ready 的 port 必须 `DomainStatus=degraded,effective_action=bypass`，不能中断业务。

多租户字段约束：

- `project_id` 对 tenant-scoped 对象必填，不能只从 port 反推。
- `network_project_id` 用于 shared network 场景，port owner 和 network owner 可以不同。
- `scope = "shared"` 或 `scope = "admin"` 的对象必须由 `neutron-aria-agent` 根据 Neutron RBAC/admin policy 解析后再下发。
- Snapshot 内部引用必须使用 ID，不使用 name。
- Neutron 对象如果支持 `revision_number`，snapshot 必须携带对象级 revision；不支持 revision 的来源必须携带 adapter-local `source_revision` 或在 full resync 中作为 authoritative state 下发。
- `neutron-aria-agent` 必须在下发前丢弃 stale revision；对象级 revision 不可信时，只允许 full resync 重建该对象集合。
- `aria-datapath` 对 unknown project、unknown scoped group 或跨 project 未授权引用返回 domain degraded 或拒绝相关对象 apply。

### 5.3 Snapshot 返回结构

建议返回结构：

```json
{
  "accepted": true,
  "schema_version": "1",
  "agent_mode": "openstack",
  "integration_mode": "coexist",
  "accepted_generation": "compute-01-000001",
  "applied_generation": "compute-01-000001",
  "last_classified_generation": "compute-01-000001",
  "last_feature_ready_generation_by_domain": {
    "acl": "compute-01-000001",
    "qos": null
  },
  "agent_health": "alive",
  "overall_readiness": "degraded",
  "domains": {
    "runtime": {
      "status": "ready",
      "effective_action": "enforce",
      "support_disposition": "supported",
      "applied": 1,
      "removed": 0,
      "error_code": null,
      "message": null
    },
    "groups": {
      "status": "ready",
      "effective_action": "enforce",
      "support_disposition": "supported",
      "applied": 4,
      "removed": 1,
      "error_code": null,
      "message": null
    },
    "conntrack": {
      "status": "ready",
      "effective_action": "enforce",
      "support_disposition": "supported",
      "applied": 1,
      "removed": 0,
      "error_code": null,
      "message": null
    },
    "monitoring": {
      "status": "ready",
      "effective_action": "enforce",
      "support_disposition": "supported",
      "applied": 1,
      "removed": 0,
      "error_code": null,
      "message": null
    },
    "acl": {
      "status": "ready",
      "effective_action": "enforce",
      "support_disposition": "supported",
      "applied": 12,
      "removed": 3,
      "error_code": null,
      "message": null
    },
    "qos": {
      "status": "degraded",
      "effective_action": "enforce",
      "support_disposition": "supported",
      "applied": 1,
      "removed": 0,
      "error_code": "QOS_SHAPING_FALLBACK",
      "message": "egress shaping unavailable on this kernel; applied policing degraded mode"
    }
  }
}
```

Domain status 输出顺序固定为 `runtime -> groups -> conntrack -> monitoring -> acl -> qos`。实现内部可以按其它结构保存，但 API、日志、测试断言和方案文档都按这个顺序表达，避免后续 Rust/Python 两边理解不一致。

Domain status 枚举：

- `ready`：该 domain 成功。
- `degraded`：该 domain 有降级，原 OVS 转发不受该降级影响。
- `blocked`：该 domain 失败，且无法证明状态一致性或无法安全推进 generation。
- `not_requested`：该 domain 本次没有输入、没有功能需求或不在当前请求范围内。

Domain status 不表达是否 bypass、是否 unsupported、是否 ignored optional field，也不表达 Neutron agent 是否 alive。相关信息必须分别放入 `effective_action`、`support_disposition`、`ignored_optional_fields`、`unsupported_features` 和 `AgentHealth`。

`NeutronDomainStatus` 标准样例：

| 场景 | `DomainStatus` | `effective_action` | `support_disposition` | generation 影响 |
| --- | --- | --- | --- | --- |
| 无 ACL enhancement 输入 | `not_requested` | `bypass` | `not_applicable` | 可推进 `accepted_generation` 和 `last_classified_generation`；不更新 `last_feature_ready_generation_by_domain.acl` |
| `aria_acl` binding 指向不存在或不可访问的 policy | `degraded` | `bypass` | `supported` | 可推进 `accepted_generation` 和 `last_classified_generation`；不更新 `last_feature_ready_generation_by_domain.acl` |
| trunk/SR-IOV/direct port 未支持 | `degraded` 或 `not_requested` | `bypass` 或 `no_op` | `unsupported` | 不得假 ready；是否推进 accepted 取决于该 port 是否被请求 enhancement |
| WAL append/commit 失败 | `blocked` | `unchanged` 或 `bypass` | `supported` | 不推进 `accepted_generation`；保留 `last_classified_generation` 对应动作 |
| QoS shaping 不可用但 policing 已应用 | `degraded` | `enforce` | `supported` | 可推进 `last_classified_generation`；不更新 `last_feature_ready_generation_by_domain.qos` |

### 5.4 Aria Ready 与 OVS 转发边界

本文档里的 ready 默认指 Aria security/features ready，不等于 OVS connectivity ready。

必须分开理解两条路径：

| 层级 | 负责组件 | Ready 含义 | 是否由 `neutron-aria-agent` 接管 |
| --- | --- | --- | --- |
| OVS connectivity ready | OVS agent / OVS | tap 已接入 `br-int`，bridge/tunnel/local switching 可转发 | 否 |
| Aria runtime attached | `aria-datapath` + Netlink | tap 上已挂载 eBPF runtime，但默认 inert/bypass | 是，限本机 runtime |
| Aria security/features ready | `neutron-aria-agent` + `aria-datapath` | Neutron snapshot 已 accepted，ACL/QoS 按 feature flags 生效 | 是 |

因此：

- `neutron-aria-agent` 上报 not ready 或 degraded，不会自动让 OVS 停止二层转发。
- 只要 OVS agent 和 OVS pipeline 正常，tap 接入 `br-int` 后 OVS 仍可能转发。
- 不需要 Aria 功能的 Neutron port 可以保持 eBPF bypass。
- 启用 ACL 增强的 port 在 ACL snapshot accepted 前不能标记 Aria ACL ready。
- 启用 ACL 增强但 ACL apply 失败时，Aria ACL domain degraded，并保持 bypass；不能影响 OVS L2 转发。
- Conntrack 失败会阻止状态化 ACL enhancement 宣称 ready；ACL domain 必须 `DomainStatus=degraded,effective_action=bypass`，同时不能阻断 OVS 原有转发，也不能伪装成 Security Group enforcement。
- QoS 失败默认只影响 QoS domain；未来如果定义安全关键模式，必须独立设计。
- Monitoring 失败默认不阻断 OVS 或 ACL 转发；如果 snapshot 承诺统计能力，则 observability status 必须 degraded，不能向上游报告统计 ready。

#### 5.4.1 状态决策表

下面这张表是实现和测试的硬合同。后续代码不能把“没有配置增强能力”和“配置了但失败”混成同一种状态。

| 场景 | port runtime | ACL domain | agent heartbeat | 告警 | OVS 转发 |
| --- | --- | --- | --- | --- | --- |
| port 不属于本 host | `RuntimeAttachmentState=unmanaged_bypass` 或 cleanup | `not_requested` | `alive` | 无 | 不受 Aria 影响 |
| port 属于本 host，但无 `aria_acl` binding | `RuntimeAttachmentState=neutron_bound_pending` 或 `managed_ready`，`effective_action=bypass` | `not_requested` | `alive` | 无 | 保持原 OVS 转发 |
| port 有 `aria_acl` binding，但 policy 不存在或不可访问 | `effective_action=bypass` | `degraded: ACL_POLICY_NOT_FOUND` 或 `ACL_INPUT_INVALID` | `degraded` | `AriaAclBypassDegradedPorts` | 保持原 OVS 转发 |
| ACL policy 输入 schema 错误 | `effective_action=bypass` | `degraded: ACL_INPUT_INVALID` | `degraded` | `AriaAclBypassDegradedPorts` | 保持原 OVS 转发 |
| ACL policy 已 accepted 且 apply 成功 | `effective_action=enforce` | `ready` | `alive` | 无 | OVS 转发叠加 Aria 增强行为 |
| ACL apply 失败 | `effective_action=bypass` | `degraded: ACL_APPLY_FAILED` | `degraded` | `AriaAclBypassDegradedPorts` | 保持原 OVS 转发 |
| 状态化 ACL 需要 conntrack，但 conntrack 不可用 | `effective_action=bypass` | `degraded: CONNTRACK_REQUIRED_UNAVAILABLE` | `degraded` | `AriaAclBypassDegradedPorts` | 保持原 OVS 转发 |
| QoS 失败 | QoS domain `DomainStatus=degraded` 或 `blocked`，`effective_action` 按 domain 决定 | ACL 不受影响 | 默认 `alive`，除非该失败破坏 snapshot/WAL/contract 一致性 | domain 告警 | OVS 基础转发不受影响 |
| WAL append/commit 失败 | 不接受新 generation | `blocked` 或 `degraded`，由 WAL 可修复性决定 | `degraded` | `AriaWalBlocked` | 保持 `last_classified_generation` 对应动作；无 classified state 时保持 bypass |
| UDS socket 不可达 | 不提交新 snapshot | 保持最近一次 classified status | degraded | `AriaSocketPermissionDenied` 或 generation lag | 保持 `last_classified_generation` 对应动作 |

默认规则：

- `bypass` 只能作为 `effective_action`，表示增强能力未启用、被主动关闭或因失败保护原 OVS 转发，不能宣称功能 ready。
- `degraded` 表示有明确的期望输入或运行基础，但未能达成；必须带错误码、affected ports、`effective_action` 和恢复动作。
- `ready` 只能在请求 domain 已持久化且 apply 成功后出现；未请求 domain 必须使用 `not_requested`，不能靠 `ready` 冒充功能生效。
- `blocked` 只用于 WAL/state/capability 这类无法证明一致性的情况；blocked 时不能推进 `accepted_generation`。

### 5.5 错误码

错误码要稳定，便于 `neutron-aria-agent` 上报和排障：

| 错误码 | Domain | 含义 | 处理 |
| --- | --- | --- | --- |
| `SCHEMA_UNSUPPORTED` | runtime | schema 版本不支持 | 拒绝 snapshot，agent degraded |
| `PORT_IFACE_NOT_FOUND` | runtime | Neutron port 对应本机接口不存在 | domain degraded，等待 Netlink 对账 |
| `PORT_IFINDEX_NOT_READY` | runtime | port 接口存在但 ifindex 尚不可用或刚发生变化 | domain degraded，等待 Netlink 对账 |
| `PORT_BINDING_HOST_MISMATCH` | runtime | snapshot port 的 binding_host 与本机 host 不一致 | 拒绝该 port apply，触发 full resync |
| `BPF_ATTACH_DEFERRED_IFACE_MISSING` | runtime | attach 前置检查发现目标 tap 不存在 | 不执行 eBPF attach，等待接口事件 |
| `BPF_ATTACH_STALE_LINK_CLEANUP_FAILED` | runtime | tap 删除后旧 attach/link/qdisc 清理失败 | 记录 warning/degraded，允许新 ifindex preflight 后重新 attach |
| `GROUP_COMPILE_FAILED` | groups | group/address-set 编译失败 | 拒绝相关 port apply |
| `CONNTRACK_APPLY_FAILED` | conntrack | conntrack 开关或 CT config 写入失败 | 状态化 ACL 和 flow 观测 degraded；相关 ACL 必须 `effective_action=bypass` |
| `CONNTRACK_REQUIRED_UNAVAILABLE` | acl | ACL enhancement 请求状态化语义但 conntrack 不可用 | ACL `DomainStatus=degraded,effective_action=bypass`，不启用 ACL feature flag |
| `MONITORING_APPLY_FAILED` | monitoring | monitoring 开关或 stats runtime 初始化失败 | observability degraded，承诺统计时不能报统计 ready |
| `ACL_POLICY_NOT_FOUND` | acl | `aria_acl` binding 指向的 policy 不存在或不可访问 | `DomainStatus=degraded,effective_action=bypass`，不启用 feature flag |
| `ACL_INPUT_INVALID` | acl | `aria_acl` policy/rule/address-set schema 不合法 | `DomainStatus=degraded,effective_action=bypass`，拒绝相关 policy ready |
| `ACL_COMPILE_FAILED` | acl | ACL 规则编译失败 | 拒绝相关 port ACL |
| `QOS_SHAPING_FALLBACK` | qos | shaping 不可用，降级 policing | degraded，不阻塞 ACL |
| `QOS_APPLY_FAILED` | qos | QoS map 写入失败 | qos blocked，不阻塞 ACL |
| `WAL_APPEND_FAILED` | runtime | WAL append 失败 | 尝试 compact 降级修复，失败则 runtime blocked |
| `PINNED_RUNTIME_MISSING` | runtime | pinned map/link 不完整 | 触发 runtime repair 或 full resync |
| `LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_DOMAIN` | runtime | 本机命令试图修改 Neutron-managed domain | 拒绝写入，提示通过 Neutron 修改 |
| `REJOIN_REQUIRES_LOCAL_OVERRIDE_DISCARD` | runtime | break-glass 后重新接管前存在 local override | 进入 rejoin pending，等待管理员确认 |
| `UDS_PEER_UNAUTHORIZED` | api | Unix socket peer uid/gid 不在允许范围 | 拒绝请求，记录 peer credential 和路径 |
| `UDS_PEERCRED_UNAVAILABLE` | api | 无法读取 Unix socket peer credential | 拒绝写路径，status 可返回 degraded |
| `UDS_SCHEMA_MISMATCH` | api | 请求 `schema_version` 不在 capability 支持范围 | 拒绝 snapshot，Python 侧降级并重新握手 |
| `UDS_CAPABILITY_MISMATCH` | api | 请求包含 Rust 不支持的 mandatory field/domain | 拒绝 snapshot，Python 侧停止增量并 full resync |
| `UDS_BODY_TOO_LARGE` | api | 请求体超过本机 contract 的最大 snapshot body | 拒绝 snapshot，Python 侧拆分 port-scoped 或触发 degraded |
| `UDS_CONTRACT_DRIFT` | api | Python 使用的 `neutron-uds-contract.json` 与 Rust artifact 不一致 | 拒绝写路径，要求版本对齐后重试 |
| `UDS_CONTRACT_VERSION_UNSUPPORTED` | api | Python contract version 与 Rust capabilities 不兼容 | 停止写路径，agent degraded，要求升级或回滚 |
| `UDS_ERROR_CODES_HASH_MISMATCH` | api | Python 本地错误码集合与 Rust 返回摘要不一致 | reload contract；仍不一致则停止写路径 |
| `UDS_CONNECT_TIMEOUT` | api | Python 连接 Unix socket 超过 `timeout_ms` | agent degraded，重试 socket，禁止 fallback TCP |
| `UDS_REQUEST_TIMEOUT` | api | UDS 请求超过 `timeout_ms` 未完成 | 当前 snapshot 未 accepted，触发 status check/full resync |
| `UDS_MUTATION_DETACHED` | api | client timeout/disconnect after a mutating UDS request has started | Rust must continue or roll back the detached apply task; Python must status-check and converge by full resync |
| `UDS_AUDIT_WRITE_FAILED` | api | 写入 UDS 审计日志失败 | 写路径 blocked 或 degraded，避免不可追踪 generation |

### 5.6 DELETE 语义

`DELETE /api/v1/neutron/ports/{port_id}` 用于快速清理单个端口：

- 清理该 port 关联的 group/address-set 引用。
- 清理 ACL/QoS 状态。
- 清理 feature flag。
- 不删除其它 port 仍引用的 group。
- 写 `neutron-state.wal` durable delete record。
- 返回 domain status。

删除 API 是优化路径。最终一致性仍依赖下一次 full snapshot。

`PUT /api/v1/neutron/snapshot` 和 `DELETE /api/v1/neutron/ports/{port_id}` 都是 mutating UDS API。Rust 侧必须在 HTTP handler 收到请求后立即交给独立 apply task 执行；客户端 timeout、断连或进程退出不能取消已经开始的 datapath apply。Python 侧收到 `UDS_REQUEST_TIMEOUT` 时不能假设请求未生效，必须先 `GET /api/v1/neutron/status` 对齐 generation/managed_ports，再通过 full resync 收敛。

### 5.7 本机写入保护

当 datapath 进入 OpenStack mode 后，现有本机管理 API 必须识别 Neutron-managed port 或 Neutron-managed instance，并按 `managed_domains` 做 domain 级写入仲裁。

OpenStack mode 包括 `openstack_managed` 和 `openstack_degraded`。通信失败只会进入 degraded，不能自动切到本机可写模式。

对已经出现在该 port/instance `managed_domains` 中的 domain，必须拒绝的本机写入：

- Neutron-reserved group/address-set add/delete/update。
- policy add/delete/batch。
- QoS add/delete，前提是 `qos` 已被列入 `managed_domains`。
- mirror add/delete，前提是 `mirror` 已被列入 `managed_domains`。
- config set 中影响被 Neutron 纳管 domain 的开关。
- 任何会改变 Neutron-managed port datapath policy 的操作。

允许的本机操作：

- health、status、stats、metrics。
- diagnose。
- trace start/stop/list/flush，除非未来显式把 `trace` 列入 `managed_domains`。
- drops list/flush。
- tcprt query/list。
- 未列入 `managed_domains` 的本机持久 domain 写入，例如仅 `managed_domains=["acl"]` 时，本机 QoS/Mirror 写入仍按本机模式处理。

拒绝策略：

- 返回 `409 Conflict` 或等价错误。
- 错误码使用 `LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_DOMAIN`。
- 错误信息必须提示“该端口/实例的该 domain 由 Neutron 管理，请通过 Neutron 修改配置”。
- 只读和临时排障操作不能写入 Neutron WAL，也不能改变 `last_classified_generation`。

本机持久写入只允许在 `local_break_glass` 或 `local_standalone` 状态下执行。`local_break_glass` 写入必须进入 local override WAL。重新接管时默认丢弃 local override，并由 Neutron full snapshot 重建托管 domains。

## 6. neutron-aria-agent 设计

### 6.1 建议文件结构

建议新增 Python 子项目：

```text
neutron-aria-agent/
├── pyproject.toml
├── neutron_aria_agent/
│   ├── __init__.py
│   ├── agent.py              # service launcher, heartbeat, main loop
│   ├── config.py             # oslo config
│   ├── neutron_client.py     # Neutron RPC/full resync adapter
│   ├── local_client.py       # datapath snapshot API client
│   ├── state.py              # local projected state and generation
│   ├── translator.py         # Neutron objects -> Aria snapshot
│   ├── status.py             # apply status, degraded reason, heartbeat payload
└── tests/
    ├── test_translator_acl.py
    ├── test_translator_qos.py
    └── test_snapshot_client.py
```

### 6.2 主要模块职责

| 模块 | 职责 |
| --- | --- |
| `agent.py` | 启动服务、注册 agent、heartbeat、resync 调度、事件消费 |
| `config.py` | 读取 Neutron/Aria 配置，如 host、local socket、resync interval |
| `neutron_client.py` | 封装 Neutron RPC、full resync、port/QoS 拉取和显式 ACL enhancement 输入 |
| `local_client.py` | 调用 datapath snapshot/status/capabilities/delete API |
| `state.py` | 保存本 host 投影状态、generation、last status |
| `translator.py` | 把 Neutron 对象翻译成 Aria snapshot |
| `status.py` | 把 domain apply status 转成 agent alive/degraded 上报 |

### 6.3 运行循环

`neutron-aria-agent` 的主循环：

1. 启动后加载配置。
2. 检查本机 datapath health。
3. 向 Neutron 注册 agent。
4. 执行 full resync。
5. 生成 full snapshot。
6. 调用 `PUT /api/v1/neutron/snapshot`。
7. 保存 generation 和 apply status。
8. 进入事件循环。
9. 收到 port、ACL enhancement 或 QoS 事件后，重新计算受影响端口。
10. 下发 port-scoped 或 host-scoped snapshot。
11. 周期性执行 full resync 修正漂移。

### 6.4 Full Resync 触发条件

以下情况必须触发 full resync：

- agent 启动。
- Neutron RPC reconnect。
- Neutron 事件队列溢出。
- local_generation 和 datapath status 不一致。
- `aria-datapath` 重启后 `last_classified_generation` 缺失。
- Netlink 对账发现本机接口集合和 Neutron binding 不一致。
- snapshot apply 返回 `PINNED_RUNTIME_MISSING` 或 runtime blocked。
- 周期性 resync interval 到期。

### 6.5 事件合并

Neutron 事件可能短时间内大量到达。`neutron-aria-agent` 应合并事件：

- port update：按 port_id 合并，只保留最后状态。
- ACL enhancement update：找出本 host 相关 ports，批量重算。
- QoS update：找出绑定该 policy 的 ports/network。
- 其它本机能力 update 不进入 Neutron event merge；如果未来接入 Mirror/TCPrt，需要另起独立 translator 与事件语义。

事件合并窗口建议从 100ms 到 500ms 起步，避免每条规则都触发一次 map apply。

## 7. aria-datapath 改造点

### 7.1 API 类型

在 `api` crate 增加 Neutron snapshot 相关类型：

- `NeutronSnapshotRequest`
- `NeutronPortEntry`
- `NeutronGroupEntry`
- `NeutronAclPolicyEntry`
- `NeutronQosPolicyEntry`
- `NeutronFeatureFlags`
- `NeutronSnapshotResponse`
- `NeutronDomainStatus`
- `NeutronStatusResponse`

### 7.2 API Handler

在 `agent` crate 增加 handler：

- `PUT /api/v1/neutron/snapshot`
- `DELETE /api/v1/neutron/ports/{port_id}`
- `GET /api/v1/neutron/status`

建议放在独立模块，避免污染现有逐条 CRUD handler：

```text
agent/src/neutron_api.rs
agent/src/neutron_api.rs
```

### 7.3 Apply Engine

Snapshot apply 必须按固定顺序执行：

1. 校验 schema、host、integration_mode、generation。
2. 对 snapshot 中的 ports 做 Neutron-managed preflight。
3. 解析 preflight 通过的 port 到本机 instance/tap_id/ifindex。
4. 写 WAL intent。
5. 编译 group/address-set/port-set。
6. 清理被 snapshot 覆盖端口上的旧状态。
7. apply groups。
8. apply Conntrack / Monitoring 基础 runtime 要求。
9. apply ACL。
10. apply QoS。
11. 写 runtime config。
12. 写 WAL commit。
13. 更新 generation/status。
14. 返回 domain status。

WAL 顺序以本节为准：OpenStack snapshot apply 使用 `WAL intent -> datapath apply -> WAL commit -> generation/status`。不能使用“先 apply 完整 datapath，再单次写 WAL”的语义；那会在 WAL 失败时造成内存/eBPF 状态和持久状态分裂。

当前 `attach + acl` 实现进一步固定以下边界：preflight/plan 完成后先
fsync intent，HTTP 只返回 `pending`，此时 `accepted_generation` 和
`applied_generation` 仍指向上一个 commit；后台任务持有同一把 apply lock
执行 datapath apply。commit fsync 成功后立即发布 RAM，之后的
`after_commit` return-error 只记录告警。commit 前失败或 commit append
失败时恢复 attach、清理受影响 ACL 并标记 `blocked/bypass`，保留 pending
等待显式 recovery，不实现 QoS/Mirror 功能。

`WAL intent` 至少记录将要覆盖的 generation、affected ports、affected projects、scoped object keys、domain set 和 expected object revision 摘要。`WAL commit` 至少记录实际完成的 domain status、compacted state hash 和最终 accepted/applied generation 候选值。

OpenStack 模式下要把两个动作拆开：

1. 物理 runtime attach：Netlink 发现 tap 后，`aria-datapath` 可以先 attach eBPF runtime，并保持 inert/bypass。
2. Neutron-managed feature apply：只有 snapshot 通过 preflight 后，才能启用 ACL/QoS 或把 port 标记为 Aria ready。

inert/bypass runtime 的硬边界：

- 可以 attach 物理 eBPF program、建立 tap/ifindex/tap_id mapping、维护 pinned link inventory。
- 可以写入只用于 runtime 发现和健康检查的基础 metadata。
- 不得写入 Neutron-managed group/ACL/QoS feature map。
- 不得启用任何 port-scoped feature flag。
- 不得推进 `accepted_generation`、`last_classified_generation` 或 Neutron domain ready。
- 默认行为是 bypass，不改变 OVS L2 connectivity；如果该 port 已启用 ACL 增强但 snapshot 尚未 accepted，则只能上报 ACL degraded，不能冒充 Aria ACL ready，也不能阻断业务。
- pinned runtime 可以存在，但 pinned runtime 存在不等于 Neutron-managed state accepted。

因此，Neutron-managed preflight 必须在任何 feature map 写入、Neutron-managed state accepted、feature flag 启用或 ready 推进前执行。对于 Netlink 已经提前 attach 的 inert runtime，preflight 不是重新证明“可以 attach”，而是证明“这个 tap 可以承载本次 Neutron-managed snapshot”：

- `binding_host` 必须等于本机 host。
- 目标环境中 `if_name` 必须匹配本机实际存在的 tap 接口。
- 目标环境的 tap 口直接挂到 OVS `br-int`，不期望存在 `qvo`、`qvb`、`veth` 中间设备。
- `ifindex` 如果由 snapshot 提供，必须和本机 Netlink 查询结果一致。
- `ifindex` 如果未提供，必须能通过 Netlink 从 `if_name` 查出。
- 接口不存在时返回 `PORT_IFACE_NOT_FOUND` 或 `BPF_ATTACH_DEFERRED_IFACE_MISSING`。
- 接口存在但 ifindex 暂不可用或刚发生变化时返回 `PORT_IFINDEX_NOT_READY`。
- preflight 失败的 port 不进入 groups/ACL/QoS feature apply。
- preflight 失败不能写入 Neutron accepted datapath state，也不能把 port 标记 Aria ready，只能写入 degraded status。
- Netlink 后续发现接口 ready 后，由 `neutron-aria-agent` 重新下发 port-scoped snapshot。

原则：

- group 是 ACL/QoS 的共同基础，不能绕过。
- conntrack 是 Aria ACL 状态化、连接跟踪、fast-path 和 flow 统计的运行基础；它不是 Neutron ACL mapping 输入，但状态化 ACL enhancement 需要它 ready。
- monitoring 是 ACL/QoS/flow/group 统计基础；如果承诺统计可用，monitoring 失败必须进入 observability degraded，不能上报统计 ready，但默认不阻断 OVS 或 ACL 转发。
- ACL 是 enhancement domain；失败时 domain degraded，并保持 bypass。
- QoS 是 independent enhancement domain，失败不能影响 OVS L2 转发。
- runtime/WAL 是 Aria enhancement 的基础 domain；失败只影响 Aria accepted/ready，不影响 OVS connectivity。
- apply 必须支持重放。
- 删除 port 必须清理旧 map entry，避免 orphan。

### 7.3.1 Fragment tracking 观测边界

Fragment tracking 的实现级观测已经接入现有 `/metrics`：

- `aria_fragment_events_total` 按唯一 runtime `pin_path`、`family` 和 `event`
  输出；稳定 event 为 `first`、`non_initial`、`hit`、`miss`、`expired`、
  `stale`、`inserted`、`update_failed`、`invalid_l4` 和 `overlap`。共享
  managed runtime 只聚合一次，不能按 tap 重复累计。
- `aria_fragment_context_occupancy`、`aria_fragment_context_max_entries` 和
  `aria_fragment_context_pressure` 分别输出 IPv4/IPv6 LRU 的实际占用、内核
  报告容量和两者比值。eBPF LRU 不报告逐次淘汰，因此不得推导或发布
  eviction counter。
- pinned map open、read 或 info 任一严格读取失败时，受影响的 series 必须
  省略并写 warning，不能用 `0` 冒充成功采样。
- `invalid_l4` / `fragment-invalid-l4` 只表示 IP 和首片元数据已经验证、但
  TCP/UDP 首片 transport header 不完整；stored-context invalidity 与通用
  `malformed-ip` 保持独立分类。该分类不改变原 TC drop 结果。

以上只表示代码与 hosted CI 中的观测能力已经实现，不表示生产激活或现场
验证完成。两个发布配置仍保持 `fragment_tracking_field_verified=false`、
`[fragment_tracking].enabled=false`、每族容量 `8192`、IPv4/IPv6 timeout
`30/30` 秒；真实 privileged tap/fragment 证据仍是 `deferred/pending`。在
现场证据完成前，不得把该能力描述为 production ready。

### 7.4 WAL 语义

新增 WAL entry 类型建议：

- `NeutronSnapshotApplied`
- `NeutronPortDeleted`
- `NeutronStatusUpdated`

WAL 内容至少包含：

- schema_version
- local_generation
- host
- affected_ports
- affected_projects
- scoped_object_keys
- domain_status
- compacted state hash

当前实现中的 WAL 失败语义：

1. intent append/fsync 失败：拒绝请求，不建立 RAM pending，不推进
   accepted/applied。
2. datapath mutation 后 commit append/fsync 失败：按上一个 committed
   runtime 恢复 attach，scrub 受影响 ACL 为 bypass，保留失败 generation
   为 pending，并进入 `blocked_recovery_required`。
3. blocked recovery 状态能写入 WAL 时，重启后继续保留该 blocked pending；
   若该写入也失败，RAM 使用 `wal_status=recovery_commit_failed`，原始
   durable intent 负责启动恢复。
4. Python 发现 recoverable authority 时，即使 desired hash 相同也先调用
   recover-pending；失败时保持本地 pending/degraded。

WAL compact/rotation 尚未实现，继续由 `REVIEW-OPS-019` 跟踪，不能写成
commit 失败后的现有自动修复能力。

崩溃恢复矩阵：

| 持久状态 | 启动恢复语义 | generation 处理 |
| --- | --- | --- |
| 无 intent、无 commit | 忽略未开始的 apply，按上一个 compact state 和 committed WAL replay | 不推进 |
| 有 intent、无 commit | 视为上次 apply 未完成，先 scrub/repair affected scoped objects，再等待或触发 full snapshot 重放 | 不推进 `accepted_generation` |
| 有 intent、datapath 可能部分写入、无 commit | 标记 `runtime.degraded`，对 affected domains 做 map/state 对账；无法证明一致时要求 full resync | 不推进 `accepted_generation`，`applied_generation` 只可用于诊断 |
| 有 commit、status/RAM 未写完 | valid commit 是最终结果；从 committed generation/domain status 重建 RAM/status，随后做 runtime reconcile | 恢复 commit 中的 `accepted_generation`，不得由旧 RAM 写回更低 generation |
| 存在 `local-override.wal` 且 Neutron reconnect | 进入 `rejoin_pending`，归档 local override，等待 Neutron full snapshot 重建托管 domains | 不 replay local override 到 OpenStack-managed state |
| compact state hash 不匹配 | 停止自动接管，返回 `runtime.blocked`，要求人工介入或 full rebuild | 不推进 |

`有 commit、status/RAM 未写完` 先通过 WAL record hash/格式校验恢复 durable
state；后续 runtime reconcile 可以把 authority 降级，但不能把旧 RAM
generation 追加成回滚 commit。最小校验包括：

- `neutron-state.wal` 中存在同一 `local_generation` 的完整 commit entry。
- commit entry 的 `compacted state hash` 与当前 compact state 或 replay 后 state 一致。
- commit entry 记录的 enhancement domains 至少包含 `runtime`、`groups`，以及本次 snapshot 请求的 `acl/qos/conntrack/monitoring`。
- 请求的 enhancement domains 状态必须是 `ready`、`degraded`、`blocked` 或 `not_requested` 之一，且带对应 `effective_action`；不能缺失、不能用组合字符串、不能伪造 ready。
- affected ports 的 tap/ifindex 当前仍可通过 Netlink 校验；如果 VM reboot/tap recreate 导致 ifindex 变化，只能恢复为 degraded，等待新的 port-scoped snapshot。
- pinned map/link inventory 与 state 中的 numeric ID 映射一致；不一致时返回 `PINNED_RUNTIME_MISSING` 或 `runtime.blocked`，不得推进 accepted。
- 如果以上任一条件不能证明一致，必须保持 `accepted_generation` 不变，并触发 full resync。

WAL 物理布局必须避免 Neutron 托管状态和 break-glass 本机覆盖状态混写：

```text
/var/lib/aria-agent/<instance>/state.json
/var/lib/aria-agent/<instance>/state.wal
/var/lib/aria-agent/<instance>/neutron-state.wal
/var/lib/aria-agent/<instance>/local-override.wal
/var/lib/aria-agent/<instance>/local-override.archive/
```

默认规则：

- `state.wal` 继续服务现有 standalone/local 模式，保持向后兼容。
- `neutron-state.wal` 只记录 `source = "neutron"` 的 snapshot/delete/status。
- `local-override.wal` 只记录 `local_break_glass` 下的本机持久写入。
- `openstack_managed` 和 `openstack_degraded` 不写 `local-override.wal`。
- `rejoin_pending` 下不得追加新的 `local-override.wal`。
- 重新接管时先把 `local-override.wal` 移入 `local-override.archive/`，再由 Neutron full snapshot 重建托管 domains。
- replay 顺序为 compact `state.json` -> committed `neutron-state.wal` -> incomplete intent recovery；只有处于 `local_break_glass` 或 `local_standalone` 时才 replay `local-override.wal`。

### 7.5 Netlink 与接口对账

Netlink 是必选支撑能力：

- Standalone 模式下，本机接口新增仍可按 `iface_pattern` 自动 attach。
- OpenStack 模式下，本机 tap 新增可以触发 physical eBPF runtime attach。
- OpenStack 模式下，Netlink attach 后默认 feature flags 全关，runtime 处于 inert/bypass，不执行 ACL/QoS。
- OpenStack 模式下，Netlink 不能仅凭 tap 名称创建 Neutron-managed policy state。
- OpenStack 模式下，Neutron snapshot 才能把 observed tap 提升为 Neutron-managed port，并按 feature flags 启用 ACL/QoS。
- 本机接口删除时，标记对应 port runtime degraded。
- ifindex 变化时，刷新 tap/ifindex/tap_id 映射。
- ifindex 变化时，旧 ifindex 上的 pinned runtime 不能直接复用到新接口，必须重新校验 tap_id/ifindex 映射。
- feature apply 前必须通过 Netlink 或等价系统接口确认 tap 已存在。
- 周期性对账时比较 Neutron binding ports 和本机 managed instances。

不能只依赖 Neutron RPC，因为 VM 生命周期和接口生命周期不是同一个事件源。

OpenStack mode 下建议使用以下 tap 状态机：

| 状态 | 触发条件 | eBPF attach | 功能启用 | Ready 语义 |
| --- | --- | --- | --- | --- |
| `observed_tap` | Netlink 发现 tap | 可 attach | 全关 / bypass | 不认为是 Neutron ready |
| `unmanaged_bypass` | tap 不属于本 host Neutron projected state | 可保留或清理 | 全关 / bypass | 不上报 Aria ready |
| `neutron_bound_pending` | Neutron 确认 port 属于本 host，但 snapshot 尚未 accepted | 已 attach 或等待 attach | 全关 / bypass | 不能 Aria ready |
| `managed_ready` | snapshot accepted，请求的 enhancement domains 有明确终态 | attach 必须存在 | 按 feature flags 启用 | Aria ready |
| `managed_degraded` | tap 删除、ifindex 变化、WAL 失败、ACL/conntrack/monitoring 失败 | 视情况 cleanup/repair | 失败 domain `DomainStatus=degraded` 或 `blocked`，`effective_action=bypass`；不阻断 OVS | 不能宣称对应功能 ready |

这个状态机的核心边界：

- tap 生命周期由 Netlink 驱动 physical attach。
- 功能启用由 Neutron snapshot 驱动。
- attach 可以提前，功能不能提前。
- ready 不能提前。
- Neutron 权威不能被本机 tap 事件绕过。

### 7.6 Aria Ready 与 OVS 转发

OVS 转发和 Aria ready 是两套状态，不允许混写。

| 场景 | OVS L2 转发 | Aria datapath 行为 |
| --- | --- | --- |
| tap 出现但还不是 Neutron-managed port | OVS 可继续转发 | attach 后 inert/bypass |
| Neutron 确认本 host port，但没有 Aria 功能需求 | OVS 可继续转发 | bypass |
| ACL enhancement 尚未 accepted | OVS 本身不被 `neutron-aria-agent` 停止 | ACL bypass，不能 Aria ACL ready |
| ACL enhancement apply 失败 | OVS 本身继续转发 | ACL `DomainStatus=degraded,effective_action=bypass` |
| Conntrack apply 失败 | OVS 本身继续转发 | conntrack/flow 观测 degraded；状态化 ACL enhancement 同步 degraded+bypass，不能宣称 ready |
| QoS apply 失败 | OVS 可继续转发 | QoS domain degraded |
| Monitoring 失败 | OVS 可继续转发 | observability degraded；承诺统计时不能统计 ready |

不能把 Aria ready 当作 OVS connectivity ready。当前阶段 Aria 只增强 OVS，任何 Aria domain 未 ready 都只能影响 Aria 的功能状态和告警，不能停止原有 OVS 转发。安全组替代和业务中断策略是未来独立模式，不进入当前 `v0.9-neutron-agent` 默认路线。

### 7.7 Pinned Maps

Pinned Maps / pinned links 是必选支撑能力：

- `aria-datapath` restart 后应复用现有 pinned runtime。
- pinned runtime 不完整时，返回 `PINNED_RUNTIME_MISSING`。
- 能 repair 的 runtime 由 `aria-datapath` repair。
- 不能 repair 的 runtime 由 `neutron-aria-agent` full resync 修正。

## 8. 功能映射

### 8.1 Group / Address-set

Group 是 Aria ACL/QoS 的必选编译中间层。当前阶段只从 `aria_acl` Neutron service plugin 产生的显式 ACL enhancement 对象、QoS 规则和必要的 port 归属关系生成 group/address-set，不从 Neutron Security Group 或 remote group 自动投影。历史 tag + 本机 mapping 只能作为 lab/bootstrap/迁移辅助输入，不作为生产主路径。

来源：

- `aria_acl` policy/rule/address-set 中的 CIDR / address-set。
- 显式 ACL enhancement group。
- QoS match 所需 port/group 归属。

执行语义：

- 每个 group 必须有稳定 ID。
- 每个 group 的稳定 ID 必须从 scoped object key 派生，不能只用 display name。
- group 可以是 host-scoped，也可以是 port-scoped。
- 删除 port 时释放只被该 port 引用的 group/address-set。
- 删除 port 时按 scoped object key 释放引用，不能影响其它 project 的同名或同 ID 缓存对象。
- 不允许 ACL 直接绕过 group 写 map。

### 8.2 ACL Enhancement

当前阶段只接受显式 ACL enhancement 输入；如果没有显式输入，该 port 保持 bypass：

正式产品显式输入源固定为：

1. `aria_acl` Neutron service plugin/API/DB 中的 `aria_acl_policy`、`aria_acl_rule`、`aria_acl_address_set` 和 `aria_acl_binding`。
2. `neutron-aria-agent` 通过 Neutron 读取本 host port 的 effective ACL，编译为 snapshot 中的 per-port ACL enhancement payload。
3. policy 内部只表达 Aria 传统 ACL 维度：src/dst `explicit_acl_group` 或 CIDR、protocol、direction、port range、allow/drop action。

这是独立的 Neutron northbound，但不是 Security Group projection。普通租户不能直接调用 Aria，也不能通过 Neutron Security Group 间接生成 Aria ACL。`fixture` 输入仅用于 CI/smoke；历史 tag + 本机 mapping 只允许作为 lab/bootstrap/迁移辅助，并且不能成为生产控制面契约。

Aria 执行语义：

- 当前阶段只做 ACL enhancement，不替代 Neutron Security Group enforcement；目标环境没有原 SG enforcement 时，不能因为 SG 输入缺失而阻断 OVS 转发。
- 未 materialize 或未 ready 时默认 `effective_action=bypass`，并按原因返回 `DomainStatus=not_requested` 或 `degraded`，不影响 OVS 转发。
- rule 可以表达 allow/drop enhancement，但不能把未匹配流量默认 drop 作为当前阶段语义。
- 多个显式 ACL enhancement policy 按 additive 合并。
- 同名 `explicit_acl_group` 在不同 project 中必须完全隔离。
- 当前阶段不做 remote group 展开。
- 当前阶段不做 anti-spoof 或 port security enforcement。
- 当前阶段不读取 allowed address pairs，也不把 fixed IP/MAC 转换成 ACL 或 anti-spoof 规则。
- 当前阶段不要求生成 DHCP、metadata、ARP、IPv6 NDP 特殊 allow；默认 bypass 必须保护原 OVS 转发。

第一阶段必须支持：

- `aria_acl` policy/rule/address-set/binding 的最小 CRUD/read path。
- `NeutronAclSource` 从 Neutron 生成 effective ACL index。
- IPv4 ingress / egress。
- TCP / UDP / ICMP。
- remote CIDR。

暂缓：

- Security Group projection。
- remote group 展开。
- anti-spoof / port security enforcement。
- 本地 `ariactl` 直接创建 OpenStack 托管 ACL northbound。
- 全局策略中心。

### 8.3 QoS

Neutron 输入：

- network-level QoS policy。
- port-level QoS policy。
- bandwidth limit rule。
- minimum bandwidth rule。
- DSCP marking rule。

Aria 执行语义：

- port-level QoS 覆盖 network-level QoS。
- QoS policy 必须带 owner project 和 scope。
- shared QoS policy 由 `neutron-aria-agent` 解析成 port effective policy。
- egress 优先 shaping。
- ingress 不支持 shaping 时降级 policing。
- 降级必须进入 apply status。
- policy 删除后清理 token bucket。

第一阶段必须支持：

- per-port bandwidth limit。
- egress shaping。
- ingress policing 降级。
- policy 更新幂等重放。

暂缓：

- minimum bandwidth 调度保证。
- DSCP marking。
- Nova scheduler bandwidth guarantee 联动。

### 8.4 暂不接入 Neutron 的既有能力

这些能力代码保留，但不进入 `neutron-aria-agent` 暴露面：

- `mirror`
- `tcprt`
- `trace`
- `drops`
- `ssl`
- `diagnose`
- `service chain`
- 通用 `stats/metrics`

约束：

- 不删除代码。
- 不新增 Neutron extension。
- 不新增 Neutron RPC topic。
- 不新增 tenant API。
- 不参与 snapshot blocking domain。
- 不参与 Neutron snapshot、translator、feature flag、status domain、feature gate 或 deployment smoke。
- 不影响 Neutron port binding、ACL、QoS apply 成败。
- 只读观测和临时排障能力可以由本机管理员使用。
- 临时排障状态不进入 WAL，不参与 generation。
- 任何会改变 Neutron-managed domain policy 的本机持久写操作必须被拒绝；未列入 `managed_domains` 的 domain 不受该拒绝规则影响。
- 如果未来要把 Mirror 或 TCPrt 接入 Neutron，需要另起独立设计，重新定义 northbound 输入、权限、status domain、smoke 和回滚策略。

## 9. 数据流

### 9.1 启动 Full Resync

1. `neutron-aria-agent` 启动。
2. 检查 datapath health。
3. 向 Neutron 注册 agent。
4. 拉取本 host 绑定 ports。
5. 拉取相关 ACL enhancement inputs 和 QoS policies。
6. 查询本机 datapath status。
7. 对比 local_generation 和 last_classified_generation。
8. 生成 full snapshot。
9. 调用 `PUT /api/v1/neutron/snapshot`。
10. 记录 apply status。
11. heartbeat 上报 `AgentHealth=alive` 或 `degraded`。

### 9.2 Port Create / Bind

1. Neutron port 绑定到本 host。
2. `neutron-aria-agent` 收到 port update。
3. 判断本机接口是否存在。
4. 接口存在且 Neutron-managed preflight 通过时生成 port-scoped snapshot。
5. 接口不存在时标记 runtime degraded，等待 Netlink 对账。
6. Netlink 发现接口后触发重算。
7. 下发 snapshot。
8. 成功后 port 对应 Aria runtime ready。

Fail-safe 规则：

- 新 port 在没有 accepted snapshot 前不能被标记为 Aria ready。
- Aria ACL 尚未 ready 时，该 host 必须保持 ACL domain degraded，但不能阻断 OVS 转发。
- 对已经 attached 但没有 matching Neutron ACL enhancement 的 port，默认保持 bypass，除非未来显式进入 Security Group replacement mode。
- `PORT_IFACE_NOT_FOUND` 只能让 runtime degraded，不能自动变成本机可写。
- `BPF_ATTACH_DEFERRED_IFACE_MISSING` 时不得尝试 feature apply，也不得写 accepted generation。
- tap 出现前，`aria-datapath` 只能记录 degraded status，不能把该 port 加入 ready 状态。
- N3 之前不得在目标环境全局切换 OVS 转发或 SG/firewall flow；当前阶段只验证 Aria 增强失败时 OVS 转发保持不变。

### 9.3 Port Delete / Unbind

1. Neutron port 从本 host 删除或迁走。
2. `neutron-aria-agent` 调用 `DELETE /api/v1/neutron/ports/{port_id}`。
3. `aria-datapath` 清理该 port 的 group/ACL/QoS。
4. 释放只被该 port 引用的 group/address-set。
5. 写 `neutron-state.wal` durable delete record。
6. 返回 domain status。
7. 下一次 full snapshot 校准最终状态。

### 9.4 VM Migration / Port Rebind

虚机迁移本质上是 Neutron port binding host 从旧 compute host 切换到新 compute host。Aria 不参与 Nova/Neutron 的迁移编排，只消费 Neutron binding 结果并在本机 materialize datapath state。

关键原则：

- Neutron 的 `binding_host` 是迁移归属的权威来源。
- 每个 `neutron-aria-agent` 只处理 `binding_host == local_host` 的 ports。
- Snapshot 中的 `ports[].binding_host` 必须和本机 host 匹配，否则 `aria-datapath` 拒绝该 port apply。
- `port_id` 全局唯一，但本机状态必须按 `binding_host + port_id + source_revision` 判断新旧。
- 迁移过程不要求旧 host 和新 host 直接通信；最终一致性靠 Neutron event + full resync。

旧 host 流程：

1. 旧 host 的 `neutron-aria-agent` 收到 port update，发现该 port 不再绑定本 host。
2. 将该 port 从本机 projected state 删除。
3. 调用 `DELETE /api/v1/neutron/ports/{port_id}`。
4. `aria-datapath` 清理该 port 的 ACL/QoS 和 port-scoped group/address-set 引用。
5. 只释放 refcount 归零的 scoped object，不影响同 host 其它 port，也不影响其它 project 的同名对象。
6. 写入 `neutron-state.wal`。
7. 下一次 full resync 再次确认本 host 不应存在该 port。

新 host 流程：

1. 新 host 的 `neutron-aria-agent` 收到 port update，发现该 port 绑定到本 host。
2. 将该 port 加入 projected state。
3. 查询本机接口是否已经出现。
4. 如果接口存在且 Neutron-managed preflight 通过，生成 port-scoped snapshot 并下发。
5. 如果接口尚未出现，标记 `PORT_IFACE_NOT_FOUND`，agent degraded，等待 Netlink 对账。
6. Netlink 发现接口并确认 ifindex ready 后，重新生成 port-scoped snapshot。
7. Snapshot apply 成功后，该 port 的 Aria runtime 才能 ready。

乱序、重复和事件丢失处理：

- port update、unbind、bind event 都必须按 `source_revision` 或 Neutron revision number 去重。
- 旧 revision 不能覆盖新 revision。
- 同一 port 的多次 event 合并时，只保留最后的 `binding_host` 结果。
- 如果旧 host 没收到 unbind event，周期 full resync 会发现本 host 不再拥有该 port，并触发本地 delete。
- 如果新 host 没收到 bind event，周期 full resync 会发现本 host 应拥有该 port，并触发 snapshot apply。
- `DELETE /api/v1/neutron/ports/{port_id}` 必须幂等，port 不存在时返回成功状态或 no-op status。

Fail-safe 规则：

- 新 host 在 port snapshot accepted 前不能上报该 port ready。
- 当前阶段 Aria 不接管 SG enforcement；新 host 上该 port 未 ready 时不能把 Aria enhancement 状态报为 ready，但 OVS 转发必须保持不变。
- 对 Aria-managed 但 policy 尚未 materialize 的 port，默认 bypass，除非未来显式进入 Security Group replacement mode。
- 旧 host 清理失败时必须进入 degraded，并在下一次 full resync 继续重试。
- 新旧 host 同时短暂存在同一 `port_id` 的状态时，以 Neutron 当前 `binding_host` 为准；旧 host 不再收到本机流量后必须清理，不能长期保留 stale map entry。

迁移验收：

- live/cold migration 后，旧 host 不再保留该 port 的 ACL/QoS state。
- 新 host 接口出现后能自动 apply port-scoped snapshot。
- 旧 host 丢失 unbind event 时，full resync 能清理 stale port。
- 新 host 丢失 bind event 时，full resync 能补齐 port state。
- 重复 migration event 不产生重复 group/rule/qos。
- event 乱序时旧 revision 不覆盖新 binding_host。

### 9.5 VM Restart / Tap Recreate

虚机重启时，Neutron port 的 `binding_host` 通常不变，但本机 tap 可能被删除后重新创建。这个场景会影响已经 attach 在旧 netdev 上的 eBPF 程序。

影响判断：

- 旧 tap netdev 被删除后，挂在旧 netdev 上的 XDP/TC attach 会随 netdev 生命周期失效。
- 旧 ifindex 失效，即使新 tap 使用同一个 `if_name`，也通常会得到新的 ifindex。
- pinned maps 可以保留，但 pinned link 或旧 ifindex/tap_id 映射不能直接认为仍然有效。
- 对旧 netdev 做 detach、map 更新或 link 查询时，可能出现 `ENODEV`、`ENOENT`、`No such device`、`Link not found` 这类错误；这些是可预期生命周期错误，不应导致进程崩溃。

处理流程：

1. Netlink 收到旧接口 `RTM_DELLINK` 或周期对账发现 ifindex 消失。
2. `aria-datapath` 标记该 port runtime degraded。
3. 清理旧 ifindex -> tap_id 映射。
4. 尝试清理旧 pinned link/qdisc/attach state；如果内核已自动删除，记录 no-op cleanup。
5. 保留 Neutron desired state、scoped object、WAL 和 generation，不把该 port 当作 Neutron 删除。
6. Netlink 收到新接口 `RTM_NEWLINK`，按 `if_name` 匹配原 Neutron port。
7. 重新查询 ifindex，执行 Neutron-managed preflight。
8. preflight 通过后确认或重新 attach eBPF inert runtime，并重新 apply port-scoped snapshot。
9. apply 成功后该 port runtime 回到 ready。

Fail-safe 规则：

- tap 删除到新 tap ready 之间，agent 必须 degraded。
- 新 tap 未创建前不得尝试 eBPF attach。
- 新 tap 已创建但 ifindex 尚不稳定时返回 `PORT_IFINDEX_NOT_READY`。
- 旧 ifindex 的 cleanup 失败不能阻止新 ifindex attach，但必须记录 degraded reason 和 cleanup warning。
- 不能因为 tap 删除就进入 `local_standalone` 或允许本机持久写入。
- 不因为 tap 重建而清空 Neutron desired state；desired state 仍由 Neutron snapshot/full resync 决定。

验收：

- VM reboot 删除旧 tap 后，agent 进入 degraded，不崩溃。
- 旧 ifindex 上的 stale attach/link cleanup 是幂等的。
- 新 tap 以相同 `if_name`、新 ifindex 出现后，自动重新 attach 并恢复 ready。
- tap 删除期间不会写 accepted datapath state。
- trace 等临时排障状态不要求恢复；ACL/QoS 必须按 Neutron desired state 恢复。

### 9.6 ACL Enhancement Update

1. 显式 ACL enhancement 输入更新。
2. `neutron-aria-agent` 找出本 host 受影响 ports。
3. 生成受影响 ports 的 snapshot。
4. `aria-datapath` 先更新 group/address-set，再更新 ACL enhancement。
5. 成功后更新 generation/status。

当前阶段不处理 Neutron Security Group event，不展开 remote group，也不做 anti-spoof。相关能力如果未来需要，必须作为独立阶段重新设计和验收。

### 9.7 QoS Update

1. Neutron QoS policy 更新。
2. 找出 port-level 或 network-level 受影响 ports。
3. 按 port-level 覆盖 network-level 计算最终 QoS。
4. 生成 snapshot。
5. `aria-datapath` apply QoS。
6. shaping 不可用时返回 degraded 状态。

### 9.8 既有本机能力更新边界

Mirror 和 TCPrt 不进入当前 Neutron snapshot 更新路径：

- 本阶段不监听 Neutron 里的 Mirror/TCPrt 事件。
- 本阶段不生成 `mirror` 或 `tcprt` snapshot domain。
- 本阶段不把 Mirror/TCPrt 状态写入 Neutron agent heartbeat 或 feature smoke。
- 本机管理员只读观测和临时排障能力可以保留，但不能改变 Neutron-managed domain 的持久 policy。
- 如果未来要接入 Mirror/TCPrt，必须新增独立 northbound 输入、权限模型、domain status、smoke 和回滚策略。

### 9.9 Agent Restart

`aria-datapath` 重启：

1. 复用 pinned runtime。
2. replay WAL 或加载 compact state。
3. 恢复 status。
4. `neutron-aria-agent` 检查 last_classified_generation。
5. generation 不一致时 full resync。

`neutron-aria-agent` 重启：

1. 本地缓存不作为权威来源。
2. 从 Neutron full resync。
3. 查询 datapath status。
4. 下发 full snapshot。

### 9.10 场景矩阵与处置规则

前面的数据流覆盖主路径，但 OpenStack compute node 上真正容易出问题的是边界场景。下面的场景矩阵是实现时的判断依据：每个场景都必须明确权威来源、是否允许 ready、失败影响范围、是否写 WAL、是否需要 full resync。

#### 9.10.1 VM 与 Port 生命周期场景

| 场景 | 触发 | 权威来源 | Aria 行为 | Ready 条件 |
| --- | --- | --- | --- | --- |
| VM create，Neutron event 先到，tap 后出现 | port bind event 早于本机接口创建 | Neutron `binding_host` + Netlink | 记录 desired state，返回 `PORT_IFACE_NOT_FOUND`，等待 Netlink `NEWLINK` 后 port-scoped snapshot | tap 存在，ifindex ready，snapshot apply 成功 |
| VM create，tap 先出现，Neutron event 后到 | Netlink 先发现接口 | Neutron full resync/event | 可 attach inert/bypass runtime，但不因接口名匹配就创建 Neutron-managed policy state | 后续 Neutron port 绑定到本 host 且 preflight 成功 |
| VM reboot / hard reboot | tap 删除并重建，`binding_host` 不变 | Neutron desired state + Netlink | 保留 desired state，旧 ifindex runtime degrade，新 ifindex 出现后重新 attach | 新 ifindex preflight 成功，port-scoped snapshot accepted |
| VM live migration | 旧 host unbind，新 host bind | Neutron `binding_host` | 旧 host delete，新 host wait tap 后 apply | 新 host apply 成功，旧 host 清理完成或进入可重试 degraded |
| VM cold migration / resize confirm | port 可能经历 unbind、bind、tap 重建 | Neutron revision | 按最新 revision 处理，旧 revision 丢弃 | 最新 binding_host 对应 host apply 成功 |
| VM resize revert | port 可能回到旧 host | Neutron revision | 不假设迁移方向，按最新 `binding_host` 重建本机投影 | 返回 host 重新 attach 成功 |
| VM evacuate | 原 host 可能不可达，新 host 重新绑定 | Neutron full resync | 新 host 按 bind 处理；原 host 恢复后 full resync 发现 port 不再属于本机并清理 | 新 host ready；旧 host 恢复后无 stale port |
| VM shelve / unshelve | port 可能长期无本机 tap | Neutron port 状态 + binding | port 无本机接口期间保持 degraded 或 removed，不能本机写入 | unshelve 后接口出现并 apply 成功 |
| VM rebuild | port_id 通常不变，tap 可能重建 | Neutron revision + Netlink | 视为 tap recreate 或 port update，不清空 Neutron policy | 新接口 ready 后恢复 ACL/QoS |
| Port delete | Neutron 删除 port | Neutron event/full resync | 调用 local delete，清理 port-scoped state，释放 refcount 归零对象 | delete 幂等成功 |

补充规则：

- 接口名只能作为匹配线索，不能作为权威。权威始终是 Neutron port `id`、`binding_host`、revision 和本机 Netlink 结果的交集。
- 对于先看到 tap、后看到 Neutron event 的场景，不能因为 `tap*` 名称符合模式就提前挂载 eBPF。
- resize、evacuate、rebuild、shelve 这类 Nova 生命周期最终都要落到 port bind/unbind、tap recreate、full resync 三类动作上，不能额外创造本机权威状态。

#### 9.10.2 Neutron 控制面与消息场景

| 场景 | 处置 |
| --- | --- |
| Neutron server 重启 | `neutron-aria-agent` 保持进程 alive 但进入 degraded，RPC 恢复后 full resync，不允许本机持久写入 |
| RabbitMQ / oslo.messaging 中断 | 保持 `last_classified_generation` 对应 snapshot，事件恢复后先 full resync 再处理增量事件 |
| 事件重复 | 按 `source_revision` 或 Neutron revision 去重，重复事件不得重复增加 refcount |
| 事件乱序 | 旧 revision 不能覆盖新 revision；如果无法判断新旧，触发 full resync |
| 事件队列溢出 | 丢弃本地增量队列，进入 full resync |
| Neutron API 查询部分失败 | 不下发半截 full snapshot；保持 `last_classified_generation`，记录 degraded reason |
| Neutron agent heartbeat 失败 | 不改变 datapath desired state；heartbeat 恢复后 full resync |
| Neutron 返回对象缺字段 | translator 拒绝生成 snapshot，标记 input degraded，不让 Rust 侧猜测 |
| Neutron revision 回退或不可信 | 使用 agent 本地单调 `local_generation`，但仍以 full resync 当前视图为内容权威 |

实现要求：

- `neutron-aria-agent` 必须区分 liveness 和 readiness。进程能运行、能 heartbeat，不代表 ACL/QoS 都 ready。
- 如果 Neutron 控制面不可达，datapath 不能进入 `local_standalone`，只能进入 `openstack_degraded`。
- 所有控制面恢复路径都从 full resync 开始，不能只依赖恢复后的第一条增量事件。

#### 9.10.3 OVS / Linux Interface 场景

| 场景 | 处置 |
| --- | --- |
| OVS agent 重启 | 不把 OVS agent restart 视为 Neutron authority 变化；依靠 Netlink 和 full resync 校准接口 |
| ovs-vswitchd / ovsdb-server 重启 | 先按 attach boundary 分类：tap 仍存在且 ifindex/XDP/map 健康时 ACL 可保持 ready；tap 消失或 ifindex 改变时才按 tap recreate 处理 |
| tap 命名模式与预期不同 | N0.5 必须发现目标环境命名；不匹配时不得 attach，返回 `DomainStatus=degraded` |
| trunk port / VLAN subport | 第一阶段默认只支持目标环境验证过的 port 形态；未验证 subport 标记 `support_disposition=unsupported` 或 `DomainStatus=degraded` |
| SR-IOV / direct / macvtap port | 第一阶段默认不支持 eBPF attach，必须明确 `support_disposition=unsupported`，不允许假 ready |
| DHCP/router/metadata service port | 不因接口名匹配自动接管；只处理 Neutron 明确绑定且在范围内的 compute VM port |

关键规则：

- attach 点的设计假设是直接挂到 OVS `br-int` 的 tap，但仍必须在目标 OpenStack 环境中实测并记录。
- OVN、Linux bridge 或 hybrid plug 是否不存在必须由 N0.5 discovery 验证；验证失败时这些模式不进入第一阶段默认路径。
- 当前阶段 Aria 不能宣称已经独立承担 SG；Aria 未 ready 的 port 默认 `effective_action=bypass`，不得中断业务。

#### 9.10.4 eBPF / 内核 / Pinned Runtime 场景

| 场景 | 处置 |
| --- | --- |
| BTF 缺失或不匹配 | `aria-datapath` 启动 degraded，Neutron agent alive 但不可 ready，不能接受生产 smoke |
| eBPF verifier 拒绝加载 | 不更新 accepted generation，返回 datapath domain degraded |
| attach 点 qdisc 冲突 | 返回 attach degraded，不覆盖未知 qdisc，除非目标环境明确允许 |
| pinned map schema 版本不匹配 | 拒绝复用旧 map，进入 repair 或 rebuild；不能用新用户态读写旧布局 |
| bpffs 未挂载或只读 | `aria-datapath` 不能 ready；不允许把 pinned runtime 放到容器临时层 |
| map update 部分成功 | domain degraded，触发补偿或 full resync；accepted generation 只能在完整 apply 后推进 |
| 旧 ifindex stale entry | cleanup 幂等；清理失败记录 warning，不阻止新 ifindex preflight 后 attach |
| host kernel 升级后重启 | 必须重新校验 eBPF artifact、BTF、pinned schema 和 attach mode |

WAL 与 eBPF apply 的一致性要求：

- `accepted_generation` 只能在 snapshot 校验、WAL durable 写入、且各请求 domain 都有明确 `DomainStatus`、`effective_action` 和 `support_disposition` 后推进。
- 如果 WAL 写入失败，不能把内存态标记为 accepted，即使部分 eBPF map 已经更新。
- 如果 eBPF apply 失败，不能写成成功 WAL；下一次 full resync 必须能重试并修复。
- 对需要先写 intent 再 apply 的实现，WAL entry 必须能区分 `intent` 和 `committed`，replay 时只能恢复 committed state 或重新执行未完成 intent。

#### 9.10.5 ACL Enhancement 输入语义场景

当前阶段文档、代码命名和验收统一使用 `ACL enhancement`。生产输入只来自独立 `aria_acl` Neutron service plugin/API/DB，不来自 Neutron Security Group projection。历史 tag + 本机只读 ACL policy mapping 只允许作为 lab/bootstrap/迁移辅助，不作为生产验收主线。

| 输入 | Aria 处理 |
| --- | --- |
| 无 ACL enhancement 输入 | 默认 bypass，不改变 OVS 转发 |
| port/network 无 `aria_acl` binding | 默认 bypass，不改变 OVS 转发 |
| binding 指向不存在或不可访问的 `aria_acl` policy | `DomainStatus=degraded,effective_action=bypass`，错误码 `ACL_POLICY_NOT_FOUND` 或 `ACL_INPUT_INVALID` |
| 显式 ACL enhancement policy | 编译成 per-port ACL enhancement；失败时 `DomainStatus=degraded,effective_action=bypass` |
| 显式 remote CIDR | 可作为 ACL match 条件 |
| `explicit_acl_group` | 可展开成本 host `address_set`；不是 Neutron Security Group remote group |
| 未支持的 protocol/ethertype/port range | 显式 degraded，不静默宣称 ready |
| DHCP / metadata / IPv6 ND | 当前阶段默认依赖 bypass 保护原转发；只有显式 ACL policy 覆盖相关流量时才进入 smoke 验证 |

当前阶段不做：

- Neutron Security Group projection。
- remote group 展开。
- anti-spoof。
- port security enforcement。
- default security group 语义。
- allowed address pairs 语义。

关键规则：

- `project_id` 不能作为包路径上的直接 drop 条件。租户隔离由 Neutron 网络、路由、shared/RBAC 和未来独立策略表达。
- 如果显式 ACL enhancement 输入类型暂不支持，必须显式 degraded，不允许静默放通后宣称 ready。
- ACL enhancement 未 materialize 或未 ready 时必须 `effective_action=bypass`，并按原因返回 `DomainStatus=not_requested` 或 `degraded`，不能影响 OVS 转发。

#### 9.10.6 QoS 场景

| 场景 | 处置 |
| --- | --- |
| port-level QoS 和 network-level QoS 同时存在 | port-level 覆盖 network-level，translator 输出 per-port effective QoS |
| shared QoS policy | Python 侧验证 RBAC/shared 关系后下发到绑定 ports |
| QoS policy 删除 | 下发 port-scoped snapshot 清理 shaping state |
| bandwidth limit 不支持方向 | QoS domain degraded，不影响 ACL ready |
| DSCP marking 暂不支持 | 明确 unsupported/degraded，不静默忽略 |
| minimum bandwidth / placement 语义 | 第一阶段不承诺调度语义，只能记录 unsupported 或作为后续阶段 |
| qdisc 不可用或冲突 | QoS domain degraded，不能宣称限速生效 |

QoS 的失败不应扩大为 ACL 失败，但生产验收必须能看到 QoS domain degraded。也就是说，ACL ready 和 QoS ready 是不同 domain，不能用一个总 ready 掩盖局部失败。

#### 9.10.7 既有本机能力边界场景

| 场景 | 处置 |
| --- | --- |
| 本机已有 mirror/tcprt 配置文件 | 不被 `neutron-aria-agent` 读取，不生成 Neutron snapshot 字段 |
| 本机管理员查询 TCPrt 观测结果 | 允许只读，不改变 Neutron generation |
| 本机管理员尝试对 Neutron-managed domain 写入持久配置 | 拒绝或要求显式 break-glass，不写入 Neutron WAL；未纳管 domain 仍按本机模式处理 |
| 未来需要 Mirror/TCPrt 对接 Neutron | 新增独立方案，重新定义 northbound 输入、权限、status domain、smoke 和回滚策略 |

Mirror/TCPrt 代码保留是为了避免破坏 standalone/local legacy 能力，不代表它们进入 `v0.9-neutron-agent` 第一阶段交付。

#### 9.10.9 多租户、共享网络与特殊 Port 场景

| 场景 | 处置 |
| --- | --- |
| shared network 上不同 project 的 ports 互通 | 按 Neutron SG/router/RBAC 结果决定，不按 project 不同直接 drop |
| router / floating IP 路径 | 第一阶段不实现 L3 datapath 替代，不能在 Rust 侧推导 router 语义 |
| provider network | port policy 仍按 Neutron 输入编译，不新增 provider 特判 |
| admin-owned shared policy | scoped object key 使用 admin/owner scope，binding 记录实际 port project |
| project 删除 | full resync 后清理该 project 在本 host 的所有 scoped state |
| 同名 ACL group / QoS policy | 使用 ID 和 scoped object key，不使用名称 |

实现上必须避免两种错误：

1. Rust 侧按 `project_id` 直接做硬隔离，破坏 shared network。
2. Python 侧只按对象名称关联，导致跨租户串 policy。

#### 9.10.10 容器、启动顺序与单实例场景

| 场景 | 处置 |
| --- | --- |
| host reboot 后容器先于 VM tap 启动 | full resync 建立 desired state，tap 缺失 port degraded，Netlink 后恢复 |
| `neutron-aria-agent` 先启动，socket 不存在 | agent degraded，重试 socket，socket 恢复后 full resync |
| `aria-datapath` 先启动，Neutron 不可达 | datapath 保持 `last_classified_generation` 对应 state，不允许本机持久写入 Neutron-managed state |
| `/run/aria` 权限错误 | agent 无法连接，进入 degraded；不得 fallback 到 TCP |
| 两个 `aria-datapath` 容器同时启动 | 必须通过 socket/pid/lock 拒绝第二个 owner，避免同时操作 bpffs 和 WAL |
| 两个 `neutron-aria-agent` 同 host 运行 | 必须通过 host lock 或 Neutron agent identity 防止双写；检测到双实例时其中一个退出或 degraded |
| 容器镜像升级 | 先升级 `aria-datapath` 或按兼容矩阵滚动；每一步都以 schema/capability 握手确认 |
| 容器 rollback | Python 和 Rust snapshot schema 必须兼容，不能让新 snapshot 写入旧 datapath 不认识的字段 |

部署规则：

- 没有编排平台时也必须有本机单实例保护。建议使用 `/run/aria/aria-datapath.lock` 和 `/run/aria/neutron-aria-agent.lock` 或等价机制。
- `neutron-aria-agent` 不允许在 socket 不可达时改用 localhost HTTP。
- `/run/aria` 是通信目录，`/var/lib/aria-agent` 是状态目录，二者不能混用。

#### 9.10.11 WAL、磁盘与状态修复场景

| 场景 | 处置 |
| --- | --- |
| WAL append 失败 | 不推进 accepted generation，domain degraded，保留 `last_classified_generation` 对应动作 |
| WAL replay 发现尾部半写 | 截断到最后完整 record，记录 repair 事件 |
| compact state 损坏 | 回退到 WAL replay；如果 WAL 也损坏，进入 `DomainStatus=blocked` 或 `degraded`，不假 ready |
| 磁盘满 | 拒绝新 snapshot accepted，进入 degraded，避免内存态和持久态分裂 |
| `local-override.wal` 存在 | 不自动 rejoin；进入 `rejoin_pending`，等待 archive/discard |
| `neutron-state.wal` 和 `local-override.wal` 同时有同一 port | Neutron rejoin 前必须归档 local override，不能 merge |
| state_path 被误挂成容器临时目录 | deployment smoke gate 必须失败；生产部署禁止 |

WAL 修复不能扩大权限。即使 WAL 损坏，OpenStack-managed port 仍不能允许本机持久写入；只能保留 `last_classified_generation` 对应动作，或进入 `DomainStatus=degraded` / `blocked`。

#### 9.10.12 Bypass 与降级边界

当前 `v0.9-neutron-agent` 是 OVS enhancement mode，不是 Security Group replacement mode。默认规则是：Aria 增强能力失败必须可见、可告警、可恢复，但不能中断原有 OVS 转发。

| Domain | 失败时默认行为 | 是否影响 port ready |
| --- | --- | --- |
| ACL enhancement | `DomainStatus=degraded,effective_action=bypass`，不启用 ACL feature flag | 影响 Aria ACL ready，不影响 OVS connectivity |
| Group / Address-set | 相关 enhancement `DomainStatus=degraded,effective_action=bypass` | 影响对应 Aria feature ready |
| WAL / state durable | 不接受新 generation，保持 `last_classified_generation` 对应动作或 `effective_action=bypass` | 影响 Aria accepted/ready |
| Netlink / Neutron-managed preflight | port degraded，不启用 feature；tap 不存在时不 attach | 影响 Aria ready，不影响 OVS connectivity |
| QoS | QoS `DomainStatus=degraded`，`effective_action` 按已应用能力决定 | 只影响 QoS ready |
| trace/drops/diagnose | 临时功能失败只影响排障 | 不影响 Neutron/OVS 转发 |

如果未来要把 Aria ACL 变成安全组替代链路，必须新增显式 replacement mode，并重新定义业务中断策略、OVS 过滤链路处理和回滚门槛；这不是当前第一阶段默认行为。

#### 9.10.13 版本、能力握手与升级回滚场景

`neutron-aria-agent` 和 `aria-datapath` 必须在 snapshot 前通过 `GET /api/v1/neutron/capabilities` 做 capability 握手，具体 contract 以 5.1.2 为准：

- `schema_version`：snapshot schema 版本。
- `datapath_version`：Rust runtime 版本。
- `ebpf_artifact_version`：用户态和 eBPF map layout 版本。
- `capabilities`：acl、qos、wal、netlink、pinned_maps、break_glass。
- `unsupported_features`：Rust 侧明确拒绝的 feature。
- `schema_version_min/schema_version_max`：Rust 接受的 schema 范围。
- `mandatory_domains`：runtime、groups、conntrack、monitoring 这类不能被静默忽略的基础域。
- `enhancement_domains`：acl、qos，失败时按 `DomainStatus` 和 `effective_action` 暴露。
- `capability_hash`：Python 侧判断是否需要 full resync 的握手摘要。

升级规则：

- Python 侧不能向旧 Rust 侧下发未知 mandatory domain。
- Rust 侧不能静默忽略 unknown required field。
- 可选字段可以忽略，但必须进入 status 的 `ignored_optional_fields` 或等价观测字段。
- capability hash 改变后必须 full resync，不能继续复用旧增量上下文。
- schema 或 mandatory domain 不兼容时必须返回 `UDS_SCHEMA_MISMATCH` 或 `UDS_CAPABILITY_MISMATCH`，不能 fallback 到 TCP、本机 CLI 或 best-effort apply。
- eBPF map layout 变化必须有 migration 或 rebuild 策略，不能直接复用旧 pinned map。
- 回滚时，如果新版本已经写入旧版本不能理解的 WAL entry，旧版本必须拒绝启动或进入只读 repair 模式，不能误 replay。

#### 9.10.14 运维操作场景

| 操作 | 允许性 | 规则 |
| --- | --- | --- |
| 本机 `ariactl trace start` | 允许 | 临时排障，不写 WAL，不改变 generation |
| 本机 `ariactl policy/qos` 改 Neutron-managed domain | 禁止 | 返回 `LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_DOMAIN`；仅 `managed_domains=["acl"]` 时本机 QoS 仍允许 |
| 管理员 break-glass | 允许但显式 | 进入 `local_break_glass`，写 `local-override.wal`，暂停 Neutron apply |
| break-glass 后恢复 Neutron | 不自动 merge | 进入 `rejoin_pending`，默认 Neutron wins |
| 手动清理 stale pinned map | 谨慎允许 | 必须先让 datapath stopped/degraded，并通过 repair/full resync 重建 |
| 手动删除 socket | 不允许作为恢复手段 | agent degraded，datapath 重建 socket 后 full resync |

运维文档必须把“临时排障”和“持久配置”分开。允许 trace 不等于允许本机改安全组或 QoS。

## 10. OpenStack 集成方式

### 10.1 Coexist 集成

第一阶段推荐 Coexist 集成：

- OVS 继续做 L2 binding 和 connectivity。
- `neutron-aria-agent` 作为 Aria 本地 agent 注册和同步。
- 不要求关闭或旁路任何 OVS 转发能力。
- Aria ACL 只作为增强能力；未 ready 时 `effective_action=bypass`，不影响业务转发。

这种方式可以先验证节点侧功能，不直接挑战完整 L2 替换。

### 10.2 ML2 / Extension 边界

需要两类 OpenStack 集成点：

1. Agent 注册与 RPC 消费。
2. Aria enhancement 的 `aria_acl` Neutron service plugin/API/DB 输入。

第一阶段不要把 `neutron-aria-agent` 宣称为完整 port binding owner，除非已经实现完整 L2 lifecycle。

建议边界：

- port binding 仍由现有 OVS mechanism 处理。
- Aria 读取 binding host，只处理绑定到本 host 的 ports。
- Aria 可以有自己的 agent type 和 heartbeat。
- Mirror/TCPrt 不作为当前阶段 Neutron 对接功能；老 Neutron L 系列没有 TaaS 不影响第一阶段交付。
- 如果后续目标环境升级或补齐 extension，需要独立设计 Mirror/TCPrt adapter，不能复用当前 ACL/QoS scope 直接塞进 translator。

### 10.3 容器化部署

如果目标 OpenStack 环境里的 OVS agent 已经是容器形态，Aria 也应采用容器化交付，保持部署、升级、回滚和编排方式一致。

目标节点至少运行两个容器：

```text
aria-datapath container        Rust datapath runtime, runs aria-agent binary
neutron-aria-agent container   Python Neutron adapter
```

生产环境不采用“一个容器里同时跑 Rust datapath binary 和 `neutron-aria-agent`”的形态。原因是两个进程的权限、升级节奏、健康检查和故障影响面不同：

- `aria-datapath` 是高权限宿主机 datapath runtime，需要 host network、eBPF、bpffs、Netlink、WAL、Pinned Maps。
- `neutron-aria-agent` 是低权限 OpenStack adapter，只需要 Neutron RPC/配置和调用本机 snapshot API。
- 两者放进同一个容器会迫使 Python adapter 继承 eBPF 特权，扩大安全面。
- 两者合并会让重启、升级、日志、探针和故障定位变复杂。

可以接受的编排形态：

- 两个独立容器，分别由 OpenStack/Kolla/容器平台管理。
- 同一个 pod、compose service group 或等价编排单元里的两个容器，共享宿主机 Unix socket 通信。

不推荐的生产形态：

- 一个容器里用 supervisor 同时拉起 Rust datapath binary 和 `neutron-aria-agent`。
- 一个镜像里同时打包并默认运行两个进程。

启动顺序：

1. `aria-datapath` 容器先启动。
2. `neutron-aria-agent` 容器依赖本机 datapath health。
3. `neutron-aria-agent` 启动后 full resync。

失败策略：

- `aria-datapath` 失败时，Neutron agent heartbeat 进入 degraded。
- `neutron-aria-agent` 失败时，不删除 pinned datapath，由下一次启动 full resync 修正。

### 10.4 Aria Datapath Runtime 交付形态

推荐生产形态：

- Rust `aria-agent` 编译成二进制。
- 二进制放进 `aria-datapath` 容器镜像。
- 容器按 host runtime 运行，而不是普通隔离应用容器。

也就是说，Rust 程序本质上仍是一个宿主机 datapath runtime，只是通过容器镜像分发和运行。

OpenStack 方案不规划裸机服务形态；生产交付只描述 `aria-datapath` 容器和 `neutron-aria-agent` 容器。

`aria-datapath` 容器必须具备宿主机网络和 eBPF 操作能力：

- `hostNetwork` 或等价网络命名空间。
- privileged 容器，或至少具备 `CAP_NET_ADMIN`、`CAP_BPF`、`CAP_PERFMON`、`CAP_SYS_ADMIN` 等目标内核需要的能力。
- 挂载 `/sys/fs/bpf`，用于 pinned maps / pinned links。
- 挂载 `/sys/kernel/btf`，用于 BTF。
- 挂载 tracefs/debugfs，仅供既有本机管理员排障入口和 eBPF 运行诊断使用；不代表第一阶段新增 trace/drop 功能。
- 挂载 `/proc`，用于接口、进程和部分观测能力。
- 挂载 `/var/lib/aria-agent`，用于 WAL、compact state 和既有本机 legacy state；不代表第一阶段新增 service chain 功能。
- 挂载 `/var/log/aria-agent`，用于日志。
- 需要时只读挂载 `/lib/modules`，用于目标内核相关探测。

容器镜像里应包含：

- `aria-agent` 二进制。
- `ariactl`，用于本机排障。
- `libebpf_firewall.so`。
- `libebpf_firewall_perf.so` 或后续等价 eBPF artifact。
- 默认配置模板。

关键约束：

- eBPF pinned runtime 必须落在宿主机 `/sys/fs/bpf`，不能落在容器临时文件系统。
- WAL/state 必须落在宿主机持久化目录，不能随容器删除而丢失。
- 容器重启不能主动清理 pinned maps。
- 镜像升级时必须原子升级 `aria-agent`、`ariactl` 和 eBPF artifact，避免用户态和 eBPF 数据结构版本不一致。

### 10.5 neutron-aria-agent 交付形态

`neutron-aria-agent` 推荐独立 Python 容器：

- 与 OpenStack Neutron container deployment 保持一致。
- 通过 Neutron 配置、RPC、消息队列和 agent heartbeat 接入 OpenStack。
- 默认通过宿主机 Unix socket 访问本机 datapath。
- 不需要直接操作 eBPF map。
- 不需要挂载 `/sys/fs/bpf`。
- 不应该拥有比读取 Neutron 状态和调用本机 snapshot API 更多的权限。

不建议把 `neutron-aria-agent` 和 `aria-datapath` 合并成一个进程或一个生产容器。可以部署在同一个节点、同一 pod 或同一编排单元里，但生命周期和权限边界应分开：

- `aria-datapath` 权限高，负责 eBPF 和宿主机网络。
- `neutron-aria-agent` 权限低，负责 OpenStack 同步。
- 两者之间只通过 `/run/aria/aria-agent.sock` 通信。

### 10.6 无编排环境的容器通信

如果平台没有 Kubernetes、Compose、Kolla 这类编排能力，两个容器仍然可以在同一台 compute host 上直接通信。OpenStack agent mode 只采用 Unix socket：

```text
/run/aria/aria-agent.sock
```

这个模型参考 OVS agent 和 OVS 的本机通信方式：

```text
neutron-openvswitch-agent container
        |
        | host bind mount
        v
/var/run/openvswitch/db.sock
        |
        v
host ovsdb-server / ovs-vswitchd
```

Aria 对应关系：

```text
neutron-aria-agent container
        |
        | host bind mount
        v
/run/aria/aria-agent.sock
        |
        v
aria-datapath container
        |
        v
host eBPF datapath
```

因此，`/run/aria/aria-agent.sock` 是 OpenStack 模式的主控制通道，地位类似 OVS 环境里的 `/var/run/openvswitch/db.sock`。`neutron-aria-agent` 只需要访问这个 socket，不需要直接访问 eBPF map、bpffs 或宿主机网络设备。

#### 10.6.1 Unix socket

目标形态：

```text
host /run/aria/aria-agent.sock
        ^
        | bind mount
        |
aria-datapath container
neutron-aria-agent container
```

部署方式：

- 宿主机创建 `/run/aria`。
- `aria-datapath` 容器挂载 `/run/aria`，由其中的 `aria-agent` 二进制监听 `/run/aria/aria-agent.sock`。
- `neutron-aria-agent` 容器挂载同一个 `/run/aria`，通过 Unix socket 调用 snapshot API。
- socket 父目录和 socket 文件权限必须由宿主机 systemd/tmpfiles 或 `aria-datapath` entrypoint 固定设置，不能依赖容器默认 umask。
- 推荐目录 `/run/aria` 为 `root:neutron-aria`、`0770`，socket 文件为 `aria-datapath:neutron-aria`、`0660`。
- `neutron-aria-agent` 容器只需要加入 `neutron-aria` supplementary group，不需要 eBPF capability、bpffs 挂载或宿主机网络设备访问权限。
- 不提供 world-writable socket，不提供 TCP fallback，不允许 Python agent 直接读写 pinned maps。
- SELinux/AppArmor/Kolla/systemd 部署必须显式声明 `/run/aria` 的 bind mount、读写权限和 socket connect 权限。
- `aria-datapath` 应在接收请求时记录 Unix peer credential；Linux 环境优先使用 `SO_PEERCRED` 或等价机制校验 uid/gid 属于允许的 `neutron-aria` 运行身份。
- peer credential 校验失败必须返回 typed auth error，并记录 audit log；不能继续解析 snapshot。
- audit log 至少包含 peer uid/gid、pid、请求路径、local_generation、schema_version、accepted/applied 结果和 error_code。
- peer credential 策略必须来自配置，不能在代码里写死：
  - `uds_require_peercred = true`：默认启用，生产不能关闭。
  - `uds_allowed_group = "neutron-aria"`：只允许该 supplementary group 的本地进程访问写路径。
  - `uds_audit_log_path = "/var/log/aria-agent/neutron-uds-audit.log"`：写路径审计日志位置。
  - `uds_audit_fail_closed = true`：审计日志写失败时返回 `UDS_AUDIT_WRITE_FAILED`，不推进 generation。

示例配置：

```ini
[aria]
socket_path = /run/aria/aria-agent.sock
```

无编排环境的容器启动约束：

```text
aria-datapath:
  mounts:
    /run/aria:/run/aria
    /sys/fs/bpf:/sys/fs/bpf
    /sys/kernel/btf:/sys/kernel/btf:ro
    /var/lib/aria-agent:/var/lib/aria-agent
    /var/log/aria-agent:/var/log/aria-agent
  network:
    host
  security:
    privileged or required eBPF capabilities

neutron-aria-agent:
  mounts:
    /run/aria:/run/aria
    neutron config paths
  network:
    existing OpenStack management/RPC network
  security:
    no eBPF capabilities
```

优点：

- 不依赖容器编排服务发现。
- 不把 datapath API 暴露到网络 namespace。
- `neutron-aria-agent` 不需要 host network。
- 权限边界比 TCP 端口更清楚。

约束：

- N1 实现 snapshot API 时必须支持 Unix socket listener。
- `/run/aria` 是宿主机路径，不能只存在于容器临时层。
- 容器重启不能删除 socket 目录本身。
- 如果 `aria-datapath` 重启，`neutron-aria-agent` 必须重试连接并触发 status check / full resync。

### 10.7 配置项

Rust datapath binary（`aria-agent`）侧：

```toml
agent_mode = "openstack"
listen_unix_socket = "/run/aria/aria-agent.sock"
uds_require_peercred = true
uds_allowed_group = "neutron-aria"
uds_audit_log_path = "/var/log/aria-agent/neutron-uds-audit.log"
uds_audit_fail_closed = true
iface_pattern = "^tap"
state_path = "/var/lib/aria-agent"
pin_path = "/sys/fs/bpf/aria"
```

`neutron-aria-agent` 侧建议配置：

```ini
[agent]
host = compute-01
resync_interval = 60
full_resync_enabled = false
managed_domains = acl

[ovs]
integration_bridge = br-int

[aria]
socket_path = /run/aria/aria-agent.sock

[neutron]
port_source = neutronclient
rpc_events_enabled = false
incremental_rpc_enabled = false
revisionless_incremental_mode = disabled

[acl]
source = neutron
# fixture is CI/smoke only; tag-mapping is legacy lab/bootstrap only.
# fixture_path = /etc/neutron-aria-agent/acl-fixture.json
```

`integration_mode=coexist` 是 snapshot body 字段，由 `neutron-aria-agent`
写入 `PUT /api/v1/neutron/snapshot`，不得出现在 ini 配置中。`neutron-uds-contract.json`
是 CI/package 校验产物，不作为阶段一 runtime ini 字段。Python agent 启动后必须先调用 `GET /api/v1/neutron/capabilities`，再用返回的 `contract_version`、`body_max_bytes`、timeout、`error_codes_hash` 和 `peer_auth_policy` 校验本地 contract。生产配置必须使用 `[acl] source = neutron`，由 `aria_acl` Neutron service plugin/API/DB 提供 ACL 输入；`fixture` 只用于 CI/smoke，历史 tag + 本机 mapping 只允许作为 lab/bootstrap/迁移辅助。第一版不读取 Neutron Security Group，不依赖 TaaS，不从本地 CLI/API 创建 OpenStack 托管 ACL/QoS。

具体 Neutron 配置文件、agent heartbeat 和 OVS `br-int` attach 事实必须按目标 OpenStack 版本验证，不能只写文档不做 smoke。

## 11. 安全模型

### 11.1 本机 API 安全

Datapath Neutron snapshot API 必须是本机接口：

- 优先 Unix socket。
- 容器模式下通过宿主机 `/run/aria` 挂载和 Unix socket 文件权限限制访问。
- 只允许 `neutron-aria-agent` 用户访问。
- 服务端需要校验 Unix peer credential；文件权限是第一层控制，peer uid/gid 校验和 audit log 是第二层控制。
- 每次 snapshot/delete/status 写路径请求必须可审计到本地进程身份和 generation。

不允许把 snapshot API 暴露到租户网络或管理网。

### 11.2 租户隔离

租户隔离由 Neutron 对象语义决定：

- `project_id` 是状态索引、审计、refcount 和 status 归属字段，不是租户可直接操作的 Aria API 凭据。
- ACL enhancement 按 port 与显式 ACL group/policy 编译，包路径按 port identity 进入对应 per-port policy。
- 不在 datapath 中简单增加“project 不同就丢包”的硬规则，避免破坏 shared network、router、floating IP 和 provider network 场景。
- 当前阶段不做 Neutron remote group 展开，也不消费 Security Group、port security 或 allowed address pairs；跨 project 访问只接受 operator-admin 显式 ACL enhancement policy，不由 datapath 自行推导。
- QoS 必须按 port effective policy 下发，不能让 Rust 侧根据 project 自行推导租户权限。
- tenant 不能直接创建 Aria 本地 policy，也不能访问 `/run/aria/aria-agent.sock`。
- status/log 可以面向 operator 输出 project 粒度计数，但不得作为租户自服务查询 API。

### 11.3 观测能力权限

`trace`、`drops`、`ssl`、`diagnose`、`service chain`、`mirror`、`tcprt` 保留为既有本机管理员能力，不作为第一阶段新增功能模块：

- 不进入 Neutron tenant API。
- 不进入 `neutron-aria-agent` snapshot schema。
- 不作为当前阶段 heartbeat、status domain 或 smoke 验收项。
- 对 Neutron-managed domain 的持久写入仍必须被 gate 拒绝或要求显式 break-glass。
- 不参与 Neutron object sync。
- 不影响 port apply。
- SSL 是 host-global，默认不得作为租户功能暴露。

## 12. 可观测性与运维

本章只定义 ACL/QoS Neutron Agent Mode 的运行状态、告警和排障入口，不新增可观测性功能模块。stats、metrics、diagnose、trace、drops 等只作为既有本机管理员能力或支撑性观测入口出现，不进入第一阶段 Neutron snapshot、translator、feature flag、status domain、smoke 或 PR gate。

### 12.1 neutron-aria-agent 指标

建议暴露：

- agent alive/degraded。
- full resync count。
- event backlog。
- snapshot submit count。
- snapshot apply latency。
- last submitted generation。
- accepted_generation。
- last_classified_generation。
- last_feature_ready_generation_by_domain。
- overall_readiness。
- domain status count。
- last error code。
- port migration/rebind event count。
- stale port cleanup count。
- `PORT_IFACE_NOT_FOUND` count。
- `BPF_ATTACH_DEFERRED_IFACE_MISSING` count。
- `BPF_ATTACH_STALE_LINK_CLEANUP_FAILED` count。
- Neutron-managed preflight failure count。
- interface recreate count。
- Neutron full resync reason count：startup、RPC reconnect、event overflow、status drift、manual。
- dropped stale revision count。
- unsupported port type count：trunk、SR-IOV、direct、unknown binding。
- unsupported QoS rule count。
- WAL append / replay / compact repair count。
- disk full or state path write failure count。
- capability handshake failure count。
- duplicate local agent instance count。
- ACL degraded with bypass action port count。

### 12.2 aria-datapath 状态

`GET /api/v1/neutron/status` 应返回：

- schema_version。
- host。
- agent_mode。
- integration_mode。
- agent_health。
- overall_readiness。
- accepted_generation。
- applied_generation。
- last_classified_generation。
- last_feature_ready_generation_by_domain。
- managed_ports。
- managed_groups。
- capability_hash。
- capability_handshake。
- ignored_optional_fields。
- unsupported_features。
- domain_status。
- pinned runtime status。
- WAL status。
- Netlink reconciliation status。

### 12.3 排障路径

推荐排障顺序：

1. 看 Neutron agent alive/degraded。
2. 看 `neutron-aria-agent` last error。
3. 看 datapath `/api/v1/neutron/status`。
4. 看 domain status。
5. 看 Netlink port/interface mapping。
6. 看 WAL/pinned runtime 状态。
7. 必要时使用本机管理员能力：trace、drops、diagnose、metrics。

### 12.4 告警门槛

指标必须能形成最少一组生产告警：

| 告警 | 触发条件 | 原因 | 默认处置 |
| --- | --- | --- | --- |
| `AriaAcceptedGenerationLag` | `last_submitted_generation` 持续领先 `accepted_generation` 超过 2 个 resync interval | snapshot 一直无法 accepted，可能是 preflight、WAL 或 enhancement domain 卡住 | 查看 status domain，必要时 full resync |
| `AriaAclBypassDegradedPorts` | `acl_bypass_degraded_port_count > 0` 持续超过 1 个检查周期 | ACL enhancement 未 ready，`effective_action=bypass` 以保护业务转发 | 查看 affected ports 和 ACL/conntrack status |
| `AriaWalBlocked` | `runtime.blocked`、`WAL_APPEND_FAILED`、compact repair failed 任一出现 | 持久状态无法证明一致，不能继续推进 generation | 停止自动接管，检查 state_path、磁盘和 WAL |
| `AriaFullResyncLoop` | 同一 host 在 10 分钟内连续 full resync 超过阈值，且 accepted generation 未推进 | Neutron/Rust 状态漂移或 schema/capability 不兼容 | 比对 capability handshake、last error 和 stale revision |
| `AriaSocketPermissionDenied` | Unix socket connect 或 peer credential 校验失败 | 容器 group、SELinux/AppArmor、bind mount 或身份配置错误 | 检查 `/run/aria` owner/group/mode 和 profile |
| `AriaPinnedRuntimeMismatch` | pinned map/link inventory 与 state 不一致 | restart 或升级后 runtime 不可信 | 进入 degraded/blocked，执行 repair 或 full rebuild |

这些告警不替代 Neutron agent heartbeat。heartbeat 只能说明进程活着，不能说明 ACL/QoS 或 WAL ready。

### 12.5 告警 Runbook

下面的命令表示目标排障入口，可以是 `ariactl` 封装，也可以是通过 UDS 访问同名本机 API；实现时不得要求 `neutron-aria-agent` 打开 TCP 管理端口。

| 告警 | 首查入口 | 判定依据 | 默认恢复动作 |
| --- | --- | --- | --- |
| `AriaAcceptedGenerationLag` | `GET /api/v1/neutron/status` | `last_submitted_generation`、`accepted_generation`、`domains[].last_error` | 暂停增量，触发 full resync；若 WAL 或 schema 错误持续存在，保持 degraded |
| `AriaAclBypassDegradedPorts` | status 的 `acl`、`conntrack`、`affected_ports` | ACL/conntrack domain degraded，port feature flag 未启用 | 修复输入规则或 conntrack runtime；恢复后 port-scoped snapshot，不影响 OVS 转发 |
| `AriaWalBlocked` | status 的 `wal` 与 state_path 磁盘检查 | `WAL_APPEND_FAILED`、compact repair failed、磁盘或权限异常 | 停止推进 accepted generation，修复 state_path/磁盘后 full resync；不能直接删除 WAL 跳过恢复 |
| `AriaFullResyncLoop` | `GET /api/v1/neutron/capabilities` 和 status last error | capability hash 变化、schema mismatch、stale revision 或 host mismatch | 重新握手并对齐版本；清理过期 event 队列后 full resync |
| `AriaSocketPermissionDenied` | `/run/aria` owner/group/mode 与 peer audit log | `UDS_PEER_UNAUTHORIZED`、`UDS_PEERCRED_UNAVAILABLE` | 修复容器 supplementary group、mount、SELinux/AppArmor；禁止 fallback TCP |
| `AriaPinnedRuntimeMismatch` | status 的 `pinned_runtime` 和 runtime inventory | pinned map/link schema 与 WAL/state 不一致 | 进入 degraded/blocked，按 repair/rebuild runbook 重建，完成后 full resync |

## 13. 测试与验收

### 13.1 Python 单元测试

覆盖：

- port -> snapshot port entry。
- 显式 ACL enhancement group / CIDR -> group/address-set。
- 显式 ACL enhancement rule -> ACL policy。
- QoS port-level 覆盖 network-level。
- event merge。
- full resync。
- startup capability handshake。
- `neutron-uds-contract.json` request/response 校验。
- snapshot model 使用 `integration_mode`，本地配置使用 `agent_mode`，两者不得混用。
- VM migration / port rebind 的 `binding_host` 变化。
- event `source_revision` 去重和旧 revision 丢弃。
- Neutron event 队列溢出后触发 full resync。
- Neutron API 部分失败时不生成半截 snapshot。
- capability hash 变化后触发 full resync，不继续使用旧增量上下文。
- 没有显式 ACL enhancement 输入时 ACL domain 返回 `DomainStatus=not_requested,effective_action=bypass`，不生成隐式规则。
- IPv6 / ND / DHCP / metadata 在无显式 ACL enhancement 时必须保持 bypass，不生成隐式 ACL 或例外规则；只有 operator-admin 显式 ACL policy 才进入 translator。
- shared network 不因 project 不同被直接拒绝。
- unsupported trunk / SR-IOV / direct port 被显式标记 `support_disposition=unsupported`，必要时对应 domain 返回 `DomainStatus=degraded`。
- shared QoS RBAC 解析成 per-port effective QoS。
- DSCP / minimum bandwidth 不支持时进入 unsupported status。
- break-glass/rejoin 状态不被 translator 当作 Neutron desired state。

### 13.2 Rust API / Apply 测试

通过 GitHub Actions 执行，不在本地运行 Rust 编译。

覆盖：

- snapshot schema deserialize。
- capability response schema deserialize。
- `neutron-uds-contract.json` artifact drift check。
- generation 幂等。
- port delete 清理。
- port delete 幂等。
- port `binding_host` 不匹配本机时拒绝 apply。
- migration 乱序 event 中旧 revision 不能覆盖新 binding_host。
- tap 不存在时不得执行 eBPF attach 或 feature apply。
- ifindex 不匹配或未 ready 时返回 `PORT_IFINDEX_NOT_READY`。
- VM reboot/tap recreate 后旧 ifindex cleanup 幂等。
- 新 ifindex 出现后能重新 attach 并恢复 status。
- tap 先出现但没有 Neutron binding 时可以 attach inert runtime，但不得启用 ACL/QoS，也不得标记 Aria ready。
- OVS agent、ovs-vswitchd 或 ovsdb-server 重启时不把 OVS forwarding
  短暂中断归因给 ACL；tap 存在且 ifindex/XDP/map 健康时 ACL attach
  可保持 ready，tap 消失或 ifindex 改变时进入 detached/degraded 并等待
  full-resync 修复。
- unknown binding_host 或 binding_host 不匹配时拒绝 apply。
- BTF 缺失、bpffs 未挂载、pinned map schema mismatch 进入 degraded。
- WAL append 失败时不推进 accepted generation。
- WAL 尾部半写 replay 时可截断到最后完整 record。
- compact state 损坏时回退 WAL replay；无法修复时不假 ready。
- disk full 时拒绝新 snapshot accepted。
- local override 存在时 Neutron rejoin 进入 `rejoin_pending`。
- capability handshake 不匹配时拒绝对应 mandatory field/domain。
- 同 host 双 `aria-datapath` 或双 `neutron-aria-agent` 实例被检测并拒绝双写。
- group 引用释放。
- ACL apply 顺序。
- QoS 降级状态。
- WAL append / compact 降级修复。
- status response。
- Unix socket router 的 request/response/error code 符合 Local Unix API Contract。
- Unix socket router 的 capabilities response 符合 5.1.2。
- full snapshot body 超过预算时返回 `UDS_BODY_TOO_LARGE`；后续如需分片或 port-scoped resync，必须另开设计。
- peer credential 校验失败时拒绝写路径请求并记录 audit log。
- 只配置 `listen_unix_socket` 但未启用 `agent_mode = "openstack"` 时不会启动 Neutron router。

### 13.3 DevStack / OpenStack Smoke

至少覆盖：

- VM port active。
- `neutron-aria-agent` alive。
- port 绑定到本 host 后生成 Aria snapshot。
- ACL enhancement 变更实时影响 Aria domain status 和已启用的增强行为。
- 不需要关闭或旁路 OVS 转发；Aria degraded 时原有 OVS 连通性保持不变。
- `/run/aria/aria-agent.sock` 可用，`neutron-aria-agent` 通过该 socket 下发 snapshot。
- QoS 限速可观察。
- `aria-datapath` restart 后 pinned runtime 和 full resync 成功。
- `neutron-aria-agent` restart 后 full resync 成功。
- VM 迁移或 port unbind 后旧 host 清理 port 状态。
- VM reboot/hard reboot 后 tap recreate，旧 ifindex cleanup，新 ifindex reattach。
- Neutron server/RabbitMQ 短暂中断后 full resync 恢复，不允许本机持久写入。
- OVS agent、ovs-vswitchd 或 ovsdb-server 重启后 Aria 不崩溃，接口恢复后 ready。
- 未配置显式 ACL enhancement 的 port 保持 ACL bypass，不被 Aria ACL 阻断。
- IPv6 ND、DHCP、metadata 在无显式 ACL enhancement 时保持原 OVS 转发；如果 operator-admin 显式配置相关 ACL policy，再按该 policy 验证。
- shared network 上跨 project ports 不因 project_id 不同被 Aria 额外丢包。
- unsupported trunk/SR-IOV/direct port 不假 ready。
- `/run/aria` 权限错误时 `neutron-aria-agent` degraded，不 fallback localhost HTTP。
- `aria-datapath` 和 `neutron-aria-agent` 双实例启动被拒绝或 degraded。
- 磁盘满、WAL repair、pinned map schema mismatch 都有明确 degraded/status 输出。
- ACL/QoS domain 局部 `DomainStatus=degraded` 或 `effective_action=bypass` 时不互相掩盖，也不影响 OVS 转发。

### 13.4 首阶段性能预算

N6 scale test 和 GitHub Actions 中的轻量性能回归必须至少覆盖下面预算。超过预算时不能写成“可接受”，必须明确是 unsupported、degraded、拆分 snapshot，还是需要继续优化。

| 项目 | 首阶段预算 | 验收方式 |
| --- | --- | --- |
| 管理规模 | 单 host 1000 个 Neutron VM ports、10000 条 ACL rules、2000 个 group/address-set entries | mock scale test + 目标环境抽样 |
| full snapshot body | JSON body 不超过 1 MiB；超过返回 `UDS_BODY_TOO_LARGE` 或等待后续 port-scoped resync 设计 | UDS client/body size 测试 |
| full resync apply | mock scale p95 <= 5s，目标环境 smoke p99 <= 10s | CI mock perf + DevStack/目标环境 smoke |
| port-scoped snapshot | 单 port 更新 p95 <= 500ms | Python event merge + UDS apply 测试 |
| event merge window | 默认 1s，backlog 时最大 5s；超过则触发 full resync | Python event loop 测试 |
| 显式 ACL group/policy 更新 | 只重算本 host 受影响 ports，不做全 host/global recompute | translator 单元测试 + scale trace |
| status 查询 | p95 <= 200ms，不能扫描全量 eBPF map 才返回 basic status | Rust status 单元/集成测试 |

这些数值是第一阶段工程预算，不是最终产品性能上限。任何提高规模的后续阶段都必须先补新的 scale fixture、CI 阈值和 runbook。

#### 13.4.1 固定规模 Fixture

从 N1/N2 开始就必须固化一组 mock scale fixture，后续 N6 只是把它升级为性能门槛，不得重新定义输入语义。

首阶段固定 fixture：

- 1 个 host：`compute-01`。
- 1000 个 Neutron VM ports。
- 20 个 project，每个 project 50 个 ports。
- 10000 条显式 ACL enhancement rules。
- 2000 个 ACL group/address-set entries。
- 100 个 QoS policies，其中 20 个 shared QoS。
- 10% ports 处于 unsupported/degraded/ignored 混合状态。

该 fixture 必须用于：

- DTO serde roundtrip。
- `neutron-uds-contract.json` body size 测试。
- Python translator 完整 snapshot 断言。
- event merge 只重算受影响 ports 的测试。
- status 查询不扫描全量 map 的测试。

fixture 产物固定为：

```text
ci/fixtures/neutron-scale-v1.schema.json
ci/fixtures/neutron-scale-v1.json
ci/scripts/generate_neutron_scale_fixture.py
```

生成命令固定为：

```text
python ci/scripts/generate_neutron_scale_fixture.py \
  --version neutron-scale-v1 \
  --seed 20260613 \
  --output ci/fixtures/neutron-scale-v1.json
```

fixture 规则：

- `neutron-scale-v1.schema.json` 定义 fixture 文件结构和对象数量约束。
- `generate_neutron_scale_fixture.py` 必须 deterministic；同一 seed 生成的 JSON hash 必须稳定。
- `perf-summary.json` 必须包含 `fixture_version`、`fixture_path`、`fixture_sha256` 和 generator command。
- `ci/perf-baseline.json` 的 `fixture_version` 和 `fixture_sha256` 必须与当前 fixture 一致。
- 修改 fixture 只能通过显式 `ci:` PR，并同步更新 schema、baseline 和本节说明。

#### 13.4.2 性能测量协议

性能预算必须用固定 protocol 评估，避免不同机器、不同样本或一次性结果互相比较：

| 项目 | 要求 |
| --- | --- |
| CI runner | 使用 GitHub Actions 固定 runner class；如果 runner 规格变化，必须在 CI 结果中记录 runner label 和 CPU 信息 |
| 样本数 | 每个指标至少 30 次有效样本；full resync 可以 10 次 warmup + 30 次 measurement |
| 预热 | 先执行 10 次 warmup，不计入 p95/p99；warmup 失败直接判定性能 smoke 失败 |
| 统计口径 | p95/p99 使用排序后的 nearest-rank；报告 min、median、p95、p99、max |
| 超时 | 单次 full resync mock 超过 30s、port-scoped snapshot 超过 5s、status 查询超过 2s 时记为 hard failure |
| 资源上限 | CI 记录 peak RSS 和 CPU time；RSS 超过 baseline 2 倍或出现持续增长趋势时不得合入 |
| 目标环境 smoke | 目标环境只作为 N0.5/N6 证据，不和 CI mock 数值直接比较；必须记录 OpenStack 版本、kernel、OVS、CPU、内存和负载 |
| 失败处理 | 性能失败不能改低预算绕过；只能优化实现、降级为 unsupported，或显式拆分 snapshot 策略 |

CI 产物必须保存 `perf-summary.json`，字段至少包含 `fixture_version`、`fixture_path`、`fixture_sha256`、`generator_command`、`runner`、`sample_count`、`warmup_count`、`min_ms`、`median_ms`、`p95_ms`、`p99_ms`、`max_ms`、`peak_rss_bytes` 和 `result`。

#### 13.4.3 性能 Baseline

性能 baseline 必须有独立文件，避免把某次 CI 结果临时当成标准：

```text
ci/perf-baseline.json
```

字段至少包含：

- `fixture_version`、`fixture_path`、`fixture_sha256`：必须与 13.4.1 固定 fixture 对齐。
- `runner_label`、`cpu_model`、`cpu_count`、`memory_total_bytes`：baseline 对应的 runner 规格。
- `full_resync_p95_ms`、`port_scoped_p95_ms`、`status_p95_ms`：当前允许阈值。
- `peak_rss_bytes`、`cpu_time_ms`：资源基线。
- `updated_by_pr`、`updated_reason`：更新来源和原因。

更新规则：

- baseline 只能在显式 `ci:` PR 中更新，不能夹带在功能 PR 中。
- baseline 更新必须附带 `perf-summary.json` 前后对比。
- 如果性能变差，只能在明确容量换取、fixture 增大或 runner 变化时接受；否则必须优化实现或调整拆分策略。
- N6 前的 baseline 是工程回归阈值，不代表最终产品 SLA。

### 13.5 不做本地编译

本仓库规则禁止本地运行：

- `cargo build`
- `cargo check`
- `cargo test`

代码修改后应 commit + push，由 GitHub Actions 编译验证。文档变更可以使用：

```bash
git diff --check
rg -n "[ \t]+$" docs/openstack-neutron-agent-mode.md README.md
```

## 14. 阶段计划

### 14.0 最终大步骤总览

原方案的 8 个大步骤主要对应工程实现段。经过 N0.5 目标环境发现 gate、Mirror/TCPrt scope cut、部署验证拆分和生产化 gate 收敛后，最终按 9 个大步骤管理，落地时拆成 10 个 PR 或连续 commit。

口径如下：

- 如果按最终方案管理粒度统计：9 个大步骤。
- 如果只统计代码实施，不把 PR-0 文档基线算进去：8 个实施步骤。
- 如果按 GitHub PR 或连续 commit 统计：10 个落地单元。

| 最终步骤 | 名称 | 覆盖范围 | 对应 PR/Phase | 是否需要 OpenStack 环境 | 退出条件 |
| --- | --- | --- | --- | --- | --- |
| S0 | 文档与语义基线 | 方案、README 入口、分支基线、术语冻结 | PR-0 / Phase N0 | 否 | 本文档成为唯一方案入口，明确不引入 `aria-controller`，明确第一阶段为 Coexist Mode |
| S0.5 | 目标环境发现与 gate | `N0.5-lite` schema freeze gate 和完整 N0.5 feature gate | Phase N0.5 | 是 | PR-1A schema freeze 前完成 `N0.5-lite`，PR-5A 前完成完整 N0.5 并写入 discovery 文档 |
| S1 | Rust 契约与 UDS contract | Neutron DTO、OpenAPI components、固定 fixture、UDS contract artifact | PR-1A / N1-A | 否 | schema、fixture、contract drift 测试稳定，Neutron API 不暴露到 TCP router |
| S2 | Rust 本机写入通道基础 | Unix socket router、`agent_mode`、socket 权限、本机写入 gate、snapshot apply/status/WAL 骨架 | PR-1B + PR-2 / N1-B/N1-C/N1-D | 否 | UDS snapshot/status/capabilities/delete 可用，local override 与 Neutron 托管写入语义隔离 |
| S3 | Python agent 骨架与 UDS client | Python package、配置加载、UDS client、capability handshake | PR-3 / N2-A/N2-B | 否 | Python 侧能用 fake 或本机 UDS 完成 capabilities/status/snapshot 基础交互 |
| S4 | Neutron 投影与主循环 | Neutron 对象投影、translator、full resync、事件合并、heartbeat/readiness 映射 | PR-4 / N2-C/N2-D | 可用 mock | 多 project translator 测试通过，`AgentHealth` 与 `OverallReadiness` 语义稳定 |
| S5 | ACL enhancement 垂直闭环 | ACL bypass、显式 ACL group、跨 project 隔离、原 OVS 转发保护 | PR-5A / N3 | 是 | ACL domain 可独立 ready/degraded，失败时 `effective_action=bypass` 且不影响原转发 |
| S6 | QoS 垂直闭环 | QoS policy 投影、带宽限制、shared QoS 绑定和失败隔离 | PR-5B / N4 | 是 | QoS 行为可观察，QoS domain 失败不影响 OVS 转发和其它 feature domain |
| S7 | 容器部署、完整 smoke 与生产化硬化 | 容器骨架、host mounts、UDS 权限、ACL/QoS deployment smoke、持久化、双实例、runbook | PR-6A + PR-6B / N5/N6 | 是 | PR-6A 完成最小部署 smoke，PR-6B 完成 ACL/QoS smoke 和生产化 hardening |

因此后续沟通统一使用这三个层次：

- “9 个大步骤”用于方案管理和阶段汇报。
- “10 个 PR/commit”用于开发落地和 CI 验证。
- “8 个技术执行章节”只保留为 Rust/Python/feature/container 的展开说明，不再代表总步骤数。

### Phase N0：文档与分支基线

产出：

- `v0.9-neutron-agent` 分支。
- 本详细方案文档。
- README 文档入口。

验收：

- 明确不引入 `aria-controller`。
- 明确第一阶段是 Coexist Mode。
- 明确第一阶段只对接 ACL/QoS；Mirror/TCPrt Rust 代码保留但不进入 Neutron Agent Mode。
- 明确 Group、Conntrack、Monitoring、WAL、Netlink、Pinned Maps 是必选支撑能力。
- 明确其它已有能力代码保留但不进入 `neutron-aria-agent` 暴露面。

### Phase N0.5：OpenStack 目标环境兼容性发现

这不是实现阶段，但它提供两个 gate：`schema_freeze_gate` 和 `feature_gate`。N1/N2 可以先用 mock 和本机单元测试推进；PR-1A schema freeze 前必须完成 N0.5-lite，进入 N3 目标环境功能闭环前必须完成完整 N0.5。发现结果必须写入 [OpenStack Target Environment Discovery](openstack-target-env-discovery.md)。

N0.5 分成两层：

- `N0.5-lite`：`schema_freeze_gate`，PR-1A schema freeze 前必须完成，至少验证目标环境 tap 是否直接接入 OVS `br-int`、hook direction 映射、`integration_mode = "coexist"` 是否足够表达第一阶段语义。
- 完整 N0.5：`feature_gate`，进入 N3 目标环境功能闭环前必须完成，覆盖 OpenStack 版本、OVS `br-int` attach 事实、DHCP/metadata/IPv6 ND bypass 保护、权限挂载、unsupported port 类型和升级回滚。

这样做的原因是 direction 和 attach 点会影响 DTO 字段、ACL/QoS direction 语义和测试样例；如果等到 PR-5A 前才验证，会导致 PR-1A schema 返工。

产出：

- 目标 OpenStack 版本及证据。
- 目标环境是否为 OVS、不采用 OVN 的证据。
- 是否没有 Linux bridge、`qvo/qvb/veth` 和原 SG 过滤链路的证据；证据缺失时只能保持 `assumption`，不能写成已确认。
- 目标环境是否无需关闭或旁路 OVS 转发能力的证据；若未来启用 SG replacement mode，再补独立关闭/回滚方案。
- Neutron agent heartbeat 注册方式。
- 需要消费的 Neutron RPC topic、port binding 事件和 full resync API。
- QoS extension 可用性。
- 确认 Mirror/TCPrt 不作为第一阶段 Neutron 对接能力，不进入 discovery gate。
- compute host 上 tap 命名模式。
- tap 直接接入 OVS `br-int` 的实际 attach 点。
- tap hook direction 语义矩阵：VM->VM same host、VM->external、external->VM、DHCP、metadata、IPv6 ND 分别在哪些 XDP ingress、TC ingress、TC egress hook 可见。
- trunk port、VLAN subport、SR-IOV、direct、macvtap 是否存在，以及第一阶段如何 degraded 或忽略。
- IPv6 ND、DHCP、metadata 在目标环境中的流量路径，以及无显式 ACL enhancement 时是否保持 bypass。
- 目标内核 BTF、bpffs、qdisc、TC/XDP attach 能力。
- `/run/aria`、`/var/lib/aria-agent`、`/sys/fs/bpf` 的宿主机挂载和权限策略。
- 双容器无编排部署下的单实例锁策略。
- schema/capability 握手和升级回滚最低兼容版本。

验收：

- PR-1A schema freeze 前，至少完成 `N0.5-lite`，并把 tap attach 点和 Aria ingress/egress 映射写入本方案或目标环境记录。
- 写明目标环境当前没有 Linux bridge、`qvo/qvb/veth` 和原 SG enforcement 的事实依据。
- 写明 Aria ACL 未 ready 时如何保持 `effective_action=bypass`，并验证 OVS 转发不受影响。
- 写明 `neutron-aria-agent` heartbeat 在 Neutron agent list 中的 agent type。
- 写明 DevStack 或目标环境 smoke 的具体配置文件路径。
- 写明不支持 port 类型的处理策略，不能假 ready。
- 写明 DHCP/metadata/IPv6 ND 在无显式 ACL enhancement 时如何保持 bypass；如需限制，必须由 operator-admin 显式 ACL policy 表达。
- 写明 Aria `ingress`/`egress` 与目标环境 hook 方向的映射；如果 VM->VM、VM->external、external->VM 任一方向无法稳定匹配 ACL/QoS 语义，不进入 N3。
- 写明 `aria-datapath` 所需内核能力和容器 capability。
- 没完成完整 N0.5 时，不进入 N3 的目标环境验证。
- `docs/openstack-target-env-discovery.md` 仍有关键“未执行”项时，不允许把 smoke 结果计为完整 N0.5 通过。

### Phase N1：本机 Neutron Snapshot API

产出：

- `api` crate 新增 snapshot 请求/响应类型。
- `agent` 新增 `/api/v1/neutron/snapshot`。
- `agent` 新增 `/api/v1/neutron/status`。
- `agent` 新增 `/api/v1/neutron/ports/{port_id}` delete。
- `agent` 支持 `/run/aria/aria-agent.sock` Unix socket listener。
- `agent_mode = "openstack"` 与 `listen_unix_socket` 同时配置时才启用 Neutron Unix router。
- domain status：`runtime/groups/conntrack/monitoring/acl/qos`。
- WAL/pinned runtime 复用。

验收：

- 同一个 snapshot 重放多次结果一致。
- 删除 port 后清理 group/ACL/QoS。
- 任一 independent domain 失败时不影响其它 domain。
- enhancement domain 失败时有明确错误码、`DomainStatus` 和 `effective_action`。
- snapshot API 不包含 trace/drops/ssl/diagnose/service chain。
- Unix socket 权限和 peer credential 校验能限制只有 `neutron-aria-agent` 访问，并记录写路径 audit log。

### Phase N2：neutron-aria-agent 原型

产出：

- Python `neutron-aria-agent` skeleton。
- 配置读取。
- agent heartbeat。
- full resync。
- port update 消费。
- local snapshot client，默认连接 `unix:///run/aria/aria-agent.sock`。
- 本机 port/interface 对账。

验收：

- agent 能在 Neutron 里显示 alive。
- 本 host port 全量下发成功。
- datapath status 可被读取。
- datapath socket 不存在时进入 degraded，并在 socket 恢复后自动重连。
- Netlink/接口变化能触发状态修正。
- 重启后 full resync 成功。

### Phase N3：ACL Enhancement

产出：

- 显式 ACL enhancement rule 展开。
- 显式 ACL group/address-set 编译。
- per-port ACL feature flag。
- 无 ACL 输入时的 bypass reason。
- ACL apply 失败时的 `DomainStatus=degraded,effective_action=bypass` reason。
- DHCP/metadata/ARP/NDP 在无显式 ACL enhancement 时保持 bypass；如业务确需限制，必须来自 operator-admin 显式 ACL enhancement policy。

验收：

- ACL enhancement 未 ready 时 `effective_action=bypass` 正确，不中断 OVS 转发。
- 未配置显式 ACL enhancement 的 port 保持 bypass。
- 配置显式 ACL enhancement 后，allow/drop 规则只影响启用该增强能力的 port。
- 显式 ACL group/policy 更新只影响本 host 相关端口。
- Aria ACL 增强不要求关闭 OVS 转发能力；不存在双重过滤或转发中断。

### Phase N4：QoS

产出：

- Neutron QoS policy 翻译。
- network-level / port-level 合并。
- per-port QoS snapshot。
- shaping / policing 降级状态。

验收：

- port-level 覆盖 network-level。
- egress shaping 可观察。
- ingress 降级明确进入 apply status。
- policy 删除后 token bucket 清理。

### Phase N5：容器部署 Smoke

产出：

- 容器部署配置样例。
- OpenStack 目标版本配置说明引用 N0.5 discovery 证据，不在本阶段重新定义环境事实。
- `aria-datapath` 容器镜像说明。
- `neutron-aria-agent` 容器镜像说明。
- 容器运行参数、network mode、host mounts、capabilities 配置。
- `/run/aria/aria-agent.sock` 通信验证。
- e2e smoke 脚本。

验收：

- 容器启动顺序正确，`aria-datapath` 和 `neutron-aria-agent` 只有一个活动实例。
- `/run/aria/aria-agent.sock` 权限、peer credential、audit log 和 contract file 安装验证通过。
- VM port active 作为 deployment smoke 输入，不替代 N3/N4 feature gate。
- 显式 ACL enhancement policy 生效；不测试 Security Group replacement 语义。
- QoS 限速只在 N4 feature gate 已通过后进入 deployment smoke gate。PR-6A 只能记录“未纳入 smoke scope”，不能用 `support_disposition=unknown` 作为通过条件；PR-6B 中 ACL/QoS 都必须收敛为 `supported`、`unsupported` 或 `not_applicable`。
- VM migration 后旧 host 清理 port state，新 host apply port-scoped snapshot。
- 旧 host 丢失 unbind event 时，full resync 清理 stale port。
- 新 host 丢失 bind event 时，full resync 补齐 port state。
- 新 host tap 口尚未创建时不挂载 eBPF，Netlink 发现接口后再 attach。
- VM reboot/tap recreate 后 agent degraded -> ready，ACL/QoS 按 Neutron desired state 恢复。
- datapath restart 后 resync 成功。
- datapath socket 断开后 `neutron-aria-agent` degraded，socket 恢复后 full resync 成功。
- Neutron server/RabbitMQ 中断后保持 `last_classified_generation`，恢复时 full resync。
- OVS agent、ovs-vswitchd 或 ovsdb-server 重启后接口对账可恢复。
- IPv6 ND、DHCP、metadata 通过目标环境 smoke，未配置 ACL enhancement 时不被 Aria 阻断。
- unsupported trunk/SR-IOV/direct port 不进入 ready，并以 `support_disposition=unsupported` 表达。
- `/run/aria` 权限错误时不 fallback TCP。
- 双 `aria-datapath` 或双 `neutron-aria-agent` 实例不会双写。

### Phase N6：生产化硬化

产出：

- error code 文档。
- metrics dashboard。
- runbook。
- upgrade/rollback 说明。
- scale test。

验收：

- 13.4 首阶段性能预算全部通过，超过预算时有明确 `DomainStatus=degraded`、拆分 snapshot 或 `support_disposition=unsupported` 策略。
- 显式 ACL group/policy 更新不会全局重算所有 host。
- `aria-datapath` crash 后 datapath 不瞬断或可解释降级。
- 所有 `degraded` 或 `blocked` 状态都有明确排障路径。

## 15. 风险与门槛

| 风险 | 等级 | 约束 |
| --- | --- | --- |
| 误把 Aria ACL 当成安全组替代链路 | 高 | 当前阶段只做 enhancement；ACL 未 ready 必须 `effective_action=bypass`，不影响 OVS 转发 |
| 与未来 SG replacement mode 语义混淆 | 中 | 目标环境无 Linux bridge/qvo/qvb 且未启用原 SG 过滤链路只是 N0.5 待验证假设；本分支不关闭、不旁路、不接管 OVS 基础转发 |
| 逐条 API 留下 orphan map entries | 高 | 主路径必须是 full snapshot |
| 显式 ACL group 更新成本高 | 中 | 第一阶段只重算本 host 相关 ports |
| 绕过 group/address-set 直接写 ACL | 高 | Group 是必选编译中间层，ACL/QoS 共用 |
| WAL 或 pinned maps 缺失导致重启丢状态 | 高 | snapshot apply 必须持久化，并复用 pinned runtime |
| 只依赖 Neutron RPC 忽略接口生命周期 | 高 | Netlink 监听与周期对账必须保留 |
| 既有 Mirror/TCPrt 被重新拉回 Neutron scope | 中 | Rust 代码保留，但不进入 `neutron-aria-agent`、snapshot、feature flag、status domain、smoke 或 PR gate |
| 其它本地观测能力被误扩成 Neutron 功能 | 中 | 保留代码，但不进入 `neutron-aria-agent` 暴露面 |
| Neutron adapter 与 Rust datapath 状态漂移 | 高 | generation、full resync、status API 必须同时实现 |
| 本机 CLI 写入和 Neutron snapshot 双写 | 高 | Neutron-managed domain 的本机配置写操作必须拒绝；未纳管 domain 继续按本机模式处理 |
| 临时排障状态被错误持久化 | 中 | trace/drops flush 等临时操作不进入 WAL，不改变 generation |
| 通信失败被误判为退出 OpenStack mode | 高 | degraded 仍保持 Neutron 权威，本机持久写入继续拒绝 |
| break-glass 本机配置和 Neutron 重新接管冲突 | 高 | rejoin 默认 Neutron wins，local override 必须先归档或丢弃 |
| 多租户对象 key 冲突或串租户 | 高 | 所有 Neutron 对象使用 scoped object key，WAL/refcount/pinned map ID 都按 project 隔离 |
| shared network/shared QoS 被错误拦截 | 中 | 不按 project_id 直接丢包，由 `neutron-aria-agent` 解析 Neutron RBAC 后下发 effective policy |
| Aria ACL 未 ready 影响业务转发 | 高 | 默认 `effective_action=bypass`；N3 smoke 必须验证 Aria 故障不改变原有 OVS 转发 |
| OpenStack 版本差异导致 agent/RPC/OVS attach 事实返工 | 高 | N0.5 先完成目标环境兼容性发现，PR-5A 前必须写入配置、smoke 证据和回滚路径 |
| Neutron WAL 与 break-glass WAL 混写 | 高 | 使用 `neutron-state.wal` 与 `local-override.wal` 分离，rejoin 前归档 local override |
| VM 迁移后旧 host stale policy 未清理 | 高 | 以 Neutron `binding_host` 为权威，unbind event 或 full resync 都必须触发旧 host delete |
| VM 迁移到新 host 但接口晚于 Neutron event 出现 | 中 | 返回 `PORT_IFACE_NOT_FOUND`，等待 Netlink 对账后自动 port-scoped snapshot |
| 新节点 tap 未创建就尝试挂载 eBPF | 高 | attach 前必须通过 Netlink preflight；失败返回 `BPF_ATTACH_DEFERRED_IFACE_MISSING`，不得写 accepted state |
| VM 重启导致旧 tap 删除、新 tap 复用同名但 ifindex 改变 | 高 | Netlink DELLINK 标记 degraded，清理旧 ifindex runtime，NEWLINK 后重新 preflight + attach |
| unsupported trunk/SR-IOV/direct port 假 ready | 高 | N0.5 明确支持矩阵；未验证 port 类型必须 `support_disposition=unsupported` 或返回 `DomainStatus=degraded` |
| DHCP/metadata/IPv6 ND 被 Aria ACL enhancement 误伤 | 高 | 无显式 ACL enhancement 时必须保持 bypass；translator 不生成隐式 deny 或隐式例外，限制需求必须来自 operator-admin 显式 policy |
| WAL 写失败但内存/eBPF 状态被标记 accepted | 高 | `accepted_generation` 只能在 WAL durable 与 apply 成功后推进 |
| 磁盘满或 state_path 错挂容器临时层 | 高 | snapshot 不 accepted，deployment smoke gate 验证宿主机持久化挂载 |
| pinned map schema 版本不兼容 | 高 | capability/schema 握手，无法 repair 时 degraded，不复用旧布局 |
| Python/Rust 版本不匹配导致未知字段被静默忽略 | 高 | required field 不认识必须拒绝，可选字段必须进入 ignored status |
| 双 `aria-datapath` 或双 `neutron-aria-agent` 实例双写 | 高 | 本机 lock/identity 防重，检测到双实例退出或 degraded |
| 非关键 domain 失败掩盖业务转发影响 | 高 | domain readiness 分离，所有 Aria domain 失败都必须结构化返回 `DomainStatus` 和 `effective_action`，不能停止 OVS forwarding |
| 范围滑向 OVS L2 agent 替代 | 高 | `neutron-aria-agent` 始终不替代 OVS L2 agent，只做 ACL/QoS |
| UDS API 虽不进 TCP OpenAPI 但契约漂移 | 高 | Local Unix API Contract 固化路径、DTO、错误码和兼容策略 |
| 同 group 的非授权本地进程调用 socket | 高 | 文件权限之外增加 peer credential 校验和 audit log |
| 指标存在但没有告警 | 中 | 至少实现 generation lag、ACL degraded with bypass action、WAL blocked、full resync loop、socket permission denied 告警 |

## 16. 执行级实施计划

本节把前面的架构方案拆成可以直接执行的开发计划。原则是每个提交都能单独解释、单独回看，并且尽量让 GitHub Actions 在较早阶段发现 Rust 编译问题。

### 16.1 当前代码落点

当前 `v0.9.0` 基线是一个 Rust workspace：

| 路径 | 当前职责 | Neutron agent mode 里的改造定位 |
| --- | --- | --- |
| `api/src/lib.rs` | REST 请求/响应 DTO、OpenAPI schema 类型 | 增加 Neutron snapshot/status/capabilities/delete 的稳定 schema |
| `agent/src/api_routes.rs` | 现有 TCP REST router | 保持现有管理 API；新增独立 Neutron Unix socket router |
| `agent/src/openapi.rs` | OpenAPI paths/components 注册 | 只注册 Neutron DTO components，不暴露 UDS paths 到 TCP OpenAPI |
| `agent/src/neutron_api.rs` | Neutron UDS router、snapshot/delete/status/capabilities handler | 处理 snapshot/status/capabilities/delete，并保持 UDS-only |
| `docs/neutron-uds-contract.json` + `ci/check_neutron_stage1.py` | 阶段一 UDS contract artifact 与 drift check | 校验 UDS paths、schema range、错误码和 capabilities response |
| `agent/src/main.rs` | 配置、启动 TCP listener、后台任务 | 新增 `listen_unix_socket` 配置与 Unix socket listener |
| `agent/src/control_plane.rs` | runtime state、apply、WAL、实例管理 | 增加 Neutron apply 入口与 status 聚合 |
| `agent/src/control_plane/` | 分域控制面扩展 | 新增 `neutron_snapshot.rs`，承载 snapshot apply 编排 |
| `core/src/state.rs` | 持久化状态、group/rule/qos/mirror model | 增加 Neutron metadata、generation、port ownership 索引 |
| `agent/src/neutron_wal.rs` | WAL entry、replay、compact | 增加 Neutron snapshot/delete/status WAL entry |
| `agent/src/tap_registry.rs` | Netlink 发现 tap，attach/detach runtime | 复用，不在 N1 重写；N2/N3 通过 status 对账 |
| `config/aria-agent.toml` | `aria-agent` 默认配置 | 增加 Unix socket 示例配置 |
| `.github/workflows/build.yml` | GitHub Actions 编译、测试和产物 | 增加 Rust tests/schema contract、Python agent 检查、UDS contract artifact 和容器镜像构建 |
| `README.md` | 项目入口文档 | 保持链接到本方案 |

现有源码按能力层归类：

| 能力层 | 现有源码 | OpenStack 第一阶段处理 |
| --- | --- | --- |
| 基础运行能力 | `agent/src/netlink.rs`、`agent/src/tap_registry.rs`、`core/src/ebpf_ops/attach.rs`、`core/src/ebpf_ops/runtime.rs`、`core/src/ebpf_ops/inventory.rs`、`core/src/ebpf_ops/replay.rs` | 保留并接入 OpenStack tap 状态机；Netlink 可先 attach inert/bypass runtime |
| 持久化基础 | `core/src/state.rs`、`agent/src/neutron_wal.rs` | 增加 `neutron-state.wal`、generation、domain status、local override WAL 隔离 |
| 身份与选择器基础 | `agent/src/api_handlers/groups.rs`、`core/src/state.rs` | group/address-set 由 Neutron snapshot 投影，Neutron-managed domain 的本机托管写入被 gate 拒绝 |
| 有状态基础 | `agent/src/api_handlers/conntrack.rs`、`core/src/ct_ops.rs`、`core/src/ct_contract_ops.rs`、`ebpf/src/conntrack.rs`、`ebpf/src/ct_contract.rs` | 作为 ACL 状态化、连接跟踪、fast-path 和 flow 观测基础，不作为 tenant feature |
| 观测基础 | `core/src/monitoring.rs`、`agent/src/api_handlers/stats.rs`、`agent/src/api_handlers/metrics.rs`、`ebpf/src/stats.rs` | 作为 rule/flow/group/QoS 统计基础，失败进入 observability degraded |
| 第一阶段功能模块：ACL | `agent/src/api_handlers/policies.rs`、`core/src/ebpf_ops/policy.rs`、`ebpf/src/policy.rs` | enhancement domain；失败时 `DomainStatus=degraded,effective_action=bypass`，不影响 OVS 转发 |
| 第一阶段功能模块：QoS | `agent/src/api_handlers/qos.rs`、`core/src/qos_ops.rs`、`ebpf/src/qos.rs` | independent domain；失败 degraded，不影响 OVS 转发 |
| 非第一阶段功能：Mirror | `agent/src/api_handlers/mirror.rs`、`core/src/mirror_ops.rs`、`ebpf/src/mirror.rs` | 既有本机能力保留；不新增、不进入 Neutron snapshot、translator、feature flag、status domain 或 smoke |
| 非第一阶段功能：TCPrt | `agent/src/api_handlers/tcprt.rs`、`agent/src/control_plane/tcprt.rs`、`core/src/tcprt_ops.rs`、`ebpf/src/tcprt.rs` | 既有本机观测能力保留；不新增、不进入 Neutron snapshot、translator、feature flag、status domain 或 smoke |
| 非第一阶段功能：运维排障 | `agent/src/api_handlers/trace.rs`、`agent/src/api_handlers/drops.rs`、`agent/src/api_handlers/ssl.rs`、`agent/src/api_handlers/chains.rs`、`agent/src/control_plane/trace.rs`、`agent/src/control_plane/ssl.rs`、`agent/src/service_chain.rs` | 保留本机 admin-only；不新增、不进入 `neutron-aria-agent` snapshot schema |

新增 Python 子项目：

```text
neutron-aria-agent/
├── pyproject.toml
├── neutron_aria_agent/
│   ├── __init__.py
│   ├── agent.py
│   ├── config.py
│   ├── event_loop.py
│   ├── generation.py
│   ├── local_client.py
│   ├── models.py
│   ├── neutron_client.py
│   ├── state.py
│   ├── status.py
│   ├── translator.py
└── tests/
    ├── test_event_merge.py
    ├── test_generation.py
    ├── test_local_client.py
    ├── test_status.py
    ├── test_translator_acl.py
    └── test_translator_qos.py
```

### 16.2 不可变实现边界

这些边界必须在代码 review 时逐项检查：

- Neutron snapshot/status/capabilities/delete 路由不能挂到现有 TCP REST router 上。
- Neutron snapshot/status/capabilities/delete 路由只由 Unix socket listener 暴露。
- 不新增本机 TCP 端口或临时网络入口。
- `neutron-aria-agent` 不写 eBPF map，不挂载 `/sys/fs/bpf`。
- `aria-datapath` 不访问 Neutron DB，不消费 Neutron RPC。
- `trace`、`drops`、`ssl`、`diagnose`、`service chain` 不进入 `neutron-aria-agent` 配置、事件、snapshot schema 或 status domain。
- Group、Conntrack、Monitoring、WAL、Netlink、Pinned Maps 不能做成可选能力。
- 第一阶段功能模块白名单只有 ACL/QoS；Mirror/TCPrt 代码保留为本机能力，不进入当前阶段 Neutron roadmap、domain status 或 smoke。ACL/QoS 失败时用 `DomainStatus` 和 `effective_action` 表达，不影响 OVS 转发。
- 所有 port 删除、迁移和 unbind 都必须最终清理 orphan map entry。

### 16.3 推荐提交拆分

#### Commit N1-A：Neutron schema 与 OpenAPI 契约

修改文件：

- `api/src/lib.rs`
- `agent/src/openapi.rs`
- `agent/src/neutron_api.rs`
- `docs/neutron-uds-contract.json`
- `ci/check_neutron_stage1.py`

新增类型：

- `NeutronSnapshotRequest`
- `NeutronTenantModel`
- `NeutronPortEntry`
- `NeutronGroupEntry`
- `NeutronAclPolicyEntry`
- `NeutronQosPolicyEntry`
- `NeutronFeatureFlags`
- `NeutronSnapshotResponse`
- `NeutronDomainStatus`
- `NeutronStatusResponse`
- `NeutronPortDeleteResponse`
- `NeutronCapabilitiesResponse`
- `NeutronContractError`

类型约束：

- `schema_version` 第一版固定为 `"1"`。
- `integration_mode` 第一版只接受 `"coexist"`。
- `local_generation` 必填，不能由 `aria-datapath` 自动生成。
- `host` 必填，必须和 `aria-datapath` 本机配置匹配。
- `tenant_model.scope_key` 第一版固定为 `"source/project_id/domain/object_id"`。
- `ports[].port_id`、`ports[].project_id`、`ports[].if_name`、`ports[].mac_address` 必填。
- `groups[].project_id`、`acl_policies[].project_id`、`qos_policies[].project_id` 必填。
- port/group/ACL/QoS 支持对象级 `revision_number` 或等价 `source_revision`。
- `runtime_foundations` 只能表达 `conntrack/monitoring` 运行基础要求。
- feature flags 只允许 `acl/qos` 两个暴露项。
- `NeutronCapabilitiesResponse` 必须包含 `contract_version`、`schema_version_min/max`、`supported_domains`、`mandatory_domains`、`enhancement_domains`、`unsupported_features`、`body_max_bytes`、timeout、`error_codes_hash`、`peer_auth_policy` 和 `capability_hash`。
- error code enum 必须包含 UDS contract 错误码，且序列化值稳定。

测试：

- 扩展 `agent/src/openapi.rs` 里的 `openapi_contains_core_paths_and_components`。
- 新增断言：Neutron schema 都出现在 `/components/schemas`。
- 新增断言：`/api/v1/neutron/snapshot`、`/api/v1/neutron/status`、`/api/v1/neutron/capabilities`、`/api/v1/neutron/ports/{port_id}` 都不出现在现有 TCP router 的普通路径暴露检查里，避免误把 UDS API 当成管理 API。
- 新增断言：四个 UDS paths 都出现在 `neutron-uds-contract.json`。
- 新增 UDS contract artifact drift check：UDS paths、schema refs、capabilities response 和错误码与 DTO 定义一致。

验收：

- GitHub Actions 能编译 `aria-api` 和 `aria-agent`，并运行 Rust DTO/schema/contract 测试。
- OpenAPI schema 名称稳定，UDS contract artifact 可被 Python agent 作为请求/响应校验依据。

#### Commit N1-B：Unix socket listener 与 Neutron-only router

修改文件：

- `agent/src/main.rs`
- `agent/src/api_routes.rs`
- `agent/src/neutron_api.rs`
- `config/aria-agent.toml`

实现要求：

- 在 `Config` 增加 `agent_mode: AgentMode` 或等价显式 `openstack_mode`，并增加 `listen_unix_socket: Option<String>`。
- 默认配置可以为空；OpenStack 示例配置使用 `/run/aria/aria-agent.sock`。
- 只有 `agent_mode = "openstack"` 且配置了 socket 时才启动 Neutron Unix router；单独配置 socket 不能推断 OpenStack mode。
- 启动 Unix socket 时：
  - 创建父目录 `/run/aria`。
  - 删除同路径陈旧 socket 文件。
  - bind `tokio::net::UnixListener`。
  - `chmod` socket 为 `0660`。
  - 校验或记录父目录 owner/group/mode。
  - 启动 `axum::serve(unix_listener, neutron_router)`。
- `api_routes.rs` 新增 `build_neutron_router(control_plane)`，只注册：
  - `PUT /api/v1/neutron/snapshot`
  - `GET /api/v1/neutron/status`
  - `GET /api/v1/neutron/capabilities`
  - `DELETE /api/v1/neutron/ports/{port_id}`
- 现有 `build_router(control_plane)` 不注册 Neutron snapshot/status/capabilities/delete 路由。
- handler skeleton 返回稳定 typed error，不 panic。
- capabilities handler 必须返回 5.1.2 定义的 schema 范围、domain、unsupported features 和 `capability_hash`。
- 写路径记录 peer credential、local_generation、schema_version、accepted/applied result 和 error_code。

验收：

- Neutron snapshot API 不依赖 `listen_addr`。
- 现有 TCP REST API 继续给 `ariactl` 和本机管理员使用。
- OpenStack 模式只要求挂载 `/run/aria`，不要求 `neutron-aria-agent` 使用 host network。
- 只配置 `listen_unix_socket` 但未启用 `agent_mode = "openstack"` 时，不启动 Neutron router。
- Unix router 通过 Local Unix API Contract 验证 request/response、capabilities response 和错误码。

#### Commit N1-C：Rust snapshot apply 编排骨架

新增或修改文件：

- `agent/src/neutron_api.rs`
- `agent/src/neutron_api.rs`

修改文件：

- `agent/src/control_plane.rs`
- `core/src/state.rs`
- `agent/src/neutron_wal.rs`

实现要求：

- handler 只做 JSON 解析、调用 control plane、返回 domain status。
- `control_plane/neutron_snapshot.rs` 负责 apply 顺序：
  1. 校验 `schema_version/host/integration_mode/local_generation`。
  2. 对 snapshot 中的 ports 做 Neutron-managed preflight。
  3. 解析 preflight 通过的 port 到本机 instance/tap_id/ifindex。
  4. 写 WAL intent。
  5. 编译 group/address-set。
  6. 清理被 snapshot 覆盖端口上的旧状态。
  7. apply groups。
  8. apply conntrack/monitoring 基础 runtime。
  9. apply ACL。
  10. apply QoS。
  11. 写 runtime config。
  12. 写 WAL commit。
  13. 更新 generation/status。
- 第一版可以复用现有 `add_group/add_policy/add_qos/update_config` 原子操作，但必须在同一个 snapshot apply 中收集 domain status。
- 如果复用现有原子操作，必须保证这些操作在 WAL intent 之后、WAL commit 之前执行，并且 failure 能进入 domain status。
- `core/src/state.rs` 增加 Neutron 相关状态索引：
  - `neutron_host`
  - `neutron_generation`
  - `neutron_ports`
  - `neutron_domain_status`
  - `neutron_managed`
  - `state_source`
  - `authority_state`
  - `authority_epoch`
  - `local_override_present`
  - `neutron_projects`
  - `neutron_scoped_objects`
  - `neutron_project_domain_status`
  - `neutron_scoped_refcounts`
- `agent/src/neutron_wal.rs` 增加 WAL entry：
  - `NeutronSnapshotApplied`
  - `NeutronPortDeleted`
  - `NeutronStatusUpdated`
- WAL entry 必须区分来源：
  - `source = "neutron"` 用于 snapshot apply。
  - `project_id` 和 scoped object key 用于多租户归属、replay 和 compact。
  - 本机临时排障操作不写 WAL。
  - 本机持久写操作不得写入 Neutron-managed state。
- `accepted_generation` 只能在 snapshot 校验、WAL durable，且各请求 domain 都有 `DomainStatus`、`effective_action` 和 `support_disposition` 后推进；如果 WAL 或 mandatory domain 失败，status 必须 degraded 或 blocked。
- Netlink 可以提前 attach inert/bypass runtime，但不能启用 Neutron feature、写 accepted state 或宣称 Aria ready。

验收：

- 同一个 snapshot 重放两次，第二次不新增重复 group/rule/qos。
- 删除 port 后该 port 相关状态为空，仍被其它 port 引用的 group 不删除。
- 删除 project A 的 port 不会释放 project B 的同名 ACL group/address-set。
- 同一个 snapshot 中多个 project 的 scoped object key 不冲突。
- QoS 失败不会让已成功的 ACL enhancement 状态失效。
- WAL 写入失败进入 runtime domain status，不能被吞掉。
- WAL 恢复测试覆盖 intent without commit、partial apply without commit、commit without status。

#### Commit N1-C2：本机写入 gate 与 WAL 隔离

修改文件：

- `agent/src/api_handlers/groups.rs`
- `agent/src/api_handlers/policies.rs`
- `agent/src/api_handlers/qos.rs`
- `agent/src/api_handlers/config.rs`
- `agent/src/control_plane.rs`
- `core/src/state.rs`

实现要求：

- 对 Neutron-managed instance 或 Neutron-managed port 中已列入 `managed_domains` 的 domain，拒绝本机持久配置写入。
- `openstack_degraded` 仍视为 Neutron-managed，继续拒绝本机配置写入。
- 拒绝范围包括 Neutron-reserved group、policy、qos、mirror 以及影响被纳管 domain 的 config toggle。
- 允许本机只读与临时排障操作，包括 stats、metrics、diagnose、trace、drops flush、tcprt query。
- trace start/stop/flush 不写 WAL，不更新 Neutron generation。
- 增加 authority state：
  - `openstack_managed`
  - `openstack_degraded`
  - `local_break_glass`
  - `local_standalone`
  - `rejoin_pending`
- 本机持久写入只在 `local_break_glass` 或 `local_standalone` 允许。
- `local_break_glass` 写入 local override WAL，不写 Neutron WAL。
- Neutron 通信恢复时，如果存在 local override，进入 `rejoin_pending`。
- 重新接管默认 `Neutron wins`，必须先归档或丢弃 local override，再 full snapshot。
- 拒绝错误码统一为 `LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_DOMAIN`。
- 错误必须提示通过 Neutron 修改配置。

验收：

- `ariactl trace start` 在 Neutron-managed tap 上可用。
- `managed_domains=["acl"]` 时，`ariactl policy add` 被拒绝，`ariactl qos add` 仍允许。
- `managed_domains=["acl","qos"]` 时，`ariactl policy add` 和 `ariactl qos add` 都被拒绝。
- 上述被拒绝操作不写 WAL。
- trace start/stop/flush 不写 WAL，datapath 重启后 trace filter 不恢复。
- Neutron 通信失败时，本机 policy 写入仍被拒绝。
- break-glass 后本机 policy 写入可持久化到 local override WAL。
- Neutron 恢复后，存在 local override 时不自动接管，进入 `rejoin_pending`。
- 执行 discard local overrides 后，full snapshot 覆盖本机托管 domains。

#### Commit N1-D：Status 与 drift 检测

修改文件：

- `api/src/lib.rs`
- `agent/src/neutron_api.rs`
- `agent/src/neutron_api.rs`
- `agent/src/control_plane.rs`

实现要求：

- `GET /api/v1/neutron/status` 返回：
  - `schema_version`
  - `host`
  - `agent_mode`
  - `integration_mode`
  - `agent_health`
  - `overall_readiness`
  - `accepted_generation`
  - `applied_generation`
  - `last_classified_generation`
  - `last_feature_ready_generation_by_domain`
  - `managed_ports`
  - `managed_groups`
  - `domains`
  - `wal`
  - `pinned_runtime`
  - `netlink`
- status 中必须区分：
  - `ready`
  - `degraded`
  - `blocked`
  - `not_requested`
- status 中必须独立表达：
  - `effective_action`
  - `support_disposition`
  - `agent_health`
- `PINNED_RUNTIME_MISSING`、`PORT_IFACE_NOT_FOUND`、`WAL_APPEND_FAILED` 必须能被 status 表达。

验收：

- `neutron-aria-agent` 可以只靠 status 判断是否需要 full resync。
- status 不暴露 trace/drops/ssl/diagnose/service chain。

#### Commit N2-A：Python 项目骨架

新增文件：

- `neutron-aria-agent/pyproject.toml`
- `neutron-aria-agent/neutron_aria_agent/__init__.py`
- `neutron-aria-agent/neutron_aria_agent/config.py`
- `neutron-aria-agent/neutron_aria_agent/models.py`
- `neutron-aria-agent/neutron_aria_agent/generation.py`
- `neutron-aria-agent/tests/test_generation.py`

实现要求：

- package 名称使用 `neutron-aria-agent`。
- Python module 使用 `neutron_aria_agent`。
- console script 使用 `neutron-aria-agent`。
- 配置项至少包含：
  - `host`
  - `resync_interval`
  - `[aria] socket_path = /run/aria/aria-agent.sock`
  - `[agent] managed_domains = acl`
  - `[acl] source = neutron`
- generation 格式固定为 `{host}-{counter:012d}`。

验收：

- Python 单元测试覆盖 generation 单调递增和重启后从本地状态恢复 counter。
- 不需要 OpenStack 环境即可跑 translator/model 单元测试。

#### Commit N2-B：UDS local client

新增文件：

- `neutron-aria-agent/neutron_aria_agent/local_client.py`
- `neutron-aria-agent/tests/test_local_client.py`

实现要求：

- 只接受 `unix://` scheme。
- 拒绝网络 URL、裸 host:port 和空地址。
- 提供四个方法：
  - `put_snapshot(snapshot)`
  - `get_status()`
  - `get_capabilities()`
  - `delete_port(port_id)`
- `get_capabilities()` 必须在 agent startup、UDS reconnect、`aria-datapath` restart 和 capability hash 变化后调用。
- local client 必须从 capability/contract 读取 `body_max_bytes` 并校验 `timeout_ms`；端口级握手后的 mutation 使用请求级 timeout ceiling，不能永久缩短共享 client 默认值。
- 连接失败返回 typed error，供 `status.py` 转成 agent degraded。

验收：

- 单元测试证明非 Unix 地址会被拒绝。
- socket 不存在时不崩溃，返回可上报错误。
- 单元测试覆盖 `get_capabilities()` 成功、schema mismatch、capability mismatch、contract drift 和 capability hash 变化。
- 单元测试覆盖请求体超过 `body_max_bytes` 时本地拒绝或返回 `UDS_BODY_TOO_LARGE`。

#### Commit N2-C：Neutron 投影状态与 translator

新增文件：

- `neutron-aria-agent/neutron_aria_agent/state.py`
- `neutron-aria-agent/neutron_aria_agent/translator.py`
- `neutron-aria-agent/tests/test_translator_acl.py`
- `neutron-aria-agent/tests/test_translator_qos.py`

实现要求：

- `state.py` 保存可重建投影：
  - ports by port_id，并保留 port owner project_id
  - explicit ACL groups by `(project_id, acl_group_id)`
  - qos policies by `(owner_project_id, policy_id)`
  - shared network / shared QoS binding
- `translator.py` 输出和 `api/src/lib.rs` 对齐的 snapshot dict。
- ACL：
  - 当前阶段默认 bypass，不生成隐式 default deny。
  - 只消费显式 ACL enhancement rule，不消费 Neutron Security Group 输入。
  - CIDR 或显式 ACL group 编译成本地 address-set。
  - 跨 project 规则必须来自显式 ACL enhancement policy，不由 translator 自行推导。
- QoS：
  - port-level 覆盖 network-level。
  - shared QoS policy 解析成 per-port effective QoS。
  - 第一版支持 bandwidth limit。
  - minimum bandwidth 和 DSCP 进入 unsupported/degraded status，不静默忽略。
- Mirror/TCPrt：
  - 不进入 translator 输入。
  - 不生成 snapshot 字段。
  - 不作为当前阶段 status domain 或 smoke 验收项。

验收：

- 每个 translator 测试都给出输入对象和完整 snapshot 断言。
- 两个 project 有同名 ACL group 时 snapshot scoped key 不冲突。
- shared network 中 port owner 与 network owner 不同时 ACL 仍按 port owner project 编译。
- shared QoS policy 只影响 Neutron 绑定的 ports，不按 project 全局扩散。
- 不出现 trace/drops/ssl/diagnose/service chain 字段。
- 不出现 mirror/tcprt 字段。

#### Commit N2-D：Agent 主循环与 heartbeat

新增文件：

- `neutron-aria-agent/neutron_aria_agent/agent.py`
- `neutron-aria-agent/neutron_aria_agent/event_loop.py`
- `neutron-aria-agent/neutron_aria_agent/event_merge.py`
- `neutron-aria-agent/neutron_aria_agent/rpc.py`
- `neutron-aria-agent/neutron_aria_agent/neutron_client.py`
- `neutron-aria-agent/neutron_aria_agent/status.py`
- `neutron-aria-agent/tests/test_event_merge.py`
- `neutron-aria-agent/tests/test_status.py`

实现要求：

- 启动顺序：
  1. 读取配置。
  2. 检查 Unix socket status。
  3. 注册 Neutron agent heartbeat。
  4. full resync。
  5. 下发 full snapshot。
  6. 进入事件合并循环。
- event merge：
  - 第一版 RPC event wiring 对照目标环境旧版 OVS agent，只订阅 `PORT UPDATE`、`PORT DELETE`、`NETWORK UPDATE`。
  - `rpc_events_enabled` 默认关闭；未显式开启时只做 heartbeat/full-resync，不消费 RabbitMQ 事件。
  - `incremental_rpc_enabled` 生产默认必须保持 false；P3 port-scoped apply 已有显式配置入口，但只能在受控 P3 gate 下开启。
  - merge window 默认 `0.2s`，允许配置在 100ms-500ms 之间调优。
  - port update 按 port_id 合并。
  - port update 带 `binding:host_id` / `revision_number` 时保留最新 revision 或最后 binding 结果。
  - fanout 到本 agent 但 `binding_host` 明确不是本机的 update，不触发本机 full-resync；只有该 port 已在本机 projected state 中时才调用本地 delete。
  - port delete 使用旧版 Neutron 的 `kwargs["port_id"]` 语义；只删除本机已知 port，避免误处理其它 compute 的 fanout delete。
  - network update 当前没有 network->local ports 增量索引，第一版按 full-resync 处理。
  - backlog 超过 `event_queue_max_ports/event_queue_max_networks` 时丢弃增量队列并触发 full-resync。
  - explicit ACL group/policy update 找出本 host 相关 ports。
  - QoS update 找出绑定 policy 的 ports。
  - 非 ACL/QoS 的本机能力 update 不进入 Neutron event merge。
- status：
  - datapath socket 不可达时 Neutron agent degraded。
  - `runtime.blocked` 时 agent degraded 并触发 full resync。
  - `acl.degraded/blocked` 时 agent degraded，但必须确认 datapath bypass 不影响 OVS 转发。
  - `qos.degraded` 不影响 alive，但必须上报原因。

验收：

- socket 断开后进入 degraded。
- socket 恢复后 full resync。
- burst event 合并窗口内只提交一次 snapshot。

#### Commit N3：ACL Enhancement 垂直闭环

修改重点：

- Rust snapshot apply 的 groups + ACL enhancement domain。
- Python translator 的显式 ACL enhancement、CIDR/group address-set。
- DevStack smoke 中确认 Aria ACL `DomainStatus=degraded,effective_action=bypass` 不影响原 OVS 转发。

验收：

- ACL enhancement 未配置或未 ready 时 VM 仍按原 OVS 连通性转发。
- 启用 ACL enhancement 后，显式规则按预期影响 Aria domain 行为。
- 显式 ACL group/policy 更新能影响本 host 已绑定 port。
- 两个 project 的同名 ACL group 不互相串 scoped key。
- shared network 场景不因为 project_id 不同被 Aria 额外丢包。
- Aria ACL `DomainStatus=degraded,effective_action=bypass` 不形成双重过滤或转发中断。

#### Commit N4：QoS 垂直闭环

修改重点：

- bandwidth limit rule 翻译。
- port-level 覆盖 network-level。
- Rust QoS domain status。
- QoS stats smoke。

验收：

- egress shaping 可观察。
- ingress policing 降级明确上报。
- 删除 QoS policy 后 token bucket 清理。
- shared QoS 只作用于被 Neutron 绑定的 port。
- QoS 失败不影响 ACL。

#### Commit N5：容器骨架与部署 Smoke

新增文件：

- `containers/aria-datapath/Dockerfile`
- `containers/neutron-aria-agent/Dockerfile`
- `deploy/openstack/aria-datapath.container.example`
- `deploy/openstack/neutron-aria-agent.container.example`
- `deploy/openstack/aria-agent.toml`
- `deploy/openstack/neutron-aria-agent.ini`
- `deploy/openstack/smoke.sh`

实现要求：

- `aria-datapath` 容器：
  - 包含 `aria-agent`、`ariactl`、eBPF artifact。
  - 需要 host network 或等价网络命名空间。
  - 挂载 `/run/aria`、`/sys/fs/bpf`、`/sys/kernel/btf`、`/var/lib/aria-agent`、`/var/log/aria-agent`。
- `neutron-aria-agent` 容器：
  - 只挂载 `/run/aria` 和 Neutron 配置。
  - 不授予 eBPF capability。
  - 不使用 host network，除非目标 OpenStack 管理网络本身要求。

验收：

- 两个容器通过 `/run/aria/aria-agent.sock` 通信。
- `neutron-aria-agent` 不需要访问 `/sys/fs/bpf`。
- `deploy/openstack/smoke.sh` 支持 PR-6A 与 PR-6B 两种 profile：PR-6A 只覆盖 agent alive、snapshot 下发、默认 bypass、socket 权限和 host mounts；PR-6B 在 ACL/QoS feature gate 通过后覆盖 ACL/QoS 基础链路和生产化硬化检查。

### 16.4 GitHub Actions 细化

CI 工作包必须把 `.github/workflows/build.yml` 拆成三个可见阶段：

1. Rust build + tests + schema contract：
   - 继续构建 eBPF、`ariactl`、`aria-agent`。
   - 在 GitHub Actions 中运行 Rust API DTO serde、OpenAPI components、TCP path exclusion、Unix router、snapshot apply skeleton、WAL recovery 和 status schema 测试。
   - 生成或校验 `neutron-uds-contract.json`，并上传为 CI artifact。
   - contract drift check 必须覆盖 UDS snapshot/status/capabilities/delete paths、schema refs、错误码、contract version、body/timeout 元字段、peer auth policy 和 capability response。
   - 运行首阶段 mock scale/perf smoke，至少验证 body size、full resync mock p95、port-scoped snapshot p95、event merge window 和 status 查询 p95。
   - 按 13.4.2 生成 `perf-summary.json`，按 13.4.3 读取 `ci/perf-baseline.json` 做回归判断，并将二者作为 CI artifact 上传。
   - 继续上传 `firewall-binaries-x86_64` artifact。
2. Python agent test：
   - 安装 `neutron-aria-agent` 的 test dependencies。
   - 运行 Python 单元测试。
   - 使用 `neutron-uds-contract.json` 校验 local client request/response。
   - 覆盖 `get_capabilities()`、startup capability handshake、capability hash 变化 full resync、UDS schema/capability mismatch 降级。
   - 校验 Python client 使用 contract 中的 body 上限，并把 timeout 作为 mutation 请求级 ceiling，不污染共享 client 默认值。
   - 运行 formatter/linter 检查。
3. Container packaging：
   - 构建 `aria-datapath` image。
   - 构建 `neutron-aria-agent` image。
   - 上传镜像构建元数据或 tar artifact。

本地开发仍遵守仓库规则：不运行 `cargo build`、`cargo check`、`cargo test`。文档阶段只做：

```bash
git diff --check
rg -n "[ \t]+$" docs/openstack-neutron-agent-mode.md README.md
```

### 16.5 阶段门槛

| 门槛 | 必须满足后才能进入下一阶段 |
| --- | --- |
| N1 -> N2 | Rust DTO/OpenAPI、Unix socket snapshot/status/capabilities/delete API、显式 `agent_mode = "openstack"`、本机写入 gate 合入，Neutron 路由不在 TCP router 暴露，`neutron-uds-contract.json` drift check 通过，`N0.5-lite` 完成，GitHub Actions Rust build + tests + schema contract 通过 |
| N2 -> N3 | Python agent 能 full resync、下发 full snapshot、`AgentHealth` 与 readiness 映射正确，多 project translator 测试通过，完整 N0.5 目标环境兼容性发现完成 |
| N3 -> N4 | ACL enhancement 垂直闭环通过，ACL `DomainStatus=degraded,effective_action=bypass` 不影响原 OVS 转发，同名 `explicit_acl_group` 跨 project 不串 |
| N4 -> N5 | QoS bandwidth limit 可观察，shared QoS 绑定语义正确，QoS domain 失败不影响 OVS 转发 |
| PR-4 + 完整 N0.5 -> N5/PR-6A | 容器骨架、host mounts、UDS 权限、agent alive、snapshot 下发和默认 bypass smoke 通过；不验证未过 gate 的 QoS |
| N5/PR-6A + PR-5A/PR-5B -> N6/PR-6B | ACL/QoS 对应 feature gate 已通过，完整 deployment smoke 覆盖所有纳入 scope 的 feature，并完成生产化 hardening、持久化、双实例、capabilities、host mounts 和 runbook 验证 |

### 16.6 落地执行计划

开发从 N1 开始，不先写 Python agent 的完整业务逻辑。原因是 Python 侧必须依赖 Rust 侧稳定的 snapshot schema、Unix socket API、status 语义和本机写入 gate。

最终大步骤口径见 14.0。实际开发推荐按 10 个小 PR 或连续 commit 落地，其中 PR-1 拆成 1A/1B，PR-5 拆成 5A/5B，PR-6 拆成 6A/6B，先稳定 DTO，再接 Unix socket router：

| 顺序 | 名称 | 目标 | 是否依赖前置 | 是否需要 OpenStack 环境 |
| --- | --- | --- | --- | --- |
| PR-0 | 文档基线 | 提交本方案、README 链接和分支基线 | 无 | 否 |
| PR-1A | N1-A | Rust schema、OpenAPI、对象级 revision 约束 | PR-0 | 否 |
| PR-1B | N1-B | Unix socket router、显式 `agent_mode`、socket 权限策略 | PR-1A | 否 |
| PR-2 | N1-C/N1-C2/N1-D | Snapshot apply 骨架、写入 gate、status、WAL intent/commit 恢复语义 | PR-1B | 否 |
| PR-3 | N2-A/N2-B | Python package 骨架、UDS client | PR-1A，UDS 集成依赖 PR-1B | 否 |
| PR-4 | N2-C/N2-D | Neutron 投影、translator、event loop、heartbeat | PR-2/PR-3 | 可用 mock |
| PR-5A | N3 | ACL enhancement 垂直闭环 | PR-4 | 是 |
| PR-5B | N4 | QoS 垂直闭环 | PR-4 | 是 |
| PR-6A | N5 container skeleton | 容器、host mounts、UDS 权限、agent alive、snapshot 下发、默认 bypass smoke | PR-4，完整 N0.5 | 是 |
| PR-6B | N6 full smoke + hardening | ACL/QoS 已通过 feature gate 后的完整 deployment smoke 和生产化硬化 | PR-5A/PR-5B/PR-6A | 是 |

并行规则：

- PR-1A 必须先做，作为 Rust/Python 共同 DTO 契约。
- PR-1A 可以先开发 DTO，但 schema freeze 前必须完成 `N0.5-lite`，确认 direction 和 attach 点不会改变字段语义。
- PR-1B 依赖 PR-1A，负责本机传输和 `agent_mode` 开关，不和 schema 混在同一个变更里。
- PR-2 和 PR-3 可以并行，但 PR-3 的 UDS 集成测试依赖 PR-1B，PR-4 不能早于 PR-2。
- PR-5A 的 ACL enhancement 必须独立完成并可单独回滚；PR-5B 的 QoS 不能和 ACL 边界验证混在同一个 PR。
- N3 ACL enhancement 必须早于 N4 的生产 smoke，因为它验证 feature domain 与 OVS 转发的隔离边界。
- Dockerfile 可以在 PR-3 后开始；PR-6A 只验证容器骨架、UDS、heartbeat、snapshot 下发和默认 bypass，不验证未过 gate 的 QoS。
- PR-6B 才是完整 deployment smoke，必须等 PR-5A/PR-5B 对应 feature gate 通过后执行。
- OpenStack 环境验证不阻塞 PR-1 到 PR-4，但会阻塞进入 PR-5A 之后的阶段门槛。
- PR-5A 开始前必须完成 N0.5 目标环境兼容性发现。
- N3/N4 smoke 前不得在目标环境全局切换 OVS 转发或 SG/firewall flow；当前阶段只验证 Aria 增强不影响原转发。
- 任何进入 PR-6B 的 feature 不允许继续保持 `support_disposition=unknown`；未纳入 PR-6A 的 feature 只能写成 out of smoke scope，不能计为通过。

每个 PR 的共同要求：

- 提交信息使用 `feat:`、`test:`、`docs:` 或 `ci:` 前缀。
- 不在本地运行 `cargo build`、`cargo check`、`cargo test`。
- Rust 编译验证只看 GitHub Actions。
- 文档或 Python-only 阶段可以本地运行 `git diff --check` 和 Python 单元测试。
- 每个 PR 合入前必须确认没有把 Neutron snapshot/status/capabilities/delete 任一 UDS route 暴露到现有 TCP router 或 TCP OpenAPI paths。

### 16.7 第一批可执行工作包

#### Work Package 0：提交方案基线

目标：先把方案作为 `v0.9-neutron-agent` 分支的开发合同提交。

修改范围：

- `README.md`
- `docs/openstack-neutron-agent-mode.md`

本地验证：

```bash
git diff --check
rg -n "[ \t]+$" docs/openstack-neutron-agent-mode.md README.md
```

硬验收 checklist：

- README 能跳转到 OpenStack Neutron Agent Mode 方案。
- 方案明确 `neutron-aria-agent`、`aria-datapath`、Unix socket、容器化、多租户、authority state 和 N1-N6 阶段门槛。
- 方案明确第一阶段新增功能模块白名单只有 ACL/QoS；其它能力只允许作为支撑能力或既有本机能力出现。
- README、主方案、报告材料都使用 OVS enhancement / ACL enhancement 统一口径。
- `docs/openstack-target-env-discovery.md` 模板存在，并被 N0.5 阶段引用。
- 不残留旧式安全组组合投影、更新或 port-security-disabled 这类当前阶段交付口径。
- `git diff --check` 通过。
- 不触碰 Rust/Python 实现代码。

#### Work Package 1：Rust API 契约

目标：先让 `api` crate 拥有稳定的 Neutron snapshot/status/capabilities/delete DTO。

修改范围：

- `api/src/lib.rs`
- `agent/src/openapi.rs`
- `agent/src/neutron_api.rs`
- `docs/neutron-uds-contract.json`
- `ci/check_neutron_stage1.py`

新增或修改内容：

- `NeutronSnapshotRequest`
- `NeutronTenantModel`
- `NeutronPortEntry`
- `NeutronGroupEntry`
- `NeutronAclPolicyEntry`
- `NeutronQosPolicyEntry`
- `NeutronFeatureFlags`
- `NeutronSnapshotResponse`
- `NeutronDomainStatus`
- `NeutronStatusResponse`
- `NeutronPortDeleteResponse`
- `NeutronCapabilitiesResponse`
- `NeutronContractError`

测试要求：

- OpenAPI components 包含所有 Neutron DTO。
- OpenAPI paths 不包含 `/api/v1/neutron/snapshot`、`/api/v1/neutron/status`、`/api/v1/neutron/capabilities`、`/api/v1/neutron/ports/{port_id}`，因为这些 API 只属于 UDS router。
- `neutron-uds-contract.json` 包含 snapshot/status/capabilities/delete 四个 UDS paths、schema refs、错误码和 capability response。
- `neutron-uds-contract.json` 包含 `contract_version`、`body_max_bytes`、`timeout_ms`、`error_codes_hash` 和 `peer_auth_policy`。
- CI 中的 contract drift test 能发现 DTO、错误码或 UDS path 漂移。
- CI 中的 contract drift test 能发现 contract 元字段、capability response 和 error code hash 漂移。
- DTO serde 测试覆盖：
  - 多 project snapshot。
  - shared network 的 `network_project_id`。
  - `tenant_model.scope_key = "source/project_id/domain/object_id"`。
  - port/group/ACL/QoS 的对象级 `revision_number` 或等价 `source_revision`。
  - ACL/QoS 两个 domain 的最小合法输入。

硬验收 checklist：

- Python agent 可以按这些 DTO 手写或生成 snapshot dict。
- Python agent 可以按 `neutron-uds-contract.json` 校验 UDS request/response。
- Python agent 可以按 `neutron-uds-contract.json` 读取 body 上限、timeout 和 peer auth policy。
- `project_id` 必填约束写入类型或显式校验。
- 对象级 revision 字段可被 Python agent 用于 stale update 过滤。
- feature flags 只暴露 `acl/qos`。
- DTO serde roundtrip 覆盖 13.4.1 固定规模 fixture。
- ACL DTO 只表达显式 ACL enhancement，不包含 Security Group projection 字段；contract artifact 覆盖 13.4.2 需要的 body 上限和 timeout 字段。

#### Work Package 2：Unix Socket Neutron Router

目标：新增只监听 Unix socket 的 Neutron-only API 入口，保持 TCP router 不变。

修改范围：

- `agent/src/main.rs`
- `agent/src/api_routes.rs`
- `agent/src/neutron_api.rs`
- `config/aria-agent.toml`

实现要求：

- `Config` 增加 `agent_mode: AgentMode` 或等价显式 `openstack_mode`，并增加 `listen_unix_socket: Option<String>`。
- 只有 `agent_mode = "openstack"` 且配置了 `listen_unix_socket` 时才启动 Neutron Unix router。
- `build_neutron_router(control_plane)` 只注册：
  - `PUT /api/v1/neutron/snapshot`
  - `GET /api/v1/neutron/status`
  - `GET /api/v1/neutron/capabilities`
  - `DELETE /api/v1/neutron/ports/{port_id}`
- 现有 `build_router(control_plane)` 不注册任何 Neutron UDS 路由。
- OpenStack 示例配置使用 `/run/aria/aria-agent.sock`。
- socket 文件权限固定为 `0660`，父目录由容器 entrypoint 或进程启动时确保存在。

测试要求：

- router 单元测试确认 TCP router 不包含 Neutron snapshot/status/capabilities/delete route。
- Unix router 单元测试确认只包含 snapshot/status/capabilities/delete 四个 route。
- Unix router 单元测试确认 request/response/capabilities response/error code 符合 Local Unix API Contract。

硬验收 checklist：

- `neutron-aria-agent` 只需要挂载 `/run/aria`。
- 不新增 localhost HTTP 过渡入口。
- 不要求 `neutron-aria-agent` 使用 host network。
- TCP OpenAPI paths 不出现 Neutron snapshot/status/capabilities/delete route。
- Unix socket 权限和 peer credential 校验有测试或明确 typed error。
- `neutron-uds-contract.json` drift check 能覆盖四个 UDS paths。

#### Work Package 3：Snapshot Apply 骨架

目标：让 Rust 侧能接受 snapshot、生成 domain status，并以幂等方式更新本机托管状态。

修改范围：

- `agent/src/neutron_api.rs`
- `agent/src/control_plane.rs`
- `core/src/state.rs`
- `agent/src/neutron_wal.rs`

实现要求：

- 新增 `authority_state`、`authority_epoch`、`local_override_present`。
- 新增 `neutron_projects`、`neutron_scoped_objects`、`neutron_project_domain_status`、`neutron_scoped_refcounts`。
- `NeutronSnapshotApplied` WAL entry 带 `source = "neutron"`、`project_id`、domain 和 scoped object key。
- apply 顺序固定为 schema/authority -> Neutron-managed preflight -> WAL intent -> groups -> conntrack/monitoring -> ACL -> QoS -> WAL commit -> status。
- 同 generation 重放幂等。
- 任一 enhancement domain 失败不影响其它 domain，也不影响 OVS 转发。
- Netlink 可提前 attach inert/bypass runtime，但 snapshot apply 不能在 preflight 失败时启用任何 feature flag。
- domain status 输出顺序固定为 `runtime -> groups -> conntrack -> monitoring -> acl -> qos`。

测试要求：

- 同一个 snapshot 重放两次，不产生重复 group/rule/qos。
- 删除 project A port 不释放 project B 的同名 group/address-set。
- tap 不存在时不执行 eBPF attach，不写 accepted datapath state。
- Netlink 已提前 attach inert runtime 时，未 accepted snapshot 前所有 feature flags 仍为 off/bypass。
- ifindex 不匹配时返回 `PORT_IFINDEX_NOT_READY` 或 degraded status。
- VM reboot/tap recreate 后旧 ifindex cleanup 幂等，新 ifindex ready 后重新 attach。
- WAL append 失败能进入 runtime domain status。
- QoS 失败时 ACL status 可独立表达 `ready` 或 `degraded`。
- ACL enhancement 或 conntrack 未 ready 时必须 `effective_action=bypass`，并按原因返回 `DomainStatus=not_requested`、`degraded` 或 `blocked`，不能影响 OVS 转发。
- Monitoring 失败默认只进入 observability degraded；承诺统计时不能上报 stats ready。

硬验收 checklist：

- `GET /api/v1/neutron/status` 能返回 `accepted_generation`、`applied_generation`、`last_classified_generation`、`last_feature_ready_generation_by_domain` 和 per-domain status。
- `DELETE /api/v1/neutron/ports/{port_id}` 能清理该 port 的托管状态，并等待下一次 full snapshot 最终校准。
- `accepted_generation` 只在 WAL durable 和请求 domain 终态明确后推进。
- ACL/conntrack 未 ready 时返回结构化 `DomainStatus` 和 `effective_action=bypass`，不影响 OVS 转发。
- 同 generation 重放幂等，不重复写 group/rule/qos。
- WAL append/commit 失败进入 `DomainStatus=blocked` 或 `degraded`，不假 ready。
- 13.4.1 固定规模 fixture 的 full snapshot 不超过预算或返回 typed error。

#### Work Package 4：本机写入 Gate

目标：OpenStack managed/degraded 状态下，拒绝本机持久配置写入，同时保留只读和临时排障。

修改范围：

- `agent/src/api_handlers/groups.rs`
- `agent/src/api_handlers/policies.rs`
- `agent/src/api_handlers/qos.rs`
- `agent/src/api_handlers/config.rs`
- `agent/src/control_plane.rs`
- `core/src/state.rs`
- `agent/src/neutron_wal.rs`

拒绝范围：

- group add/delete。
- policy add/delete。
- qos add/delete，前提是 `qos` 已被列入 `managed_domains`。
- ACL/QoS config toggle。

允许范围：

- health、status、stats、metrics。
- diagnose。
- trace start/stop/list/flush。
- drops list/flush。
- tcprt query/list。

硬验收 checklist：

- `openstack_managed` 和 `openstack_degraded` 下，针对已列入 `managed_domains` 的本机持久写入返回 `LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_DOMAIN`。
- trace 不写 WAL，不更新 Neutron generation。
- break-glass 写入 local override WAL。
- Neutron 恢复后存在 local override 时进入 `rejoin_pending`。
- gate 放在 control plane 写入口，不只放在 HTTP handler。
- 所有拒绝路径都有错误码、HTTP 409 或等价本机 API response。

#### Work Package 5：Python Agent 骨架与 UDS Client

目标：建立 `neutron-aria-agent` Python 子项目，先完成配置、模型、generation 和 Unix socket client。

新增范围：

- `neutron-aria-agent/pyproject.toml`
- `neutron-aria-agent/neutron_aria_agent/__init__.py`
- `neutron-aria-agent/neutron_aria_agent/config.py`
- `neutron-aria-agent/neutron_aria_agent/models.py`
- `neutron-aria-agent/neutron_aria_agent/generation.py`
- `neutron-aria-agent/neutron_aria_agent/local_client.py`
- `neutron-aria-agent/tests/test_generation.py`
- `neutron-aria-agent/tests/test_local_client.py`

实现要求：

- package 名称是 `neutron-aria-agent`。
- Python module 是 `neutron_aria_agent`。
- console script 是 `neutron-aria-agent`。
- 只接受 `unix:///run/aria/aria-agent.sock` 这类地址。
- 拒绝 TCP URL、裸 host:port 和空地址。
- generation 固定为 `{host}-{counter:012d}`，并能从本地状态恢复 counter。

本地验证：

```bash
cd neutron-aria-agent
python -m pytest tests/test_generation.py tests/test_local_client.py -q
```

硬验收 checklist：

- 不需要 OpenStack 环境即可测试。
- socket 不存在时返回 typed error，供 heartbeat 上报 degraded。
- `[aria] socket_path` 只接受 Unix socket path，拒绝 TCP/HTTP fallback。
- `get_capabilities()` 在 startup/reconnect 后先执行，能识别 contract drift、schema mismatch 和 capability mismatch。
- Python client 使用 contract/capabilities 中的 body 上限，校验 timeout，并对端口级 mutation 应用请求级 timeout ceiling；超过限制时返回 typed error。
- generation counter 可从本地 state file 恢复。
- Python 单元测试不依赖真实 Neutron 或 oslo messaging。
- 配置包含 `[acl] source = neutron`、可选 `[acl] fixture_path`；生产路径不得要求 `acl_tag_prefix` 或 `acl_policy_mapping_file`。

#### Work Package 6：Neutron 投影与 Translator

目标：把 Neutron 对象投影成 Aria snapshot，不直接写 datapath。

新增范围：

- `neutron-aria-agent/neutron_aria_agent/state.py`
- `neutron-aria-agent/neutron_aria_agent/translator.py`
- `neutron-aria-agent/tests/test_translator_acl.py`
- `neutron-aria-agent/tests/test_translator_qos.py`

实现要求：

- ports by port_id，并保留 owner project。
- explicit ACL groups by `(project_id, acl_group_id)`。
- QoS policies by `(owner_project_id, policy_id)`。
- shared network、shared QoS 在 Python 侧解析成 per-port effective policy。

硬验收 checklist：

- 两个 project 有同名 ACL group 时 scoped key 不冲突。
- shared network 不因为 port owner 和 network owner 不同而被额外丢包。
- port migration 后 `binding_host` 变化能把 port 从旧 projected state 移到新 projected state。
- shared QoS 只作用于绑定 port。
- snapshot 不包含 trace/drops/ssl/diagnose/service chain。
- snapshot 不包含 mirror/tcprt。
- ACL 输入只来自 `aria_acl` Neutron service plugin/API/DB；fixture 仅用于 CI/smoke，历史 tag + 本机只读 mapping 仅用于 lab/bootstrap/迁移辅助；不消费 Security Group。

#### Work Package 7：主循环、Heartbeat 与事件合并

目标：让 `neutron-aria-agent` 能 full resync、提交 snapshot、处理事件合并并上报状态。

新增范围：

- `neutron-aria-agent/neutron_aria_agent/agent.py`
- `neutron-aria-agent/neutron_aria_agent/event_loop.py`
- `neutron-aria-agent/neutron_aria_agent/event_merge.py`
- `neutron-aria-agent/neutron_aria_agent/rpc.py`
- `neutron-aria-agent/neutron_aria_agent/neutron_client.py`
- `neutron-aria-agent/neutron_aria_agent/status.py`
- `neutron-aria-agent/tests/test_event_merge.py`
- `neutron-aria-agent/tests/test_status.py`

实现要求：

- 启动后先检查 Unix socket status。
- socket 不可达时 agent degraded，不本地接管。
- full resync 后提交 full snapshot。
- RPC event 第一版只消费目标环境已确认的旧版 Neutron topic：`q-agent-notifier` 下的 `port.update`、`port.delete`、`network.update`。
- 默认 `rpc_events_enabled=false`；只有 full-resync、port source、UDS snapshot 都配置完成后才开启。
- 默认 `incremental_rpc_enabled=false`；P3 port-scoped apply 只能在受控 P3 gate 下显式开启，不能作为生产默认。
- port update 按 port_id 合并。
- port migration/rebind event 按 `source_revision` 去重，保留最新 `binding_host`。
- 本 host 失去 port binding 时，如果该 port 存在于本机 projected state，调用本地 delete；如果不是本机已知 port，忽略该 fanout event。
- 本 host 获得 port binding 时，当前第一版触发 full-resync；port-scoped snapshot 等 translator/state cache 完成后再启用。
- ACL/QoS update 后续只重算相关 ports；当前 RPC event skeleton 不提前硬编码 ACL/QoS translator。
- burst window 内只提交一次 snapshot。
- event backlog 超过上限时触发 full-resync。
- status 模块必须区分 OVS connectivity ready 和 Aria security/features ready；不能把 Aria degraded 翻译成 OVS 停止转发。

硬验收 checklist：

- socket 断开进入 degraded。
- socket 恢复后 full resync。
- 旧 host 丢失 unbind event 时，full resync 清理 stale port。
- 新 host 丢失 bind event 时，full resync 补齐 port state。
- ACL degraded/blocked 让 agent degraded。
- QoS degraded 不影响 alive，但必须上报原因。
- ACL/conntrack blocked 时上报 Aria readiness=false、对应 `DomainStatus=blocked` 或 `degraded`，并明确 `effective_action=bypass` 不影响 OVS 转发。
- burst event 合并窗口内只提交一次 snapshot；超过 backlog 策略时触发 full resync。

#### Work Package 8：容器与 OpenStack Smoke

目标：形成无编排环境可部署的两个容器和 smoke 验证。

新增范围：

- `containers/aria-datapath/Dockerfile`
- `containers/neutron-aria-agent/Dockerfile`
- `deploy/openstack/aria-datapath.container.example`
- `deploy/openstack/neutron-aria-agent.container.example`
- `deploy/openstack/aria-agent.toml`
- `deploy/openstack/neutron-aria-agent.ini`
- `deploy/openstack/smoke.sh`

实现要求：

- `aria-datapath` 容器包含 `aria-agent`、`ariactl` 和 eBPF artifact。
- `aria-datapath` 挂载 `/run/aria`、`/sys/fs/bpf`、`/sys/kernel/btf`、`/var/lib/aria-agent`、`/var/log/aria-agent`。
- `neutron-aria-agent` 只挂载 `/run/aria` 和 Neutron 配置。
- `neutron-aria-agent` 不授予 eBPF capability。
- 两个容器通过 `/run/aria/aria-agent.sock` 通信。

硬验收 checklist：

- PR-6A smoke 覆盖 agent alive、snapshot 下发、默认 bypass、socket 权限和 host mounts。
- PR-6B smoke 在 ACL/QoS feature gate 通过后覆盖 ACL/QoS 基础链路；未过 gate 的 feature 不计入通过项。
- socket 权限、capabilities、host mounts 被显式验证。
- 删除容器不丢失 WAL/state。
- `docs/openstack-target-env-discovery.md` 完整 N0.5 项已补齐证据。
- 默认 bypass smoke 证明 Aria degraded 不影响原 OVS 转发。
- 显式 `aria_acl` binding smoke 覆盖 ready、policy missing/input invalid degraded 两条路径；fixture smoke 只验证 CI/本地 datapath，不替代产品路径。
- GitHub Actions 有 Python test job 和 container packaging job。

### 16.8 开发启动检查清单

正式开始写代码前，先确认：

- 当前分支是 `v0.9-neutron-agent`。
- 工作目录是 `/Users/chen/code/aria-firewall-v0.9-neutron-agent`。
- remote 指向 `git@github.com:chenyongming211-glitch/aria-firewall.git`。
- Git identity 使用 `netmouser <chenyongming211@gmail.com>`。
- 本地不运行 `cargo build`、`cargo check`、`cargo test`。
- 代码提交后由 GitHub Actions 编译。
- PR-1 前不需要 OpenStack 环境。
- N3 之前必须确定目标 OpenStack 版本、tap 接入方式，以及 Aria `DomainStatus=degraded,effective_action=bypass` 不影响 OVS 转发的验证方式。

建议第一天只做 PR-0 和 PR-1：

1. 提交本方案基线。
2. 增加 Neutron DTO 和 OpenAPI schema。
3. 增加 Unix socket router skeleton。
4. 推送分支，让 GitHub Actions 验证 Rust 编译。
5. 根据 CI 修正 Rust 编译问题。

### 16.9 免询问默认决策

后续开始开发时，除非遇到代码事实冲突，默认按以下决策执行，不再单独确认。

通用默认：

- 开发分支固定为 `v0.9-neutron-agent`。
- 工作目录固定为 `/Users/chen/code/aria-firewall-v0.9-neutron-agent`。
- remote 固定为 `git@github.com:chenyongming211-glitch/aria-firewall.git`。
- 提交身份固定为 `netmouser <chenyongming211@gmail.com>`。
- Rust 编译、测试和打包只通过 GitHub Actions 验证，本地不运行 `cargo build`、`cargo check`、`cargo test`。
- 文档和 Python 单元测试可以本地执行。
- 每个工作包完成后独立提交，提交信息使用 `docs:`、`feat:`、`test:` 或 `ci:`。
- 如果 GitHub Actions 失败，直接按 CI 日志修复，不重新讨论路线。

Rust 默认：

- `api` crate 只定义稳定 DTO、serde 和 OpenAPI schema，不依赖 agent 内部状态。
- Neutron snapshot API 不注册到现有 TCP router。
- Neutron snapshot API 只通过 Unix socket router 暴露。
- Unix socket 路径默认 `/run/aria/aria-agent.sock`。
- OpenStack 模式下仍运行现有 `aria-agent` binary，不改 binary 名。
- `aria-datapath` 是角色名和容器名，不改 crate、binary、socket、state、log 路径。
- scoped object key 作为内部逻辑 key；eBPF map 继续使用紧凑 numeric ID，numeric ID 由 state 持久化映射保证稳定。

Python 默认：

- Python package 名称 `neutron-aria-agent`。
- Python module 名称 `neutron_aria_agent`。
- Console script 名称 `neutron-aria-agent`。
- 最低 Python 版本按 Ubuntu 22.04 环境采用 Python 3.10。
- 单元测试使用 `pytest`。
- UDS HTTP client 使用 `httpx` 的 Unix socket transport。
- 模型优先使用 `dataclasses` 和普通 dict，不引入重型 schema 框架。
- OpenStack 依赖隔离在 `neutron_client.py`，translator/model/local_client/status 单元测试不需要真实 OpenStack。

OpenStack 默认：

- `neutron-aria-agent` 使用 Neutron 服务账号读取状态，不接受租户直接调用。
- `neutron-aria-agent` 不写 eBPF map，不挂载 `/sys/fs/bpf`。
- `aria-datapath` 不访问 Neutron DB，不消费 Neutron RPC。
- 通信失败只进入 `openstack_degraded`，不自动切到本机可写。
- break-glass 必须显式触发，且写 local override WAL。
- 重新接管默认 `Neutron wins`，不做自动 local wins merge。
- 新 port 没有 accepted snapshot 前不能标记 Aria ready。
- 当前阶段不关闭或旁路 OVS 转发能力；如果未来需要 SG replacement mode，必须另起设计。
- 如果 Aria ACL 未 ready，agent 必须 degraded，但不能影响原有 OVS 转发。

功能默认：

- 第一阶段功能模块白名单只有 ACL/QoS；N3 MVP 只要求 ACL enhancement 闭环，N4 才进入 QoS 闭环。
- Group、Conntrack、Monitoring、WAL、Netlink、Pinned Maps 是必选支撑能力。
- trace、drops、ssl、diagnose、service chain 代码保留为既有本机管理员能力，但不新增、不进入 `neutron-aria-agent` 暴露面。
- Mirror/TCPrt Rust 代码保留为既有本机能力，但不进入 `neutron-aria-agent`、snapshot、translator、feature flag、status domain、smoke 或 PR gate。

WAL 默认：

- Neutron 托管写入使用 `neutron-state.wal`。
- break-glass 本机覆盖写入使用 `local-override.wal`。
- standalone/local legacy 模式继续使用 `state.wal`。
- 重新接管前先归档 `local-override.wal`，再执行 Neutron full snapshot。

### 16.10 技术执行章节细化

下面 8 个技术执行章节对应 Work Package 1 到 Work Package 8，用于展开 Rust/Python/feature/container 的具体实现任务。它不是最终方案总步骤数；最终管理口径以 14.0 的 9 个大步骤为准，落地口径以 16.6 的 10 个 PR/commit 为准。Work Package 0、N0.5 discovery gate、PR-6A/PR-6B 拆分和 N6 hardening 在阶段门槛与 PR 表中表达。

#### 执行章节 1：Rust API 契约

目标：让 Rust/Python 双方先共享稳定 snapshot/status/capabilities/delete schema。

文件范围：

- `api/src/lib.rs`
- `agent/src/openapi.rs`
- `agent/src/neutron_api.rs`
- `docs/neutron-uds-contract.json`
- `ci/check_neutron_stage1.py`

默认实现顺序：

1. 在 `api/src/lib.rs` 增加 Neutron DTO，全部派生 `Debug`、`Clone`、`Serialize`、`Deserialize`、`ToSchema`。
2. 对 request/response 增加 `#[schema(example = json!(...))]`，示例必须包含多 project、shared network、ACL/QoS。
3. 增加 `NeutronTenantModel`，默认字段：
   - `scope_key`
   - `shared_object_policy`
4. 增加 `NeutronSnapshotRequest`，默认字段：
   - `schema_version`
   - `local_generation`
   - `host`
   - `integration_mode`
   - `full`
   - `tenant_model`
   - `runtime_foundations`
   - `ports`
   - `groups`
   - `acl_policies`
   - `qos_policies`
   - `feature_flags`
5. 增加 `NeutronSnapshotResponse` 和 `NeutronStatusResponse`，status 必须表达：
   - `agent_mode`
   - `integration_mode`
   - `agent_health`
   - `overall_readiness`
   - `accepted_generation`
   - `applied_generation`
   - `last_classified_generation`
   - `last_feature_ready_generation_by_domain`
   - `authority_state`
   - `domains`
   - `wal`
   - `pinned_runtime`
   - `netlink`
6. 增加 `NeutronCapabilitiesResponse` 和 `NeutronContractError`，覆盖 contract version、schema range、domain、unsupported features、body/timeout 元字段、`error_codes_hash`、`peer_auth_policy`、`capability_hash` 和 UDS 错误码。
7. 在 `agent/src/openapi.rs` 注册 Neutron DTO components。
8. 增加 `neutron-uds-contract.json` 生成或校验入口，包含 snapshot/status/capabilities/delete paths、schema refs、错误码、contract version、body/timeout 元字段和 peer auth policy。
9. 在 OpenAPI 测试中断言 components 存在。
10. 在 OpenAPI 测试中断言 TCP OpenAPI paths 不包含 `/api/v1/neutron/snapshot`、`/api/v1/neutron/status`、`/api/v1/neutron/capabilities` 和 `/api/v1/neutron/ports/{port_id}`。
11. 在 contract drift 测试中断言 UDS paths、schema refs、capabilities response、错误码、`error_codes_hash` 和 contract 元字段稳定。
12. 增加 serde roundtrip 测试，覆盖多 project snapshot。
13. 提交：`feat: add neutron snapshot api schema`。

必须覆盖的测试断言：

- `NeutronSnapshotRequest` 能反序列化最小合法 snapshot。
- `tenant_model.scope_key` 等于 `source/project_id/domain/object_id`。
- port 必须带 `project_id`。
- group/ACL/QoS 必须带 `project_id`。
- port/group/ACL/QoS 必须携带对象级 `revision_number` 或等价 `source_revision`。
- `runtime_foundations` 只能包含 `conntrack`、`monitoring` 这类运行基础要求。
- feature flags 只有 `acl`、`qos`。
- response/status 的 domain 顺序固定为 `runtime -> groups -> conntrack -> monitoring -> acl -> qos`。
- capabilities response 包含 contract version、schema range、mandatory/enhancement domains、unsupported features、body/timeout 元字段、`error_codes_hash`、`peer_auth_policy` 和 `capability_hash`。
- `neutron-uds-contract.json` 包含四个 UDS paths、稳定错误码、contract version、body/timeout 元字段和 peer auth policy。
- OpenAPI components 有 Neutron DTO。
- OpenAPI paths 没有 Neutron snapshot/status/capabilities/delete route。

停止条件：

- 如果 API DTO 需要引用 agent 或 core 类型，停止并改回纯 DTO，不让 `api` crate 依赖运行时状态。

#### 执行章节 2：Unix Socket Neutron Router

目标：给 `neutron-aria-agent` 提供本机 Unix socket API，保持现有 TCP API 不变。

文件范围：

- `agent/src/main.rs`
- `agent/src/api_routes.rs`
- `agent/src/neutron_api.rs`
- `config/aria-agent.toml`

默认实现顺序：

1. 在 `Config` 增加 `agent_mode: AgentMode` 或等价显式 `openstack_mode`，并增加 `listen_unix_socket: Option<String>`。
2. 保持 `listen_addr` 的现有行为，TCP router 继续服务本机管理员 API。
3. 在 `api_routes.rs` 增加 `build_neutron_router(control_plane)`。
4. `build_neutron_router` 只注册：
   - `PUT /api/v1/neutron/snapshot`
   - `GET /api/v1/neutron/status`
   - `GET /api/v1/neutron/capabilities`
   - `DELETE /api/v1/neutron/ports/{port_id}`
5. 在 `api_handlers/neutron.rs` 增加 handler skeleton。
6. handler skeleton 调用 control plane 的 Neutron 方法；如果方法尚未实现，返回稳定的 typed error 或 empty status，不返回 panic。
7. 在 `main.rs` 中，当 `agent_mode = "openstack"` 且 `listen_unix_socket` 存在时启动 Unix listener。
8. 启动时创建父目录，移除同路径陈旧 socket 文件。
9. bind 前确保父目录 owner/group/mode 符合部署约定，bind 后设置 socket 权限为 `0660`。
10. 在 `config/aria-agent.toml` 增加注释化 OpenStack 示例，明确 `agent_mode = "openstack"` 和 `listen_unix_socket` 必须同时出现。
11. 增加 router 测试，证明 TCP router 没有 Neutron route。
12. 增加 router 测试，证明只配置 `listen_unix_socket` 但未启用 `agent_mode = "openstack"` 时不会启动 Neutron router。
13. 增加 router 测试，证明 Unix router 只有 snapshot/status/capabilities/delete 四个 Neutron route。
14. 提交：`feat: add neutron unix socket router`。

默认错误处理：

- socket bind 失败：进程启动失败并输出明确错误。
- socket 父目录创建失败：进程启动失败并输出明确错误。
- 陈旧 socket 删除失败：进程启动失败并输出明确错误。
- TCP listener 启动成功但 Unix listener 启动失败：OpenStack 配置下进程失败，不进入半托管状态。

停止条件：

- 如果实现需要暴露 localhost HTTP 或 TCP fallback，停止并回到 Unix socket 设计。

#### 执行章节 3：Snapshot Apply 骨架

目标：Rust 侧具备 Neutron snapshot 的幂等 apply 框架、status 和 WAL 基础，不要求第一步完成所有 datapath 细节。

文件范围：

- `agent/src/neutron_api.rs`
- `agent/src/control_plane.rs`
- `core/src/state.rs`
- `agent/src/neutron_wal.rs`

默认实现顺序：

1. 新增 `control_plane/neutron_snapshot.rs`，把 Neutron apply 逻辑从主 `control_plane.rs` 中隔离。
2. 在 `FirewallState` 增加 Neutron state block：
   - `neutron_managed`
   - `neutron_host`
   - `neutron_generation`
   - `authority_state`
   - `authority_epoch`
   - `local_override_present`
   - `neutron_ports`
   - `neutron_projects`
   - `neutron_scoped_objects`
   - `neutron_scoped_refcounts`
   - `neutron_domain_status`
3. 保证新增字段都有 `#[serde(default)]`，旧 state 文件可以 replay。
4. 在 `WalEntry` 增加：
   - `NeutronSnapshotApplied`
   - `NeutronPortDeleted`
   - `NeutronStatusUpdated`
   - `LocalOverrideApplied`
   - `LocalOverrideDiscarded`
5. WAL entry 带 `source`、`project_id`、`domain`、`object_id`、`scoped_key`、`local_generation`。
6. 实现 `apply_neutron_snapshot(snapshot)`，第一版按 domain 收集 status。
7. 支持 Netlink 提前 attach inert/bypass runtime，但不能因此启用任何 Neutron feature。
8. 在任何 feature map 写入、feature flag 启用或 ready 推进前执行 Neutron-managed preflight。
9. Neutron-managed preflight 校验 `binding_host`、`if_name`、`ifindex` 和 Netlink 查询结果。
10. preflight 失败的 port 只更新 degraded status，不进入 feature apply，也不写 accepted datapath state。
11. apply 顺序固定为 schema/authority -> Neutron-managed preflight -> WAL intent -> groups -> conntrack/monitoring -> ACL -> QoS -> WAL commit -> status。
12. 重放同 generation 时返回当前 status，不重复写业务对象。
13. `DELETE /ports/{port_id}` 清理 port 关联对象和 scoped refcount。
14. `GET /status` 返回 authority、generation、domain、WAL、pinned、netlink 摘要。
15. 增加 WAL 恢复测试，覆盖 intent without commit、partial apply without commit、commit without status 三种路径。
16. 增加纯 state 单元测试覆盖 scoped key/refcount。
17. 提交：`feat: add neutron snapshot apply skeleton`。

默认 apply 语义：

- full snapshot 覆盖 Neutron-managed domains。
- port-scoped snapshot 只覆盖相关 port 的 Neutron-managed domains。
- unknown project 或 unknown scoped object 不 panic，返回 domain degraded。
- tap 未创建时返回 `BPF_ATTACH_DEFERRED_IFACE_MISSING`，等待 Netlink 对账。
- ACL 失败时该 port ACL domain 返回 `DomainStatus=degraded,effective_action=bypass`。
- QoS 失败时只标记对应 independent domain。

停止条件：

- 如果实现要求重构 eBPF map 格式才能通过 skeleton 测试，先保持 skeleton 和 status，不在本工作包做 datapath 热路径重构。

#### 执行章节 4：本机写入 Gate

目标：防止 OpenStack 托管状态和本机 CLI/API 双写。

文件范围：

- `agent/src/api_handlers/groups.rs`
- `agent/src/api_handlers/policies.rs`
- `agent/src/api_handlers/qos.rs`
- `agent/src/api_handlers/config.rs`
- `agent/src/control_plane.rs`
- `core/src/state.rs`
- `agent/src/neutron_wal.rs`

默认实现顺序：

1. 在 control plane 增加 `ensure_local_persistent_write_allowed(instance, domain)`。
2. gate 放在 control plane 写方法入口，不只放在 HTTP handler。
3. 对以下方法加 gate：
   - `add_group`
   - `delete_group`
   - `add_policy`
   - `delete_policy`
   - `add_qos`
   - `delete_qos`
   - `update_config`
4. `openstack_managed` 和 `openstack_degraded` 下，针对已列入 `managed_domains` 的 domain 返回 `LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_DOMAIN`。
5. 错误 HTTP 状态使用 `409 Conflict`。
6. trace、drops、stats、health、metrics、tcprt query 不加持久写 gate。
7. break-glass 状态允许本机持久写入，但 WAL source 必须是 local override。
8. Neutron 通信恢复且存在 local override 时进入 `rejoin_pending`。
9. `rejoin_pending` 拒绝新的本机持久写入。
10. 增加单元测试或 handler 测试覆盖每个拒绝面。
11. 提交：`feat: block local writes for neutron managed state`。

默认错误文案：

```text
LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_DOMAIN: this domain is managed by Neutron; update it through Neutron
```

停止条件：

- 如果某个本机命令既可能是排障又可能持久化，默认按持久写入拒绝，除非代码确认它不写 WAL、不改 generation。

#### 执行章节 5：Python Agent 骨架与 UDS Client

目标：建立可测试的 Python 子项目，不依赖真实 OpenStack 即可验证配置、generation 和本机 Unix socket client。

文件范围：

- `neutron-aria-agent/pyproject.toml`
- `neutron-aria-agent/neutron_aria_agent/__init__.py`
- `neutron-aria-agent/neutron_aria_agent/config.py`
- `neutron-aria-agent/neutron_aria_agent/models.py`
- `neutron-aria-agent/neutron_aria_agent/generation.py`
- `neutron-aria-agent/neutron_aria_agent/local_client.py`
- `neutron-aria-agent/tests/test_generation.py`
- `neutron-aria-agent/tests/test_local_client.py`

默认实现顺序：

1. 创建 `neutron-aria-agent` 子项目。
2. `pyproject.toml` 设置 package、console script、pytest 配置。
3. runtime 依赖默认：
   - `httpx`
4. test 依赖默认：
   - `pytest`
   - `respx` 或本地 fake transport；优先本地 fake transport，减少依赖。
5. `config.py` 定义默认配置：
   - `host`
   - `resync_interval`
   - `[aria] socket_path`
   - `[agent] managed_domains`
   - `[acl] source`
6. `models.py` 用 dataclass 表达 snapshot/status 基本模型。
7. `generation.py` 实现 `{host}-{counter:012d}`。
8. generation counter 持久化到 Python agent 本地 state file。
9. `local_client.py` 只连接 Unix socket path。
10. `local_client.py` 拒绝 `http://`、`https://`、裸 host:port 和空地址。
11. `local_client.py` 实现 `get_capabilities()`，并在 startup/reconnect 后先执行 capability handshake。
12. `local_client.py` 从 contract/capabilities 读取 body 上限并校验 timeout；端口级 mutation 使用请求级 timeout ceiling，超过 `body_max_bytes` 时返回 typed error。
13. socket 不存在时返回 typed error，不抛未分类异常。
14. 增加 Python 单元测试，覆盖 `get_capabilities()`、contract drift、body too large、schema/capability mismatch。
15. 提交：`feat: add neutron aria agent python skeleton`。

本地验证：

```bash
cd neutron-aria-agent
python -m pytest -q
```

停止条件：

- 如果需要真实 `neutron`、`oslo.messaging` 或 OpenStack 配置才能跑单元测试，说明模块边界错了；把真实 OpenStack 依赖隔离到后续 `neutron_client.py`。

#### 执行章节 6：Neutron 投影与 Translator

目标：把 Neutron 对象转换成 Aria snapshot dict，并把多租户、shared network、shared QoS 规则固定下来。

文件范围：

- `neutron-aria-agent/neutron_aria_agent/state.py`
- `neutron-aria-agent/neutron_aria_agent/translator.py`
- `neutron-aria-agent/tests/test_translator_acl.py`
- `neutron-aria-agent/tests/test_translator_qos.py`

默认实现顺序：

1. `state.py` 定义 `ProjectedState`。
2. `ProjectedState` 保存：
   - ports by `port_id`
   - explicit ACL groups by `(project_id, acl_group_id)`
   - explicit ACL rules by `(project_id, acl_rule_id)`
   - QoS policies by `(owner_project_id, policy_id)`
   - shared network bindings
   - shared QoS bindings
3. `translator.py` 输入 `ProjectedState`，输出与 `NeutronSnapshotRequest` 对齐的 dict。
4. ACL translator 当前阶段默认 bypass，只生成显式 enhancement policy。
5. ACL translator 不消费 Neutron Security Group、remote group、allowed address pairs 或 port security 输入。
6. 跨 project ACL 必须来自显式 ACL enhancement policy。
7. QoS translator 先算 port effective policy：port-level > network-level > shared default。
8. Mirror/TCPrt 不进入 translator 输入，不生成 snapshot 字段。
9. 所有 snapshot 内部引用使用 ID，不使用 name。
10. 测试中固定完整 snapshot 断言，不只断言字段存在。
11. 提交：`feat: add neutron state translator`。

必须覆盖的测试场景：

- 两个 project 有同名 ACL group，不串 scoped key。
- shared network 的 network owner 与 port owner 不同，ACL 仍按 port owner 编译。
- port migration event 只让新 `binding_host` 所在 host 生成 snapshot。
- 显式 ACL group/policy update 只影响本 host 相关 ports。
- shared QoS 只影响绑定 ports。
- snapshot 不包含 trace/drops/ssl/diagnose/service chain。
- snapshot 不包含 mirror/tcprt。

停止条件：

- 如果 translator 需要直接调用 datapath API，停止；translator 只产出 snapshot，不执行下发。

#### 执行章节 7：主循环、Heartbeat 与事件合并

目标：让 `neutron-aria-agent` 具备 OpenStack agent 形态：启动、full resync、事件合并、下发 snapshot、上报 `AgentHealth` 和 readiness。

文件范围：

- `neutron-aria-agent/neutron_aria_agent/agent.py`
- `neutron-aria-agent/neutron_aria_agent/event_loop.py`
- `neutron-aria-agent/neutron_aria_agent/event_merge.py`
- `neutron-aria-agent/neutron_aria_agent/rpc.py`
- `neutron-aria-agent/neutron_aria_agent/neutron_client.py`
- `neutron-aria-agent/neutron_aria_agent/status.py`
- `neutron-aria-agent/tests/test_event_merge.py`
- `neutron-aria-agent/tests/test_status.py`

默认实现顺序：

1. `agent.py` 负责启动顺序和 main loop。
2. `neutron_client.py` 定义接口类，真实 OpenStack 依赖放在这里。
3. 第一版测试使用 fake Neutron client。
4. 启动时先读取 config。
5. 检查 datapath Unix socket status。
6. socket 不可达时 agent degraded，不进入本机接管。
7. socket 可达后执行 full resync。
8. translator 生成 full snapshot。
9. local client 下发 full snapshot。
10. status 模块把 datapath domain status 转成 agent alive/degraded。
11. `rpc_events_enabled=false` 作为默认安全边界，未开启时不消费 RabbitMQ 事件。
11a. `incremental_rpc_enabled=false` 作为 P3 安全边界；只有 P3 entry gate 闭合后，才能在指定测试/灰度主机显式启用 port-scoped apply。
12. 开启后接入旧版 Neutron `q-agent-notifier` topic，只订阅 `port.update`、`port.delete`、`network.update`。
13. event loop 合并 burst events，merge window 默认 `0.2s`。
14. port update 按 `port_id` 合并，只保留最高 `source_revision/revision_number` 或最后 binding 结果。
15. migration/rebind event 中，如果最新 `binding_host != local_host`，只有 port 存在于本机 projected state 时才调用 local delete。
16. migration/rebind event 中，如果最新 `binding_host == local_host` 或缺少 binding host，当前第一版触发 full-resync；port-scoped snapshot 留到 translator/state cache 完成后开启。
17. port delete 使用旧版 Neutron `port_id` kwarg，只删除本机已知 port。
18. network update 当前触发 full-resync；后续有 network->local ports 索引后再缩小影响范围。
19. ACL group/policy update 找本 host 相关 ports，QoS update 找绑定 policy 的 ports；该增量 translator 不在当前 RPC skeleton 中硬猜。
20. 非 ACL/QoS 的本机能力 update 不进入 Neutron event merge。
21. backlog 超过上限时触发 full-resync。
22. 提交：`feat: wire neutron aria rpc event merge`。

默认 degraded 规则：

- datapath socket 不可达：agent degraded。
- `runtime.blocked`：agent degraded 并触发 full resync。
- `acl.degraded/blocked`：agent degraded，但保持 datapath bypass，不影响 OVS 转发。
- `qos.degraded`：agent alive，但上报原因。
- `rejoin_pending`：agent degraded，等待管理员处理 local override。

停止条件：

- 如果真实 OpenStack RPC 依赖阻塞单元测试，先保留 adapter interface 和 fake client，不把真实 RPC 绑死在 main loop。

#### 执行章节 8：容器与 OpenStack Smoke

目标：形成两个容器的无编排部署形态，并提供 OpenStack smoke 验证。

文件范围：

- `containers/aria-datapath/Dockerfile`
- `containers/neutron-aria-agent/Dockerfile`
- `deploy/openstack/aria-datapath.container.example`
- `deploy/openstack/neutron-aria-agent.container.example`
- `deploy/openstack/aria-agent.toml`
- `deploy/openstack/neutron-aria-agent.ini`
- `deploy/openstack/smoke.sh`
- `.github/workflows/build.yml`

默认实现顺序：

1. `aria-datapath` image 包含 `aria-agent`、`ariactl`、eBPF artifact。
2. `aria-datapath` 默认挂载：
   - `/run/aria`
   - `/sys/fs/bpf`
   - `/sys/kernel/btf`
   - `/var/lib/aria-agent`
   - `/var/log/aria-agent`
3. `aria-datapath` 需要 host network 或等价 datapath namespace。
4. `neutron-aria-agent` image 只包含 Python agent。
5. `neutron-aria-agent` 默认只挂载：
   - `/run/aria`
   - Neutron 配置路径
6. `neutron-aria-agent` 不授予 eBPF capability。
7. 两个容器通过 `/run/aria/aria-agent.sock` 通信。
8. `aria-agent.toml` 开启 Unix socket。
9. `neutron-aria-agent.ini` 指向 `unix:///run/aria/aria-agent.sock`。
10. `smoke.sh` 检查 socket 权限。
11. `smoke.sh` 检查 agent status。
12. `smoke.sh` 下发最小 snapshot。
13. `smoke.sh` 覆盖 ACL/QoS 基础路径。
14. GitHub Actions 增加 Python test job。
15. GitHub Actions 增加 container packaging job。
16. 提交：`feat: add openstack container deployment`。

默认 smoke 场景：

- agent alive。
- full snapshot 下发成功。
- 默认 bypass 生效，Aria 未 ready 不影响原 OVS 转发。
- 显式 ACL enhancement policy 生效。
- QoS bandwidth limit 可观察。
- 删除容器后 WAL/state 仍在宿主机持久目录。

停止条件：

- 如果目标环境暂时没有完整 OpenStack，先提交容器和 mock smoke；真实 DevStack/OpenStack smoke 作为进入 N6 的门槛，不阻塞 N1-N5。

## 17. 最终决策

`v0.9-neutron-agent` 分支采用 Neutron Agent Mode：

- 用 `v0.9.0` 作为基线。
- 不引入 `aria-controller`。
- 不迁移 v0.10 的 Controller / RFC 体系。
- 新增 Python `neutron-aria-agent` 作为 OpenStack 适配层。
- `aria-datapath` 继续作为 Rust 本机 datapath runtime，运行现有 `aria-agent` 二进制。
- 第一阶段采用 Coexist Mode，不替代 OVS L2 agent。
- ACL、QoS 两个功能进入 Phase-1 roadmap；N3 MVP 只冻结 ACL enhancement 最小闭环，QoS domain 受对应 feature gate 约束。Mirror/TCPrt Rust 代码保留，但不进入 Neutron Agent Mode 对接范围。
- 多租户按 Neutron project/RBAC 关系适配，使用 scoped object key 隔离 state、WAL、refcount 和 pinned map ID。
- Group、Conntrack、Monitoring、WAL、Netlink、Pinned Maps 作为必选支撑能力随 N1/N2 一起落地。
- trace、drops、ssl、diagnose、service chain 等其它已有能力代码保留，但不作为 OpenStack agent mode 对外功能暴露。

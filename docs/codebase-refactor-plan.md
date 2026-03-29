# Codebase Refactor Plan

本文档记录当前仓库的大文件重构方案。目标不是“把大文件拆小”本身，而是在**不改变行为语义**的前提下，逐步把边界、职责和目录结构整理清楚，降低后续功能迭代成本。

本文档基于当前代码实际结构，而不是只按文件行数做抽象判断。

## 目标

本轮重构的目标：

- 降低单文件认知负担
- 提高领域边界清晰度
- 保持对外 API、CLI、eBPF 运行时行为稳定
- 将高风险核心文件拆分为“可逐步迁移”的模块结构

本轮重构**不是**要做的事情：

- 不重写 `ControlPlane` 的锁模型
- 不重设计 WAL 持久化语义
- 不修改 REST 路由或 CLI 参数语义
- 不在同一批 PR 里同时做“目录拆分 + 行为修复”
- 不优先重构 `ebpf/src/lib.rs`

## 当前基线

当前几个主要大文件的行数：

| 文件 | 行数 | 初始风险判断 | 备注 |
| --- | ---: | --- | --- |
| `agent/src/control_plane.rs` | 2742 | 高 | 状态核心、注册/注销/WAL/内核调用交织 |
| `agent/src/api_handlers.rs` | 2672 | 低到中 | 路由边界清晰，但有共享 helper 和超大 `metrics` |
| `user/src/main.rs` | 2498 | 低到中 | CLI 入口集中，但 `trace/tcprt/diagnose` 共享大量渲染逻辑 |
| `core/src/ebpf_ops.rs` | 2106 | 中到高 | 对外调用面很广，属于核心基础设施 |
| `ebpf/src/lib.rs` | 1239 | 中 | 目前层次尚可，短期收益不高 |

## 当前状态

截至 `2026-03-29`，本轮结构化重构主线已经完成，状态如下：

| 阶段 | 状态 | 说明 |
| --- | --- | --- |
| Phase 1 `api_handlers` 模块化 | 已完成 | `agent/src/api_handlers/` 已按领域拆分，`mod.rs` 仅保留模块声明和 re-export |
| Phase 2 `user/src/main.rs` 拆分 | 已完成 | `main.rs` 已收成薄分发层，复杂工作流迁到 `user/src/commands/` |
| Phase 3 `control_plane` 只读域抽取 | 已完成 | `trace` / `tcprt` / `ssl` / `observability` 已迁到 `agent/src/control_plane/` |
| Phase 4 `ebpf_ops` 内部模块化 | 已完成 | `runtime` / `network` / `attach` / `scrub` / `inventory` / `policy` / `replay` 已迁到 `core/src/ebpf_ops/` |
| Phase 5 `ControlPlane` 写路径重构 | 暂缓 | 明确不纳入本轮，留待下一轮单独规划 |

这意味着本轮计划里的“目录模块化 + 保持行为不变”的主体工作已经收口。当前剩余工作主要是：

- 文档和测试记录同步
- 未来 `4.18` 环境恢复后的补测
- 独立于本轮结构重构的 trace runtime backlog（如 consumer failure 注入）

## 重构后的运行时修复补记

虽然本计划刻意避免把“目录拆分”和“行为修复”混在同一批 PR 中，但在重构收尾和线上回归期间，仍然发现并修复了几类与运行时生命周期相关的真实 bug。这些修复不是本计划的主目标，但它们影响了最终的稳定性判断，需要在这里记录。

### 1. `system stop` / managed detach 的 `fq` 生命周期修复

相关结果：

- `system stop` 之前存在 root qdisc 清理与实例注销不对称的问题
- managed `instance` 在启用 `QoS shaping` 时存在同类 `fq` ownership 缺口
- 后续通过 ownership marker、stale marker 清理和 gone-device cleanup 收敛了这条链路

最终语义：

- 我们自己安装的 `fq` 会在 stop/detach 时清理
- 接口原本就存在的 `fq` 不会被误删
- 如果接口已经消失，则 cleanup 会直接清 marker，不再阻断实例注销

### 2. crash recovery 路径补回 TC/FQ 运行时

相关结果：

- pinned XDP 仍在、但 `tc_egress` / `tc_ingress` link pin 缺失时，恢复路径现在会补回 TC runtime
- 若恢复后的状态需要 `QoS shaping`，也会补回 `fq`
- `6.8` 上已完成“恢复后 trace 20/20 正常、恢复后 managed tap 可再次删除”的闭环验证

### 3. ghost instance 清理问题已修复

这轮线上回归里确认过一个 recovery 副作用：

- managed tap 在 crash recovery 后再次删除时，`DelLink` 会到达
- 但 `owned fq qdisc` 清理在接口已消失时失败，导致 `instances.remove()` 和 `unregister_instance()` 没有执行

后续修复后，当前行为是：

- `system stop + vanished iface`：实例和 marker 都会被清掉
- `crash recovery -> DelLink`：实例会正常消失，marker 也会一起删除

这些修复说明：虽然本轮没有继续拆 `ControlPlane` 写路径，但 runtime attach/detach/recovery 相关的 correctness 已经在 `6.8` 线上回归中补齐。

## 设计原则

### 1. 先拆“天然边界”，后拆“状态核心”

优先拆已经存在清晰边界的文件：

- `api_routes.rs -> api_handlers.rs`
- `Cli/Commands -> trace/tcprt/diagnose helpers`
- `control_plane.rs` 中已经用分段注释明确划分的只读域

避免一开始就碰以下区域：

- managed registration / unregister
- tap id 分配
- WAL append / compact fallback
- 共享 runtime repair
- 锁粒度重设计

### 2. 先目录模块化，后语义模块化

第一阶段的目标应是：

- 文件搬运
- import 调整
- re-export 稳定对外符号

而不是：

- 顺手改函数签名
- 顺手去重逻辑
- 顺手重命名对外接口

### 3. 每个 PR 只做一种事情

推荐的提交粒度：

- 纯搬运 PR
- 纯清理 import / re-export PR
- 纯行为修复 PR

不要把“目录重构”和“功能修复”混在一起。

### 4. 保持外部调用面稳定

这一点尤其适用于：

- `aria_core::ebpf_ops::*`
- `crate::api_handlers::*`
- `user/src/main.rs` 对 CLI 语义的定义

重构期间，优先通过 `mod.rs` re-export 保持外部调用点不变。

### 5. 不在没有验证的情况下动核心写路径

`ControlPlane` 的写路径不是不能重构，而是必须分阶段：

- 先抽只读域
- 再抽局部写域
- 最后才考虑锁和状态模型

## 真实风险评估

### `agent/src/api_handlers.rs`

判断：`低到中`

原因：

- 优势：路由分组已经存在，见 `agent/src/api_routes.rs`
- 优势：handlers 本身大多是薄封装，主要调用 `ControlPlane`
- 风险：文件底部的 `metrics` 和多组 helper 属于共享依赖，不能机械拆成每个 endpoint 一个文件

结论：

- 这是最适合先动的文件
- 但应先单独抽 `metrics.rs`

### `user/src/main.rs`

判断：`低到中`

原因：

- 优势：CLI 入口单点，顶层 dispatch 清晰
- 风险：`trace`、`tcprt`、`diagnose` 共享较多渲染和聚合逻辑
- 风险：如果按子命令一比一拆分，很容易把共享 helper 复制到多个文件

结论：

- 适合第二阶段重构
- 拆分单位应是“复杂工作流”和“输出渲染”，不是每个命令一个文件

### `agent/src/control_plane.rs`

判断：`高`

原因：

- `ControlPlane` 是控制面主状态机
- 既有只读聚合接口，也有写路径和运行时 repair
- 包含多类共享状态：
  - `instances`
  - `trace_manager`
  - `ssl_manager`
  - `kernel_drop_manager`
  - `chains`
- 还包含 `InstanceState`、WAL compact fallback、register/unregister 等高耦合逻辑

但它并不是“完全不能拆”。代码里已经有天然分段：

- Groups
- Policies
- QoS
- Mirror
- Conntrack
- Config
- SSL
- Stats
- TCP-RT
- Trace
- Service Chains
- Kernel Drops

结论：

- 先抽只读域和轻写域
- 暂不触碰 managed registration / unregister / compact / helpers

### `core/src/ebpf_ops.rs`

判断：`中到高`

原因：

- 它不是简单的“map 操作工具箱”
- 当前外部调用面非常广，覆盖：
  - `agent/src/control_plane.rs`
  - `agent/src/instance.rs`
  - `agent/src/system_manager.rs`
  - `core/src/qos_ops.rs`
  - `core/src/mirror_ops.rs`
- 既包含 attach/load，也包含 replay/scrub/runtime/network/policy

结论：

- 适合做“内部模块化”
- 不适合第一阶段就改变对外 API

### `ebpf/src/lib.rs`

判断：`先不做`

原因：

- 当前 eBPF 数据面已经按 hook/path 分层
- 近期收益不如 userspace 大
- 任何拆分都会让 CI 回归成本更高

结论：

- 暂不进入本轮计划
- 只有在未来新增 dataplane feature 导致 hook dispatch 明显失控时再考虑

## 推荐的重构顺序

推荐顺序不是：

1. `user/src/main.rs`
2. `api_handlers.rs`
3. `core/src/ebpf_ops.rs`
4. `control_plane.rs`

而是：

1. `agent/src/api_handlers.rs`
2. `user/src/main.rs`
3. `agent/src/control_plane.rs` 的只读域
4. `core/src/ebpf_ops.rs` 的内部模块化
5. `control_plane.rs` 的局部写路径
6. `ebpf/src/lib.rs`（如未来确有必要）

理由：

- `api_handlers.rs` 已有天然路由边界，收益最大、风险最低
- `user/src/main.rs` 可以只抽复杂工作流，不必重写所有命令
- `control_plane.rs` 不应该“一刀切不动”，而应从只读域减肥
- `ebpf_ops.rs` 对外调用面太广，适合放在 `ControlPlane` 初步瘦身之后再动

## Phase 1: 拆分 `agent/src/api_handlers.rs`

状态：已完成

### 目标

- 将 handler 按领域路由拆分为目录模块
- 保持 `api_routes.rs` 基本不变
- 保持对外 handler 名称不变

### 目标目录

```text
agent/src/api_handlers/
├── mod.rs
├── common.rs
├── system.rs
├── groups.rs
├── policies.rs
├── qos.rs
├── mirror.rs
├── conntrack.rs
├── config.rs
├── stats.rs
├── tcprt.rs
├── ssl.rs
├── chains.rs
├── drops.rs
├── trace.rs
└── metrics.rs
```

### 函数映射

`common.rs`

- `type AppState = Arc<ControlPlane>`
- `err_response`
- `kernel_drop_mode_name`
- `trace_map_mode_name`

`system.rs`

- `health`
- `list_instances`
- `system_start`
- `system_stop`

`groups.rs`

- `list_groups`
- `add_group`
- `delete_group`
- `list_groups_with_stats`

`policies.rs`

- `list_policies`
- `add_policy`
- `delete_policy`
- `list_policies_with_stats`
- `batch_add_policies`

`qos.rs`

- `list_qos`
- `add_qos`
- `delete_qos`
- `list_qos_with_stats`

`mirror.rs`

- `list_mirror`
- `add_mirror`
- `delete_mirror`
- `stats_mirror`
- `list_mirror_with_stats`

`conntrack.rs`

- `list_conntrack`
- `flush_conntrack`

`config.rs`

- `get_config`
- `update_config`

`stats.rs`

- `default_top`
- `stats_overview`
- `stats_rules`
- `stats_flows`
- `stats_qos`
- `stats_groups`

`tcprt.rs`

- `list_tcprt`
- `flush_tcprt`
- `batch_query_tcprt`
- `filter_tcprt`
- `tcprt_histogram`
- `tcprt_states`

`ssl.rs`

- `map_ssl_connections`
- `map_ssl_http_events`
- `list_ssl_global`
- `flush_ssl_global`
- `list_ssl`
- `flush_ssl`
- `list_ssl_http_global`
- `flush_ssl_http_global`
- `list_ssl_http`
- `flush_ssl_http`
- `get_ssl_config`
- `update_ssl_config`
- `list_ssl_errors`
- `flush_ssl_errors`

`chains.rs`

- `list_chains`
- `create_chain`
- `get_chain`
- `delete_chain`

`drops.rs`

- `legacy_drop_headers`
- `list_drops`
- `flush_drops`
- `list_kernel_drops`
- `flush_kernel_drops`

`trace.rs`

- `start_trace`
- `stop_trace`
- `list_trace`
- `flush_trace`

`metrics.rs`

- `prom_escape`
- `ct_contract_hook_to_string`
- `ct_contract_family_to_string`
- `ct_contract_reason_to_string`
- `flush_metrics_chunk`
- `write_latency_histogram`
- `write_tcprt_summary_metrics`
- `write_ssl_summary_metrics`
- `write_ssl_http_summary_metrics`
- `metrics`

### 实施步骤

PR 1:

- 新建 `api_handlers/mod.rs`
- 先把原文件内容搬进去并通过 `pub use` 暴露旧名字
- `api_routes.rs` 暂时不改调用方式

PR 2:

- 单独抽出 `metrics.rs`
- 再抽 `common.rs`
- 保证 `/metrics` 行为不变

PR 3:

- 按路由域逐步搬运剩余 handlers
- 每次只搬 1 到 3 个领域

### 验收条件

- `api_routes.rs` 路由路径完全不变
- 所有 handler 函数签名保持不变
- CI 通过
- `/metrics`、`/trace`、`/ssl` 这些较复杂路由做至少一次手工 smoke

## Phase 2: 拆分 `user/src/main.rs`

状态：已完成

### 目标

- 把 CLI 定义、复杂工作流、渲染逻辑拆开
- 保留 `main.rs` 作为启动和顶层 dispatch 入口

### 不建议的拆法

不建议按所有子命令一比一拆成：

- `group.rs`
- `policy.rs`
- `qos.rs`
- `mirror.rs`
- ...

因为当前真正复杂的不是这些简单 CRUD 命令，而是：

- `trace`
- `tcprt`
- `diagnose`

### 目标目录

```text
user/src/
├── main.rs
├── api_client.rs
├── cli.rs
├── commands/
│   ├── mod.rs
│   ├── tcprt.rs
│   ├── trace.rs
│   └── diagnose.rs
└── render/
    ├── mod.rs
    ├── trace.rs
    └── kernel_drop.rs
```

### 函数映射

`cli.rs`

- `Cli`
- `Commands`
- `SystemCommands`
- `GroupCommands`
- `PolicyCommands`
- `ConntrackCommands`
- `QosCommands`
- `MirrorCommands`
- `TcprtCommands`
- `DropsCommands`
- `ChainCommands`
- `TraceCommands`
- `SslCommands`
- `ConfigCommands`
- `get_instance`
- `note_ssl_is_global`
- `kernel_drop_query_from_cli`

`commands/tcprt.rs`

- `FlowKey`
- `InstanceFlows`
- `fetch_all_instance_flows`
- `sort_value`
- `run_tcprt_top`
- `run_tcprt_flow`
- `run_tcprt_flow_coarse`
- `run_tcprt_flow_with_chain`

`render/kernel_drop.rs`

- `print_kernel_drop_stats`

`render/trace.rs`

- `collect_trace_events`
- `display_trace_live`
- `display_trace_summary`
- `print_instance_summary`
- `ChainHopTrace`
- `build_chain_hops`
- `count_in_out`
- `format_drop_summary`
- `HopAgg`
- `collect_hop_aggs`
- `print_chain_table_rows`
- `print_drop_annotations`
- `display_trace_chain_summary`
- `display_trace_chain_live`

`commands/trace.rs`

- `run_trace_with_chain`
- `run_trace`

`commands/diagnose.rs`

- `run_diagnose`

`main.rs`

- 只保留：
  - `Cli::parse()`
  - `ApiClient::new()`
  - 顶层 `match cli.command`
  - 简单 CRUD 命令直连调用

### 实施步骤

PR 1:

- 提取 `cli.rs`
- 保持顶层 `match` 不变

PR 2:

- 提取 `render/trace.rs`
- 再提取 `commands/trace.rs`

PR 3:

- 提取 `commands/tcprt.rs`
- 最后提取 `commands/diagnose.rs`

### 验收条件

- `ariactl --help` 输出不变
- 复杂命令保持现有行为：
  - `trace start`
  - `tcprt top`
  - `tcprt flow`
  - `diagnose`

## Phase 3: 抽取 `agent/src/control_plane.rs` 的只读域

状态：已完成

### 目标

- 先降低 `ControlPlane` 文件体积
- 不改变核心写路径
- 不调整锁结构

### 第一阶段只抽这些域

```text
agent/src/control_plane/
├── mod.rs
├── shared.rs
├── observability.rs
├── tcprt.rs
├── ssl.rs
├── trace.rs
└── chains.rs
```

### 函数范围

`observability.rs`

- `get_stats_overview`
- `get_rule_stats`
- `get_flow_stats`
- `get_qos_stats`
- `get_group_stats`
- `get_drop_stats`
- `get_kernel_drop_stats`
- `flush_kernel_drop_stats`
- `get_kernel_drop_status`

`tcprt.rs`

- `list_tcprt`
- `get_tcprt_metrics_summary`
- `flush_tcprt`
- `batch_query_tcprt`
- `filter_tcprt`

`ssl.rs`

- `read_ssl_global_config`
- `update_ssl_global_config`
- `get_ssl_sync_errors`
- `flush_ssl_sync_errors`
- `list_ssl_global`
- `get_ssl_metrics_summary`
- `flush_ssl_global`
- `list_ssl`
- `flush_ssl`
- `list_ssl_http_global`
- `get_ssl_http_metrics_summary`
- `flush_ssl_http_global`
- `list_ssl_http`
- `flush_ssl_http`

`trace.rs`

- `trace_map_mode`
- `trace_backend_name`
- `get_trace_runtime_status`
- `start_trace`
- `stop_trace`
- `get_trace_events`
- `flush_trace`

`chains.rs`

- `list_chains`
- `get_chain`
- `create_chain`
- `delete_chain`

`shared.rs`

- 与上面模块复用的实例获取、query 解析、错误转换 helper

### 暂不抽出的高风险区域

- `prepare_managed_registration`
- `cleanup_failed_managed_registration`
- tap id 分配逻辑
- group/policy/qos/mirror 写路径
- `compact_all`
- `compact_instance`
- `shutdown_instance`
- `InstanceState::wal_append`
- `InstanceState::do_compact`

### 第二阶段才考虑的域

- `groups.rs`
- `policies.rs`
- `qos.rs`
- `mirror.rs`

这些域虽然有明显边界，但都带写路径和回滚逻辑，不适合先动。

### 验收条件

- 现有 API 和 `ControlPlane` 对外方法名保持稳定
- register/unregister、agent restart、trace lifecycle 不回归
- CI 通过

## Phase 4: 内部模块化 `core/src/ebpf_ops.rs`

状态：已完成

### 目标

- 只整理内部目录结构
- 对外仍保持 `aria_core::ebpf_ops::*`

### 目标目录

```text
core/src/ebpf_ops/
├── mod.rs
├── attach.rs
├── inventory.rs
├── maps.rs
├── network.rs
├── policy.rs
├── replay.rs
├── runtime.rs
└── scrub.rs
```

### 函数映射

`maps.rs`

- `tap_lpm_key_v4`
- `tap_lpm_key_v6`
- `open_pinned_lpm_v4`
- `open_pinned_lpm_v6`
- `open_pinned_policy_table`
- `open_pinned_port_pool`
- `open_pinned_iface_ctx`
- `open_pinned_tap_config`

`scrub.rs`

- `scrub_hash_map`
- `scrub_per_cpu_hash_map`
- `scrub_lpm_v4_map`
- `scrub_lpm_v6_map`
- `scrub_iface_ctx_entries`
- `scrub_tap_config_entries`
- `record_optional_scrub`
- `scrub_runtime_state`
- `scrub_managed_runtime_state`
- `scrub_standalone_runtime_state`

`inventory.rs`

- `summarize_entries`
- `validate_entry_set`
- `collect_lpm_entries_v4`
- `collect_lpm_entries_v6`
- `format_lpm_entry_v4`
- `format_lpm_entry_v6`
- `validate_pinned_runtime_state`
- `critical_network_map_names`

`runtime.rs`

- `init_ct_config_pinned`
- `sync_iface_ctx`
- `read_iface_ctx`
- `clear_iface_ctx`
- `write_tap_config`
- `delete_tap_config`
- `update_runtime_config`
- `update_firewall_config`
- `read_firewall_config`
- `read_runtime_config`

`policy.rs`

- `encode_port_action`
- `stored_policy_action`
- `parse_ports_impl`
- `parse_ports`
- `parse_normalized_ports`
- `add_policy`
- `validate_policy_ports`
- `delete_policy`
- `delete_port_set`

`network.rs`

- `parse_cidr`
- `add_network`
- `delete_network`

`replay.rs`

- `replay_state`
- `replay_state_to_pinned_maps`
- `show_stats`

`attach.rs`

- `load_bpf_with_pin`
- `attach_tc_ingress`
- `attach_tc_egress`
- `detach_tc_egress`
- `setup_fq_qdisc`
- `check_fq_qdisc`

### 关键约束

- `core/src/lib.rs` 继续只暴露 `pub mod ebpf_ops;`
- `mod.rs` 中通过 `pub use` 保持原有函数路径不变
- 不在拆分同一 PR 里改 `agent/src/control_plane.rs` 的调用方式

### 为什么现在不按“trace/runtime/replay/attach”语义随意切

因为当前外部调用是按函数粒度分散引用的，不是按领域对象引用的。过早改变外部 import 结构，会把一次“内部模块化”放大成全仓库改名。

## Phase 5: 后续是否继续拆 `ControlPlane` 写路径

状态：暂缓，不纳入本轮

只有满足以下条件，才建议继续：

- 前四个阶段已经稳定完成
- CI 长期稳定
- 对 register/unregister、trace lifecycle、policy rollback 已有足够信心
- 有时间补更强的集成覆盖

那时再考虑：

- `groups.rs`
- `policies.rs`
- `qos.rs`
- `mirror.rs`

但仍然不建议在这个阶段直接改锁粒度。

## 明确暂缓项

以下内容不进入本轮：

- `ebpf/src/lib.rs`
- `core/src/state.rs`
- `core/src/wal.rs`
- `agent/src/instance.rs`

原因不是这些文件不重要，而是当前收益/风险比不如前述几个目标高。

## 推荐 PR 切分

推荐用以下顺序落地：

1. `docs/codebase-refactor-plan.md`
2. `api_handlers`: 先建目录和 `mod.rs`
3. `api_handlers`: 抽 `metrics.rs`
4. `api_handlers`: 抽剩余领域
5. `user/main`: 抽 `cli.rs`
6. `user/main`: 抽 `trace` 与 `render`
7. `user/main`: 抽 `tcprt` / `diagnose`
8. `control_plane`: 抽 `trace` / `ssl` / `tcprt` / `chains`
9. `control_plane`: 抽 `observability`
10. `ebpf_ops`: 纯内部模块化

## 每个阶段的统一验收标准

- 行为不变
- 路由不变
- CLI 参数不变
- 不引入新的共享可变状态
- 不改变 eBPF pin/runtime 语义
- GitHub Actions CI 通过

此外，涉及 trace 路径的阶段还应补一次已有远端回归：

- `flush -> start trace -> send -> first read`
- detach / re-register
- agent restart

## 一句话结论

最稳的路径不是“先拆 CLI，再拆其它”，也不是“完全不碰 ControlPlane”，而是：

**先拆 `api_handlers`，再拆 CLI 的复杂工作流，再从 `ControlPlane` 抽只读域，最后再做 `ebpf_ops` 的内部模块化。**

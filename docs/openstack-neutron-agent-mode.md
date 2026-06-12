# OpenStack Neutron Agent Mode 详细方案

状态：Draft
基线分支：`v0.9.0`
目标分支：`v0.9-neutron-agent`

## 1. 目标与结论

### 1.1 建设目标

把 `aria-firewall` 放到 OpenStack compute node 中使用，让 OpenStack 继续以 Neutron 作为唯一网络控制入口，同时让 Aria 的 eBPF datapath 承担节点侧安全、限速、镜像和可观测能力。

第一阶段目标不是完整替代 OVS/OVN 的 L2 datapath，而是做 Neutron Agent Mode：

- Neutron 仍然是唯一 source of truth。
- OpenStack 用户继续通过 Neutron API、Horizon、Terraform、Heat 等入口配置网络对象。
- `neutron-aria-agent` 消费 Neutron 本 host 状态，生成本机声明式 snapshot。
- `aria-datapath` 接收 snapshot，负责本机 group、ACL、QoS、Mirror、TCPrt、runtime status、WAL、Netlink、Pinned Maps 和 eBPF map apply。
- 其它已有能力代码保留，但不进入 `neutron-aria-agent` 对外暴露面。

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

第一阶段保留 OVS/OVN 的基础 L2 connectivity。Aria 接管或增强节点侧：

- ACL：对应 Neutron Security Group / port security。
- QoS：对应 Neutron QoS policy。
- Mirror：对应 TaaS、vendor extension 或 admin host-local mirror policy。
- TCPrt：对应 port/network feature flag 的观测能力。
- Group：作为 ACL、QoS、Mirror 的共同编译中间层。
- WAL / Netlink / Pinned Maps：作为 OpenStack 模式的必选运行时支撑能力。

### 1.3 第一阶段明确不做

第一阶段不做这些事情：

- 不引入 `aria-controller`。
- 不迁移 v0.10 Controller / RFC 体系到该分支。
- 不让用户绕过 Neutron 创建 OpenStack 网络对象。
- 不完整替代 OVS/OVN 的 L2 bridge、tunnel、local switching、VLAN/VXLAN/GENEVE 管理。
- 不把 `trace`、`drops`、`ssl`、`diagnose`、`service chain` 扩成 Neutron tenant API。
- 不把 TCPrt 结果写回 Neutron DB。
- 不把 Mirror 做成普通租户自服务能力。

## 2. 组件边界

### 2.1 Neutron

Neutron 拥有 OpenStack 网络对象和用户语义：

- project / tenant
- network / subnet
- port
- port binding host
- fixed IP / MAC
- security group / security group rule
- port security
- allowed address pairs
- QoS policy
- port status

Aria 不为这些对象新增独立 northbound 写入口。

### 2.2 OVS / OVN

第一阶段 OVS/OVN 继续负责基础 L2 connectivity：

- VM tap/vif plug。
- bridge/tunnel/local switching。
- underlay/overlay 网络连通。
- 与现有 OpenStack 部署流程兼容。

OpenStack 模式必须处理和 OVS/OVN security group 的边界：

- 如果 Aria 接管 Security Group enforcement，原 OVS/OVN security group enforcement 必须关闭或旁路。
- 不能让同一个端口同时被 OVS/OVN SG 和 Aria ACL 双重过滤。
- 具体关闭方式依赖目标 OpenStack 版本和 OVS/OVN 部署形态，必须作为 DevStack / 目标环境 smoke 的显式验收项。

### 2.3 neutron-aria-agent

`neutron-aria-agent` 是 OpenStack 适配层，建议使用 Python 编写。

职责：

- 向 Neutron 注册本 host 上的 Aria agent。
- 维持 agent heartbeat。
- 消费 Neutron port、security group、QoS、mirror、feature flag 相关更新。
- 在启动、重连、事件丢失、generation 不一致时执行 full resync。
- 只处理绑定到本 host 的 Neutron ports。
- 把 Neutron 对象翻译成本机 snapshot。
- 调用本机 datapath 的 Neutron snapshot API。
- 记录 latest desired generation、last applied generation、last error 和 domain status。

不负责：

- 不直接写 eBPF map。
- 不管理 XDP/TC attach。
- 不读取或写入 Aria WAL。
- 不实现完整 OVS/OVN L2 datapath。
- 不暴露非 Neutron 同步对象。

建议使用 Python 的原因：

- Neutron agent、RPC、heartbeat、service launcher、配置、logging 都是 Python 生态。
- Security group、QoS、port binding 的事件模型可以复用 Neutron 原有模式。
- 后续做 ML2 driver、agent extension、vendor extension 时接入成本更低。

### 2.4 aria-datapath

`aria-datapath` 是 Rust 本机 datapath runtime 的角色名和容器名。它运行现有 `aria-agent` 二进制，不改 binary、既有服务文件、配置目录、socket、日志路径和 CLI 兼容性。

职责：

- 接收本机声明式 snapshot。
- 编译本地 group/address-set/port-set。
- 编译并 apply ACL/QoS/Mirror/TCPrt。
- 维护 tap/veth/ifindex/tap_id 映射。
- 通过 Netlink 感知接口生命周期。
- 通过 WAL 保存本机状态变更。
- 通过 Pinned Maps / pinned links 保持 runtime。
- 提供 status、metrics、stats、diagnose、trace 等本机管理员能力。

不负责：

- 不访问 Neutron DB。
- 不消费 Neutron RPC。
- 不理解 Neutron server 内部对象生命周期。
- 不作为 OpenStack northbound。

## 3. 工作模式

### 3.1 Coexist Mode

第一阶段采用 Coexist Mode：

```text
OVS/OVN          负责 L2 connectivity
neutron-aria-agent 负责 Neutron 状态同步与翻译
aria-datapath    负责节点侧 eBPF 执行
```

这个模式的好处是：

- 改动范围小。
- 可以先验证 Aria 的节点侧价值。
- 不需要一次性替换 OpenStack 现有 L2 绑定路径。
- 出问题时可以退回 OVS/OVN 原有能力。

### 3.2 不是完整 L2 Agent 替代

`neutron-aria-agent` 在 Neutron 体系里的位置类似 `neutron-openvswitch-agent`，都是 compute node 上的本地 agent。但第一阶段职责比 OVS agent 窄。

`neutron-openvswitch-agent` 通常负责：

- port plug / bridge / tunnel
- local switching
- security group
- QoS
- agent heartbeat
- port status

`neutron-aria-agent` 第一阶段只负责：

- agent heartbeat
- full resync
- port 归属判断
- group/ACL/QoS/Mirror/TCPrt 翻译
- 调用本机 datapath snapshot API
- 上报 Aria runtime status

完整 L2 替代可以作为后续阶段，但不进入当前计划。

## 4. 状态模型

### 4.1 Neutron 拥有的状态

Neutron 是 source of truth：

- 租户、网络、子网、端口。
- 端口绑定在哪个 host。
- 端口 fixed IP、MAC、allowed address pairs。
- Security Group 和规则。
- QoS policy 和 rule。
- port security。
- port status。

这些对象不允许通过 `aria-datapath` 或 `neutron-aria-agent` 另开一套 northbound 修改。

### 4.2 neutron-aria-agent 拥有的状态

`neutron-aria-agent` 只保存本机可重建投影：

- 本 host 绑定的 Neutron ports。
- 每个 port 的 fixed IP、MAC、allowed address pairs。
- Neutron security group / remote group 展开后的本地 group/address-set 投影。
- 每个 port 的 ACL 结果。
- 每个 port 的 QoS 结果。
- 每个 port 的 Mirror 结果。
- 每个 port 的 TCPrt 开关。
- `desired_generation`。
- `last_submitted_generation`。
- `last_accepted_generation`。
- `last_good_generation`。
- domain apply status。

该状态必须能通过 Neutron full resync 重建。磁盘缓存只能作为加速或诊断，不能成为权威来源。

### 4.3 aria-datapath 拥有的状态

`aria-datapath` 拥有本机运行态：

- tap/veth/ifindex/tap_id 映射。
- group/address-set/port-set。
- ACL map。
- QoS map。
- Mirror map。
- TCPrt map。
- feature flags。
- WAL。
- Netlink 监听与接口对账。
- Pinned Maps / pinned links。
- metrics、stats、diagnose、trace。

`aria-datapath` 只接受本机 snapshot，不解释 Neutron RPC。

### 4.4 Generation 语义

每次 `neutron-aria-agent` 下发 snapshot 必须带 generation：

- `schema_version`：snapshot schema 版本。
- `local_generation`：本 host 本次 desired state 的单调 generation。
- `source_revision`：可选，记录 Neutron full resync 或事件批次来源。
- `host`：OpenStack compute host。
- `mode`：第一阶段固定为 `coexist`。

`aria-datapath` 必须保存：

- `accepted_generation`：最近一次通过 schema/host/authority 校验、WAL durable、且 required domain 到达终态的 generation；WAL 失败、preflight 阻断或 required domain blocked 时不得推进。
- `applied_generation`：最近一次完成 apply 尝试并生成 `domain_status` 的 generation，可包含 independent domain degraded。
- `last_good_generation`：最近一次所有 required domain ready 且没有 blocked 的 generation。
- `domain_status`：每个 domain 的 apply 结果。

同一个 generation 重放必须幂等。

### 4.5 控制权与本机管理员能力

OpenStack 模式必须把“Neutron 权威配置”和“本机管理员排障能力”分开。

Neutron 权威配置包括：

- Neutron ports 对应的 group/address-set。
- ACL / Security Group。
- QoS。
- Mirror。
- TCPrt feature flag。
- 这些对象对应的 runtime status、generation 和 WAL 持久化状态。

这些状态只能由 `neutron-aria-agent` 通过 snapshot API 修改。本机 `ariactl` 或现有管理 API 不允许对 Neutron-managed port 直接写这些状态。

本机管理员能力分成两类：

| 类型 | 例子 | OpenStack 模式策略 | 是否进入 WAL |
| --- | --- | --- | --- |
| 只读观测 | stats、metrics、diagnose、tcprt query | 允许 | 否 |
| 临时排障 | trace start/stop/flush、drop stats flush | 允许，但不进入 Neutron schema | 否 |
| Neutron 权威配置写入 | group、policy、qos、mirror、tcprt enable、ACL enable | 禁止本机手动写 Neutron-managed port | 是，只能由 snapshot 写 |
| 非 Neutron 持久配置 | service chain、host-global ssl、手动 config toggle | OpenStack 模式默认不作为落地范围 | 不得混入 Neutron WAL 命名空间 |

因此，管理员可以在 compute node 上使用 trace 做临时排障；trace filter 不应被视为 Neutron desired state，也不应通过 WAL 持久化。`aria-datapath` 重启后，trace 需要重新开启。

相反，如果管理员用本机命令手动改 ACL/QoS/Mirror/TCPrt 配置，这会和 Neutron snapshot 形成双写冲突。OpenStack 模式应在代码层拒绝这类写入，返回明确错误，例如 `LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_PORT`。

### 4.6 Authority 状态机与重新接管

OpenStack mode 不能只用“通信是否成功”判断是否允许本机写入。通信失败不等于退出 OpenStack 托管。

必须区分以下状态：

| 状态 | 触发条件 | 权威来源 | 本机持久配置写入 | Datapath 行为 |
| --- | --- | --- | --- | --- |
| `openstack_managed` | 收到并成功接受 Neutron snapshot | Neutron | 拒绝 | 执行最新 `last_good_generation` |
| `openstack_degraded` | Neutron RPC、socket 或 status 暂时异常，但本机仍有托管标记 | Neutron | 拒绝 | 继续执行最后一次成功 snapshot |
| `local_break_glass` | 管理员显式执行本机接管命令 | Local admin | 允许，写 local override WAL | 暂停 Neutron apply |
| `local_standalone` | 非 OpenStack 部署或管理员显式脱离 OpenStack | Local admin | 允许，写 local WAL | 按本机配置运行 |
| `rejoin_pending` | break-glass 后 Neutron 通信恢复 | Neutron pending | 拒绝新的本机持久写入 | 等待重新接管决策 |

默认规则：

- `openstack_managed` 和 `openstack_degraded` 都不能本机改 ACL/QoS/Mirror/TCPrt/group。
- Neutron 通信失败时，datapath 继续使用 `last_good_generation`，不能自动开放本机写入口。
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
- `project_id` 是所有租户对象的必填元数据，至少覆盖 port、security group、ACL rule、QoS policy、Mirror policy、TCPrt flag。
- `aria-datapath` 内部对象 key 必须使用 scoped object key：`source/project_id/domain/object_id`。
- 不能只用 security group name、policy name 或短 ID 做 key。
- 数据包本身不携带 project_id，实际 enforcement 仍按 ingress/egress port identity 和编译后的 per-port policy 执行。
- 不因为 project_id 不同就自动丢包；跨租户共享网络、路由、floating IP、provider/admin policy 是否允许，由 Neutron 对象关系和 ACL 规则决定。
- 所有跨 project 引用都必须来自 Neutron 明确授权的对象关系，例如 shared network、RBAC shared QoS policy 或 admin-only mirror policy。
- 未经 Neutron 表达的跨 project remote group、QoS、Mirror、TCPrt 引用必须拒绝或标记 degraded。

多租户对象命名建议：

```text
port key          = neutron/{project_id}/port/{port_id}
group key         = neutron/{project_id}/group/{security_group_id}
address-set key   = neutron/{project_id}/address-set/{security_group_id}/{ethertype}
acl key           = neutron/{project_id}/acl/{security_group_rule_id}
qos key           = neutron/{project_id}/qos/{policy_id}
mirror key        = neutron/{project_id}/mirror/{policy_id}
tcprt key         = neutron/{project_id}/tcprt/{scope}/{scope_id}
```

如果 Neutron 对象是 shared/admin-owned，对象 key 仍保留 owner project 或 admin scope，同时在 binding 关系里记录实际 port project。`aria-datapath` 只消费已经解析好的 effective binding，不在 Rust 侧重新判断 Neutron RBAC。

四个功能域的多租户规则：

| 功能 | 多租户适配 |
| --- | --- |
| ACL | security group、rule、remote group 必须带 `project_id`；remote group 默认只展开同 project 成员，跨 project 只接受 Neutron 明确授权的 shared/admin 关系 |
| QoS | policy 带 owner `project_id` 和 `scope`；shared QoS 由 `neutron-aria-agent` 解析成 port effective QoS，datapath 只按 port apply |
| Mirror | 默认 admin-only；tenant 不能自服务创建 mirror；跨 project mirror target 默认拒绝，只有 admin policy 显式允许时才生成 snapshot |
| TCPrt | 支持 project/network/port 三级输入时，Python 侧先解析成 per-port effective flag；datapath 只按 port flag apply |

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
```

约束：

- OpenStack agent mode 只监听 Unix socket：`/run/aria/aria-agent.sock`。
- 不作为租户 API。
- 只给 `neutron-aria-agent` 和本机管理员使用。
- 主路径必须是 full snapshot 或 port-scoped snapshot，不能依赖逐条 CRUD 叠加。
- 现有 `/{instance}/policies`、`/{instance}/qos`、`/{instance}/mirror` 可以保留，但不是 OpenStack 主路径。

### 5.2 Snapshot 请求结构

建议请求结构：

```json
{
  "schema_version": "1",
  "local_generation": "compute-01-000001",
  "host": "compute-01",
  "mode": "coexist",
  "full": true,
  "tenant_model": {
    "scope_key": "source/project_id/domain/object_id",
    "shared_object_policy": "neutron_rbac_only"
  },
  "ports": [
    {
      "port_id": "port-uuid",
      "network_id": "network-uuid",
      "project_id": "project-uuid",
      "network_project_id": "network-owner-project-uuid",
      "device_id": "server-uuid",
      "binding_host": "compute-01",
      "if_name": "tapabcdef12-34",
      "ifindex": 123,
      "mac_address": "fa:16:3e:00:00:01",
      "fixed_ips": ["10.0.0.10"],
      "allowed_address_pairs": ["10.0.0.11"],
      "port_security_enabled": true,
      "admin_state_up": true
    }
  ],
  "groups": [
    {
      "group_id": "sg-web",
      "project_id": "project-uuid",
      "scope": "security_group",
      "scope_id": "sg-web",
      "addresses": ["10.0.0.10", "10.0.0.11"]
    }
  ],
  "acl_policies": [
    {
      "port_id": "port-uuid",
      "project_id": "project-uuid",
      "security_group_id": "sg-web",
      "security_group_rule_id": "rule-uuid",
      "direction": "ingress",
      "ethertype": "IPv4",
      "protocol": "tcp",
      "remote_group_id": "sg-web",
      "remote_ip_prefix": null,
      "port_range_min": 80,
      "port_range_max": 80,
      "action": "allow"
    }
  ],
  "qos_policies": [
    {
      "policy_id": "qos-policy-uuid",
      "port_id": "port-uuid",
      "project_id": "project-uuid",
      "scope": "port",
      "direction": "egress",
      "max_kbps": 100000,
      "max_burst_kbps": 10000,
      "mode": "shaping"
    }
  ],
  "mirror_policies": [
    {
      "policy_id": "mirror-policy-uuid",
      "port_id": "port-uuid",
      "project_id": "project-uuid",
      "source_project_id": "project-uuid",
      "target_project_id": "admin-project-uuid",
      "direction": "ingress",
      "protocol": "any",
      "target_iface": "mirror0",
      "admin_only": true
    }
  ],
  "feature_flags": {
    "default": {
      "acl": true,
      "qos": true,
      "mirror": true,
      "tcprt": false
    },
    "ports": {
      "port-uuid": {
        "acl": true,
        "qos": true,
        "mirror": false,
        "tcprt": true
      }
    }
  }
}
```

第一版可以先实现必要字段，但字段语义必须稳定。

多租户字段约束：

- `project_id` 对 tenant-scoped 对象必填，不能只从 port 反推。
- `network_project_id` 用于 shared network 场景，port owner 和 network owner 可以不同。
- `scope = "shared"` 或 `scope = "admin"` 的对象必须由 `neutron-aria-agent` 根据 Neutron RBAC/admin policy 解析后再下发。
- Snapshot 内部引用必须使用 ID，不使用 name。
- `aria-datapath` 对 unknown project、unknown scoped group 或跨 project 未授权引用返回 domain degraded 或拒绝相关对象 apply。

### 5.3 Snapshot 返回结构

建议返回结构：

```json
{
  "accepted": true,
  "schema_version": "1",
  "accepted_generation": "compute-01-000001",
  "applied_generation": "compute-01-000001",
  "last_good_generation": "compute-01-000001",
  "status": "ready",
  "domains": {
    "groups": {
      "status": "ready",
      "applied": 4,
      "removed": 1,
      "error_code": null,
      "message": null
    },
    "acl": {
      "status": "ready",
      "applied": 12,
      "removed": 3,
      "error_code": null,
      "message": null
    },
    "qos": {
      "status": "degraded",
      "applied": 1,
      "removed": 0,
      "error_code": "QOS_SHAPING_FALLBACK",
      "message": "egress shaping unavailable on this kernel; applied policing degraded mode"
    },
    "mirror": {
      "status": "ready",
      "applied": 0,
      "removed": 0,
      "error_code": null,
      "message": null
    },
    "tcprt": {
      "status": "ready",
      "applied": 1,
      "removed": 0,
      "error_code": null,
      "message": null
    },
    "runtime": {
      "status": "ready",
      "applied": 1,
      "removed": 0,
      "error_code": null,
      "message": null
    }
  }
}
```

Domain status 枚举：

- `ready`：该 domain 成功。
- `degraded`：该 domain 有降级，但 required traffic path 仍可运行。
- `blocked`：该 domain 失败，且会影响对应功能。
- `skipped`：该 domain 本次没有输入或功能未开启。

### 5.4 错误码

错误码要稳定，便于 `neutron-aria-agent` 上报和排障：

| 错误码 | Domain | 含义 | 处理 |
| --- | --- | --- | --- |
| `SCHEMA_UNSUPPORTED` | runtime | schema 版本不支持 | 拒绝 snapshot，agent degraded |
| `PORT_IFACE_NOT_FOUND` | runtime | Neutron port 对应本机接口不存在 | domain degraded，等待 Netlink 对账 |
| `PORT_IFINDEX_NOT_READY` | runtime | port 接口存在但 ifindex 尚不可用或刚发生变化 | domain degraded，等待 Netlink 对账 |
| `PORT_BINDING_HOST_MISMATCH` | runtime | snapshot port 的 binding_host 与本机 host 不一致 | 拒绝该 port apply，触发 full resync |
| `BPF_ATTACH_DEFERRED_IFACE_MISSING` | runtime | attach 前置检查发现 tap/qvo/veth 不存在 | 不执行 eBPF attach，等待接口事件 |
| `BPF_ATTACH_STALE_LINK_CLEANUP_FAILED` | runtime | tap 删除后旧 attach/link/qdisc 清理失败 | 记录 warning/degraded，允许新 ifindex preflight 后重新 attach |
| `GROUP_COMPILE_FAILED` | groups | group/address-set 编译失败 | 拒绝相关 port apply |
| `ACL_COMPILE_FAILED` | acl | ACL 规则编译失败 | 拒绝相关 port ACL |
| `QOS_SHAPING_FALLBACK` | qos | shaping 不可用，降级 policing | degraded，不阻塞 ACL |
| `QOS_APPLY_FAILED` | qos | QoS map 写入失败 | qos blocked，不阻塞 ACL |
| `MIRROR_TARGET_NOT_FOUND` | mirror | mirror target 不存在 | mirror degraded |
| `MIRROR_APPLY_FAILED` | mirror | mirror map 写入失败 | mirror blocked，不阻塞 ACL/QoS/TCPrt |
| `TCPRT_APPLY_FAILED` | tcprt | TCPrt 开关写入失败 | tcprt blocked，不阻塞 ACL/QoS/Mirror |
| `WAL_APPEND_FAILED` | runtime | WAL append 失败 | 尝试 compact 降级修复，失败则 runtime blocked |
| `PINNED_RUNTIME_MISSING` | runtime | pinned map/link 不完整 | 触发 runtime repair 或 full resync |
| `LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_PORT` | runtime | 本机命令试图修改 Neutron-managed policy | 拒绝写入，提示通过 Neutron 修改 |
| `REJOIN_REQUIRES_LOCAL_OVERRIDE_DISCARD` | runtime | break-glass 后重新接管前存在 local override | 进入 rejoin pending，等待管理员确认 |

### 5.5 DELETE 语义

`DELETE /api/v1/neutron/ports/{port_id}` 用于快速清理单个端口：

- 清理该 port 关联的 group/address-set 引用。
- 清理 ACL/QoS/Mirror/TCPrt 状态。
- 清理 feature flag。
- 不删除其它 port 仍引用的 group。
- 写 WAL。
- 返回 domain status。

删除 API 是优化路径。最终一致性仍依赖下一次 full snapshot。

### 5.6 本机写入保护

当 datapath 进入 OpenStack mode 后，现有本机管理 API 必须识别 Neutron-managed port 或 Neutron-managed instance。

OpenStack mode 包括 `openstack_managed` 和 `openstack_degraded`。通信失败只会进入 degraded，不能自动切到本机可写模式。

必须拒绝的本机写入：

- group add/delete。
- policy add/delete。
- QoS add/delete。
- Mirror add/delete。
- config set 中影响 ACL/QoS/Mirror/TCPrt 的开关。
- 任何会改变 Neutron-managed port datapath policy 的操作。

允许的本机操作：

- health、status、stats、metrics。
- diagnose。
- trace start/stop/list/flush。
- drops list/flush。
- tcprt query/list。

拒绝策略：

- 返回 `409 Conflict` 或等价错误。
- 错误码使用 `LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_PORT`。
- 错误信息必须提示“该端口由 Neutron 管理，请通过 Neutron 修改配置”。
- 只读和临时排障操作不能写入 Neutron WAL，也不能改变 `last_good_generation`。

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
│   └── extensions/
│       ├── mirror.py         # TaaS/vendor mirror input
│       └── tcprt.py          # feature flag input
└── tests/
    ├── test_translator_acl.py
    ├── test_translator_qos.py
    ├── test_translator_mirror.py
    ├── test_translator_tcprt.py
    └── test_snapshot_client.py
```

### 6.2 主要模块职责

| 模块 | 职责 |
| --- | --- |
| `agent.py` | 启动服务、注册 agent、heartbeat、resync 调度、事件消费 |
| `config.py` | 读取 Neutron/Aria 配置，如 host、local socket、resync interval |
| `neutron_client.py` | 封装 Neutron RPC、full resync、port/SG/QoS 拉取 |
| `local_client.py` | 调用 datapath snapshot/status/delete API |
| `state.py` | 保存本 host 投影状态、generation、last status |
| `translator.py` | 把 Neutron 对象翻译成 Aria snapshot |
| `status.py` | 把 domain apply status 转成 agent alive/degraded 上报 |
| `extensions/mirror.py` | 接入 TaaS 或 Aria vendor mirror extension |
| `extensions/tcprt.py` | 接入 port/network tag 或 vendor feature flag |

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
9. 收到 port/SG/QoS/Mirror/TCPrt 事件后，重新计算受影响端口。
10. 下发 port-scoped 或 host-scoped snapshot。
11. 周期性执行 full resync 修正漂移。

### 6.4 Full Resync 触发条件

以下情况必须触发 full resync：

- agent 启动。
- Neutron RPC reconnect。
- Neutron 事件队列溢出。
- local_generation 和 datapath status 不一致。
- `aria-datapath` 重启后 `last_good_generation` 缺失。
- Netlink 对账发现本机接口集合和 Neutron binding 不一致。
- snapshot apply 返回 `PINNED_RUNTIME_MISSING` 或 runtime blocked。
- 周期性 resync interval 到期。

### 6.5 事件合并

Neutron 事件可能短时间内大量到达。`neutron-aria-agent` 应合并事件：

- port update：按 port_id 合并，只保留最后状态。
- SG rule update：找出本 host 引用该 SG 的 ports，批量重算。
- remote group update：只重算本 host 相关 address-set。
- QoS update：找出绑定该 policy 的 ports/network。
- Mirror/TCPrt update：只重算相关 ports。

事件合并窗口建议从 100ms 到 500ms 起步，避免每条规则都触发一次 map apply。

## 7. aria-datapath 改造点

### 7.1 API 类型

在 `api` crate 增加 Neutron snapshot 相关类型：

- `NeutronSnapshotRequest`
- `NeutronPortEntry`
- `NeutronGroupEntry`
- `NeutronAclPolicyEntry`
- `NeutronQosPolicyEntry`
- `NeutronMirrorPolicyEntry`
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
agent/src/api_handlers/neutron.rs
agent/src/control_plane/neutron_snapshot.rs
```

### 7.3 Apply Engine

Snapshot apply 必须按固定顺序执行：

1. 校验 schema、host、mode、generation。
2. 对 snapshot 中的 ports 做 attach preflight。
3. 解析 preflight 通过的 port 到本机 instance/tap_id/ifindex。
4. 编译 group/address-set/port-set。
5. 清理被 snapshot 覆盖端口上的旧状态。
6. apply groups。
7. apply ACL。
8. apply QoS。
9. apply Mirror。
10. apply TCPrt feature flags。
11. 写 runtime config。
12. 写 WAL。
13. 更新 generation/status。
14. 返回 domain status。

Attach preflight 必须在任何 eBPF attach、map 写入或 pinned runtime 修改前执行：

- `binding_host` 必须等于本机 host。
- `if_name` 必须匹配本机实际存在的 tap/qvo/qvb/veth/eth 接口。
- `ifindex` 如果由 snapshot 提供，必须和本机 Netlink 查询结果一致。
- `ifindex` 如果未提供，必须能通过 Netlink 从 `if_name` 查出。
- 接口不存在时返回 `PORT_IFACE_NOT_FOUND` 或 `BPF_ATTACH_DEFERRED_IFACE_MISSING`。
- 接口存在但 ifindex 暂不可用或刚发生变化时返回 `PORT_IFINDEX_NOT_READY`。
- preflight 失败的 port 不进入 groups/ACL/QoS/Mirror/TCPrt apply。
- preflight 失败不能写入 accepted datapath state，只能写入 degraded status。
- Netlink 后续发现接口 ready 后，由 `neutron-aria-agent` 重新下发 port-scoped snapshot。

原则：

- group 是 ACL/QoS/Mirror 的共同基础，不能绕过。
- ACL 是 required domain。
- QoS/Mirror/TCPrt 是 independent domain，失败不能影响 ACL 成功路径。
- runtime/WAL 是 required domain。
- apply 必须支持重放。
- 删除 port 必须清理旧 map entry，避免 orphan。

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

如果 WAL append 失败：

1. 尝试 compact 降级修复。
2. compact 成功则返回 `runtime.degraded`。
3. compact 失败则返回 `runtime.blocked`。
4. `neutron-aria-agent` 必须保持 degraded 并触发 full resync。

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
- replay 顺序为 compact `state.json` -> `neutron-state.wal`；只有处于 `local_break_glass` 或 `local_standalone` 时才 replay `local-override.wal`。

### 7.5 Netlink 与接口对账

Netlink 是必选支撑能力：

- 本机接口新增时，尝试匹配 Neutron port 的 `if_name`。
- 本机接口删除时，标记对应 port runtime degraded。
- ifindex 变化时，刷新 tap/veth/ifindex/tap_id 映射。
- ifindex 变化时，旧 ifindex 上的 pinned runtime 不能直接复用到新接口，必须重新校验 tap_id/ifindex 映射。
- port attach 前必须通过 Netlink 或等价系统接口确认 tap/qvo/qvb/veth 已存在。
- 周期性对账时比较 Neutron binding ports 和本机 managed instances。

不能只依赖 Neutron RPC，因为 VM 生命周期和接口生命周期不是同一个事件源。

### 7.6 Pinned Maps

Pinned Maps / pinned links 是必选支撑能力：

- `aria-datapath` restart 后应复用现有 pinned runtime。
- pinned runtime 不完整时，返回 `PINNED_RUNTIME_MISSING`。
- 能 repair 的 runtime 由 `aria-datapath` repair。
- 不能 repair 的 runtime 由 `neutron-aria-agent` full resync 修正。

## 8. 功能映射

### 8.1 Group / Address-set

Group 是必选编译中间层。

来源：

- Neutron fixed IP。
- allowed address pairs。
- remote IP prefix。
- remote security group 展开结果。
- Mirror match 所需 src/dst group。
- QoS match 所需 port/group 归属。

执行语义：

- 每个 group 必须有稳定 ID。
- 每个 group 的稳定 ID 必须从 scoped object key 派生，不能只用 security group name。
- group 可以是 host-scoped，也可以是 port-scoped。
- remote group 只展开本 host 相关 IP。
- remote group 默认按 `project_id` 隔离展开；shared/admin 跨 project 关系必须由 `neutron-aria-agent` 显式解析。
- 删除 port 时释放只被该 port 引用的 group/address-set。
- 删除 port 时按 scoped object key 释放引用，不能影响其它 project 的同名或同 ID 缓存对象。
- 不允许 ACL 直接绕过 group 写 map。

### 8.2 ACL / Security Group

Neutron 输入：

- security group。
- security group rule。
- port security。
- fixed IP / MAC。
- allowed address pairs。
- remote group。

Aria 执行语义：

- 保持 Neutron security group 用户语义。
- 默认 deny。
- rule 只表达 allow。
- 多个 security group 按 additive 合并。
- 同名 security group 在不同 project 中必须完全隔离。
- remote group 规则只展开该 rule 所属 project 的 security group 成员，除非 Neutron 输入明确给出 shared/admin 关系。
- port security disabled 时 bypass ACL 与 anti-spoof。
- allowed address pairs 进入 anti-spoof 例外集合。
- DHCP、metadata、ARP、IPv6 NDP 必要例外必须明确生成。

第一阶段必须支持：

- IPv4 ingress / egress。
- TCP / UDP / ICMP。
- remote CIDR。
- remote security group 展开。
- allowed address pairs。

暂缓：

- 跨 region remote group 优化。
- Neutron 以外的自定义 ACL northbound。
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

### 8.4 Mirror

Mirror 是第一阶段功能域，但不是 Neutron core 普通租户能力。

输入来源优先级：

1. Neutron Tap-as-a-Service，如果目标环境已有。
2. Aria vendor extension，例如 admin-only port mirror policy。
3. 管理员 host-local 配置。

Aria 执行语义：

- 默认 admin-only。
- tenant 不能自服务创建 mirror。
- 跨 project mirror 默认拒绝；只有 admin policy 显式允许时才生成 snapshot。
- mirror target 必须在本 host 可达。
- target 不存在时 `mirror` domain degraded。
- mirror 失败不能影响 ACL/QoS/TCPrt。

第一阶段必须支持：

- 按 port/direction/protocol 镜像。
- 指定本机 target interface。
- mirror stats。
- target 缺失时 degrade。

暂缓：

- 跨 host mirror target。
- 多 target fan-out。
- tenant self-service mirror。

### 8.5 TCPrt

TCPrt 是观测能力，不是 policy 能力。

Neutron 输入：

- port binding host。
- port fixed IP / MAC。
- port tag 或 vendor extension feature flag。
- network-level default feature flag。

Aria 执行语义：

- TCPrt 不改变包转发结果。
- 可按 project/network/port 输入，但必须先解析成 per-port effective flag。
- port 级配置覆盖 network 级配置，network 级配置覆盖 project 级默认值。
- 查询和聚合不能阻塞 ACL/QoS/Mirror apply。
- 不写回 Neutron DB。

第一阶段必须支持：

- per-port enable / disable。
- top flow 查询。
- single flow 查询。
- histogram / states 查询。
- 本地 metrics 或 observe API 暴露。

暂缓：

- 跨 host 全局聚合。
- Neutron DB 时序存储。
- 租户自服务查询。

### 8.6 其它已有能力

这些能力代码保留，但不进入 `neutron-aria-agent` 暴露面：

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
- 不参与 snapshot required domain。
- 不影响 Neutron port binding、ACL、QoS、Mirror、TCPrt apply 成败。
- 只读观测和临时排障能力可以由本机管理员使用。
- 临时排障状态不进入 WAL，不参与 generation。
- 任何会改变 Neutron-managed port policy 的本机写操作必须被拒绝。

## 9. 数据流

### 9.1 启动 Full Resync

1. `neutron-aria-agent` 启动。
2. 检查 datapath health。
3. 向 Neutron 注册 agent。
4. 拉取本 host 绑定 ports。
5. 拉取相关 security groups、QoS policies、mirror policies、feature flags。
6. 查询本机 datapath status。
7. 对比 local_generation 和 last_good_generation。
8. 生成 full snapshot。
9. 调用 `PUT /api/v1/neutron/snapshot`。
10. 记录 apply status。
11. heartbeat 上报 alive 或 degraded。

### 9.2 Port Create / Bind

1. Neutron port 绑定到本 host。
2. `neutron-aria-agent` 收到 port update。
3. 判断本机接口是否存在。
4. 接口存在且 attach preflight 通过时生成 port-scoped snapshot。
5. 接口不存在时标记 runtime degraded，等待 Netlink 对账。
6. Netlink 发现接口后触发重算。
7. 下发 snapshot。
8. 成功后 port 对应 Aria runtime ready。

Fail-safe 规则：

- 新 port 在没有 accepted snapshot 前不能被标记为 Aria ready。
- 如果 OVS/OVN SG 已经关闭或旁路，而 Aria ACL 尚未 ready，该 host 必须保持 agent degraded，并阻止进入生产 smoke 通过状态。
- 对已经 attached 但没有 matching Neutron policy 的 Aria-managed port，默认 ACL 行为是 deny，除非 Neutron 明确表达 port security disabled 或允许例外。
- `PORT_IFACE_NOT_FOUND` 只能让 runtime degraded，不能自动变成本机可写。
- `BPF_ATTACH_DEFERRED_IFACE_MISSING` 时不得尝试 eBPF attach，也不得写 accepted generation。
- tap/qvo/veth 出现前，`aria-datapath` 只能记录 degraded status，不能把该 port 加入 ready 状态。
- N3 之前不得在目标环境全局关闭 OVS/OVN SG enforcement；只能在 smoke 环境或明确回滚窗口内验证关闭方式。

### 9.3 Port Delete / Unbind

1. Neutron port 从本 host 删除或迁走。
2. `neutron-aria-agent` 调用 `DELETE /api/v1/neutron/ports/{port_id}`。
3. `aria-datapath` 清理该 port 的 group/ACL/QoS/Mirror/TCPrt。
4. 释放只被该 port 引用的 group/address-set。
5. 写 WAL。
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
4. `aria-datapath` 清理该 port 的 ACL/QoS/Mirror/TCPrt 和 port-scoped group/address-set 引用。
5. 只释放 refcount 归零的 scoped object，不影响同 host 其它 port，也不影响其它 project 的同名对象。
6. 写入 `neutron-state.wal`。
7. 下一次 full resync 再次确认本 host 不应存在该 port。

新 host 流程：

1. 新 host 的 `neutron-aria-agent` 收到 port update，发现该 port 绑定到本 host。
2. 将该 port 加入 projected state。
3. 查询本机接口是否已经出现。
4. 如果接口存在且 attach preflight 通过，生成 port-scoped snapshot 并下发。
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
- 如果 Aria 已接管 SG enforcement，新 host 上该 port 未 ready 时不能把 agent 状态报为完全 ready。
- 对 Aria-managed 但 policy 尚未 materialize 的 port，默认 deny，除非 Neutron 明确表达 port security disabled。
- 旧 host 清理失败时必须进入 degraded，并在下一次 full resync 继续重试。
- 新旧 host 同时短暂存在同一 `port_id` 的状态时，以 Neutron 当前 `binding_host` 为准；旧 host 不再收到本机流量后必须清理，不能长期保留 stale map entry。

迁移验收：

- live/cold migration 后，旧 host 不再保留该 port 的 ACL/QoS/Mirror/TCPrt state。
- 新 host 接口出现后能自动 apply port-scoped snapshot。
- 旧 host 丢失 unbind event 时，full resync 能清理 stale port。
- 新 host 丢失 bind event 时，full resync 能补齐 port state。
- 重复 migration event 不产生重复 group/rule/qos/mirror。
- event 乱序时旧 revision 不覆盖新 binding_host。

### 9.5 VM Restart / Tap Recreate

虚机重启时，Neutron port 的 `binding_host` 通常不变，但本机 tap/qvo/qvb/veth 可能被删除后重新创建。这个场景会影响已经 attach 在旧 netdev 上的 eBPF 程序。

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
7. 重新查询 ifindex，执行 attach preflight。
8. preflight 通过后重新 attach eBPF，并重新 apply port-scoped snapshot。
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
- trace 等临时排障状态不要求恢复；ACL/QoS/Mirror/TCPrt 必须按 Neutron desired state 恢复。

### 9.6 Security Group Update

1. Neutron security group 或 rule 更新。
2. `neutron-aria-agent` 找出本 host 引用该 SG 的 ports。
3. 展开 remote group。
4. 生成受影响 ports 的 snapshot。
5. `aria-datapath` 先更新 group/address-set，再更新 ACL。
6. 成功后更新 generation。

### 9.7 QoS Update

1. Neutron QoS policy 更新。
2. 找出 port-level 或 network-level 受影响 ports。
3. 按 port-level 覆盖 network-level 计算最终 QoS。
4. 生成 snapshot。
5. `aria-datapath` apply QoS。
6. shaping 不可用时返回 degraded 状态。

### 9.8 Mirror / TCPrt Update

Mirror 和 TCPrt 都走 snapshot：

- Mirror target 不存在时只让 mirror domain degraded。
- TCPrt 查询失败不能影响 apply。
- 不能只追加单条规则而不重算完整 port 状态。

### 9.9 Agent Restart

`aria-datapath` 重启：

1. 复用 pinned runtime。
2. replay WAL 或加载 compact state。
3. 恢复 status。
4. `neutron-aria-agent` 检查 last_good_generation。
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
| VM create，Neutron event 先到，tap 后出现 | port bind event 早于本机接口创建 | Neutron `binding_host` + Netlink | 记录 desired state，返回 `PORT_IFACE_NOT_FOUND`，等待 Netlink `NEWLINK` 后 port-scoped snapshot | tap/qvo/veth 存在，ifindex ready，snapshot apply 成功 |
| VM create，tap 先出现，Neutron event 后到 | Netlink 先发现接口 | Neutron full resync/event | 只记录候选接口，不因接口名匹配就创建 Neutron-managed port state | 后续 Neutron port 绑定到本 host 且 preflight 成功 |
| VM reboot / hard reboot | tap 删除并重建，`binding_host` 不变 | Neutron desired state + Netlink | 保留 desired state，旧 ifindex runtime degrade，新 ifindex 出现后重新 attach | 新 ifindex preflight 成功，port-scoped snapshot accepted |
| VM live migration | 旧 host unbind，新 host bind | Neutron `binding_host` | 旧 host delete，新 host wait tap 后 apply | 新 host apply 成功，旧 host 清理完成或进入可重试 degraded |
| VM cold migration / resize confirm | port 可能经历 unbind、bind、tap 重建 | Neutron revision | 按最新 revision 处理，旧 revision 丢弃 | 最新 binding_host 对应 host apply 成功 |
| VM resize revert | port 可能回到旧 host | Neutron revision | 不假设迁移方向，按最新 `binding_host` 重建本机投影 | 返回 host 重新 attach 成功 |
| VM evacuate | 原 host 可能不可达，新 host 重新绑定 | Neutron full resync | 新 host 按 bind 处理；原 host 恢复后 full resync 发现 port 不再属于本机并清理 | 新 host ready；旧 host 恢复后无 stale port |
| VM shelve / unshelve | port 可能长期无本机 tap | Neutron port 状态 + binding | port 无本机接口期间保持 degraded 或 removed，不能本机写入 | unshelve 后接口出现并 apply 成功 |
| VM rebuild | port_id 通常不变，tap 可能重建 | Neutron revision + Netlink | 视为 tap recreate 或 port update，不清空 Neutron policy | 新接口 ready 后恢复 ACL/QoS/Mirror/TCPrt |
| Port delete | Neutron 删除 port | Neutron event/full resync | 调用 local delete，清理 port-scoped state，释放 refcount 归零对象 | delete 幂等成功 |

补充规则：

- 接口名只能作为匹配线索，不能作为权威。权威始终是 Neutron port `id`、`binding_host`、revision 和本机 Netlink 结果的交集。
- 对于先看到 tap、后看到 Neutron event 的场景，不能因为 `tap*` 名称符合模式就提前挂载 eBPF。
- resize、evacuate、rebuild、shelve 这类 Nova 生命周期最终都要落到 port bind/unbind、tap recreate、full resync 三类动作上，不能额外创造本机权威状态。

#### 9.10.2 Neutron 控制面与消息场景

| 场景 | 处置 |
| --- | --- |
| Neutron server 重启 | `neutron-aria-agent` 保持进程 alive 但进入 degraded，RPC 恢复后 full resync，不允许本机持久写入 |
| RabbitMQ / oslo.messaging 中断 | 保持 last good snapshot，事件恢复后先 full resync 再处理增量事件 |
| 事件重复 | 按 `source_revision` 或 Neutron revision 去重，重复事件不得重复增加 refcount |
| 事件乱序 | 旧 revision 不能覆盖新 revision；如果无法判断新旧，触发 full resync |
| 事件队列溢出 | 丢弃本地增量队列，进入 full resync |
| Neutron API 查询部分失败 | 不下发半截 full snapshot；保持 last good generation，记录 degraded reason |
| Neutron agent heartbeat 失败 | 不改变 datapath desired state；heartbeat 恢复后 full resync |
| Neutron 返回对象缺字段 | translator 拒绝生成 snapshot，标记 input degraded，不让 Rust 侧猜测 |
| Neutron revision 回退或不可信 | 使用 agent 本地单调 `local_generation`，但仍以 full resync 当前视图为内容权威 |

实现要求：

- `neutron-aria-agent` 必须区分 liveness 和 readiness。进程能运行、能 heartbeat，不代表 ACL/QoS/Mirror/TCPrt 都 ready。
- 如果 Neutron 控制面不可达，datapath 不能进入 `local_standalone`，只能进入 `openstack_degraded`。
- 所有控制面恢复路径都从 full resync 开始，不能只依赖恢复后的第一条增量事件。

#### 9.10.3 OVS / OVN / Linux Interface 场景

| 场景 | 处置 |
| --- | --- |
| OVS agent 重启 | 不把 OVS agent restart 视为 Neutron authority 变化；依靠 Netlink 和 full resync 校准接口 |
| ovs-vswitchd / ovsdb-server 重启 | tap/qvo/qvb 可能短暂消失或 ifindex 改变，按 tap recreate 处理 |
| qvo/qvb/tap 命名模式与预期不同 | N0.5 必须发现目标环境命名；不匹配时不得 attach，返回 degraded |
| Linux bridge / hybrid plug 模式 | 需要识别 tap、qvo、qvb 的真实包路径，attach 点必须在 N0.5 smoke 中确认 |
| OVN native port 模式 | 需要确认是否仍有本机 tap/veth attach 点；没有 attach 点则该 port 不进入 ready |
| trunk port / VLAN subport | 第一阶段默认只支持目标环境验证过的 port 形态；未验证 subport 标记 unsupported/degraded |
| SR-IOV / direct / macvtap port | 第一阶段默认不支持 eBPF attach，必须明确 degraded 或 ignored，不允许假 ready |
| DHCP/router/metadata service port | 不因接口名匹配自动接管；只处理 Neutron 明确绑定且在范围内的 compute VM port |

关键规则：

- attach 点不是文档假设，必须在目标 OpenStack 环境中实测。
- 如果目标环境同时存在 OVS hybrid plug 和 OVN native plug，`neutron-aria-agent` 必须按 port binding details 选择处理方式，不能全局硬编码。
- 原 OVS/OVN SG enforcement 关闭之前，Aria 不能宣称已经独立承担 SG；关闭之后，Aria 未 ready 的 port 默认 fail closed。

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

- `accepted_generation` 只能在 snapshot 校验、WAL durable 写入、required datapath apply 都成功后推进。
- 如果 WAL 写入失败，不能把内存态标记为 accepted，即使部分 eBPF map 已经更新。
- 如果 eBPF apply 失败，不能写成成功 WAL；下一次 full resync 必须能重试并修复。
- 对需要先写 intent 再 apply 的实现，WAL entry 必须能区分 `intent` 和 `committed`，replay 时只能恢复 committed state 或重新执行未完成 intent。

#### 9.10.5 Security Group / ACL 语义场景

| Neutron 输入 | Aria 处理 |
| --- | --- |
| port security enabled + security groups | 编译成 per-port ACL，默认不允许未表达流量 |
| port security disabled | 不下发 SG ACL enforcement，但仍可按配置执行 QoS/Mirror/TCPrt |
| port 没有 SG 但 port security enabled | 按 Neutron 语义处理，不自行添加宽松 allow |
| default security group | 和普通 SG 一样按 rule 编译，不使用名称做特殊判断 |
| remote group | Python 侧展开成本 host effective address-set，Rust 侧不访问 Neutron |
| allowed address pairs | 纳入 address-set / anti-spoof 输入，不能只看 fixed IP |
| IPv6 / SLAAC / ND | 必须在 ACL 语义里保留 Neutron 需要的 IPv6 邻居发现路径 |
| DHCP / metadata | 不能被默认 deny 破坏，是否作为显式 allow 由 Neutron 语义和目标环境 smoke 决定 |

关键规则：

- `project_id` 不能作为包路径上的直接 drop 条件。租户隔离由 Neutron rule、network、router、shared/RBAC 关系表达。
- 如果 Neutron SG rule 类型、ethertype 或 protocol Aria 暂不支持，必须显式 degraded，不允许静默放通。
- ACL、group/address-set、anti-spoof 需要一起考虑。只做 ACL 而忽略 allowed address pairs，会破坏 Neutron port security 语义。

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

#### 9.10.7 Mirror 场景

| 场景 | 处置 |
| --- | --- |
| mirror source port 不在本 host | 本 host 不创建 source mirror state |
| mirror target interface 不存在 | mirror domain degraded，ACL/QoS/TCPrt 不受影响 |
| mirror target 和 source 同 port | 拒绝，避免自环 |
| cross-project mirror | 默认拒绝，除非 admin policy 显式允许 |
| cross-host mirror | 第一阶段不做透明跨 host mirror；需要 admin 显式 target 或后续 remote sink 设计 |
| target port 删除 | 清理 mirror state，source port 不因此删除 |
| mirror 配置删除 | port-scoped snapshot 清理 mirror domain |

Mirror 是高风险观测能力，默认 admin-only。任何无法证明授权关系的 mirror 都必须拒绝或 degraded，不能为了可用性选择放宽。

#### 9.10.8 TCPrt 场景

| 场景 | 处置 |
| --- | --- |
| project/network/port 同时配置 TCPrt | translator 解析优先级，Rust 只接收 per-port final flag |
| port 级关闭，network 级开启 | port 级优先，最终关闭该 port TCPrt |
| TCPrt runtime 查询失败 | TCPrt domain degraded，不写回 Neutron DB |
| port 删除 | 清理该 port 的 TCPrt runtime state |
| 本机 ariactl 临时查看 TCPrt 观测结果 | 允许只读，不改变 Neutron generation |

TCPrt 是观察能力，不是 Neutron policy 权威。它可以影响本机观测输出，但不能反向修改 Neutron port 或 project 状态。

#### 9.10.9 多租户、共享网络与特殊 Port 场景

| 场景 | 处置 |
| --- | --- |
| shared network 上不同 project 的 ports 互通 | 按 Neutron SG/router/RBAC 结果决定，不按 project 不同直接 drop |
| router / floating IP 路径 | 第一阶段不实现 L3 datapath 替代，不能在 Rust 侧推导 router 语义 |
| provider network | port policy 仍按 Neutron 输入编译，不新增 provider 特判 |
| admin-owned shared policy | scoped object key 使用 admin/owner scope，binding 记录实际 port project |
| project 删除 | full resync 后清理该 project 在本 host 的所有 scoped state |
| 同名 security group / QoS policy | 使用 ID 和 scoped object key，不使用名称 |
| 同一个 remote group 被多个 project 引用 | 只有 Neutron 明确授权的引用可展开，否则 degraded |

实现上必须避免两种错误：

1. Rust 侧按 `project_id` 直接做硬隔离，破坏 shared network。
2. Python 侧只按对象名称关联，导致跨租户串 policy。

#### 9.10.10 容器、启动顺序与单实例场景

| 场景 | 处置 |
| --- | --- |
| host reboot 后容器先于 VM tap 启动 | full resync 建立 desired state，tap 缺失 port degraded，Netlink 后恢复 |
| `neutron-aria-agent` 先启动，socket 不存在 | agent degraded，重试 socket，socket 恢复后 full resync |
| `aria-datapath` 先启动，Neutron 不可达 | datapath 保持 last good state，不允许本机持久写入 Neutron-managed state |
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
| WAL append 失败 | 不推进 accepted generation，domain degraded，保留 last good |
| WAL replay 发现尾部半写 | 截断到最后完整 record，记录 repair 事件 |
| compact state 损坏 | 回退到 WAL replay；如果 WAL 也损坏，进入 blocked/degraded，不假 ready |
| 磁盘满 | 拒绝新 snapshot accepted，进入 degraded，避免内存态和持久态分裂 |
| `local-override.wal` 存在 | 不自动 rejoin；进入 `rejoin_pending`，等待 archive/discard |
| `neutron-state.wal` 和 `local-override.wal` 同时有同一 port | Neutron rejoin 前必须归档 local override，不能 merge |
| state_path 被误挂成容器临时目录 | N7 smoke 必须失败；生产部署禁止 |

WAL 修复不能扩大权限。即使 WAL 损坏，OpenStack-managed port 仍不能允许本机持久写入；只能保留 last good 或进入 degraded/blocked。

#### 9.10.12 Fail-Closed 与降级边界

OpenStack 模式要避免两个极端：一个是出错就全放通，另一个是一个非关键功能失败就把整台 compute node 打死。默认规则如下：

| Domain | 失败时默认行为 | 是否影响 port ready |
| --- | --- | --- |
| ACL / SG | fail closed，除非 Neutron 明确 `port_security_enabled = false` | 是 |
| Group / Address-set | fail closed，因为 ACL 依赖它 | 是 |
| WAL / state durable | 不接受新 generation | 是 |
| Netlink / attach preflight | port degraded，不 attach | 是 |
| QoS | QoS degraded，不影响 ACL ready | 不影响 ACL，但影响 QoS ready |
| Mirror | mirror degraded，不影响 ACL/QoS/TCPrt | 不影响 ACL |
| TCPrt | TCPrt degraded，不影响 ACL/QoS/Mirror | 不影响 ACL |
| trace/drops/diagnose | 临时功能失败只影响排障 | 不影响 Neutron ready |

如果原 OVS/OVN SG enforcement 已关闭，ACL domain 未 ready 的 port 不能被宣称可生产使用。对于安全组替代目标，这是硬门槛。

#### 9.10.13 版本、能力握手与升级回滚场景

`neutron-aria-agent` 和 `aria-datapath` 必须在 snapshot 前做 capability 握手：

- `schema_version`：snapshot schema 版本。
- `datapath_version`：Rust runtime 版本。
- `ebpf_artifact_version`：用户态和 eBPF map layout 版本。
- `capabilities`：acl、qos、mirror、tcprt、wal、netlink、pinned_maps、break_glass。
- `unsupported_features`：Rust 侧明确拒绝的 feature。

升级规则：

- Python 侧不能向旧 Rust 侧下发未知 required domain。
- Rust 侧不能静默忽略 unknown required field。
- 可选字段可以忽略，但必须进入 status 的 `ignored_optional_fields` 或等价观测字段。
- eBPF map layout 变化必须有 migration 或 rebuild 策略，不能直接复用旧 pinned map。
- 回滚时，如果新版本已经写入旧版本不能理解的 WAL entry，旧版本必须拒绝启动或进入只读 repair 模式，不能误 replay。

#### 9.10.14 运维操作场景

| 操作 | 允许性 | 规则 |
| --- | --- | --- |
| 本机 `ariactl trace start` | 允许 | 临时排障，不写 WAL，不改变 generation |
| 本机 `ariactl policy/qos/mirror` 改 Neutron port | 禁止 | 返回 `LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_PORT` |
| 管理员 break-glass | 允许但显式 | 进入 `local_break_glass`，写 `local-override.wal`，暂停 Neutron apply |
| break-glass 后恢复 Neutron | 不自动 merge | 进入 `rejoin_pending`，默认 Neutron wins |
| 手动清理 stale pinned map | 谨慎允许 | 必须先让 datapath stopped/degraded，并通过 repair/full resync 重建 |
| 手动删除 socket | 不允许作为恢复手段 | agent degraded，datapath 重建 socket 后 full resync |

运维文档必须把“临时排障”和“持久配置”分开。允许 trace 不等于允许本机改安全组、QoS、Mirror 或 TCPrt。

## 10. OpenStack 集成方式

### 10.1 Coexist 集成

第一阶段推荐 Coexist 集成：

- OVS/OVN 继续做 L2 binding 和 connectivity。
- `neutron-aria-agent` 作为 Aria 本地 agent 注册和同步。
- 原 OVS/OVN SG enforcement 必须关闭或旁路。
- Aria ACL 执行 Neutron security group 语义。

这种方式可以先验证节点侧功能，不直接挑战完整 L2 替换。

### 10.2 ML2 / Extension 边界

需要两类 OpenStack 集成点：

1. Agent 注册与 RPC 消费。
2. Mirror / TCPrt 的 admin-only extension 输入。

第一阶段不要把 `neutron-aria-agent` 宣称为完整 port binding owner，除非已经实现完整 L2 lifecycle。

建议边界：

- port binding 仍由现有 OVS/OVN mechanism 处理。
- Aria 读取 binding host，只处理绑定到本 host 的 ports。
- Aria 可以有自己的 agent type 和 heartbeat。
- Mirror/TCPrt 通过 admin extension、port tag 或 host-local 配置输入。

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
- 挂载 tracefs/debugfs，供 trace、kernel drop、部分 eBPF 观测能力使用。
- 挂载 `/proc`，用于接口、进程和部分观测能力。
- 挂载 `/var/lib/aria-agent`，用于 WAL、compact state、service chain 等持久化状态。
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
- 通过 Unix socket 文件权限控制访问，例如 owner/group 只给 Aria runtime 用户。
- socket 目录和文件权限由宿主机或 `aria-datapath` entrypoint 固定设置，推荐 `0770` 目录权限和专用 `aria` group。
- `neutron-aria-agent` 容器只需要加入能访问该 socket 的 group，不需要 eBPF capability。

示例配置：

```ini
[aria]
local_api = unix:///run/aria/aria-agent.sock
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
listen_unix_socket = "/run/aria/aria-agent.sock"
iface_pattern = "^(tap|qvo|qvb|veth|eth)"
state_path = "/var/lib/aria-agent"
pin_path = "/sys/fs/bpf/aria"
```

`neutron-aria-agent` 侧建议配置：

```ini
[DEFAULT]
host = compute-01
resync_interval = 60
mode = coexist

[aria]
local_api = unix:///run/aria/aria-agent.sock
enable_acl = true
enable_qos = true
enable_mirror = true
enable_tcprt = true
mirror_source = host-local
tcprt_source = port-tag
```

具体 Neutron 配置文件和 security group 关闭方式必须按目标 OpenStack 版本验证，不能只写文档不做 smoke。

## 11. 安全模型

### 11.1 本机 API 安全

Datapath Neutron snapshot API 必须是本机接口：

- 优先 Unix socket。
- 容器模式下通过宿主机 `/run/aria` 挂载和 Unix socket 文件权限限制访问。
- 只允许 `neutron-aria-agent` 用户访问。

不允许把 snapshot API 暴露到租户网络或管理网。

### 11.2 租户隔离

租户隔离由 Neutron 对象语义决定：

- `project_id` 是状态索引、审计、refcount 和 status 归属字段，不是租户可直接操作的 Aria API 凭据。
- ACL 按 port/security group 编译，包路径按 port identity 进入对应 per-port policy。
- 不在 datapath 中简单增加“project 不同就丢包”的硬规则，避免破坏 shared network、router、floating IP 和 provider network 场景。
- remote group 只展开允许的 Neutron 对象，默认同 project，跨 project 必须来自 Neutron shared/admin 关系。
- QoS/Mirror/TCPrt 都必须按 port effective policy 下发，不能让 Rust 侧根据 project 自行推导租户权限。
- tenant 不能直接创建 Aria 本地 policy，也不能访问 `/run/aria/aria-agent.sock`。
- status/log 可以面向 operator 输出 project 粒度计数，但不得作为租户自服务查询 API。

### 11.3 Mirror 权限

Mirror 默认 admin-only：

- 不开放 tenant self-service。
- target interface 必须本机可达。
- target 缺失只 degraded mirror domain。
- mirror 失败不影响 ACL/QoS/TCPrt。

### 11.4 观测能力权限

`trace`、`drops`、`ssl`、`diagnose`、`service chain` 保留为本机管理员能力：

- 不进入 Neutron tenant API。
- 不参与 Neutron object sync。
- 不影响 port apply。
- SSL 是 host-global，默认不得作为租户功能暴露。

## 12. 可观测性与运维

### 12.1 neutron-aria-agent 指标

建议暴露：

- agent alive/degraded。
- full resync count。
- event backlog。
- snapshot submit count。
- snapshot apply latency。
- last submitted generation。
- last accepted generation。
- last good generation。
- domain status count。
- last error code。
- port migration/rebind event count。
- stale port cleanup count。
- `PORT_IFACE_NOT_FOUND` count。
- `BPF_ATTACH_DEFERRED_IFACE_MISSING` count。
- `BPF_ATTACH_STALE_LINK_CLEANUP_FAILED` count。
- attach preflight failure count。
- interface recreate count。
- Neutron full resync reason count：startup、RPC reconnect、event overflow、status drift、manual。
- dropped stale revision count。
- unsupported port type count：trunk、SR-IOV、direct、unknown binding。
- unsupported QoS rule count。
- WAL append / replay / compact repair count。
- disk full or state path write failure count。
- capability handshake failure count。
- duplicate local agent instance count。
- fail-closed port count。

### 12.2 aria-datapath 状态

`GET /api/v1/neutron/status` 应返回：

- schema_version。
- host。
- mode。
- accepted_generation。
- applied_generation。
- last_good_generation。
- managed_ports。
- managed_groups。
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

## 13. 测试与验收

### 13.1 Python 单元测试

覆盖：

- port -> snapshot port entry。
- fixed IP / allowed address pairs -> group/address-set。
- security group -> ACL。
- remote group expansion。
- QoS port-level 覆盖 network-level。
- Mirror admin-only 输入。
- TCPrt feature flag。
- event merge。
- full resync。
- VM migration / port rebind 的 `binding_host` 变化。
- event `source_revision` 去重和旧 revision 丢弃。
- Neutron event 队列溢出后触发 full resync。
- Neutron API 部分失败时不生成半截 snapshot。
- port security disabled 时不生成 SG ACL enforcement。
- allowed address pairs 进入 anti-spoof / address-set 输入。
- IPv6 / ND / DHCP / metadata 例外按目标 Neutron 语义进入 translator。
- shared network 不因 project 不同被直接拒绝。
- unsupported trunk / SR-IOV / direct port 被显式标记 degraded 或 ignored。
- shared QoS RBAC 解析成 per-port effective QoS。
- DSCP / minimum bandwidth 不支持时进入 unsupported status。
- Mirror 自环、target 缺失、cross-project 未授权都被拒绝或 degraded。
- TCPrt project/network/port 优先级。
- break-glass/rejoin 状态不被 translator 当作 Neutron desired state。

### 13.2 Rust API / Apply 测试

通过 GitHub Actions 执行，不在本地运行 Rust 编译。

覆盖：

- snapshot schema deserialize。
- generation 幂等。
- port delete 清理。
- port delete 幂等。
- port `binding_host` 不匹配本机时拒绝 apply。
- migration 乱序 event 中旧 revision 不能覆盖新 binding_host。
- tap/qvo/veth 不存在时不得执行 eBPF attach。
- ifindex 不匹配或未 ready 时返回 `PORT_IFINDEX_NOT_READY`。
- VM reboot/tap recreate 后旧 ifindex cleanup 幂等。
- 新 ifindex 出现后能重新 attach 并恢复 status。
- tap 先出现但没有 Neutron binding 时不得 attach。
- OVS/OVN 重启导致 qvo/qvb/tap 消失时进入 degraded，不崩溃。
- unknown binding_host 或 binding_host 不匹配时拒绝 apply。
- port security disabled 时 ACL domain 不做 SG enforcement。
- BTF 缺失、bpffs 未挂载、pinned map schema mismatch 进入 degraded。
- WAL append 失败时不推进 accepted generation。
- WAL 尾部半写 replay 时可截断到最后完整 record。
- compact state 损坏时回退 WAL replay；无法修复时不假 ready。
- disk full 时拒绝新 snapshot accepted。
- local override 存在时 Neutron rejoin 进入 `rejoin_pending`。
- capability handshake 不匹配时拒绝 required domain。
- 同 host 双 `aria-datapath` 或双 `neutron-aria-agent` 实例被检测并拒绝双写。
- group 引用释放。
- ACL apply 顺序。
- QoS 降级状态。
- Mirror target missing degraded。
- TCPrt failure isolation。
- WAL append / compact 降级修复。
- status response。

### 13.3 DevStack / OpenStack Smoke

至少覆盖：

- VM port active。
- `neutron-aria-agent` alive。
- port 绑定到本 host 后生成 Aria snapshot。
- Security group 变更实时影响连通性。
- OVS/OVN SG enforcement 已关闭或旁路，没有双重过滤。
- `/run/aria/aria-agent.sock` 可用，`neutron-aria-agent` 通过该 socket 下发 snapshot。
- QoS 限速可观察。
- Mirror target 存在时 stats 增长。
- Mirror target 缺失时 only mirror degraded。
- TCPrt 开启后有流记录。
- `aria-datapath` restart 后 pinned runtime 和 full resync 成功。
- `neutron-aria-agent` restart 后 full resync 成功。
- VM 迁移或 port unbind 后旧 host 清理 port 状态。
- VM reboot/hard reboot 后 tap recreate，旧 ifindex cleanup，新 ifindex reattach。
- Neutron server/RabbitMQ 短暂中断后 full resync 恢复，不允许本机持久写入。
- OVS/OVN agent 或 ovs-vswitchd 重启后 Aria 不崩溃，接口恢复后 ready。
- port security disabled 的 port 不被 Aria SG ACL 阻断。
- allowed address pairs、IPv6 ND、DHCP、metadata 流量不被默认 deny 误伤。
- shared network 上跨 project ports 按 Neutron SG/RBAC 语义处理。
- unsupported trunk/SR-IOV/direct port 不假 ready。
- `/run/aria` 权限错误时 `neutron-aria-agent` degraded，不 fallback localhost HTTP。
- `aria-datapath` 和 `neutron-aria-agent` 双实例启动被拒绝或 degraded。
- 磁盘满、WAL repair、pinned map schema mismatch 都有明确 degraded/status 输出。
- ACL domain fail-closed，QoS/Mirror/TCPrt domain 局部 degraded，不互相掩盖。

### 13.4 不做本地编译

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

### Phase N0：文档与分支基线

产出：

- `v0.9-neutron-agent` 分支。
- 本详细方案文档。
- README 文档入口。

验收：

- 明确不引入 `aria-controller`。
- 明确第一阶段是 Coexist Mode。
- 明确 ACL/QoS/Mirror/TCPrt 都进入规划。
- 明确 Group、WAL、Netlink、Pinned Maps 是必选支撑能力。
- 明确其它已有能力代码保留但不进入 `neutron-aria-agent` 暴露面。

### Phase N0.5：OpenStack 目标环境兼容性发现

这不是实现阶段，但必须在进入 N3/N4 垂直闭环前完成。N1/N2 可以先用 mock 和本机单元测试推进。

产出：

- 目标 OpenStack 版本。
- 目标环境是 OVS 还是 OVN。
- 当前 Neutron security group backend 和 firewall driver。
- OVS/OVN SG enforcement 的关闭或旁路方式。
- Neutron agent heartbeat 注册方式。
- 需要消费的 Neutron RPC topic、port binding 事件和 full resync API。
- QoS extension 可用性。
- TaaS 或 mirror vendor extension 可用性。
- port tag 或 vendor extension 承载 TCPrt flag 的方式。
- compute host 上 tap/qvo/qvb/veth 命名模式。
- Linux bridge / OVS hybrid plug / OVN native plug 的实际 attach 点。
- trunk port、VLAN subport、SR-IOV、direct、macvtap 是否存在，以及第一阶段如何 degraded 或忽略。
- port security disabled、allowed address pairs、IPv6 ND、DHCP、metadata 在目标环境中的 Neutron 语义。
- 目标内核 BTF、bpffs、qdisc、TC/XDP attach 能力。
- `/run/aria`、`/var/lib/aria-agent`、`/sys/fs/bpf` 的宿主机挂载和权限策略。
- 双容器无编排部署下的单实例锁策略。
- schema/capability 握手和升级回滚最低兼容版本。

验收：

- 写明目标环境中“关闭原 SG enforcement”的最小回滚步骤。
- 写明如果 Aria ACL 未 ready，是否自动回滚 OVS/OVN SG。
- 写明 `neutron-aria-agent` heartbeat 在 Neutron agent list 中的 agent type。
- 写明 DevStack 或目标环境 smoke 的具体配置文件路径。
- 写明不支持 port 类型的处理策略，不能假 ready。
- 写明 DHCP/metadata/IPv6 ND 是否需要显式 allow 规则。
- 写明 `aria-datapath` 所需内核能力和容器 capability。
- 没完成 N0.5 时，不进入 N3 的目标环境验证。

### Phase N1：本机 Neutron Snapshot API

产出：

- `api` crate 新增 snapshot 请求/响应类型。
- `agent` 新增 `/api/v1/neutron/snapshot`。
- `agent` 新增 `/api/v1/neutron/status`。
- `agent` 新增 `/api/v1/neutron/ports/{port_id}` delete。
- `agent` 支持 `/run/aria/aria-agent.sock` Unix socket listener。
- domain status：`groups/acl/qos/mirror/tcprt/runtime`。
- WAL/pinned runtime 复用。

验收：

- 同一个 snapshot 重放多次结果一致。
- 删除 port 后清理 group/ACL/QoS/Mirror/TCPrt。
- 任一 independent domain 失败时不影响其它 domain。
- required domain 失败时有明确错误码。
- snapshot API 不包含 trace/drops/ssl/diagnose/service chain。
- Unix socket 权限能限制只有 `neutron-aria-agent` 访问。

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

### Phase N3：ACL / Security Group

产出：

- security group 展开。
- remote group 本 host 展开。
- group/address-set 编译。
- allowed address pairs。
- anti-spoof。
- DHCP/metadata/ARP/NDP 例外。

验收：

- 默认 deny 正确。
- 多 security group additive 正确。
- remote group 更新影响对应端口。
- port security disabled bypass 正确。
- 原 OVS/OVN SG 不再双重过滤。

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

### Phase N5：Mirror

产出：

- admin-only mirror 输入。
- TaaS 或 vendor extension 适配。
- per-port mirror snapshot。
- mirror stats。

验收：

- target 存在时镜像计数增长。
- target 不存在时 mirror degraded。
- mirror degraded 不影响 ACL/QoS/TCPrt。

### Phase N6：TCPrt

产出：

- port/network TCPrt feature flag。
- per-port `tcprt_enabled`。
- 本地查询和 metrics。

验收：

- 开启后有 TCPrt 流记录。
- 关闭后不再新增该 port 流记录。
- 查询失败不影响其它 domain apply。
- 不写回 Neutron DB。

### Phase N7：DevStack / OpenStack Smoke

产出：

- DevStack 配置样例。
- OpenStack 目标版本配置说明。
- `aria-datapath` 容器镜像说明。
- `neutron-aria-agent` 容器镜像说明。
- 容器运行参数、network mode、host mounts、capabilities 配置。
- `/run/aria/aria-agent.sock` 通信验证。
- e2e smoke 脚本。

验收：

- VM port active。
- Security group 变更实时影响连通性。
- QoS 限速可观察。
- Mirror stats 可观察。
- TCPrt 查询可观察。
- VM migration 后旧 host 清理 port state，新 host apply port-scoped snapshot。
- 旧 host 丢失 unbind event 时，full resync 清理 stale port。
- 新 host 丢失 bind event 时，full resync 补齐 port state。
- 新 host tap 口尚未创建时不挂载 eBPF，Netlink 发现接口后再 attach。
- VM reboot/tap recreate 后 agent degraded -> ready，ACL/QoS/Mirror/TCPrt 按 Neutron desired state 恢复。
- datapath restart 后 resync 成功。
- datapath socket 断开后 `neutron-aria-agent` degraded，socket 恢复后 full resync 成功。
- Neutron server/RabbitMQ 中断后保持 last good，恢复时 full resync。
- OVS/OVN agent 或 ovs-vswitchd 重启后接口对账可恢复。
- port security disabled、allowed address pairs、IPv6 ND、DHCP、metadata 通过目标环境 smoke。
- unsupported trunk/SR-IOV/direct port 不进入 ready。
- `/run/aria` 权限错误时不 fallback TCP。
- 双 `aria-datapath` 或双 `neutron-aria-agent` 实例不会双写。

### Phase N8：生产化硬化

产出：

- error code 文档。
- metrics dashboard。
- runbook。
- upgrade/rollback 说明。
- scale test。

验收：

- 1000 ports / host 下 full resync 时间可接受。
- remote group 更新不会全局重算所有 host。
- `aria-datapath` crash 后 datapath 不瞬断或可解释降级。
- 所有 degraded 状态都有明确排障路径。

## 15. 风险与门槛

| 风险 | 等级 | 约束 |
| --- | --- | --- |
| 与 OVS/OVN security group 双重过滤 | 高 | OpenStack 模式必须关闭或旁路原有 SG enforcement |
| 逐条 API 留下 orphan map entries | 高 | 主路径必须是 full snapshot |
| Neutron remote group 展开成本高 | 中 | 第一阶段只重算本 host 相关 ports |
| 绕过 group/address-set 直接写 ACL | 高 | Group 是必选编译中间层，ACL/QoS/Mirror 共用 |
| WAL 或 pinned maps 缺失导致重启丢状态 | 高 | snapshot apply 必须持久化，并复用 pinned runtime |
| 只依赖 Neutron RPC 忽略接口生命周期 | 高 | Netlink 监听与周期对账必须保留 |
| Mirror 不是 Neutron core 能力 | 中 | admin-only，可选扩展 |
| TCPrt 被误当 policy | 中 | 只做 observe feature flag |
| 其它本地观测能力被误扩成 Neutron 功能 | 中 | 保留代码，但不进入 `neutron-aria-agent` 暴露面 |
| Neutron adapter 与 Rust datapath 状态漂移 | 高 | generation、full resync、status API 必须同时实现 |
| 本机 CLI 写入和 Neutron snapshot 双写 | 高 | Neutron-managed port 的本机配置写操作必须拒绝 |
| 临时排障状态被错误持久化 | 中 | trace/drops flush 等临时操作不进入 WAL，不改变 generation |
| 通信失败被误判为退出 OpenStack mode | 高 | degraded 仍保持 Neutron 权威，本机持久写入继续拒绝 |
| break-glass 本机配置和 Neutron 重新接管冲突 | 高 | rejoin 默认 Neutron wins，local override 必须先归档或丢弃 |
| 多租户对象 key 冲突或串租户 | 高 | 所有 Neutron 对象使用 scoped object key，WAL/refcount/pinned map ID 都按 project 隔离 |
| shared network/shared QoS 被错误拦截 | 中 | 不按 project_id 直接丢包，由 `neutron-aria-agent` 解析 Neutron RBAC 后下发 effective policy |
| 跨租户 mirror 造成越权观测 | 高 | Mirror 默认 admin-only，跨 project target 必须显式 admin policy，否则拒绝或 degraded |
| Aria ACL 未 ready 但原 SG 已关闭 | 高 | 新 port 未 accepted snapshot 前不得 ready；N3 前不得全局关闭 OVS/OVN SG；smoke 必须验证 fail-safe |
| OpenStack 版本差异导致 agent/RPC/SG 关闭方式返工 | 高 | N0.5 先完成目标环境兼容性发现，PR-5 前必须写入配置和回滚路径 |
| Neutron WAL 与 break-glass WAL 混写 | 高 | 使用 `neutron-state.wal` 与 `local-override.wal` 分离，rejoin 前归档 local override |
| VM 迁移后旧 host stale policy 未清理 | 高 | 以 Neutron `binding_host` 为权威，unbind event 或 full resync 都必须触发旧 host delete |
| VM 迁移到新 host 但接口晚于 Neutron event 出现 | 中 | 返回 `PORT_IFACE_NOT_FOUND`，等待 Netlink 对账后自动 port-scoped snapshot |
| 新节点 tap/qvo/veth 未创建就尝试挂载 eBPF | 高 | attach 前必须通过 Netlink preflight；失败返回 `BPF_ATTACH_DEFERRED_IFACE_MISSING`，不得写 accepted state |
| VM 重启导致旧 tap 删除、新 tap 复用同名但 ifindex 改变 | 高 | Netlink DELLINK 标记 degraded，清理旧 ifindex runtime，NEWLINK 后重新 preflight + attach |
| unsupported trunk/SR-IOV/direct port 假 ready | 高 | N0.5 明确支持矩阵；未验证 port 类型必须 degraded 或 ignored |
| DHCP/metadata/IPv6 ND 被默认 deny 误伤 | 高 | translator 必须按目标 Neutron 语义生成必要例外，并在 smoke 中验证 |
| WAL 写失败但内存/eBPF 状态被标记 accepted | 高 | `accepted_generation` 只能在 WAL durable 与 apply 成功后推进 |
| 磁盘满或 state_path 错挂容器临时层 | 高 | snapshot 不 accepted，N7 smoke 验证宿主机持久化挂载 |
| pinned map schema 版本不兼容 | 高 | capability/schema 握手，无法 repair 时 degraded，不复用旧布局 |
| Python/Rust 版本不匹配导致未知字段被静默忽略 | 高 | required field 不认识必须拒绝，可选字段必须进入 ignored status |
| 双 `aria-datapath` 或双 `neutron-aria-agent` 实例双写 | 高 | 本机 lock/identity 防重，检测到双实例退出或 degraded |
| 非关键 domain 失败掩盖 ACL fail-closed | 高 | domain readiness 分离，ACL/group/WAL/Netlink 是硬门槛 |
| 范围滑向完整 L2 替代 | 高 | 第一阶段只做 Coexist Mode |

## 16. 执行级实施计划

本节把前面的架构方案拆成可以直接执行的开发计划。原则是每个提交都能单独解释、单独回看，并且尽量让 GitHub Actions 在较早阶段发现 Rust 编译问题。

### 16.1 当前代码落点

当前 `v0.9.0` 基线是一个 Rust workspace：

| 路径 | 当前职责 | Neutron agent mode 里的改造定位 |
| --- | --- | --- |
| `api/src/lib.rs` | REST 请求/响应 DTO、OpenAPI schema 类型 | 增加 Neutron snapshot/status/delete 的稳定 schema |
| `agent/src/api_routes.rs` | 现有 TCP REST router | 保持现有管理 API；新增独立 Neutron Unix socket router |
| `agent/src/api_handlers/mod.rs` | handler module 与 re-export | 增加 `neutron` handler re-export |
| `agent/src/api_handlers/` | 各功能 REST handler | 新增 `neutron.rs`，只处理 snapshot/status/delete |
| `agent/src/openapi.rs` | OpenAPI paths/components 注册 | 增加 Neutron schema 与路径文档，用于 CI schema 回归 |
| `agent/src/main.rs` | 配置、启动 TCP listener、后台任务 | 新增 `listen_unix_socket` 配置与 Unix socket listener |
| `agent/src/control_plane.rs` | runtime state、apply、WAL、实例管理 | 增加 Neutron apply 入口与 status 聚合 |
| `agent/src/control_plane/` | 分域控制面扩展 | 新增 `neutron_snapshot.rs`，承载 snapshot apply 编排 |
| `core/src/state.rs` | 持久化状态、group/rule/qos/mirror model | 增加 Neutron metadata、generation、port ownership 索引 |
| `core/src/wal.rs` | WAL entry、replay、compact | 增加 Neutron snapshot/delete/status WAL entry |
| `agent/src/tap_registry.rs` | Netlink 发现 tap，attach/detach runtime | 复用，不在 N1 重写；N2/N3 通过 status 对账 |
| `config/aria-agent.toml` | `aria-agent` 默认配置 | 增加 Unix socket 示例配置 |
| `.github/workflows/build.yml` | GitHub Actions 编译和产物 | 后续增加 Python agent 检查和容器镜像构建 |
| `README.md` | 项目入口文档 | 保持链接到本方案 |

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
│   └── extensions/
│       ├── __init__.py
│       ├── mirror.py
│       └── tcprt.py
└── tests/
    ├── test_event_merge.py
    ├── test_generation.py
    ├── test_local_client.py
    ├── test_status.py
    ├── test_translator_acl.py
    ├── test_translator_mirror.py
    ├── test_translator_qos.py
    └── test_translator_tcprt.py
```

### 16.2 不可变实现边界

这些边界必须在代码 review 时逐项检查：

- Neutron snapshot 路由不能挂到现有 TCP REST router 上。
- Neutron snapshot 路由只由 Unix socket listener 暴露。
- 不新增本机 TCP 端口或临时网络入口。
- `neutron-aria-agent` 不写 eBPF map，不挂载 `/sys/fs/bpf`。
- `aria-datapath` 不访问 Neutron DB，不消费 Neutron RPC。
- `trace`、`drops`、`ssl`、`diagnose`、`service chain` 不进入 `neutron-aria-agent` 配置、事件、snapshot schema 或 status domain。
- Group、WAL、Netlink、Pinned Maps 不能做成可选能力。
- ACL 是 required domain；QoS、Mirror、TCPrt 是 independent domain。
- 所有 port 删除、迁移和 unbind 都必须最终清理 orphan map entry。

### 16.3 推荐提交拆分

#### Commit N1-A：Neutron schema 与 OpenAPI 契约

修改文件：

- `api/src/lib.rs`
- `agent/src/openapi.rs`

新增类型：

- `NeutronSnapshotRequest`
- `NeutronTenantModel`
- `NeutronPortEntry`
- `NeutronGroupEntry`
- `NeutronAclPolicyEntry`
- `NeutronQosPolicyEntry`
- `NeutronMirrorPolicyEntry`
- `NeutronFeatureFlags`
- `NeutronSnapshotResponse`
- `NeutronDomainStatus`
- `NeutronStatusResponse`
- `NeutronPortDeleteResponse`

类型约束：

- `schema_version` 第一版固定为 `"1"`。
- `mode` 第一版只接受 `"coexist"`。
- `local_generation` 必填，不能由 `aria-datapath` 自动生成。
- `host` 必填，必须和 `aria-datapath` 本机配置匹配。
- `tenant_model.scope_key` 第一版固定为 `"source/project_id/domain/object_id"`。
- `ports[].port_id`、`ports[].project_id`、`ports[].if_name`、`ports[].mac_address` 必填。
- `groups[].project_id`、`acl_policies[].project_id`、`qos_policies[].project_id`、`mirror_policies[].project_id` 必填。
- feature flags 只允许 `acl/qos/mirror/tcprt` 四个暴露项。

测试：

- 扩展 `agent/src/openapi.rs` 里的 `openapi_contains_core_paths_and_components`。
- 新增断言：Neutron schema 都出现在 `/components/schemas`。
- 新增断言：`/api/v1/neutron/snapshot` 不出现在现有 TCP router 的普通路径暴露检查里，避免误把它当成管理 API。

验收：

- GitHub Actions 能编译 `aria-api` 和 `aria-agent`。
- OpenAPI schema 名称稳定，后续 Python agent 可以按 schema 生成请求。

#### Commit N1-B：Unix socket listener 与 Neutron-only router

修改文件：

- `agent/src/main.rs`
- `agent/src/api_routes.rs`
- `config/aria-agent.toml`

实现要求：

- 在 `Config` 增加 `listen_unix_socket: Option<String>`。
- 默认配置可以为空；OpenStack 示例配置使用 `/run/aria/aria-agent.sock`。
- 启动时如果配置了 socket：
  - 创建父目录 `/run/aria`。
  - 删除同路径陈旧 socket 文件。
  - bind `tokio::net::UnixListener`。
  - `chmod` socket 为 `0660`。
  - 启动 `axum::serve(unix_listener, neutron_router)`。
- `api_routes.rs` 新增 `build_neutron_router(control_plane)`，只注册：
  - `PUT /api/v1/neutron/snapshot`
  - `GET /api/v1/neutron/status`
  - `DELETE /api/v1/neutron/ports/{port_id}`
- 现有 `build_router(control_plane)` 不注册 Neutron snapshot 路由。

验收：

- Neutron snapshot API 不依赖 `listen_addr`。
- 现有 TCP REST API 继续给 `ariactl` 和本机管理员使用。
- OpenStack 模式只要求挂载 `/run/aria`，不要求 `neutron-aria-agent` 使用 host network。

#### Commit N1-C：Rust snapshot apply 编排骨架

新增文件：

- `agent/src/api_handlers/neutron.rs`
- `agent/src/control_plane/neutron_snapshot.rs`

修改文件：

- `agent/src/api_handlers/mod.rs`
- `agent/src/control_plane.rs`
- `core/src/state.rs`
- `core/src/wal.rs`

实现要求：

- handler 只做 JSON 解析、调用 control plane、返回 domain status。
- `control_plane/neutron_snapshot.rs` 负责 apply 顺序：
  1. 校验 `schema_version/host/mode/local_generation`。
  2. 对 snapshot 中的 ports 做接口存在性检查。
  3. 编译 group/address-set。
  4. 清理被覆盖 ports 的旧 ACL/QoS/Mirror/TCPrt。
  5. apply groups。
  6. apply ACL。
  7. apply QoS。
  8. apply Mirror。
  9. apply TCPrt feature flags。
  10. 写入 WAL intent/commit 或等价 durable record。
  11. 更新 generation/status。
- 第一版可以复用现有 `add_group/add_policy/add_qos/add_mirror/update_config` 原子操作，但必须在同一个 snapshot apply 中收集 domain status。
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
- `core/src/wal.rs` 增加 WAL entry：
  - `NeutronSnapshotApplied`
  - `NeutronPortDeleted`
  - `NeutronStatusUpdated`
- WAL entry 必须区分来源：
  - `source = "neutron"` 用于 snapshot apply。
  - `project_id` 和 scoped object key 用于多租户归属、replay 和 compact。
  - 本机临时排障操作不写 WAL。
  - 本机持久写操作不得写入 Neutron-managed state。
- `accepted_generation` 只能在 snapshot 校验、WAL durable 和 required datapath apply 都成功后推进；如果 WAL 或 required apply 任一失败，status 必须 degraded。

验收：

- 同一个 snapshot 重放两次，第二次不新增重复 group/rule/qos/mirror。
- 删除 port 后该 port 相关状态为空，仍被其它 port 引用的 group 不删除。
- 删除 project A 的 port 不会释放 project B 的同名 security group/address-set。
- 同一个 snapshot 中多个 project 的 scoped object key 不冲突。
- QoS/Mirror/TCPrt 失败不会让 ACL 成功路径失效。
- WAL 写入失败进入 runtime domain status，不能被吞掉。

#### Commit N1-C2：本机写入 gate 与 WAL 隔离

修改文件：

- `agent/src/api_handlers/groups.rs`
- `agent/src/api_handlers/policies.rs`
- `agent/src/api_handlers/qos.rs`
- `agent/src/api_handlers/mirror.rs`
- `agent/src/api_handlers/config.rs`
- `agent/src/control_plane.rs`
- `core/src/state.rs`

实现要求：

- 对 Neutron-managed instance 或 Neutron-managed port，拒绝本机配置写入。
- `openstack_degraded` 仍视为 Neutron-managed，继续拒绝本机配置写入。
- 拒绝范围包括 group、policy、qos、mirror、ACL/QoS/Mirror/TCPrt config toggle。
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
- 拒绝错误码统一为 `LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_PORT`。
- 错误必须提示通过 Neutron 修改配置。

验收：

- `ariactl trace start` 在 Neutron-managed tap 上可用。
- `ariactl policy add` 在 Neutron-managed tap 上被拒绝。
- `ariactl qos add` 在 Neutron-managed tap 上被拒绝。
- `ariactl mirror add` 在 Neutron-managed tap 上被拒绝。
- `ariactl config set tcprt off` 在 Neutron-managed tap 上被拒绝。
- 上述被拒绝操作不写 WAL。
- trace start/stop/flush 不写 WAL，datapath 重启后 trace filter 不恢复。
- Neutron 通信失败时，本机 policy 写入仍被拒绝。
- break-glass 后本机 policy 写入可持久化到 local override WAL。
- Neutron 恢复后，存在 local override 时不自动接管，进入 `rejoin_pending`。
- 执行 discard local overrides 后，full snapshot 覆盖本机托管 domains。

#### Commit N1-D：Status 与 drift 检测

修改文件：

- `api/src/lib.rs`
- `agent/src/api_handlers/neutron.rs`
- `agent/src/control_plane/neutron_snapshot.rs`
- `agent/src/control_plane.rs`

实现要求：

- `GET /api/v1/neutron/status` 返回：
  - `schema_version`
  - `host`
  - `mode`
  - `accepted_generation`
  - `applied_generation`
  - `last_good_generation`
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
  - `skipped`
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
  - `local_api = unix:///run/aria/aria-agent.sock`
  - `enable_acl`
  - `enable_qos`
  - `enable_mirror`
  - `enable_tcprt`
  - `mirror_source`
  - `tcprt_source`
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
- 提供三个方法：
  - `put_snapshot(snapshot)`
  - `get_status()`
  - `delete_port(port_id)`
- 连接失败返回 typed error，供 `status.py` 转成 agent degraded。

验收：

- 单元测试证明非 Unix 地址会被拒绝。
- socket 不存在时不崩溃，返回可上报错误。

#### Commit N2-C：Neutron 投影状态与 translator

新增文件：

- `neutron-aria-agent/neutron_aria_agent/state.py`
- `neutron-aria-agent/neutron_aria_agent/translator.py`
- `neutron-aria-agent/tests/test_translator_acl.py`
- `neutron-aria-agent/tests/test_translator_qos.py`
- `neutron-aria-agent/tests/test_translator_mirror.py`
- `neutron-aria-agent/tests/test_translator_tcprt.py`

实现要求：

- `state.py` 保存可重建投影：
  - ports by port_id，并保留 port owner project_id
  - security groups by `(project_id, sg_id)`
  - qos policies by `(owner_project_id, policy_id)`
  - mirror policies by `(owner_project_id, policy_id)`
  - tcprt flags by project_id/network_id/port_id
  - shared network / shared QoS / admin mirror binding
- `translator.py` 输出和 `api/src/lib.rs` 对齐的 snapshot dict。
- ACL：
  - 默认 deny。
  - SG rule 只生成 allow。
  - remote group 展开成本地 address-set，默认只展开同 project 成员。
  - 跨 project remote group 只有 Neutron 输入明确授权时才生成。
  - allowed address pairs 进入 anti-spoof 例外。
- QoS：
  - port-level 覆盖 network-level。
  - shared QoS policy 解析成 per-port effective QoS。
  - 第一版支持 bandwidth limit。
  - minimum bandwidth 和 DSCP 进入 unsupported/degraded status，不静默忽略。
- Mirror：
  - 默认 admin-only。
  - host-local source 必须显式开启。
  - 跨 project target 默认拒绝，除非 admin policy 显式允许。
- TCPrt：
  - project/network/port 输入解析成 per-port feature flag。
  - 不写 Neutron DB。

验收：

- 每个 translator 测试都给出输入对象和完整 snapshot 断言。
- 两个 project 有同名 security group 时 snapshot scoped key 不冲突。
- shared network 中 port owner 与 network owner 不同时 ACL 仍按 port owner project 编译。
- shared QoS policy 只影响 Neutron 绑定的 ports，不按 project 全局扩散。
- tenant mirror 输入不会生成 snapshot；admin cross-project mirror 必须显式带 admin policy。
- project 默认 TCPrt 被 port override 覆盖。
- 不出现 trace/drops/ssl/diagnose/service chain 字段。

#### Commit N2-D：Agent 主循环与 heartbeat

新增文件：

- `neutron-aria-agent/neutron_aria_agent/agent.py`
- `neutron-aria-agent/neutron_aria_agent/event_loop.py`
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
  - port update 按 port_id 合并。
  - SG update 找出本 host 相关 ports。
  - QoS update 找出绑定 policy 的 ports。
  - Mirror/TCPrt update 只重算相关 ports。
- status：
  - datapath socket 不可达时 Neutron agent degraded。
  - `runtime.blocked` 时 agent degraded 并触发 full resync。
  - `acl.blocked` 时 agent degraded。
  - `qos/mirror/tcprt.degraded` 不影响 alive，但必须上报原因。

验收：

- socket 断开后进入 degraded。
- socket 恢复后 full resync。
- burst event 合并窗口内只提交一次 snapshot。

#### Commit N3：ACL / Security Group 垂直闭环

修改重点：

- Rust snapshot apply 的 groups + ACL required domain。
- Python translator 的 SG/remote group/allowed address pairs。
- DevStack smoke 中关闭或旁路原 OVS/OVN SG enforcement。

验收：

- VM 默认 deny。
- 同 security group 内互通按 Neutron 规则生效。
- remote group 更新能影响本 host 已绑定 port。
- 两个 project 的同名 security group 不互相展开 remote group。
- shared network 场景不因为 project_id 不同被 Aria 额外丢包。
- 原 OVS/OVN SG 不形成双重过滤。

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

#### Commit N5：Mirror 垂直闭环

修改重点：

- admin-only mirror input。
- host-local target 校验。
- Mirror domain status。
- mirror stats smoke。

验收：

- target interface 存在时 stats 增长。
- target interface 缺失时只有 mirror domain degraded。
- tenant 不能自服务创建 mirror。
- 跨 project mirror 没有 admin policy 时被拒绝或 degraded。

#### Commit N6：TCPrt 垂直闭环

修改重点：

- port/network feature flag。
- Rust runtime config 中 per-port TCPrt 开关。
- 本机查询和 metrics。

验收：

- 开启 port 有 TCPrt 流记录。
- 关闭 port 不再新增记录。
- project/network/port 优先级解析成 per-port flag。
- 查询失败不影响 ACL/QoS/Mirror apply。

#### Commit N7：容器与部署脚本

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
- `deploy/openstack/smoke.sh` 覆盖 agent alive、snapshot 下发、SG/QoS/Mirror/TCPrt 基础链路。

### 16.4 GitHub Actions 细化

CI 工作包必须把 `.github/workflows/build.yml` 拆成三个可见阶段：

1. Rust build：
   - 继续构建 eBPF、`ariactl`、`aria-agent`。
   - 继续上传 `firewall-binaries-x86_64` artifact。
2. Python agent test：
   - 安装 `neutron-aria-agent` 的 test dependencies。
   - 运行 Python 单元测试。
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
| N1 -> N2 | Unix socket snapshot/status/delete API 合入，本机写入 gate 生效，Neutron 路由不在 TCP router 暴露，GitHub Actions Rust build 通过 |
| N2 -> N3 | Python agent 能 full resync、下发 full snapshot、heartbeat degraded/ready 状态正确，多 project translator 测试通过，N0.5 目标环境兼容性发现完成 |
| N3 -> N4 | ACL/Security Group 垂直闭环通过，OVS/OVN SG 双重过滤问题有目标环境验证，同名 SG 跨 project 不串 |
| N4 -> N5 | QoS bandwidth limit 可观察，shared QoS 绑定语义正确，QoS domain 失败不影响 ACL |
| N5 -> N6 | Mirror admin-only、cross-project gate、target missing degraded、stats smoke 通过 |
| N6 -> N7 | TCPrt project/network/port 优先级、开关和查询闭环通过，不写回 Neutron DB |
| N7 -> N8 | 两容器部署 smoke 通过，socket 权限、capabilities、host mounts 验证完成 |

### 16.6 落地执行计划

开发从 N1 开始，不先写 Python agent 的完整业务逻辑。原因是 Python 侧必须依赖 Rust 侧稳定的 snapshot schema、Unix socket API、status 语义和本机写入 gate。

推荐按 8 个小 PR 或 8 个连续 commit 落地：

| 顺序 | 名称 | 目标 | 是否依赖前置 | 是否需要 OpenStack 环境 |
| --- | --- | --- | --- | --- |
| PR-0 | 文档基线 | 提交本方案、README 链接和分支基线 | 无 | 否 |
| PR-1 | N1-A/N1-B | Rust schema、OpenAPI、Unix socket router | PR-0 | 否 |
| PR-2 | N1-C/N1-C2/N1-D | Snapshot apply 骨架、写入 gate、status | PR-1 | 否 |
| PR-3 | N2-A/N2-B | Python package 骨架、UDS client | PR-1 | 否 |
| PR-4 | N2-C/N2-D | Neutron 投影、translator、event loop、heartbeat | PR-2/PR-3 | 可用 mock |
| PR-5 | N3/N4 | ACL 和 QoS 垂直闭环 | PR-4 | 是 |
| PR-6 | N5/N6 | Mirror 和 TCPrt 垂直闭环 | PR-4 | 是 |
| PR-7 | N7/N8 | 容器、部署脚本、smoke、生产化硬化 | PR-5/PR-6 | 是 |

并行规则：

- PR-1 必须先做，作为 Rust/Python 共同契约。
- PR-2 和 PR-3 可以并行，但 PR-4 不能早于 PR-2。
- N3 ACL 必须早于 N4/N5/N6 的生产 smoke，因为 ACL 是 required domain。
- Dockerfile 可以在 PR-3 后开始，但部署 smoke 必须等 PR-5/PR-6 至少有基础闭环。
- OpenStack 环境验证不阻塞 PR-1 到 PR-4，但会阻塞进入 PR-5 之后的阶段门槛。
- PR-5 开始前必须完成 N0.5 目标环境兼容性发现。
- N3/N4 smoke 前不得在目标环境全局关闭 OVS/OVN SG enforcement；只能在可回滚 smoke 窗口验证关闭或旁路方式。

每个 PR 的共同要求：

- 提交信息使用 `feat:`、`test:`、`docs:` 或 `ci:` 前缀。
- 不在本地运行 `cargo build`、`cargo check`、`cargo test`。
- Rust 编译验证只看 GitHub Actions。
- 文档或 Python-only 阶段可以本地运行 `git diff --check` 和 Python 单元测试。
- 每个 PR 合入前必须确认没有把 Neutron snapshot route 暴露到现有 TCP router。

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

验收：

- README 能跳转到 OpenStack Neutron Agent Mode 方案。
- 方案明确 `neutron-aria-agent`、`aria-datapath`、Unix socket、容器化、多租户、authority state 和 N1-N8 阶段门槛。
- 不触碰 Rust/Python 实现代码。

#### Work Package 1：Rust API 契约

目标：先让 `api` crate 拥有稳定的 Neutron snapshot/status/delete DTO。

修改范围：

- `api/src/lib.rs`
- `agent/src/openapi.rs`

新增或修改内容：

- `NeutronSnapshotRequest`
- `NeutronTenantModel`
- `NeutronPortEntry`
- `NeutronGroupEntry`
- `NeutronAclPolicyEntry`
- `NeutronQosPolicyEntry`
- `NeutronMirrorPolicyEntry`
- `NeutronFeatureFlags`
- `NeutronSnapshotResponse`
- `NeutronDomainStatus`
- `NeutronStatusResponse`
- `NeutronPortDeleteResponse`

测试要求：

- OpenAPI components 包含所有 Neutron DTO。
- OpenAPI paths 不包含 `/api/v1/neutron/snapshot`，因为该 API 不属于现有 TCP router。
- DTO serde 测试覆盖：
  - 多 project snapshot。
  - shared network 的 `network_project_id`。
  - `tenant_model.scope_key = "source/project_id/domain/object_id"`。
  - ACL/QoS/Mirror/TCPrt 四个 domain 的最小合法输入。

验收：

- Python agent 可以按这些 DTO 手写或生成 snapshot dict。
- `project_id` 必填约束写入类型或显式校验。
- feature flags 只暴露 `acl/qos/mirror/tcprt`。

#### Work Package 2：Unix Socket Neutron Router

目标：新增只监听 Unix socket 的 Neutron-only API 入口，保持 TCP router 不变。

修改范围：

- `agent/src/main.rs`
- `agent/src/api_routes.rs`
- `agent/src/api_handlers/mod.rs`
- `agent/src/api_handlers/neutron.rs`
- `config/aria-agent.toml`

实现要求：

- `Config` 增加 `listen_unix_socket: Option<String>`。
- `build_neutron_router(control_plane)` 只注册：
  - `PUT /api/v1/neutron/snapshot`
  - `GET /api/v1/neutron/status`
  - `DELETE /api/v1/neutron/ports/{port_id}`
- 现有 `build_router(control_plane)` 不注册任何 Neutron snapshot 路由。
- OpenStack 示例配置使用 `/run/aria/aria-agent.sock`。
- socket 文件权限固定为 `0660`，父目录由容器 entrypoint 或进程启动时确保存在。

测试要求：

- router 单元测试确认 TCP router 不包含 Neutron snapshot route。
- Unix router 单元测试确认只包含 snapshot/status/delete 三个 route。

验收：

- `neutron-aria-agent` 只需要挂载 `/run/aria`。
- 不新增 localhost HTTP 过渡入口。
- 不要求 `neutron-aria-agent` 使用 host network。

#### Work Package 3：Snapshot Apply 骨架

目标：让 Rust 侧能接受 snapshot、生成 domain status，并以幂等方式更新本机托管状态。

修改范围：

- `agent/src/control_plane/neutron_snapshot.rs`
- `agent/src/control_plane.rs`
- `core/src/state.rs`
- `core/src/wal.rs`

实现要求：

- 新增 `authority_state`、`authority_epoch`、`local_override_present`。
- 新增 `neutron_projects`、`neutron_scoped_objects`、`neutron_project_domain_status`、`neutron_scoped_refcounts`。
- `NeutronSnapshotApplied` WAL entry 带 `source = "neutron"`、`project_id`、domain 和 scoped object key。
- apply 顺序固定为 schema/authority -> attach preflight -> WAL intent -> groups -> ACL -> QoS -> Mirror -> TCPrt -> WAL commit -> status。
- 同 generation 重放幂等。
- independent domain 失败不影响 ACL required domain 的成功路径。

测试要求：

- 同一个 snapshot 重放两次，不产生重复 group/rule/qos/mirror。
- 删除 project A port 不释放 project B 的同名 group/address-set。
- tap/qvo/veth 不存在时不执行 eBPF attach，不写 accepted datapath state。
- ifindex 不匹配时返回 `PORT_IFINDEX_NOT_READY` 或 degraded status。
- VM reboot/tap recreate 后旧 ifindex cleanup 幂等，新 ifindex ready 后重新 attach。
- WAL append 失败能进入 runtime domain status。
- QoS/Mirror/TCPrt 失败时 ACL status 仍可 ready。

验收：

- `GET /api/v1/neutron/status` 能返回 `accepted_generation`、`applied_generation`、`last_good_generation` 和 per-domain status。
- `DELETE /api/v1/neutron/ports/{port_id}` 能清理该 port 的托管状态，并等待下一次 full snapshot 最终校准。

#### Work Package 4：本机写入 Gate

目标：OpenStack managed/degraded 状态下，拒绝本机持久配置写入，同时保留只读和临时排障。

修改范围：

- `agent/src/api_handlers/groups.rs`
- `agent/src/api_handlers/policies.rs`
- `agent/src/api_handlers/qos.rs`
- `agent/src/api_handlers/mirror.rs`
- `agent/src/api_handlers/config.rs`
- `agent/src/control_plane.rs`
- `core/src/state.rs`
- `core/src/wal.rs`

拒绝范围：

- group add/delete。
- policy add/delete。
- qos add/delete。
- mirror add/delete。
- ACL/QoS/Mirror/TCPrt config toggle。

允许范围：

- health、status、stats、metrics。
- diagnose。
- trace start/stop/list/flush。
- drops list/flush。
- tcprt query/list。

验收：

- `openstack_managed` 和 `openstack_degraded` 下本机持久写入返回 `LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_PORT`。
- trace 不写 WAL，不更新 Neutron generation。
- break-glass 写入 local override WAL。
- Neutron 恢复后存在 local override 时进入 `rejoin_pending`。

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

验收：

- 不需要 OpenStack 环境即可测试。
- socket 不存在时返回 typed error，供 heartbeat 上报 degraded。

#### Work Package 6：Neutron 投影与 Translator

目标：把 Neutron 对象投影成 Aria snapshot，不直接写 datapath。

新增范围：

- `neutron-aria-agent/neutron_aria_agent/state.py`
- `neutron-aria-agent/neutron_aria_agent/translator.py`
- `neutron-aria-agent/tests/test_translator_acl.py`
- `neutron-aria-agent/tests/test_translator_qos.py`
- `neutron-aria-agent/tests/test_translator_mirror.py`
- `neutron-aria-agent/tests/test_translator_tcprt.py`

实现要求：

- ports by port_id，并保留 owner project。
- security groups by `(project_id, sg_id)`。
- QoS policies by `(owner_project_id, policy_id)`。
- Mirror policies by `(owner_project_id, policy_id)`。
- TCPrt flags by project/network/port。
- shared network、shared QoS、admin mirror binding 在 Python 侧解析成 per-port effective policy。

验收：

- 两个 project 有同名 SG 时 scoped key 不冲突。
- shared network 不因为 port owner 和 network owner 不同而被额外丢包。
- port migration 后 `binding_host` 变化能把 port 从旧 projected state 移到新 projected state。
- shared QoS 只作用于绑定 port。
- tenant mirror 不生成 snapshot；admin cross-project mirror 必须显式授权。
- project/network/port TCPrt 优先级正确。
- snapshot 不包含 trace/drops/ssl/diagnose/service chain。

#### Work Package 7：主循环、Heartbeat 与事件合并

目标：让 `neutron-aria-agent` 能 full resync、提交 snapshot、处理事件合并并上报状态。

新增范围：

- `neutron-aria-agent/neutron_aria_agent/agent.py`
- `neutron-aria-agent/neutron_aria_agent/event_loop.py`
- `neutron-aria-agent/neutron_aria_agent/neutron_client.py`
- `neutron-aria-agent/neutron_aria_agent/status.py`
- `neutron-aria-agent/tests/test_event_merge.py`
- `neutron-aria-agent/tests/test_status.py`

实现要求：

- 启动后先检查 Unix socket status。
- socket 不可达时 agent degraded，不本地接管。
- full resync 后提交 full snapshot。
- port update 按 port_id 合并。
- port migration/rebind event 按 `source_revision` 去重，保留最新 `binding_host`。
- 本 host 失去 port binding 时调用本地 delete。
- 本 host 获得 port binding 时等待接口出现并下发 port-scoped snapshot。
- SG/QoS/Mirror/TCPrt update 只重算相关 ports。
- burst window 内只提交一次 snapshot。

验收：

- socket 断开进入 degraded。
- socket 恢复后 full resync。
- 旧 host 丢失 unbind event 时，full resync 清理 stale port。
- 新 host 丢失 bind event 时，full resync 补齐 port state。
- ACL blocked 让 agent degraded。
- QoS/Mirror/TCPrt degraded 不影响 alive，但必须上报原因。

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

验收：

- smoke 覆盖 agent alive、snapshot 下发、SG/QoS/Mirror/TCPrt 基础链路。
- socket 权限、capabilities、host mounts 被显式验证。
- 删除容器不丢失 WAL/state。

### 16.8 开发启动检查清单

正式开始写代码前，先确认：

- 当前分支是 `v0.9-neutron-agent`。
- 工作目录是 `/Users/chen/code/aria-firewall-v0.9-neutron-agent`。
- remote 指向 `git@github.com:chenyongming211-glitch/aria-firewall.git`。
- Git identity 使用 `netmouser <chenyongming211@gmail.com>`。
- 本地不运行 `cargo build`、`cargo check`、`cargo test`。
- 代码提交后由 GitHub Actions 编译。
- PR-1 前不需要 OpenStack 环境。
- N3 之前必须确定目标 OpenStack 版本和 OVS/OVN SG 关闭或旁路方式。

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
- OVS/OVN SG enforcement 的关闭或旁路方式必须来自 N0.5，不用猜测实现。
- 如果 Aria ACL 未 ready，agent 必须 degraded，不能把 host 标成生产可用。

功能默认：

- ACL 是 required domain。
- QoS、Mirror、TCPrt 是 independent domain。
- Group、WAL、Netlink、Pinned Maps 是必选支撑能力。
- trace、drops、ssl、diagnose、service chain 代码保留，但不进入 `neutron-aria-agent` 暴露面。
- Mirror 默认 admin-only。
- TCPrt 只做 observe feature flag，不写回 Neutron DB。

WAL 默认：

- Neutron 托管写入使用 `neutron-state.wal`。
- break-glass 本机覆盖写入使用 `local-override.wal`。
- standalone/local legacy 模式继续使用 `state.wal`。
- 重新接管前先归档 `local-override.wal`，再执行 Neutron full snapshot。

### 16.10 八个执行章节细化

下面 8 个执行章节对应 Work Package 1 到 Work Package 8。Work Package 0 只负责提交方案基线，不再展开。

#### 执行章节 1：Rust API 契约

目标：让 Rust/Python 双方先共享稳定 snapshot/status/delete schema。

文件范围：

- `api/src/lib.rs`
- `agent/src/openapi.rs`

默认实现顺序：

1. 在 `api/src/lib.rs` 增加 Neutron DTO，全部派生 `Debug`、`Clone`、`Serialize`、`Deserialize`、`ToSchema`。
2. 对 request/response 增加 `#[schema(example = json!(...))]`，示例必须包含多 project、shared network、ACL/QoS/Mirror/TCPrt。
3. 增加 `NeutronTenantModel`，默认字段：
   - `scope_key`
   - `shared_object_policy`
4. 增加 `NeutronSnapshotRequest`，默认字段：
   - `schema_version`
   - `local_generation`
   - `host`
   - `mode`
   - `full`
   - `tenant_model`
   - `ports`
   - `groups`
   - `acl_policies`
   - `qos_policies`
   - `mirror_policies`
   - `feature_flags`
5. 增加 `NeutronSnapshotResponse` 和 `NeutronStatusResponse`，status 必须表达：
   - `accepted_generation`
   - `applied_generation`
   - `last_good_generation`
   - `authority_state`
   - `domains`
   - `wal`
   - `pinned_runtime`
   - `netlink`
6. 在 `agent/src/openapi.rs` 注册 Neutron DTO components。
7. 在 OpenAPI 测试中断言 components 存在。
8. 在 OpenAPI 测试中断言 TCP OpenAPI paths 不包含 `/api/v1/neutron/snapshot`。
9. 增加 serde roundtrip 测试，覆盖多 project snapshot。
10. 提交：`feat: add neutron snapshot api schema`。

必须覆盖的测试断言：

- `NeutronSnapshotRequest` 能反序列化最小合法 snapshot。
- `tenant_model.scope_key` 等于 `source/project_id/domain/object_id`。
- port 必须带 `project_id`。
- group/ACL/QoS/Mirror 必须带 `project_id`。
- feature flags 只有 `acl`、`qos`、`mirror`、`tcprt`。
- OpenAPI components 有 Neutron DTO。
- OpenAPI paths 没有 Neutron snapshot route。

停止条件：

- 如果 API DTO 需要引用 agent 或 core 类型，停止并改回纯 DTO，不让 `api` crate 依赖运行时状态。

#### 执行章节 2：Unix Socket Neutron Router

目标：给 `neutron-aria-agent` 提供本机 Unix socket API，保持现有 TCP API 不变。

文件范围：

- `agent/src/main.rs`
- `agent/src/api_routes.rs`
- `agent/src/api_handlers/mod.rs`
- `agent/src/api_handlers/neutron.rs`
- `config/aria-agent.toml`

默认实现顺序：

1. 在 `Config` 增加 `listen_unix_socket: Option<String>`。
2. 保持 `listen_addr` 的现有行为，TCP router 继续服务本机管理员 API。
3. 在 `api_routes.rs` 增加 `build_neutron_router(control_plane)`。
4. `build_neutron_router` 只注册：
   - `PUT /api/v1/neutron/snapshot`
   - `GET /api/v1/neutron/status`
   - `DELETE /api/v1/neutron/ports/{port_id}`
5. 在 `api_handlers/neutron.rs` 增加 handler skeleton。
6. handler skeleton 调用 control plane 的 Neutron 方法；如果方法尚未实现，返回稳定的 typed error 或 empty status，不返回 panic。
7. 在 `main.rs` 中，当 `listen_unix_socket` 存在时启动 Unix listener。
8. 启动时创建父目录，移除同路径陈旧 socket 文件。
9. bind 后设置 socket 权限为 `0660`。
10. 在 `config/aria-agent.toml` 增加注释化 OpenStack 示例。
11. 增加 router 测试，证明 TCP router 没有 Neutron route。
12. 增加 router 测试，证明 Unix router 只有 Neutron route。
13. 提交：`feat: add neutron unix socket router`。

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

- `agent/src/control_plane/neutron_snapshot.rs`
- `agent/src/control_plane.rs`
- `core/src/state.rs`
- `core/src/wal.rs`

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
7. 在任何 eBPF attach 或 map 写入前执行 attach preflight。
8. attach preflight 校验 `binding_host`、`if_name`、`ifindex` 和 Netlink 查询结果。
9. preflight 失败的 port 只更新 degraded status，不进入 apply，也不写 accepted datapath state。
10. apply 顺序固定为 schema/authority -> preflight -> WAL intent -> groups -> ACL -> QoS -> Mirror -> TCPrt -> WAL commit -> status。
11. 重放同 generation 时返回当前 status，不重复写业务对象。
12. `DELETE /ports/{port_id}` 清理 port 关联对象和 scoped refcount。
13. `GET /status` 返回 authority、generation、domain、WAL、pinned、netlink 摘要。
14. 增加纯 state 单元测试覆盖 scoped key/refcount。
15. 提交：`feat: add neutron snapshot apply skeleton`。

默认 apply 语义：

- full snapshot 覆盖 Neutron-managed domains。
- port-scoped snapshot 只覆盖相关 port 的 Neutron-managed domains。
- unknown project 或 unknown scoped object 不 panic，返回 domain degraded。
- tap/qvo/veth 未创建时返回 `BPF_ATTACH_DEFERRED_IFACE_MISSING`，等待 Netlink 对账。
- ACL 失败时该 port required path blocked。
- QoS/Mirror/TCPrt 失败时只标记对应 independent domain。

停止条件：

- 如果实现要求重构 eBPF map 格式才能通过 skeleton 测试，先保持 skeleton 和 status，不在本工作包做 datapath 热路径重构。

#### 执行章节 4：本机写入 Gate

目标：防止 OpenStack 托管状态和本机 CLI/API 双写。

文件范围：

- `agent/src/api_handlers/groups.rs`
- `agent/src/api_handlers/policies.rs`
- `agent/src/api_handlers/qos.rs`
- `agent/src/api_handlers/mirror.rs`
- `agent/src/api_handlers/config.rs`
- `agent/src/control_plane.rs`
- `core/src/state.rs`
- `core/src/wal.rs`

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
   - `add_mirror`
   - `delete_mirror`
   - `update_config`
4. `openstack_managed` 和 `openstack_degraded` 下返回 `LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_PORT`。
5. 错误 HTTP 状态使用 `409 Conflict`。
6. trace、drops、stats、health、metrics、tcprt query 不加持久写 gate。
7. break-glass 状态允许本机持久写入，但 WAL source 必须是 local override。
8. Neutron 通信恢复且存在 local override 时进入 `rejoin_pending`。
9. `rejoin_pending` 拒绝新的本机持久写入。
10. 增加单元测试或 handler 测试覆盖每个拒绝面。
11. 提交：`feat: block local writes for neutron managed state`。

默认错误文案：

```text
LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_PORT: this port is managed by Neutron; update policy through Neutron
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
   - `local_api`
   - `enable_acl`
   - `enable_qos`
   - `enable_mirror`
   - `enable_tcprt`
   - `mirror_source`
   - `tcprt_source`
6. `models.py` 用 dataclass 表达 snapshot/status 基本模型。
7. `generation.py` 实现 `{host}-{counter:012d}`。
8. generation counter 持久化到 Python agent 本地 state file。
9. `local_client.py` 只接受 `unix://` 或 `unix:///` 形式。
10. `local_client.py` 拒绝 `http://`、`https://`、裸 host:port 和空地址。
11. socket 不存在时返回 typed error，不抛未分类异常。
12. 增加 Python 单元测试。
13. 提交：`feat: add neutron aria agent python skeleton`。

本地验证：

```bash
cd neutron-aria-agent
python -m pytest -q
```

停止条件：

- 如果需要真实 `neutron`、`oslo.messaging` 或 OpenStack 配置才能跑单元测试，说明模块边界错了；把真实 OpenStack 依赖隔离到后续 `neutron_client.py`。

#### 执行章节 6：Neutron 投影与 Translator

目标：把 Neutron 对象转换成 Aria snapshot dict，并把多租户、shared network、shared QoS、admin mirror 规则固定下来。

文件范围：

- `neutron-aria-agent/neutron_aria_agent/state.py`
- `neutron-aria-agent/neutron_aria_agent/translator.py`
- `neutron-aria-agent/tests/test_translator_acl.py`
- `neutron-aria-agent/tests/test_translator_qos.py`
- `neutron-aria-agent/tests/test_translator_mirror.py`
- `neutron-aria-agent/tests/test_translator_tcprt.py`

默认实现顺序：

1. `state.py` 定义 `ProjectedState`。
2. `ProjectedState` 保存：
   - ports by `port_id`
   - security groups by `(project_id, sg_id)`
   - security group rules by `(project_id, rule_id)`
   - QoS policies by `(owner_project_id, policy_id)`
   - Mirror policies by `(owner_project_id, policy_id)`
   - TCPrt flags by project/network/port
   - shared network bindings
   - shared QoS bindings
   - admin mirror bindings
3. `translator.py` 输入 `ProjectedState`，输出与 `NeutronSnapshotRequest` 对齐的 dict。
4. ACL translator 默认 deny，只生成 allow rules。
5. remote group 默认只展开同 project 成员。
6. 跨 project remote group 只有明确 shared/admin binding 时生成。
7. QoS translator 先算 port effective policy：port-level > network-level > shared default。
8. Mirror translator 默认拒绝 tenant self-service mirror。
9. admin cross-project mirror 必须显式带 admin binding。
10. TCPrt translator 先算 per-port effective flag：port > network > project > default。
11. 所有 snapshot 内部引用使用 ID，不使用 name。
12. 测试中固定完整 snapshot 断言，不只断言字段存在。
13. 提交：`feat: add neutron state translator`。

必须覆盖的测试场景：

- 两个 project 有同名 security group，不串 scoped key。
- shared network 的 network owner 与 port owner 不同，ACL 仍按 port owner 编译。
- port migration event 只让新 `binding_host` 所在 host 生成 snapshot。
- remote group update 只影响本 host 相关 ports。
- shared QoS 只影响绑定 ports。
- tenant mirror 不生成 mirror policy。
- admin cross-project mirror 生成 mirror policy。
- project 默认 TCPrt 被 network 覆盖，network 被 port 覆盖。
- snapshot 不包含 trace/drops/ssl/diagnose/service chain。

停止条件：

- 如果 translator 需要直接调用 datapath API，停止；translator 只产出 snapshot，不执行下发。

#### 执行章节 7：主循环、Heartbeat 与事件合并

目标：让 `neutron-aria-agent` 具备 OpenStack agent 形态：启动、full resync、事件合并、下发 snapshot、上报 degraded/ready。

文件范围：

- `neutron-aria-agent/neutron_aria_agent/agent.py`
- `neutron-aria-agent/neutron_aria_agent/event_loop.py`
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
11. event loop 合并 burst events。
12. port update 按 `port_id` 合并，只保留最高 `source_revision` 或最后 binding 结果。
13. migration/rebind event 中，如果最新 `binding_host != local_host`，从本机 projected state 删除该 port，并调用 local delete。
14. migration/rebind event 中，如果最新 `binding_host == local_host`，加入 projected state，等待 Netlink 接口出现后提交 port-scoped snapshot。
15. tap recreate event 中，DELLINK 标记 runtime degraded，NEWLINK 后触发 port-scoped snapshot。
16. SG update 找本 host 相关 ports。
17. QoS update 找绑定 policy 的 ports。
18. Mirror/TCPrt update 只重算相关 ports。
19. burst window 内只提交一次 snapshot。
20. 提交：`feat: add neutron aria agent event loop`。

默认 degraded 规则：

- datapath socket 不可达：agent degraded。
- `runtime.blocked`：agent degraded 并触发 full resync。
- `acl.blocked`：agent degraded。
- `qos.degraded`、`mirror.degraded`、`tcprt.degraded`：agent alive，但上报原因。
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
13. `smoke.sh` 覆盖 SG/QoS/Mirror/TCPrt 基础路径。
14. GitHub Actions 增加 Python test job。
15. GitHub Actions 增加 container packaging job。
16. 提交：`feat: add openstack container deployment`。

默认 smoke 场景：

- agent alive。
- full snapshot 下发成功。
- 默认 deny 生效。
- 同 security group 允许流量。
- QoS bandwidth limit 可观察。
- mirror target 存在时 stats 增长。
- mirror target 不存在时 mirror degraded，不影响 ACL。
- TCPrt 开启后有流记录，关闭后不新增。
- 删除容器后 WAL/state 仍在宿主机持久目录。

停止条件：

- 如果目标环境暂时没有完整 OpenStack，先提交容器和 mock smoke；真实 DevStack/OpenStack smoke 作为进入 N7 的门槛，不阻塞 N1-N6。

## 17. 最终决策

`v0.9-neutron-agent` 分支采用 Neutron Agent Mode：

- 用 `v0.9.0` 作为基线。
- 不引入 `aria-controller`。
- 不迁移 v0.10 的 Controller / RFC 体系。
- 新增 Python `neutron-aria-agent` 作为 OpenStack 适配层。
- `aria-datapath` 继续作为 Rust 本机 datapath runtime，运行现有 `aria-agent` 二进制。
- 第一阶段采用 Coexist Mode，不完整替代 OVS/OVN L2。
- ACL、QoS、Mirror、TCPrt 四个功能进入第一阶段规划。
- 多租户按 Neutron project/RBAC 关系适配，使用 scoped object key 隔离 state、WAL、refcount 和 pinned map ID。
- Group、WAL、Netlink、Pinned Maps 作为必选支撑能力随 N1/N2 一起落地。
- trace、drops、ssl、diagnose、service chain 等其它已有能力代码保留，但不作为 OpenStack agent mode 对外功能暴露。

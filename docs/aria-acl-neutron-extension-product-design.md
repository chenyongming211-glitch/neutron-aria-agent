# Aria ACL Neutron 独立扩展产品化设计

状态：Draft  
创建日期：2026-06-15  
适用分支：`v0.9-neutron-agent`  
关联方案：[OpenStack Neutron Agent Mode 详细方案](openstack-neutron-agent-mode.md)

## 1. 结论

Aria ACL 产品化路线应实现为一个独立的 Neutron 扩展能力，而不是复用或改造 Neutron Security Group。

最终目标形态：

```text
Neutron API / neutron-server
        |
        | aria_acl service plugin
        v
Aria ACL API + DB + policy engine
        |
        | RPC / notification / full resync
        v
neutron-aria-agent on compute node
        |
        | Unix socket snapshot
        v
aria-agent / aria-datapath
        |
        | eBPF ACL apply
        v
tap interface on br-int
```

核心判断：

- ACL 做 Aria 独立 Neutron 扩展，提供独立 API、DB、RBAC、RPC、agent 同步和状态上报。
- QoS 复用 Neutron 原生 QoS policy/rule 模型，只把执行后端切换到 Aria。
- ACL 不消费 Neutron Security Group、remote group、port security、allowed address pairs，也不承担 Security Group replacement 语义。
- ACL 不启用 `OVSHybridIptablesFirewallDriver` 链路，不引入 `qbr/qvo/qvb`。
- Aria 只增强普通 OVS tap 端口，SR-IOV 和 LinuxBridge 端口不纳入 Aria ACL 管理。

## 2. 目标环境约束

当前目标 OpenStack 环境的关键事实：

- 业务 VM tap 口直接挂载到 OVS `br-int`。
- 平台未启用 Neutron Security Group，`enable_security_group = False`。
- SR-IOV 端口可以不使用 Aria。
- LinuxBridge agent 存在，但业务侧几乎不使用。
- 当前没有 `qbr/qvo/qvb` hybrid 安全组端口链路。
- Neutron 仍然是网络配置唯一入口，Aria 不暴露独立租户 northbound。

因此产品化 ACL 方案必须围绕下面的 port 选择条件设计：

```text
只接管：
  binding:host_id == 当前 compute host
  binding:vif_type == ovs
  binding:vnic_type 为 normal 或等价普通虚机端口
  OVS br-int 上存在 external_ids:iface-id=<neutron-port-id>

明确跳过：
  SR-IOV direct / direct-physical 端口
  LinuxBridge 端口
  OVN 端口
  无法在 br-int 找到 iface-id 的端口
  迁移中、binding 未完成或 tap 尚未出现的端口
```

## 3. 设计原则

### 3.1 不复用 Security Group

Aria ACL 与 Neutron Security Group 的边界必须硬隔离：

| 项目 | Aria ACL | Neutron Security Group |
| --- | --- | --- |
| API 对象 | `aria_acl_policy`、`aria_acl_rule`、`aria_acl_binding` | `security_group`、`security_group_rule` |
| 执行后端 | Aria eBPF datapath | iptables / OVS firewall / OVN ACL |
| remote group | 不支持 | 支持 |
| port security | 不消费 | 强相关 |
| anti-spoof | 当前阶段不实现 | SG/port security 相关 |
| qbr/qvo/qvb | 不引入 | hybrid driver 可能引入 |
| 默认语义 | 显式 ACL enhancement | Neutron 原生安全组 |

禁止做法：

- 禁止把 `security_group_ids` 翻译成 Aria ACL。
- 禁止把 `remote_group_id` 展开成 Aria address set。
- 禁止把 `port_security_enabled` 当成 Aria ACL 开关。
- 禁止把没有 Aria ACL 绑定的 port 默认套用 Neutron 默认安全组。
- 禁止通过开启 Security Group 来触发 Aria ACL 生效。

### 3.2 Neutron 是唯一 source of truth

所有 OpenStack 托管端口的 ACL 配置都来自 Neutron：

- 租户或平台管理员只通过 Neutron API 创建、修改、删除 ACL 对象。
- `neutron-aria-agent` 只消费 Neutron 状态，不提供租户 API。
- `aria-agent` 只接收本机声明式 snapshot，不访问 Neutron DB，不消费 Neutron RPC。
- 本机 `ariactl` 对 Neutron-managed port 的 ACL/QoS 写操作必须被拒绝。

### 3.3 OVS 转发保护

Aria ACL 是 OVS enhancement，不替代 OVS L2 转发。

失败处理原则：

- 没有 ACL 绑定的 port：`not_requested + bypass`。
- ACL 配置错误：对应 port `degraded + bypass`。
- apply 失败：对应 port `degraded + bypass`。
- conntrack 不可用且 policy 要求 stateful：对应 port `degraded + bypass`。
- Neutron agent 或 Aria agent 异常：不主动破坏 OVS 原有转发。

## 4. 组件边界

### 4.1 neutron-server: `aria_acl` service plugin

职责：

- 提供 Aria ACL REST API。
- 维护 Aria ACL DB 表。
- 执行 RBAC、project ownership、输入校验和引用校验。
- 对 policy/rule/address-set/binding 变更生成 revision。
- 向 `neutron-aria-agent` 发 RPC notification。
- 提供 full resync 查询接口。

不负责：

- 不访问 OVS。
- 不写 eBPF map。
- 不访问 `/run/aria`。
- 不直接调用 `aria-agent`。
- 不修改 Neutron Security Group。

建议 Python 包结构：

```text
neutron_aria/
  extensions/
    aria_acl.py
  services/
    aria_acl/
      plugin.py
      constants.py
      exceptions.py
      validators.py
  db/
    aria_acl/
      models.py
      api.py
      migration/
  objects/
    aria_acl.py
  policies/
    aria_acl.py
  rpc/
    aria_acl.py
```

入口注册：

```ini
[entry_points]
neutron.service_plugins =
    aria_acl = neutron_aria.services.aria_acl.plugin:AriaAclPlugin
```

启用配置：

```ini
# neutron.conf
service_plugins = router,network_ip_availability,mirror,qos,aria_acl
```

### 4.2 neutron-aria-agent

职责：

- 注册为独立 Neutron agent。
- 订阅 port、network、Aria ACL、QoS 相关事件。
- 定期或按需执行 full resync。
- 只处理绑定到本 host 的普通 OVS tap port。
- 计算每个 port 的 effective ACL。
- 查询 OVSDB，建立 `port_id -> tap_name -> ifindex` 映射。
- 生成 Aria Neutron snapshot。
- 通过 Unix socket 调用本机 `aria-agent`。
- 上报 agent health、domain readiness 和错误原因。

不负责：

- 不访问 Neutron DB。
- 不写 eBPF map。
- 不挂载 `/sys/fs/bpf`。
- 不替代 neutron-openvswitch-agent。
- 不接管 OVS bridge/tunnel/local switching。

### 4.3 aria-agent / aria-datapath

职责：

- 暴露本机 Neutron snapshot Unix socket API。
- 校验 snapshot schema、generation、authority state 和 capability。
- 持久化 WAL。
- 编译 group/address-set/ACL。
- attach 或维护 tap eBPF runtime。
- 写入 eBPF map。
- 输出 per-domain status。

不负责：

- 不访问 Neutron API。
- 不访问 Neutron DB。
- 不判断租户权限。
- 不推导跨 project 访问关系。
- 不消费 Security Group。

## 5. Neutron API 设计

### 5.1 API 资源

产品化 ACL 扩展包含四类资源：

```text
aria_acl_policies
aria_acl_rules
aria_acl_address_sets
aria_acl_bindings
```

建议 extension alias：

```text
aria-acl
```

建议 API prefix：

```text
/v2.0/aria-acl-policies
/v2.0/aria-acl-rules
/v2.0/aria-acl-address-sets
/v2.0/aria-acl-bindings
```

### 5.2 Policy API

`aria_acl_policy` 表达一个可绑定到 network 或 port 的 ACL 策略。

字段：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | uuid | 否 | 服务端生成 |
| `project_id` | string | 是 | owner project |
| `name` | string | 否 | 策略名称 |
| `description` | string | 否 | 描述 |
| `enabled` | bool | 否 | 默认 true |
| `stateful` | bool | 否 | 默认 true |
| `default_action` | enum | 是 | `allow` 或 `deny` |
| `revision_number` | int | 否 | Neutron revision |
| `created_at` | datetime | 否 | 创建时间 |
| `updated_at` | datetime | 否 | 更新时间 |

创建示例：

```http
POST /v2.0/aria-acl-policies
```

```json
{
  "aria_acl_policy": {
    "name": "web-db-acl",
    "description": "deny web to db mysql",
    "project_id": "project-a",
    "enabled": true,
    "stateful": true,
    "default_action": "allow"
  }
}
```

返回示例：

```json
{
  "aria_acl_policy": {
    "id": "5a3f3b72-1f8e-43f9-87bb-711a99c5f2f1",
    "project_id": "project-a",
    "name": "web-db-acl",
    "description": "deny web to db mysql",
    "enabled": true,
    "stateful": true,
    "default_action": "allow",
    "revision_number": 1,
    "created_at": "2026-06-15T10:00:00Z",
    "updated_at": "2026-06-15T10:00:00Z"
  }
}
```

### 5.3 Rule API

`aria_acl_rule` 表达一条 ACL 匹配和动作。

字段：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | uuid | 否 | 服务端生成 |
| `project_id` | string | 是 | owner project，必须与 policy 兼容 |
| `policy_id` | uuid | 是 | 所属 policy |
| `direction` | enum | 是 | `ingress` 或 `egress` |
| `priority` | int | 是 | 数字越小优先级越高 |
| `action` | enum | 是 | `allow` 或 `deny` |
| `ethertype` | enum | 否 | `IPv4` 或 `IPv6` |
| `protocol` | string/int | 否 | `tcp`、`udp`、`icmp`、`1` 等 |
| `src_cidr` | cidr | 否 | 源 CIDR |
| `dst_cidr` | cidr | 否 | 目的 CIDR |
| `src_address_set_id` | uuid | 否 | 源 address set |
| `dst_address_set_id` | uuid | 否 | 目的 address set |
| `src_port_min` | int | 否 | L4 源端口下限 |
| `src_port_max` | int | 否 | L4 源端口上限 |
| `dst_port_min` | int | 否 | L4 目的端口下限 |
| `dst_port_max` | int | 否 | L4 目的端口上限 |
| `enabled` | bool | 否 | 默认 true |
| `revision_number` | int | 否 | Neutron revision |

创建示例：

```http
POST /v2.0/aria-acl-rules
```

```json
{
  "aria_acl_rule": {
    "project_id": "project-a",
    "policy_id": "5a3f3b72-1f8e-43f9-87bb-711a99c5f2f1",
    "direction": "egress",
    "priority": 100,
    "action": "deny",
    "ethertype": "IPv4",
    "protocol": "tcp",
    "dst_address_set_id": "9f647c1d-0899-4a20-9f12-f3dbda91a45f",
    "dst_port_min": 3306,
    "dst_port_max": 3306,
    "enabled": true
  }
}
```

规则校验：

- `priority` 在同一 policy、同一 direction 内不能重复。
- `src_cidr` 与 `src_address_set_id` 不能同时设置。
- `dst_cidr` 与 `dst_address_set_id` 不能同时设置。
- 设置 L4 端口时必须指定 TCP 或 UDP。
- `port_min` 不能大于 `port_max`。
- IPv4 rule 不能引用 IPv6 CIDR，反之亦然。
- `action=deny` 和 `action=allow` 都必须显式写入。

### 5.4 Address Set API

`aria_acl_address_set` 表达一组 IP 或 CIDR。

字段：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | uuid | 否 | 服务端生成 |
| `project_id` | string | 是 | owner project |
| `name` | string | 是 | 名称 |
| `description` | string | 否 | 描述 |
| `members` | list | 否 | IP/CIDR 成员 |
| `revision_number` | int | 否 | Neutron revision |

创建示例：

```json
{
  "aria_acl_address_set": {
    "project_id": "project-a",
    "name": "db-subnets",
    "description": "database networks",
    "members": [
      {"address": "10.10.20.0/24"},
      {"address": "10.10.21.15/32"}
    ]
  }
}
```

### 5.5 Binding API

`aria_acl_binding` 表达 policy 与 Neutron target 的绑定关系。

支持 target：

```text
network
port
```

字段：

| 字段 | 类型 | 必填 | 说明 |
| --- | --- | --- | --- |
| `id` | uuid | 否 | 服务端生成 |
| `project_id` | string | 是 | binding owner |
| `policy_id` | uuid | 是 | ACL policy |
| `target_type` | enum | 是 | `network` 或 `port` |
| `target_id` | uuid | 是 | Neutron network_id 或 port_id |
| `enabled` | bool | 否 | 默认 true |
| `revision_number` | int | 否 | Neutron revision |

创建示例：

```json
{
  "aria_acl_binding": {
    "project_id": "project-a",
    "policy_id": "5a3f3b72-1f8e-43f9-87bb-711a99c5f2f1",
    "target_type": "port",
    "target_id": "2b7550c2-5378-41e9-a066-68008a35f532",
    "enabled": true
  }
}
```

绑定校验：

- `target_type=network` 时，`target_id` 必须是存在的 Neutron network。
- `target_type=port` 时，`target_id` 必须是存在的 Neutron port。
- 非 admin 用户只能绑定自己 project 内的资源，第一版建议关闭普通租户绑定权限。
- 同一 target 第一版只允许一个 enabled policy 生效。
- 删除 policy 前必须先删除 binding，或由服务端执行级联清理并通知 agent。

## 6. DB 模型

### 6.1 表结构

建议新增表：

```text
aria_acl_policies
aria_acl_rules
aria_acl_address_sets
aria_acl_address_set_members
aria_acl_bindings
aria_acl_rbac
```

### 6.2 `aria_acl_policies`

```text
id                 UUID primary key
project_id         String indexed not null
name               String
description        String
enabled            Boolean not null default true
stateful           Boolean not null default true
default_action     Enum allow/deny not null
revision_number    Integer not null
created_at         DateTime
updated_at         DateTime
```

索引：

```text
(project_id)
(project_id, name)
(revision_number)
```

### 6.3 `aria_acl_rules`

```text
id                    UUID primary key
project_id            String indexed not null
policy_id             UUID foreign key aria_acl_policies.id
direction             Enum ingress/egress not null
priority              Integer not null
action                Enum allow/deny not null
ethertype             Enum IPv4/IPv6 nullable
protocol              String nullable
src_cidr              String nullable
dst_cidr              String nullable
src_address_set_id    UUID nullable
dst_address_set_id    UUID nullable
src_port_min          Integer nullable
src_port_max          Integer nullable
dst_port_min          Integer nullable
dst_port_max          Integer nullable
enabled               Boolean not null default true
revision_number       Integer not null
created_at            DateTime
updated_at            DateTime
```

约束：

```text
unique(policy_id, direction, priority)
foreign key(policy_id) references aria_acl_policies(id)
foreign key(src_address_set_id) references aria_acl_address_sets(id)
foreign key(dst_address_set_id) references aria_acl_address_sets(id)
```

### 6.4 `aria_acl_address_sets`

```text
id                 UUID primary key
project_id         String indexed not null
name               String not null
description        String
revision_number    Integer not null
created_at         DateTime
updated_at         DateTime
```

约束：

```text
unique(project_id, name)
```

### 6.5 `aria_acl_address_set_members`

```text
id                 UUID primary key
address_set_id     UUID foreign key aria_acl_address_sets.id
address            String not null
description        String
created_at         DateTime
updated_at         DateTime
```

约束：

```text
unique(address_set_id, address)
```

### 6.6 `aria_acl_bindings`

```text
id                 UUID primary key
project_id         String indexed not null
policy_id          UUID foreign key aria_acl_policies.id
target_type        Enum network/port not null
target_id          UUID not null
enabled            Boolean not null default true
revision_number    Integer not null
created_at         DateTime
updated_at         DateTime
```

约束：

```text
unique(target_type, target_id, enabled) for enabled=true
foreign key(policy_id) references aria_acl_policies(id)
```

如果数据库不支持 partial unique index，可以用插件逻辑保证同一 target 只有一个 enabled binding。

### 6.7 `aria_acl_rbac`

第一版建议只实现 admin 管理，不开放普通租户共享；但 DB 可以预留 RBAC 表。

```text
id                 UUID primary key
object_id          UUID not null
object_type        String not null default aria_acl_policy
target_project_id  String not null
action             String not null
created_at         DateTime
updated_at         DateTime
```

第一版支持的 action：

```text
access_as_shared
```

## 7. ACL 生效语义

### 7.1 Direction

Aria ACL direction 以 VM tap 视角定义：

```text
egress:
  VM 发出的流量，从 VM tap 进入 br-int 方向。

ingress:
  发往 VM 的流量，从 br-int 进入 VM tap 方向。
```

具体 eBPF attach 点必须在目标环境 smoke 中验证：

- VM 到同 host VM。
- VM 到跨 host VM。
- VM 到 external network。
- external network 到 VM。
- DHCP、metadata、ARP、IPv6 ND。

### 7.2 Policy 匹配

每个 port 最终只能得到一个 effective ACL policy：

```text
port-level binding > network-level binding > no binding
```

第一版不做多个 policy 叠加。

原因：

- 排障简单。
- 状态返回明确。
- 避免多个 policy 的 priority 合并冲突。
- 降低 snapshot 大小和编译复杂度。

未来如果需要叠加，可以引入：

```text
binding_priority
merge_strategy = additive / override
```

### 7.3 Default Action

`default_action` 必须显式配置。

推荐默认产品策略：

```text
policy 未绑定到 port:
  not_requested + bypass

policy 已绑定，规则未命中:
  按 policy.default_action 执行

policy 绑定但编译失败:
  degraded + bypass
```

不允许因为创建了空 policy 就静默 `deny all`，除非管理员显式配置：

```json
{
  "default_action": "deny"
}
```

### 7.4 Stateful

`stateful=true` 表示需要 Aria conntrack 支撑。

行为：

```text
conntrack ready:
  policy 可以进入 ready

conntrack unavailable:
  ACL domain degraded
  effective_action=bypass
  不启用 ACL feature flag
```

`stateful=false` 可用于纯 stateless ACL，适合早期排障或极简策略。

### 7.5 未绑定端口

未绑定 Aria ACL 的端口必须保持 bypass：

```text
DomainStatus=not_requested
effective_action=bypass
support_disposition=not_applicable
```

这条规则非常重要，用于保证 Aria ACL 不会在无显式配置时改变现有 OVS 转发。

## 8. RPC 与事件模型

### 8.1 事件类型

`aria_acl` service plugin 在以下动作后通知 agent：

```text
aria_acl_policy.create
aria_acl_policy.update
aria_acl_policy.delete
aria_acl_rule.create
aria_acl_rule.update
aria_acl_rule.delete
aria_acl_address_set.create
aria_acl_address_set.update
aria_acl_address_set.delete
aria_acl_binding.create
aria_acl_binding.update
aria_acl_binding.delete
```

还需要消费 Neutron 原生事件：

```text
port.create
port.update
port.delete
network.update
network.delete
```

QoS 另走 Neutron QoS 原生事件，不混入 ACL plugin。

### 8.2 事件内容

事件中至少包含：

```json
{
  "event_type": "aria_acl_rule.update",
  "resource_id": "rule-uuid",
  "policy_id": "policy-uuid",
  "project_id": "project-a",
  "revision_number": 7,
  "affected_targets": [
    {"target_type": "port", "target_id": "port-uuid"},
    {"target_type": "network", "target_id": "network-uuid"}
  ]
}
```

agent 收到事件后不直接执行单条 eBPF 增量写入，而是：

```text
1. 标记受影响 policy/address-set/binding dirty。
2. 找出受影响 network/port。
3. 合并短时间内连续事件。
4. 拉取最新对象状态。
5. 重算 affected ports 的 effective ACL。
6. 提交 port-scoped snapshot 或 full snapshot。
```

### 8.3 乱序处理

所有 ACL 对象必须携带 `revision_number`。

处理规则：

```text
event.revision_number < local_cache.revision_number:
  丢弃旧事件

event.revision_number == local_cache.revision_number:
  幂等处理

event.revision_number > local_cache.revision_number:
  拉取最新对象或触发 partial resync
```

如果 agent 发现 revision 不连续或对象缺失：

```text
1. 停止相关 policy 的增量 apply。
2. 标记 affected ports degraded + bypass。
3. 触发 full resync。
4. full resync 成功后恢复。
```

## 9. neutron-aria-agent 详细设计

### 9.1 启动流程

```text
1. 读取 neutron-aria-agent 配置。
2. 获取本机 host 名称，与 Neutron binding:host_id 对齐。
3. 注册 Neutron agent heartbeat。
4. 连接 RabbitMQ / Neutron RPC。
5. 连接本机 /run/aria/aria-agent.sock。
6. 调用 aria-agent capabilities。
7. 校验 UDS contract。
8. 执行 full resync。
9. 进入事件循环。
```

### 9.2 Full Resync

full resync 必须一次性拉取：

```text
本 host ports
本 host ports 所属 networks
aria_acl_policies
aria_acl_rules
aria_acl_address_sets
aria_acl_bindings
Neutron QoS policies and bindings
```

ACL full resync 输出：

```text
port_inventory
policy_cache
rule_cache
address_set_cache
binding_cache
effective_acl_by_port
```

### 9.3 Port 过滤

agent 只处理满足条件的 port：

```text
port.binding_host_id == local_host
port.binding_vif_type == ovs
port.binding_vnic_type in ["normal", "", null]
port.admin_state_up == true
OVS br-int interface external_ids:iface-id == port.id
```

跳过端口需要写入 status：

| 场景 | support_disposition | 原因 |
| --- | --- | --- |
| SR-IOV direct | `unsupported` | Aria 不接管 SR-IOV datapath |
| LinuxBridge | `unsupported` | 当前只支持 OVS br-int tap |
| OVN | `unsupported` | 当前不支持 OVN |
| tap 未出现 | `unknown` 或 `not_applicable` | binding 未完成或迁移中 |
| 无 ACL binding | `not_applicable` | ACL 未请求 |

### 9.4 Effective ACL 计算

伪代码：

```python
def resolve_effective_acl(port):
    port_binding = find_enabled_binding("port", port.id)
    if port_binding:
        return build_policy(port_binding.policy_id, source="port")

    network_binding = find_enabled_binding("network", port.network_id)
    if network_binding:
        return build_policy(network_binding.policy_id, source="network")

    return None
```

`build_policy()` 必须展开：

```text
policy 基础字段
enabled rules
address set members
project_id
revision_number
binding source
```

### 9.5 Snapshot 下发

agent 向 aria-agent 提交声明式 snapshot：

```json
{
  "schema_version": "v1",
  "source": "neutron-aria-agent",
  "host": "ostack2.bj159.net",
  "generation": 1024,
  "integration_mode": "coexist",
  "ports": [
    {
      "port_id": "2b7550c2-5378-41e9-a066-68008a35f532",
      "project_id": "project-a",
      "network_id": "network-a",
      "tap_name": "tap2b7550c2-53",
      "mac_address": "fa:16:3e:11:22:33",
      "fixed_ips": ["10.10.10.15"],
      "binding": {
        "vif_type": "ovs",
        "vnic_type": "normal",
        "host_id": "ostack2.bj159.net"
      },
      "acl": {
        "requested": true,
        "policy_id": "5a3f3b72-1f8e-43f9-87bb-711a99c5f2f1",
        "binding_id": "binding-uuid",
        "binding_source": "port",
        "stateful": true,
        "default_action": "allow",
        "revision_number": 12,
        "rules": [
          {
            "rule_id": "rule-uuid",
            "direction": "egress",
            "priority": 100,
            "action": "deny",
            "ethertype": "IPv4",
            "protocol": "tcp",
            "dst_address_set_id": "9f647c1d-0899-4a20-9f12-f3dbda91a45f",
            "dst_port_min": 3306,
            "dst_port_max": 3306
          }
        ],
        "address_sets": [
          {
            "id": "9f647c1d-0899-4a20-9f12-f3dbda91a45f",
            "members": ["10.10.20.0/24", "10.10.21.15/32"]
          }
        ]
      }
    }
  ]
}
```

### 9.6 Agent 状态上报

Neutron agent heartbeat 中至少包含：

```json
{
  "agent_type": "Aria ACL agent",
  "host": "ostack2.bj159.net",
  "binary": "neutron-aria-agent",
  "configurations": {
    "integration_mode": "coexist",
    "managed_port_count": 128,
    "acl_ready_port_count": 120,
    "acl_degraded_port_count": 8,
    "unsupported_port_count": 3,
    "accepted_generation": 1024,
    "last_classified_generation": 1024
  }
}
```

`alive=true` 只表示 agent 进程和 heartbeat 正常，不代表所有 ACL ready。

## 10. aria-agent / datapath 接口

### 10.1 Unix Socket API

Neutron snapshot API 只能通过 Unix socket 暴露：

```text
/run/aria/aria-agent.sock
```

建议接口：

```text
GET    /api/v1/neutron/capabilities
GET    /api/v1/neutron/status
PUT    /api/v1/neutron/snapshot
DELETE /api/v1/neutron/ports/{port_id}
```

禁止：

- 禁止暴露到 TCP OpenAPI paths。
- 禁止 `neutron-aria-agent` fallback 到 localhost HTTP。
- 禁止租户访问该 socket。

### 10.2 Apply 顺序

aria-agent apply 顺序固定：

```text
1. schema / capability 校验
2. authority state 校验
3. Neutron-managed port preflight
4. WAL intent
5. runtime attach / tap identity check
6. group / address-set apply
7. conntrack readiness check
8. ACL apply
9. QoS apply
10. WAL commit
11. status update
```

ACL 失败时：

```text
ACL domain = degraded
effective_action = bypass
不启用 ACL feature flag
不影响 OVS L2 forwarding
```

### 10.3 本机写入保护

OpenStack mode 下，本机 API 必须拒绝对 Neutron-managed port 的 ACL 写入：

```text
LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_PORT
```

拒绝范围：

- group add/update/delete
- policy add/update/delete
- ACL rule add/update/delete
- QoS add/update/delete
- config set acl/qos

只允许：

- status
- metrics
- diagnose/read-only
- break-glass 模式下的显式管理员操作

break-glass 必须单独设计，不进入默认产品路径。

## 11. RBAC 与权限

### 11.1 第一版权限模型

建议第一版采用平台管理员托管模型：

| 操作 | admin | project user |
| --- | --- | --- |
| create policy | 允许 | 禁止 |
| update policy | 允许 | 禁止 |
| delete policy | 允许 | 禁止 |
| create rule | 允许 | 禁止 |
| update rule | 允许 | 禁止 |
| delete rule | 允许 | 禁止 |
| create binding | 允许 | 禁止 |
| delete binding | 允许 | 禁止 |
| list own policy | 允许 | 只读可选 |
| show own policy | 允许 | 只读可选 |

原因：

- 当前平台未启用安全组，ACL 更像平台侧治理能力。
- 第一版先保证可控、可审计、可回滚。
- 避免租户自服务规则误封业务。

### 11.2 后续租户自服务

后续可以开放租户自服务，但必须满足：

- 租户只能管理自己 project 的 ACL。
- 租户只能绑定自己 project 的 port。
- shared network 场景必须经过 Neutron RBAC 授权。
- 跨 project address set 引用必须显式授权。
- 不允许租户引用或推导其它 project 的 port IP。

## 12. Kolla 部署方案

### 12.1 neutron-server 镜像

需要打入：

```text
neutron_aria Python package
aria_acl service plugin entrypoint
DB migration
policy rules
config sample
```

配置：

```ini
# /etc/kolla/neutron-server/neutron.conf
[DEFAULT]
service_plugins = router,network_ip_availability,mirror,qos,aria_acl

[aria_acl]
enabled = true
default_admin_only = true
notify_agents = true
```

### 12.2 neutron-aria-agent 镜像

容器职责：

```text
Python Neutron adapter
RPC consumer
full resync
OVSDB read-only mapping
UDS client
heartbeat reporter
```

挂载：

```text
/etc/kolla/neutron-aria-agent/
/run/aria/
/var/lib/neutron-aria-agent/
```

权限：

- 需要访问 Neutron RPC 配置。
- 需要读 OVSDB 或通过 host 工具查询 `br-int` 端口。
- 需要访问 `/run/aria/aria-agent.sock`。
- 不需要 `/sys/fs/bpf`。
- 不需要 eBPF capability。

示例配置：

```ini
[DEFAULT]
host = ostack2.bj159.net
agent_type = Aria ACL agent
report_interval = 30
full_resync_interval = 300

[aria]
socket_path = /run/aria/aria-agent.sock
integration_bridge = br-int
integration_mode = coexist
enable_acl = true
enable_qos = true

[ovs]
ovsdb_connection = unix:/run/openvswitch/db.sock
```

### 12.3 aria-agent 容器

aria-agent 容器职责：

```text
eBPF program load/attach
WAL
runtime status
Unix socket server
ACL/QoS apply
metrics
```

需要权限：

- host network 或足够的 net admin 能力。
- `/sys/fs/bpf`。
- `/run/aria`。
- `/var/lib/aria-agent`。
- 访问 tap interface 和 netlink。

## 13. 变更流程

### 13.1 创建 ACL 策略

```text
1. admin 调用 POST /v2.0/aria-acl-policies。
2. neutron-server 写 aria_acl_policies。
3. admin 调用 POST /v2.0/aria-acl-rules。
4. neutron-server 写 aria_acl_rules。
5. admin 调用 POST /v2.0/aria-acl-bindings。
6. neutron-server 写 aria_acl_bindings。
7. aria_acl plugin 发送 binding update notification。
8. 对应 host 的 neutron-aria-agent 发现 affected port。
9. agent 计算 effective ACL。
10. agent 下发 snapshot。
11. aria-agent apply。
12. agent 上报 status。
```

### 13.2 更新 ACL 规则

```text
1. admin 更新 rule。
2. neutron-server 增加 rule revision。
3. plugin 发送 rule update notification。
4. agent 找出绑定该 policy 的 ports。
5. agent 合并短时间连续事件。
6. agent 拉取最新 policy/rules/address sets。
7. agent 重算 affected ports。
8. agent 下发 port-scoped snapshot。
```

### 13.3 删除绑定

```text
1. admin 删除 aria_acl_binding。
2. agent 收到 binding delete。
3. agent 重算 port effective ACL。
4. 如果没有 network-level binding，该 port 进入 not_requested + bypass。
5. aria-agent 清理该 port ACL maps。
6. OVS 转发保持原状。
```

### 13.4 Port 迁移

live migration 或冷迁移：

```text
1. 旧 host 收到 port update，发现 binding_host 已变化。
2. 旧 host neutron-aria-agent 删除本机 port snapshot。
3. 旧 host aria-agent 清理旧 tap ACL state。
4. 新 host 收到 port update，发现 port 绑定本机。
5. 新 host 查询 br-int tap。
6. 新 host 计算 effective ACL。
7. 新 host 下发 snapshot。
```

迁移过程中如果 tap 尚未出现：

```text
RuntimeAttachmentState=neutron_bound_pending
ACL domain=not_requested 或 degraded
effective_action=bypass
```

## 14. 错误处理与状态

### 14.1 Domain Status

ACL domain 使用结构化状态：

| DomainStatus | effective_action | 场景 |
| --- | --- | --- |
| `ready` | `enabled` | policy 编译和 apply 成功 |
| `not_requested` | `bypass` | port 没有 ACL binding |
| `degraded` | `bypass` | policy/rule/address-set 错误 |
| `degraded` | `bypass` | conntrack 不可用但 stateful=true |
| `degraded` | `bypass` | tap identity 不稳定 |
| `blocked` | `unchanged` | WAL 或 schema 严重错误，无法安全 apply |

### 14.2 错误码

建议错误码：

| 错误码 | 层级 | 含义 | 处理 |
| --- | --- | --- | --- |
| `ARIA_ACL_POLICY_NOT_FOUND` | neutron-server | binding 引用不存在的 policy | API 拒绝 |
| `ARIA_ACL_RULE_INVALID` | neutron-server | rule 字段非法 | API 拒绝 |
| `ARIA_ACL_ADDRESS_SET_INVALID` | neutron-server | address set 成员非法 | API 拒绝 |
| `ARIA_ACL_BINDING_CONFLICT` | neutron-server | target 已有 enabled binding | API 拒绝 |
| `ARIA_ACL_TARGET_UNSUPPORTED` | agent | target port 非 OVS tap | status unsupported |
| `ARIA_ACL_TAP_NOT_FOUND` | agent | br-int 找不到 iface-id | pending/degraded |
| `ARIA_ACL_REVISION_STALE` | agent | 收到旧 revision | 丢弃事件 |
| `ARIA_ACL_CONTRACT_DRIFT` | agent/datapath | UDS contract 不匹配 | 停止写路径 |
| `ARIA_ACL_COMPILE_FAILED` | datapath | ACL 编译失败 | degraded + bypass |
| `ARIA_ACL_APPLY_FAILED` | datapath | eBPF map apply 失败 | degraded + bypass |
| `CONNTRACK_REQUIRED_UNAVAILABLE` | datapath | stateful ACL 缺少 conntrack | degraded + bypass |

### 14.3 告警

建议 Prometheus/告警指标：

```text
aria_acl_managed_ports_total
aria_acl_ready_ports_total
aria_acl_degraded_ports_total
aria_acl_bypass_ports_total
aria_acl_unsupported_ports_total
aria_acl_policy_count
aria_acl_rule_count
aria_acl_apply_failures_total
aria_acl_snapshot_generation
aria_acl_last_successful_generation
```

关键告警：

| 告警 | 条件 | 说明 |
| --- | --- | --- |
| `AriaAclBypassDegradedPorts` | degraded+bypass port > 0 持续超过阈值 | ACL 未生效但业务未中断 |
| `AriaAclAgentDown` | Neutron heartbeat down | agent 不可用 |
| `AriaAclContractDrift` | UDS contract mismatch | Python/Rust 版本不匹配 |
| `AriaAclApplyFailureSpike` | apply failure 增长 | datapath apply 异常 |
| `AriaAclUnsupportedPortBound` | ACL binding 指向 unsupported port | 配置对象无法执行 |

## 15. 与 QoS 的关系

ACL 和 QoS 必须分层：

```text
ACL:
  新增 aria_acl service plugin
  新增 API/DB/RBAC/RPC
  不复用 Security Group

QoS:
  复用 Neutron QoS service plugin
  复用 Neutron QoS policy/rule/binding
  neutron-aria-agent 增加 QoS translator
  aria-agent 执行 eBPF QoS
```

QoS 不应该放进 `aria_acl` plugin。

原因：

- Neutron 已有成熟 QoS API/DB。
- ACL 是新产品语义，QoS 是已有 Neutron 语义。
- 分开后可以独立灰度、独立回滚、独立排障。

## 16. 测试方案

### 16.1 Neutron Server 单元测试

覆盖：

- policy CRUD。
- rule CRUD。
- address set CRUD。
- binding CRUD。
- binding conflict。
- RBAC policy。
- project ownership。
- rule validator。
- address CIDR validator。
- revision_number 更新。
- delete policy 时引用检查。

### 16.2 Neutron DB migration 测试

覆盖：

- 新建所有表。
- downgrade 或回滚策略。
- 索引存在。
- foreign key 存在。
- unique 约束有效。

### 16.3 RPC 测试

覆盖：

- policy update notification。
- rule update notification。
- binding update notification。
- event merge。
- stale revision 丢弃。
- RPC 断开后 full resync。

### 16.4 neutron-aria-agent 单元测试

覆盖：

- host port 过滤。
- OVS tap 映射。
- SR-IOV skip。
- LinuxBridge skip。
- port-level binding 覆盖 network-level binding。
- 未绑定 port bypass。
- address set 展开。
- stateful conntrack required。
- snapshot generation 单调递增。
- UDS contract drift。

### 16.5 aria-agent Rust 测试

覆盖：

- Neutron snapshot DTO serde。
- UDS route 不进入 TCP OpenAPI。
- ACL snapshot apply。
- WAL intent/commit/replay。
- degraded+bypass。
- local write blocked。
- delete port cleanup。
- capability mismatch。

### 16.6 目标环境 smoke

必须覆盖：

```text
无 ACL binding:
  VM 连通性不变

绑定 allow policy:
  允许流量通过

绑定 deny policy:
  指定流量被拦截

删除 binding:
  恢复 bypass

rule update:
  已运行 VM 上实时生效

agent restart:
  full resync 后恢复

aria-agent restart:
  WAL/replay 后恢复

tap recreate:
  port_id 不变，tap 变化后恢复

SR-IOV port:
  明确 unsupported，不被 Aria 接管

DHCP / metadata / ARP / IPv6 ND:
  无显式 ACL 时不被误伤
```

## 17. 灰度与回滚

### 17.1 灰度开关

建议配置：

```ini
[aria_acl]
enabled = true
enforcement_enabled = false
admin_only = true
allowed_projects =
allowed_networks =
allowed_hosts =
```

灰度阶段：

```text
enabled=true
enforcement_enabled=false
```

含义：

- Neutron API 可创建对象。
- agent 可计算 snapshot。
- aria-agent 可校验 schema。
- 不真正启用 datapath ACL。

生产启用：

```text
enforcement_enabled=true
```

### 17.2 回滚策略

按层回滚：

```text
1. 关闭 enforcement_enabled。
2. neutron-aria-agent 下发 cleanup snapshot。
3. 确认所有 managed ports 进入 bypass。
4. 停止 neutron-aria-agent。
5. 从 neutron.conf 移除 aria_acl service plugin。
6. 保留 DB 表，避免删除历史对象。
```

不建议生产回滚时立即 drop DB 表。

### 17.3 失败隔离

ACL 失败不得影响：

- OVS L2 转发。
- neutron-openvswitch-agent。
- Neutron QoS。
- SR-IOV。
- LinuxBridge。
- 非 Aria-managed port。

## 18. 实施阶段

### Phase 1: Neutron 扩展骨架

目标：

- `aria_acl` service plugin 可加载。
- API extension 可被 `openstack extension list` 看到。
- DB migration 可执行。
- policy/rule/address-set/binding CRUD 可用。

验收：

- Neutron server 启动成功。
- API CRUD 测试通过。
- DB 表创建成功。
- 不影响现有 network/port/router API。

### Phase 2: RPC 与 agent full resync

目标：

- `neutron-aria-agent` 可注册 heartbeat。
- 可拉取本 host OVS tap ports。
- 可拉取 Aria ACL 对象。
- 可计算 effective ACL。

验收：

- agent alive。
- full resync 输出稳定。
- SR-IOV/LinuxBridge 被正确跳过。
- 未绑定 port 显示 bypass。

### Phase 3: aria-agent snapshot 接入

目标：

- UDS contract 固化。
- snapshot schema 固化。
- Rust apply skeleton 完成。
- WAL 和 status 接入。

验收：

- snapshot accepted。
- status 可查询。
- TCP OpenAPI 不暴露 Neutron UDS path。
- 本机写入 gate 生效。

### Phase 4: ACL datapath 生效

目标：

- group/address-set 编译。
- ACL rule 编译。
- eBPF map apply。
- ready/degraded/bypass 状态正确。

验收：

- allow/deny smoke 通过。
- rule update 实时生效。
- apply 失败不会中断 OVS 转发。

### Phase 5: Kolla 产品化

目标：

- neutron-server 镜像包含 plugin。
- neutron-aria-agent 镜像可部署。
- aria-agent 容器权限和挂载完成。
- 配置、日志、metrics、runbook 完成。

验收：

- 三节点部署 smoke。
- agent restart 恢复。
- tap recreate 恢复。
- 回滚流程通过。

## 19. OpenStack 配置示例

### 19.1 neutron.conf

```ini
[DEFAULT]
service_plugins = router,network_ip_availability,mirror,qos,aria_acl

[aria_acl]
enabled = true
admin_only = true
notify_agents = true
default_stateful = true
enforcement_enabled = true
```

### 19.2 neutron-aria-agent.ini

```ini
[DEFAULT]
host = ostack2.bj159.net
debug = false
report_interval = 30
full_resync_interval = 300

[aria]
socket_path = /run/aria/aria-agent.sock
contract_file = /etc/neutron-aria-agent/neutron-uds-contract.json
integration_mode = coexist
enable_acl = true
enable_qos = true

[ovs]
integration_bridge = br-int
ovsdb_connection = unix:/run/openvswitch/db.sock

[acl]
enforcement_enabled = true
unsupported_port_action = skip
default_unbound_action = bypass
```

### 19.3 policy.yaml

第一版 admin-only：

```yaml
"create_aria_acl_policy": "rule:admin_only"
"update_aria_acl_policy": "rule:admin_only"
"delete_aria_acl_policy": "rule:admin_only"
"get_aria_acl_policy": "rule:admin_only"
"create_aria_acl_rule": "rule:admin_only"
"update_aria_acl_rule": "rule:admin_only"
"delete_aria_acl_rule": "rule:admin_only"
"create_aria_acl_binding": "rule:admin_only"
"delete_aria_acl_binding": "rule:admin_only"
```

## 20. 产品边界总结

最终产品口径：

```text
Aria ACL 是 OpenStack Neutron 的独立 ACL enhancement 扩展。
它使用独立 API、独立 DB、独立 RBAC、独立 agent 同步和 Aria eBPF datapath 执行。
它不复用 Neutron Security Group，不做 Security Group projection，不展开 remote group，不依赖 port security。
它只增强普通 OVS tap port，不替代 OVS L2，不接管 SR-IOV 和 LinuxBridge。
QoS 不重造 API，复用 Neutron QoS policy/rule，由 Aria 执行。
```

这个路线比 tag + 本地 mapping 更适合产品化，因为 ACL 对象可审计、可回滚、可 RBAC、可 API 化，也能被 Horizon、Terraform、Heat 或平台编排系统长期集成。

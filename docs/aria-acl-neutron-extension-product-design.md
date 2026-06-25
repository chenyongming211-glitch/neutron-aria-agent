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
- Aria 只增强普通虚机 OVS tap 端口，SR-IOV、LinuxBridge 端口和 Neutron 服务端口不纳入 Aria ACL enforcement。

## 2. 目标环境约束

当前目标 OpenStack 环境的关键事实：

- 环境由现有产品部署，采用 Kolla 风格容器化 OpenStack。
- Neutron Server 镜像为 `neutron-server:2.0.6sp2`，不是上游原生镜像。
- Neutron Server 运行时为 Python 2，进程形态为 `/usr/bin/python2 /usr/bin/neutron-server`。
- Neutron 代码位于 `/usr/lib/python2.7/site-packages/neutron`，当前运行环境不应假设存在新版 `neutron-lib` 写法。
- `neutron.conf` 当前 `service_plugins = router,network_ip_availability,mirror`，未启用 `qos`。
- Neutron extension 当前未暴露 `qos`，只确认有 `binding`、`agent`、`rbac-policies` 等基础扩展。
- 镜像内已经存在 Neutron QoS 相关代码，包括 `neutron/extensions/qos.py`、`neutron/services/qos/qos_plugin.py`、`neutron/plugins/ml2/extensions/qos.py` 和 `neutron/agent/l2/extensions/qos.py`。
- `neutron-openvswitch-agent` 当前 `extensions = mirror`，未启用 `qos` agent extension。
- 业务 VM tap 口直接挂载到 OVS `br-int`。
- `br-int` 上的 tap interface 带有 `external_ids:iface-id=<neutron-port-id>`，可用于稳定建立 Neutron port 到 tap 的映射。
- 平台未启用 Neutron Security Group，`enable_security_group = False`。
- SR-IOV 端口可以不使用 Aria。
- LinuxBridge agent 存在，但业务侧几乎不使用。
- 当前没有 `qbr/qvo/qvb` hybrid 安全组端口链路。
- Neutron 仍然是网络配置唯一入口，Aria 不暴露独立租户 northbound。
- 宿主机已挂载 bpffs，`/sys/fs/bpf` 可用；`/sys/kernel/btf/vmlinux` 可读。
- 三台宿主机当前均缺少 `tc` 命令，QoS shaping 依赖必须单独补齐或降级为 eBPF policing。

### 2.1 真实环境探测摘要

探测时间：2026-06-15；2026-06-22 重新确认三节点 root 级只读证据
探测节点：`ostack2=10.58.159.2`、`ostack3=10.58.159.3`、`ostack4=10.58.159.4`

三台节点均可取得 root 级只读证据，结论如下：

| 项目 | 现场结果 | 对方案的影响 |
| --- | --- | --- |
| 操作系统 | 三台均为 kernel `4.18.0-553.5.1.el8_10.x86_64` | eBPF 能力需按该内核验证，不按新内核特性假设 |
| 部署形态 | Kolla 风格容器；三台均有 `neutron_openvswitch_agent`、`neutron_linuxbridge_agent`、`neutron_sriov_agent`、`nova_compute`；`ostack2`、`ostack3` 有 `neutron_server`；`ostack4` 为 compute/agent 侧 | ACL/QoS 能力必须进入产品镜像和 Kolla 配置；Neutron Server 扩展至少要覆盖控制节点容器 |
| Neutron 运行时 | neutron-server 使用 Python 2 | 插件实现必须兼容 Python 2 和当前 Neutron 代码结构 |
| Neutron 插件 | `service_plugins = router,network_ip_availability,mirror` | 当前没有 QoS API，也没有 Aria ACL，需要改 neutron-server 配置和镜像 |
| ML2 drivers | `openvswitch,linuxbridge,l2population,sriovnicswitch` | Aria 只接管普通虚机 OVS tap，SR-IOV/LinuxBridge/Neutron 服务端口标记 unsupported 或 not_applicable |
| ML2 type drivers | `vxlan,vlan,flat` | ACL/QoS 不改变 L2/VXLAN/VLAN 管理 |
| OVS agent | 三台均为 `integration_bridge = br-int`、`extensions = mirror`、`l2_population = True`、`enable_security_group = False` | Aria 可作为并行增强 agent；QoS 不应开启 OVS agent 执行后端 |
| Security Group | `enable_security_group = False` | ACL 不能走 SG projection，也不需要启用 SG |
| tap 形态 | `ostack2` 有 VM tap `tap86b83885-67` 直接挂在 `br-int`，带 `iface-id` 和 `vm-id`；`ostack3` 当前只有 DHCP 类 OVS internal tap；`ostack4` 当前 `br-int` 无 Neutron port | 端口发现路径成立，但 agent 必须按 host 和 port 类型过滤；无 eligible port 的节点应保持 idle/ready |
| QoS 代码 | 镜像中存在 Neutron QoS plugin/extension 代码，但未启用 | QoS 可复用现有模型，但需要启用 API/DB/extension，并接入 Aria 执行 |
| bpffs/BTF | 三台 `/sys/fs/bpf` 均已挂载，`/sys/kernel/btf/vmlinux` 均可读 | Aria datapath 基础条件较好 |
| `tc` | 三台宿主机均未找到 `tc` 命令 | QoS shaping 不能直接承诺；第一版 QoS 应优先 eBPF policing，或在产品镜像/宿主机补齐 iproute-tc 后再打开 shaping |
| SR-IOV | 三台均运行 SR-IOV agent，物理网卡存在 `sriov_totalvfs`，但 `physical_device_mappings` 为空且 `sriov_numvfs=0` | 当前环境未实际分配 SR-IOV VF；方案仍应把 SR-IOV direct port 标记 unsupported，不纳入第一阶段接管 |
| LinuxBridge | 三台均运行 LinuxBridge agent，但 `enable_vxlan=false`、安全组关闭，现场未发现 `qbr/qvb/qvo` 主路径 | 第一阶段仍不接管 LinuxBridge；service/bridge 端口必须跳过 |

### 2.2 基于现场事实的方案修正

本方案从本节开始以真实产品环境为基线，不再按“现代 Python 3 Neutron + neutron-lib”的默认假设编写实现任务。

必须修正的实现假设：

- `aria_acl` 插件必须兼容 Python 2。
- 插件应参考当前环境已有的 `neutron/extensions/qos.py` 和 `neutron/services/qos/qos_plugin.py` 的扩展风格。
- 不能默认依赖新版 `neutron-lib` API；如需使用，应先确认产品镜像内对应模块和版本。
- DB migration 必须接入当前 `neutron-db-manage` / alembic 分支体系，不能只给独立 SQL。
- Kolla 镜像构建是主路径；运行时 bind mount Python 文件只允许作为临时调试手段，不能作为产品交付路径。
- `neutron-aria-agent` 必须作为产品容器部署，不能假设宿主机直接安装 Python 包。
- QoS 先复用现场已有 Neutron QoS 代码，再新增 Aria notification/translator/enforcement，而不是重新定义 QoS API。

因此产品化 ACL 方案必须围绕下面的 port 选择条件设计：

```text
只接管：
  binding:host_id == 当前 compute host
  binding:vif_type == ovs
  binding:vnic_type 为 normal 或等价普通虚机端口
  device_owner 为空或以 compute: 开头
  OVS br-int 上存在 external_ids:iface-id=<neutron-port-id>

明确跳过：
  SR-IOV direct / direct-physical 端口
  LinuxBridge 端口
  OVN 端口
  network:dhcp、network:router_gateway、network:router_interface 等 Neutron 服务端口
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

在目标产品环境中，上述结构必须按 Python 2 兼容方式实现：

- 代码语法必须兼容 Python 2.7。
- 不能使用 Python 3 only 类型注解、f-string、dataclasses、async/await。
- oslo、sqlalchemy、alembic、oslo.versionedobjects 的用法必须以产品镜像内版本为准。
- extension 描述建议参考当前镜像中的 `/usr/lib/python2.7/site-packages/neutron/extensions/qos.py`。
- service plugin 建议参考当前镜像中的 `/usr/lib/python2.7/site-packages/neutron/services/qos/qos_plugin.py`。
- object/db 层建议先复用当前 Neutron 内部已有 pattern，而不是照搬新版 `neutron-lib` 示例。

入口注册：

```ini
[entry_points]
neutron.service_plugins =
    aria_acl = neutron_aria.services.aria_acl.plugin:AriaAclPlugin
```

如果目标 Neutron 的 service plugin manager 对 out-of-tree entrypoint 支持不稳定，可以使用产品镜像内置注册方式：

```text
方案 A：Python package entrypoint
  neutron.service_plugins:
    aria_acl = neutron_aria.services.aria_acl.plugin:AriaAclPlugin

方案 B：镜像内置别名
  在产品 Neutron 代码的 service plugin map 中加入 aria_acl -> class path

方案 C：配置直接使用完整 class path
  service_plugins = ...,neutron_aria.services.aria_acl.plugin.AriaAclPlugin
```

最终采用哪种方式必须以当前 `neutron-server:2.0.6sp2` 的启动验证为准。验收条件不是“代码能安装”，而是：

```text
neutron-server 启动成功
openstack extension list --network 能看到 aria-acl
aria_acl API CRUD 可用
现有 router/network_ip_availability/mirror 不受影响
```

启用配置：

```ini
# neutron.conf
service_plugins = router,network_ip_availability,mirror,qos,aria_acl,aria_qos
```

现场当前配置没有 `qos`，因此启用 `aria_acl` 时应分两步灰度：

```text
Step 1:
  service_plugins = router,network_ip_availability,mirror,aria_acl
  只验证 ACL API/DB/RPC/agent。

Step 2:
  service_plugins = router,network_ip_availability,mirror,qos,aria_acl,aria_qos
  再启用 Neutron 原生 QoS API/DB、Aria QoS facade，并接入 Aria QoS translator。
```

这样可以把 ACL 插件风险和 QoS 激活风险拆开。

### 4.2 neutron-aria-agent

职责：

- 注册为独立 Neutron agent。
- 订阅 port、network、Aria ACL、QoS 相关事件。
- 定期或按需执行 full resync。
- 只处理绑定到本 host 的普通虚机 OVS tap port。
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

### 5.6 Legacy `neutron` CLI 表达

目标产品环境是旧版 OpenStack，因此北向管理入口优先支持 Legacy `neutron` CLI，而不是只设计新版 `openstack network ...` 命令。

命令设计原则：

- `neutron` CLI 只是 Neutron REST API 的客户端封装，不直接访问 DB。
- CLI 命令名必须和 API 资源一一对应，便于排障时从命令反推 API 和 DB 表。
- ACL 对象使用独立命令族，不复用 `security-group-*` 命令。
- port/network 绑定使用 `aria-acl-binding-*` 命令表达，不修改 `binding:vif_type`、`binding:vnic_type` 等 ML2 绑定字段。
- CLI 第一版只开放 admin 使用；如果后续开放租户自服务，再按 policy.yaml 放开只读或写权限。
- 旧版环境仍可能习惯使用 `tenant_id`，CLI 应兼容 `--tenant-id`，服务端内部统一映射为 `project_id`。

extension 查询：

```bash
neutron ext-list | grep aria-acl
neutron ext-show aria-acl
```

policy 命令：

```bash
neutron aria-acl-policy-list
neutron aria-acl-policy-show <policy-id-or-name>
neutron aria-acl-policy-create \
  --name web-db-acl \
  --description "web to db acl" \
  --default-action allow \
  --stateful true
neutron aria-acl-policy-update <policy-id> --default-action deny
neutron aria-acl-policy-delete <policy-id>
```

rule 命令：

```bash
neutron aria-acl-rule-list --policy <policy-id-or-name>
neutron aria-acl-rule-show <rule-id>
neutron aria-acl-rule-create \
  --policy <policy-id-or-name> \
  --direction egress \
  --priority 100 \
  --action deny \
  --ethertype IPv4 \
  --protocol tcp \
  --dst-address-set <address-set-id-or-name> \
  --dst-port-min 3306 \
  --dst-port-max 3306
neutron aria-acl-rule-update <rule-id> --priority 90
neutron aria-acl-rule-delete <rule-id>
```

为了贴近安全组和 QoS 的使用习惯，`aria-acl-rule-create` 可以额外支持简写：

```bash
neutron aria-acl-rule-create \
  --policy <policy-id-or-name> \
  --direction egress \
  --priority 100 \
  --action deny \
  --protocol tcp \
  --dst-address-set db-subnets \
  --dst-port 3306
```

CLI 将 `--dst-port 3306` 展开成：

```text
dst_port_min = 3306
dst_port_max = 3306
```

address set 命令：

```bash
neutron aria-acl-address-set-list
neutron aria-acl-address-set-show <address-set-id-or-name>
neutron aria-acl-address-set-create \
  --name db-subnets \
  --description "database subnets" \
  --member 10.10.20.0/24 \
  --member 10.10.21.15/32
neutron aria-acl-address-set-member-add <address-set-id> 10.10.22.0/24
neutron aria-acl-address-set-member-remove <address-set-id> 10.10.21.15/32
neutron aria-acl-address-set-delete <address-set-id>
```

binding 命令：

```bash
neutron aria-acl-binding-list
neutron aria-acl-binding-list --policy <policy-id-or-name>
neutron aria-acl-binding-list --port <port-id>
neutron aria-acl-binding-list --network <network-id>
neutron aria-acl-binding-show <binding-id>
neutron aria-acl-binding-create --policy <policy-id-or-name> --port <port-id>
neutron aria-acl-binding-create --policy <policy-id-or-name> --network <network-id>
neutron aria-acl-binding-update <binding-id> --disable
neutron aria-acl-binding-update <binding-id> --enable
neutron aria-acl-binding-delete <binding-id>
```

运行态查询命令：

```bash
neutron aria-acl-port-status-show <port-id>
neutron aria-acl-effective-show --port <port-id>
```

`aria-acl-port-status-show` 面向运维排障，展示 agent 是否已经在本机 tap 上应用成功。`aria-acl-effective-show` 面向策略确认，展示某个 port 最终命中的 policy、rule、address set 展开结果和来源。

完整业务示例：

```bash
neutron aria-acl-policy-create --name web-db-acl --default-action allow --stateful true
neutron aria-acl-address-set-create --name db-subnets --member 10.10.20.0/24
neutron aria-acl-rule-create \
  --policy web-db-acl \
  --direction egress \
  --priority 100 \
  --action deny \
  --protocol tcp \
  --dst-address-set db-subnets \
  --dst-port 3306
neutron aria-acl-binding-create --policy web-db-acl --port <port-id>
neutron aria-acl-binding-list --port <port-id>
neutron aria-acl-port-status-show <port-id>
neutron port-show <port-id>
```

### 5.7 `neutron port-show` 只读摘要字段

Aria ACL 不应把策略字段塞进 Neutron 原生 `ports` 表，但可以把摘要字段扩展到 port API response，让旧版运维命令 `neutron port-show` 能看到 ACL 状态。

推荐在 `aria_acl` extension 中扩展 `ports` 资源的只读字段：

```text
aria_acl_enabled
aria_acl_effective_policy_id
aria_acl_effective_policy_name
aria_acl_effective_source
aria_acl_binding_id
aria_acl_effective_revision
aria_acl_runtime_status
aria_acl_runtime_host
aria_acl_runtime_reason
```

字段语义：

| 字段 | 类型 | 说明 |
| --- | --- | --- |
| `aria_acl_enabled` | bool | 是否存在 enabled 的 effective ACL policy |
| `aria_acl_effective_policy_id` | uuid/string | 当前 port 最终命中的 ACL policy |
| `aria_acl_effective_policy_name` | string | 当前 port 最终命中的 ACL policy 名称 |
| `aria_acl_effective_source` | enum | `port`、`network` 或 `none` |
| `aria_acl_binding_id` | uuid/string | 产生 effective policy 的 binding |
| `aria_acl_effective_revision` | int | policy、rule、address-set、binding 合成后的版本号 |
| `aria_acl_runtime_status` | enum | `not_requested`、`pending`、`applied`、`degraded`、`unsupported`、`unknown` |
| `aria_acl_runtime_host` | string | 最近上报该 port Aria 状态的 compute host |
| `aria_acl_runtime_reason` | string | 未生效、降级或跳过的原因 |

示例：

```bash
neutron port-show 2b7550c2-5378-41e9-a066-68008a35f532
```

预期输出增加：

```text
+------------------------------+--------------------------------------+
| Field                        | Value                                |
+------------------------------+--------------------------------------+
| id                           | 2b7550c2-5378-41e9-a066-68008a35f532 |
| binding:vif_type             | ovs                                  |
| binding:vnic_type            | normal                               |
| binding:host_id              | ostack3.bj159.net                    |
| aria_acl_enabled             | True                                 |
| aria_acl_effective_policy_id | 5a3f3b72-1f8e-43f9-87bb-711a99c5f2f1 |
| aria_acl_effective_source    | port                                 |
| aria_acl_binding_id          | 37bd7c9e-0a4f-48c3-b862-4f1c60b7a270 |
| aria_acl_effective_revision  | 18                                   |
| aria_acl_runtime_status      | applied                              |
| aria_acl_runtime_host        | ostack3.bj159.net                    |
| aria_acl_runtime_reason      |                                      |
+------------------------------+--------------------------------------+
```

实现要求：

- `aria_acl.py` extension 定义独立 ACL 资源，同时定义 `ports` 的 read-only extended attributes。
- `allow_post=False`、`allow_put=False`、`is_visible=True`，禁止用户通过 `port-create` 或 `port-update` 写入这些字段。
- `Ml2Plugin.get_port()` / `get_ports()` 或产品 Neutron 当前可用的 resource extend hook 负责填充这些字段。
- `get_ports()` 必须批量查询 binding/status，避免 port list 出现 N+1 DB 查询。
- 如果当前 Legacy `neutron` CLI 能原样打印服务端返回字段，则 `port-show` 无需单独改命令；如果客户端会过滤未知字段，则需要同步扩展 `python-neutronclient` 的 port resource field map。
- `port-show` 中的 Aria 字段只是摘要。权威 ACL 对象仍以 `aria-acl-policy-show`、`aria-acl-rule-list`、`aria-acl-binding-show`、`aria-acl-effective-show` 为准。

字段来源：

```text
aria_acl_enabled / effective_policy / binding:
  neutron-server 查询 aria_acl_bindings、aria_acl_policies 和 port/network 关系后动态计算。

aria_acl_runtime_status / host / reason:
  neutron-aria-agent 上报到 neutron-server 的 runtime status。

binding:vif_type / binding:vnic_type / binding:host_id:
  仍然由 ML2/Open vSwitch mechanism driver 和 Nova binding 流程维护，Aria 不更新这些字段。
```

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
aria_acl_port_statuses
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

### 6.8 `aria_acl_port_statuses`

`aria_acl_port_statuses` 用于保存 `neutron-aria-agent` 最近一次上报的 per-port 运行态，支撑 `neutron port-show` 的只读摘要和 `neutron aria-acl-port-status-show` 排障命令。

这张表不表达用户期望策略，只表达执行态。用户期望策略仍来自 `aria_acl_policies`、`aria_acl_rules`、`aria_acl_address_sets` 和 `aria_acl_bindings`。

```text
port_id                    UUID primary key
host                       String indexed not null
project_id                 String indexed nullable
network_id                 UUID indexed nullable
binding_id                 UUID nullable
effective_policy_id         UUID nullable
effective_source            Enum port/network/none not null
effective_revision          Integer nullable
runtime_status              Enum not_requested/pending/applied/degraded/unsupported/unknown not null
support_disposition         Enum supported/unsupported/not_applicable/unknown nullable
effective_action            Enum enforce/bypass/cleanup nullable
tap_name                   String nullable
ifindex                    Integer nullable
reason                     String nullable
last_applied_at             DateTime nullable
updated_at                 DateTime not null
```

索引：

```text
(host)
(network_id)
(effective_policy_id)
(runtime_status)
(updated_at)
```

更新方：

- `neutron-aria-agent` 在 full resync、port update、ACL binding update、apply success/failure 后上报。
- `aria_acl` service plugin 接收状态上报并写入该表。
- neutron-server 读取该表填充 `port-show` 的 `aria_acl_runtime_*` 字段。

清理规则：

- Neutron port 删除时删除对应 `aria_acl_port_statuses`。
- port 迁移到其它 host 后，新 host 上报会覆盖 `host`、`tap_name`、`ifindex` 和 runtime 状态。
- agent 长时间未上报时，`runtime_status` 不应继续显示为可靠 `applied`；查询层应结合 agent heartbeat 或 `updated_at` 标记为 `unknown` 或 `stale`。
- 该表不参与策略决策，不能用它反向推导是否应该启用 ACL。

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

每个 eligible VM port 最终只能得到一个 effective ACL policy：

```text
port-level binding > network-level binding > no binding
```

eligible VM port 必须同时满足 Port 过滤条件。特别是，network-level binding 只向该 network 下的 VM compute port 展开，不向 DHCP、router、metadata 等 Neutron 服务端口展开。

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

full resync 可以拉取本 host 全量 port，但进入 `effective_acl_by_port` 的只能是 eligible VM ports。Neutron 服务端口必须保留在 inventory/status 中用于解释 `not_applicable`，不能进入 ACL snapshot。

### 9.2.1 neutron-aria-agent 本地事务恢复

`neutron-aria-agent` 不能只依赖 Rust `aria-datapath` 的 WAL。Python agent 自己也必须持久化“已准备提交给 UDS、但尚未确认收敛”的本地事务状态，避免 agent 重启、VM 迁移、port delete 事件丢失时出现静默不一致。

本地事务状态必须包含：

```text
pending snapshot:
  generation
  desired_hash
  snapshot_ports
  projected_port_ids
  pending_since

pending delete:
  port_id
  reason = port_delete_event | migration_source_cleanup | operator_cleanup
  pending_since

last committed:
  last_generation
  last_desired_hash
  last_projected_port_ids
  last_deleted_port_id
  last_committed_at
```

启动或 full resync 前的恢复规则：

```text
if pending snapshot exists:
    read /api/v1/neutron/status
    if applied_generation >= pending_generation
       and applied_desired_hash == pending_desired_hash
       and managed_ports covers pending projected_port_ids:
           commit local snapshot state
           reuse the same generation for the same desired state
    elif applied_generation >= pending_generation
         and applied_desired_hash != pending_desired_hash:
           block resync, mark agent degraded, require operator/full-resync audit
    else:
           mark pending_snapshot_unresolved
           continue full resync with the pending generation when desired_hash matches

if pending delete exists:
    read /api/v1/neutron/status
    if port_id no longer appears in managed_ports:
        commit local delete state
    else:
        mark pending_delete_unresolved
        continue full resync so authoritative inventory can clean old host state
```

迁移场景必须按两个独立事务处理：

```text
old host:
  receives port.update with binding:host_id != local_host
  if port is locally projected:
      prepare_delete(reason=migration_source_cleanup)
      call UDS DELETE /ports/{port_id}
      commit only after delete success or status convergence

new host:
  receives full resync or local binding event
  prepare_snapshot
  apply eligible tap
  commit only after UDS status converges
```

`neutron-aria-agent` heartbeat/configurations 必须携带最近一次 UDS status 中的 `managed_ports` 和 `port_statuses`。后续 `neutron-server` 插件落地后，这些状态要写入 `aria_acl_port_statuses`，并按 `last_reported_at` 做 stale 判断；不能只靠 agent-level ready/degraded 表示每个 port 的 ACL 生效状态。

### 9.3 Port 过滤

agent 只处理满足条件的 port：

```text
port.binding_host_id == local_host
port.binding_vif_type == ovs
port.binding_vnic_type in ["normal", "", null]
port.device_owner is empty or port.device_owner startswith "compute:"
port.admin_state_up == true
OVS br-int interface external_ids:iface-id == port.id
```

现场 `neutron port-list` 已确认 DHCP port 也可能同时满足 `binding:vif_type=ovs` 和 `binding:vnic_type=normal`，例如 `device_owner=network:dhcp`。因此过滤条件不能只看 OVS 绑定字段，必须排除 Neutron 服务端口。

跳过端口需要写入 status：

| 场景 | support_disposition | 原因 |
| --- | --- | --- |
| SR-IOV direct | `unsupported` | Aria 不接管 SR-IOV datapath |
| LinuxBridge | `unsupported` | 当前只支持 OVS br-int tap |
| OVN | `unsupported` | 当前不支持 OVN |
| Neutron service port | `not_applicable` | DHCP、router、metadata 等服务端口不做 ACL enforcement |
| tap 未出现 | `unknown` 或 `not_applicable` | binding 未完成或迁移中 |
| 无 ACL binding | `not_applicable` | ACL 未请求 |

### 9.4 Effective ACL 计算

伪代码：

```python
def resolve_effective_acl(port):
    if not is_eligible_vm_port(port):
        return None

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

### 10.0 启动模式与自动 attach 边界

当前 Aria-agent 已有 standalone 能力，可以通过 `iface_pattern` 扫描并自动接管匹配的本机接口。这个能力适合单机测试、非 OpenStack 部署和实验室验证，但不能作为 OpenStack 产品模式的默认行为。

产品化必须显式区分两种模式：

```text
standalone:
  保留 iface_pattern 自动扫描。
  保留 netlink 新接口自动 attach。
  面向本地 ariactl / 单机部署 / 实验室验证。

neutron_managed:
  默认 auto_attach = false。
  不根据 iface_pattern 扫描并接管所有 tap。
  不根据 netlink 事件自动接管新 tap。
  只接管 neutron-aria-agent 通过 Unix socket snapshot 明确声明的 port。
```

推荐产品配置：

```toml
mode = "neutron_managed"
auto_attach = false
iface_pattern = "^$"
neutron_socket_path = "/run/aria/aria-agent.sock"
```

在 `neutron_managed` 模式下，aria-agent attach 前必须校验：

- snapshot 中声明的 Neutron `port_id`。
- snapshot 中声明的 ifname。
- 当前 ifindex。
- OVSDB `external_ids:iface-id == port_id`。
- `neutron-aria-agent` 已判定该 port 是 supported VM OVS tap。

因此，即使宿主机存在多个 `tap*`，aria-agent 也不能自行 attach。没有进入 snapshot 的 DHCP、router、metadata、LinuxBridge、SR-IOV、临时测试 tap 或未知 tap，必须保持 untouched，只通过 status 解释为 `not_applicable`、`unsupported` 或 `unknown`。

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

#### 10.2.1 ACL gate-first apply 与崩溃安全

Neutron-managed ACL 的数据面 apply 必须避免暴露“半写入”的 eBPF map 状态。对一个被 Neutron 接管的 VM tap port，ACL apply 顺序固定为：

```text
1. WAL snapshot intent 已经写入
2. 将该 port 的 ACL runtime gate 设置为 disabled / bypass
3. 清理旧的 Neutron-owned ACL groups / policies
4. 写入本次翻译后的 ACL address groups
5. 写入本次翻译后的 ACL policies
6. 按需 flush 该 port 的 conntrack
7. 将该 port 的 ACL runtime gate 设置为 enabled
8. 写入 WAL commit 和最终 per-port / per-domain status
```

如果 Rust 进程在步骤 2 到步骤 7 之间退出，该 port 必须保持 `bypass`，不能执行半套 ACL。下一次 full resync 可以重放同一个 desired state 或更高 generation，但只有 ACL gate 重新 enabled 且 WAL commit/status 持久化后，才能报告该 domain 为 `ready`。

崩溃验证必须使用确定性的 fault-injection 点，而不是随机 kill 进程。测试专用 fault point 包括：

```text
neutron.snapshot.after_intent
neutron.port.after_attach
neutron.acl.after_disable
neutron.acl.after_purge
neutron.acl.after_group_write
neutron.acl.after_policy_write
neutron.acl.before_enable
neutron.acl.after_enable_before_commit
neutron.snapshot.before_commit
neutron.snapshot.after_commit
neutron.delete.after_intent
neutron.delete.after_acl_purge
neutron.delete.after_detach_before_commit
```

fault injection 默认关闭，只能通过 datapath 本机测试配置或环境变量显式打开，不能暴露成租户 API 或 Neutron northbound API。

进程级 kill 类测试必须配置一次性 marker，例如 `ARIA_FAULT_ONCE_FILE=/run/aria/fault.once`。触发点在执行故障动作前先原子创建 marker，容器重启后如果 marker 已存在就跳过同一故障点。这样可以稳定验证“第一次 apply 中途崩溃、重启后 replay/full-resync 恢复”，不会因为同一个环境变量在 `--restart unless-stopped` 容器里反复触发而形成重启循环。

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

目标产品环境当前使用 `neutron-server:2.0.6sp2`，Neutron Server 在容器内以 Python 2 运行。因此 `aria_acl` 不能只作为外部文档中的抽象插件存在，必须构建进产品镜像。

需要打入：

```text
neutron_aria Python 2 package
aria_acl service plugin entrypoint
DB migration
policy rules
config sample
```

镜像内文件建议：

```text
/usr/lib/python2.7/site-packages/neutron_aria/
/usr/lib/python2.7/site-packages/neutron_aria/extensions/aria_acl.py
/usr/lib/python2.7/site-packages/neutron_aria/services/aria_acl/plugin.py
/usr/lib/python2.7/site-packages/neutron_aria/db/aria_acl/
/usr/lib/python2.7/site-packages/neutron_aria/policies/aria_acl.py
```

如果产品团队更倾向把代码放入现有 `neutron` namespace，也可以采用：

```text
/usr/lib/python2.7/site-packages/neutron/extensions/aria_acl.py
/usr/lib/python2.7/site-packages/neutron/services/aria_acl/plugin.py
/usr/lib/python2.7/site-packages/neutron/db/aria_acl/
```

二者选择原则：

| 方式 | 优点 | 风险 |
| --- | --- | --- |
| 独立 `neutron_aria` namespace | 边界清晰，便于单独打包和回滚 | 需要确认当前 stevedore/pkg_resources entrypoint 加载正常 |
| 放入 `neutron` namespace | 更贴合当前 Python2 老 Neutron 写法 | 更像 fork Neutron，升级冲突更明显 |

正式产品建议优先选择独立 `neutron_aria` namespace；如果启动验证发现 entrypoint 兼容性问题，再退回内置 alias 或完整 class path。

配置：

```ini
# /etc/kolla/neutron-server/neutron.conf
[DEFAULT]
service_plugins = router,network_ip_availability,mirror,qos,aria_acl,aria_qos

[aria_acl]
enabled = true
default_admin_only = true
notify_agents = true
```

当前现场没有启用 QoS，因此 ACL 镜像灰度建议先不同时启用 QoS：

```ini
# ACL-only first rollout
[DEFAULT]
service_plugins = router,network_ip_availability,mirror,aria_acl
```

待 ACL API/DB/RPC/agent 验证完成后，再启用 QoS：

```ini
# ACL + QoS rollout
[DEFAULT]
service_plugins = router,network_ip_availability,mirror,qos,aria_acl,aria_qos
```

DB migration 要求：

- migration 必须通过 `neutron-db-manage` 跑通。
- migration 分支必须兼容当前环境的两个 head：`4af11ca47297` 和 `2948f8b16a0c`。
- 不能在生产首次升级时直接手工建表。
- 回滚时默认保留表和历史数据，只关闭 service plugin 和 enforcement。

上线前镜像验收：

```text
docker exec neutron_server python2 -c "import neutron_aria"
neutron-server --config-file ... 启动成功
openstack extension list --network 显示 aria-acl
现有 router/network_ip_availability/mirror API 正常
neutron-db-manage current 正常
```

### 12.2 neutron-aria-agent 镜像

容器职责：

```text
Python 2 compatible Neutron adapter
RPC consumer
full resync
UDS client
heartbeat reporter
```

挂载：

```text
/etc/kolla/neutron-aria-agent/
/run/aria/
/var/lib/neutron-aria-agent/
```

在当前产品环境中，还需要读取或挂载 Neutron 配置：

```text
/etc/kolla/neutron-openvswitch-agent/openvswitch_agent.ini
/etc/kolla/neutron-server/neutron.conf 或等价 oslo messaging 配置
```

权限：

- 需要访问 Neutron RPC 配置。
- 需要访问 `/run/aria/aria-agent.sock`。
- 不需要 `/sys/fs/bpf`。
- 不需要 eBPF capability。
- 不需要 `/run/openvswitch`。
- 不需要特权容器。

产品边界修正：

- `neutron-aria-agent` 只消费 Neutron 逻辑状态，生成候选 port snapshot。
- `neutron-aria-agent` 不直接读 OVSDB，不判断本机 tap 是否真实在 `br-int` 上。
- 本地 OVS/tap/ifindex 校验下沉到 `aria-agent / aria-datapath`，通过 UDS response 返回 structured result。
- 当前 root + OVSDB full-resync smoke 仅用于验证旧契约可行性，不能作为最终产品形态。

端口身份校验必须以现场验证过的 OVSDB external_ids 为主，但执行位置在 `aria-datapath`：

```text
ovs-vsctl list Interface <tap>
external_ids:iface-id=<neutron-port-id>
external_ids:attached-mac=<mac>
external_ids:iface-status=active
```

不要依赖 Linux `ip link` 一定能看到所有 OVS internal tap；现场已经观察到部分 tap 是 OVS internal 类型。

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
```

三节点部署注意：

- `ostack2`、`ostack3`、`ostack4` 已验证 root 级只读信息。
- 三台 OVS agent 配置一致：`integration_bridge=br-int`、`extensions=mirror`、`enable_security_group=False`。
- 三台均已挂载 bpffs 且 BTF 可读。
- 三台宿主机当前均缺少 `tc` 命令，QoS shaping 不能作为第一阶段默认承诺。
- `ostack2` 当前存在 eligible VM OVS tap；`ostack3` 当前只有 DHCP 类 OVS internal port；`ostack4` 当前没有 br-int Neutron port。
- 上线前必须给 `aria-datapath` 容器足够权限读取 OVSDB/访问 tap，不依赖 SSH 受限命令。
- 三台 compute 的 agent 配置、镜像 tag 和 socket 权限必须一致。

### 12.3 aria-agent 容器

aria-agent 容器职责：

```text
eBPF program load/attach
WAL
runtime status
Unix socket server
ACL/QoS apply
metrics
OVS/tap identity validation
```

需要权限：

- host network 或足够的 net admin 能力。
- `/sys/fs/bpf`。
- `/run/aria`。
- `/var/lib/aria-agent`。
- `/run/openvswitch` 或等价 OVSDB 访问能力。
- 访问 tap interface 和 netlink。

现场已确认 `ostack2` 有 bpffs 和 BTF：

```text
bpf on /sys/fs/bpf type bpf
/sys/kernel/btf/vmlinux readable
```

但仍需补齐：

- `/run/aria` 目录、用户组和 socket 权限。
- `/var/lib/aria-agent` 持久化目录。
- `tc` 或等价 QoS shaping 依赖。
- `bpftool` 是否作为排障工具进入镜像或宿主机。

### 12.4 Legacy `neutron` CLI 交付

旧版 OpenStack 环境下，服务端 extension 可用不代表 `neutron` 命令自动可用。产品化交付必须同时包含 Legacy CLI 扩展。

交付位置：

```text
neutron-server 镜像:
  提供 aria_acl REST API、DB、RPC、policy。

运维节点 / toolbox / controller CLI 环境:
  提供 neutron aria-acl-* 命令。

Horizon 或平台后端:
  如需页面集成，调用同一组 Neutron REST API。
```

客户端包建议：

```text
python-neutronclient-aria
```

或合并进产品当前的 `python-neutronclient` 派生包。

需要新增的客户端能力：

```text
neutron aria-acl-policy-*
neutron aria-acl-rule-*
neutron aria-acl-address-set-*
neutron aria-acl-binding-*
neutron aria-acl-port-status-show
neutron aria-acl-effective-show
```

如果 `neutron port-show` 无法自动显示服务端返回的 `aria_acl_*` 字段，还必须扩展客户端 port resource 的显示字段，确保旧版运维习惯可用：

```bash
neutron port-show <port-id>
```

能看到：

```text
aria_acl_enabled
aria_acl_effective_policy_id
aria_acl_effective_source
aria_acl_runtime_status
aria_acl_runtime_reason
```

CLI 验收条件：

```text
neutron ext-show aria-acl 成功
neutron aria-acl-policy-create/list/show/delete 成功
neutron aria-acl-rule-create/list/show/delete 成功
neutron aria-acl-address-set-create/member-add/member-remove/show 成功
neutron aria-acl-binding-create/list --port/delete 成功
neutron aria-acl-effective-show --port <port-id> 能展示 effective policy
neutron aria-acl-port-status-show <port-id> 能展示 runtime status
neutron port-show <port-id> 能展示 aria_acl_* 只读摘要字段
```

兼容性要求：

- CLI 必须兼容 Python 2 运行环境。
- 命令参数必须支持 UUID；名称解析可以作为便利能力，但不能代替 UUID。
- `--tenant-id` 和 `--project-id` 至少支持一种；推荐两者都支持，内部统一为 `project_id`。
- CLI 不保存本地状态，不缓存 policy，不直接调用 `aria-agent`。
- CLI 错误信息必须保留 Neutron request id，便于和 neutron-server 日志关联。

## 13. Security Group 与 Aria ACL 流程对比

### 13.1 OpenStack 默认 Security Group 开发流程

OpenStack Security Group 是 Neutron 原生 port security 体系的一部分，不是一个与数据面解耦的普通 service plugin。开启 Security Group 后，开发和执行链路通常如下：

```text
Neutron API extension
  security-groups / security-group-rules
        |
Neutron DB / Object
  securitygroups
  securitygrouprules
  securitygroupportbindings
        |
ML2 port create/update
  port.security_groups
  port_security_enabled
        |
RPC 通知 L2 agent
        |
neutron-openvswitch-agent / neutron-linuxbridge-agent
        |
firewall_driver
  OVSHybridIptablesFirewallDriver / OVS firewall driver / LinuxBridge iptables driver
        |
iptables、OVS flow 或 conntrack 生效
```

默认 Security Group 开发会涉及：

- Neutron 原生 API extension：`security-groups`、`security-group-rules`。
- Neutron 原生 DB：security group、security group rule、port binding。
- Neutron port 字段：`security_groups`、`port_security_enabled`。
- ML2 plugin 与 L2 agent 的 RPC 通知。
- `neutron-openvswitch-agent` 或 `neutron-linuxbridge-agent`。
- firewall driver，例如 hybrid iptables 或 OVS native firewall。
- remote group、port security、anti-spoof 等原生安全组语义。

在 hybrid iptables driver 下，Security Group 可能引入：

```text
tap -> qbr -> qvb/qvo -> br-int
```

而当前目标环境没有启用 Security Group，也没有 `qbr/qvo/qvb` 作为主路径，因此 Aria ACL 不应该回到这条链路。

### 13.2 OpenStack 默认 Security Group 业务流程

用户视角的默认 Security Group 流程如下：

```text
创建 project
        |
Neutron 创建 default security group
        |
创建 VM / port
        |
如果用户没有显式指定 security group
        |
Neutron 自动绑定 default security group
        |
用户添加 allow rule
        |
Neutron Server 保存 security group rule
        |
Neutron Server 找到绑定该 security group 的 ports
        |
Neutron Server RPC 通知对应 compute L2 agent
        |
L2 agent 调用 firewall driver
        |
iptables / OVS flow / conntrack 生效
```

典型业务语义：

```text
ingress:
  未显式 allow 时默认不允许进入 VM。

egress:
  默认通常允许出方向。

default security group:
  port 创建时可能自动绑定。

rule model:
  主要表达 allow rule。
```

因此默认 Security Group 更像是：

```text
每个 port 自动带一个安全边界。
没有允许规则就进不来。
用户通过增加 allow rule 放通流量。
```

### 13.3 Aria ACL 开发流程

Aria ACL 是独立 Neutron ACL enhancement，不复用 Security Group。它的 northbound 入口仍然是 Neutron Server，不允许绕过 Neutron 直接创建 OpenStack 托管 ACL。

开发链路如下：

```text
Neutron API extension
  aria-acl-policies
  aria-acl-rules
  aria-acl-address-sets
  aria-acl-bindings
        |
aria_acl service plugin
        |
Aria ACL DB / Object
  aria_acl_policies
  aria_acl_rules
  aria_acl_address_sets
  aria_acl_address_set_members
  aria_acl_bindings
        |
RPC / notification / full resync API
        |
neutron-aria-agent
        |
OVSDB port discovery
  br-int interface external_ids:iface-id=<neutron-port-id>
        |
per-port ACL snapshot
        |
aria-agent Unix socket
  /run/aria/aria-agent.sock
        |
Aria eBPF map apply
        |
tap 上 ACL 生效
```

开发对象包括：

- `aria_acl_policy`
- `aria_acl_rule`
- `aria_acl_address_set`
- `aria_acl_binding`
- `neutron-aria-agent`
- `aria-agent` Neutron snapshot UDS API
- Aria eBPF ACL apply/status/WAL

明确不开发：

- Security Group projection。
- remote group 展开。
- port security enforcement。
- allowed address pairs enforcement。
- anti-spoof。
- hybrid iptables `qbr/qvb/qvo` 链路。

### 13.4 Aria ACL 业务流程

Aria ACL 的准确业务流程如下：

```text
管理员 / 平台调用 Neutron API 创建 Aria ACL policy
        |
Neutron Server 写 aria_acl_policies DB
        |
管理员 / 平台调用 Neutron API 创建 Aria ACL rule / address-set
        |
Neutron Server 写 aria_acl_rules / aria_acl_address_sets DB
        |
管理员 / 平台调用 Neutron API 绑定 policy 到 network 或 port
        |
Neutron Server 写 aria_acl_bindings DB
        |
Neutron Server 发 RPC / notification
        |
neutron-aria-agent 收到事件或执行 full resync
        |
neutron-aria-agent 找到本机 OVS tap port
        |
neutron-aria-agent 生成 per-port ACL snapshot
        |
neutron-aria-agent 通过 /run/aria/aria-agent.sock 下发给 aria-agent
        |
aria-agent 写 eBPF map
        |
tap 上 ACL 生效
```

这条流程的关键点：

- Aria ACL 的 northbound 入口是 Neutron Server。
- 管理员或平台通过 Neutron API 创建 ACL 对象。
- `aria-agent` 不提供租户 northbound。
- `neutron-aria-agent` 不直接接受租户请求。
- `aria-agent` 不访问 Neutron DB，也不判断租户权限。
- 未绑定 Aria ACL 的 port 保持 bypass。
- ACL apply 失败时对应 port `degraded + bypass`，不破坏 OVS 原有转发。

### 13.5 Security Group 与 Aria ACL 业务差异

| 项目 | OpenStack Security Group | Aria ACL |
| --- | --- | --- |
| northbound 入口 | Neutron Server | Neutron Server |
| API 对象 | `security_group`、`security_group_rule` | `aria_acl_policy`、`aria_acl_rule`、`aria_acl_address_set`、`aria_acl_binding` |
| 是否自动绑定 | port 可能自动绑定 default SG | 不自动绑定，必须显式绑定 |
| 未配置时行为 | 受 default SG 影响 | `not_requested + bypass` |
| 规则语义 | 主要是 allow-list | 支持显式 allow / deny |
| remote group | 支持 | 当前不支持 |
| port security | 强相关 | 不消费 |
| anti-spoof | 相关 | 当前不实现 |
| 执行 agent | OVS/LinuxBridge L2 agent | `neutron-aria-agent` + `aria-agent` |
| 数据面 | iptables / OVS firewall | Aria eBPF |
| hybrid bridge | 可能出现 `qbr/qvo/qvb` | 不引入 |
| 失败策略 | 原生安全组语义 | degraded + bypass，保护 OVS 原有转发 |

一句话：

```text
Aria ACL 的 northbound 入口是 Neutron Server；
只是它不复用 Security Group 的 default SG 自动绑定机制。
```

## 14. 变更流程

### 14.1 创建 ACL 策略

```text
1. admin / 平台调用 Neutron API: POST /v2.0/aria-acl-policies。
2. neutron-server 写 aria_acl_policies。
3. admin / 平台调用 Neutron API: POST /v2.0/aria-acl-rules。
4. neutron-server 写 aria_acl_rules。
5. admin / 平台调用 Neutron API: POST /v2.0/aria-acl-bindings。
6. neutron-server 写 aria_acl_bindings。
7. aria_acl plugin 发送 binding update notification。
8. 对应 host 的 neutron-aria-agent 发现 affected port。
9. agent 计算 effective ACL。
10. agent 下发 snapshot。
11. aria-agent apply。
12. agent 上报 status。
```

### 14.2 更新 ACL 规则

```text
1. admin / 平台通过 Neutron API 更新 rule。
2. neutron-server 增加 rule revision。
3. plugin 发送 rule update notification。
4. agent 找出绑定该 policy 的 ports。
5. agent 合并短时间连续事件。
6. agent 拉取最新 policy/rules/address sets。
7. agent 重算 affected ports。
8. agent 下发 port-scoped snapshot。
```

### 14.3 删除绑定

```text
1. admin / 平台通过 Neutron API 删除 aria_acl_binding。
2. agent 收到 binding delete。
3. agent 重算 port effective ACL。
4. 如果没有 network-level binding，该 port 进入 not_requested + bypass。
5. aria-agent 清理该 port ACL maps。
6. OVS 转发保持原状。
```

### 14.4 Port 迁移

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

## 15. 错误处理与状态

### 15.1 Domain Status

ACL domain 使用结构化状态：

| DomainStatus | effective_action | 场景 |
| --- | --- | --- |
| `ready` | `enabled` | policy 编译和 apply 成功 |
| `not_requested` | `bypass` | port 没有 ACL binding |
| `degraded` | `bypass` | policy/rule/address-set 错误 |
| `degraded` | `bypass` | conntrack 不可用但 stateful=true |
| `degraded` | `bypass` | tap identity 不稳定 |
| `blocked` | `unchanged` | WAL 或 schema 严重错误，无法安全 apply |

### 15.2 错误码

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

### 15.3 告警

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

## 16. 与 QoS 的关系

ACL 和 QoS 必须分层：

```text
ACL:
  新增 aria_acl service plugin
  新增 API/DB/RBAC/RPC
  不复用 Security Group

QoS:
  产品入口统一叫 aria-qos
  复用 Neutron QoS service plugin
  复用 Neutron QoS policy/rule/binding
  不复用 qhqos / qcloud floating IP QoS
  neutron-aria-agent 增加 QoS translator
  aria-agent 执行 eBPF QoS
```

QoS 不应该放进 `aria_acl` plugin。

原因：

- Neutron 已有成熟 QoS API/DB。
- ACL 是新产品语义，QoS 是已有 Neutron 语义。
- 分开后可以独立灰度、独立回滚、独立排障。

### 16.1 现场 QoS 基线

真实环境中，QoS 当前状态是：

| 项目 | 结果 |
| --- | --- |
| `service_plugins` | 未包含 `qos` |
| Neutron extension list | 未暴露 `qos` |
| neutron-server 镜像内 QoS 代码 | 已存在 |
| ML2 QoS extension driver | 代码存在，配置未启用 |
| OVS agent QoS extension | 代码存在，配置未启用 |
| 当前 OVS agent extensions | `mirror` |
| 宿主机 `tc` | 三台宿主机均未找到 `tc` 命令 |
| `qhqos` 定制扩展 | 代码和 Legacy CLI 命令存在，但服务端未启用 |

因此 QoS 路线不是“重新开发 QoS API”，而是“启用已有 Neutron QoS API/DB，并新增 Aria 执行路径”。

`qhqos` 不纳入 Aria QoS 基础模型。线上镜像里的 `qhqos` 是 `qcloud/qos` 定制扩展，服务端入口为 `neutron.services.qcloud.qos.plugin:QhQoSPlugin`，API path 为 `/qcloud/qos/qhqos-policies`，DB 表为 `qhqos_rules`，字段围绕 `floating_ip_id`、`floating_ip`、`router_id`、`gw_port_id`、`upload_bandwidth`、`download_bandwidth`。当前产品场景不使用 Floating IP、Router、网关 QoS，因此它不适合承担普通 VM OVS tap 的 Aria QoS 模型。

### 16.2 QoS 启用配置

Neutron Server 侧：

```ini
# /etc/kolla/neutron-server/neutron.conf
[DEFAULT]
service_plugins = router,network_ip_availability,mirror,qos,aria_acl,aria_qos
```

ML2 侧：

```ini
# /etc/kolla/neutron-server/ml2_conf.ini
[ml2]
extension_drivers = qos
```

是否还需要保留其它 extension driver，要以当前产品配置为准。如果当前为空，则只加 `qos`；如果已有其它 extension driver，则追加而不是覆盖。

OVS agent 侧不建议启用标准 QoS 执行：

```ini
# /etc/kolla/neutron-openvswitch-agent/openvswitch_agent.ini
[agent]
extensions = mirror
```

不要改成：

```ini
extensions = mirror,qos
```

除非明确要让 OVS agent 执行 QoS。当前 Aria 方案要求避免 OVS QoS 和 Aria QoS 双重 enforcement。

### 16.3 Aria QoS 产品入口

为保持产品命名一致，对外入口统一为：

| 能力 | 产品入口 | 底层模型 |
| --- | --- | --- |
| ACL | `aria-acl` | Aria 独立 ACL DB/API |
| QoS | `aria-qos` | Neutron 原生 QoS DB/API，Aria 执行 |
| Mirror | `aria-mirror` | Aria 独立 Mirror DB/API |

`aria-qos` 不是重新造一套 QoS DB。它是产品 facade：

```text
用户看到:
  neutron aria-qos-policy-create
  neutron aria-qos-bandwidth-limit-rule-create
  neutron aria-qos-port-bind
  neutron aria-qos-status-show

底层写入:
  Neutron 原生 qos_policies
  Neutron 原生 qos_bandwidth_limit_rules
  Neutron 原生 port/network qos_policy_id binding

Aria 侧新增:
  aria_qos_port_statuses
  aria-qos runtime status / capability / degraded reason
```

因此产品 CLI 建议：

```bash
neutron aria-qos-policy-create web-limit

neutron aria-qos-bandwidth-limit-rule-create \
  web-limit \
  --max-kbps 100000 \
  --max-burst-kbps 10000

neutron aria-qos-port-bind \
  --port $PORT_ID \
  --policy web-limit

neutron aria-qos-status-show \
  --port $PORT_ID
```

这些命令的实现方式：

```text
aria-qos-policy-*:
  调用/代理 Neutron 原生 QoS policy API。
  不创建 aria_qos_policies 表。

aria-qos-bandwidth-limit-rule-*:
  调用/代理 Neutron 原生 QoS bandwidth limit rule API。
  不创建 aria_qos_rules 表。

aria-qos-port-bind / network-bind:
  更新原生 port/network 的 qos_policy_id。

aria-qos-status-show:
  读取 aria_qos_port_statuses 和 aria-agent runtime stats。
```

服务端 extension 建议：

```text
qos:
  必须启用。提供原生 QoS policy/rule/binding API 和 DB。

aria-qos:
  必须启用。提供 Aria QoS capability/status API，并声明该环境 QoS 执行后端为 Aria。
  依赖 qos 已启用；如果 qos 未启用，aria-qos plugin 启动应失败或进入 disabled。
```

对外推荐只使用 `aria-qos-*` 作为产品入口；原生 `qos-*` 命令保留为兼容入口，不作为产品主文档入口。

### 16.4 Aria QoS notification / translator

QoS plugin 已有 notification driver manager。产品化时推荐新增 Aria QoS notification driver 或由 `neutron-aria-agent` 通过 full resync + RPC 监听获取 QoS 状态。

推荐优先级：

```text
首选：
  使用 Neutron QoS 原生 policy/rule DB 和绑定关系。
  neutron-aria-agent full resync 拉取 effective QoS。
  通过 QoS policy/rule/network/port 事件触发增量重算。

可选增强：
  新增 Aria QoS notification driver，只负责通知 neutron-aria-agent。
  不在 notification driver 中直接操作 OVS 或 eBPF。
```

QoS effective policy 计算：

```text
port-level QoS policy > network-level QoS policy > no QoS
```

第一版支持：

```text
bandwidth_limit_rule
  max_kbps
  max_burst_kbps
  direction
```

第一版明确 unsupported：

```text
dscp_marking
minimum_bandwidth
minimum_packet_rate
packet_rate_limit
```

unsupported rule 必须进入 status，不允许静默忽略后宣称 QoS ready。

### 16.5 QoS 执行后端

Aria QoS 执行必须满足：

- `neutron-server` 保存 QoS policy/rule。
- `neutron-aria-agent` 翻译 QoS 为 per-port snapshot。
- `aria-agent` 写 eBPF QoS map。
- OVS agent 不执行同一端口 QoS。

如果 `tc` 不可用：

```text
policing:
  可以作为第一阶段可行路径，前提是 Aria eBPF 不依赖 tc。

shaping:
  不得直接承诺 ready。
  必须安装/验证 tc 或提供等价实现。
  未满足时返回 QOS_SHAPING_UNAVAILABLE 或 QOS_SHAPING_FALLBACK。
```

QoS 失败隔离：

```text
QoS apply 失败:
  qos domain degraded/blocked
  ACL domain 不受影响
  OVS L2 forwarding 不受影响
```

### 16.6 QoS 产品化验收

QoS 进入生产 smoke 前必须完成：

- `openstack extension list --network` 能看到 `qos`。
- `neutron ext-show aria-qos` 成功。
- `neutron aria-qos-policy-*` facade 命令可用。
- QoS policy/rule CRUD 通过。
- port/network QoS binding 生效。
- `neutron-aria-agent` 能计算 per-port effective QoS。
- 不启用 OVS agent `qos` execution，或证明不会双重限速。
- bandwidth limit 在 tap 上可观察。
- 删除 QoS policy 后 eBPF token bucket / map entry 清理。
- QoS 失败不影响 ACL。
- `qhqos-policy-*` 不作为 Aria QoS 路线入口。

## 17. 测试方案

### 17.1 Neutron Server 单元测试

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
- port response 只读扩展字段填充。
- port response 只读字段禁止 create/update 写入。
- `aria_acl_port_statuses` 写入、覆盖和 stale 判断。

### 17.2 Neutron DB migration 测试

覆盖：

- 新建所有表。
- downgrade 或回滚策略。
- 索引存在。
- foreign key 存在。
- unique 约束有效。
- `aria_acl_port_statuses` 随 port 删除清理。
- migration 后 `neutron-db-manage current` 正常。

### 17.3 Legacy `neutron` CLI 测试

覆盖：

- `neutron ext-show aria-acl`。
- `neutron aria-acl-policy-create/list/show/update/delete`。
- `neutron aria-acl-rule-create/list/show/update/delete`。
- `neutron aria-acl-address-set-create/member-add/member-remove/show/delete`。
- `neutron aria-acl-binding-create/list --port/list --network/show/update/delete`。
- `neutron aria-acl-effective-show --port <port-id>`。
- `neutron aria-acl-port-status-show <port-id>`。
- `neutron port-show <port-id>` 显示 `aria_acl_*` 只读摘要字段。
- CLI 在 Python 2 环境可运行。
- CLI 错误输出保留 Neutron request id。

### 17.4 RPC 测试

覆盖：

- policy update notification。
- rule update notification。
- binding update notification。
- port runtime status 上报。
- event merge。
- stale revision 丢弃。
- RPC 断开后 full resync。

### 17.5 neutron-aria-agent 单元测试

覆盖：

- host port 过滤。
- OVS tap 映射。
- SR-IOV skip。
- LinuxBridge skip。
- Neutron service port skip。
- port-level binding 覆盖 network-level binding。
- 未绑定 port bypass。
- address set 展开。
- stateful conntrack required。
- snapshot generation 单调递增。
- UDS contract drift。
- runtime status 上报。
- port 迁移后旧 host cleanup、新 host apply。

### 17.6 aria-agent Rust 测试

覆盖：

- Neutron snapshot DTO serde。
- UDS route 不进入 TCP OpenAPI。
- ACL snapshot apply。
- WAL intent/commit/replay。
- degraded+bypass。
- local write blocked。
- delete port cleanup。
- capability mismatch。

### 17.7 目标环境 smoke

必须覆盖：

```text
产品镜像:
  neutron-server:2.0.6sp2 派生镜像可启动
  python2 import neutron_aria 成功
  aria-acl extension 可见

Legacy neutron CLI:
  neutron ext-show aria-acl 成功
  neutron aria-acl-policy-create/list/show 成功
  neutron aria-acl-rule-create/list/show 成功
  neutron aria-acl-binding-create/list --port 成功
  neutron aria-acl-effective-show --port 成功
  neutron aria-acl-port-status-show 成功
  neutron port-show 显示 aria_acl_* 只读摘要字段

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

Neutron service port:
  network:dhcp / network:router_* 即使是 ovs normal tap，也显示 not_applicable，不进入 ACL snapshot

DHCP / metadata / ARP / IPv6 ND:
  无显式 ACL 时不被误伤

QoS extension:
  启用 qos 后 openstack extension list --network 可见
  QoS policy/rule CRUD 成功
  port/network QoS binding 可被 neutron-aria-agent 解析

QoS enforcement:
  OVS agent 不启用 qos execution
  Aria bandwidth limit 可观察
  tc 缺失时 shaping 返回 degraded/unsupported，不宣称 ready
```

### 17.8 三节点一致性检查

2026-06-22 已可登录 `ostack3`、`ostack4` 并完成 root 级只读确认。正式部署 smoke 仍必须通过容器和自动化脚本完成三节点一致性检查：

| 检查项 | ostack2 | ostack3 | ostack4 |
| --- | --- | --- | --- |
| OVS agent 配置 | 已确认，`br-int`/`mirror`/SG off | 已确认，`br-int`/`mirror`/SG off | 已确认，`br-int`/`mirror`/SG off |
| 当前 br-int Neutron port | 有 VM tap 和 DHCP internal port | 只有 DHCP internal port | 当前无 Neutron port |
| `neutron-aria-agent` 容器运行 | 必须 | 必须 | 必须 |
| `aria-agent` 容器运行 | 必须 | 必须 | 必须 |
| `/run/aria/aria-agent.sock` 权限 | 必须 | 必须 | 必须 |
| `/sys/fs/bpf` 挂载 | 已确认，部署后复测 | 已确认，部署后复测 | 已确认，部署后复测 |
| BTF 可读 | 已确认，部署后复测 | 已确认，部署后复测 | 已确认，部署后复测 |
| br-int tap `iface-id` | 已确认，部署后复测 | 已确认 DHCP internal，创建 VM 后复测 VM tap | 当前无 port，创建 VM 后复测 |
| SR-IOV port skip | 必须 | 必须 | 必须 |
| LinuxBridge port skip | 必须 | 必须 | 必须 |
| QoS `tc` 依赖 | 当前缺失；如启用 shaping 则必须补齐 | 当前缺失；如启用 shaping 则必须补齐 | 当前缺失；如启用 shaping 则必须补齐 |

## 18. 灰度与回滚

### 18.1 灰度开关

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

### 18.2 回滚策略

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

### 18.3 失败隔离

ACL 失败不得影响：

- OVS L2 转发。
- neutron-openvswitch-agent。
- Neutron QoS。
- SR-IOV。
- LinuxBridge。
- 非 Aria-managed port。

## 19. 实施阶段

### Phase 0: 产品环境兼容基线

目标：

- 明确当前 `neutron-server:2.0.6sp2` 的 Python2 插件加载方式。
- 明确 `neutron-db-manage` migration 分支和 head。
- 明确三台 compute 的 OVSDB、bpffs、BTF、tc、tap 形态。
- 明确 Kolla 镜像构建和配置分发方式。

验收：

- 在测试镜像中 `python2 -c "import neutron_aria"` 成功。
- `aria_acl` service plugin 可以被 neutron-server 加载。
- DB migration 可以在当前 head 上 upgrade。
- `ostack2/3/4` 均确认 `br-int` tap 带 `external_ids:iface-id`。
- `ostack2/3/4` 均确认 `/sys/fs/bpf`、BTF、`/run/aria`、`/var/lib/aria-agent` 和 socket 权限方案。
- QoS shaping 如果纳入第一版，必须确认 `tc` 可用；否则第一版只承诺 policing 或将 shaping 标记 unsupported。

### Phase 1: Neutron 扩展骨架

目标：

- `aria_acl` service plugin 可加载。
- API extension 可被 `openstack extension list` 看到。
- API extension 可被 `neutron ext-show aria-acl` 看到。
- DB migration 可执行。
- policy/rule/address-set/binding CRUD 可用。
- Legacy `neutron aria-acl-*` CLI 可用。
- `neutron port-show` 可显示 `aria_acl_*` 只读摘要字段。

验收：

- Neutron server 启动成功。
- API CRUD 测试通过。
- Legacy neutron CLI CRUD 测试通过。
- DB 表创建成功。
- 不影响现有 network/port/router API。
- 不要求同时启用 QoS。

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
- 运维/控制节点 CLI 环境包含 Legacy `neutron aria-acl-*` 命令。
- neutron-aria-agent 镜像可部署。
- aria-agent 容器权限和挂载完成。
- 配置、日志、metrics、runbook 完成。

验收：

- 三节点部署 smoke。
- `neutron port-show`、`neutron aria-acl-effective-show`、`neutron aria-acl-port-status-show` 可用于现场排障。
- agent restart 恢复。
- tap recreate 恢复。
- 回滚流程通过。

## 20. OpenStack 配置示例

### 20.1 ACL-only 首次灰度配置

首次在当前产品环境中引入 Aria ACL 时，建议先不要同时启用 QoS。

```ini
[DEFAULT]
service_plugins = router,network_ip_availability,mirror,aria_acl

[aria_acl]
enabled = true
admin_only = true
notify_agents = true
default_stateful = true
enforcement_enabled = false
```

验证内容：

- neutron-server 能启动。
- `aria-acl` extension 可见。
- `neutron ext-show aria-acl` 成功。
- ACL API/DB CRUD 可用。
- `neutron aria-acl-policy-*`、`neutron aria-acl-rule-*`、`neutron aria-acl-binding-*` 命令可用。
- `neutron port-show <port-id>` 能看到 `aria_acl_*` 只读摘要字段。
- `neutron-aria-agent` 能 full resync。
- 未开启 enforcement 时业务流量不受影响。

### 20.2 ACL enforcement 配置

ACL API/DB/agent 验证完成后，再打开 enforcement：

```ini
[aria_acl]
enabled = true
admin_only = true
notify_agents = true
default_stateful = true
enforcement_enabled = true
```

### 20.3 ACL + QoS 配置

QoS 验证通过后再启用：

```ini
[DEFAULT]
service_plugins = router,network_ip_availability,mirror,qos,aria_acl,aria_qos

[ml2]
extension_drivers = qos

[aria_qos]
enabled = true
product_facade = true
enforcement_driver = aria
require_native_qos = true
unsupported_rule_action = degraded
```

OVS agent 保持：

```ini
[agent]
extensions = mirror
```

不要在 Aria QoS 路线中启用：

```ini
extensions = mirror,qos
```

除非已经切换为 OVS QoS 执行模式，或明确证明不会和 Aria 双重限速。

### 20.4 neutron-aria-agent.ini

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

[qos]
enabled = true
enforcement_driver = aria
unsupported_rule_action = degraded
shaping_requires_tc = true

[aria_qos]
enabled = true
use_native_qos_model = true
status_table = aria_qos_port_statuses
```

### 20.5 policy.yaml

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

## 21. Aria Mirror 第二阶段设计

Aria Mirror 不放在第一阶段。第一阶段主线仍然是 `aria_acl` 独立 ACL 扩展和基于 Neutron 原生 QoS 模型的 Aria QoS 执行。Mirror 作为第二阶段开发，原因是现场已经存在一个 `networking_mirror` 插件和 OVS agent mirror extension，但它的语义、数据面和 Aria-agent 已有 mirror 能力并不相同，不能简单认为“已有 mirror API 可以直接等价接入 Aria”。

### 21.1 现有 `networking_mirror` 的真实实现语义

基于源码和线上环境确认，现有 `networking_mirror` 是一个 Neutron service plugin + OVS agent extension/补丁组合。

北向入口：

```text
Neutron extension alias:
  mirror

Neutron service plugin:
  networking_mirror.plugins.plugin.MirrorPlugin

OVS agent extension:
  networking_mirror.agent.driver:MirrorAgentExtension
```

它暴露的主要对象字段包括：

```text
tenant_id
id
port_id
vm_type
ethertype
ip_prefix
```

这里最容易误解的是 `port_id`。从现有代码的数据面看，`port_id` 不是“被镜像的源 VM port”，而是“接收镜像流量的目标 VM port”。OVS driver 中会执行类似逻辑：

```text
port = br_int.get_vif_port_by_id(flowrule["port"])
actions = output:<port.ofport>
br_int.add_flow(table=<vm_type_table>, priority=10, match=<ip_prefix/proto>, actions=actions)
```

也就是说：

```text
源流量来源:
  [mirror] interface 配置指定的宿主机采集口
  -> br-mirror
  -> patch port
  -> br-int

目的端口:
  Neutron mirror 对象里的 port_id
  -> br-int 上某个 VM tap/ofport
```

现有数据面不是 OVSDB `Mirror` 表，也不是对 VM tap 做 per-port SPAN。它是 OpenFlow table + group 方案：

```text
物理/采集接口
  |
  v
br-mirror
  |
  v
patch: phy-br-mirror / int-br-mirror
  |
  v
br-int table 0
  |
  v
group 10 type=all
  |
  +--> table 100: ICG
  +--> table 101: DLP
  +--> table 102: NDS
```

三个 table 的作用：

| Table | 当前语义 | 作用 |
| --- | --- | --- |
| `100` | `vm_type=icg` | 把进入 br-int 的镜像流量按规则分发给 ICG 类型分析 VM |
| `101` | `vm_type=dlp` | 把进入 br-int 的镜像流量按规则分发给 DLP 类型分析 VM |
| `102` | `vm_type=nds` | 把进入 br-int 的镜像流量按规则分发给 NDS 类型分析 VM；线上包存在，离线 zip 分支不一定完整 |

`ip_prefix` 的作用不是 ACL，也不是“镜像必须过滤后才算镜像”。它是为了在同一股外部镜像流量进入宿主机后，把不同网段的流量分流到不同类型或不同用途的分析 VM。代码会把一个 prefix 展开成双向匹配：

```text
nw_src=0.0.0.0/0,nw_dst=<ip_prefix>
nw_src=<ip_prefix>,nw_dst=0.0.0.0/0
```

因此，现有 `networking_mirror` 的业务模型更接近：

```text
交换机或外部设备把流量镜像到宿主机采集口。
宿主机把采集口接入 br-mirror。
br-mirror 通过 patch 口把镜像流量送到 br-int。
br-int 根据 vm_type table 和 ip_prefix 把流量输出到目标分析 VM port。
```

现场当前状态：

```text
service_plugins:
  已包含 mirror

OVS agent extensions:
  已包含 mirror

[mirror] interface:
  为空

OVSDB Mirror table:
  无 Mirror 对象

br-int group 10:
  未看到有效 group

br-int table 100/101/102:
  未看到有效分发表
```

结论：现有 mirror 功能代码和 API 是存在的，但当前环境没有配置采集接口，也没有看到实际 mirror OpenFlow 生效状态，不能直接按“线上正在可用”来对外承诺。

### 21.2 `networking_mirror` 与 `aria_mirror` 对比

| 对比项 | 现有 `networking_mirror` | 第二阶段 `aria_mirror` 建议 |
| --- | --- | --- |
| Neutron extension alias | `mirror` | `aria-mirror` |
| 北向 API 语义 | 创建某类分析 VM 的镜像接收规则 | 创建 Aria 管理的镜像会话、规则和目标 |
| 源的表达 | `[mirror] interface` 指定宿主机采集口；API 里没有真正的 source port 字段 | 明确表达 `source_port_id`、`source_network_id` 或 admin-only `source_host_interface` |
| `port_id` 语义 | 目标 VM port，用于 `output:<ofport>` | 不建议复用为单一字段；应拆成 `source_port_id` 和 `target_port_id` |
| 目标的表达 | `port_id` + `vm_type` | `target_type` + `target_port_id` / `target_interface` / 后续 remote collector |
| 分类条件 | `vm_type`、`ethertype`、`ip_prefix`、协议/端口字段 | `direction`、`protocol`、`src_address_set`、`dst_address_set`，必要时支持 prefix |
| 数据面位置 | OVS br-mirror/br-int OpenFlow group/table | Aria-agent TC/eBPF `bpf_clone_redirect` |
| 是否修改原始业务流 | 不应修改原始流量，只复制进入的镜像流量 | 不修改原始业务流，只 clone 到目标 ifindex |
| 对 VM tap 的源镜像 | 不是当前 API 的主要语义 | 是核心能力之一 |
| 对物理采集口的镜像 | 支持外部镜像流量从采集口进入，再分发给分析 VM | 支持 admin-only host interface source；适合交换机 SPAN -> 宿主机采集 NIC -> VM/接口 |
| 跨物理节点 | 代码未实现跨节点 tunnel；要求源镜像流量已到目标 VM 所在节点 | 第二阶段第一版也不做跨节点；如需跨节点，后续增加 tunnel/remote collector |
| LinuxBridge 关系 | 未看到 LinuxBridge 数据面路径 | 不接管 LinuxBridge；只处理 Aria 可 attach 的接口 |
| SR-IOV 关系 | 不接管 VF representor 语义 | 第二阶段第一版不接管 SR-IOV；除非后续证明 representor/TC attach 可控 |
| 状态可见性 | 依赖现有 mirror API 和 OVS flow 排查 | 增加 `aria_mirror_status`，展示 source、target、ifindex、packets、bytes、errors |
| 产品边界 | 更像外部镜像流量分发系统 | Aria eBPF clone 能力的 Neutron 产品化入口 |

核心差异可以压缩成一句话：

```text
networking_mirror 是“把外部采集口进入的镜像流量，按 vm_type/ip_prefix 分发给目标分析 VM”；
aria_mirror 应该是“对 Aria 管理的源接口或采集接口做 clone，把副本送到明确的目标接口或目标 VM”。
```

### 21.3 为什么第二阶段建议新增 `aria_mirror`，而不是直接复用 `mirror`

最初可以考虑“复用现有 mirror API，新增 Aria 执行后端”。但结合实际代码后，这条路存在明显歧义：

- 现有 `mirror.port_id` 是目标 VM port，不是源 port。
- Aria-agent 的 mirror API 是围绕 source instance/tap 上的 ingress/egress clone 设计的。
- 现有 `vm_type=icg/dlp/nds` 是业务分发表语义，不等价于 Aria 的 source/destination group。
- 现有 `ip_prefix` 是镜像流量分流条件，不是完整 ACL 风格的 match model。
- 现有实现依赖 `br-mirror`、patch port、br-int group/table；Aria 实现依赖 TC/eBPF map 和 target ifindex。
- 如果在同一个 `mirror` API 下同时支持两套语义，用户很难判断 `port_id` 到底是源还是目的，也很难解释一条规则到底走 OVS flow 还是 Aria eBPF。

因此产品化建议是：

```text
保留现有 networking_mirror:
  继续服务已有外部采集口 -> 分析 VM 的场景。

新增 aria_mirror:
  服务 Aria-agent 已具备的 eBPF mirror 能力。
  字段显式拆分 source 和 target。
  第二阶段作为独立 Neutron extension/plugin 落地。

可选兼容:
  后续可以提供 mirror -> aria_mirror 的迁移工具或只读对照视图。
  不建议把现有 mirror 对象自动投影为 aria_mirror 对象。
```

### 21.4 `aria_mirror` 产品语义

`aria_mirror` 是 Aria 的独立镜像增强扩展，北向仍然走 Neutron Server，但不复用 Security Group，也不复用现有 `networking_mirror` 的 `mirror` 对象。

建议 extension：

```text
alias: aria-mirror
python symbol prefix: aria_mirror
service plugin: aria_mirror
```

建议资源：

```text
aria_mirror_session
aria_mirror_rule
aria_mirror_binding
aria_mirror_status
```

`aria_mirror_session` 表达一个镜像会话：

| 字段 | 说明 |
| --- | --- |
| `id` | session UUID |
| `project_id` | project/tenant |
| `name` | 名称 |
| `description` | 描述 |
| `enabled` | 是否启用 |
| `source_type` | `port`、`network`、`host_interface` |
| `source_port_id` | source_type 为 `port` 时使用 |
| `source_network_id` | source_type 为 `network` 时使用，表示该 network 下符合条件的本机 VM tap |
| `source_host` | source_type 为 `host_interface` 时必填，admin-only |
| `source_interface` | 宿主机采集接口名，admin-only |
| `target_type` | `port`、`local_interface`，后续可扩展 `remote_collector` |
| `target_port_id` | target_type 为 `port` 时使用，第一版要求和 source 在同一宿主机 |
| `target_host` | target_type 为 `local_interface` 时使用 |
| `target_interface` | 目标接口名 |
| `direction` | `ingress`、`egress`、`both` |
| `mirror_mode` | `global` 或 `policy`；`global` 表示全量镜像，`policy` 表示按 rule 条件镜像 |
| `admin_state_up` | 管理状态 |
| `status` | `ACTIVE`、`DOWN`、`DEGRADED`、`UNSUPPORTED` |

`aria_mirror_rule` 表达可选匹配条件：

| 字段 | 说明 |
| --- | --- |
| `id` | rule UUID |
| `session_id` | 所属 session |
| `priority` | 优先级 |
| `ethertype` | `IPv4` / `IPv6` |
| `protocol` | `any`、`tcp`、`udp`、`icmp` 或协议号 |
| `src_address_set_id` | 可选，复用或独立使用 Aria address set |
| `dst_address_set_id` | 可选 |
| `src_ip_prefix` | 可选；简单 prefix 场景 |
| `dst_ip_prefix` | 可选 |
| `target_type` | 可选；为空时继承 session target |
| `target_port_id` | 可选；用于把不同 IP 网段镜像到不同 VM port |
| `target_host` | 可选；target_type 为 `local_interface` 时使用 |
| `target_interface` | 可选；target_type 为 `local_interface` 时使用 |
| `enabled` | 是否启用 |

目标选择规则：

```text
rule.target_* 存在:
  使用 rule 级别 target。
  适合“不同 IP 网段 -> 不同分析 VM port”。

rule.target_* 为空:
  继承 session.target_*。
  适合“同一个源 -> 同一个分析 VM port”。
```

全局镜像规则：

```text
session.mirror_mode = global:
  不需要创建 rule，或者只允许一条 any/any/any 规则。
  neutron-aria-agent 翻译为 Aria-agent 的 MIRROR_GLOBAL。
  语义是：该 source + direction 上所有流量都 clone 到 session target。

session.mirror_mode = policy:
  必须至少有一条 rule。
  每条 rule 可以指定 src/dst prefix、address-set、protocol 和可选 rule target。
  neutron-aria-agent 翻译为 Aria-agent 的 MIRROR_POLICY。
```

按 IP 网段分流到不同 VM port 的推荐表达：

```text
source: host_interface ensXfY
direction: ingress
mode: policy

rule 10:
  dst_ip_prefix = 10.10.0.0/16
  target_port_id = analyzer_vm_a_port

rule 20:
  dst_ip_prefix = 10.20.0.0/16
  target_port_id = analyzer_vm_b_port

rule 30:
  dst_ip_prefix = 10.30.0.0/16
  target_port_id = analyzer_vm_c_port
```

冲突处理：

- 同一 source + direction 下，rule 必须有 `priority`。
- 如果两个 prefix/address-set 重叠，优先级高的 rule 先匹配。
- 第一版建议默认禁止同一优先级的重叠 prefix。
- 如果同时配置 global 和 policy，默认语义是 `global_l2 + selective rule` 共存：
  - global 总是保留 SPAN-like 全量二层镜像语义。
  - policy 只对解析成功的 IP 包做选择性镜像。
  - policy 命中且目标与 global 不同：同一包同时镜像到 global target 和 policy target。
  - policy 命中且目标与 global 相同：只复制一份包，但 global/policy 两套统计都增加。
  - ARP、LLDP、未知 EtherType、VLAN 等非 IP 包只由 global 覆盖，不进入 policy 规则。

`aria_mirror_binding` 用于把 session 绑定到 port/network，便于后续和 `aria_acl_binding` 保持一致的产品交互方式：

| 字段 | 说明 |
| --- | --- |
| `id` | binding UUID |
| `session_id` | mirror session |
| `target_type` | `port` / `network` |
| `target_id` | 绑定对象 UUID |
| `project_id` | project/tenant |

第一版可以把 `source_*` 直接放在 session 中，不一定强制单独 binding；如果产品希望 ACL/Mirror 操作风格统一，则使用 binding 表。

### 21.5 `aria_mirror` Legacy CLI 表达

旧版本 OpenStack 环境优先支持 Legacy `neutron` CLI：

```bash
neutron ext-show aria-mirror

neutron aria-mirror-session-create \
  --name span-web-01 \
  --source-port $SRC_PORT_ID \
  --target-port $TARGET_PORT_ID \
  --direction both

neutron aria-mirror-rule-create $SESSION_ID \
  --protocol tcp \
  --src-address-set $SRC_SET_ID \
  --dst-address-set $DST_SET_ID

neutron aria-mirror-session-show $SESSION_ID
neutron aria-mirror-session-list
neutron aria-mirror-session-update $SESSION_ID --disable
neutron aria-mirror-session-delete $SESSION_ID

neutron aria-mirror-status-show --port $SRC_PORT_ID
```

全局镜像：

```bash
neutron aria-mirror-session-create \
  --name vm-global-mirror \
  --source-port $SRC_PORT_ID \
  --target-port $ANALYZER_VM_PORT_ID \
  --direction both \
  --mirror-mode global
```

不同 IP 网段镜像到不同 VM port：

```bash
neutron aria-mirror-session-create \
  --name span-by-prefix \
  --source-host ostack2 \
  --source-interface ensXfY \
  --direction ingress \
  --mirror-mode policy

neutron aria-mirror-rule-create $SESSION_ID \
  --priority 10 \
  --dst-ip-prefix 10.10.0.0/16 \
  --target-port $ANALYZER_VM_A_PORT_ID

neutron aria-mirror-rule-create $SESSION_ID \
  --priority 20 \
  --dst-ip-prefix 10.20.0.0/16 \
  --target-port $ANALYZER_VM_B_PORT_ID
```

物理采集口场景必须 admin-only：

```bash
neutron aria-mirror-session-create \
  --name span-uplink-to-vm \
  --source-host ostack2 \
  --source-interface ensXfY \
  --target-port $ANALYZER_VM_PORT_ID \
  --direction ingress
```

限制：

- `--source-interface` 只能由 admin 使用。
- 第一版 `source_host` 和 `target_port` 所在 host 必须一致。
- 目标 port 必须是普通 OVS tap port。
- 不能把 Neutron DHCP/router/metadata port 作为目标分析 VM port。
- 不支持把 SR-IOV VF 直接作为 source 或 target。

### 21.6 DB 表设计

建议新增：

```text
aria_mirror_sessions
aria_mirror_rules
aria_mirror_bindings
aria_mirror_port_statuses
```

`aria_mirror_sessions`：

```text
id
project_id
name
description
enabled
source_type
source_port_id
source_network_id
source_host
source_interface
target_type
target_port_id
target_host
target_interface
direction
mirror_mode
admin_state_up
status
created_at
updated_at
revision_number
```

`aria_mirror_rules`：

```text
id
session_id
project_id
priority
ethertype
protocol
src_address_set_id
dst_address_set_id
src_ip_prefix
dst_ip_prefix
target_type
target_port_id
target_host
target_interface
enabled
created_at
updated_at
revision_number
```

`aria_mirror_port_statuses`：

```text
port_id
host
session_id
source_ifname
source_ifindex
target_ifname
target_ifindex
runtime_status
status_reason
mirrored_packets
mirrored_bytes
mirror_errors
last_applied_revision
updated_at
```

状态必须能解释为什么没有生效：

```text
ACTIVE
  已下发并有明确 source/target ifindex。

PENDING
  Neutron DB 已保存，agent 尚未完成下发。

UNSUPPORTED
  source/target 不是 Aria 支持的接口类型，例如 SR-IOV VF 或 LinuxBridge。

DEGRADED
  部分规则失败，例如 target ifindex 不存在、TC attach 失败或 eBPF map 写入失败。

NO_LOCAL_BINDING
  当前 host 上没有该 source port。

CROSS_HOST_UNSUPPORTED
  第一版检测到 source 与 target 不在同一 host。
```

### 21.7 `neutron-aria-agent` mirror translator

`neutron-aria-agent` 第二阶段新增 mirror translator，职责是把 Neutron DB/API 中的 `aria_mirror` 对象翻译成 Aria-agent 已支持的 mirror snapshot。

输入：

```text
Neutron port
Neutron binding:host_id
OVSDB Interface external_ids:iface-id
aria_mirror_session
aria_mirror_rule
address set / prefix
```

输出给 `aria-agent`：

```text
source instance/tap identity
direction: ingress / egress / both
protocol: any / tcp / udp / icmp / number
src_group_id
dst_group_id
target_iface
target_ifindex
is_global
priority
```

处理流程：

```text
neutron-aria-agent 收到 aria_mirror session/rule/port 事件
  |
  v
full resync 或增量重算 effective mirror
  |
  v
根据 source_type 找到本机 source tap 或 source host interface
  |
  v
根据 target_type 找到本机 target tap/interface 和 ifindex
  |
  v
校验 source/target 是否同 host、是否 OVS tap、是否 admin-only host interface
  |
  v
生成 per-source mirror snapshot
  |
  v
global session 生成 MIRROR_GLOBAL，policy rule 生成 MIRROR_POLICY
  |
  v
通过 /run/aria/aria-agent.sock 下发给 aria-agent
  |
  v
回写 aria_mirror_port_statuses
```

与 ACL/QoS 一样，`neutron-server` 只保存意图和发布事件；`neutron-aria-agent` 负责宿主机本地发现和翻译；`aria-agent` 负责真正写 eBPF map。

### 21.8 `aria-agent` 执行模型

现有 Aria-agent 已有 mirror 能力，核心模型是：

```text
MirrorEntry:
  src_group
  src_group_id
  dst_group
  dst_group_id
  proto
  direction
  target_iface
  target_ifindex
  is_global
```

数据面使用 TC/eBPF：

```text
TC ingress/egress hook
  |
  v
先按 tap_id、direction 查 MIRROR_GLOBAL
  |
  v
命中则 bpf_clone_redirect 到 global target，并更新 MIRROR_GLOBAL_STATS
  |
  v
如果是可解析 IP 包，继续根据 tap_id、src_group_id、dst_group_id、proto、direction 查 MIRROR_POLICY
  |
  v
命中 policy 且 target 不同，则再 bpf_clone_redirect 到 policy target
  |
  v
命中 policy 且 target 相同，则不重复 clone，只更新 policy stats
  |
  v
原始业务包继续按原路径转发
```

这对 Neutron 产品化有两个重要约束：

- `aria_mirror` 下发的目标必须最终能解析成 target ifindex。
- 原始业务包不应被 consume，mirror 失败只能影响 mirror 状态，不能阻断业务转发。
- 全局镜像必须映射到 Aria-agent 现有 `MIRROR_GLOBAL`。
- 按 IP 网段分流必须映射到带 `src_group_id` / `dst_group_id` / `proto` / `direction` / `target_ifindex` 的 `MIRROR_POLICY`；IP prefix 可编译为 Aria address group。
- 包数/字节数/error 由 eBPF map 累计；速率不放在 eBPF 数据面计算。
- `aria-agent` 控制面周期读取 `MIRROR_GLOBAL_STATS` / `MIRROR_STATS`，按差值计算：
  - `mirrored_pps = delta_packets / interval_seconds`
  - `mirrored_bps = delta_bytes * 8 / interval_seconds`
- `neutron-aria-agent` 只读取 aria-agent 的统计快照并回写 Neutron status；Neutron Server 不做秒级 eBPF 轮询。

### 21.9 物理端口镜像场景

如果要做物理端口镜像，推荐模型是：

```text
交换机配置 SPAN / port mirror
  |
  v
镜像流量进入宿主机专用采集 NIC
  |
  v
aria_mirror source_type=host_interface
  |
  v
aria-agent 在采集接口 ingress 方向 clone
  |
  v
target_port_id 指向本机分析 VM tap
```

要求：

- 采集 NIC 建议为专用网卡，不承载宿主机管理、存储或租户业务流量。
- 第一版只支持本机目标 VM，不做跨宿主机转发。
- 如果交换机镜像流量已经包含 VLAN tag，需要明确 Aria eBPF 是否保留、解析或过滤 VLAN。
- 如果目标 VM 需要看到原始二层帧，目标 tap 的 MTU、offload 和 promisc 行为要单独验收。

### 21.10 第二阶段开发计划

第二阶段建议拆成 6 个子阶段：

**阶段 2.1：现有 mirror 兼容性冻结**

- 固化 `networking_mirror` 现状说明。
- 明确现有 `mirror` API 继续保留。
- 禁止在 `mirror.port_id` 上新增 Aria source 语义。
- 给运维文档补充现有 mirror 排查命令：`ovs-ofctl dump-flows br-int table=100,101,102`、`ovs-ofctl dump-groups br-int`、`ovs-vsctl list-br`。

**阶段 2.2：Neutron Server `aria_mirror` API/DB**

- 新增 `aria-mirror` extension descriptor。
- 新增 `aria_mirror` service plugin。
- 新增 DB migration。
- 新增 CRUD、validator、RBAC。
- 支持 session/rule/status show。
- 保证 `neutron ext-show aria-mirror` 可见。

**阶段 2.3：Legacy CLI**

- 新增 `neutron aria-mirror-session-*`。
- 新增 `neutron aria-mirror-rule-*`。
- 新增 `neutron aria-mirror-status-show`。
- 对 admin-only host interface 参数做 CLI 侧和 server 侧双重校验。

**阶段 2.4：`neutron-aria-agent` mirror translator**

- 增加 mirror full resync。
- 监听 port binding、session、rule、address set 变化。
- 解析 OVS tap 的 ifname/ifindex。
- 解析 target port / target interface。
- 拒绝 cross-host target，并写状态。
- 生成 Aria mirror snapshot。

**阶段 2.5：`aria-agent` OpenStack UDS contract**

- 在 OpenStack snapshot contract 中加入 mirror domain。
- 支持 session/rule revision。
- 支持 mirror apply/delete/status。
- 保证 mirror apply 失败不影响 ACL/QoS 域。
- 把 Aria-agent 现有 mirror stats 暴露给 `neutron-aria-agent`。
- 在 aria-agent 控制面实现 mirror stats sampler，输出累计 counters 和 `mirrored_pps` / `mirrored_bps`。
- 在 `aria_mirror_port_statuses` 中保存最近一次上报的 counters、rates、`stats_window_seconds` 和 `last_sampled_at`。

**阶段 2.6：数据面验收**

- VM tap -> 本机分析 VM tap。
- 物理采集 NIC -> 本机分析 VM tap。
- ingress、egress、both 三种方向。
- protocol/address-set/prefix 匹配。
- target VM 重启后 target ifindex 恢复。
- source VM 迁移后源宿主机清理，目的宿主机重建。
- cross-host target 返回 `CROSS_HOST_UNSUPPORTED`。
- 删除 session 后 eBPF mirror map 清理。
- global mirror 能把 source + direction 上全部流量 clone 到目标 VM port。
- policy mirror 能把不同 IP prefix/address-set clone 到不同目标 VM port。
- global + policy 目标不同时，命中 policy 的 IP 包同时到 global target 和 policy target。
- global + policy 目标相同时，目标只收到一份包，但 global/policy stats 都增加。
- 非 IP 包只进入 global，不进入 policy stats。
- mirror status 能显示累计包数、字节数、errors、pps、bps。

### 21.11 第二阶段配置示例

Neutron Server：

```ini
[DEFAULT]
service_plugins = router,network_ip_availability,mirror,qos,aria_acl,aria_qos,aria_mirror
```

`neutron-aria-agent`：

```ini
[mirror]
enabled = true
enforcement_driver = aria
allow_host_interface_source = true
allow_cross_host_target = false
default_unmatched_action = no_mirror
```

`policy.yaml`：

```yaml
"create_aria_mirror_session": "rule:admin_only"
"update_aria_mirror_session": "rule:admin_only"
"delete_aria_mirror_session": "rule:admin_only"
"get_aria_mirror_session": "rule:admin_only"
"create_aria_mirror_rule": "rule:admin_only"
"delete_aria_mirror_rule": "rule:admin_only"
"get_aria_mirror_status": "rule:admin_only"
```

### 21.12 第二阶段验收口径

第二阶段可以对外承诺的现象：

```text
neutron ext-show aria-mirror 成功。
neutron aria-mirror-session-create 能创建 VM tap 镜像会话。
neutron aria-mirror-status-show 能显示 source/target ifindex、累计 stats、pps、bps、统计窗口和最后采样时间。
本机 VM tap 的 ingress/egress 流量可以 clone 到本机分析 VM。
global mirror 覆盖 ARP、IPv4、IPv6、LLDP、广播、多播、未知 EtherType 和 VLAN 帧。
policy mirror 支持按 IP prefix/address-set/protocol/direction 分流到不同分析 VM port。
交换机 SPAN 到宿主机采集 NIC 的流量可以 clone 到本机分析 VM。
删除 session 后 clone 停止，原业务流量不受影响。
source/target 跨宿主机时明确显示 CROSS_HOST_UNSUPPORTED。
SR-IOV、LinuxBridge、Neutron 服务端口明确显示 UNSUPPORTED 或 NOT_APPLICABLE。
```

第二阶段不承诺：

```text
不承诺跨宿主机 mirror。
不承诺直接接管 SR-IOV VF。
不承诺替代现有 networking_mirror。
不承诺兼容现有 mirror.port_id 语义。
不承诺 tenant 自助配置宿主机物理采集口。
```

## 22. 产品边界总结

最终产品口径：

```text
Aria ACL 是 OpenStack Neutron 的独立 ACL enhancement 扩展。
它使用独立 API、独立 DB、独立 RBAC、独立 agent 同步和 Aria eBPF datapath 执行。
它不复用 Neutron Security Group，不做 Security Group projection，不展开 remote group，不依赖 port security。
它只增强普通虚机 OVS tap port，不替代 OVS L2，不接管 SR-IOV、LinuxBridge 和 Neutron 服务端口。
QoS 不重造 API，复用 Neutron QoS policy/rule，由 Aria 执行。
QoS 对外产品入口统一叫 aria-qos；aria-qos facade 复用 Neutron 原生 QoS DB/API，不复用 qhqos。
Mirror 第二阶段新增 aria_mirror 独立扩展，不复用现有 networking_mirror 的 port_id/vm_type 语义。
```

这个路线比 tag + 本地 mapping 更适合产品化，因为 ACL 对象可审计、可回滚、可 RBAC、可 API 化，也能被 Horizon、Terraform、Heat 或平台编排系统长期集成。

基于 2026-06-15 真实环境探测，还必须追加以下产品化约束：

```text
目标 neutron-server 是 Python2 老版本/定制产品镜像，不按新版 Python3 neutron-lib 方案默认实现。
aria_acl 必须打进 neutron-server 产品镜像，并通过当前 neutron-db-manage / service plugin 机制验收。
当前环境 QoS 代码存在但未启用，QoS 要分阶段打开 API/DB/ML2 extension，再由 Aria 接管执行。
当前环境 qhqos 是 qcloud/floating IP/router QoS 定制扩展，不适合作为普通 VM OVS tap 的 Aria QoS 基础。
neutron-openvswitch-agent 当前只启用 mirror extension；Aria QoS 路线不启用 OVS agent qos execution，避免双重限速。
当前 tap -> br-int + iface-id 证据支持 Aria 端口发现路径。
SR-IOV 和 LinuxBridge 存在但不纳入 Aria ACL/QoS 管理范围。
```

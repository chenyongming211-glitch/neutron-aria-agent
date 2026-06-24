# OpenStack Target Environment Discovery

状态：Template
适用阶段：N0.5-lite / N0.5

本文件是进入 N3 目标环境功能闭环前必须补齐的发现记录。没有完成 N0.5-lite 项，不冻结 PR-1A schema；没有完成完整 N0.5 项，不进入 N3 目标环境 feature smoke。PR-6A/PR-6B 容器部署 smoke 只能验证部署和运行边界，不能替代本文件的 discovery 证据。

每一项都必须保留命令、期望、实际、证据和失败动作。证据可以是命令输出、日志片段、配置路径、截图或 smoke 结果文件。

## 0. N0.5-lite 执行记录

N0.5-lite 是 PR-1A schema freeze gate。没有完成本节，不允许冻结 direction、attach 点、`integration_mode` 和 UDS/status DTO 中与目标环境相关的字段。

| 项 | 要求 |
| --- | --- |
| 执行目标环境 | 记录 cloud / region / compute host / Neutron host 名称 |
| 执行人 | 记录负责人和执行日期 |
| 证据目录 | `docs/evidence/openstack-n05-lite/<date>-<host>/` |
| 最小命令集合 | OpenStack 版本、ML2 mechanism driver、OVS agent、tap 接入 `br-int`、hook direction、默认 bypass smoke、`/run/aria` 宿主机目录与挂载策略 |
| 输出文件 | `summary.md`、`commands.log`、`ovs-topology.txt`、`hook-direction.md`、`bypass-smoke.log`、`run-aria-policy.md` |
| 失败处理 | 不能冻结 PR-1A schema；相关结论保持 `assumption` |

## 1. 环境标识

| 项 | 命令 / 检查 | 期望 | 实际 | 证据路径 | 失败动作 |
| --- | --- | --- | --- | --- | --- |
| OpenStack 发行版与版本 | `openstack --version`；记录发行版包版本 | 明确发行版和客户端版本 | 未执行 | 未执行 | 不能进入完整 N0.5 |
| Neutron ML2 mechanism driver | `grep -R "mechanism_drivers" /etc/neutron/plugins/ml2/` | 包含 OVS 相关 driver，不采用 OVN | 未执行 | 未执行 | 不冻结 attach/direction 结论 |
| compute host OS / kernel | `uname -a`; `cat /etc/os-release` | 记录 kernel 和 OS | 未执行 | 未执行 | 不进入 eBPF attach smoke |
| OVS 版本 | `ovs-vsctl --version` | 记录 OVS 版本 | 未执行 | 未执行 | 不进入 OVS smoke |
| 目标部署形态 | `openstack network agent list --host <compute>` | OVS only | 未执行 | 未执行 | 若存在 OVN/Linux bridge，当前阶段不支持 |

## 2. OVS 与 Tap 拓扑

| 项 | 命令 / 检查 | 期望 | 实际 | 证据路径 | 失败动作 |
| --- | --- | --- | --- | --- | --- |
| VM tap 是否直接接入 `br-int` | `ovs-vsctl show`; `ovs-vsctl list interface <tap>` | tap 直接在 `br-int` 上 | 未执行 | 未执行 | 不冻结 PR-1A direction 字段 |
| 是否存在 `qvo/qvb/veth` 路径 | `sh -c 'ip link show \| egrep "qvo\|qvb\|veth"'` | 目标 VM 无 hybrid plug 路径 | 未执行 | 未执行 | 当前阶段不支持该环境 |
| tap 命名模式 | `sh -c 'ip link show \| grep tap'`; `ovs-vsctl list interface` | 可稳定映射 Neutron port | 未执行 | 未执行 | 不进入 N3 smoke |
| `binding_host` 与 hostname 映射 | `hostname -f`; Neutron port binding 查询 | `binding_host` 与本机 host 一致 | 未执行 | 未执行 | adapter host 配置不得冻结 |
| OVS agent / ovs-vswitchd / ovsdb-server 重启行为 | 重启服务并记录 tap/ifindex 变化 | Aria 可 `DomainStatus=degraded` 后恢复 | 未执行 | 未执行 | 补恢复策略或标记 `support_disposition=unsupported` |

## 3. Hook Direction 矩阵

| 流量方向 | 命令 / 检查 | 期望 | 实际 | 证据路径 | 失败动作 |
| --- | --- | --- | --- | --- | --- |
| VM -> same host VM | tcpdump / tc trace / eBPF test hook | 明确 XDP/TC 可见点 | 未执行 | 未执行 | 不冻结 ACL/QoS direction |
| VM -> external | tcpdump / tc trace / eBPF test hook | 明确 egress/ingress 映射 | 未执行 | 未执行 | 不冻结 PR-1A schema |
| external -> VM | tcpdump / tc trace / eBPF test hook | 明确 ingress 映射 | 未执行 | 未执行 | 不进入 N3 smoke |
| DHCP | DHCP request/renew smoke | bypass 不影响 DHCP | 未执行 | 未执行 | N3 默认只允许 bypass，不启用相关 ACL |
| metadata | curl metadata endpoint smoke | bypass 不影响 metadata | 未执行 | 未执行 | N3 默认只允许 bypass，不启用相关 ACL |
| IPv6 ND | `ping6` / neighbor discovery smoke | bypass 不影响 ND | 未执行 | 未执行 | N3 默认只允许 bypass，不启用相关 ACL |

## 4. Aria Bypass Smoke

| 场景 | 命令 / 检查 | 期望 | 实际 | 证据路径 | 失败动作 |
| --- | --- | --- | --- | --- | --- |
| `aria-datapath` 未启动 | VM 连通性 smoke | OVS 原有转发不受影响 | 未执行 | 未执行 | 不进入 N3 |
| `neutron-aria-agent` degraded | 停止 agent 后连通性 smoke | OVS 原有转发不受影响 | 未执行 | 未执行 | 修正 agent degraded 语义 |
| ACL enhancement tag 缺失 | 无 tag VM 连通性 smoke | port 保持 bypass | 未执行 | 未执行 | 修正 translator 默认行为 |
| ACL mapping 缺失 | tag 指向不存在 mapping | `DomainStatus=degraded,effective_action=bypass`，OVS 转发不受影响 | 未执行 | 未执行 | 修正错误码和 status |
| ACL apply 失败注入 | 注入 ACL compile/apply failure | `DomainStatus=degraded,effective_action=bypass`，OVS 转发不受影响 | 未执行 | 未执行 | 不允许进入 ready |

## 5. 显式 ACL Enhancement 输入源

| 项 | 命令 / 检查 | 期望 | 实际 | 证据路径 | 失败动作 |
| --- | --- | --- | --- | --- | --- |
| Neutron tag key | 查询 port/network tag | `aria:acl=<policy-id>` | 未执行 | 未执行 | 不冻结 translator 输入 |
| tag 写入权限 | 用 tenant 和 admin 分别尝试写 tag | operator-admin only | 未执行 | 未执行 | 禁止进入 N3 |
| mapping 文件路径 | 检查配置与文件 | `/etc/neutron-aria-agent/acl-policies.yaml` | 未执行 | 未执行 | 不启动 ACL enhancement |
| mapping 文件权限 | `stat -c "%U %G %a" <file>` | operator-admin 管理，只读挂载 | 未执行 | 未执行 | 禁止进入 N3 |
| tenant 是否可直接写 ACL mapping | tenant 权限验证 | 不允许 | 未执行 | 未执行 | 阻断 N3 |
| Security Group projection | 检查 translator 输入和 schema | 不支持 / 不进入第一阶段 | 未执行 | 未执行 | 删除 SG projection 相关输入 |
| remote group / port security / allowed address pairs | 检查 translator 输入和 schema | 不作为 ACL enhancement 输入 | 未执行 | 未执行 | 删除相关输入字段 |

## 6. Neutron Agent 与 RPC

| 项 | 命令 / 检查 | 期望 | 实际 | 证据路径 | 失败动作 |
| --- | --- | --- | --- | --- | --- |
| agent type 名称 | `openstack network agent list` | 明确 agent type | 未执行 | 未执行 | 不冻结 heartbeat |
| heartbeat 注册方式 | 查 Neutron agent 配置和日志 | agent alive/degraded 可上报 | 未执行 | 未执行 | 不进入 PR-4 |
| port binding/full resync API | mock 或目标环境查询 | 可按 host 拉取 authoritative ports | 未执行 | 未执行 | 不进入 translator full resync |
| port update event source | RPC topic / callback / polling 记录 | 有明确 event source | 未执行 | 未执行 | PR-4 只能使用 full resync |
| 第一阶段功能白名单 | 检查主方案、schema、translator、PR gate | 只包含 ACL enhancement 和 QoS；其它能力只能是支撑能力或保留代码 | 未执行 | 未执行 | 删除非 ACL/QoS 的功能模块入口 |
| QoS extension 可用性 | 查 Neutron extension list | 明确 `support_disposition=supported` 或 `unsupported` | 未执行 | 未执行 | PR-5B 降级或延期 |
| Mirror/TCPrt Neutron 对接 scope | 检查本方案 scope 与 PR gate | 不进入第一阶段；不作为 N0.5、PR-6A 或 PR-6B gate | 未执行 | 未执行 | Rust 既有代码保留，但不接入 `neutron-aria-agent` |

### 6.1 2026-06-24 目标环境 RPC 源码确认记录

执行节点：`ostack2.bj159.net`

检查位置：`neutron_openvswitch_agent` 容器内 `/usr/lib/python2.7/site-packages/neutron/plugins/ml2/drivers/openvswitch/agent/ovs_neutron_agent.py` 与 `neutron/agent/rpc.py`。

确认结果：

- 旧版 OVS agent 的 `setup_rpc()` 使用 `self.topic = topics.AGENT`，目标环境中对应 fanout prefix 为 `q-agent-notifier`。
- OVS agent 已消费的相关 topic 为 `PORT UPDATE`、`PORT DELETE`、`NETWORK UPDATE`；同时还消费 tunnel/security-group/DVR/l2population，但这些不属于 Aria 第一阶段 RPC event skeleton 范围。
- `port_update(self, context, **kwargs)` 从 `kwargs["port"]["id"]` 取得 port ID，并加入本地 `updated_ports`。
- `port_delete(self, context, **kwargs)` 从 `kwargs["port_id"]` 取得 port ID，加入 `deleted_ports`，并从 `updated_ports` 移除。
- `network_update(self, context, **kwargs)` 从 `kwargs["network"]["id"]` 取得 network ID；OVS agent 有本地 `network_ports` 索引时只标记相关 ports。Aria 第一版没有该索引，因此按 full-resync 处理。
- `agent_rpc.create_consumers(endpoints, prefix, topic_details, start_listening=False)` 会对每个 topic 调 `connection.create_consumer(topic_name, endpoints, fanout=True)`；开启监听时调用 `connection.consume_in_threads()`。

对方案的约束：

- `neutron-aria-agent` 第一版 RPC callback 只接入 `port.update`、`port.delete`、`network.update`。
- `port.delete` 必须按旧版 `port_id` kwarg 兼容；不能假设删除事件携带完整 port。
- Neutron event 是 fanout，Aria 不能对所有收到的 delete/update 都直接操作本地 datapath；必须结合本机 projected state 和 `binding:host_id` 过滤。
- 当前没有 ACL/QoS translator 与 network->local ports 索引时，port/network update 只能触发 full-resync 或安全忽略，不能硬猜增量 port-scoped snapshot。

### 6.2 2026-06-24 RPC skeleton 测试部署记录

执行节点：`ostack2.bj159.net`、`ostack3.bj159.net`、`ostack4.bj159.net`

部署形态：

- 临时测试部署，源码位于各节点 `neutron_openvswitch_agent` 容器内 `/tmp/neutron_aria_agent_src`。
- 部署代码提交：`c4dbef0`，GitHub Actions run：`28090615180`，结果：`success`。
- 进程命令保持 `--heartbeat-only`。
- `/tmp/neutron-aria-agent.ini` 保持：
  - `full_resync_enabled = false`
  - `port_source = disabled`
  - `rpc_events_enabled = false`
  - `event_merge_interval = 0.2`

验证结果：

- 三台容器内均存在最新 `neutron_aria/agent/event_merge.py` 与 `neutron_aria/agent/rpc.py`。
- 三台容器内均可导入 `neutron_aria.agent.effective_acl` 与 `neutron_aria.agent.effective_qos`。
- 三台 `--report-once` 均可成功向 Neutron 上报 heartbeat。
- 三台均以 `python -m neutron_aria.agent.main ... --heartbeat-only` 启动临时常驻进程。
- 控制面查询 `neutron agent-list` 可见三个 `Aria ACL agent`，host 分别为 `ostack2.bj159.net`、`ostack3.bj159.net`、`ostack4.bj159.net`，alive 均为 `:-)`。

边界说明：

- 这是 RPC/event-merge 代码的 heartbeat-only 部署确认，不代表已经打开 RabbitMQ event consumer。
- `rpc_events_enabled=false` 时，不会消费 Neutron event，不会提交 snapshot，不会触碰 tap datapath。
- 进入真实 event smoke 前，必须先把 `full_resync_enabled=true`、`port_source=neutronclient`、UDS socket、OVS mount 和回滚流程补齐。

## 7. Unsupported Port 类型

| port 类型 | 命令 / 检查 | 期望 | 实际 | 证据路径 | 失败动作 |
| --- | --- | --- | --- | --- | --- |
| normal tap | 创建普通 VM port | supported | 未执行 | 未执行 | 不进入 N3 |
| trunk parent | 创建或查询 trunk port | `support_disposition=unsupported` 或 `DomainStatus=degraded` | 未执行 | 未执行 | 不假 ready |
| VLAN subport | 创建或查询 VLAN subport | `support_disposition=unsupported` 或 `DomainStatus=degraded` | 未执行 | 未执行 | 不假 ready |
| SR-IOV / direct | 查询 binding vnic type | `support_disposition=unsupported`，不假 ready | 未执行 | 未执行 | 标记 unsupported |
| macvtap | 查询 binding vnic type | `support_disposition=unsupported`，不假 ready | 未执行 | 未执行 | 标记 unsupported |

## 8. 内核、容器与 UDS 安全

| 项 | 命令 / 检查 | 期望 | 实际 | 证据路径 | 失败动作 |
| --- | --- | --- | --- | --- | --- |
| BTF `/sys/kernel/btf/vmlinux` | `test -r /sys/kernel/btf/vmlinux` | 可读 | 未执行 | 未执行 | datapath degraded |
| bpffs `/sys/fs/bpf` | `sh -c 'mount \| grep bpffs'` | 已挂载且持久 | 未执行 | 未执行 | 不进入 datapath ready |
| TC clsact/qdisc 能力 | `tc qdisc show dev <tap>` | 可 attach 或明确冲突策略 | 未执行 | 未执行 | attach degraded |
| XDP attach 能力 | `ip link show <tap>` + attach smoke | 明确支持或不采用 | 未执行 | 未执行 | 不使用 XDP path |
| `/run/aria` mount / owner / mode | `stat -c "%U %G %a" /run/aria` | `root:neutron-aria 0770` | 未执行 | 未执行 | socket 不启动 |
| socket owner / mode | `stat -c "%U %G %a" /run/aria/aria-agent.sock` | `aria-datapath:neutron-aria 0660` | 未执行 | 未执行 | `AriaSocketPermissionDenied` |
| peer credential | 本地非授权用户尝试连接 | 返回 `UDS_PEER_UNAUTHORIZED` | 未执行 | 未执行 | 不进入 deployment smoke gate |
| audit log | 写路径请求后检查 audit log | 有 uid/gid/pid/path/generation/result/error_code | 未执行 | 未执行 | `UDS_AUDIT_WRITE_FAILED` 或阻断写路径 |
| contract file 安装 | `sha256sum /etc/neutron-aria-agent/neutron-uds-contract.json` | 与 CI artifact 一致 | 未执行 | 未执行 | agent degraded，停止写路径 |
| 单实例锁策略 | 启动双实例 smoke | 第二实例退出或 `AgentHealth=degraded` | 未执行 | 未执行 | 不进入 deployment smoke gate |

## 9. 完成标准

N0.5-lite 必须完成：

- OVS only、tap 直接接入 `br-int`、无 `qvo/qvb/veth` 证据。
- Hook direction 至少覆盖 VM -> external 和 external -> VM。
- `integration_mode = "coexist"` 足够表达第一阶段语义。
- Aria `DomainStatus=degraded,effective_action=bypass` 不影响原 OVS 转发的最小 smoke。
- `/run/aria` 宿主机目录、owner/group/mode 和容器挂载策略已记录；真实 UDS socket、peer credential 和 audit log 实测留到 PR-1B/PR-6A。

完整 N0.5 必须完成：

- 本文件所有“实际”为结果或明确“不适用”，不得保留“未执行”。
- 每个关键结论都有命令、日志、配置路径或 smoke 输出证据。
- unsupported port 类型有 `support_disposition` 和必要的 `DomainStatus` 策略。
- ACL enhancement 输入源、mapping 权限和 tenant 隔离已验证。
- UDS contract file、peer credential、audit log、socket 权限已验证。
- 完整 N0.5 完成前，不进入 N3 目标环境验证。

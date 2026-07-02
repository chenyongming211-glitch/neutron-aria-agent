# OpenStack Target Environment Discovery

状态：G4 discovery accepted；完整 N0.5 仍按后续 gate 补齐
适用阶段：N0.5-lite / N0.5

本文件是进入 N3 目标环境功能闭环前必须补齐的发现记录。没有完成 N0.5-lite 项，不冻结 PR-1A schema；没有完成完整 N0.5 项，不进入 N3 目标环境 feature smoke。PR-6A/PR-6B 容器部署 smoke 只能验证部署和运行边界，不能替代本文件的 discovery 证据。

每一项都必须保留命令、期望、实际、证据和失败动作。证据可以是命令输出、日志片段、配置路径、截图或 smoke 结果文件。

## 0.1 2026-06-29 Stage-Two ACL MVP 证据索引

证据路径：`docs/evidence/openstack-n05-lite/2026-06-29-stage2-acl/summary.md`

本次记录只覆盖 stage-two ACL MVP 交付 gate：

- `aria_acl` Neutron service plugin/API/DB 在 `ostack2.bj159.net` 与
  `ostack3.bj159.net` 上通过安装、DB schema、REST CRUD smoke。
- `NeutronAclSource` 通过真实 Neutron API 读取 `aria_acl` policy/rule/binding，
  并提交 full-resync snapshot。
- `aria_acl_port_statuses` 可以从 Neutron API 读回 runtime reportback，
  包含 `last_reported_at`、`stale`、`runtime_status` 投影。
- `neutron-aria-agent` heartbeat 可以上报 generation lag、accepted/applied
  generation、domain counts、degraded reason summary。
- 发现一个交付约束：所有 active `neutron_server` 节点必须安装同一 bundle，
  否则 API 可能随机返回旧字段集。

这份 2026-06-29 证据本身只代表 ACL 输入闭环；后续 2026-06-30 证据已经补齐
G4 discovery、hook direction、rollback/connectivity、UDS hardening，以及
DHCP/metadata/IPv6 disposition。完整 N0.5 中与未来 N3/生产上线相关的持久化
hardening、legacy path、增量事件等项仍按本文件后续表格跟踪。

## 0.2 2026-06-30 N0.5 Discovery 证据索引

汇总证据：`docs/evidence/openstack-n05-lite/2026-06-30-discovery-summary.md`

逐主机证据：

| Host | Evidence Path | Result |
| --- | --- | --- |
| `ostack2.bj159.net` | `docs/evidence/openstack-n05-lite/20260630114142-ostack2.bj159.net/` | 18 pass, 3 unsupported, 0 fail |
| `ostack3.bj159.net` | `docs/evidence/openstack-n05-lite/20260630114142-ostack3.bj159.net/` | 16 pass, 3 unsupported, 2 not_applicable, 0 fail |
| `ostack4.bj159.net` | `docs/evidence/openstack-n05-lite/20260630114142-ostack4.bj159.net/` | 16 pass, 3 unsupported, 2 not_applicable, 0 fail |

G4 discovery 验收命令：

```bash
python ci/check_n05_discovery_evidence.py
```

验收结果：

```text
G4 N0.5 discovery evidence accepted
hosts=3
hosts_with_compute_iface_id=ostack2.bj159.net
unsupported=9
not_applicable=4
```

已确认：

- 三台均为 Rocky Linux 8.6，kernel
  `4.18.0-553.5.1.el8_10.x86_64`。
- 三台 OVS 版本均为 `3.3.5`，均存在 `br-int`。
- `ostack2`、`ostack3` neutron-server ML2 配置包含
  `openvswitch,linuxbridge,l2population,sriovnicswitch`。
- 三台均未发现 `qvo/qvb` hybrid-plug 链路。
- 三台均可读 BTF，且 bpffs 已挂载。
- Neutron 当前没有 QoS extension，宿主机缺 `tc`，QoS shaping 仍为
  `unsupported`。
- Neutron 当前没有 Trunk extension，当前三台本地端口 `vnic_type` 只发现
  `normal`，未发现 `direct`、`direct-physical`、`macvtap`、`baremetal`
  或 `virtio-forwarder`。
- 三台均可读取 UDS capabilities/status。
- 三台均可通过 `neutron_aria_agent` 读取 `aria_acl` API。
- `ostack4` 初始 agent egg 滞后，已通过 stage-two bundle 安装同版
  `neutron_aria` egg 并重启 `neutron_aria_agent` 修正。

剩余或带 disposition 的项：

- UDS peer credential / audit 已完成三节点可逆 hardening 证据；持久化 hardened
  rollout 尚未启用，仍作为正式上线前 gate。
- 真实 trunk、VLAN subport、SR-IOV/direct、macvtap 端口的 active 行为未验证；
  当前环境未暴露这些本地 port class，已记录 disposition。
- DHCP/metadata/IPv6 ND 已有 bounded guest 证据：DHCP 首次租约链路通过；
  metadata 请求到达 Neutron metadata namespace proxy，但目标环境 metadata
  backend Unix socket 缺失导致 HTTP 500；IPv6 ND 因无 IPv6 subnet 标记为
  `not_applicable`。

## 0.3 2026-06-30 G7 Rollback Connectivity 证据索引

汇总证据：`docs/evidence/openstack-n05-lite/2026-06-30-g7-rollback-summary.md`

逐主机证据：

| Host | Evidence Path | Result |
| --- | --- | --- |
| `ostack2.bj159.net` | `docs/evidence/openstack-n05-lite/20260630115838-ostack2.bj159.net/` | 7 pass, 0 fail |

已确认：

- `10.58.159.26` 在 smoke 前可达。
- `neutron_aria_rollback_connectivity_smoke.sh` 对
  `86b83885-671f-474c-9556-8af98cf1cdc8` / `tap86b83885-67` 执行
  ACL fixture full-resync，generation `81` 管理 5 个本地 compute tap ports。
- ICMP from `10.58.159.2/32` 被 smoke ACL 阻断，证明 external/host -> VM
  active path 已经过 datapath。
- UDS rollback 删除所有 5 个 managed ports，`rollback_remaining_managed_ports=0`，
  rollback 后 `managed_ports=[]`、`active_instances=[]`、`wal_replay_failures=0`。
- rollback 后 `10.58.159.26` 恢复可达。
- 停止 `neutron_aria_agent` 期间 `10.58.159.26` 仍保持 0% 丢包，重启后
  `Aria ACL agent` heartbeat 恢复为 `:-)`。
- 停止 `aria_datapath` 期间 `10.58.159.26` 仍保持 0% 丢包，重启后
  UDS status 恢复可读，且 `managed_ports=[]`、`active_instances=[]`、
  `wal_replay_failures=0`。

后续或带 disposition 的项：

- VM -> external active path 已通过临时 CirrOS guest-originated ICMP 证据接受；
  早先 host-initiated egress probe 仍保留为 rejected proof。
- DHCP/metadata/IPv6 ND bounded guest 证据已补齐到可验收 disposition：DHCP
  首次租约通过，metadata network path 到达 proxy 但目标 metadata backend
  degraded，IPv6 ND 当前 `not_applicable`。
- UDS peer credential/audit/hardened socket 已有三节点可逆证据；持久化 rollout
  尚未启用。

## 0.4 2026-06-30 Active Direction Evidence

Summary evidence:
`docs/evidence/openstack-n05-lite/2026-06-30-active-direction-summary.md`

Accepted:

- external/host -> VM active ACL evidence is covered by
  `docs/evidence/openstack-n05-lite/20260630115838-ostack2.bj159.net/`.
- VM -> external/host active ACL evidence is covered by
  `docs/evidence/openstack-n05-lite/20260630145200-ostack2.bj159.net-cirros-vm-egress-final/`.

Rejected as proof:

- `docs/evidence/openstack-n05-lite/20260630121023-ostack2.bj159.net/`
  submitted an `ACL_DIRECTION=egress` policy and rolled back cleanly, but the
  host-initiated ping was not blocked. This is not counted as VM -> external
  evidence because the echo-reply is reverse traffic for a stateful inbound
  flow, not a VM-initiated flow.

Guest access status:

Detailed read-only audit:
`docs/evidence/openstack-n05-lite/20260630134000-ostack2.bj159.net-guest-access-audit/`

- `wp-test` / `10.58.159.26`: SSH unavailable; QEMU guest agent is not
  configured.
- `cym_vfw1` / `10.58.159.28`: SSH port reachable inside the cloud, but
  existing root/admin/centos key auth was denied.
- `test1111` / `10.58.159.27`: SSH refused; console is `SecOS login:`; QEMU
  guest agent is not configured.
- `cym_hlas_test` / `10.58.159.29`: SSH refused; console is Rocky Linux
  `LAS login:` with cloud-init fallback datasource; QEMU guest agent is not
  configured.
- Existing servers all report `key_name=null`. Legacy `nova`/`glance` clients can
  list product images and create an RSA keypair; the newer `openstack image
  list` path still returns HTTP 404 in this client context.
- Short-lived `qcsp` and `hlas` test VMs were booted with config-drive and the
  temporary RSA keypair. Both produced ACTIVE Neutron ports, direct OVS tap
  attachment, and host-to-VM ping, then were deleted. Neither produced a usable
  SSH/QGA guest execution channel.

The accepted VM-originated evidence used a temporary raw CirrOS image and
key-injected guest SSH to start a ping loop. tcpdump captured packets before the
ACL, captured 0 matching packets after generation `85` reached UDS `ready`, and
captured packets again after UDS rollback. Temporary server/keypair/image/files
were cleaned up after the run. A later bounded CirrOS guest probe with explicit
`--nic net-id=23eb9d08-ec8b-4610-a1ff-61492134b6d2` collected
DHCP/metadata/IPv6 disposition evidence: DHCP initial lease passed, metadata
traffic reached the Neutron metadata namespace proxy but returned HTTP 500
because the proxy backend Unix socket was missing (`ENOENT`), and IPv6 ND is
`not_applicable` in the current IPv4-only target networks.

## 0.5 2026-06-30 DHCP / Metadata / IPv6 Guest Probe Evidence

Read-only evidence:
`docs/evidence/openstack-n05-lite/20260630153231-ostack2.bj159.net-service-path-readonly/`

Bounded guest evidence:
`docs/evidence/openstack-n05-lite/20260630155334-ostack2.bj159.net-guest-bypass-probe/`

Accepted for disposition:

- DHCP agents are alive on `ostack2.bj159.net` and `ostack3.bj159.net`.
- Metadata agents are alive on `ostack2.bj159.net` and `ostack3.bj159.net`.
- UDS status remained `authority_state=ready`, `managed_ports=[]`, and
  `active_instances=[]` during the read-only service-path and bounded guest
  checks.
- A temporary CirrOS VM `10.58.159.40/25` received DHCP through Neutron dnsmasq;
  `service-logs.txt` records `DHCPOFFER`, `DHCPREQUEST`, and `DHCPACK`.
- The CirrOS image does not include an executable `udhcpc`, so explicit DHCP
  renew is marked `not_applicable`; the initial DHCP request/lease path is the
  accepted DHCP evidence for this environment.
- The guest had a route to `169.254.169.254` via `10.58.159.24`, and the
  Neutron metadata namespace proxy accepted HTTP from `10.58.159.40`. The
  endpoint returned HTTP 500 because the proxy backend Unix socket was missing
  (`ENOENT`). This is recorded as target metadata service degraded, not an Aria
  ACL block.
- `neutron subnet-list` and guest route evidence show only IPv4 CIDRs, so IPv6
  ND is `not_applicable` for the current target networks.

Operational note:

- The old Nova API in this target environment fails boot requests that omit
  explicit network selection (`request_networks=None`). Temporary probe VMs must
  pass `--nic net-id=23eb9d08-ec8b-4610-a1ff-61492134b6d2`.

## 0.6 2026-06-30 UDS Hardened Rollout Evidence

Summary evidence:
`docs/evidence/openstack-n05-lite/2026-06-30-uds-hardening-summary.md`

Accepted:

- `ostack2.bj159.net`, `ostack3.bj159.net`, and `ostack4.bj159.net` have
  reversible `REQUIRE_HARDENED=true` proofs using
  `aria-datapath:peercred-test-202606301305`.
- During the hardened window, `/run/aria/aria-agent.sock` was
  `root:42435 0660`, matching the recorded `neutron_aria_agent` neutron
  UID/GID allow-list candidate.
- A UDS probe from the `neutron_aria_agent` container as the `neutron` user
  returned HTTP 200 from `/api/v1/neutron/status`.
- The audit log recorded `result=allowed` and
  `reason=peercred_allow_list_match`.
- The rollout smoke restored the original `aria_datapath` container and config
  after evidence collection.

Validation:

```bash
python ci/check_uds_hardening_evidence.py \
  --evidence-dir docs/evidence/openstack-n05-lite/20260630131254-ostack2.bj159.net \
  --evidence-dir docs/evidence/openstack-n05-lite/20260630133213-ostack3.bj159.net \
  --evidence-dir docs/evidence/openstack-n05-lite/20260630133213-ostack4.bj159.net \
  --min-hosts 3 \
  --require-hardened
```

Remaining:

- Persistent hardened rollout on `ostack2/3/4` is not enabled yet; the restored
  baseline still uses the previous smoke-functional `0666` socket.

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
| OpenStack 发行版与版本 | `openstack --version`；记录发行版包版本 | 明确发行版和客户端版本 | 三台采集到 `openstack 1.7.1`；发行版为 Rocky Linux 8.6 | `docs/evidence/openstack-n05-lite/2026-06-30-discovery-summary.md` | 不能进入完整 N0.5 |
| Neutron ML2 mechanism driver | `grep -R "mechanism_drivers" /etc/neutron/plugins/ml2/` | 包含 OVS 相关 driver，不采用 OVN | `ostack2/3` neutron-server 配置为 `mechanism_drivers=openvswitch,linuxbridge,l2population,sriovnicswitch`；未见 OVN | `docs/evidence/openstack-n05-lite/2026-06-30-discovery-summary.md` | 不冻结 attach/direction 结论 |
| compute host OS / kernel | `uname -a`; `cat /etc/os-release` | 记录 kernel 和 OS | 三台均为 kernel `4.18.0-553.5.1.el8_10.x86_64`，Rocky Linux 8.6 | `docs/evidence/openstack-n05-lite/2026-06-30-discovery-summary.md` | 不进入 eBPF attach smoke |
| OVS 版本 | `ovs-vsctl --version` | 记录 OVS 版本 | 三台均为 Open vSwitch `3.3.5` | `docs/evidence/openstack-n05-lite/2026-06-30-discovery-summary.md` | 不进入 OVS smoke |
| 目标部署形态 | `openstack network agent list --host <compute>` | OVS only | 三台均有 `Aria ACL agent` heartbeat；ML2 同时启用 OVS/Linuxbridge/SRIOV 机制，当前 Aria MVP 仅按 OVS tap 证据推进 | `docs/evidence/openstack-n05-lite/2026-06-30-discovery-summary.md` | 若存在 OVN/Linux bridge，当前阶段不支持 |

## 2. OVS 与 Tap 拓扑

| 项 | 命令 / 检查 | 期望 | 实际 | 证据路径 | 失败动作 |
| --- | --- | --- | --- | --- | --- |
| VM tap 是否直接接入 `br-int` | `ovs-vsctl show`; `ovs-vsctl list interface <tap>` | tap 直接在 `br-int` 上 | `ostack2` 有 5 个 compute ports 且 br-int 上可见对应 tap；`ostack3/4` 当前无 compute ports，VM tap `iface-id`/XDP 证据为 not_applicable | `docs/evidence/openstack-n05-lite/2026-06-30-discovery-summary.md` | 不冻结 PR-1A direction 字段 |
| 是否存在 `qvo/qvb/veth` 路径 | `sh -c 'ip link show \| egrep "qvo\|qvb\|veth"'` | 目标 VM 无 hybrid plug 路径 | 三台均未发现 `qvo/qvb` hybrid-plug 链路 | `docs/evidence/openstack-n05-lite/2026-06-30-discovery-summary.md` | 当前阶段不支持该环境 |
| tap 命名模式 | `sh -c 'ip link show \| grep tap'`; `ovs-vsctl list interface` | 可稳定映射 Neutron port | `ostack2` compute ports 映射到 `tap<port-id-prefix>`；`ostack3/4` 当前 compute_ports=0 | `docs/evidence/openstack-n05-lite/2026-06-30-discovery-summary.md` | 不进入 N3 smoke |
| `binding_host` 与 hostname 映射 | `hostname -f`; Neutron port binding 查询 | `binding_host` 与本机 host 一致 | `ostack2` 5 个 compute port 的 `binding_host=ostack2.bj159.net`；`ostack3/4` 当前 compute_ports=0 | `docs/evidence/openstack-n05-lite/2026-06-30-discovery-summary.md` | adapter host 配置不得冻结 |
| OVS agent / ovs-vswitchd / ovsdb-server 重启行为 | 重启服务并记录 tap/ifindex/XDP 和 VM forwarding 变化 | tap 仍存在且 XDP/map 健康时 ACL attach 可保持 ready；tap 消失或 ifindex 改变时按 tap recreate 恢复；VM ping 单独作为 OVS forwarding 证据 | 2026-07-01 ACL-focused smoke passed: test harness restarted `ovs-vswitchd.service`, target tap stayed at ifindex 71 with XDP attached, ACL remained `ready/enforce`, rollback left zero managed ports, and VM forwarding recovered after 8 seconds | `docs/evidence/openstack-n05-lite/20260701-stage3-ovs-restart-acl-focused-probe/summary.md` | 无 |

## 3. Hook Direction 矩阵

| 流量方向 | 命令 / 检查 | 期望 | 实际 | 证据路径 | 失败动作 |
| --- | --- | --- | --- | --- | --- |
| VM -> same host VM | tcpdump / tc trace / eBPF test hook | 明确 XDP/TC 可见点 | 未执行 | 未执行 | 不冻结 ACL/QoS direction |
| VM -> external | tcpdump / tc trace / eBPF test hook | 明确 egress/ingress 映射 | 临时 CirrOS VM `10.58.159.35` 从 guest 内发起 ICMP；egress ACL generation `85` ready 后 tcpdump 捕获 0 包；UDS rollback 后恢复捕获 | `docs/evidence/openstack-n05-lite/20260630145200-ostack2.bj159.net-cirros-vm-egress-final/` | 保留为 active ACL direction 验收证据 |
| external -> VM | tcpdump / tc trace / eBPF test hook | 明确 ingress 映射 | `ostack2` -> VM `10.58.159.26` 的 ICMP 在 ACL full-resync 后被阻断，UDS rollback 后恢复；datapath HTTP policy 显示对应 drop ACL | `docs/evidence/openstack-n05-lite/2026-06-30-g7-rollback-summary.md` | 不进入 N3 smoke |
| DHCP | DHCP request/renew smoke | bypass 不影响 DHCP | DHCP agents alive；UDS `managed_ports=[]`；guest `10.58.159.40/25` 获取动态 IPv4，dnsmasq 记录 `DHCPOFFER/DHCPREQUEST/DHCPACK`；显式 renew 因 CirrOS 无可执行 `udhcpc` 标记 `not_applicable` | `docs/evidence/openstack-n05-lite/20260630155334-ostack2.bj159.net-guest-bypass-probe/` | 默认只允许 bypass，不启用相关 ACL；若换用含 DHCP client 的镜像，可补 explicit renew |
| metadata | curl metadata endpoint smoke | bypass 不影响 metadata | Metadata agents alive；guest 有 `169.254.169.254 via 10.58.159.24` 路由，请求到达 Neutron metadata namespace proxy；HTTP 500 原因为 backend Unix socket `ENOENT`，记为目标 metadata service degraded，不是 Aria block | `docs/evidence/openstack-n05-lite/20260630155334-ostack2.bj159.net-guest-bypass-probe/` | 修复目标 metadata service 后重测 HTTP 200 内容；不扩 Aria 功能 |
| IPv6 ND | `ping6` / neighbor discovery smoke | bypass 不影响 ND | 当前 Neutron subnet 只发现 IPv4 CIDR，guest 无 IPv6 global route；本环境标记 `not_applicable`，新增 IPv6 network 后重测 | `docs/evidence/openstack-n05-lite/20260630155334-ostack2.bj159.net-guest-bypass-probe/` | N3 如启用 IPv6 network，必须补 IPv6 ND guest probe |

## 4. Aria Bypass Smoke

| 场景 | 命令 / 检查 | 期望 | 实际 | 证据路径 | 失败动作 |
| --- | --- | --- | --- | --- | --- |
| `aria-datapath` 未启动 | VM 连通性 smoke | OVS 原有转发不受影响 | `ostack2` 上 rollback 后停止 `aria_datapath` 时，VM `10.58.159.26` ping 0% 丢包；重启后 UDS status 可读且 `managed_ports=[]` | `docs/evidence/openstack-n05-lite/2026-06-30-g7-rollback-summary.md` | 不进入 N3 |
| `neutron-aria-agent` degraded | 停止 agent 后连通性 smoke | OVS 原有转发不受影响 | `ostack2` 上停止 `neutron_aria_agent` 时，VM `10.58.159.26` ping 0% 丢包；重启后 agent heartbeat 恢复 | `docs/evidence/openstack-n05-lite/2026-06-30-g7-rollback-summary.md` | 修正 agent degraded 语义 |
| ACL rollback cleanup | 下发显式 ACL 后 UDS delete rollback | rollback 后 VM 连通性恢复，`managed_ports=[]` | generation `81` 下发 ICMP drop 后 ping 被阻断；UDS rollback 删除 5 个 managed ports，`rollback_remaining_managed_ports=0`，VM ping 恢复 | `docs/evidence/openstack-n05-lite/2026-06-30-g7-rollback-summary.md` | 不允许进入 ready |
| `aria_acl` binding 缺失 | 无 ACL binding VM 连通性 smoke | port 保持 bypass | 未执行 | 未执行 | 修正 translator 默认行为 |
| `aria_acl` policy 缺失或不可访问 | binding 指向不存在/无权限 policy | `DomainStatus=degraded,effective_action=bypass`，OVS 转发不受影响 | 未执行 | 未执行 | 修正错误码和 status |
| ACL apply 失败注入 | 注入 ACL compile/apply failure | `DomainStatus=degraded,effective_action=bypass`，OVS 转发不受影响 | 未执行 | 未执行 | 不允许进入 ready |

## 5. 显式 ACL Enhancement 输入源

生产输入源固定为 `aria_acl` Neutron service plugin/API/DB。下面的 legacy tag/mapping 项只用于探测历史环境是否存在旧辅助路径，不能作为生产控制面契约或 N3 验收主线。

| 项 | 命令 / 检查 | 期望 | 实际 | 证据路径 | 失败动作 |
| --- | --- | --- | --- | --- | --- |
| `aria_acl` extension | `openstack extension list --network` 或 legacy neutron extension list | 能看到 `aria-acl` | 2026-06-29 stage-two gate 通过；`ostack2`、`ostack3` 的 `neutron extension-list` 均可见 `aria-acl` | `docs/evidence/openstack-n05-lite/2026-06-29-stage2-acl/summary.md` | 任一 active `neutron_server` 未安装同一 bundle 时，不进入生产 ACL feature gate |
| `aria_acl` API CRUD | 创建/查询 policy、rule、address-set、binding | admin/operator 可操作，request id 可追踪 | 2026-06-29 stage-two gate 通过；plugin DB CRUD 与 REST CRUD 均为 `ok` | `docs/evidence/openstack-n05-lite/2026-06-29-stage2-acl/summary.md` | 不启动 `acl_source=neutron` |
| `aria_acl` effective read path | 查询 port effective ACL | 返回 policy/rules/revision/project 信息 | 阶段二 MVP 通过；`NeutronAclSource` 从真实 Neutron API 读到 `policies=1 rules=1 bindings=1` 并生成 full-resync snapshot。Port-show effective 字段仍属后续产品化增强 | `docs/evidence/openstack-n05-lite/2026-06-29-stage2-acl/summary.md` | `NeutronAclSource` 不得宣称完整增量 ready |
| `aria_acl` DB/revision | 检查 revision_number 和 binding 更新 | revision 单调，agent 能识别更新 | DB schema upgrade/check 通过；七张 `aria_acl` 表存在。Revision/增量事件 gate 尚未完成 | `docs/evidence/openstack-n05-lite/2026-06-29-stage2-acl/summary.md` | 不进入增量事件 gate |
| legacy Neutron tag key | 查询 port/network tag | 仅记录是否存在历史 `aria:acl=<policy-id>`；不作为生产输入 | 未执行 | 未执行 | 不影响生产 ACL gate |
| legacy mapping 文件路径 | 检查配置与文件 | 仅记录是否存在历史 `/etc/neutron-aria-agent/acl-policies.yaml` | 未执行 | 未执行 | 不影响生产 ACL gate |
| legacy tenant 是否可直接写 ACL mapping | tenant 权限验证 | 如存在 legacy mapping，也必须不允许 tenant 写 | 未执行 | 未执行 | 标记 legacy path unsupported |
| Security Group projection | 检查 translator 输入和 schema | 不支持 / 不进入第一阶段 | 未执行 | 未执行 | 删除 SG projection 相关输入 |
| remote group / port security / allowed address pairs | 检查 translator 输入和 schema | 不作为 ACL enhancement 输入 | 未执行 | 未执行 | 删除相关输入字段 |

## 6. Neutron Agent 与 RPC

| 项 | 命令 / 检查 | 期望 | 实际 | 证据路径 | 失败动作 |
| --- | --- | --- | --- | --- | --- |
| agent type 名称 | `openstack network agent list` | 明确 agent type | 2026-06-29 可见 `Aria ACL agent`，host 包含 `ostack2.bj159.net`、`ostack3.bj159.net`、`ostack4.bj159.net`，alive 为 `:-)` | `docs/evidence/openstack-n05-lite/2026-06-29-stage2-acl/summary.md` | 不冻结 heartbeat |
| heartbeat 注册方式 | 查 Neutron agent 配置和日志 | agent alive/degraded 可上报 | 阶段二 MVP 通过；`agent-show` configurations 可见 generation lag、accepted/applied generation、domain counts、degraded reasons | `docs/evidence/openstack-n05-lite/2026-06-29-stage2-acl/summary.md` | 不进入后续状态验收 |
| port binding/full resync API | mock 或目标环境查询 | 可按 host 拉取 authoritative ports | 阶段二 MVP 通过；`ostack2` host ports=8、compute ports=5，snapshot generation 78；`ostack3` host ports=3、compute ports=0，snapshot generation 15 | `docs/evidence/openstack-n05-lite/2026-06-29-stage2-acl/summary.md` | 不进入 translator full resync |
| port update event source | RPC topic / callback / polling 记录 | 有明确 event source | 未执行 | 未执行 | PR-4 只能使用 full resync |
| 第一阶段功能白名单 | 检查主方案、schema、translator、PR gate | 只包含 ACL enhancement 和 QoS；其它能力只能是支撑能力或保留代码 | stage-two ACL gate 只打开 `aria_acl` production input；QoS/Mirror/RPC event 未随本 gate 启用 | `docs/evidence/openstack-n05-lite/2026-06-29-stage2-acl/summary.md` | 删除非 ACL/QoS 的功能模块入口 |
| QoS extension 可用性 | 查 Neutron extension list | 明确 `support_disposition=supported` 或 `unsupported` | 三台 discovery 均未发现 QoS extension；`support_disposition=unsupported` | `docs/evidence/openstack-n05-lite/2026-06-30-discovery-summary.md` | PR-5B 降级或延期 |
| Trunk extension 可用性 | 查 Neutron extension list | 明确 `support_disposition=supported` 或 `unsupported` | 三台 discovery 均未发现 Trunk extension；`support_disposition=unsupported` | `docs/evidence/openstack-n05-lite/2026-06-30-discovery-summary.md` | trunk/VLAN subport 不进入当前阶段 |
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
  - `incremental_rpc_enabled = false`
  - `event_merge_interval = 0.2`

验证结果：

- 三台容器内均存在最新 `neutron_aria/agent/event_merge.py` 与 `neutron_aria/agent/rpc.py`。
- 三台容器内均可导入 `neutron_aria.agent.effective_acl` 与 `neutron_aria.agent.effective_qos`。
- 三台 `--report-once` 均可成功向 Neutron 上报 heartbeat。
- 三台均以 `python -m neutron_aria.agent.main ... --heartbeat-only` 启动临时常驻进程。
- 三台临时进程 stdout/stderr 已切到 `/var/log/kolla/neutron/neutron-aria-agent.log`，文件存在且可看到启动记录。
- 2026-06-24 更新：提交 `e68e1aa` 已刷新到三台临时进程，日志文件可看到 `service_initialize`、`heartbeat_reported`、`service_result`，且包含 host、generation、snapshot_ports、managed_ports、degraded reason、event counters。
- 控制面查询 `neutron agent-list` 可见三个 `Aria ACL agent`，host 分别为 `ostack2.bj159.net`、`ostack3.bj159.net`、`ostack4.bj159.net`，alive 均为 `:-)`。

边界说明：

- 这是 RPC/event-merge 代码的 heartbeat-only 部署确认，不代表已经打开 RabbitMQ event consumer。
- `rpc_events_enabled=false` 时，不会消费 Neutron event，不会提交 snapshot，不会触碰 tap datapath。
- `incremental_rpc_enabled=false` 时，不会执行 P3 port-scoped apply。
- 进入真实 event smoke 前，必须先把 `full_resync_enabled=true`、`port_source=neutronclient`、UDS socket、OVS mount 和回滚流程补齐。

### 6.3 2026-06-24 Independent Kolla Container Smoke

Hosts: `ostack2.bj159.net`, `ostack3.bj159.net`, `ostack4.bj159.net`

Deployment shape:
- Built `neutron-aria-agent:smoke-e68e1aa` from the onsite OVS agent image family.
- Started an independent container named `neutron_aria_agent` on each host.
- Prepared Kolla config under `/etc/kolla/neutron-aria-agent`.
- Kept product-safe heartbeat-only mode:
  - `full_resync_enabled = false`
  - `port_source = disabled`
  - `rpc_events_enabled = false`
  - `incremental_rpc_enabled = false`
- Logs are written to `/var/log/kolla/neutron/neutron-aria-agent.log`.

Validation result:
- The previous temporary embedded `neutron-aria-agent` process inside `neutron_openvswitch_agent` was stopped on all three hosts.
- The independent `neutron_aria_agent` container is `Up` on all three hosts.
- Logs on all three hosts show `agent_start`, `service_initialize`, `heartbeat_reported`, and `service_result`.
- `neutron agent-list` shows alive `Aria ACL agent` entries for all three hosts.

Boundary:
- This is an independent Kolla-style container smoke, not yet a full product Kolla rollout or registry-published image flow.
- Full resync, RPC event consumption, UDS snapshot submission, and tap datapath writes remain disabled.
- Before enabling full-resync smoke, the next gate is local `aria-agent` UDS readiness, OVS mount validation, rollback flow, and authoritative port-source credentials.

### 6.4 2026-06-24 Full-Resync Smoke Gate

Host: `ostack2.bj159.net`

Gate checks:
- Started a temporary Rust `aria-agent` from the existing smoke artifact with:
  - `mode = "neutron_managed"`
  - `auto_attach = false`
  - `neutron_socket_path = "/run/aria/aria-agent.sock"`
- Restarted the independent `neutron_aria_agent` container with `/run/aria` mounted.
- Rebuilt the smoke Python image so the container process runs as root. This is required because the target host exposes `/run/openvswitch/db.sock` as `root:root 0750`; the image's `neutron` user cannot read OVSDB.
- Confirmed UDS capabilities:
  - `api_version = v1`
  - `attach_authority = neutron_snapshot`
  - `supports_full_snapshot = true`
  - `supports_port_delete = true`
  - `supported_domains` includes `acl`
- Confirmed initial UDS status had `managed_ports = []`.
- Confirmed legacy neutronclient could list local ports for `ostack2.bj159.net`:
  - total host ports: 5
  - compute ports: 2
- Submitted one full-resync snapshot through `neutron-aria-agent --once --enable-full-resync`.
- UDS post-status showed two managed ports:
  - `86b83885-671f-474c-9556-8af98cf1cdc8` -> `tap86b83885-67`, ifindex `26`, domains `["acl"]`
  - `e607e86b-9e5f-4c63-a5df-3dc8986a1b0f` -> `tape607e86b-9e`, ifindex `27`, domains `["acl"]`
- Rollback used `DELETE /api/v1/neutron/ports/{port_id}` for both ports.
- Final UDS status returned `active_instances = []` and `managed_ports = []`.
- `ip -d link show` on both tap ports showed no XDP attachment after rollback.
- `neutron agent-list` still showed the `Aria ACL agent` on `ostack2.bj159.net` as alive.

Boundary:
- This validates full-resync smoke mechanics on one compute host.
- The long-running `neutron_aria_agent` service remains heartbeat-only in its default config.
- RPC event consumption remains disabled.
- The Rust `aria-agent` used here is a temporary host process, not yet a product Kolla service.
- This root/OVSDB path is legacy smoke only. Final product shape must keep `neutron-aria-agent` non-privileged and move OVSDB/tap validation into the privileged `aria-datapath` container.

## 7. Unsupported Port 类型

| port 类型 | 命令 / 检查 | 期望 | 实际 | 证据路径 | 失败动作 |
| --- | --- | --- | --- | --- | --- |
| normal tap | 查询 host-bound ports 与 `binding:vnic_type` | supported | `ostack2` 有 8 个本地 `normal` vnic ports，其中 5 个 compute ports；`ostack3` 有 3 个本地 `normal` vnic ports；`ostack4` 当前 0 个本地 ports | `docs/evidence/openstack-n05-lite/2026-06-30-discovery-summary.md` | 不进入 N3 |
| trunk parent | 查询 Trunk extension 与本地 port class | `support_disposition=unsupported` 或 `DomainStatus=degraded` | 三台未发现 Trunk extension；当前未发现本地 trunk port | `docs/evidence/openstack-n05-lite/2026-06-30-discovery-summary.md` | 不假 ready |
| VLAN subport | 查询 Trunk extension 与本地 port class | `support_disposition=unsupported` 或 `DomainStatus=degraded` | 三台未发现 Trunk extension；当前未发现本地 VLAN subport | `docs/evidence/openstack-n05-lite/2026-06-30-discovery-summary.md` | 不假 ready |
| SR-IOV / direct | 查询 binding vnic type | `support_disposition=unsupported`，不假 ready | 本次本地 port class 未发现 `direct` / `direct-physical` / `baremetal` | `docs/evidence/openstack-n05-lite/2026-06-30-discovery-summary.md` | 标记 unsupported |
| macvtap | 查询 binding vnic type | `support_disposition=unsupported`，不假 ready | 本次本地 port class 未发现 `macvtap` | `docs/evidence/openstack-n05-lite/2026-06-30-discovery-summary.md` | 标记 unsupported |

## 8. 内核、容器与 UDS 安全

| 项 | 命令 / 检查 | 期望 | 实际 | 证据路径 | 失败动作 |
| --- | --- | --- | --- | --- | --- |
| BTF `/sys/kernel/btf/vmlinux` | `test -r /sys/kernel/btf/vmlinux` | 可读 | 三台均可读 | `docs/evidence/openstack-n05-lite/2026-06-30-discovery-summary.md` | datapath degraded |
| bpffs `/sys/fs/bpf` | `sh -c 'mount \| grep bpffs'` | 已挂载且持久 | 三台均已挂载 bpffs | `docs/evidence/openstack-n05-lite/2026-06-30-discovery-summary.md` | 不进入 datapath ready |
| TC clsact/qdisc 能力 | `tc qdisc show dev <tap>` | 可 attach 或明确冲突策略 | 三台均缺 `tc` 命令；QoS shaping 标记 `unsupported` | `docs/evidence/openstack-n05-lite/2026-06-30-discovery-summary.md` | attach degraded |
| XDP attach 能力 | `ip link show <tap>` + attach smoke | 明确支持或不采用 | `ostack2/3` 已记录当前 tap XDP status；`ostack4` 无本地 VM tap，`not_applicable`。未执行主动 attach | `docs/evidence/openstack-n05-lite/2026-06-30-discovery-summary.md` | 不使用 XDP path |
| `/run/aria` mount / owner / mode | `stat -c "%U %G %a" /run/aria` | `root:neutron-aria 0770` | 三台为 `/run/aria root:UNKNOWN 0770`，smoke-functional 但非最终 hardened group | `docs/evidence/openstack-n05-lite/2026-06-30-discovery-summary.md` | socket 不启动 |
| socket owner / mode | `stat -c "%U %G %a" /run/aria/aria-agent.sock` | `aria-datapath:neutron-aria 0660` | discovery baseline 为 `root:root 0666`；三节点可逆 hardening proof 期间为 `root:42435 0660`；持久化 rollout 尚未启用 | `docs/evidence/openstack-n05-lite/2026-06-30-uds-hardening-summary.md` | `AriaSocketPermissionDenied` |
| peer credential | 记录容器 uid/gid，并在 enforcement 模式拒绝非授权 peer | 三台均记录 `neutron_aria_agent` 的 `neutron` UID/GID `42435`，groups `42435 42400`；`REQUIRE_HARDENED=true` proof 已验证 allow-list match | `docs/evidence/openstack-n05-lite/2026-06-30-uds-hardening-summary.md` | 持久化 hardened rollout 前复核生产容器 uid/gid |
| audit log | 写路径请求后检查 audit log | 有 uid/gid/pid/path/generation/result/error_code | 三节点 hardening proof 期间 audit 记录 `result=allowed`、`reason=peercred_allow_list_match`；baseline restore 后不保留为持久化配置 | `docs/evidence/openstack-n05-lite/2026-06-30-uds-hardening-summary.md` | `UDS_AUDIT_WRITE_FAILED` 或阻断写路径 |
| contract file 安装 | `sha256sum /etc/neutron-aria-agent/neutron-uds-contract.json` | 与 CI artifact 一致 | discovery 已验证 UDS capabilities/status 可读；contract artifact 安装 hash 仍未执行 | `docs/evidence/openstack-n05-lite/2026-06-30-discovery-summary.md` | agent degraded，停止写路径 |
| 单实例锁策略 | 启动双实例 smoke | 第二实例退出或 `AgentHealth=degraded` | 未执行 | 未执行 | 不进入 deployment smoke gate |

2026-06-30 UDS peercred gate update:

- Repository/config gate: `ci/check_neutron_stage1.py` checks the
  non-world-writable UDS mode, audit-only safe defaults,
  `neutron_peercred_*` config fields, `SO_PEERCRED` source hook, and
  `docs/neutron-uds-contract.json` phase status.
- Evidence-only field gate: `neutron_aria_uds_hardening_smoke.sh` recorded the
  10.58.159 container uid/gid allow-list candidates on all three hosts.
- Field enforcement gate: three-node reversible `REQUIRE_HARDENED=true`
  evidence is accepted. Persistent rollout still needs the same uid/gid
  allow-list and socket policy to be applied through the formal deployment path.

## 9. 完成标准

N0.5-lite 必须完成：

- OVS only、tap 直接接入 `br-int`、无 `qvo/qvb/veth` 证据。
- Hook direction 至少覆盖 VM -> external 和 external -> VM；已通过
  `2026-06-30-active-direction-summary.md` 中的 accepted evidence 覆盖。
- `integration_mode = "coexist"` 足够表达第一阶段语义。
- Aria `DomainStatus=degraded,effective_action=bypass` 不影响原 OVS 转发的最小 smoke。
- `/run/aria` 宿主机目录、owner/group/mode 和容器挂载策略已记录；UDS peer credential / audit 的 repository/config gate 已具备，现场 enforcement 实测留到记录真实 uid/gid allow-list 后执行。

完整 N0.5 必须完成：

- 本文件所有“实际”为结果或明确“不适用”，不得保留“未执行”。
- 每个关键结论都有命令、日志、配置路径或 smoke 输出证据。
- unsupported port 类型有 `support_disposition` 和必要的 `DomainStatus` 策略。
- `aria_acl` 生产输入源、legacy mapping 定位和 tenant 隔离已验证。
- UDS contract file、peer credential、audit log、socket 权限已验证。
- 完整 N0.5 完成前，不进入 N3 目标环境验证。
## 2026-06-30 G4 UDS Hardening Update

`ostack2.bj159.net`, `ostack3.bj159.net`, and `ostack4.bj159.net` now have
reversible UDS hardened rollout proofs using
`aria-datapath:peercred-test-202606301305`. During each proof window the socket
was `root:42435 0660`, the `neutron` user in `neutron_aria_agent` received
HTTP 200 from `/api/v1/neutron/status`, and peercred audit recorded
`peercred_allow_list_match`. The rollout smoke restored each original
`aria_datapath` container and config after evidence collection. Persistent
three-host rollout is still pending.

## 2026-07-02 P3-1 Projection Heartbeat Update

`ostack2.bj159.net`, `ostack3.bj159.net`, and `ostack4.bj159.net` now have
accepted P3-1 heartbeat/debug observability evidence:

- Current `neutron_aria` egg was installed into each running
  `neutron_aria_agent` container.
- Only `neutron_aria_agent` was restarted on each host.
- `neutron_aria_rpc_event_smoke.sh` passed on all three hosts.
- `neutron_aria_heartbeat_smoke.sh` passed with
  `REQUIRE_HEARTBEAT_SUMMARY_FIELDS=true` and
  `REQUIRE_P3_PROJECTION_FIELDS=true` for all three hosts.

Evidence:
`docs/evidence/openstack-n05-lite/20260702-p3-projection-heartbeat-3node/summary.md`.

Boundary: this proves read-only P3-1 projection/decision observability only.
`incremental_rpc_enabled` remains `false`; no port-scoped snapshot apply,
Rust datapath incremental path, OVS restart, OVS-agent restart, Neutron-server
restart, or `aria-datapath` restart was performed.

## 2026-07-02 P3 Revisionless Experimental Update

`ostack2.bj159.net` has controlled legacy-mode evidence for P3 port-scoped
apply when the old Neutron API returns no port `revision_number`.

- Current `neutron_aria` egg was installed into the running
  `neutron_aria_agent` container.
- Only `neutron_aria_agent` was restarted to load the Python egg.
- `neutron_aria_rpc_event_smoke.sh` passed.
- `neutron_aria_rpc_fanout_smoke.sh` passed with
  `INCREMENTAL_RPC_ENABLED=true` and
  `REVISIONLESS_INCREMENTAL_MODE=experimental`.
- The enabled leg selected a currently projected local managed port, consumed
  a real RabbitMQ `port.update`, and reached `port_scoped_snapshot_complete`.
- Rollback left `managed_ports=0`.

Evidence:
`docs/evidence/openstack-n05-lite/20260702-p3-revisionless-experimental-fanout/summary.md`.

Boundary: this proves the explicit test-only revisionless P3 path can run in
the legacy lab. Production P3 remains revision-aware; old Neutron defaults to
P2 full-resync fallback unless a controlled test explicitly enables
`revisionless_incremental_mode=experimental`.

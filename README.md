# Aria Firewall

Aria Firewall 是基于 eBPF/XDP/TC 的主机侧网络执行与观测组件。当前 `v0.9-neutron-agent` 分支的重点不是继续扩展本地 CLI 功能菜单，而是把现有 datapath 能力整理成 OpenStack Neutron Agent Mode 可落地的形态。

当前分支基线：

- 基线分支：`v0.9.0`
- 目标分支：`v0.9-neutron-agent`
- 现有 Rust 二进制仍是 `aria-agent`
- OpenStack 运行角色名和容器名使用 `aria-datapath`
- OpenStack 适配层为 `neutron-aria-agent`
- 不引入 `aria-controller`
- 不迁移 v0.10 controller/RFC 体系到本分支

## 当前结论

本分支采用 Neutron Agent Mode：

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
aria-datapath               Rust datapath runtime
                            runs existing aria-agent binary
        |
        | WAL + Netlink + pinned maps + eBPF map apply
        v
VM tap <-> OVS br-int
```

OpenStack 模式下：

- Neutron 是唯一 source of truth。
- OVS 继续负责 L2 bridge、tunnel、local switching、port plug 和基础连通。
- `neutron-aria-agent` 不替代 OVS L2 agent。
- `aria-datapath` 不访问 Neutron DB，不消费 Neutron RPC。
- 第一阶段只增强 ACL、QoS、Mirror、TCPrt；不替代当前 OVS L2 转发路径。
- Group、Conntrack、Monitoring、WAL、Netlink、Pinned Maps 是基础能力，不是租户功能。
- Trace、Drops、SSL、Diagnose、Service Chain 代码保留，但不作为 OpenStack tenant feature 暴露。

目标 OpenStack 环境采用 OVS，VM `tap` 直接接入 OVS `br-int`。第一阶段不支持 OVN，不使用 Linux bridge hybrid plug，不引入 `qvo/qvb/veth` 路径。

本次方案边界修正：

- 当前阶段是 OVS enhancement mode，不是 Security Group replacement mode。
- Aria ready 与 OVS connectivity ready 必须分离；Aria degraded 不能让原有 OVS 转发中断。
- ACL enhancement 未 ready 时必须 `bypass/degraded`；Conntrack 是 Aria ACL 状态化执行基础，失败时 ACL 不能宣称 ready，但也不能作为业务中断门槛。
- N3 从 `ACL / Security Group` 收敛为 `ACL enhancement`，验收重点是增强能力失败不影响原 OVS 转发。
- ACL enhancement 只做 Aria Firewall 已有的传统 `group + policy` 增强能力，不消费 Neutron Security Group 规则。
- N3 不做 Security Group projection、remote group 展开、anti-spoof 或 port security enforcement。
- N3 不读取 allowed address pairs，也不实现 Neutron port security 语义。
- 未来如果要做安全组替代，必须另起显式 replacement mode 设计，不能混入本分支第一阶段。

## 能力分类

以前 README 和 CLI 容易把所有能力平铺成同一级功能。后续以这张表为准：

| 分类 | 能力 | 定位 | OpenStack 第一阶段处理 |
| --- | --- | --- | --- |
| 基础运行能力 | tap attach、ifindex、WAL、Netlink、Pinned Maps、runtime status | 保证 eBPF runtime 可挂载、可恢复、可对账 | 必选，不作为租户 feature |
| 身份与选择器基础 | Group、address-set、port identity | ACL、QoS、Mirror 和统计归因的共同输入 | 由 Neutron snapshot 投影生成 |
| 有状态基础 | Conntrack、CT config、CT stats | ACL 状态化、fast-path、flow 统计、TCPrt 的运行基础 | operator 基础配置；状态化 ACL 需要时失败必须 degraded/bypass |
| 观测基础 | Monitoring、stats、metrics | rule、flow、group、QoS、Mirror 统计 | operator 基础配置；关闭后相关统计不可用 |
| 第一阶段功能模块 | ACL、QoS、Mirror、TCPrt | Neutron snapshot 驱动的可开关功能面 | 只暴露这四个 feature flags |
| 运维观测调试 | Trace、Drops、SSL、Diagnose、Service Chain | 本机排障、诊断、host-level observe | admin/operator-only |
| 后续平台能力 | Route、NAT、L4 LB、Service | IaaS 数据面扩展能力 | 不进入第一阶段 |

关键约束：

- `feature_flags` 只表达 `acl/qos/mirror/tcprt`。
- `runtime_foundations` 表达 `conntrack/monitoring` 这类运行基础要求，不表达租户可开关功能。
- `group` 是身份/选择器基础，不是独立业务功能。
- `conntrack` 是 Aria ACL 状态化、fast-path 和观测基础，不是租户功能，也不是 Neutron ACL mapping 输入。
- `monitoring` 是统计基础，不是租户功能。
- 新 snapshot/status domain 不能照搬旧 CLI 的平铺菜单。

## 两种使用模式

### Standalone / Local Mode

这是当前已有的本地模式：

- 运行 `aria-agent`
- 通过 `ariactl` 或 REST API 管理本机接口实例
- 支持本地 group、policy、QoS、Mirror、TCPrt、Trace、Drops、SSL、Stats
- WAL、Netlink、Pinned Maps 负责本机恢复和对账

本地模式适合单机验证、实验环境、非 OpenStack 场景和故障排查。

当前已有能力速览：

| 能力 | 当前入口 | OpenStack 第一阶段定位 |
| --- | --- | --- |
| Group / ACL | `ariactl group`、`ariactl policy`、REST | ACL enhancement；当前阶段不做 Security Group projection |
| QoS | `ariactl qos`、REST | 由 Neutron QoS policy 投影生成 |
| Mirror | `ariactl mirror`、REST | admin/operator controlled feature |
| TCPrt | `ariactl tcprt`、REST/status | port/network observe feature flag |
| Conntrack | `ariactl conntrack`、REST/runtime | ACL 状态化、连接跟踪和观测基础能力 |
| Monitoring / Stats | `ariactl stats`、metrics/status | ACL/QoS/Mirror/flow/group 统计基础 |
| Trace / Drops / SSL / Diagnose / Service Chain | 本机 CLI/API | 保留为管理员排障能力，不进入租户 API |

### OpenStack Neutron Agent Mode

这是当前分支采用的集成模式：

- `neutron-aria-agent` 使用 Neutron 状态生成本机 snapshot
- `aria-datapath` 只接收 Unix socket 上的声明式 snapshot
- 本机写入 ACL/QoS/Mirror/TCPrt/group 会被拒绝，避免绕过 Neutron
- Neutron 通信失败时进入 `openstack_degraded`，继续使用 `last_good_generation`
- 只有显式 break-glass 才允许本机持久覆盖，并写入独立 local override WAL
- 重新接管默认 `Neutron wins`

详细方案见 [OpenStack Neutron Agent Mode 详细方案](docs/openstack-neutron-agent-mode.md)。

## 文档入口

- [OpenStack Neutron Agent Mode 详细方案](docs/openstack-neutron-agent-mode.md)
- [OpenStack Neutron Aria 设计决策总账](docs/openstack-neutron-aria-design-decisions.md)
- [OpenStack Neutron Aria 细化方案目录](docs/openstack-neutron-aria-details/README.md)
- [Neutron managed domains 短合同](docs/neutron-managed-domains-contract.md)
- [OpenStack 部署启用 Runbook](docs/openstack-deployment-runbook.md)
- [OpenStack 目标环境发现模板](docs/openstack-target-env-discovery.md)
- [用户手册](docs/user-manual.md)

README 只保留项目入口和边界说明。完整命令、示例、排障路径请看用户手册；OpenStack 分支计划、场景矩阵、实施章节请看 Neutron Agent Mode 方案。

## 系统要求

- Linux kernel 4.18+，推荐 5.8+
- BTF：`/sys/kernel/btf/vmlinux`
- bpffs：`/sys/fs/bpf`
- TC clsact
- root 或等价 eBPF/Netlink 权限
- Ubuntu 22.04+、Fedora 35+、RHEL/CentOS 8.2+ 等环境

内核能力参考：

| 能力 | 4.18 | 5.8+ | 5.16+ |
| --- | :---: | :---: | :---: |
| ACL / Conntrack / Monitoring | 支持 | 支持 | 支持 |
| QoS policing | 支持 | 支持 | 支持 |
| QoS EDT shaping | 不支持 | 支持 | 支持 |
| Mirror / TCPrt / Trace | 支持 | 支持 | 支持 |
| XDP link pin | 不支持 | 支持 | 支持 |
| TC link pin | 不支持 | 支持 | 支持 |

在 4.18 内核上，QoS shaping 会降级为 policing；部分 link pin 能力不可用，需要依赖 agent 恢复路径。

## 安装与运行

### Release 安装

推荐使用仓库根目录的 `install.sh`：

```bash
chmod +x install.sh
sudo ./install.sh --zip /path/to/firewall-binaries-x86_64.zip
```

脚本会安装或更新：

- `aria-agent`
- `ariactl`
- `libebpf_firewall.so`
- `libebpf_firewall_perf.so`
- `aria-agent.service`
- 默认配置目录 `/etc/aria-agent`

常用命令：

```bash
sudo systemctl start aria-agent
sudo systemctl status aria-agent
journalctl -u aria-agent -f
ariactl health
ariactl instances
```

### Standalone 快速验证

```bash
# 创建 IP group
ariactl --tap eth0 group add --name web --cidr 10.0.0.0/8
ariactl --tap eth0 group add --name db --cidr 192.168.1.0/24

# ACL
ariactl --tap eth0 policy add \
  --src-group web --dst-group db \
  --proto tcp --ports 3306 \
  --action accept --direction ingress

# QoS
ariactl --tap eth0 qos add \
  --group web --direction egress \
  --rate 100mbps --mode shaping

# Mirror
ariactl --tap eth0 mirror add \
  --src-group web --dst-group db \
  --proto tcp --direction both \
  --target tapmirror

# TCPrt
ariactl tcprt top --by art --top 10

# Stats
ariactl --tap eth0 stats --rules --qos --groups --mirror
```

更多命令见 [用户手册](docs/user-manual.md)。

## OpenStack 开发范围

第一阶段只做：

- Neutron snapshot DTO
- Unix socket Neutron-only API
- OpenStack authority state
- 本机写入保护
- Python `neutron-aria-agent`
- Neutron translator
- ACL enhancement
- QoS
- Mirror
- TCPrt
- 容器与 OpenStack smoke

第一阶段不做：

- 不替代 OVS L2 agent
- 不做 OVN
- 不做 Linux bridge hybrid plug
- 不做 Neutron L3 router、Floating IP、DVR、DHCP、Metadata agent 替代
- 不把 Trace、Drops、SSL、Diagnose、Service Chain 做成 Neutron tenant API
- 不把 TCPrt 结果写回 Neutron DB
- 不把 Mirror 做成普通租户自服务能力

## OpenStack Ready 规则

OpenStack mode 下，attach 成功不等于 Aria ready。

Aria-managed port ready 必须满足：

- tap 存在
- Neutron-managed preflight 通过
- snapshot accepted
- WAL intent/apply/commit/status 顺序成功
- group/identity 成功
- 启用 ACL 增强时 ACL apply 成功，未成功时该增强降级为 bypass
- ACL enhancement 只按显式 Aria ACL policy apply；Conntrack 是状态化 ACL 的运行基础，失败时 ACL 降级为 bypass/degraded，不能作为业务中断门槛
- 承诺统计时 monitoring 成功

ACL、QoS、Mirror、TCPrt 都是 OpenStack enhancement domain。它们失败时必须上报 degraded，但不得中断原有 OVS 转发。

Ready 不接管 OVS L2 转发状态：

- OVS agent 仍负责 tap 接入 `br-int`、bridge、tunnel、local switching 和基础连通。
- `neutron-aria-agent` 的 ready/degraded 表达 Aria 安全与功能域状态，不会自动让 OVS 停止转发。
- 如果某个 Neutron-managed port 不需要 ACL/QoS/Mirror/TCPrt，Aria 可以保持 bypass。
- 如果 port 的 ACL/Conntrack 增强尚未成功，Aria 必须保持 bypass/degraded，不能影响原有 OVS 转发。
- Monitoring 失败默认不阻断转发；只有承诺向 OpenStack/operator 提供统计时，才影响 Aria ready/observability status。

## 开发规则

本分支协作规则：

- 正确工作目录是 `/Users/chen/code/aria-firewall-v0.9-neutron-agent`
- 正确分支是 `v0.9-neutron-agent`
- 不在本机运行 `cargo build`、`cargo check`、`cargo test`
- 修改完成后提交到 GitHub，由 GitHub Actions 编译验证
- 如果 CI 失败，再根据 CI 日志修复

本地可做的文档和静态检查：

```bash
git status --short --branch
git diff --check
rg -n "[ \t]+$" README.md docs/openstack-neutron-agent-mode.md
```

## 回归脚本

现有远端回归脚本保留：

```bash
python3 tools/runtime_lifecycle_regression.py --host root@<host>
python3 tools/trace_perf_regression.py --host root@<host> --packet-counts 20,200 --rounds 2
```

用途：

- `runtime_lifecycle_regression.py`：覆盖 system stop、vanished iface、fq qdisc、managed crash recovery、DelLink
- `trace_perf_regression.py`：覆盖 trace flush、start、send、first read、retention

## 代码结构

```text
agent/        aria-agent runtime、REST/Unix API、Netlink、WAL、OpenStack snapshot 入口
api/          shared DTO、OpenAPI schema、dataplane 类型和 Neutron DTO
core/         eBPF map 操作、state、WAL、monitoring、feature ops
ebpf/         XDP/TC eBPF 程序、maps、policy/qos/mirror/tcprt/trace/stats
user/         ariactl CLI
tools/        远端回归脚本
docs/         用户手册和 OpenStack Neutron Agent Mode 方案
```

现有模块按 OpenStack agent mode 归类：

| 分类 | 主要源码 | 定位 |
| --- | --- | --- |
| 基础运行 | `agent/src/netlink.rs`、`agent/src/tap_registry.rs`、`core/src/ebpf_ops/*` | tap/ifindex attach、runtime repair、pinned runtime |
| 持久化 | `core/src/state.rs`、`core/src/wal.rs` | standalone WAL、Neutron WAL、break-glass WAL 隔离 |
| 身份基础 | `agent/src/api_handlers/groups.rs`、`core/src/state.rs` | group/address-set/port identity |
| 状态化基础 | `agent/src/api_handlers/conntrack.rs`、`core/src/ct_ops.rs`、`ebpf/src/conntrack.rs` | ACL 状态化、连接跟踪、fast-path 和 flow 观测基础 |
| 观测基础 | `core/src/monitoring.rs`、`agent/src/api_handlers/stats.rs`、`agent/src/api_handlers/metrics.rs` | stats、metrics、rule/group/flow 统计 |
| 功能模块 | `policies.rs`、`qos.rs`、`mirror.rs`、`tcprt.rs` 及对应 `core/ebpf` 模块 | ACL/QoS/Mirror/TCPrt |
| 运维排障 | `trace.rs`、`drops.rs`、`ssl.rs`、`diagnose.rs`、`service_chain.rs` | admin-only，本分支不暴露成 Neutron tenant feature |

## 项目边界

Aria 在本分支里的目标是成为 OpenStack compute node 上的 eBPF datapath enforcement/observability backend，而不是重写 OpenStack 网络控制面。

一句话边界：

```text
Neutron 决定应该是什么。
OVS 保持基础连通。
neutron-aria-agent 做 OpenStack 投影。
aria-datapath 做本机 eBPF 执行。
```

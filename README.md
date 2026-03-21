# Aria Firewall

基于 eBPF/XDP + TC 的高性能网络防火墙与可观测平台，支持多实例管理、双向策略、连接跟踪、QoS 限速、端口镜像、TCP 响应时间分析和实时流量追踪。

## 功能特性

### 数据面（eBPF 内核态）

- **XDP 入向过滤** — 在网卡驱动层拦截，零拷贝、无内核协议栈开销
- **TC 出向控制** — 基于 clsact/TC 的出向策略匹配与 EDT 调度
- **TC 入向镜像** — 入向流量镜像（SPAN）到分析接口
- **IPv4/IPv6 双栈** — 全部功能支持双栈，LPM 前缀树做 CIDR 最长前缀匹配
- **8 级 fallback 策略匹配** — (src, dst, proto) 三维通配，自动回退到更宽泛的规则
- **连接跟踪快速路径** — 已建立连接跳过策略评估，直接放行并更新统计
- **Per-CPU 统计** — 多核无锁聚合，零竞争

### 控制面（aria-agent 守护进程）

- **多实例管理** — 自动发现 tap/veth/eth 接口，每个接口独立状态
- **REST API** — 完整的 HTTP API，CLI 是其薄客户端
- **WAL 持久化** — 操作追加写入日志（O(1)），定期 compact 为快照，crash-safe
- **Netlink 监听** — 实时感知接口增删，60 秒对账兜底
- **Pinned Maps** — eBPF map 固定到 bpffs，agent 重启后自动恢复

## 系统要求

- Linux 内核 4.18+（RHEL/CentOS 8.2+）或 5.8+（推荐）
- 内核支持 BTF：`ls /sys/kernel/btf/vmlinux`
- Ubuntu 22.04+ / Fedora 35+ / RHEL 8.2+ / CentOS 8.2+

### 内核版本功能对照

| 功能 | 4.18 (RHEL 8) | 5.8+ | 5.16+ |
|------|:---:|:---:|:---:|
| ACL / 连接跟踪 / 统计 | 完整 | 完整 | 完整 |
| 端口镜像 / TCP-RT / Trace | 完整 | 完整 | 完整 |
| QoS Policing（入向/出向） | 完整 | 完整 | 完整 |
| QoS EDT Shaping（平滑整形） | 不支持 | 支持 | 支持 |
| XDP Link Pin（agent 崩溃保活） | 不支持 | 支持 | 支持 |
| TC Link Pin | 不支持 | 支持 | 支持 |

> 在 4.18 内核上，QoS shaping 会自动降级为 policing，XDP 会在 agent 退出时脱落（systemd 自动重启恢复）。

## 安装

### 从 Release 安装

```bash
# 下载最新 release
wget https://github.com/chenyongming211-glitch/aria-firewall/releases/latest/download/firewall-binaries-x86_64.zip
unzip firewall-binaries-x86_64.zip -d /tmp/aria

# 安装
sudo cp /tmp/aria/aria-agent /usr/local/bin/
sudo cp /tmp/aria/ariactl /usr/local/bin/
sudo cp /tmp/aria/libebpf_firewall.so /usr/local/lib/
sudo chmod +x /usr/local/bin/aria-agent /usr/local/bin/ariactl

# 创建配置（首次）
sudo mkdir -p /etc/aria-agent
sudo cat > /etc/aria-agent/config.toml << 'EOF'
ebpf_path = "/usr/local/lib/libebpf_firewall.so"
pin_path = "/sys/fs/bpf/aria"
state_path = "/var/lib/aria-agent"
iface_pattern = "^(eth|tap)"
max_port_policies = 16384
EOF

# 启动
sudo aria-agent
```

### 从源码编译

```bash
# 安装依赖
sudo apt-get install llvm-dev clang libelf-dev libbpf-dev

# 安装 Rust 和 BPF linker
rustup install nightly
cargo install bpf-linker

# 编译
cargo build --release
```

## 快速开始

### 1. 启动 Agent

```bash
# 前台运行（调试）
sudo aria-agent

# 或 systemd 服务
sudo systemctl start aria-agent
```

Agent 启动后自动扫描匹配 `iface_pattern` 的网卡并挂载 eBPF 程序。

### 2. IP 组管理

```bash
# 添加 IP 组
ariactl --tap eth0 group add --name web --cidr 10.0.0.0/8
ariactl --tap eth0 group add --name db --cidr 192.168.1.0/24

# 查看
ariactl --tap eth0 group list
```

### 3. ACL 策略

```bash
# 入向：允许 web 到 db 的 MySQL 流量
ariactl --tap eth0 policy add \
  --src-group web --dst-group db \
  --proto tcp --ports 3306 \
  --action accept --direction ingress

# 出向：允许 HTTP/HTTPS
ariactl --tap eth0 policy add \
  --src-group any --dst-group web \
  --proto tcp --ports 80,443 \
  --action accept --direction egress

# 批量导入策略
ariactl --tap eth0 policy batch --file policies.json

# 查看 / 删除
ariactl --tap eth0 policy list
ariactl --tap eth0 policy delete --src-group web --dst-group db --proto tcp --direction ingress
```

### 4. QoS 限速

```bash
# 出向 EDT shaping（平滑限速）
ariactl --tap eth0 qos add --group web --direction egress --rate 100mbps --burst 1mb --mode shaping

# 入向 policing（超限丢包）
ariactl --tap eth0 qos add --group web --direction ingress --rate 50mbps

# 双向同时限速
ariactl --tap eth0 qos add --group db --direction both --rate 200mbps

# 查看 / 删除
ariactl --tap eth0 qos list
ariactl --tap eth0 qos delete --group web --direction egress
```

速率支持单位：`gbps`、`mbps`、`kbps`、`bps`，或纯数字（字节/秒）。

### 5. 端口镜像（SPAN）

```bash
# 镜像 web→db 的 TCP 流量到 tapmirror 接口
ariactl --tap eth0 mirror add \
  --src-group web --dst-group db --proto tcp \
  --direction both --target tapmirror

# 全局镜像（所有流量）
ariactl --tap eth0 mirror add \
  --src-group any --dst-group any --proto any \
  --direction ingress --target tapmirror

# 查看 / 删除
ariactl --tap eth0 mirror list
ariactl --tap eth0 mirror delete --src-group web --dst-group db --proto tcp --direction both
```

### 6. TCP 响应时间分析（TCP-RT）

每条 TCP 流自动采集：握手延迟、客户端 RTT、服务端 RTT、应用响应时间（ART）、重传次数。

```bash
# Top-N 流按 ART 排序
ariactl tcprt top --by art --top 10

# 实时刷新模式
ariactl tcprt top --by crtt --top 20 --watch --interval 2

# 单流详细延迟分解
ariactl tcprt flow --dst 10.0.0.5 --dport 3306

# 结合 service chain 做逐跳分析
ariactl tcprt flow --dst 10.0.0.5 --dport 3306 --chain prod-chain
```

排序维度：`art`（应用响应）、`crtt`（客户端 RTT）、`srtt`（服务端 RTT）、`hs`（握手）、`retrans`（重传）。

### 7. Service Chain 拓扑

定义多跳服务路径，实现逐段延迟归因：

```bash
# 应用拓扑
ariactl chain apply --file chain.json

# 查看
ariactl chain list
ariactl chain show prod-chain
ariactl chain delete prod-chain
```

chain.json 示例：

```json
{
  "name": "prod-chain",
  "description": "Production service chain",
  "hops": [
    {
      "name": "load-balancer",
      "hop_type": "proxy",
      "taps": [{"tap": "tap1", "role": "in"}, {"tap": "tap2", "role": "out"}]
    },
    {
      "name": "app-server",
      "hop_type": "bridge",
      "taps": [{"tap": "tap3", "role": "bidirectional"}]
    }
  ]
}
```

### 8. Chain X-Ray — 基于服务链感知的链路分析

利用 Service Chain 拓扑，按 hop 顺序追踪包的流转路径，自动归因丢包位置。即使安全设备内部的 drop 无法被 eBPF 捕获，也能通过 in/out 口的包数差定位到具体设备。

```bash
# 定时模式（5 秒采集，按 hop 展示）
ariactl trace start --chain prod-chain --dst 10.0.0.5 --dport 3306 --wait 5

# 连续模式（实时刷新，Ctrl+C 结束）
ariactl trace start --chain prod-chain --dst 10.0.0.5

# 不指定 --chain 则按传统平铺模式展示（向后兼容）
ariactl trace start --dst 10.0.0.5 --wait 5
```

输出示例：

```
Chain: prod-chain    Filter: * → 10.0.0.5:3306

  Hop            Tap     Role   In        Out       Drops
  ──────────     ──────  ────   ────────  ────────  ──────────────────
  load-balancer  tap1    in     50 pkts   -         -
  load-balancer  tap2    out    -         48 pkts   -
                                          ↓ 2 pkts lost between load-balancer and firewall
  firewall       tap3    in     46 pkts   -         ✗ 40 acl_deny
  firewall       tap4    out    -         0 pkts    ✗ 6 qos_drop
                         ★ dropped 46/46 inside firewall
                           ├─ ingress: 40 (acl_deny)
                           └─ egress: 6 (qos_drop)
  app-server     tap5    bidi   0 pkts    0 pkts    -
```

丢包归因：

| 标记 | 含义 |
|------|------|
| `✗ N reason` | eBPF 捕获到的 drop 事件，按 reason 分组 |
| `★ dropped M/N inside <hop>` | 设备内部丢包（in 口进入但 out 口未出），附带方向+原因树状展开 |
| `└─ no drop reason captured` | 黑盒丢包：设备内部阻拦，eBPF 未捕获 drop 事件 |
| `↓ N pkts lost between A and B` | hop 间网络丢包 |

### 9. 包追踪调试

实时包级别调试，查看每个包在 XDP/TC 各阶段的处理结果。支持 IPv4 和 IPv6。

```bash
# 定时模式（5 秒后自动结束）
ariactl trace start --dst 192.168.1.10 --proto tcp --dport 3306 --wait 5

# IPv6 追踪
ariactl trace start --dst ::1 --wait 3

# 连续模式（Ctrl+C 结束）
ariactl trace start --tap eth0 --dst 10.0.0.5

# 无过滤条件（追踪所有 IPv4+IPv6 流量）
ariactl trace start --wait 3
```

输出包含：实例汇总（入/出包数、verdict）+ 详细 drop 原因分析。

### 10. Drop 原因分析

```bash
# 查看丢包统计
ariactl stats --drops

# 清空计数器
ariactl drops flush --tap eth0
```

丢包原因：`acl-deny`、`acl-port-deny`、`acl-default-deny`、`qos-ingress`、`qos-egress`。

### 11. 连接跟踪

```bash
# 查看活跃连接
ariactl --tap eth0 conntrack list

# 清空连接表
ariactl --tap eth0 conntrack flush
```

### 12. 监控与统计

```bash
# 概览（groups/policies/qos/mirror/conntrack 数量）
ariactl --tap eth0 stats

# 按规则统计（命中次数、字节数）
ariactl --tap eth0 stats --rules

# Top 流量
ariactl --tap eth0 stats --flows --top 20

# QoS 统计（通过/丢弃/整形）
ariactl --tap eth0 stats --qos

# 按组统计
ariactl --tap eth0 stats --groups

# 镜像统计
ariactl --tap eth0 stats --mirror

# TCP-RT 统计
ariactl --tap eth0 stats --tcprt

# Drop 统计
ariactl --tap eth0 stats --drops
```

### 13. 运行时配置

所有开关可热切换，无需重启：

```bash
ariactl --tap eth0 config show

ariactl --tap eth0 config set conntrack on
ariactl --tap eth0 config set monitoring on
ariactl --tap eth0 config set acl on
ariactl --tap eth0 config set qos off
ariactl --tap eth0 config set mirror off
ariactl --tap eth0 config set tcprt on
```

### 14. 实例管理

```bash
# 列出所有实例
ariactl instances

# 健康检查
ariactl health

# 指定实例操作
ariactl --tap tap1 stats
ariactl --tap tap2 policy list
```

## 命令参考

| 命令 | 说明 |
|------|------|
| `health` | Agent 健康检查 |
| `instances` | 列出所有实例 |
| `system start/stop` | 独立模式启停 |
| `group add/delete/list` | IP 组管理（CIDR） |
| `policy add/delete/list/batch` | ACL 策略管理 |
| `qos add/delete/list` | QoS 限速管理 |
| `mirror add/delete/list` | 端口镜像管理 |
| `conntrack list/flush` | 连接跟踪操作 |
| `tcprt top/flow/flush` | TCP 响应时间分析 |
| `chain apply/list/show/delete` | Service Chain 拓扑 |
| `trace start` | 包追踪调试（支持 `--chain` 服务链透视） |
| `drops list/flush` | Drop 原因分析 |
| `stats` | 统计信息 |
| `config show/set` | 运行时配置 |

## 技术架构

```
                ariactl (CLI)
                     │  HTTP
                     ▼
              aria-agent (daemon)
              ┌──────────────────────────────────────────────┐
              │  REST API (axum)                              │
              │  ControlPlane (per-instance state + WAL)      │
              │  TapRegistry (netlink auto-discovery)         │
              │  ServiceChain (topology-aware aggregation)    │
              └──────────────────────────────────────────────┘
                     │  pinned maps + state.json + state.wal
                     ▼
              aria-core (shared library)
              ┌──────────────────────────────────────────────┐
              │  ebpf_ops · state · wal · monitoring         │
              │  qos_ops · mirror_ops · ct_ops · trace_ops   │
              │  tcprt_ops · drop_ops                        │
              └──────────────────────────────────────────────┘
                     │
                     ▼
              libebpf_firewall.so (eBPF kernel programs)
              ┌──────────────────────────────────────────────┐
              │                                              │
              │  ┌─────────┐ ┌──────────┐ ┌──────────────┐  │
              │  │ policy   │ │conntrack │ │    qos       │  │
              │  │ 8级匹配  │ │ CT 跟踪  │ │ 令牌桶/EDT   │  │
              │  └─────────┘ └──────────┘ └──────────────┘  │
              │  ┌─────────┐ ┌──────────┐ ┌──────────────┐  │
              │  │ mirror  │ │ tcp-rt   │ │   trace      │  │
              │  │ SPAN    │ │ 延迟分析  │ │  包追踪      │  │
              │  └─────────┘ └──────────┘ └──────────────┘  │
              │  ┌─────────┐ ┌──────────┐ ┌──────────────┐  │
              │  │ parser  │ │  stats   │ │   drops      │  │
              │  │ 协议解析 │ │ 流量统计  │ │  丢包分析    │  │
              │  └─────────┘ └──────────┘ └──────────────┘  │
              └──────────────────────────────────────────────┘
                     │                    │
                XDP (ingress)        TC (egress/ingress)
                     │                    │
              ┌──────────────────────────────────────────────┐
              │                   NIC                         │
              └──────────────────────────────────────────────┘
```

### 包处理流水线

```
入向包 → XDP → parse → CT lookup ─── hit ──→ fast-path (stats + tcprt + qos) → PASS
                                  │
                                  └─ miss ─→ LPM (src/dst) → policy (8级) → qos → CT create → PASS/DROP
                                                                                      │
                                                                                      ├─ mirror
                                                                                      ├─ trace
                                                                                      └─ drop stats
```

## 项目结构

```
aria-firewall/
├── ebpf/src/              — eBPF 数据面（内核态）
│   ├── lib.rs             XDP/TC 入口 + pipeline 调度
│   ├── policy.rs          8 级 fallback 策略匹配
│   ├── conntrack.rs       连接跟踪（双向查找 + 超时）
│   ├── qos.rs             QoS 令牌桶（shaping + policing）
│   ├── mirror.rs          端口镜像（bpf_clone_redirect）
│   ├── tcprt.rs           TCP 响应时间追踪
│   ├── trace.rs           包追踪过滤（IPv4/IPv6）
│   ├── drops.rs           丢包原因记录
│   ├── stats.rs           统计更新（rule/flow/group）
│   ├── parser.rs          协议解析（Eth/IPv4/IPv6/TCP/UDP/VLAN）
│   ├── maps.rs            eBPF map 定义
│   └── common.rs          共享数据结构
├── core/src/              — 共享业务库
│   ├── ebpf_ops.rs        eBPF 加载、map 读写、replay
│   ├── state.rs           FirewallState（组/规则/端口集/引用计数）
│   ├── wal.rs             WAL 增量持久化（append + compact）
│   ├── monitoring.rs      监控数据读取与聚合
│   ├── qos_ops.rs         QoS map 操作 + 速率解析
│   ├── mirror_ops.rs      镜像 map 操作 + ifindex 解析
│   ├── tcprt_ops.rs       TCP-RT map 读取与过滤
│   ├── trace_ops.rs       Trace 过滤器设置与事件读取
│   ├── drop_ops.rs        Drop 统计读取
│   ├── ct_ops.rs          连接跟踪 map 操作
│   └── common.rs          共享数据结构（repr(C) 对齐）
├── agent/src/             — 多实例守护进程
│   ├── main.rs            aria-agent 入口
│   ├── control_plane.rs   ControlPlane（状态 + WAL + kernel 同步）
│   ├── api_handlers.rs    REST API handlers
│   ├── api_routes.rs      路由注册
│   ├── netlink.rs         Netlink 网卡监听 + 对账
│   ├── tap_registry.rs    Tap 实例注册表
│   ├── instance.rs        实例生命周期（load/attach/replay）
│   ├── service_chain.rs   Service Chain 拓扑管理
│   └── system_manager.rs  独立模式管理
├── user/src/              — CLI 控制面
│   ├── main.rs            ariactl 命令实现
│   └── api_client.rs      HTTP API 客户端
├── api/src/               — 共享 API 类型
│   └── lib.rs             请求/响应结构体
└── Cargo.toml             Workspace 配置
```

## REST API

所有路由前缀 `/api/v1/`。

| 方法 | 路由 | 说明 |
|------|------|------|
| GET | `/health` | 健康检查 |
| GET | `/instances` | 实例列表 |
| POST | `/system/start` | 启动防火墙 |
| POST | `/system/stop` | 停止防火墙 |
| GET/POST/DELETE | `/{instance}/groups` | IP 组 CRUD |
| GET/POST/DELETE | `/{instance}/policies` | 策略 CRUD |
| POST | `/{instance}/policies/batch` | 批量添加策略 |
| GET/POST/DELETE | `/{instance}/qos` | QoS CRUD |
| GET/POST/DELETE | `/{instance}/mirror` | 镜像 CRUD |
| GET/DELETE | `/{instance}/conntrack` | 连接跟踪查看/清空 |
| GET/PUT | `/{instance}/config` | 配置查看/更新 |
| GET | `/{instance}/stats` | 统计概览 |
| GET | `/{instance}/stats/rules\|flows\|qos\|groups\|mirror\|drops` | 详细统计 |
| GET/DELETE | `/{instance}/tcprt` | TCP-RT 查看/清空 |
| POST | `/tcprt/query` | 跨实例批量查询 |
| POST | `/tcprt/filter` | 按目标聚合查询 |
| POST/GET/DELETE | `/{instance}/trace` | 追踪启动/查看/停止 |
| GET/POST/DELETE | `/chains` | Service Chain CRUD |

## 配置文件

`/etc/aria-agent/config.toml`：

```toml
ebpf_path = "/usr/local/lib/libebpf_firewall.so"
pin_path = "/sys/fs/bpf/aria"
state_path = "/var/lib/aria-agent"
iface_pattern = "^(eth|tap)"    # 正则匹配要管理的接口
max_port_policies = 16384       # 端口集上限
listen_addr = "127.0.0.1:8080"  # API 监听地址
```

环境变量：`ARIA_API_URL` 覆盖 CLI 连接地址（默认 `http://127.0.0.1:8080`）。

## 许可证

MIT

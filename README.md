# Aria Firewall

基于 eBPF/XDP + TC 的高性能防火墙，支持双向策略（ingress/egress）、连接跟踪、QoS 限速和实时流量监控。

## 功能特性

- **XDP 入向过滤** — 在网卡驱动层拦截，零拷贝、无内核协议栈开销
- **TC 出向控制** — 基于 clsact/TC 的出向策略匹配与 EDT 调度
- **8 级 fallback 策略匹配** — (src, dst, proto) 三维通配，自动回退到更宽泛的规则
- **LPM 前缀树** — 高效 CIDR 最长前缀匹配，IPv4/IPv6 双栈
- **端口集 (port set)** — 引用计数共享，支持端口范围和逗号分隔
- **连接跟踪 (conntrack)** — 有状态防火墙，已建立连接走快速路径
- **QoS 限速** — 出向 EDT shaping + 入向 policing，令牌桶算法，多核感知
- **实时监控** — 按规则/流/连接维度统计，快速路径也计入 rule stats
- **运行时配置** — conntrack/monitoring 开关可热切换，无需重启
- **状态持久化** — 服务重启后自动恢复规则、组、QoS 配置
- **Tap 模式** — aria-agent 守护进程管理多实例，支持 veth/tap 网卡

## 系统要求

- Linux 内核 5.8+（推荐 5.16+）
- 内核支持 BTF：`ls /sys/kernel/btf/vmlinux`
- Ubuntu 22.04+ / Fedora 35+ / RHEL 9+

## 快速开始

### 编译

```bash
# 安装依赖
sudo apt-get install llvm-dev clang libelf-dev libbpf-dev

# 安装 Rust 和 BPF linker
rustup install nightly
cargo install bpf-linker

# 编译
cargo build --release
```

### 基本用法

```bash
# 启动防火墙
sudo firewall-ctl system start --iface eth0

# 添加 IP 组
sudo firewall-ctl group add --name web --cidr 10.0.0.0/8
sudo firewall-ctl group add --name db --cidr 192.168.1.0/24

# 添加策略（入向：允许 web 到 db 的 TCP 3306）
sudo firewall-ctl policy add \
  --src-group web --dst-group db \
  --proto tcp --ports 3306 \
  --action accept --direction ingress

# 添加策略（出向：允许所有到 web 的 HTTP/HTTPS）
sudo firewall-ctl policy add \
  --src-group any --dst-group web \
  --proto tcp --ports 80,443 \
  --action accept --direction egress

# 查看
sudo firewall-ctl policy list
sudo firewall-ctl group list

# 停止
sudo firewall-ctl system stop
```

### QoS 限速

```bash
# 出向限速（EDT shaping）
sudo firewall-ctl qos add --group web --direction egress --rate 100mbps --burst 1mb

# 入向限速（policing，超限直接丢包）
sudo firewall-ctl qos add --group web --direction ingress --rate 50mbps

# 查看 QoS 规则
sudo firewall-ctl qos list

# 删除
sudo firewall-ctl qos delete --group web --direction egress
```

### 连接跟踪

```bash
# 查看活跃连接
sudo firewall-ctl conntrack list

# 清空连接表
sudo firewall-ctl conntrack flush
```

### 运行时配置

```bash
# 查看当前配置（conntrack/monitoring 开关、CPU 数）
sudo firewall-ctl config show

# 关闭连接跟踪
sudo firewall-ctl config set conntrack off

# 关闭流量监控
sudo firewall-ctl config set monitoring off
```

### 监控与统计

```bash
# 概览
sudo firewall-ctl stats

# 按规则统计
sudo firewall-ctl stats --rules

# Top 流量
sudo firewall-ctl stats --flows --top 20

# 连接跟踪摘要
sudo firewall-ctl stats --conntrack

# QoS 状态
sudo firewall-ctl stats --qos

# 实时仪表盘（2 秒刷新）
sudo firewall-ctl monitor --interval 2
```

## 命令参考

| 命令 | 说明 |
|------|------|
| `system start --iface <IF>` | 启动防火墙，加载 eBPF 到指定网卡 |
| `system stop` | 停止防火墙，卸载 eBPF 程序 |
| `group add/delete/list` | IP 组管理（CIDR 格式） |
| `policy add/delete/list` | 策略规则管理（支持 ingress/egress） |
| `qos add/delete/list` | QoS 限速管理（egress shaping / ingress policing） |
| `conntrack list/flush` | 连接跟踪操作 |
| `config show/set` | 运行时配置（conntrack / monitoring 开关） |
| `stats` | 统计信息（--rules / --flows / --conntrack / --qos） |
| `monitor` | 实时监控仪表盘 |
| `tap list` | 列出 aria-agent 管理的 tap 实例 |

## 技术架构

```
                 firewall-ctl (CLI)          aria-agent (daemon)
                       │                          │
                       ▼                          ▼
              ┌─────────────────────────────────────────────┐
              │              aria-core (共享库)               │
              │  ebpf_ops · state · monitoring · qos_ops    │
              └─────────────────────────────────────────────┘
                       │  pinned maps + state.json
                       ▼
              ┌─────────────────────────────────────────────┐
              │           libebpf_firewall.so (eBPF)        │
              │                                             │
              │  ┌─────────┐ ┌──────────┐ ┌──────────────┐ │
              │  │ policy   │ │conntrack │ │    qos       │ │
              │  │ 8级匹配  │ │ CT 跟踪  │ │ 令牌桶限速   │ │
              │  └─────────┘ └──────────┘ └──────────────┘ │
              │  ┌─────────┐ ┌──────────┐ ┌──────────────┐ │
              │  │ parser  │ │  stats   │ │    maps      │ │
              │  │协议解析  │ │ 流量统计  │ │ LPM/Hash/..│ │
              │  └─────────┘ └──────────┘ └──────────────┘ │
              └─────────────────────────────────────────────┘
                       │                    │
                  XDP (ingress)        TC (egress)
                       │                    │
              ┌─────────────────────────────────────────────┐
              │                  NIC                         │
              └─────────────────────────────────────────────┘
```

## 项目结构

```
aria-firewall/           5,305 行 Rust
├── ebpf/src/            1,274 行 — eBPF 数据面
│   ├── lib.rs           入口调度（XDP ingress / TC egress）
│   ├── policy.rs        8 级 fallback 策略匹配
│   ├── conntrack.rs     连接跟踪（CT lookup/create + 超时）
│   ├── qos.rs           QoS 令牌桶（egress shaping / ingress policing）
│   ├── parser.rs        协议解析（IPv4/IPv6/TCP/UDP/ICMP）
│   ├── stats.rs         统计更新（rule stats / flow stats）
│   ├── maps.rs          eBPF map 定义
│   └── common.rs        共享数据结构
├── core/src/            2,174 行 — 共享业务库
│   ├── ebpf_ops.rs      eBPF 加载、map 读写、replay_state
│   ├── state.rs         状态持久化（JSON + 文件锁）
│   ├── monitoring.rs    监控数据读取与格式化
│   ├── qos_ops.rs       QoS map 操作 + 速率解析
│   ├── ct_ops.rs        连接跟踪 map 操作
│   └── common.rs        共享数据结构（与 eBPF 侧 repr(C) 对齐）
├── user/src/            1,207 行 — CLI 控制面
│   ├── main.rs          firewall-ctl 命令实现
│   └── manager.rs       系统启停管理
├── agent/src/             650 行 — 多实例守护进程
│   ├── main.rs          aria-agent 入口
│   ├── netlink.rs       Netlink 网卡监听
│   ├── tap_registry.rs  tap 实例注册表
│   └── instance.rs      实例生命周期管理
└── Cargo.toml           Workspace 配置
```

## 许可证

MIT

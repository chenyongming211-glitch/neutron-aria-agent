# Aria Firewall

基于 eBPF/XDP + TC 的高性能网络防火墙与可观测平台，支持多实例管理、双向策略、连接跟踪、QoS 限速、端口镜像、TCP 响应时间分析和实时流量追踪。

## 功能特性

### 数据面（eBPF 内核态）

- **XDP 入向过滤** — 在网卡驱动层拦截，零拷贝、无内核协议栈开销
- **TC 出向控制** — 基于 clsact/TC 的出向策略匹配与 EDT 调度
- **TC 入向镜像** — 入向流量镜像（SPAN）到分析接口
- **双观测延迟分解** — bond1 XDP+TC 双观测，精确拆解 5 段延迟（正/反向平台处理、网络 RTT、业务处理）
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

## 文档

- [用户手册](docs/user-manual.md)

## 回归脚本

仓库当前提供两类可直接远端执行的回归脚本：

- `tools/trace_perf_regression.py`
  - 覆盖 `flush -> start trace -> send -> first read`
  - 用于 perf trace backend 的 first-read / flush / retention 验证
- `tools/runtime_lifecycle_regression.py`
  - 覆盖 `system stop + vanished iface`
  - 覆盖 `system preexisting fq`
  - 覆盖 `managed crash recovery -> DelLink`

示例：

```bash
python3 tools/runtime_lifecycle_regression.py --host root@<host>
python3 tools/trace_perf_regression.py --host root@<host> --packet-counts 20,200 --rounds 2
```

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

推荐优先使用仓库根目录的 `install.sh` 做一键安装/更新。  
把下面两个文件放在同一个目录：

- `firewall-binaries-x86_64.zip`
- `install.sh`

然后执行：

```bash
chmod +x install.sh
sudo ./install.sh
```

脚本会自动完成：

- 检测 root、内核版本、BTF、bpffs
- 解压 zip 并校验 release 产物
- 备份当前安装
- 安装/更新 `aria-agent`、`ariactl`、`libebpf_firewall.so`、`libebpf_firewall_perf.so`
- 写入/更新 `aria-agent.service`
- 首次创建默认 `/etc/aria-agent/config.toml`
- 重启 `aria-agent` 并做健康检查

常用参数：

```bash
# 指定 zip 路径
sudo ./install.sh --zip /path/to/firewall-binaries-x86_64.zip

# 覆盖默认配置
sudo ./install.sh --force-config

# 只安装，不启动服务
sudo ./install.sh --no-start
```

后续更新也使用同一个脚本，直接换成新的 zip 再执行一次即可。

如果你想手工安装，也可以按下面步骤操作：

```bash
# 下载最新 release
wget https://github.com/chenyongming211-glitch/aria-firewall/releases/latest/download/firewall-binaries-x86_64.zip
unzip firewall-binaries-x86_64.zip -d /tmp/aria

# 安装
sudo cp /tmp/aria/aria-agent /usr/local/bin/
sudo cp /tmp/aria/ariactl /usr/local/bin/
sudo cp /tmp/aria/libebpf_firewall.so /usr/local/lib/
sudo cp /tmp/aria/libebpf_firewall_perf.so /usr/local/lib/
sudo chmod +x /usr/local/bin/aria-agent /usr/local/bin/ariactl

# 创建配置（首次）
sudo mkdir -p /etc/aria-agent
sudo cat > /etc/aria-agent/config.toml << 'EOF'
ebpf_path = "/usr/local/lib/libebpf_firewall.so"
trace_backend = "auto"
trace_auto_allow_ringbuf = false
pin_path = "/sys/fs/bpf/aria"
state_path = "/var/lib/aria-agent"
iface_pattern = "^(eth|tap)"
max_port_policies = 16384
EOF

# 启动
sudo aria-agent
```

> Trace perf rollout 期间，请始终原子更新 `aria-agent`、`ariactl`、
> `libebpf_firewall.so` 和 `libebpf_firewall_perf.so`。只更新 `.so`
> 而不更新 `aria-agent`，会导致用户态 trace backend 逻辑仍停留在旧版本。

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

### 3. ACL 策略（`ariactl policy`）

产品能力上通常叫 ACL，但 CLI 子命令实际是 `ariactl policy`。除特别说明外，规则默认作用在 `--tap` 指定实例上；省略 `--tap` 时默认操作 `system` 实例。

策略匹配维度：

- `--src-group` / `--dst-group`：源/目的 IP 组，`any` 表示任意
- `--proto`：`tcp`、`udp`、`icmp` 或 `any`
- `--direction`：`ingress` 或 `egress`
- `--ports`：可选，仅对有端口概念的协议生效，支持逗号分隔端口和范围，例如 `80,443,10000-20000`
- `--action`：常用值是 `accept` 或 `drop`

常见用法：

```bash
# 入向：允许 web -> db 的 MySQL
ariactl --tap eth0 policy add \
  --src-group web --dst-group db \
  --proto tcp --ports 3306 \
  --action accept --direction ingress

# 出向：允许 web 访问 HTTP/HTTPS
ariactl --tap eth0 policy add \
  --src-group web --dst-group any \
  --proto tcp --ports 80,443 \
  --action accept --direction egress

# 入向：显式拒绝任意来源访问 db 的 Redis
ariactl --tap eth0 policy add \
  --src-group any --dst-group db \
  --proto tcp --ports 6379 \
  --action drop --direction ingress
```

查看、统计和删除：

```bash
# 仅查看配置
ariactl --tap eth0 policy list

# 配置 + 命中统计
ariactl --tap eth0 policy with-stats

# 删除单条规则
ariactl --tap eth0 policy delete \
  --src-group web --dst-group db \
  --proto tcp --direction ingress
```

批量导入支持 JSON 文件或标准输入。`direction` 必须写成 `ingress` 或 `egress`；如果同一规则要双向生效，请写两条。

```bash
cat <<'EOF' > policies.json
{
  "policies": [
    {
      "src_group": "web",
      "dst_group": "db",
      "proto": "tcp",
      "action": "accept",
      "direction": "ingress",
      "ports": "3306"
    },
    {
      "src_group": "db",
      "dst_group": "web",
      "proto": "tcp",
      "action": "accept",
      "direction": "egress",
      "ports": "3306"
    }
  ]
}
EOF

ariactl --tap eth0 policy batch --file policies.json
```

### 4. QoS 限速（`ariactl qos`）

QoS 用于按 IP 组做带宽约束，支持：

- `--direction ingress|egress|both`
- `--rate`：支持 `gbps`、`mbps`、`kbps`、`bps`，也支持纯数字字节/秒
- `--burst`：突发桶大小，`0` 表示自动
- `--priority`：`0` 最高、`7` 最低
- `--mode policing|shaping`

`policing` 的语义是超限直接丢包；`shaping` 的语义是通过 EDT 做平滑整形，通常更适合 egress。
`shaping` 依赖 root `fq` qdisc。系统会自动安装 `fq`，并使用更高的
默认 `flow_limit` 来吸收单 flow 突发，避免默认 `100p` 队列过小导致的
平滑整形边界丢包。

```bash
# 出向 shaping：把 web 组整形成 100 Mbps
ariactl --tap eth0 qos add \
  --group web --direction egress \
  --rate 100mbps --burst 1mb \
  --priority 1 --mode shaping

# 入向 policing：把 db 组限制到 50 Mbps
ariactl --tap eth0 qos add \
  --group db --direction ingress \
  --rate 50mbps --mode policing

# 默认组双向限速
ariactl --tap eth0 qos add \
  --group default --direction both \
  --rate 200mbps --burst 0
```

查看、统计和删除：

```bash
ariactl --tap eth0 qos list
ariactl --tap eth0 qos with-stats
ariactl --tap eth0 qos delete --group web --direction egress
```

### 5. 端口镜像（`ariactl mirror`）

Mirror 用于把符合条件的报文镜像到目标接口，支持按源组、目的组、协议和方向过滤。

- `--target`：镜像目标接口
- `--direction ingress|egress|both`
- `--src-group` / `--dst-group`：默认都是 `any`
- `--proto`：默认 `any`

```bash
# 精确镜像：web -> db 的 TCP 双向流量
ariactl --tap eth0 mirror add \
  --src-group web --dst-group db \
  --proto tcp --direction both \
  --target tapmirror

# 全局镜像：所有入向流量
ariactl --tap eth0 mirror add \
  --src-group any --dst-group any \
  --proto any --direction ingress \
  --target tapmirror
```

查看、统计和删除：

```bash
ariactl --tap eth0 mirror list
ariactl --tap eth0 mirror with-stats
ariactl --tap eth0 mirror delete \
  --src-group web --dst-group db \
  --proto tcp --direction both
```

`mirror with-stats` 会额外显示镜像报文数、字节数和错误计数。

### 6. 业务延迟分析（`ariactl tcprt`）

TCP-RT 负责做业务延迟可观测，自动采集：

- 握手延迟 `hs`
- 客户端 RTT `crtt`
- 服务端 RTT `srtt`
- 应用响应时间 `art`
- 请求/响应方向重传次数
- NQA 评分 `nqa`

命令分成两类：

- 跨实例分析：`top`、`flow`
- 单实例视图：`histogram`、`states`、`flush`，通常配合全局 `--tap`

Top-N 和实时观察：

```bash
# 按应用响应时间排序
ariactl tcprt top --by art --top 10

# 实时刷新
ariactl tcprt top --by crtt --top 20 --watch --interval 2
```

单服务延迟分解：

```bash
ariactl tcprt flow --dst 10.0.0.5 --dport 3306
```

排序维度支持：

- `art`：应用响应时间
- `crtt`：客户端 RTT
- `srtt`：服务端 RTT
- `hs`：握手时延
- `retrans`：重传
- `nqa`：综合质量评分

实例级视图：

```bash
# 指定实例查看 ART 分布
ariactl --tap eth0 tcprt histogram

# 查看 TCP 状态分布和异常
ariactl --tap eth0 tcprt states

# 清空该实例的 TCP-RT 状态
ariactl --tap eth0 tcprt flush
```

#### 服务链逐跳归因（`ariactl chain`）

`tcprt flow --chain <name>` 和 `trace start --chain <name>` 共享同一套服务链拓扑定义。

```bash
ariactl chain apply --file chain.json
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
      "name": "firewall",
      "hop_type": "bridge",
      "taps": [{"tap": "tap3", "role": "in"}, {"tap": "tap4", "role": "out"}]
    },
    {
      "name": "app-server",
      "hop_type": "bridge",
      "taps": [{"tap": "tap5", "role": "bidi"}]
    }
  ]
}
```

结合服务链做单服务逐跳分析：

```bash
ariactl tcprt flow --dst 10.0.0.5 --dport 3306 --chain prod-chain
```

### 7. 丢包溯源（`ariactl trace`）

`trace` 用于实时包级别追踪，支持 IPv4 和 IPv6。当前 CLI 只有一个子命令：`start`。

需要注意的是，`trace start` 使用自己的 `--tap` 参数，而不是全局 `--tap`：

- `ariactl trace start --tap tap1 ...`：只追踪一个实例
- `ariactl trace start ...`：自动追踪所有活跃实例
- `--wait <seconds>`：追踪固定秒数后自动退出
- 省略 `--wait`：持续输出，直到手动 `Ctrl+C`

```bash
# 单实例追踪
ariactl trace start \
  --tap eth0 \
  --dst 10.0.0.5 --proto tcp --dport 3306 \
  --wait 5

# 跨实例追踪
ariactl trace start \
  --dst 10.0.0.5 --proto tcp --dport 3306 \
  --wait 5

# 连续模式
ariactl trace start \
  --src 10.0.0.10 --dst 10.0.0.5 \
  --proto tcp --dport 3306
```

结合服务链按 hop 展示：

```bash
ariactl trace start --chain prod-chain --dst 10.0.0.5 --dport 3306 --wait 5
```

在 chain 模式下，输出会把包在各 hop 的 in/out 口、eBPF 直接捕获的 drop reason，以及 hop 间黑盒丢包一起展示出来，适合做链路级排障。

### 8. Kernel Drop 观测（`ariactl drops`）

`drops` 统计的是内核层 `kfree_skb` 相关丢包事件，和防火墙主动丢弃是两条不同的观测链路：

- 防火墙主动丢弃：看 `ariactl stats --rules`、`ariactl stats --qos`
- 内核层 drop：看 `ariactl drops list/flush`

过滤维度：

- 全局 `--tap <instance>`：先按实例过滤
- 子命令 `--iface <name>`：再按真实接口名过滤
- `--include-unattributed`：包含无法归属到具体接口的早期 drop

```bash
# 查看所有实例上的 kernel drop
ariactl drops list

# 只看某个实例
ariactl --tap eth0 drops list

# 只看某个实例下的具体接口
ariactl --tap eth0 drops list --iface eth0 --top 20

# 包含 early unattributed drop
ariactl drops list --include-unattributed
```

清理统计必须显式带 `--force`：

```bash
# 清空某个实例上的所有 kernel drop 统计
ariactl --tap eth0 drops flush --force

# 只清某个接口
ariactl --tap eth0 drops flush --iface eth0 --force

# 清空全局 unattributed drop
ariactl drops flush --include-unattributed --force
```

### 9. SSL/TLS 观测（`ariactl ssl`）

SSL 模块提供 TLS 握手、HTTP 请求/响应和 SSL 错误三类观测数据。注意 SSL 数据是 host-global 的，不是 per-instance，`--tap` 对 SSL 只起提示作用。

```bash
# 启用/禁用/状态
ariactl ssl enable
ariactl ssl disable
ariactl ssl status

# TLS 握手记录
ariactl ssl list --top 100
ariactl ssl flush

# HTTP 请求/响应
ariactl ssl http --top 100
ariactl ssl http-flush

# SSL 错误
ariactl ssl errors --top 20
ariactl ssl errors-flush
```

### 10. 连接诊断（`ariactl diagnose`）

`diagnose` 组合多个观测面（TCP-RT、SSL/TLS、HTTP、kernel drop）做全栈连接诊断，快速判断连接健康状态。

```bash
ariactl --tap eth0 diagnose --dst 10.0.0.5 --dport 3306

# 结合服务链做逐跳诊断
ariactl --tap eth0 diagnose --dst 10.0.0.5 --dport 3306 --chain prod-chain
```

### 11. 连接跟踪（`ariactl conntrack`）

Conntrack 用于查看和清理实例级连接表，通常配合 `--tap` 使用。

```bash
# 查看活跃连接
ariactl --tap eth0 conntrack list

# 清空该实例连接表
ariactl --tap eth0 conntrack flush
```

`list` 输出包含五元组、协议、状态、报文数和字节数，适合确认连接是否已经进入 fast-path。

### 12. 监控与统计（`ariactl stats`）

`stats` 是统一统计入口。不带任何子选项时返回概览；带标志时可以一次输出多个统计分区。

概览：

```bash
ariactl --tap eth0 stats
```

会返回该实例当前的：

- group 数量
- policy 数量
- QoS 规则数量
- mirror 规则数量
- conntrack IPv4 / IPv6 条目数量

详细统计：

```bash
# 规则命中和丢弃字节/报文
ariactl --tap eth0 stats --rules

# Top-N 流量
ariactl --tap eth0 stats --flows --top 20

# QoS 通过 / 丢弃 / 整形
ariactl --tap eth0 stats --qos

# 按组流量统计
ariactl --tap eth0 stats --groups

# Mirror 统计
ariactl --tap eth0 stats --mirror

# TCP-RT Top-N
ariactl --tap eth0 stats --tcprt --top 20

# Kernel drop 统计
ariactl --tap eth0 stats --drops --top 50
```

多个统计标志可以组合使用，例如：

```bash
ariactl --tap eth0 stats --rules --qos --mirror
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

`ariactl health` 现在会额外显示 kernel drop 观测状态，包括：

- 是否可用
- 当前模式（`kfree_skb_reasonful` / `kfree_skb_legacy` / `disabled`）
- 当前已跟踪接口数量
- 最近一次初始化错误（如果存在）

## 命令参考

| 命令 | 说明 |
|------|------|
| `health` | Agent 健康检查 |
| `instances` | 列出所有实例 |
| `system start/stop` | 独立模式启停 |
| `group add/delete/list/with-stats` | IP 组管理（CIDR） |
| `policy add/delete/list/with-stats/batch` | ACL 策略管理 |
| `qos add/delete/list/with-stats` | QoS 限速管理 |
| `mirror add/delete/list/with-stats` | 端口镜像管理 |
| `conntrack list/flush` | 连接跟踪操作 |
| `tcprt top/flow/histogram/states/flush` | 业务延迟分析（支持 `--chain` 逐跳归因） |
| `trace start` | 丢包溯源（支持 `--chain` 服务链透视） |
| `chain apply/list/show/delete` | 服务链拓扑定义（供 tcprt/trace 共用） |
| `drops list/flush` | Kernel drop 观测与清理 |
| `ssl enable/disable/status/list/flush/http/http-flush/errors/errors-flush` | SSL/TLS 观测（host-global） |
| `diagnose` | 全栈连接诊断（TCP-RT + SSL + HTTP + kernel drop） |
| `stats [--rules|--flows|--qos|--groups|--mirror|--tcprt|--drops]` | 统一统计入口 |
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
| GET | `/{instance}/stats/rules\|flows\|qos\|groups\|mirror\|drops` | 详细统计（其中 `drops` 为旧防火墙 drop 接口） |
| GET/DELETE | `/stats/kernel_drops` | 全局 kernel drop 查看/清空 |
| GET/DELETE | `/{instance}/tcprt` | TCP-RT 查看/清空 |
| POST | `/tcprt/query` | 跨实例批量查询 |
| POST | `/tcprt/filter` | 按目标聚合查询 |
| POST/GET/DELETE | `/{instance}/trace` | 追踪启动/查看/停止 |
| GET/POST/DELETE | `/chains` | Service Chain CRUD |
| GET/POST/DELETE | `/ssl` | SSL 握手记录查看/清空 |
| GET/DELETE | `/ssl/http` | SSL HTTP 事件查看/清空 |
| GET/PUT | `/ssl/config` | SSL 全局配置查看/更新 |
| GET/DELETE | `/ssl/errors` | SSL 错误查看/清空 |
| POST | `/{instance}/diagnose` | 全栈连接诊断 |

`GET /health` 还会返回以下 kernel drop 状态字段：

- `kernel_drop_available`
- `kernel_drop_mode`
- `kernel_drop_managed_ifaces`
- `kernel_drop_last_error`

`GET /metrics` 还会导出以下 kernel drop 指标：

- `aria_kernel_drop_observability_up`
- `aria_kernel_drop_managed_ifaces`
- `aria_kernel_drop_mode_info`
- `aria_kernel_drop_last_error`
- `aria_kernel_drop_packets_total`
- `aria_kernel_drop_bytes_total`

同时还会导出 trace backend 运行时指标：

- `aria_trace_backend_info`
- `aria_trace_runtime_registered_taps`
- `aria_trace_runtime_active_consumers`
- `aria_trace_runtime_lost_events_total`
- `aria_trace_runtime_cache_evictions_total`
- `aria_trace_runtime_consumer_failures_total`
- `aria_trace_runtime_consumer_restarts_total`
- `aria_trace_runtime_last_error`

## 配置文件

`/etc/aria-agent/config.toml`：

```toml
ebpf_path = "/usr/local/lib/libebpf_firewall.so"
trace_backend = "auto"                 # auto / legacy-map / perf-event-array / ringbuf
trace_auto_allow_ringbuf = false      # rollout gate: auto 模式默认仍保持 perf-first
pin_path = "/sys/fs/bpf/aria"
state_path = "/var/lib/aria-agent"
iface_pattern = "^(eth|tap)"    # 正则匹配要管理的接口
max_port_policies = 16384       # 端口集上限
listen_addr = "127.0.0.1:8080"  # API 监听地址
```

环境变量：`ARIA_API_URL` 覆盖 CLI 连接地址（默认 `http://127.0.0.1:8080`）。

## 许可证

MIT

# Aria Firewall 用户手册

本文档按功能模块组织，面向实际使用和运维，不按代码层或架构层展开。阅读顺序建议是：

1. 先看“运行模式与基础对象”
2. 再看具体功能模块
3. 最后看“运维、排障与已知限制”

`ariactl` 是 `aria-agent` 的薄客户端，绝大多数命令最终都调用 HTTP API。除特别说明外，省略全局 `--tap` 时，CLI 默认操作 `system` 实例。

## 1. 产品概览

Aria Firewall 是基于 eBPF/XDP + TC 的高性能防火墙与可观测平台，核心能力包括：

- 基于 IP 组、协议、方向和端口的 ACL 控制
- 连接跟踪和 fast-path 放行
- QoS policing / shaping
- 流量镜像
- TCP 业务时延分析（TCP-RT）
- 实时包级 trace
- kernel drop 观测
- SSL/TLS 与 HTTP 观测
- 多实例管理与运行时自动恢复

从使用视角看，它可以拆成三类能力：

- 控制类：`policy`、`qos`、`mirror`、`config`
- 观测类：`stats`、`conntrack`、`tcprt`、`trace`、`drops`、`ssl`
- 运行类：`system`、`instances`、`health`

## 2. 运行模式与基础对象

### 2.1 实例模型

Aria 有两种运行模式：

- `managed` 模式
  - `aria-agent` 根据 `iface_pattern` 自动发现并接管 tap/veth/eth 等接口
  - 每个接口对应一个独立实例
  - 适合多 tap、多租户、多链路并存的场景
- `system` 模式
  - 通过 `ariactl system start --iface <iface>` 显式接管单个接口
  - 不需要全局 `--tap`
  - 更接近传统“独占接管一块网卡”的模式

常用命令：

```bash
ariactl instances
ariactl health
ariactl system start --iface eth0
ariactl system stop
```

重要语义：

- 对多数命令，`--tap` 用于选择实例
- `system start/stop` 不能和 `--tap` 一起用
- `trace start` 自己带 `--tap` 参数，不复用全局 `--tap`
- SSL 相关命令是 host-global，`--tap` 会被忽略

### 2.2 地址分组（group）

`group` 不是一个孤立的业务模块，而是给 `policy`、`qos`、`mirror`、`stats`、`drops` 等能力复用的基础对象。

它的主要作用是：

- 把一组 CIDR 抽象成稳定的名字和 group id
- 让策略定义与地址变化解耦
- 让 eBPF 数据面先做地址归类，再按 group id 匹配规则
- 统一统计与观测口径

示例：

```bash
ariactl --tap eth0 group add --name web --cidr 10.0.0.0/8
ariactl --tap eth0 group add --name db --cidr 192.168.1.0/24
ariactl --tap eth0 group list
ariactl --tap eth0 group with-stats
```

关键语义：

- `any` 是保留字，不能创建同名 group
- `any` 在规则语义里表示通配
- group id `0` 保留给通配/默认语义
- `default` 主要用于 QoS，表示 group id `0` 的默认规则

何时值得用 group：

- IP 范围会变化，但规则语义不变
- 多个模块需要复用同一地址对象
- 想按“应用组/业务组”而不是硬编码 IP 写策略

### 2.3 方向语义

方向是全产品里最容易误用的概念之一。

- `ingress`
  - 指报文进入当前实例/接口
- `egress`
  - 指报文从当前实例/接口发出

这会影响：

- `policy` 是否命中
- `qos` 规则适配哪一侧
- `mirror` 是否触发
- `stats` 统计结果怎么看

经验法则：

- 如果流量方向是 `tap -> peer`，通常在当前 tap 上更容易命中 `egress`
- 如果流量方向是 `peer -> tap`，通常更容易命中 `ingress`

### 2.4 服务链拓扑（chain）

`chain` 不是一级主功能，而是 `tcprt` 和 `trace` 的配套拓扑定义能力。

它的作用是：

- 为跨 hop 的 `trace` 输出提供链路视图
- 为 `tcprt flow --chain` 提供逐跳延迟分解

它本身只负责维护一份服务链定义：

```bash
ariactl chain apply --file chain.json
ariactl chain list
ariactl chain show prod-chain
ariactl chain delete prod-chain
```

数据结构包含：

- `name`
- `description`
- `hops`
- 每个 hop 的 `hop_type`
  - `bridge`
  - `proxy`
- 每个 hop 绑定的 `tap` 及 `role`
  - `in`
  - `out`
  - `bidirectional`

如果你的目标只是普通 ACL、QoS、镜像，通常不需要先定义 chain；只有在要做逐跳分析时才需要。

## 3. 安装、配置与启动

### 3.1 Release 安装

推荐直接使用 release 产物：

```bash
wget https://github.com/chenyongming211-glitch/aria-firewall/releases/latest/download/firewall-binaries-x86_64.zip
unzip firewall-binaries-x86_64.zip -d /tmp/aria

sudo cp /tmp/aria/aria-agent /usr/local/bin/
sudo cp /tmp/aria/ariactl /usr/local/bin/
sudo cp /tmp/aria/libebpf_firewall.so /usr/local/lib/
sudo cp /tmp/aria/libebpf_firewall_perf.so /usr/local/lib/
sudo chmod +x /usr/local/bin/aria-agent /usr/local/bin/ariactl
```

首次配置：

```toml
ebpf_path = "/usr/local/lib/libebpf_firewall.so"
trace_backend = "auto"
trace_auto_allow_ringbuf = false
pin_path = "/sys/fs/bpf/aria"
state_path = "/var/lib/aria-agent"
iface_pattern = "^(eth|tap)"
max_port_policies = 16384
listen_addr = "127.0.0.1:8080"
```

重要注意：

- trace backend rollout 期间，要原子更新以下四个文件：
  - `aria-agent`
  - `ariactl`
  - `libebpf_firewall.so`
  - `libebpf_firewall_perf.so`
- 只更新 `.so` 不更新 `aria-agent`，会造成用户态 trace backend 逻辑仍停留在旧版本

### 3.2 启动与健康检查

```bash
sudo aria-agent
# 或
sudo systemctl start aria-agent

ariactl health
ariactl instances
```

`ariactl health` 会输出：

- agent 状态
- 版本
- 当前实例数
- kernel drop observability 是否可用
- kernel drop 当前模式
- 当前已管理接口数
- 最近一次 kernel drop 初始化错误

## 4. 快速开始

下面用最小流程跑通一套实例。

### 4.1 启动 agent

```bash
sudo systemctl start aria-agent
ariactl health
```

### 4.2 创建基础 group

```bash
ariactl --tap eth0 group add --name web --cidr 10.0.0.0/8
ariactl --tap eth0 group add --name db --cidr 192.168.1.0/24
ariactl --tap eth0 group list
```

### 4.3 添加 ACL

```bash
ariactl --tap eth0 policy add \
  --src-group web --dst-group db \
  --proto tcp --ports 3306 \
  --action accept --direction ingress
```

### 4.4 查看统计

```bash
ariactl --tap eth0 stats
ariactl --tap eth0 stats --rules
ariactl --tap eth0 conntrack list
```

### 4.5 观察 trace

```bash
ariactl trace start \
  --tap eth0 \
  --dst 10.0.0.5 --proto tcp --dport 3306 \
  --wait 5
```

推荐 trace 验证方式是：

1. `flush`
2. `start`
3. 发一小批匹配流量
4. 第一次读取结果

## 5. 功能模块：ACL 策略（policy）

### 5.1 作用

`policy` 是防火墙主体能力，用于按以下维度匹配：

- 源组 `src_group`
- 目的组 `dst_group`
- 协议 `proto`
- 方向 `direction`
- 可选端口集合 `ports`

CLI 子命令是 `ariactl policy`，但产品能力上通常把它理解为 ACL。

### 5.2 常见命令

```bash
ariactl --tap eth0 policy add \
  --src-group web --dst-group db \
  --proto tcp --ports 3306 \
  --action accept --direction ingress

ariactl --tap eth0 policy list
ariactl --tap eth0 policy with-stats

ariactl --tap eth0 policy delete \
  --src-group web --dst-group db \
  --proto tcp --direction ingress
```

### 5.3 端口匹配

`--ports` 可选，仅对有端口概念的协议有意义。支持：

- 单端口：`80`
- 多端口：`80,443`
- 范围：`10000-20000`
- 混合：`80,443,10000-20000`

策略 `list` / `with-stats` 输出里的 `Bitmap` 是端口集合在底层 bitmap 池里的索引。普通用户只需要知道：

- `-` 表示这条规则没有端口位图
- 非 `-` 表示这条规则启用了端口集合

### 5.4 批量导入

```bash
ariactl --tap eth0 policy batch --file policies.json
cat policies.json | ariactl --tap eth0 policy batch --file -
```

实际行为不是“整批事务”。当前语义是：

- 合法项会继续写入
- 非法项会记录到 `errors`
- CLI 会输出 `Batch complete: N added`
- 只要存在错误，CLI 会以非零退出

这适合做“尽量导入 + 明确列出失败项”，不适合当严格全-or-nothing 事务用。

### 5.5 删除 group 的约束

如果某个 group 仍被以下对象引用，删除会失败：

- policy
- mirror

这属于正常保护行为，用来避免内存态和内核态失配。

## 6. 功能模块：QoS 限速（qos）

### 6.1 作用

`qos` 用于按 group 限制带宽。支持：

- `policing`
  - 超限直接丢包
- `shaping`
  - 使用 EDT 做平滑整形

### 6.2 常见命令

```bash
ariactl --tap eth0 qos add \
  --group web --direction egress \
  --rate 100mbps --burst 1mb \
  --priority 1 --mode shaping

ariactl --tap eth0 qos list
ariactl --tap eth0 qos with-stats
ariactl --tap eth0 qos delete --group web --direction egress
```

### 6.3 方向和 group 命中语义

这部分必须按代码逻辑理解：

- egress QoS 优先按“目标组”命中，再回退到默认组 `group_id=0`
- ingress QoS 优先按“源组”命中，再回退到默认组 `group_id=0`

所以实践上：

- 如果你要限制“发往 db 的出向流量”，更自然的是把 egress QoS 绑到 `db`
- 如果你要限制“来自 web 的入向流量”，更自然的是把 ingress QoS 绑到 `web`

### 6.4 `default` 与 `any`

QoS 里 `default` 和 `any` 都会映射到 group id `0`，作为全局默认桶使用。

示例：

```bash
ariactl --tap eth0 qos add \
  --group default --direction both \
  --rate 200mbps --burst 0
```

### 6.5 `policing` 与 `shaping`

使用建议：

- ingress：优先理解成 policing
- egress：既可以 policing，也适合 shaping

`shaping` 依赖 root `fq` qdisc。系统会尽量自动安装和恢复；如果 qdisc 不可用，EDT 效果会受限。

### 6.6 统计解释

`qos with-stats` 和 `stats --qos` 会输出：

- `PassPkts/PassBytes`
- `DropPkts/DropBytes`
- `ShapePkts/ShapeBytes`

其中：

- `Shape*` 主要在 egress shaping 下有意义
- `Drop*` 表示被 policing 直接丢弃

## 7. 功能模块：端口镜像（mirror）

### 7.1 作用

`mirror` 用于把符合条件的报文镜像到目标接口，适合：

- 抓包旁路分析
- 流量审计
- 与第三方 IDS/流量分析器对接

### 7.2 常见命令

```bash
ariactl --tap eth0 mirror add \
  --src-group web --dst-group db \
  --proto tcp --direction both \
  --target tapmirror

ariactl --tap eth0 mirror list
ariactl --tap eth0 mirror with-stats

ariactl --tap eth0 mirror delete \
  --src-group web --dst-group db \
  --proto tcp --direction both
```

### 7.3 规则维度

支持按以下条件过滤：

- `src_group`
- `dst_group`
- `proto`
- `direction`
- `target`

其中：

- `src_group` / `dst_group` 默认都是 `any`
- `proto` 默认 `any`
- `direction` 可选 `ingress` / `egress` / `both`

### 7.4 `with-stats` 如何看

镜像统计包含：

- `MirrorPkts`
- `MirrorBytes`
- `Errors`

如果 `Errors` 增长，优先排查：

- target 接口是否存在
- target 接口是否可用
- target ifindex 是否变化

### 7.5 mirror target 消失时的恢复语义

如果 mirror target 在运行时不存在：

- 正常 replay 不应该因为单个失效 target 把整次恢复拖垮
- 当前实现会记录 warning，并跳过不可达 target

这意味着其它功能对象仍能完成 replay。

## 8. 功能模块：业务延迟分析（tcprt）

### 8.1 作用

`tcprt` 用于做 TCP 业务响应时间分析，关注的核心指标包括：

- `hs`：握手时延
- `crtt`：客户端 RTT
- `srtt`：服务端 RTT
- `art`：应用响应时间
- 请求/响应方向重传
- `nqa`：综合质量分

### 8.2 命令分类

跨实例分析：

- `tcprt top`
- `tcprt flow`

实例级视图：

- `tcprt histogram`
- `tcprt states`
- `tcprt flush`

### 8.3 Top-N 分析

```bash
ariactl tcprt top --by art --top 10
ariactl tcprt top --by crtt --top 20 --watch --interval 2
```

排序维度：

- `art`
- `crtt`
- `srtt`
- `hs`
- `retrans`
- `nqa`

`top` 会从所有活跃实例抓取 TCP-RT 数据并做跨实例聚合排序。

### 8.4 单服务分析

```bash
ariactl tcprt flow --dst 10.0.0.5 --dport 3306
ariactl tcprt flow --dst 10.0.0.5 --dport 3306 --chain prod-chain
```

不带 `--chain` 时：

- 优先尝试双观测拆解
- 如果只是普通多实例聚合，会给出较粗粒度的 per-instance 视图
- 多实例场景下，CLI 会提示你可以用 `--chain`

带 `--chain` 时：

- 会先读取服务链定义
- 再按 hop 聚合各实例的 TCP-RT 数据
- 输出“客户端网络、hop 之间、服务端处理”的逐跳拆解

### 8.5 直方图与状态分布

```bash
ariactl --tap eth0 tcprt histogram
ariactl --tap eth0 tcprt states
ariactl --tap eth0 tcprt flush
```

用途分别是：

- `histogram`
  - 看 ART 分布
  - 适合判断尾延迟
- `states`
  - 看状态分布和异常提示
- `flush`
  - 清空该实例的 TCP-RT 表

### 8.6 active flow 语义

当前对外暴露的 active flow 口径已经过滤掉关闭流，但 map 生命周期仍是内部实现细节。使用上只需要记住：

- `top`
- `flow`
- `stats --tcprt`

都以“当前对外可见的活跃流”口径展示。

## 9. 功能模块：包级追踪（trace）

### 9.1 作用

`trace` 用于做包级追踪和丢包定位，适合：

- 验证规则是否命中
- 确认包在哪个 hook 被丢掉
- 多实例路径上的逐跳追踪

### 9.2 命令特点

当前 CLI 只有一个主动作：`trace start`

```bash
ariactl trace start \
  --tap eth0 \
  --dst 10.0.0.5 --proto tcp --dport 3306 \
  --wait 5
```

注意：

- 这里的 `--tap` 是 `trace start` 自己的参数
- 不带 `--tap` 时，CLI 会自动选择所有活跃实例
- 带 `--wait` 时做 timed trace
- 不带 `--wait` 时做 live trace，直到 `Ctrl+C`

### 9.3 推荐使用方式

推荐顺序：

1. `flush`
2. `start`
3. 发匹配流量
4. 第一次读取结果

CLI 内部会在开始前先尝试 `flush`，结束后再 `stop`，适合快速闭环验证。

### 9.4 输出如何理解

非 chain 模式下，trace 更像“按实例汇总”：

- 每个实例显示 `In` / `Out`
- 如果发现 drop，会给出 `drop_reason`
- 最后按实例列出 detail

chain 模式下：

- 先按 hop 展示每个 tap 的 `in/out`
- 再做 hop 内和 hop 间的丢包归因
- 最后列出各 hop 上的 detail

### 9.5 `--chain` 的作用

```bash
ariactl trace start --chain prod-chain --dst 10.0.0.5 --dport 3306 --wait 5
```

适用场景：

- 多个 tap 串联成一条业务路径
- 你关心“哪一跳丢了包”
- 你关心“这是 eBPF 明确捕获的 drop，还是 hop 间黑盒丢包”

### 9.6 trace backend 与缓存上限

当前默认 rollout 路径是：

- `trace_backend = "auto"`
- `trace_auto_allow_ringbuf = false`

实际优先使用 perf backend。当前 userspace trace cache 有固定上限，已知默认上限是 `4096` 条。也就是说：

- `20`
- `200`
- `1000`
- `4096`

这类回归通常没有问题；更大批次如果在第一次读取前积压过多，可能触发 cache eviction。

## 10. 功能模块：Kernel Drop 观测（drops）

### 10.1 作用

`drops` 看的是内核层 drop，不是防火墙主动 drop。

区别：

- 防火墙主动 drop
  - 看 `stats --rules`
  - 看 `stats --qos`
- 内核层 drop
  - 看 `drops list/flush`

### 10.2 常见命令

```bash
ariactl drops list
ariactl --tap eth0 drops list
ariactl --tap eth0 drops list --iface eth0 --top 20
ariactl drops list --include-unattributed
```

清理必须带 `--force`：

```bash
ariactl --tap eth0 drops flush --force
ariactl --tap eth0 drops flush --iface eth0 --force
ariactl drops flush --include-unattributed --force
```

### 10.3 过滤维度

- 全局 `--tap`
- 子命令 `--iface`
- `top`
- `include_unattributed`

### 10.4 输出字段

- `Instance`
- `Iface`
- `Ifindex`
- `Reason`
- `Proto`
- `Packets`
- `Bytes`
- `Source`

如果返回“kernel drop observability is not available”，通常是环境不支持或当前模式未启用，不一定是功能 bug。

## 11. 功能模块：连接跟踪（conntrack）

### 11.1 作用

`conntrack` 用于查看实例级连接表，适合：

- 确认连接是否已建立
- 确认是否进入 fast-path
- 清空连接表做回归

### 11.2 常见命令

```bash
ariactl --tap eth0 conntrack list
ariactl --tap eth0 conntrack flush
```

输出包含：

- 源/目的地址
- 源/目的端口
- 协议
- 状态
- 包计数
- 字节计数

## 12. 功能模块：监控与统计（stats / metrics）

### 12.1 `stats` 概览

不带子选项时：

```bash
ariactl --tap eth0 stats
```

返回的是当前实例的：

- group 数量
- policy 数量
- QoS 规则数量
- mirror 规则数量
- conntrack IPv4 / IPv6 数量

### 12.2 详细统计

```bash
ariactl --tap eth0 stats --rules
ariactl --tap eth0 stats --flows --top 20
ariactl --tap eth0 stats --qos
ariactl --tap eth0 stats --groups
ariactl --tap eth0 stats --mirror
ariactl --tap eth0 stats --tcprt --top 20
ariactl --tap eth0 stats --drops --top 50
```

这些选项可以组合：

```bash
ariactl --tap eth0 stats --rules --qos --mirror
```

### 12.3 统计口径建议

测试统计前，要先确认：

- 流量方向是否和规则方向一致
- group 是否绑在正确的一侧
- `qos egress` 是否绑到了目标组
- `mirror` 是否配置了匹配当前流量方向的规则

### 12.4 `/metrics`

`GET /metrics` 会导出 Prometheus 指标，包括：

- 基础对象计数
- rule/group/qos/mirror 统计
- kernel drop 指标
- trace backend 运行时指标

尤其值得关注：

- `aria_trace_backend_info`
- `aria_trace_runtime_registered_taps`
- `aria_trace_runtime_active_consumers`
- `aria_trace_runtime_consumer_failures_total`
- `aria_trace_runtime_consumer_restarts_total`
- `aria_trace_runtime_last_error`

## 13. 功能模块：SSL 可观测性（ssl）

### 13.1 作用

`ssl` 模块提供：

- TLS 握手观测
- SSL HTTP 请求/响应观测
- SSL 错误观测

### 13.2 最重要的语义

SSL 是 host-global，不是 per-instance。

这意味着：

- `ariactl --tap eth0 ssl ...` 可以执行
- 但 `--tap` 会被忽略
- CLI 会显式提示这一点

### 13.3 常见命令

```bash
ariactl ssl enable
ariactl ssl disable
ariactl ssl status

ariactl ssl list --top 100
ariactl ssl flush

ariactl ssl http --top 100
ariactl ssl http-flush

ariactl ssl errors --top 20
ariactl ssl errors-flush
```

### 13.4 输出解释

`ssl list`：

- `PID`
- `TID`
- `Handshake(us)`
- `SNI`
- `Seq`

`ssl http`：

- `Method`
- `Host`
- `Path`
- `Status`
- `Latency(us)`

`ssl errors`：

- `syscall`
- `timestamp`
- `ret_code`
- `error_hint`

## 14. 功能模块：运行时配置（config）

### 14.1 作用

所有主要开关都支持热切换，无需重启 agent。

```bash
ariactl --tap eth0 config show
ariactl --tap eth0 config set conntrack on
ariactl --tap eth0 config set monitoring on
ariactl --tap eth0 config set acl on
ariactl --tap eth0 config set qos off
ariactl --tap eth0 config set mirror off
ariactl --tap eth0 config set tcprt on
ariactl config set ssl on
```

### 14.2 支持的 key

- `conntrack`
- `monitoring`
- `acl`
- `qos`
- `mirror`
- `tcprt`
- `ssl`

### 14.3 特殊点：SSL

`ssl` 配置是全局的，不走普通实例配置路径：

- `config set ssl on/off` 会走专门的全局 SSL 配置接口
- 即使你带了 `--tap`，也只会影响提示，不影响实际作用域

## 15. 运行管理、恢复与排障

### 15.1 `instances`

```bash
ariactl instances
```

用于查看当前已注册实例及其 `active` 状态。

### 15.2 `health`

```bash
ariactl health
```

用于做：

- agent 存活确认
- kernel drop 模式确认
- 已管理实例数量确认

### 15.3 `system start/stop`

```bash
ariactl system start --iface eth0
ariactl system stop
```

用途：

- 接管单一系统接口
- 不依赖全局 `--tap`

运行时会涉及：

- XDP attach
- TC attach
- pinned objects
- root `fq` qdisc 管理

### 15.4 managed 自动恢复

managed 模式下，系统具备以下恢复能力：

- agent restart 后实例恢复
- shared runtime repair
- crash recovery 后补回缺失的 TC link
- QoS shaping 场景下补回缺失的 `fq`

### 15.5 `diagnose`

```bash
ariactl --tap eth0 diagnose --dst 10.0.0.5 --dport 3306
```

它会组合多个观测面做摘要：

- TCP-RT
- SSL/TLS
- HTTP
- kernel drop

适合快速判断：

- 健康
- 降级
- 不健康

### 15.6 建议排障路径

推荐顺序：

1. `ariactl health`
2. `ariactl instances`
3. `ariactl --tap <tap> config show`
4. `ariactl --tap <tap> stats`
5. `ariactl --tap <tap> conntrack list`
6. `ariactl trace start ...`
7. `ariactl tcprt flow ...`
8. 必要时看 `/metrics`

## 16. REST API 概览

所有接口前缀都是 `/api/v1/`。

常用分组：

- 健康与实例
  - `GET /health`
  - `GET /instances`
- system
  - `POST /system/start`
  - `POST /system/stop`
- group / policy / qos / mirror / conntrack / config
  - 都是实例作用域接口
- tcprt
  - 实例内查看
  - 全局 filter/query
- trace
  - `POST/GET/DELETE /{instance}/trace`
  - `DELETE /{instance}/trace/flush`
- ssl
  - 全局 `ssl` / `ssl/http` / `ssl/config` / `ssl/errors`
- chains
  - `GET/POST/DELETE /chains`
- kernel drops
  - `GET/DELETE /stats/kernel_drops`

如果你更习惯 CLI，可以把 CLI 理解为这些 API 的薄封装。

## 17. 测试与回归

仓库当前提供两个直接可用的远端回归脚本：

```bash
python3 tools/runtime_lifecycle_regression.py --host root@<host>
python3 tools/trace_perf_regression.py --host root@<host> --packet-counts 20,200 --rounds 2
```

适用范围：

- runtime lifecycle
- trace flush/start/first-read
- system vanished iface
- preexisting fq
- managed crash recovery

## 18. 已知限制

### 18.1 trace cache 上限

当前 userspace trace cache 有固定容量上限，已知默认值是 `4096`。因此：

- `5000` 级别回归不是未知 bug
- 它反映的是当前产品容量边界

### 18.2 4.18 回归待补

当前主要闭环验证在 `6.8` 上完成；`4.18` 环境仍然需要补回归。

### 18.3 SSL 是 host-global

这不是 bug，而是产品语义：

- `ssl` 数据和配置都不是实例私有
- `--tap` 对 SSL 只起到 UI 提示效果

## 19. 附录：常用命令速查

### 19.1 基础

```bash
ariactl health
ariactl instances
ariactl system start --iface eth0
ariactl system stop
```

### 19.2 group

```bash
ariactl --tap eth0 group add --name web --cidr 10.0.0.0/8
ariactl --tap eth0 group list
ariactl --tap eth0 group with-stats
ariactl --tap eth0 group delete --name web
```

### 19.3 policy

```bash
ariactl --tap eth0 policy add --src-group web --dst-group db --proto tcp --ports 3306 --action accept --direction ingress
ariactl --tap eth0 policy list
ariactl --tap eth0 policy with-stats
ariactl --tap eth0 policy delete --src-group web --dst-group db --proto tcp --direction ingress
```

### 19.4 qos

```bash
ariactl --tap eth0 qos add --group db --direction egress --rate 100mbps --mode shaping
ariactl --tap eth0 qos list
ariactl --tap eth0 qos with-stats
ariactl --tap eth0 qos delete --group db --direction egress
```

### 19.5 mirror

```bash
ariactl --tap eth0 mirror add --src-group web --dst-group db --proto tcp --direction both --target tapmirror
ariactl --tap eth0 mirror list
ariactl --tap eth0 mirror with-stats
ariactl --tap eth0 mirror delete --src-group web --dst-group db --proto tcp --direction both
```

### 19.6 tcprt / trace

```bash
ariactl tcprt top --by art --top 10
ariactl tcprt flow --dst 10.0.0.5 --dport 3306 --chain prod-chain
ariactl trace start --tap eth0 --dst 10.0.0.5 --proto tcp --dport 3306 --wait 5
ariactl trace start --chain prod-chain --dst 10.0.0.5 --dport 3306 --wait 5
```

### 19.7 conntrack / drops / stats / ssl

```bash
ariactl --tap eth0 conntrack list
ariactl --tap eth0 stats --rules --qos --mirror
ariactl drops list --top 50
ariactl ssl status
ariactl ssl list --top 100
```

### 19.8 chain（供 `tcprt` / `trace` 使用）

```bash
ariactl chain apply --file chain.json
ariactl chain list
ariactl chain show prod-chain
ariactl chain delete prod-chain
```

示例：

```json
{
  "name": "prod-chain",
  "description": "Production service chain",
  "hops": [
    {
      "name": "load-balancer",
      "hop_type": "proxy",
      "taps": [
        { "tap": "tap1", "role": "in" },
        { "tap": "tap2", "role": "out" }
      ]
    },
    {
      "name": "app-server",
      "hop_type": "bridge",
      "taps": [
        { "tap": "tap3", "role": "bidirectional" }
      ]
    }
  ]
}
```

# Aria Firewall 用户手册

本文档按用户实际使用的功能模块组织，不按代码目录和内部实现分层展开。  
阅读建议是：

1. 先看安装、启动和实例管理
2. 再看 ACL、QoS、Mirror 这些控制类能力
3. 然后看 TCP-RT、Trace、Drops、Conntrack、SSL 这些观测类能力
4. 最后看排障、回归和已知限制

`ariactl` 是 `aria-agent` 的薄客户端。绝大多数 CLI 命令都会转成 `/api/v1/...` HTTP 请求。

## 1. 产品概览

Aria Firewall 是基于 eBPF/XDP + TC 的网络防火墙与可观测平台，核心能力包括：

- 基于 IP 组、方向、协议、端口的 ACL 控制
- 连接跟踪与 fast-path 放行
- QoS policing / shaping
- 流量镜像
- TCP 业务延迟分析（TCP-RT）
- 实时包级 trace
- kernel drop 观测
- SSL/TLS 与 HTTP 观测
- 多实例运行、自动恢复和 pinned runtime repair

从使用视角，可以把它分成三类能力：

- 控制类
  - `policy`
  - `qos`
  - `mirror`
  - `config`
- 观测类
  - `stats`
  - `conntrack`
  - `tcprt`
  - `trace`
  - `drops`
  - `ssl`
- 运行类
  - `system`
  - `instances`
  - `health`

## 2. 安装与部署

### 2.1 Release 安装

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

```bash
sudo mkdir -p /etc/aria-agent
sudo tee /etc/aria-agent/config.toml >/dev/null <<'EOF'
ebpf_path = "/usr/local/lib/libebpf_firewall.so"
trace_backend = "auto"
trace_auto_allow_ringbuf = false
pin_path = "/sys/fs/bpf/aria"
state_path = "/var/lib/aria-agent"
iface_pattern = "^(eth|tap)"
max_port_policies = 16384
listen_addr = "127.0.0.1:8080"
EOF
```

### 2.2 配置项说明

常用配置项：

- `ebpf_path`
  - 默认 eBPF 对象路径
- `trace_backend`
  - `auto`
  - `legacy-map`
  - `perf-event-array`
  - `ringbuf`
- `trace_auto_allow_ringbuf`
  - `auto` 模式下是否允许自动切到 ringbuf
  - 当前推荐保持 `false`
- `pin_path`
  - bpffs 根目录
- `state_path`
  - 用户态状态目录
- `iface_pattern`
  - managed 模式自动接管的接口正则
- `max_port_policies`
  - 端口 bitmap 上限
- `listen_addr`
  - HTTP API 监听地址

### 2.3 启动与版本确认

```bash
sudo aria-agent
# 或
sudo systemctl start aria-agent

ariactl health
ariactl instances
```

`ariactl health` 会显示：

- 当前状态
- 版本
- 实例数量
- kernel drop observability 是否可用
- kernel drop 当前模式
- 当前已跟踪接口数
- 最近一次 kernel drop 初始化错误

### 2.4 升级注意事项

Trace backend rollout 期间，必须原子更新以下四个文件：

- `aria-agent`
- `ariactl`
- `libebpf_firewall.so`
- `libebpf_firewall_perf.so`

不要只更新 `.so` 而不更新 `aria-agent`，否则用户态 trace backend 逻辑可能仍停留在旧版本。

## 3. 快速开始

下面用最小链路跑通一个实例。

### 3.1 启动 agent

```bash
sudo systemctl start aria-agent
ariactl health
ariactl instances
```

### 3.2 创建地址对象并配置 ACL

```bash
ariactl --tap eth0 group add --name web --cidr 10.0.0.0/8
ariactl --tap eth0 group add --name db --cidr 192.168.1.0/24

ariactl --tap eth0 policy add \
  --src-group web --dst-group db \
  --proto tcp --ports 3306 \
  --action accept --direction ingress
```

### 3.3 查看配置与统计

```bash
ariactl --tap eth0 group list
ariactl --tap eth0 policy list
ariactl --tap eth0 stats
ariactl --tap eth0 stats --rules
ariactl --tap eth0 conntrack list
```

### 3.4 跑一次 trace

```bash
ariactl trace start \
  --tap eth0 \
  --dst 10.0.0.5 --proto tcp --dport 3306 \
  --wait 5
```

最稳的 trace 验证顺序是：

1. 先 `flush`
2. 再 `start`
3. 发一批匹配流量
4. 第一次读取结果

## 4. 实例管理与运行模式

### 4.1 managed 模式

managed 模式由 `aria-agent` 自动接管接口。接口是否被接管，取决于：

- 接口名是否匹配 `iface_pattern`
- agent 是否成功完成 attach / replay / registration

每个被接管的接口都会形成一个独立实例。

### 4.2 system 模式

system 模式用于显式接管一个接口：

```bash
ariactl system start --iface eth0
ariactl system stop
```

特点：

- 不依赖全局 `--tap`
- 更接近传统“独占管理一块网卡”的模式
- `system stop` 只影响 `system` 实例，不影响 managed 实例

### 4.3 `--tap` 的真实含义

全局 `--tap` 不只是“选哪个接口”，更准确地说，它是在选“哪个实例的状态命名空间”。

例如：

```bash
ariactl --tap eth0 policy list
```

这条命令的含义是：

- 去实例 `eth0` 的状态里查 ACL 配置
- 不是去全局对象池里查

省略 `--tap` 时，CLI 默认操作 `system` 实例，见 [/Users/chen/code/aria-firewall/user/src/main.rs#L9](/Users/chen/code/aria-firewall/user/src/main.rs#L9)。

### 4.4 `instances` 与 `health`

```bash
ariactl instances
ariactl health
```

`instances` 用于查看当前已注册实例及其 `active` 状态。  
`health` 更适合做全局健康检查。

### 4.5 生命周期与自动恢复

当前运行时支持的恢复能力包括：

- agent restart 后实例恢复
- shared runtime repair
- crash recovery 后补回缺失的 TC link
- QoS shaping 场景下补回缺失的 `fq`
- `system` / managed 生命周期里对 owned `fq` 的清理与保留

## 5. 功能模块：ACL 与地址对象（group / policy）

这一章把 `group` 和 `policy` 放在一起讲，因为 `group` 在产品语义上不是一个独立业务模块，而是 ACL、QoS、Mirror 等能力共享的地址对象抽象。

### 5.1 为什么需要 group

`group` 的主要价值是：

- 把 CIDR 集合抽象成稳定名字和 group id
- 让规则定义与地址变化解耦
- 让数据面先做地址归类，再做 policy/qos/mirror 匹配
- 让统计和观测结果按业务组展示，而不是直接暴露 IP

### 5.2 group 的作用域

这是最容易误解的点。

`group` 是按实例隔离的，不是全局共享对象。

例如：

```bash
ariactl --tap eth0 group add --name web --cidr 10.0.0.0/8
ariactl --tap eth1 group add --name web --cidr 172.16.0.0/16
```

这两条命令都是合法的。它们表示：

- `eth0` 实例里有一个叫 `web` 的 group
- `eth1` 实例里也有一个叫 `web` 的 group

但这两个 `web`：

- 名字可以一样
- 定义可以不同
- 互不共享
- 互不影响

为什么会这样：

- group API 路由本身就是按实例作用域设计的，见 [/Users/chen/code/aria-firewall/agent/src/api_routes.rs#L54](/Users/chen/code/aria-firewall/agent/src/api_routes.rs#L54)
- 每个 managed 实例都有自己独立的 `state_path`，见 [/Users/chen/code/aria-firewall/agent/src/tap_registry.rs#L108](/Users/chen/code/aria-firewall/agent/src/tap_registry.rs#L108)
- 每个实例的 `FirewallState` 里都有各自的 `groups` 和 `next_group_id`，见 [/Users/chen/code/aria-firewall/core/src/state.rs#L122](/Users/chen/code/aria-firewall/core/src/state.rs#L122)

所以你可以直接记成一句话：

- `group` 是每个实例自己的地址对象
- 不是整个主机共享的全局字典

### 5.3 特殊名字：`any`

`any` 是保留字：

- 不能创建名为 `any` 的 group
- 在规则语义里，`any` 表示通配
- group id `0` 保留给 `any`

对应实现见 [/Users/chen/code/aria-firewall/core/src/state.rs#L147](/Users/chen/code/aria-firewall/core/src/state.rs#L147) 和 [/Users/chen/code/aria-firewall/agent/src/control_plane.rs#L2300](/Users/chen/code/aria-firewall/agent/src/control_plane.rs#L2300)。

### 5.4 group 常用命令

```bash
ariactl --tap eth0 group add --name web --cidr 10.0.0.0/8
ariactl --tap eth0 group add --name db --cidr 192.168.1.0/24
ariactl --tap eth0 group list
ariactl --tap eth0 group with-stats
ariactl --tap eth0 group delete --name web
```

`group with-stats` 会同时展示：

- ingress 包数 / 字节数
- egress 包数 / 字节数
- group 绑定的 CIDR 列表

### 5.5 policy 的匹配维度

`policy` 是防火墙主体能力，用于按以下维度匹配：

- `src_group`
- `dst_group`
- `proto`
- `direction`
- `ports`
- `action`

其中：

- `src_group` / `dst_group` 都是在“当前实例”里解析
- 如果 group 只存在于别的实例，这里会报 `GroupNotFound`

### 5.6 policy 常见命令

```bash
ariactl --tap eth0 policy add \
  --src-group web --dst-group db \
  --proto tcp --ports 3306 \
  --action accept --direction ingress

ariactl --tap eth0 policy add \
  --src-group web --dst-group any \
  --proto tcp --ports 80,443 \
  --action accept --direction egress

ariactl --tap eth0 policy list
ariactl --tap eth0 policy with-stats

ariactl --tap eth0 policy delete \
  --src-group web --dst-group db \
  --proto tcp --direction ingress
```

### 5.7 方向语义

`direction` 的语义始终是相对于“当前实例/接口”而言：

- `ingress`
  - 包进入当前实例
- `egress`
  - 包从当前实例发出

这点非常重要，因为：

- 你明明配置了正确的 group 和端口
- 但如果方向配反了
- 规则也不会命中

经验法则：

- 如果是 `tap -> peer` 的发包路径，通常更容易命中 `egress`
- 如果是 `peer -> tap` 的发包路径，通常更容易命中 `ingress`

### 5.8 端口集合与 `Bitmap`

`--ports` 可选，仅对有端口语义的协议生效。支持：

- 单端口：`80`
- 多端口：`80,443`
- 范围：`10000-20000`
- 混合：`80,443,10000-20000`

`policy list` 和 `policy with-stats` 会显示 `Bitmap` 字段。这个字段是底层端口 bitmap 池索引，使用上只需要理解：

- `-`
  - 这条规则没有端口位图
- 非 `-`
  - 这条规则绑定了一个端口集合

### 5.9 批量导入

```bash
ariactl --tap eth0 policy batch --file policies.json
cat policies.json | ariactl --tap eth0 policy batch --file -
```

当前语义不是全局事务，而是：

- 合法项尽量写入
- 非法项收集到 `errors`
- CLI 输出 `Batch complete: N added`
- 只要存在错误，CLI 最终以非零退出

这适合“批量导入 + 明确列出失败项”，不适合拿来做严格 all-or-nothing 配置发布。

### 5.10 删除 group 的约束

如果某个 group 仍被引用，删除会失败。当前至少包括：

- 被 policy 引用
- 被 mirror 引用

这是正常保护逻辑，用来避免把内存态和内核态弄分叉。

## 6. 功能模块：QoS 限速（qos）

### 6.1 作用

QoS 用于按 group 做带宽约束，支持两种模式：

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

### 6.3 `--group` 的作用域

和 policy 一样，这里的 `--group` 也是在“当前实例”里解析的 group 名称。

例如：

```bash
ariactl --tap eth0 qos add --group web ...
```

只会去 `eth0` 实例里找 `web`，不会去别的 tap 里找。

### 6.4 `default` 与 `any`

QoS 有一个和 ACL 不太一样但很实用的语义：

- `default`
- `any`

这两个名字在 QoS 里都会映射到 group id `0`，也就是全局默认桶。

示例：

```bash
ariactl --tap eth0 qos add \
  --group default --direction both \
  --rate 200mbps --burst 0
```

### 6.5 ingress / egress 的真实命中逻辑

这里必须按代码理解，而不能只按直觉理解。

当前数据面逻辑是：

- egress QoS 优先按“目标组”命中，再回退到 `group_id=0`
- ingress QoS 优先按“源组”命中，再回退到 `group_id=0`

这意味着：

- 如果你想限制“发往 db 的流量”，更合理的是在 egress QoS 上绑定 `db`
- 如果你想限制“来自 web 的流量”，更合理的是在 ingress QoS 上绑定 `web`

对应实现见 [/Users/chen/code/aria-firewall/ebpf/src/qos.rs#L98](/Users/chen/code/aria-firewall/ebpf/src/qos.rs#L98) 和 [/Users/chen/code/aria-firewall/ebpf/src/qos.rs#L207](/Users/chen/code/aria-firewall/ebpf/src/qos.rs#L207)。

### 6.6 `policing` 与 `shaping`

使用建议：

- ingress
  - 主要理解成 policing
- egress
  - 可以 policing
  - 更适合 shaping

`shaping` 依赖 root `fq` qdisc。系统会自动尝试安装、恢复和清理 owned `fq`。

### 6.7 速率和 burst

`--rate` 支持：

- `gbps`
- `mbps`
- `kbps`
- `bps`
- 纯数字字节/秒

`--burst` 支持：

- `0`
  - 自动计算
- `1mb`
- `512kb`
- 纯数字字节数

### 6.8 优先级

`--priority`：

- `0` 最高
- `7` 最低

### 6.9 统计字段解释

`qos with-stats` 与 `stats --qos` 会输出：

- `PassPkts/PassBytes`
- `DropPkts/DropBytes`
- `ShapePkts/ShapeBytes`

含义：

- `Pass*`
  - 通过的流量
- `Drop*`
  - policing 直接丢弃的流量
- `Shape*`
  - 进入 EDT 整形路径的流量

## 7. 功能模块：端口镜像（mirror）

### 7.1 作用

Mirror 用于把符合条件的报文镜像到目标接口，适合：

- 旁路抓包
- 与 IDS/分析器联动
- 对指定业务流量做复制观测

### 7.2 规则维度

支持：

- `src_group`
- `dst_group`
- `proto`
- `direction`
- `target`

默认值：

- `src_group any`
- `dst_group any`
- `proto any`

### 7.3 常见命令

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

### 7.4 `--tap` 与 group 作用域

Mirror 和 policy/QoS 一样，都是在当前实例内解析 group 名称。  
所以：

- `eth0` 上的 mirror 规则只引用 `eth0` 自己的 group
- 不能直接复用 `eth1` 的 group 定义

### 7.5 统计字段

`mirror with-stats` 会给出：

- `MirrorPkts`
- `MirrorBytes`
- `Errors`

如果 `Errors` 持续增长，优先排查：

- target 接口是否存在
- target 接口 ifindex 是否变化
- target 接口是否仍适合做镜像出口

### 7.6 目标接口消失后的恢复语义

运行时如果 mirror target 不存在：

- replay 不应该因为一个失效 target 而整体验证失败
- 当前实现会记录 warning，并跳过不可达 target

这样可以避免单个坏 target 把其它规则、ACL、QoS、实例恢复全部拖垮。

## 8. 功能模块：业务延迟分析（tcprt）

### 8.1 作用

TCP-RT 用于做 TCP 业务响应时间分析，关注以下指标：

- `hs`
  - 握手时延
- `crtt`
  - 客户端 RTT
- `srtt`
  - 服务端 RTT
- `art`
  - 应用响应时间
- 请求/响应方向重传
- `nqa`
  - 综合质量分

### 8.2 命令分类

跨实例分析：

- `tcprt top`
- `tcprt flow`

实例级视图：

- `tcprt histogram`
- `tcprt states`
- `tcprt flush`

### 8.3 Top-N

```bash
ariactl tcprt top --by art --top 10
ariactl tcprt top --by crtt --top 20 --watch --interval 2
```

支持排序维度：

- `art`
- `crtt`
- `srtt`
- `hs`
- `retrans`
- `nqa`

`top` 会从所有活跃实例抓取 TCP-RT 数据，然后做跨实例排序。

### 8.4 单服务分析

```bash
ariactl tcprt flow --dst 10.0.0.5 --dport 3306
ariactl tcprt flow --dst 10.0.0.5 --dport 3306 --chain prod-chain
```

不带 `--chain` 时：

- 优先尝试双观测拆解
- 如果只是普通多实例聚合，会给出较粗的 per-instance 视图
- 当场景更复杂时，CLI 会提示可以使用 `--chain`

带 `--chain` 时：

- 会先读取一份服务链定义
- 再按 hop 聚合各实例的 TCP-RT 数据
- 最终输出逐跳延迟拆解

### 8.5 `chain` 在 TCP-RT 里的定位

这里的 `chain` 不是独立主功能，而是 TCP-RT 的配套拓扑定义。

你通常只有在以下场景才需要它：

- 一个业务路径跨多个 tap
- 你关心哪一跳慢
- 你需要把总时延拆成 hop-to-hop 贡献

常见命令：

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

### 8.6 实例级视图

```bash
ariactl --tap eth0 tcprt histogram
ariactl --tap eth0 tcprt states
ariactl --tap eth0 tcprt flush
```

用途：

- `histogram`
  - 看 ART 分布
  - 适合分析尾延迟
- `states`
  - 看状态分布和异常提示
- `flush`
  - 清空实例内 TCP-RT 状态

### 8.7 active flow 语义

当前对外显示的 active flow 已经过滤掉已关闭流。  
使用上可以认为：

- `top`
- `flow`
- `stats --tcprt`

都只展示当前可见的活跃流。

## 9. 功能模块：包级追踪（trace）

### 9.1 作用

Trace 用于做包级追踪和丢包定位，适合：

- 验证规则命中情况
- 定位包在哪个 hook 被丢掉
- 做跨实例、跨 hop 的路径观测

### 9.2 当前 CLI 入口

当前 CLI 主动作是：

```bash
ariactl trace start ...
```

示例：

```bash
ariactl trace start \
  --tap eth0 \
  --dst 10.0.0.5 --proto tcp --dport 3306 \
  --wait 5
```

### 9.3 `trace start` 的 `--tap`

要特别注意：

- 这里的 `--tap` 是 `trace start` 自己的参数
- 不是全局 `--tap`

语义是：

- `ariactl trace start --tap tap1 ...`
  - 只追一个实例
- `ariactl trace start ...`
  - 自动追所有活跃实例

### 9.4 timed 模式与 live 模式

- 带 `--wait`
  - timed trace
  - 到时间后自动读取并停止
- 不带 `--wait`
  - live trace
  - 持续显示，直到 `Ctrl+C`

### 9.5 推荐使用方式

最稳的 trace 使用顺序是：

1. 先 `flush`
2. 再 `start`
3. 发匹配流量
4. 第一次读取结果

CLI 的 trace 工作流本身也会尽量遵循这个模式。

### 9.6 输出怎么看

非 chain 模式：

- 按实例汇总 `In` / `Out`
- 如果有 drop，会给出 `drop_reason`
- 最后列出 detail

chain 模式：

- 先按 hop 展示各 tap 的 `in/out`
- 再做 hop 内和 hop 间丢包归因
- 最后列出各 hop detail

### 9.7 `chain` 在 trace 里的定位

和 TCP-RT 一样，trace 里的 `chain` 不是独立主功能，而是配套拓扑输入。

示例：

```bash
ariactl trace start --chain prod-chain --dst 10.0.0.5 --dport 3306 --wait 5
```

适合：

- 多个 tap 串成一条链路
- 你要判断“哪一跳掉了包”
- 你要区分“明确捕获的 drop”和“hop 间黑盒丢包”

### 9.8 trace backend 与缓存限制

当前 rollout 推荐配置是：

```toml
trace_backend = "auto"
trace_auto_allow_ringbuf = false
```

实际优先走 perf backend。当前 userspace trace cache 有固定容量上限，已知默认上限是 `4096` 条。这意味着：

- `20`
- `200`
- `1000`
- `4096`

这类回归一般没问题；如果你在第一次读取前堆得更多，可能会看到 cache eviction。

## 10. 功能模块：Kernel Drop 观测（drops）

### 10.1 作用

`drops` 看的是内核层丢包，不是防火墙主动丢包。

区别要分清：

- 防火墙主动丢包
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

清理必须显式带 `--force`：

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

如果返回“kernel drop observability is not available”，更常见的原因是环境或模式不支持，而不是产品 bug。

## 11. 功能模块：连接跟踪（conntrack）

### 11.1 作用

Conntrack 用于查看和清理实例级连接表，适合：

- 确认连接是否已建立
- 确认是否进入 fast-path
- 清空连接表做回归

### 11.2 常见命令

```bash
ariactl --tap eth0 conntrack list
ariactl --tap eth0 conntrack flush
```

输出包括：

- 源地址
- 目的地址
- 源端口
- 目的端口
- 协议
- 状态
- 包计数
- 字节计数

## 12. 功能模块：监控与统计（stats / metrics）

### 12.1 `stats` 概览

不带任何子选项时：

```bash
ariactl --tap eth0 stats
```

输出的是实例级概览，包括：

- group 数量
- policy 数量
- QoS 规则数量
- mirror 规则数量
- conntrack IPv4 / IPv6 条目数

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

这些标志可以组合：

```bash
ariactl --tap eth0 stats --rules --qos --mirror
```

### 12.3 统计口径的常见误区

做统计验证时，优先检查：

- 流量方向是否和规则方向一致
- `policy` 是否绑定到了正确的 group 组合
- `qos egress` 是否绑到了目标组
- `mirror` 是否配置了正确的方向和 group

### 12.4 `/metrics`

`GET /metrics` 会导出 Prometheus 指标，包含：

- group / policy / qos / mirror 计数
- rule/group/qos/mirror/drop 统计
- kernel drop 观测指标
- trace backend 运行时指标

trace backend 相关最值得看的是：

- `aria_trace_backend_info`
- `aria_trace_runtime_registered_taps`
- `aria_trace_runtime_active_consumers`
- `aria_trace_runtime_consumer_failures_total`
- `aria_trace_runtime_consumer_restarts_total`
- `aria_trace_runtime_last_error`

## 13. 功能模块：SSL 可观测性（ssl）

### 13.1 作用

SSL 模块提供三类数据：

- TLS 握手
- SSL HTTP 请求/响应
- SSL 错误

### 13.2 最重要的语义：它是 host-global

SSL 不是 per-instance 数据，而是 host-global。

也就是说：

- `ariactl --tap eth0 ssl list`
  可以执行
- 但 `--tap` 实际会被忽略
- CLI 会明确提示这一点

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

### 13.4 输出字段

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

运行时配置支持热切换，无需重启 agent。

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

### 14.3 SSL 配置的特殊性

`ssl` 配置不是普通实例配置，而是全局配置：

- `config set ssl on/off` 会走专门的全局 SSL 配置接口
- 即使带了 `--tap`，也只影响提示，不改变作用域

## 15. REST API 概览

所有接口前缀都是 `/api/v1/`。

主要分组：

- 健康与实例
  - `GET /health`
  - `GET /instances`
- system
  - `POST /system/start`
  - `POST /system/stop`
- 实例作用域对象
  - `/{instance}/groups`
  - `/{instance}/policies`
  - `/{instance}/qos`
  - `/{instance}/mirror`
  - `/{instance}/conntrack`
  - `/{instance}/config`
  - `/{instance}/stats/...`
  - `/{instance}/tcprt`
  - `/{instance}/trace`
- 全局功能
  - `/tcprt/query`
  - `/tcprt/filter`
  - `/chains`
  - `/ssl`
  - `/ssl/http`
  - `/ssl/config`
  - `/ssl/errors`
  - `/stats/kernel_drops`

如果你更习惯 CLI，可以直接把 CLI 理解成这些 API 的薄封装。

## 16. 运维、恢复与排障

### 16.1 常用运行命令

```bash
ariactl health
ariactl instances
ariactl system start --iface eth0
ariactl system stop
```

### 16.2 `diagnose`

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

### 16.3 推荐排障路径

建议按这个顺序看：

1. `ariactl health`
2. `ariactl instances`
3. `ariactl --tap <tap> config show`
4. `ariactl --tap <tap> stats`
5. `ariactl --tap <tap> conntrack list`
6. `ariactl trace start ...`
7. `ariactl tcprt flow ...`
8. 必要时看 `/metrics`

### 16.4 生命周期相关注意事项

实际运维里最值得关注的几个点：

- `system` 和 managed 的清理语义不同
- QoS shaping 会涉及 root `fq` qdisc 生命周期
- preexisting `fq` 不应被误删
- crash recovery 需要同时恢复 XDP、TC link 和 `fq`

## 17. 测试与回归

仓库现在提供两类可直接远端执行的回归脚本：

```bash
python3 tools/runtime_lifecycle_regression.py --host root@<host>
python3 tools/trace_perf_regression.py --host root@<host> --packet-counts 20,200 --rounds 2
```

覆盖范围：

- system stop + vanished iface
- preexisting fq
- managed crash recovery -> DelLink
- trace flush/start/first-read

## 18. 已知限制

### 18.1 trace cache 上限

当前 userspace trace cache 有固定容量上限，已知默认值是 `4096`。因此：

- `5000` 级别回归如果在第一次读取前积压太多，可能触发 eviction
- 这反映的是当前容量边界，不是未知 bug

### 18.2 4.18 回归待补

当前主要闭环验证在 `6.8` 上完成；`4.18` 环境仍然需要补回归。

### 18.3 SSL 是 host-global

这是产品语义，不是 bug：

- SSL 数据不是实例私有
- `--tap` 对 SSL 只起提示作用

## 19. 附录：命令速查

### 19.1 运行类

```bash
ariactl health
ariactl instances
ariactl system start --iface eth0
ariactl system stop
```

### 19.2 ACL / group / policy

```bash
ariactl --tap eth0 group add --name web --cidr 10.0.0.0/8
ariactl --tap eth0 group list
ariactl --tap eth0 group with-stats

ariactl --tap eth0 policy add --src-group web --dst-group db --proto tcp --ports 3306 --action accept --direction ingress
ariactl --tap eth0 policy list
ariactl --tap eth0 policy with-stats
ariactl --tap eth0 policy delete --src-group web --dst-group db --proto tcp --direction ingress
```

### 19.3 QoS / mirror

```bash
ariactl --tap eth0 qos add --group db --direction egress --rate 100mbps --mode shaping
ariactl --tap eth0 qos list
ariactl --tap eth0 qos with-stats

ariactl --tap eth0 mirror add --src-group web --dst-group db --proto tcp --direction both --target tapmirror
ariactl --tap eth0 mirror list
ariactl --tap eth0 mirror with-stats
```

### 19.4 TCP-RT / trace / chain

```bash
ariactl tcprt top --by art --top 10
ariactl tcprt flow --dst 10.0.0.5 --dport 3306
ariactl tcprt flow --dst 10.0.0.5 --dport 3306 --chain prod-chain

ariactl trace start --tap eth0 --dst 10.0.0.5 --proto tcp --dport 3306 --wait 5
ariactl trace start --chain prod-chain --dst 10.0.0.5 --dport 3306 --wait 5

ariactl chain apply --file chain.json
ariactl chain list
ariactl chain show prod-chain
ariactl chain delete prod-chain
```

### 19.5 conntrack / drops / stats / ssl / config

```bash
ariactl --tap eth0 conntrack list
ariactl --tap eth0 conntrack flush

ariactl drops list --top 50
ariactl --tap eth0 drops flush --force

ariactl --tap eth0 stats --rules --qos --mirror
ariactl ssl status
ariactl ssl list --top 100
ariactl --tap eth0 config show
```

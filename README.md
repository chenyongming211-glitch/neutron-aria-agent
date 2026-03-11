# Aria Firewall

基于 eBPF/XDP 的高性能防火墙，支持 LPM 前缀树进行 CIDR 匹配的 IP 组和基于端口位图的策略规则。

## 项目优点

### 1. 超高性能
- **XDP 架构**：在网络栈的最早阶段处理数据包，无需经过传统网络栈的层层转发
- **内核旁路**：数据包直接在网卡驱动层处理，避免内核网络协议栈开销
- **零拷贝**：eBPF 程序直接操作数据包内存，无额外复制

### 2. 灵活性
- **CO-RE 技术**：一次编译，处处运行。eBPF 程序内嵌 BTF 信息，可在支持 BTF 的不同内核版本间无缝迁移
- **动态加载**：无需重新编译内核或重启系统
- **热更新**：可在不中断服务的情况下更新防火墙规则

### 3. 资源占用低
- **无额外守护进程**：eBPF 程序运行在内核空间，无需用户空间常驻进程
- **内存高效**：LPM 前缀树和端口位图都是高度优化的数据结构

### 4. 安全性
- **沙箱执行**：eBPF 程序在受限环境中运行，无法访问任意内核内存
- **_verifier 验证**：所有 eBPF 代码必须通过内核 verifier 检查，确保安全

## 功能特性

- **XDP 加速**：在网络数据到达时最早处理
- **LPM 前缀树**：高效的最长前缀匹配，支持 CIDR 格式的 IP 组
- **端口位图**：紧凑的端口策略存储，支持引用计数优化
- **状态持久化**：服务重启后自动恢复规则状态
- **IPv6 支持**：完整的 IPv6 扩展头处理
- **CO-RE**：支持多个内核版本

## 系统要求

- Linux 内核 5.8+（推荐 5.16+ 以获得完整支持）
- 内核需支持 BTF（BPF Type Format）
  - Ubuntu 22.04+、Fedora 35+、RHEL 9+ 默认支持
  - 验证命令：`ls /sys/kernel/btf/vmlinux`
- libbpf 开发库

## 快速开始

### 编译

```bash
# 安装依赖
sudo apt-get install llvm-dev clang libelf-dev libbpf-dev rust

# 编译
cargo build --release
```

### 使用方法

```bash
# 启动防火墙（指定网卡）
sudo ./target/release/firewall-ctl system start --iface eth0

# 添加 IP 组
sudo ./target/release/firewall-ctl group add --name web-servers --cidr 10.0.0.0/8
sudo ./target/release/firewall-ctl group add --name db-servers --cidr 192.168.1.0/24

# 添加规则
sudo ./target/release/firewall-ctl rule add \
  --src-group web-servers \
  --dst-group db-servers \
  --proto tcp \
  --ports 3306 \
  --action accept

# 允许 HTTP/HTTPS
sudo ./target/release/firewall-ctl rule add \
  --src-group any \
  --dst-group web-servers \
  --proto tcp \
  --ports 80,443 \
  --action accept

# 查看规则
sudo ./target/release/firewall-ctl rule list

# 查看 IP 组
sudo ./target/release/firewall-ctl group list

# 删除规则
sudo ./target/release/firewall-ctl rule remove \
  --src-group web-servers \
  --dst-group db-servers \
  --proto tcp

# 停止防火墙
sudo ./target/release/firewall-ctl system stop
```

### 命令说明

| 命令 | 说明 |
|------|------|
| `system start` | 启动防火墙，加载 eBPF 程序到指定网卡 |
| `system stop` | 停止防火墙，卸载 eBPF 程序 |
| `group add` | 添加 IP 组，支持 CIDR 格式 |
| `group remove` | 删除 IP 组 |
| `rule add` | 添加防火墙规则 |
| `rule remove` | 删除防火墙规则 |
| `rule list` | 列出所有规则 |
| `group list` | 列出所有 IP 组 |

### 参数说明

- `--src-group`：源 IP 组名称（`any` 表示任意地址）
- `--dst-group`：目标 IP 组名称
- `--proto`：协议（`tcp`、`udp`、`icmp`、`any`）
- `--ports`：端口（支持单个端口、逗号分隔多端口、范围如 `80-443`）
- `--action`：动作（`accept` 允许，`drop` 拒绝）

## 技术架构

```
┌─────────────────────────────────────────────────────────────┐
│                      firewall-ctl                           │
│                    (用户空间控制程序)                         │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                   libebpf_firewall.so                      │
│                      (eBPF 程序)                            │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │  LPM 前缀树  │  │  端口位图    │  │     数据包解析器    │ │
│  │  (IP 组)    │  │  (策略规则)  │  │  (IPv4/IPv6/TCP)  │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                        XDP 钩子                             │
│                     (内核数据通路)                           │
└─────────────────────────────────────────────────────────────┘
```

### 核心组件

1. **LPM 前缀树**：使用 Longest Prefix Match 算法高效匹配 CIDR 格式的 IP 地址
2. **端口位图**：紧凑存储端口策略，支持引用计数共享相同端口集的规则
3. **数据包解析器**：支持 IPv4、IPv6、TCP、UDP 协议解析，以及 IPv6 扩展头

## 下载预编译版本

从 GitHub Actions 下载编译好的二进制文件：
- `libebpf_firewall.so` - eBPF 程序（已启用 CO-RE）
- `firewall-ctl` - 控制程序

## 开发相关

### GitHub Actions 自动构建

项目配置了 GitHub Actions，在每次代码提交后自动编译：
- 编译 eBPF 程序（CO-RE 特性）
- 编译用户空间控制程序
- 产物可运行于支持 BTF 的 Ubuntu 22.04+ 和 24.04+

### 项目结构

```
aria-firewall/
├── ebpf/                 # eBPF 程序代码
│   └── src/
│       ├── lib.rs        # eBPF 程序入口
│       ├── parser.rs     # 数据包解析
│       ├── maps.rs       # eBPF maps 定义
│       └── common.rs     # 公共定义
├── user/                 # 用户空间控制程序
│   └── src/
│       ├── main.rs       # CLI 入口
│       ├── manager.rs    # eBPF 管理
│       └── state.rs      # 状态管理
└── Cargo.toml           # Workspace 配置
```

## 许可证

MIT

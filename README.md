# Aria Firewall

A high-performance eBPF/XDP firewall with LPM trie for CIDR-based IP matching and port bitmap for policy rules.

## Features

- **XDP (Express Data Path)**: Process packets at the earliest possible point in the network stack
- **LPM Trie**: Efficient longest prefix matching for CIDR-based IP groups
- **Port Bitmap**: Compact port policy storage with reference counting
- **State Persistence**: Automatic state replay on restart
- **CO-RE**: Compile Once Run Everywhere - supports multiple kernel versions

## Requirements

- Linux kernel with BTF support (Ubuntu 22.04+, Fedora 35+)
- `libbpf` development libraries

## Quick Start

### Build

```bash
# Install dependencies
sudo apt-get install llvm-dev clang libelf-dev libbpf-dev

# Build
cargo build --release
```

### Usage

```bash
# Start firewall on interface
sudo ./target/release/firewall-ctl system start --iface eth0

# Add IP group
sudo ./target/release/firewall-ctl group add --name web-servers --cidr 10.0.0.0/8

# Add rule
sudo ./target/release/firewall-ctl rule add --src-group web-servers --dst-group any --proto tcp --ports 80,443 --action accept

# List rules
sudo ./target/release/firewall-ctl rule list

# Stop firewall
sudo ./target/release/firewall-ctl system stop
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     firewall-ctl                            │
│                  (User Space Control)                       │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    libebpf_firewall.so                      │
│                      (eBPF Program)                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐ │
│  │   LPM Trie  │  │ Port Bitmap │  │    Packet Parser    │ │
│  │ (IP Groups) │  │  (Policies) │  │   (IPv4/IPv6/TCP)   │ │
│  └─────────────┘  └─────────────┘  └─────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                        XDP Hook                             │
│                   (Kernel Data Path)                        │
└─────────────────────────────────────────────────────────────┘
```

## Download Pre-built Binaries

Download from GitHub Actions artifacts:
- `libebpf_firewall.so` - eBPF program (CO-RE enabled)
- `firewall-ctl` - Control binary

## License

MIT

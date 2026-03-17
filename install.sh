#!/bin/bash
set -e

echo "Installing Aria Firewall..."

INSTALL_DIR="/usr/local/bin"
EBPF_LIB_DIR="/usr/lib"
STATE_DIR="/var/lib/aria-firewall"
CONFIG_DIR="/etc/aria-firewall"
AGENT_STATE_DIR="/var/lib/aria-agent"
AGENT_CONFIG_DIR="/etc/aria-agent"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo)"
    exit 1
fi

# Create directories
mkdir -p "$STATE_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$AGENT_STATE_DIR"
mkdir -p "$AGENT_CONFIG_DIR"

# Install binary
echo "Installing ariactl to $INSTALL_DIR..."
cp target/x86_64-unknown-linux-gnu/release/ariactl "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/ariactl"

# Install agent binary (if built)
if [ -f target/x86_64-unknown-linux-gnu/release/aria-agent ]; then
    echo "Installing aria-agent to $INSTALL_DIR..."
    cp target/x86_64-unknown-linux-gnu/release/aria-agent "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/aria-agent"
fi

# Install eBPF library
echo "Installing libebpf_firewall.so to $EBPF_LIB_DIR..."
cp target/x86_64-unknown-linux-gnu/release/libebpf_firewall.so "$EBPF_LIB_DIR/"

# Install systemd services
echo "Installing systemd services..."
cp aria-firewall.service /etc/systemd/system/
cp aria-agent.service /etc/systemd/system/

# Install agent config template (don't overwrite existing)
if [ ! -f "$AGENT_CONFIG_DIR/config.toml" ]; then
    echo "Installing aria-agent config template..."
    cp config/aria-agent.toml "$AGENT_CONFIG_DIR/config.toml"
fi

# Reload systemd
systemctl daemon-reload

echo ""
echo "Installation complete!"
echo ""
echo "=== Single-interface mode (ariactl) ==="
echo "  sudo systemctl enable aria-firewall"
echo "  sudo systemctl start aria-firewall"
echo ""
echo "=== Multi-tap mode (aria-agent) ==="
echo "  Edit /etc/aria-agent/config.toml"
echo "  sudo systemctl enable aria-agent"
echo "  sudo systemctl start aria-agent"
echo ""
echo "To check status:"
echo "  sudo systemctl status aria-firewall"
echo "  sudo systemctl status aria-agent"
echo ""
echo "To view logs:"
echo "  sudo journalctl -u aria-firewall -f"
echo "  sudo journalctl -u aria-agent -f"

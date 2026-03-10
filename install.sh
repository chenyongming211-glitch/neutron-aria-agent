#!/bin/bash
set -e

echo "Installing Aria Firewall..."

INSTALL_DIR="/usr/local/bin"
EBPF_LIB_DIR="/usr/lib"
STATE_DIR="/var/lib/aria-firewall"
CONFIG_DIR="/etc/aria-firewall"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo)"
    exit 1
fi

# Create directories
mkdir -p "$STATE_DIR"
mkdir -p "$CONFIG_DIR"

# Install binary
echo "Installing firewall-ctl to $INSTALL_DIR..."
cp target/x86_64-unknown-linux-gnu/release/firewall-ctl "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/firewall-ctl"

# Install eBPF library
echo "Installing libebpf_firewall.so to $EBPF_LIB_DIR..."
cp target/x86_64-unknown-linux-gnu/release/libebpf_firewall.so "$EBPF_LIB_DIR/"

# Install systemd service
echo "Installing systemd service..."
cp aria-firewall.service /etc/systemd/system/

# Reload systemd
systemctl daemon-reload

echo ""
echo "Installation complete!"
echo ""
echo "To enable and start the firewall:"
echo "  sudo systemctl enable aria-firewall"
echo "  sudo systemctl start aria-firewall"
echo ""
echo "To check status:"
echo "  sudo systemctl status aria-firewall"
echo ""
echo "To view logs:"
echo "  sudo journalctl -u aria-firewall -f"

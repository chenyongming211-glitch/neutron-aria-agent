#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TMP_DIR=""

INSTALL_BIN_DIR="/usr/local/bin"
INSTALL_LIB_DIR="/usr/local/lib"
CONFIG_DIR="/etc/aria-agent"
CONFIG_FILE="$CONFIG_DIR/config.toml"
STATE_DIR="/var/lib/aria-agent"
LOG_DIR="/var/log/aria-agent"
LOG_FILE="$LOG_DIR/aria-agent.log"
LOGROTATE_FILE="/etc/logrotate.d/aria-agent"
PIN_ROOT="/sys/fs/bpf"
PIN_DIR="$PIN_ROOT/aria"
SYSTEMD_UNIT="/etc/systemd/system/aria-agent.service"

ZIP_PATH=""
FORCE_CONFIG=0
NO_START=0

cleanup() {
    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

log() {
    printf '[INFO] %s\n' "$*"
}

warn() {
    printf '[WARN] %s\n' "$*" >&2
}

die() {
    printf '[ERROR] %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Aria Firewall 一键安装/更新脚本

用法:
  sudo ./install.sh
  sudo ./install.sh --zip /path/to/firewall-binaries-x86_64.zip
  sudo ./install.sh --force-config
  sudo ./install.sh --no-start

说明:
  - 默认会在脚本同目录自动查找 firewall-binaries*.zip
  - 默认保留已有 /etc/aria-agent/config.toml
  - 默认会安装/更新 aria-agent、ariactl、libebpf_firewall.so、
    libebpf_firewall_perf.so，并重启 aria-agent 服务

选项:
  --zip PATH         指定 release zip 路径
  --force-config     覆盖生成默认 /etc/aria-agent/config.toml
  --no-start         只安装，不启动/重启服务
  -h, --help         显示帮助
EOF
}

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "缺少命令: $1"
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --zip)
                [[ $# -ge 2 ]] || die "--zip 需要一个路径参数"
                ZIP_PATH="$2"
                shift 2
                ;;
            --force-config)
                FORCE_CONFIG=1
                shift
                ;;
            --no-start)
                NO_START=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "未知参数: $1"
                ;;
        esac
    done
}

find_zip() {
    if [[ -n "$ZIP_PATH" ]]; then
        [[ -f "$ZIP_PATH" ]] || die "zip 不存在: $ZIP_PATH"
        return
    fi

    local -a candidates=()
    local candidate

    shopt -s nullglob
    for candidate in "$SCRIPT_DIR"/firewall-binaries*.zip; do
        candidates+=("$candidate")
    done
    shopt -u nullglob

    if [[ ${#candidates[@]} -eq 1 ]]; then
        ZIP_PATH="${candidates[0]}"
        return
    fi

    if [[ ${#candidates[@]} -gt 1 ]]; then
        die "脚本目录下发现多个 zip，请显式传入 --zip: $SCRIPT_DIR"
    fi

    die "脚本目录下未找到 firewall-binaries*.zip，请把 zip 放到脚本同目录，或使用 --zip 指定"
}

check_root() {
    [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "请使用 root 运行，例如: sudo ./install.sh"
}

parse_kernel_version() {
    local rel="$1"
    if [[ "$rel" =~ ^([0-9]+)\.([0-9]+) ]]; then
        printf '%s %s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
    else
        return 1
    fi
}

kernel_ge() {
    local cur_major="$1"
    local cur_minor="$2"
    local req_major="$3"
    local req_minor="$4"
    if (( cur_major > req_major )); then
        return 0
    fi
    if (( cur_major < req_major )); then
        return 1
    fi
    (( cur_minor >= req_minor ))
}

check_environment() {
    require_cmd unzip
    require_cmd install
    require_cmd sha256sum
    require_cmd uname
    require_cmd mountpoint
    require_cmd mount

    local kernel_release
    kernel_release="$(uname -r)"
    local major minor
    read -r major minor < <(parse_kernel_version "$kernel_release") \
        || die "无法解析内核版本: $kernel_release"

    if ! kernel_ge "$major" "$minor" 4 18; then
        die "当前内核 $kernel_release 低于最低要求 4.18"
    fi

    if kernel_ge "$major" "$minor" 5 8; then
        log "检测到内核 $kernel_release，支持 perf trace 和 EDT shaping"
    else
        warn "当前内核 $kernel_release 低于 5.8：QoS shaping 会退化，XDP link pin 能力受限"
    fi

    if [[ ! -e /sys/kernel/btf/vmlinux ]]; then
        warn "未检测到 /sys/kernel/btf/vmlinux，agent 可能无法正常加载 eBPF"
    else
        log "检测到 BTF: /sys/kernel/btf/vmlinux"
    fi

    mkdir -p "$PIN_ROOT"
    if ! mountpoint -q "$PIN_ROOT"; then
        log "挂载 bpffs 到 $PIN_ROOT"
        mount -t bpf bpffs "$PIN_ROOT"
    fi

    mkdir -p "$PIN_DIR"
}

unpack_release() {
    TMP_DIR="$(mktemp -d /tmp/aria-install.XXXXXX)"
    log "解压 release 包: $ZIP_PATH"
    unzip -q "$ZIP_PATH" -d "$TMP_DIR"

    local file
    for file in aria-agent ariactl libebpf_firewall.so libebpf_firewall_perf.so; do
        [[ -f "$TMP_DIR/$file" ]] || die "release 包缺少文件: $file"
    done
}

backup_existing() {
    local backup_dir=""
    local ts
    ts="$(date +%Y%m%d-%H%M%S)"

    local -a paths=(
        "$INSTALL_BIN_DIR/aria-agent"
        "$INSTALL_BIN_DIR/ariactl"
        "$INSTALL_LIB_DIR/libebpf_firewall.so"
        "$INSTALL_LIB_DIR/libebpf_firewall_perf.so"
        "$SYSTEMD_UNIT"
        "$CONFIG_FILE"
        "$LOGROTATE_FILE"
    )

    local path
    for path in "${paths[@]}"; do
        if [[ -e "$path" ]]; then
            backup_dir="$STATE_DIR/install-backups/$ts"
            mkdir -p "$backup_dir"
            break
        fi
    done

    [[ -n "$backup_dir" ]] || return 0

    log "备份当前安装到 $backup_dir"
    for path in "${paths[@]}"; do
        if [[ -e "$path" ]]; then
            cp -a "$path" "$backup_dir/"
        fi
    done
}

write_systemd_unit() {
    cat >"$SYSTEMD_UNIT" <<'EOF'
[Unit]
Description=Aria Firewall Agent (multi-tap XDP firewall daemon)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/aria-agent --config /etc/aria-agent/config.toml
Restart=on-failure
RestartSec=5
User=root
Group=root
LimitMEMLOCK=infinity
ProtectSystem=strict
ReadWritePaths=/sys/fs/bpf /var/lib/aria-agent /var/log
ProtectHome=yes

[Install]
WantedBy=multi-user.target
EOF
}

write_logrotate_config() {
    cat >"$LOGROTATE_FILE" <<EOF
$LOG_FILE {
    daily
    rotate 14
    missingok
    notifempty
    compress
    delaycompress
    copytruncate
    create 0640 root root
}
EOF
}

write_default_config() {
    cat >"$CONFIG_FILE" <<'EOF'
ebpf_path = "/usr/local/lib/libebpf_firewall.so"
trace_backend = "auto"
trace_auto_allow_ringbuf = false
pin_path = "/sys/fs/bpf/aria"
state_path = "/var/lib/aria-agent"
iface_pattern = "^(eth|tap)"
max_port_policies = 16384
listen_addr = "127.0.0.1:8080"
log_format = "text"
log_filter = "info"
log_file_path = "/var/log/aria-agent/aria-agent.log"
EOF
}

install_files() {
    mkdir -p "$INSTALL_BIN_DIR" "$INSTALL_LIB_DIR" "$CONFIG_DIR" "$STATE_DIR" "$LOG_DIR"
    chmod 0755 "$LOG_DIR"

    log "安装 aria-agent 到 $INSTALL_BIN_DIR"
    install -m 0755 "$TMP_DIR/aria-agent" "$INSTALL_BIN_DIR/aria-agent"

    log "安装 ariactl 到 $INSTALL_BIN_DIR"
    install -m 0755 "$TMP_DIR/ariactl" "$INSTALL_BIN_DIR/ariactl"

    log "安装 libebpf_firewall.so 到 $INSTALL_LIB_DIR"
    install -m 0644 "$TMP_DIR/libebpf_firewall.so" "$INSTALL_LIB_DIR/libebpf_firewall.so"

    log "安装 libebpf_firewall_perf.so 到 $INSTALL_LIB_DIR"
    install -m 0644 "$TMP_DIR/libebpf_firewall_perf.so" "$INSTALL_LIB_DIR/libebpf_firewall_perf.so"

    log "写入/更新 systemd 单元: $SYSTEMD_UNIT"
    write_systemd_unit

    log "写入/更新 logrotate 配置: $LOGROTATE_FILE"
    write_logrotate_config

    if [[ ! -f "$CONFIG_FILE" || "$FORCE_CONFIG" -eq 1 ]]; then
        log "写入默认配置: $CONFIG_FILE"
        write_default_config
    else
        log "保留现有配置: $CONFIG_FILE"
    fi
}

show_installed_hashes() {
    log "安装后的文件校验:"
    sha256sum \
        "$INSTALL_BIN_DIR/aria-agent" \
        "$INSTALL_BIN_DIR/ariactl" \
        "$INSTALL_LIB_DIR/libebpf_firewall.so" \
        "$INSTALL_LIB_DIR/libebpf_firewall_perf.so" | sed 's/^/  /'
}

restart_service() {
    if ! command -v systemctl >/dev/null 2>&1; then
        warn "系统没有 systemctl，已完成文件安装，请手动启动: /usr/local/bin/aria-agent --config $CONFIG_FILE"
        return 0
    fi

    log "重新加载 systemd 配置"
    systemctl daemon-reload

    log "启用 aria-agent.service"
    systemctl enable aria-agent.service >/dev/null

    if [[ "$NO_START" -eq 1 ]]; then
        warn "按 --no-start 跳过 aria-agent 启动/重启"
        return 0
    fi

    log "重启 aria-agent.service"
    if ! systemctl restart aria-agent.service; then
        warn "aria-agent 启动失败，最近日志如下:"
        journalctl -u aria-agent.service -n 50 --no-pager || true
        exit 1
    fi

    local attempt
    for attempt in {1..15}; do
        if "$INSTALL_BIN_DIR/ariactl" health >/dev/null 2>&1; then
            log "aria-agent 已启动并通过健康检查"
            return 0
        fi
        sleep 1
    done

    warn "aria-agent 服务已启动，但健康检查未在超时时间内通过"
    systemctl --no-pager --full status aria-agent.service || true
    exit 1
}

main() {
    parse_args "$@"
    check_root
    find_zip
    check_environment
    unpack_release
    backup_existing
    install_files
    show_installed_hashes
    restart_service

    log "安装/更新完成"
    printf '\n'
    printf '下一步建议:\n'
    printf '  1. 检查服务状态: systemctl status aria-agent --no-pager\n'
    printf '  2. 检查健康状态: ariactl health\n'
    printf '  3. 查看 journald 日志: journalctl -u aria-agent -n 50 --no-pager\n'
    printf '  4. 查看文件日志: tail -n 50 %s\n' "$LOG_FILE"
    printf '  5. 如需首次部署，确认 /etc/aria-agent/config.toml 中的 iface_pattern\n'
    printf '\n'
}

main "$@"

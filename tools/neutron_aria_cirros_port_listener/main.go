package main

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	defaultUser              = "cirros"
	defaultPassword          = "gocubsgo"
	defaultSSHPort           = "22"
	defaultGuestListenerPath = "/usr/local/libexec/neutron_aria_cirros_guest_listener"
	remoteGuestListenerPath  = "/tmp/neutron_aria_cirros_guest_listener"
	remoteStateDir           = "/tmp/neutron_aria_cirros_port_listener"
)

type endpoint struct {
	proto string
	port  int
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		usage()
		return nil
	}
	if len(args) != 2 && len(args) != 3 {
		usage()
		return errors.New("invalid arguments")
	}

	host := args[0]
	if net.ParseIP(host) == nil {
		return fmt.Errorf("invalid IP address: %s", host)
	}

	action := ""
	var ep endpoint
	if len(args) == 2 {
		if args[1] != "list" {
			usage()
			return errors.New("two-argument form only supports: <ip> list")
		}
		action = "list"
	} else {
		var err error
		ep, err = parseEndpoint(args[1])
		if err != nil {
			return err
		}
		action = args[2]
		if action != "start" && action != "stop" {
			usage()
			return errors.New("action must be start or stop")
		}
	}

	client, err := dialGuest(host)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := uploadGuestListener(client); err != nil {
		return err
	}

	var command string
	if action == "list" {
		command = remoteCommand("list", "", "")
	} else {
		command = remoteCommand(action, ep.proto, strconv.Itoa(ep.port))
	}

	output, err := runSSH(client, command, nil)
	if strings.TrimSpace(output) != "" {
		fmt.Print(output)
		if !strings.HasSuffix(output, "\n") {
			fmt.Println()
		}
	}
	return err
}

func usage() {
	fmt.Print(`Usage:
  neutron_aria_cirros_port_listener <ip> list
  neutron_aria_cirros_port_listener <ip> <tcp:8080> start
  neutron_aria_cirros_port_listener <ip> <udp:1080> stop

Defaults:
  user/password: cirros / gocubsgo
  env override:  CIRROS_USER, CIRROS_PASSWORD, CIRROS_SSH_PORT, CIRROS_KEY_FILE, CIRROS_GUEST_LISTENER

Examples:
  neutron_aria_cirros_port_listener 192.0.2.10 list
  neutron_aria_cirros_port_listener 192.0.2.10 tcp:8080 start
  neutron_aria_cirros_port_listener 192.0.2.10 udp:1080 stop
`)
}

func parseEndpoint(raw string) (endpoint, error) {
	parts := strings.Split(raw, ":")
	if len(parts) != 2 {
		return endpoint{}, fmt.Errorf("endpoint must look like tcp:8080 or udp:1080")
	}
	proto := strings.ToLower(strings.TrimSpace(parts[0]))
	if proto != "tcp" && proto != "udp" {
		return endpoint{}, fmt.Errorf("protocol must be tcp or udp")
	}
	port, err := strconv.Atoi(parts[1])
	if err != nil || port < 1 || port > 65535 {
		return endpoint{}, fmt.Errorf("port must be 1..65535")
	}
	return endpoint{proto: proto, port: port}, nil
}

func dialGuest(host string) (*ssh.Client, error) {
	user := getenv("CIRROS_USER", defaultUser)
	password := getenv("CIRROS_PASSWORD", defaultPassword)
	port := getenv("CIRROS_SSH_PORT", defaultSSHPort)
	keyFile := os.Getenv("CIRROS_KEY_FILE")

	authMethods := make([]ssh.AuthMethod, 0, 3)
	authDescription := make([]string, 0, 3)
	if keyFile != "" {
		method, err := privateKeyAuth(keyFile, os.Getenv("CIRROS_KEY_PASSPHRASE"))
		if err != nil {
			return nil, err
		}
		authMethods = append(authMethods, method)
		authDescription = append(authDescription, "key:"+keyFile)
	}
	if password != "" {
		authMethods = append(authMethods,
			ssh.Password(password),
			ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) ([]string, error) {
				answers := make([]string, len(questions))
				for i := range answers {
					answers[i] = password
				}
				return answers, nil
			}),
		)
		if os.Getenv("CIRROS_PASSWORD") != "" {
			authDescription = append(authDescription, "password:CIRROS_PASSWORD")
		} else {
			authDescription = append(authDescription, "password:default-gocubsgo")
		}
	}
	if len(authMethods) == 0 {
		return nil, errors.New("no auth method configured; set CIRROS_PASSWORD or CIRROS_KEY_FILE")
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	client, err := ssh.Dial("tcp", net.JoinHostPort(host, port), config)
	if err != nil {
		return nil, fmt.Errorf(
			"ssh login failed for %s@%s:%s using %s: %w; "+
				"check the VM password/key, or create the CirrOS test VM with password SSH enabled",
			user, host, port, strings.Join(authDescription, ","), err,
		)
	}
	return client, nil
}

func privateKeyAuth(path, passphrase string) (ssh.AuthMethod, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CIRROS_KEY_FILE %s: %w", path, err)
	}
	var signer ssh.Signer
	if passphrase != "" {
		signer, err = ssh.ParsePrivateKeyWithPassphrase(pemBytes, []byte(passphrase))
	} else {
		signer, err = ssh.ParsePrivateKey(pemBytes)
	}
	if err != nil {
		return nil, fmt.Errorf("parse CIRROS_KEY_FILE %s: %w", path, err)
	}
	return ssh.PublicKeys(signer), nil
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func guestListenerPath() (string, error) {
	candidates := []string{}
	if env := os.Getenv("CIRROS_GUEST_LISTENER"); env != "" {
		candidates = append(candidates, env)
	}
	candidates = append(candidates, defaultGuestListenerPath)
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		candidates = append(candidates,
			filepath.Join(dir, "neutron_aria_cirros_guest_listener"),
			filepath.Join(dir, "..", "libexec", "neutron_aria_cirros_guest_listener"),
		)
	}
	for _, candidate := range candidates {
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("guest listener binary not found; set CIRROS_GUEST_LISTENER or install %s", defaultGuestListenerPath)
}

func uploadGuestListener(client *ssh.Client) error {
	localPath, err := guestListenerPath()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("read guest listener %s: %w", localPath, err)
	}
	remoteUploadPath := fmt.Sprintf("%s.upload.%d", remoteGuestListenerPath, time.Now().UnixNano())
	command := fmt.Sprintf(
		"cat > %s && chmod 700 %s && mv -f %s %s",
		shellQuote(remoteUploadPath),
		shellQuote(remoteUploadPath),
		shellQuote(remoteUploadPath),
		shellQuote(remoteGuestListenerPath),
	)
	_, err = runSSH(client, command, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("upload guest listener: %w", err)
	}
	return nil
}

func remoteCommand(action, proto, port string) string {
	var b strings.Builder
	b.WriteString("set -eu\n")
	b.WriteString("STATE_DIR=" + shellQuote(remoteStateDir) + "\n")
	b.WriteString("GUEST_BIN=" + shellQuote(remoteGuestListenerPath) + "\n")
	b.WriteString(`mkdir -p "$STATE_DIR"

pid_file() { echo "$STATE_DIR/$1_$2.pid"; }
stats_file() { echo "$STATE_DIR/$1_$2.stats"; }
log_file() { echo "$STATE_DIR/$1_$2.log"; }

is_running_pid() {
    _pid="$1"
    [ -n "$_pid" ] || return 1
    kill -0 "$_pid" >/dev/null 2>&1
}

is_running_file() {
    _file="$1"
    [ -f "$_file" ] || return 1
    _pid="$(cat "$_file" 2>/dev/null || true)"
    is_running_pid "$_pid"
}

socket_present() {
    _proto="$1"
    _port="$2"
    _hex="$(printf '%04X' "$_port" 2>/dev/null || true)"
    [ -n "$_hex" ] || return 1
    if [ "$_proto" = "tcp" ]; then
        grep -qi ":$_hex " /proc/net/tcp /proc/net/tcp6 2>/dev/null
    else
        grep -qi ":$_hex " /proc/net/udp /proc/net/udp6 2>/dev/null
    fi
}

socket_inodes() {
    _proto="$1"
    _port="$2"
    _hex="$(printf '%04X' "$_port" 2>/dev/null || true)"
    [ -n "$_hex" ] || return 0
    if [ "$_proto" = "tcp" ]; then
        _files="/proc/net/tcp /proc/net/tcp6"
    else
        _files="/proc/net/udp /proc/net/udp6"
    fi
    for _file in $_files; do
        [ -r "$_file" ] || continue
        awk -v hex=":$_hex" 'tolower($2) ~ tolower(hex) { print $10 }' "$_file" 2>/dev/null || true
    done | sort -u
}

kill_socket_holders() {
    _proto="$1"
    _port="$2"
    if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
        sudo -n sh -s "$_proto" "$_port" <<'ARIA_SOCKET_CLEANUP'
_proto="$1"
_port="$2"
_hex="$(printf '%04X' "$_port" 2>/dev/null || true)"
[ -n "$_hex" ] || exit 0
if [ "$_proto" = "tcp" ]; then
    _files="/proc/net/tcp /proc/net/tcp6"
else
    _files="/proc/net/udp /proc/net/udp6"
fi
for _inode in $(
    for _file in $_files; do
        [ -r "$_file" ] || continue
        awk -v hex=":$_hex" 'tolower($2) ~ tolower(hex) { print $10 }' "$_file" 2>/dev/null || true
    done | sort -u
); do
    case "$_inode" in ''|*[!0-9]*) continue ;; esac
    for _fd in /proc/[0-9]*/fd/*; do
        _target="$(readlink "$_fd" 2>/dev/null || true)"
        [ "$_target" = "socket:[$_inode]" ] || continue
        _pid="${_fd#/proc/}"
        _pid="${_pid%%/*}"
        case "$_pid" in ''|*[!0-9]*) continue ;; esac
        kill "$_pid" >/dev/null 2>&1 || true
        sleep 0.1
        kill -9 "$_pid" >/dev/null 2>&1 || true
        echo "cleaned socket holder proto=$_proto port=$_port pid=$_pid inode=$_inode"
    done
done
ARIA_SOCKET_CLEANUP
        return 0
    fi

    _killed=0
    for _inode in $(socket_inodes "$_proto" "$_port"); do
        case "$_inode" in ''|*[!0-9]*) continue ;; esac
        for _fd in /proc/[0-9]*/fd/*; do
            _target="$(readlink "$_fd" 2>/dev/null || true)"
            [ "$_target" = "socket:[$_inode]" ] || continue
            _pid="${_fd#/proc/}"
            _pid="${_pid%%/*}"
            case "$_pid" in ''|*[!0-9]*) continue ;; esac
            kill "$_pid" >/dev/null 2>&1 || true
            sleep 0.1
            kill -9 "$_pid" >/dev/null 2>&1 || true
            echo "cleaned socket holder proto=$_proto port=$_port pid=$_pid inode=$_inode"
            _killed=1
        done
    done
    return "$_killed"
}

kill_matching_legacy_nc() {
    _proto="$1"
    _port="$2"
    _ps_output="$(ps w 2>/dev/null || ps 2>/dev/null || true)"
    printf '%s\n' "$_ps_output" | while IFS= read -r _line; do
        _pid="$(printf '%s\n' "$_line" | awk '{print $1}')"
        case "$_pid" in ''|PID|*[!0-9]*) continue ;; esac
        printf '%s\n' "$_line" | grep -Eq '(^|[ /])nc([[:space:]]|$)' || continue
        printf '%s\n' "$_line" | grep -Eq -- '(^|[[:space:]])-l([[:space:]]|$)' || continue
        printf '%s\n' "$_line" | grep -Eq -- "(^|[[:space:]])-p[[:space:]]+$_port([[:space:]]|$)" || continue
        if [ "$_proto" = "udp" ]; then
            printf '%s\n' "$_line" | grep -Eq -- '(^|[[:space:]])-u([[:space:]]|$)' || continue
        else
            if printf '%s\n' "$_line" | grep -Eq -- '(^|[[:space:]])-u([[:space:]]|$)'; then
                continue
            fi
        fi
        kill "$_pid" >/dev/null 2>&1 || true
        sleep 0.1
        kill -9 "$_pid" >/dev/null 2>&1 || true
        echo "cleaned legacy nc proto=$_proto port=$_port pid=$_pid"
    done
}

kill_matching_guest() {
    _proto="$1"
    _port="$2"
    _ps_output="$(ps w 2>/dev/null || ps 2>/dev/null || true)"
    printf '%s\n' "$_ps_output" | while IFS= read -r _line; do
        _pid="$(printf '%s\n' "$_line" | awk '{print $1}')"
        case "$_pid" in ''|PID|*[!0-9]*) continue ;; esac
        printf '%s\n' "$_line" | grep -F "$GUEST_BIN serve $_proto $_port " >/dev/null 2>&1 || continue
        kill "$_pid" >/dev/null 2>&1 || true
        sleep 0.1
        kill -9 "$_pid" >/dev/null 2>&1 || true
        echo "cleaned guest listener proto=$_proto port=$_port pid=$_pid"
    done
}

start_one() {
    _proto="$1"
    _port="$2"
    _pid_file="$(pid_file "$_proto" "$_port")"
    if is_running_file "$_pid_file" && socket_present "$_proto" "$_port"; then
        _pid="$(cat "$_pid_file")"
        _stats="$(cat "$(stats_file "$_proto" "$_port")" 2>/dev/null || true)"
        echo "already running proto=$_proto port=$_port pid=$_pid socket=present ${_stats}"
        return
    fi
    stop_one "$_proto" "$_port" >/dev/null 2>&1 || true
    rm -f "$(stats_file "$_proto" "$_port")"
    nohup "$GUEST_BIN" serve "$_proto" "$_port" "$STATE_DIR" >>"$(log_file "$_proto" "$_port")" 2>&1 </dev/null &
    echo "$!" > "$_pid_file"
    sleep 0.5
    if ! is_running_file "$_pid_file"; then
        echo "ERROR: listener process exited proto=$_proto port=$_port; see $(log_file "$_proto" "$_port")" >&2
        rm -f "$_pid_file"
        exit 1
    fi
    if ! socket_present "$_proto" "$_port"; then
        echo "ERROR: listener process is running but socket missing proto=$_proto port=$_port; see $(log_file "$_proto" "$_port")" >&2
        exit 1
    fi
    echo "started proto=$_proto port=$_port pid=$(cat "$_pid_file") socket=present"
}

stop_one() {
    _proto="$1"
    _port="$2"
    _pid_file="$(pid_file "$_proto" "$_port")"
    _stopped=0
    if [ -f "$_pid_file" ]; then
        _pid="$(cat "$_pid_file" 2>/dev/null || true)"
        if is_running_pid "$_pid"; then
            kill "$_pid" >/dev/null 2>&1 || true
            sleep 0.2
            kill -9 "$_pid" >/dev/null 2>&1 || true
            _stopped=1
        fi
    fi
    _extra="$(kill_matching_guest "$_proto" "$_port" || true)"
    if [ -n "$_extra" ]; then printf '%s\n' "$_extra"; _stopped=1; fi
    _extra="$(kill_matching_legacy_nc "$_proto" "$_port" || true)"
    if [ -n "$_extra" ]; then printf '%s\n' "$_extra"; _stopped=1; fi
    _extra="$(kill_socket_holders "$_proto" "$_port" || true)"
    if [ -n "$_extra" ]; then printf '%s\n' "$_extra"; _stopped=1; fi
    rm -f "$_pid_file"
    if [ "$_stopped" -eq 1 ]; then
        echo "stopped proto=$_proto port=$_port"
    else
        echo "not running proto=$_proto port=$_port"
    fi
}

list_all() {
    _found=0
    for f in "$STATE_DIR"/*.pid; do
        [ -e "$f" ] || continue
        _found=1
        _base="$(basename "$f" .pid)"
        _proto="$(echo "$_base" | awk -F_ '{print $1}')"
        _port="$(echo "$_base" | awk -F_ '{print $2}')"
        _socket="missing"
        socket_present "$_proto" "$_port" && _socket="present"
        _stats="$(cat "$(stats_file "$_proto" "$_port")" 2>/dev/null || true)"
        if is_running_file "$f"; then
            echo "managed running proto=$_proto port=$_port pid=$(cat "$f") socket=$_socket ${_stats}"
        else
            echo "managed stale proto=$_proto port=$_port socket=$_socket ${_stats}"
        fi
    done
    [ "$_found" -eq 1 ] || echo "managed none"
    echo "system listeners (best-effort; trust managed socket=present first):"
    if command -v netstat >/dev/null 2>&1; then
        netstat -lntu 2>/dev/null || netstat -an 2>/dev/null | grep -E 'LISTEN|udp' || true
    elif command -v ss >/dev/null 2>&1; then
        ss -lntu || true
    else
        echo "system listener inventory unavailable: netstat/ss not found"
    fi
}

`)
	switch action {
	case "list":
		b.WriteString("list_all\n")
	case "start":
		b.WriteString("start_one " + shellQuote(proto) + " " + shellQuote(port) + "\n")
	case "stop":
		b.WriteString("stop_one " + shellQuote(proto) + " " + shellQuote(port) + "\n")
	}
	return b.String()
}

func runSSH(client *ssh.Client, command string, stdinData *bytes.Reader) (string, error) {
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("new ssh session: %w", err)
	}
	defer session.Close()

	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr
	if stdinData != nil {
		session.Stdin = stdinData
	}
	err = session.Run(command)
	output := stdout.String()
	if stderr.Len() > 0 {
		if output != "" && !strings.HasSuffix(output, "\n") {
			output += "\n"
		}
		output += stderr.String()
	}
	if err != nil {
		return output, fmt.Errorf("remote command failed: %w", err)
	}
	return output, nil
}

func shellQuote(value string) string {
	if value == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

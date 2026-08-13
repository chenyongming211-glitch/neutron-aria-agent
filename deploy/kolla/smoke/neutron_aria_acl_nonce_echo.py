#!/usr/bin/env python
from __future__ import print_function

import os
import signal
import socket
import sys


MAX_NONCE_BYTES = 256
STOP_REQUESTED = False


def usage(message=None):
    if message:
        sys.stderr.write("ERROR: %s\n" % message)
    sys.stderr.write(
        "usage:\n"
        "  neutron_aria_acl_nonce_echo.py serve tcp|udp <bind-ip> <port> <ready-file>\n"
        "  neutron_aria_acl_nonce_echo.py probe tcp|udp <host> <port> <nonce> <timeout-seconds>\n"
    )
    return 64


def parse_protocol(value):
    if value not in ("tcp", "udp"):
        raise ValueError("protocol must be tcp or udp")
    return value


def parse_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError("port must be an integer")
    if port < 1 or port > 65535:
        raise ValueError("port must be in range 1..65535")
    return port


def parse_timeout(value):
    try:
        timeout = float(value)
    except (TypeError, ValueError):
        raise ValueError("timeout must be a number")
    if timeout <= 0 or timeout > 60:
        raise ValueError("timeout must be in range (0, 60]")
    return timeout


def nonce_bytes(value):
    payload = value.encode("utf-8")
    if not payload or len(payload) > MAX_NONCE_BYTES:
        raise ValueError("nonce must encode to 1..256 bytes")
    return payload


def request_stop(_signum, _frame):
    global STOP_REQUESTED
    STOP_REQUESTED = True


def install_signal_handlers():
    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)


def write_ready_file(path, protocol, address, port):
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        raise ValueError("ready-file parent does not exist: %s" % directory)
    temporary = "%s.tmp.%s" % (path, os.getpid())
    handle = open(temporary, "w")
    try:
        handle.write(
            "pid=%s protocol=%s address=%s port=%s\n"
            % (os.getpid(), protocol, address, port)
        )
        handle.flush()
        os.fsync(handle.fileno())
    finally:
        handle.close()
    os.rename(temporary, path)


def remove_ready_file(path):
    try:
        os.unlink(path)
    except OSError:
        pass


def recv_until_eof(conn):
    chunks = []
    total = 0
    while total <= MAX_NONCE_BYTES:
        chunk = conn.recv(MAX_NONCE_BYTES + 1 - total)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    payload = b"".join(chunks)
    if len(payload) > MAX_NONCE_BYTES:
        return b""
    return payload


def serve_tcp(bind_ip, port, ready_file):
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind((bind_ip, port))
        listener.listen(16)
        listener.settimeout(0.5)
        write_ready_file(ready_file, "tcp", bind_ip, port)
        while not STOP_REQUESTED:
            try:
                conn, _peer = listener.accept()
            except socket.timeout:
                continue
            try:
                conn.settimeout(3.0)
                payload = recv_until_eof(conn)
                if payload:
                    conn.sendall(payload)
            except (IOError, OSError, socket.timeout):
                pass
            finally:
                conn.close()
    finally:
        listener.close()
        remove_ready_file(ready_file)


def serve_udp(bind_ip, port, ready_file):
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        listener.bind((bind_ip, port))
        listener.settimeout(0.5)
        write_ready_file(ready_file, "udp", bind_ip, port)
        while not STOP_REQUESTED:
            try:
                payload, peer = listener.recvfrom(MAX_NONCE_BYTES + 1)
            except socket.timeout:
                continue
            if payload and len(payload) <= MAX_NONCE_BYTES:
                try:
                    listener.sendto(payload, peer)
                except (IOError, OSError):
                    pass
    finally:
        listener.close()
        remove_ready_file(ready_file)


def serve(protocol, bind_ip, port, ready_file):
    install_signal_handlers()
    remove_ready_file(ready_file)
    if protocol == "tcp":
        serve_tcp(bind_ip, port, ready_file)
    else:
        serve_udp(bind_ip, port, ready_file)


def recv_exact(conn, size):
    chunks = []
    total = 0
    while total < size:
        chunk = conn.recv(size - total)
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
    return b"".join(chunks)


def probe(protocol, host, port, payload, timeout):
    sock_type = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    conn = socket.socket(socket.AF_INET, sock_type)
    conn.settimeout(timeout)
    try:
        if protocol == "tcp":
            conn.connect((host, port))
            conn.sendall(payload)
            conn.shutdown(socket.SHUT_WR)
            received = recv_exact(conn, len(payload))
        else:
            expected_ip = socket.gethostbyname(host)
            conn.sendto(payload, (host, port))
            received, peer = conn.recvfrom(MAX_NONCE_BYTES + 1)
            if peer[0] != expected_ip:
                return False
        return received == payload
    except (IOError, OSError, socket.timeout):
        return False
    finally:
        conn.close()


def main(argv):
    try:
        if len(argv) == 6 and argv[1] == "serve":
            protocol = parse_protocol(argv[2])
            port = parse_port(argv[4])
            serve(protocol, argv[3], port, argv[5])
            return 0
        if len(argv) == 7 and argv[1] == "probe":
            protocol = parse_protocol(argv[2])
            port = parse_port(argv[4])
            payload = nonce_bytes(argv[5])
            timeout = parse_timeout(argv[6])
            if probe(protocol, argv[3], port, payload, timeout):
                sys.stdout.write(argv[5] + "\n")
                return 0
            return 2
        return usage()
    except (ValueError, socket.error) as error:
        return usage(str(error))


if __name__ == "__main__":
    sys.exit(main(sys.argv))

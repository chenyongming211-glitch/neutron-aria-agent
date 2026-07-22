#!/usr/bin/env python3
"""Guarded stdlib-only IPv4/IPv6 fragment field fixtures.

Shell entrypoints provide namespaces, policy transitions, and cleanup.  This
driver has no shell/eval/SSH adapter and never prints a field PASS result.
"""
import argparse
import base64
import ipaddress
import os
import re
import secrets
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request

ETH_ALL, ETH_IP, ETH_V6, ETH_VLAN = 3, 0x0800, 0x86DD, 0x8100


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def parse_mac(value):
    parts = value.split(":")
    if len(parts) != 6 or any(not re.fullmatch(r"[0-9a-fA-F]{2}", part) for part in parts):
        raise ValueError("invalid MAC: %s" % value)
    return bytes(int(part, 16) for part in parts)


def udp_datagram(source, destination, family, token):
    payload = token.encode("ascii")
    header = struct.pack("!HHHH", 43000, 53, 8 + len(payload), 0)
    if family == 4:
        pseudo = ipaddress.IPv4Address(source).packed + ipaddress.IPv4Address(destination).packed + struct.pack("!BBH", 0, 17, len(header) + len(payload))
    else:
        pseudo = ipaddress.IPv6Address(source).packed + ipaddress.IPv6Address(destination).packed + struct.pack("!I3xB", len(header) + len(payload), 17)
    return header[:6] + struct.pack("!H", checksum(pseudo + header + payload) or 0xffff) + payload


def fragments(source, destination, family, token, ident):
    data, split = udp_datagram(source, destination, family, token), 16
    chunks = (data[:split], data[split:split * 2], data[split * 2:])
    if not chunks[-1]:
        raise ValueError("token must produce three fragments")
    result = []
    for index, body in enumerate(chunks):
        offset = index * split
        if family == 4:
            flags = (0x2000 if index < 2 else 0) | offset // 8
            head = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), ident, flags, 64, 17, 0, ipaddress.IPv4Address(source).packed, ipaddress.IPv4Address(destination).packed)
            packet = head[:10] + struct.pack("!H", checksum(head)) + head[12:] + body
        else:
            frag = struct.pack("!BBHI", 17, 0, (offset // 8 << 3) | (1 if index < 2 else 0), ident)
            packet = struct.pack("!IHBB16s16s", 0x60000000, len(frag) + len(body), 44, 64, ipaddress.IPv6Address(source).packed, ipaddress.IPv6Address(destination).packed) + frag + body
        result.append(packet)
    return result


def ethernet(payload, source_mac, destination_mac, family, vlan):
    kind = ETH_IP if family == 4 else ETH_V6
    prefix = parse_mac(destination_mac) + parse_mac(source_mac)
    return prefix + (struct.pack("!HHH", ETH_VLAN, vlan, kind) if vlan else struct.pack("!H", kind)) + payload


def metric_series(text):
    values = {}
    for line in text.splitlines():
        if not line.startswith("aria_fragment_events_total{"):
            continue
        labels = dict(re.findall(r'(\w+)="([^"]*)"', line))
        key = (labels["pin_path"], labels["family"], labels["event"])
        values[key] = int(float(line.rsplit(None, 1)[1]))
    return values


def fetch_metrics(url):
    with urllib.request.urlopen(url, timeout=5) as response:
        return metric_series(response.read().decode("utf-8"))


def require_deltas(before, after, pin_path, family, expected):
    for event, delta in expected.items():
        key = (pin_path, family, event)
        if key not in before or key not in after:
            raise RuntimeError("missing exact public series %r" % (key,))
        actual = after[key] - before[key]
        if actual != delta:
            raise RuntimeError("series %r delta %d, expected %d" % (key, actual, delta))


RECEIVER = r'''import os,socket,sys
family,address,token,ready,result=sys.argv[1:]
sock=socket.socket(socket.AF_INET if family=="ipv4" else socket.AF_INET6,socket.SOCK_DGRAM)
try:
 sock.settimeout(3); sock.bind((address,53) if family=="ipv4" else (address,53,0,0)); open(ready,"w").write("ready")
 data=sock.recv(4096); open(result,"w").write("received" if data==token.encode("ascii") else "wrong")
finally: sock.close()
'''


def start_receiver(namespace, family, address, token):
    directory = tempfile.mkdtemp(prefix="aria-frag-")
    ready, result = os.path.join(directory, "ready"), os.path.join(directory, "result")
    command = [sys.executable, "-c", RECEIVER, family, address, token, ready, result]
    if namespace:
        command = ["ip", "netns", "exec", namespace] + command
    process = subprocess.Popen(command, stderr=subprocess.PIPE, text=True)
    for _ in range(30):
        if os.path.exists(ready):
            return process, result, directory
        if process.poll() is not None:
            raise RuntimeError("receiver setup failed: %s" % process.stderr.read().strip())
        time.sleep(0.1)
    process.kill()
    raise RuntimeError("receiver did not become ready")


def send_frames(interface, frames, namespace=None):
    if namespace:
        command = ["ip", "netns", "exec", namespace, sys.executable, __file__, "--emit", "--iface", interface]
        command.extend("--frame=" + base64.b64encode(frame).decode("ascii") for frame in frames)
        subprocess.check_call(command)
        return
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_ALL)) as sock:
        for frame in frames:
            sock.sendto(frame, (interface, 0))


def run_fixture(args):
    family = 4 if args.family == "ipv4" else 6
    token = args.token or "aria-frag-" + secrets.token_hex(16)
    source_mac = args.source_mac or open("/sys/class/net/%s/address" % args.iface, encoding="ascii").read().strip()
    raw = fragments(args.source, args.destination, family, token, args.ident)
    order = {"ordered": (0, 1, 2), "post-first-reorder": (0, 2, 1), "later-before-first": (1, 0, 2)}[args.scenario]
    before = fetch_metrics(args.metrics_url)
    receiver, result, directory = start_receiver(args.receiver_netns, args.family, args.destination, token)
    try:
        frames = [ethernet(raw[index], source_mac, args.destination_mac, family, args.vlan) for index in order]
        send_frames(args.iface, frames, args.send_netns)
        receiver.wait(4)
        if receiver.returncode not in (0, 1):
            raise RuntimeError("receiver operational failure: %s" % receiver.stderr.read().strip())
        received = os.path.exists(result) and open(result, encoding="ascii").read() == "received"
        after = fetch_metrics(args.metrics_url)
        expected = {"first": 1, "hit": 2} if args.scenario != "later-before-first" else {"first": 1, "miss": 1}
        require_deltas(before, after, args.pin_path, args.family, expected)
        if args.scenario == "later-before-first":
            if received:
                raise RuntimeError("later-before-first fragment delivered")
        elif not received:
            raise RuntimeError("receiver did not receive random token")
    finally:
        if receiver.poll() is None:
            receiver.kill()
        for name in ("ready", "result"):
            path = os.path.join(directory, name)
            if os.path.exists(path): os.unlink(path)
        os.rmdir(directory)
    print("fragment scenario %s complete" % args.scenario)


def self_test():
    v4 = fragments("192.0.2.1", "192.0.2.2", 4, "x" * 40, 7)
    v6 = fragments("2001:db8::1", "2001:db8::2", 6, "x" * 40, 8)
    assert checksum(v4[0][:20]) == 0 and struct.unpack("!H", v4[1][6:8])[0] & 0x1fff == 2
    assert v6[0][6] == 44 and v6[1][40] == 17 and checksum(udp_datagram("2001:db8::1", "2001:db8::2", 6, "x" * 40)) != 0
    tagged = ethernet(v4[0], "02:00:00:00:00:01", "02:00:00:00:00:02", 4, 203)
    assert struct.unpack("!H", tagged[12:14])[0] == ETH_VLAN
    before = metric_series('aria_fragment_events_total{pin_path="/p",family="ipv4",event="first"} 2\naria_fragment_events_total{pin_path="/other",family="ipv4",event="first"} 9\n')
    after = dict(before); after[("/p", "ipv4", "first")] = 3; after[("/p", "ipv4", "hit")] = 2; before[("/p", "ipv4", "hit")] = 0
    require_deltas(before, after, "/p", "ipv4", {"first": 1, "hit": 2})
    try: require_deltas(before, after, "/other", "ipv4", {"first": 1})
    except RuntimeError: pass
    else: raise AssertionError("pin identity must be exact")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true"); parser.add_argument("--run", action="store_true"); parser.add_argument("--emit", action="store_true")
    parser.add_argument("--iface"); parser.add_argument("--frame", action="append", default=[]); parser.add_argument("--source"); parser.add_argument("--destination"); parser.add_argument("--source-mac"); parser.add_argument("--destination-mac"); parser.add_argument("--family", choices=("ipv4", "ipv6")); parser.add_argument("--vlan", type=int, default=0); parser.add_argument("--metrics-url"); parser.add_argument("--pin-path"); parser.add_argument("--receiver-netns"); parser.add_argument("--send-netns"); parser.add_argument("--token"); parser.add_argument("--ident", type=int, default=7); parser.add_argument("--scenario", choices=("ordered", "post-first-reorder", "later-before-first"), default="ordered")
    args = parser.parse_args()
    if args.self_test: self_test(); return
    if args.emit: send_frames(args.iface, [base64.b64decode(frame, validate=True) for frame in args.frame]); return
    needed = ("iface", "source", "destination", "destination_mac", "family", "metrics_url", "pin_path")
    if not args.run or not all(getattr(args, key) for key in needed): parser.error("--run requires interface, addresses, MAC, family, metrics URL, and pin path")
    if args.vlan and not 1 <= args.vlan <= 4094: parser.error("VLAN must be 1..4094")
    run_fixture(args)


if __name__ == "__main__": main()

#!/usr/bin/env python3
"""Stdlib-only fragment field driver; shell entrypoints own policy and cleanup."""

import argparse
import base64
from contextlib import contextmanager
from decimal import Decimal, InvalidOperation
import ipaddress
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request


ETH_ALL, ETH_IP, ETH_V6, ETH_VLAN = 3, 0x0800, 0x86DD, 0x8100
EVENTS = (
    "first", "non_initial", "hit", "miss", "expired", "stale", "inserted",
    "update_failed", "invalid_l4", "overlap",
)
GAUGES = {
    "aria_fragment_context_occupancy": "occupancy",
    "aria_fragment_context_max_entries": "max_entries",
    "aria_fragment_context_pressure": "pressure",
}


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    total = (total & 0xffff) + (total >> 16)
    total = (total & 0xffff) + (total >> 16)
    return (~total) & 0xffff


def parse_mac(value):
    parts = value.split(":")
    if len(parts) != 6 or any(not re.fullmatch(r"[0-9a-fA-F]{2}", x) for x in parts):
        raise ValueError("invalid MAC: %s" % value)
    return bytes(int(x, 16) for x in parts)


def validate_identity(family, token, ident):
    try:
        payload = token.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("token must be ASCII") from error
    if len(payload) <= 24:
        raise ValueError("token must exceed 24 bytes to produce three fragments")
    maximum = 0xffff if family == 4 else 0xffffffff
    if ident is None or not 0 <= ident <= maximum:
        raise ValueError("fragment ID must be in 0..%d for IPv%d" % (maximum, family))


def pseudoheader(source, destination, family, length):
    if family == 4:
        return (ipaddress.IPv4Address(source).packed + ipaddress.IPv4Address(destination).packed
                + struct.pack("!BBH", 0, 17, length))
    return (ipaddress.IPv6Address(source).packed + ipaddress.IPv6Address(destination).packed
            + struct.pack("!I3xB", length, 17))


def udp_datagram(source, destination, family, token):
    payload = token.encode("ascii")
    head = struct.pack("!HHHH", 43000, 53, 8 + len(payload), 0)
    value = checksum(pseudoheader(source, destination, family, len(head) + len(payload))
                     + head + payload) or 0xffff
    return head[:6] + struct.pack("!H", value) + payload


def fragments(source, destination, family, token, ident):
    validate_identity(family, token, ident)
    data = udp_datagram(source, destination, family, token)
    chunks = (data[:16], data[16:32], data[32:])
    result = []
    for index, body in enumerate(chunks):
        offset = index * 16
        if family == 4:
            flags = (0x2000 if index < 2 else 0) | offset // 8
            head = struct.pack(
                "!BBHHHBBH4s4s", 0x45, 0, 20 + len(body), ident, flags, 64, 17, 0,
                ipaddress.IPv4Address(source).packed, ipaddress.IPv4Address(destination).packed,
            )
            packet = head[:10] + struct.pack("!H", checksum(head)) + head[12:] + body
        else:
            frag = struct.pack("!BBHI", 17, 0,
                               (offset // 8 << 3) | (index < 2), ident)
            packet = struct.pack(
                "!IHBB16s16s", 0x60000000, len(frag) + len(body), 44, 64,
                ipaddress.IPv6Address(source).packed, ipaddress.IPv6Address(destination).packed,
            ) + frag + body
        result.append(packet)
    return result


def ethernet(payload, source_mac, destination_mac, family, vlan):
    kind = ETH_IP if family == 4 else ETH_V6
    prefix = parse_mac(destination_mac) + parse_mac(source_mac)
    if vlan:
        if not 1 <= vlan <= 4094:
            raise ValueError("VLAN must be 1..4094")
        return prefix + struct.pack("!HHH", ETH_VLAN, vlan, kind) + payload
    return prefix + struct.pack("!H", kind) + payload


def derived_identity(token, ident, ordinal, family):
    """Ordinal zero deliberately reuses an identity; later ordinals are distinct."""
    maximum = 0xffff if family == 4 else 0xffffffff
    if ordinal < 0 or ident + ordinal > maximum:
        raise ValueError("derived fragment ID is outside the IPv%d range" % family)
    value = (token if ordinal == 0 else "%s-%08x" % (token, ordinal), ident + ordinal)
    validate_identity(family, *value)
    return value


def _prom_unescape(value):
    def replace(match):
        escaped = match.group(1)
        if escaped not in ('\\', '"', "n"):
            raise ValueError("invalid Prometheus label escape")
        return "\n" if escaped == "n" else escaped
    return re.sub(r"\\(.)", replace, value)


def _labels(text):
    matches = list(re.finditer(r'([A-Za-z_]\w*)="((?:\\.|[^"\\])*)"', text))
    residue = re.sub(r'([A-Za-z_]\w*)="((?:\\.|[^"\\])*)"', "", text).strip(" ,")
    if residue:
        raise ValueError("invalid Prometheus labels: %s" % text)
    labels = {}
    for match in matches:
        if match.group(1) in labels:
            raise ValueError("duplicate Prometheus label: %s" % match.group(1))
        labels[match.group(1)] = _prom_unescape(match.group(2))
    return labels


def parse_metrics(text):
    values = {"events": {}, "occupancy": {}, "max_entries": {}, "pressure": {}}
    pattern = re.compile(
        r"^(aria_fragment_(?:events_total|context_(?:occupancy|max_entries|pressure)))"
        r"\{(.*)\}\s+(\S+)\s*$"
    )
    for line in text.splitlines():
        match = pattern.match(line.strip())
        if not match:
            continue
        name, raw_labels, raw_value = match.groups()
        labels = _labels(raw_labels)
        if "pin_path" not in labels or "family" not in labels:
            raise ValueError("fragment metric lacks exact runtime/family labels")
        key = (labels["pin_path"], labels["family"])
        try:
            value = Decimal(raw_value)
        except InvalidOperation as error:
            raise ValueError("invalid fragment metric value: %s" % raw_value) from error
        if not value.is_finite():
            raise ValueError("fragment metric value must be finite")
        if name == "aria_fragment_events_total":
            event = labels.get("event")
            if event not in EVENTS:
                raise ValueError("unknown public fragment event: %r" % event)
            key += (event,)
            target = values["events"]
        else:
            target = values[GAUGES[name]]
        integral = name != "aria_fragment_context_pressure"
        if integral and value != value.to_integral_value():
            raise ValueError("fragment counter/context gauge must be integral")
        value = int(value) if integral else value
        if key in target:
            raise ValueError("duplicate fragment metric series: %r" % (key,))
        target[key] = value
    return values


def fetch_metrics(url):
    with urllib.request.urlopen(url, timeout=5) as response:
        return parse_metrics(response.read().decode("utf-8"))


def vector(**changes):
    unknown = set(changes) - set(EVENTS)
    if unknown:
        raise ValueError("unknown expected events: %s" % sorted(unknown))
    return {event: changes.get(event, 0) for event in EVENTS}


def require_deltas(before, after, pin_path, family, expected):
    expected = vector(**expected)
    for event in EVENTS:
        key = (pin_path, family, event)
        if key not in before["events"] or key not in after["events"]:
            raise RuntimeError("missing exact public series %r" % (key,))
        actual = after["events"][key] - before["events"][key]
        if actual != expected[event]:
            raise RuntimeError("series %r delta %d, expected %d" %
                               (key, actual, expected[event]))


def require_pressure(snapshot, pin_path, family, occupancy, maximum):
    key = (pin_path, family)
    if any(key not in snapshot[field] for field in ("occupancy", "max_entries", "pressure")):
        raise RuntimeError("missing exact public pressure series %r" % (key,))
    actual = snapshot["occupancy"][key], snapshot["max_entries"][key]
    if actual != (occupancy, maximum) or maximum <= 0 or not 0 <= occupancy <= maximum:
        raise RuntimeError("context bounds %r are %r, expected %r" %
                           (key, actual, (occupancy, maximum)))
    expected = Decimal(occupancy) / Decimal(maximum)
    if snapshot["pressure"][key] != expected:
        raise RuntimeError("context pressure %r is %s, expected %s" %
                           (key, snapshot["pressure"][key], expected))


RECEIVER = r'''import socket,sys,traceback
family,address,token,port,timeout,ready,result,error=sys.argv[1:]
def write(path,value):
 with open(path,"w",encoding="utf-8") as handle: handle.write(value)
try:
 sock=socket.socket(socket.AF_INET if family=="ipv4" else socket.AF_INET6,socket.SOCK_DGRAM)
 try:
  sock.settimeout(float(timeout)); sock.bind((address,int(port)) if family=="ipv4" else (address,int(port),0,0)); write(ready,"ready")
  try: data=sock.recv(65535)
  except socket.timeout: write(result,"timeout")
  else:
   if data != token.encode("ascii"): raise RuntimeError("wrong token")
   write(result,"received")
 finally: sock.close()
except BaseException as exc:
 try: write(error,"%s: %s" % (type(exc).__name__,exc))
 except BaseException: traceback.print_exc()
 traceback.print_exc(); raise
'''


def _read(path):
    try:
        with open(path, encoding="utf-8") as handle:
            return handle.read()
    except FileNotFoundError:
        return ""


@contextmanager
def receiver(namespace, family, address, token, port=53, timeout=3.0, directory=None):
    if timeout <= 0 or not 1 <= port <= 65535:
        raise ValueError("invalid receiver timeout or port")
    directory = directory or tempfile.mkdtemp(prefix="aria-frag-")
    os.makedirs(directory, exist_ok=True)
    ready, result, error = (os.path.join(directory, name)
                            for name in ("ready", "result", "error"))
    command = [sys.executable, "-c", RECEIVER, family, address, token, str(port),
               str(timeout), ready, result, error]
    if namespace:
        command = ["ip", "netns", "exec", namespace] + command
    process = None
    try:
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.PIPE, text=True)
        deadline = time.monotonic() + min(5.0, timeout + 2.0)
        while not os.path.exists(ready):
            if process.poll() is not None:
                detail = _read(error) or process.stderr.read().strip() or "unknown error"
                raise RuntimeError("receiver setup failed: %s" % detail)
            if time.monotonic() >= deadline:
                raise RuntimeError("receiver did not become ready")
            time.sleep(0.02)
        yield {"process": process, "result": result, "error": error,
               "timeout": timeout, "directory": directory}
    finally:
        if process is not None:
            if process.poll() is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                process.wait()
            if process.stderr is not None and not process.stderr.closed:
                process.stderr.close()
        shutil.rmtree(directory, ignore_errors=False)


def require_receiver_outcome(handle, expect_delivery):
    process = handle["process"]
    try:
        _, stderr = process.communicate(timeout=handle["timeout"] + 2.0)
    except subprocess.TimeoutExpired as error:
        process.kill()
        process.wait()
        raise RuntimeError("receiver subprocess exceeded its timeout") from error
    detail = _read(handle["error"])
    if process.returncode != 0 or detail:
        raise RuntimeError("receiver operational failure: %s" %
                           (detail or stderr.strip() or process.returncode))
    try:
        with open(handle["result"], encoding="utf-8") as result:
            outcome = result.read()
    except OSError as error:
        raise RuntimeError("receiver result read failed: %s" % error) from error
    expected = "received" if expect_delivery else "timeout"
    if outcome != expected:
        raise RuntimeError("receiver outcome %r, expected %r" % (outcome, expected))
    return outcome


def send_frames(interface, frames, namespace=None):
    if namespace:
        command = ["ip", "netns", "exec", namespace, sys.executable, __file__,
                   "--emit", "--iface", interface]
        command += ["--frame=" + base64.b64encode(frame).decode("ascii") for frame in frames]
        subprocess.check_call(command)
        return
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_ALL)) as raw:
        for frame in frames:
            raw.sendto(frame, (interface, 0))


def run_stage(args, frames, expected, delivery):
    before = fetch_metrics(args.metrics_url)
    with receiver(args.receiver_netns, args.family, args.destination, args.token,
                  args.receiver_port, args.receiver_timeout) as handle:
        send_frames(args.iface, frames, args.send_netns)
        require_receiver_outcome(handle, delivery)
    after = fetch_metrics(args.metrics_url)
    require_deltas(before, after, args.pin_path, args.family, expected)


def frame_set(args, family, source_mac, token=None, ident=None):
    packets = fragments(args.source, args.destination, family,
                        token or args.token, args.ident if ident is None else ident)
    return [ethernet(packet, source_mac, args.destination_mac, family, args.vlan)
            for packet in packets]


def run_pressure(args, family, source_mac):
    if args.capacity is None or not 1 <= args.capacity <= 4096:
        raise ValueError("pressure requires --capacity in 1..4096")
    identities = [derived_identity(args.token, args.ident, i, family)
                  for i in range(args.capacity + 1)]
    frame_sets = [frame_set(args, family, source_mac, *identity) for identity in identities]
    before = fetch_metrics(args.metrics_url)
    with receiver(args.receiver_netns, args.family, args.destination, args.token,
                  args.receiver_port, args.receiver_timeout) as handle:
        send_frames(args.iface, [frames[0] for frames in frame_sets], args.send_netns)
        require_receiver_outcome(handle, False)
    filled = fetch_metrics(args.metrics_url)
    require_deltas(before, filled, args.pin_path, args.family,
                   vector(first=args.capacity + 1, inserted=args.capacity + 1))
    require_pressure(filled, args.pin_path, args.family, args.capacity, args.capacity)
    with receiver(args.receiver_netns, args.family, args.destination, args.token,
                  args.receiver_port, args.receiver_timeout) as handle:
        send_frames(args.iface, [frame_sets[0][1]], args.send_netns)
        require_receiver_outcome(handle, False)
    probed = fetch_metrics(args.metrics_url)
    require_deltas(filled, probed, args.pin_path, args.family,
                   vector(non_initial=1, miss=1))
    require_pressure(probed, args.pin_path, args.family, args.capacity, args.capacity)
    print("fragment pressure fill-and-evict observation complete")


def run_fixture(args):
    family = 4 if args.family == "ipv4" else 6
    validate_identity(family, args.token, args.ident)
    if args.source_mac:
        source_mac = args.source_mac
    else:
        with open("/sys/class/net/%s/address" % args.iface, encoding="ascii") as handle:
            source_mac = handle.read().strip()
    if args.operation == "pressure":
        run_pressure(args, family, source_mac)
        return
    frames = frame_set(args, family, source_mac)
    orders = {
        "ordered": (0, 1, 2), "reordered": (0, 2, 1),
        "post-first-reorder": (0, 2, 1), "later-before-first": (1, 0, 2),
    }
    if args.operation == "complete":
        order = orders[args.scenario]
        expected = (vector(first=1, non_initial=2, hit=1, miss=1, inserted=1)
                    if args.scenario == "later-before-first"
                    else vector(first=1, non_initial=2, hit=2, inserted=1))
        delivery = args.scenario != "later-before-first"
    elif args.operation == "establish":
        order, expected, delivery = (0,), vector(first=1, inserted=1), False
    elif args.operation == "continue":
        order, expected, delivery = (1, 2), vector(non_initial=2, hit=2), True
    else:
        if args.expected_probe_event not in ("miss", "expired", "stale"):
            raise ValueError("probe-old requires --expected-probe-event")
        order = (1,)
        expected = vector(non_initial=1, **{args.expected_probe_event: 1})
        delivery = False
    run_stage(args, [frames[i] for i in order], expected, delivery)
    print("fragment operation %s scenario %s complete" % (args.operation, args.scenario))


def _metric_fixture(pin, family, changed=None, occupancy=0, maximum=4):
    changed = changed or {}
    lines = ['aria_fragment_events_total{pin_path="%s",family="%s",event="%s"} %d'
             % (pin, family, event, changed.get(event, 0)) for event in EVENTS]
    lines += [
        'aria_fragment_context_occupancy{pin_path="%s",family="%s"} %d'
        % (pin, family, occupancy),
        'aria_fragment_context_max_entries{pin_path="%s",family="%s"} %d'
        % (pin, family, maximum),
        'aria_fragment_context_pressure{pin_path="%s",family="%s"} %s'
        % (pin, family, Decimal(occupancy) / Decimal(maximum)),
    ]
    return "\n".join(lines) + "\n"


def self_test():
    token = "fragment-self-test-token-0123456789"
    v4 = fragments("192.0.2.1", "192.0.2.2", 4, token, 7)
    v6 = fragments("2001:db8::1", "2001:db8::2", 6, token, 8)
    assert checksum(v4[0][:20]) == 0
    assert checksum(pseudoheader("192.0.2.1", "192.0.2.2", 4,
                                 sum(len(x) - 20 for x in v4)) + b"".join(x[20:] for x in v4)) == 0
    assert v6[0][6] == 44 and checksum(
        pseudoheader("2001:db8::1", "2001:db8::2", 6, sum(len(x) - 48 for x in v6))
        + b"".join(x[48:] for x in v6)) == 0
    tagged = ethernet(v4[0], "02:00:00:00:00:01", "02:00:00:00:00:02", 4, 203)
    assert struct.unpack("!HHH", tagged[12:18]) == (ETH_VLAN, 203, ETH_IP)
    first, second, reused = (derived_identity(token, 100, i, 4) for i in (0, 1, 0))
    assert first != second and first == reused
    assert fragments("192.0.2.1", "192.0.2.2", 4, *first) == fragments(
        "192.0.2.1", "192.0.2.2", 4, *reused)

    before = parse_metrics(_metric_fixture("/p", "ipv4", {"first": 2}, 1)
                           + _metric_fixture("/other", "ipv4", {"first": 9}))
    changes = vector(first=1, non_initial=2, hit=2, inserted=1)
    after_text = (_metric_fixture("/p", "ipv4",
                                  {"first": 3, "non_initial": 2, "hit": 2, "inserted": 1}, 4)
                  + _metric_fixture("/other", "ipv4", {"first": 10}))
    after = parse_metrics(after_text)
    require_deltas(before, after, "/p", "ipv4", changes)
    require_pressure(after, "/p", "ipv4", 4, 4)
    for bad_before, bad_after, expected in (
        (before, after, vector()),
        (before, parse_metrics(after_text.replace('event="overlap"} 0',
                                                 'event="overlap"} 1')), changes),
    ):
        try:
            require_deltas(bad_before, bad_after, "/other" if expected == vector() else "/p",
                           "ipv4", expected)
        except RuntimeError:
            pass
        else:
            raise AssertionError("exact pin/full-vector metric comparison failed")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0)); port = probe.getsockname()[1]
    with receiver(None, "ipv4", "127.0.0.1", token, port, 0.5) as handle:
        directory = handle["directory"]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
            sender.sendto(token.encode("ascii"), ("127.0.0.1", port))
        assert require_receiver_outcome(handle, True) == "received"
    assert not os.path.exists(directory)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0)); port = probe.getsockname()[1]
    with receiver(None, "ipv4", "127.0.0.1", token, port, 0.1) as handle:
        directory = handle["directory"]
        assert require_receiver_outcome(handle, False) == "timeout"
    assert not os.path.exists(directory)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as blocker:
        blocker.bind(("127.0.0.1", 0)); directory = tempfile.mkdtemp(prefix="aria-frag-error-")
        try:
            with receiver(None, "ipv4", "127.0.0.1", token, blocker.getsockname()[1],
                          0.1, directory):
                pass
        except RuntimeError:
            pass
        else:
            raise AssertionError("receiver operational failure did not propagate")
        assert not os.path.exists(directory)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--emit", action="store_true")
    parser.add_argument("--iface"); parser.add_argument("--frame", action="append", default=[])
    parser.add_argument("--source"); parser.add_argument("--destination")
    parser.add_argument("--source-mac"); parser.add_argument("--destination-mac")
    parser.add_argument("--family", choices=("ipv4", "ipv6"))
    parser.add_argument("--vlan", type=int, default=0)
    parser.add_argument("--metrics-url"); parser.add_argument("--pin-path")
    parser.add_argument("--receiver-netns"); parser.add_argument("--send-netns")
    parser.add_argument("--receiver-port", type=int, default=53)
    parser.add_argument("--receiver-timeout", type=float, default=3.0)
    parser.add_argument("--token"); parser.add_argument("--ident", type=int)
    parser.add_argument("--operation", choices=("complete", "establish", "continue",
                                                 "probe-old", "pressure"), default="complete")
    parser.add_argument("--scenario", choices=("ordered", "reordered", "post-first-reorder",
                                                "later-before-first"), default="ordered")
    parser.add_argument("--expected-probe-event", choices=("miss", "expired", "stale"))
    parser.add_argument("--capacity", type=int)
    parser.add_argument("--reuse-reason", choices=("isolation", "epoch", "restart",
                                                    "eviction", "expiry"))
    args = parser.parse_args()
    if args.self_test:
        self_test(); return
    if args.emit:
        if not args.iface or not args.frame:
            parser.error("--emit requires interface and frames")
        send_frames(args.iface, [base64.b64decode(x, validate=True) for x in args.frame]); return
    needed = ("iface", "source", "destination", "destination_mac", "family", "metrics_url",
              "pin_path", "token", "ident")
    if not args.run or any(getattr(args, key) is None for key in needed):
        parser.error("--run requires endpoints, MAC, family, metrics, pin path, token, and ID")
    try:
        run_fixture(args)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        parser.exit(1, "fragment field driver error: %s\n" % error)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Stdlib-only fragment field driver; shell entrypoints own policy and cleanup."""

import argparse
import base64
from contextlib import contextmanager, redirect_stderr
from decimal import Decimal, InvalidOperation
import io
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
MAX_TOKEN_BYTES = 65527
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
    if len(payload) > MAX_TOKEN_BYTES:
        raise ValueError("token exceeds the maximum UDP payload of %d bytes" % MAX_TOKEN_BYTES)
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
    labels = {}
    pattern = re.compile(r'([A-Za-z_]\w*)="((?:\\.|[^"\\])*)"')
    position = 0
    while position < len(text):
        if labels:
            if text[position] != ",":
                raise ValueError("invalid Prometheus label separator: %s" % text)
            position += 1
        match = pattern.match(text, position)
        if match is None:
            raise ValueError("invalid Prometheus labels: %s" % text)
        if match.group(1) in labels:
            raise ValueError("duplicate Prometheus label: %s" % match.group(1))
        labels[match.group(1)] = _prom_unescape(match.group(2))
        position = match.end()
    return labels
def parse_metrics(text):
    values = {"events": {}, "occupancy": {}, "max_entries": {}, "pressure": {}}
    pattern = re.compile(
        r"^(aria_fragment_(?:events_total|context_(?:occupancy|max_entries|pressure)))"
        r"\{(.*)\} ([^\s]+)$"
    )
    for line in text.splitlines():
        public_line = line.lstrip().startswith("aria_fragment_")
        if not public_line:
            continue
        match = pattern.fullmatch(line)
        if match is None:
            raise ValueError("malformed or unknown public fragment metric: %s" % line)
        name, raw_labels, raw_value = match.groups()
        labels = _labels(raw_labels)
        expected_labels = ({"pin_path", "family", "event"}
                           if name == "aria_fragment_events_total"
                           else {"pin_path", "family"})
        if set(labels) != expected_labels:
            raise ValueError("fragment metric label set is not exact: %s" % sorted(labels))
        if not labels["pin_path"] or labels["family"] not in ("ipv4", "ipv6"):
            raise ValueError("fragment metric runtime/family label is invalid")
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


RECEIVER = r'''import socket
import sys
import traceback

family, address, token, port, timeout, ready, result, error = sys.argv[1:]

def write_state(path, value):
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(value)

try:
    sock = socket.socket(
        socket.AF_INET if family == "ipv4" else socket.AF_INET6,
        socket.SOCK_DGRAM,
    )
    try:
        sock.settimeout(float(timeout))
        endpoint = ((address, int(port)) if family == "ipv4"
                    else (address, int(port), 0, 0))
        sock.bind(endpoint)
        write_state(ready, "ready")
        try:
            data = sock.recv(65535)
        except socket.timeout:
            write_state(result, "timeout")
        else:
            if data != token.encode("ascii"):
                raise RuntimeError("wrong token")
            write_state(result, "received")
    finally:
        sock.close()
except BaseException as exc:
    try:
        write_state(error, "%s: %s" % (type(exc).__name__, exc))
    except BaseException:
        traceback.print_exc()
    traceback.print_exc()
    raise
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
def _expect_error(error_type, callback, message):
    try:
        callback()
    except error_type as error:
        return error
    raise AssertionError(message)
def self_test():
    token = "fragment-self-test-token-0123456789"
    assert checksum(bytes.fromhex("0001f203f4f5f6f7")) == 0x220d
    v4 = fragments("192.0.2.1", "192.0.2.2", 4, token, 7)
    v6 = fragments("2001:db8::1", "2001:db8::2", 6, token, 8)
    v4_datagram = b"".join(packet[20:] for packet in v4)
    v4_reference = bytes.fromhex("c0000201c00002020011") + struct.pack("!H", len(v4_datagram))
    assert checksum(v4[0][:20]) == 0
    assert checksum(v4_reference + v4_datagram) == 0
    v6_datagram = b"".join(packet[48:] for packet in v6)
    v6_reference = bytes.fromhex("20010db8000000000000000000000001"
                                 "20010db8000000000000000000000002")
    v6_reference += struct.pack("!I", len(v6_datagram)) + bytes.fromhex("00000011")
    assert v6[0][6] == 44 and checksum(v6_reference + v6_datagram) == 0
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
    _expect_error(RuntimeError, lambda: require_deltas(
        before, after, "/other", "ipv4", vector()), "pin-path isolation failed")
    unexpected = parse_metrics(after_text.replace('event="overlap"} 0',
                                                   'event="overlap"} 1'))
    _expect_error(RuntimeError, lambda: require_deltas(
        before, unexpected, "/p", "ipv4", changes), "full-vector comparison failed")
    malformed_metrics = (
        'aria_fragment_events_total{pin_path="/p" family="ipv4",event="first"} 1',
        'aria_fragment_events_total{pin_path="/p",pin_path="/q",family="ipv4",event="first"} 1',
        'aria_fragment_events_total{pin_path="/p",family="ipv4",event="first",extra="x"} 1',
        'aria_fragment_events_total{pin_path="/p",family="ipv4",event="first"} nope extra',
        'aria_fragment_context_unknown{pin_path="/p",family="ipv4"} 1',
    )
    for malformed in malformed_metrics:
        _expect_error(ValueError, lambda value=malformed: parse_metrics(value),
                      "malformed public fragment metric was ignored")
    common = [
        "--run", "--iface", "lo", "--source", "192.0.2.1", "--destination",
        "192.0.2.2", "--destination-mac", "02:00:00:00:00:02", "--family",
        "ipv4", "--metrics-url", "http://127.0.0.1/metrics", "--pin-path", "/p",
        "--token", token, "--ident", "7",
    ]
    rejected_arguments = (
        [], ["--self-test", "--run"], ["--self-test", "--iface", "lo"],
        ["--emit", "--iface", "lo", "--frame", "AA==", "--token", token],
        common + ["--frame", "AA=="],
        common + ["--operation", "pressure", "--capacity", "2"],
        common + ["--operation", "pressure", "--capacity", "2", "--reuse-reason", "epoch"],
        common + ["--operation", "probe-old", "--expected-probe-event", "stale"],
        common + ["--operation", "probe-old", "--expected-probe-event", "stale", "--reuse-reason", "restart"],
        common + ["--operation", "establish", "--reuse-reason", "isolation"],
        common[:-4] + ["--token", "x" * (MAX_TOKEN_BYTES + 1), "--ident", "7"],
    )
    for arguments in rejected_arguments:
        with redirect_stderr(io.StringIO()):
            error = _expect_error(SystemExit, lambda value=arguments: parse_arguments(value),
                                  "incompatible CLI arguments were accepted")
            assert error.code == 2
    accepted = (
        common + ["--operation", "pressure", "--capacity", "2", "--reuse-reason", "eviction"],
        common + ["--operation", "probe-old", "--expected-probe-event", "miss", "--reuse-reason", "restart"],
    )
    assert [parse_arguments(value).reuse_reason for value in accepted] == ["eviction", "restart"]
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
        def bind_failure():
            with receiver(None, "ipv4", "127.0.0.1", token, blocker.getsockname()[1],
                          0.1, directory):
                pass
        _expect_error(RuntimeError, bind_failure, "receiver bind failure did not propagate")
        assert not os.path.exists(directory)
def build_parser():
    parser = argparse.ArgumentParser()
    mode = parser.add_mutually_exclusive_group(required=True)
    for name in ("self-test", "run", "emit"):
        mode.add_argument("--" + name, action="store_true")
    parser.add_argument("--frame", action="append")
    for name in (
        "iface", "source", "destination", "source_mac", "destination_mac", "metrics_url",
        "pin_path", "receiver_netns", "send_netns", "token",
    ):
        parser.add_argument("--" + name.replace("_", "-"))
    parser.add_argument("--family", choices=("ipv4", "ipv6"))
    parser.add_argument("--vlan", type=int)
    parser.add_argument("--receiver-port", type=int)
    parser.add_argument("--receiver-timeout", type=float)
    parser.add_argument("--ident", type=int)
    parser.add_argument("--operation", choices=("complete", "establish", "continue",
                                                 "probe-old", "pressure"))
    parser.add_argument("--scenario", choices=("ordered", "reordered",
                                                "post-first-reorder", "later-before-first"))
    parser.add_argument("--expected-probe-event", choices=("miss", "stale"))
    parser.add_argument("--capacity", type=int)
    parser.add_argument("--reuse-reason", choices=("isolation", "epoch", "restart", "eviction"))
    return parser
def parse_arguments(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    provided = {name for name, value in vars(args).items()
                if value is not None and value is not False}
    if args.self_test:
        if provided != {"self_test"}:
            parser.error("--self-test does not accept run or emit arguments")
        return args
    if args.emit:
        if not args.iface or not args.frame:
            parser.error("--emit requires interface and frames")
        if not provided <= {"emit", "iface", "frame"}:
            parser.error("--emit accepts only --iface and --frame")
        return args
    if args.frame is not None:
        parser.error("--run does not accept --frame")
    needed = ("iface", "source", "destination", "destination_mac", "family",
              "metrics_url", "pin_path", "token", "ident")
    if any(getattr(args, key) is None for key in needed):
        parser.error("--run requires endpoints, MAC, family, metrics, pin path, token, and ID")
    try:
        validate_identity(4 if args.family == "ipv4" else 6, args.token, args.ident)
    except ValueError as error:
        parser.error(str(error))
    operation = args.operation or "complete"
    scoped = ((args.scenario, "complete", "--scenario"),
              (args.capacity, "pressure", "--capacity"),
              (args.expected_probe_event, "probe-old", "--expected-probe-event"))
    for value, owner, option in scoped:
        if value is not None and operation != owner:
            parser.error("%s is valid only with --operation %s" % (option, owner))
    if operation == "pressure":
        if args.capacity is None:
            parser.error("pressure requires --capacity")
        allowed_reuse = ("eviction",)
    elif operation == "probe-old":
        if args.expected_probe_event is None:
            parser.error("probe-old requires --expected-probe-event")
        allowed_reuse = {"stale": ("epoch",), "miss": ("isolation", "restart")}[args.expected_probe_event]
    else:
        allowed_reuse = (None, "isolation") if operation == "complete" else (None,)
    if args.reuse_reason not in allowed_reuse:
        parser.error("--reuse-reason is missing or incompatible with the selected operation")
    args.operation = operation
    args.scenario = args.scenario or "ordered"
    args.vlan = 0 if args.vlan is None else args.vlan
    args.receiver_port = 53 if args.receiver_port is None else args.receiver_port
    args.receiver_timeout = 3.0 if args.receiver_timeout is None else args.receiver_timeout
    return args
def main():
    args = parse_arguments()
    if args.self_test:
        self_test()
        return
    if args.emit:
        try:
            frames = [base64.b64decode(value, validate=True) for value in args.frame]
        except ValueError as error:
            build_parser().error("invalid base64 frame: %s" % error)
        send_frames(args.iface, frames)
        return
    try:
        run_fixture(args)
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        build_parser().exit(1, "fragment field driver error: %s\n" % error)


if __name__ == "__main__":
    main()

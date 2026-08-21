#!/usr/bin/env bash
set -euo pipefail

exec python3 - "$@" <<'PY'
from __future__ import print_function

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import threading
import time


def run(command, check=True):
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        universal_newlines=True,
    )
    if check and result.returncode != 0:
        raise RuntimeError("command failed (%d): %s\n%s" % (
            result.returncode, " ".join(command), result.stdout
        ))
    return result


def now_ms():
    return int(time.time() * 1000)


def read_ifindex(ifname):
    try:
        with open("/sys/class/net/%s/ifindex" % ifname, "r") as stream:
            return int(stream.read().strip())
    except (IOError, OSError, ValueError):
        return None


def uds_status(port_id):
    code = r'''
import json
import sys
from neutron_aria.agent.uds_client import LocalClient

payload = LocalClient("/run/aria/aria-agent.sock", timeout=3.0).status()
port_id = sys.argv[1]
status = next((item for item in payload.get("port_statuses") or []
               if item.get("port_id") == port_id), {})
managed = next((item for item in payload.get("managed_ports") or []
                if item.get("port_id") == port_id), {})
acl = next((item for item in status.get("domains") or []
            if item.get("domain") == "acl"), {})
print(json.dumps({
    "accepted_generation": payload.get("accepted_generation"),
    "applied_generation": payload.get("applied_generation"),
    "desired_hash": payload.get("desired_hash"),
    "pending_generation": payload.get("pending_generation"),
    "authority_state": payload.get("authority_state"),
    "port_status": status.get("status"),
    "port_reason": status.get("reason"),
    "effective_action": acl.get("effective_action"),
    "domain_reason": acl.get("reason"),
    "managed_ifindex": managed.get("ifindex"),
    "managed_ifname": managed.get("ifname"),
}, sort_keys=True))
'''
    result = run([
        "docker", "exec", "-u", "neutron", "neutron_aria_agent",
        "python", "-c", code, port_id,
    ])
    return json.loads(result.stdout)


def nova_command(arguments, check=True):
    return run([
        "docker", "exec", "-u", "root", "--env-file", "/etc/kolla/.adminrc",
        "openstack_client", "nova",
    ] + arguments, check=check)


def nova_active(server_id):
    result = nova_command(["show", server_id], check=False)
    return result.returncode == 0 and bool(re.search(
        r"^\|\s*status\s*\|\s*ACTIVE\s*\|", result.stdout, re.MULTILINE
    ))


def start_ping(address, output_path):
    stream = open(output_path, "w")
    process = subprocess.Popen(
        ["ping", "-D", "-O", "-i", "0.2", "-W", "1", address],
        stdout=stream,
        stderr=subprocess.STDOUT,
    )
    return process, stream


def stop_ping(process, stream):
    if process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    stream.close()


def ping_stats(path):
    with open(path, "r", errors="replace") as stream:
        content = stream.read()
    match = re.search(
        r"(\d+) packets transmitted, (\d+) received,.*?(\d+(?:\.\d+)?)% packet loss",
        content,
    )
    if not match:
        return {"transmitted": 0, "received": 0, "loss_percent": 100.0}
    return {
        "transmitted": int(match.group(1)),
        "received": int(match.group(2)),
        "loss_percent": float(match.group(3)),
    }


def ping_reply_times(path):
    replies = []
    pattern = re.compile(r"^\[(\d+(?:\.\d+)?)\].*bytes from", re.MULTILINE)
    with open(path, "r", errors="replace") as stream:
        for match in pattern.finditer(stream.read()):
            replies.append(int(float(match.group(1)) * 1000))
    return replies


def latest_sample(samples, timestamp_ms):
    current = None
    for sample in samples:
        if sample["timestamp_ms"] > timestamp_ms:
            break
        current = sample
    return current


def strip_ansi(value):
    return re.sub(r"\x1b\[[0-9;]*m", "", value)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server-id", required=True)
    parser.add_argument("--port-id", required=True)
    parser.add_argument("--ifname", required=True)
    parser.add_argument("--vm-ip", required=True)
    parser.add_argument("--canary-ip", required=True)
    parser.add_argument("--cycles", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=240)
    parser.add_argument("--settle-seconds", type=int, default=10)
    parser.add_argument("--work-dir", required=True)
    args = parser.parse_args()

    os.makedirs(args.work_dir, exist_ok=True)
    log_path = "/var/log/kolla/aria-datapath/aria-datapath.log"
    failures = []
    cycle_results = []

    baseline = uds_status(args.port_id)
    old_ifindex = read_ifindex(args.ifname)
    if baseline.get("port_status") != "ready" or baseline.get("effective_action") != "enforce":
        raise RuntimeError("baseline is not ready/enforce: %s" % baseline)
    if baseline.get("managed_ifindex") != old_ifindex:
        raise RuntimeError("baseline ifindex mismatch: runtime=%s actual=%s" % (
            baseline.get("managed_ifindex"), old_ifindex
        ))
    if run(["ping", "-c", "2", "-W", "1", args.vm_ip], check=False).returncode == 0:
        raise RuntimeError("baseline ACL probe is not blocked")
    if run(["ping", "-c", "3", "-W", "1", args.canary_ip], check=False).returncode != 0:
        raise RuntimeError("baseline OVS canary is not reachable")

    with open(os.path.join(args.work_dir, "candidate.json"), "w") as stream:
        json.dump({
            "agent_sha256": run([
                "docker", "exec", "aria_datapath", "sha256sum",
                "/usr/local/bin/aria-agent",
            ]).stdout.split()[0],
            "ebpf_sha256": run([
                "docker", "exec", "aria_datapath", "sha256sum",
                "/usr/local/lib/libebpf_firewall.so",
            ]).stdout.split()[0],
            "baseline": baseline,
        }, stream, indent=2, sort_keys=True)

    for cycle in range(1, args.cycles + 1):
        cycle_dir = os.path.join(args.work_dir, "cycle-%d" % cycle)
        os.makedirs(cycle_dir, exist_ok=True)
        status_path = os.path.join(cycle_dir, "status.jsonl")
        acl_ping_path = os.path.join(cycle_dir, "acl-probe.log")
        canary_ping_path = os.path.join(cycle_dir, "ovs-canary.log")
        log_offset = os.path.getsize(log_path)
        samples = []
        stop_event = threading.Event()

        def sample_status():
            with open(status_path, "w") as stream:
                while not stop_event.is_set():
                    timestamp = now_ms()
                    actual_ifindex_before = read_ifindex(args.ifname)
                    try:
                        sample = uds_status(args.port_id)
                        sample["sample_error"] = None
                    except Exception as error:
                        sample = {"sample_error": str(error)}
                    actual_ifindex_after = read_ifindex(args.ifname)
                    sample["timestamp_ms"] = timestamp
                    sample["actual_ifindex_before"] = actual_ifindex_before
                    sample["actual_ifindex_after"] = actual_ifindex_after
                    sample["identity_stable"] = (
                        actual_ifindex_before == actual_ifindex_after
                    )
                    sample["actual_ifindex"] = actual_ifindex_after
                    samples.append(sample)
                    stream.write(json.dumps(sample, sort_keys=True) + "\n")
                    stream.flush()
                    stop_event.wait(0.25)

        sampler = threading.Thread(target=sample_status, daemon=True)
        acl_ping, acl_stream = start_ping(args.vm_ip, acl_ping_path)
        canary_ping, canary_stream = start_ping(args.canary_ip, canary_ping_path)
        sampler.start()
        cycle_started = now_ms()
        previous_ifindex = old_ifindex
        new_ifindex = None
        new_ifindex_seen_ms = None
        ready_seen_ms = None
        try:
            # This legacy novaclient performs a soft reboot by default and only
            # exposes --hard as an override.
            nova_command(["reboot", args.server_id])
            deadline = time.time() + args.timeout
            while time.time() < deadline:
                current_ifindex = read_ifindex(args.ifname)
                if current_ifindex is not None and current_ifindex != previous_ifindex:
                    if new_ifindex is None:
                        new_ifindex = current_ifindex
                        new_ifindex_seen_ms = now_ms()
                if new_ifindex is not None and samples:
                    current = samples[-1]
                    if (
                        current.get("port_status") == "ready"
                        and current.get("effective_action") == "enforce"
                        and current.get("managed_ifindex") == new_ifindex
                        and current.get("actual_ifindex") == new_ifindex
                    ):
                        ready_seen_ms = current["timestamp_ms"]
                if (
                    new_ifindex is not None
                    and ready_seen_ms is not None
                    and nova_active(args.server_id)
                ):
                    break
                time.sleep(0.25)
            else:
                failures.append("cycle-%d did not recover before timeout" % cycle)

            if ready_seen_ms is not None:
                time.sleep(args.settle_seconds)
        finally:
            stop_event.set()
            sampler.join(timeout=5)
            stop_ping(acl_ping, acl_stream)
            stop_ping(canary_ping, canary_stream)

        with open(log_path, "rb") as stream:
            stream.seek(log_offset)
            log_segment = strip_ansi(stream.read().decode("utf-8", "replace"))
        with open(os.path.join(cycle_dir, "aria-datapath.log"), "w") as stream:
            stream.write(log_segment)

        identity_false_ready = [sample for sample in samples if (
            sample.get("identity_stable") is True
            and
            sample.get("port_status") == "ready"
            and sample.get("effective_action") == "enforce"
            and (
                sample.get("actual_ifindex") is None
                or sample.get("managed_ifindex") != sample.get("actual_ifindex")
            )
        )]
        acl_replies = ping_reply_times(acl_ping_path)
        traffic_false_ready = []
        for reply_ms in acl_replies:
            sample = latest_sample(samples, reply_ms)
            if sample and sample.get("port_status") == "ready" \
                    and sample.get("effective_action") == "enforce":
                traffic_false_ready.append(reply_ms)

        canary = ping_stats(canary_ping_path)
        has_delete = "received netlink DelLink" in log_segment and args.ifname in log_segment
        has_new = "received netlink NewLink" in log_segment and args.ifname in log_segment
        has_scoped_replay = any(
            "neutron_snapshot_apply_done" in line
            and 'scope="port"' in line
            and args.port_id in line
            for line in log_segment.splitlines()
        )
        tc_ingress = run([
            "docker", "exec", "aria_datapath", "/usr/sbin/tc",
            "filter", "show", "dev", args.ifname, "ingress"
        ], check=False).stdout
        tc_egress = run([
            "docker", "exec", "aria_datapath", "/usr/sbin/tc",
            "filter", "show", "dev", args.ifname, "egress"
        ], check=False).stdout
        with open(os.path.join(cycle_dir, "tc-ingress.txt"), "w") as stream:
            stream.write(tc_ingress)
        with open(os.path.join(cycle_dir, "tc-egress.txt"), "w") as stream:
            stream.write(tc_egress)

        final = uds_status(args.port_id)
        result = {
            "cycle": cycle,
            "cycle_started_ms": cycle_started,
            "old_ifindex": previous_ifindex,
            "new_ifindex": new_ifindex,
            "new_ifindex_seen_ms": new_ifindex_seen_ms,
            "ready_seen_ms": ready_seen_ms,
            "reattach_ms": (
                ready_seen_ms - new_ifindex_seen_ms
                if ready_seen_ms is not None and new_ifindex_seen_ms is not None else None
            ),
            "identity_false_ready_samples": len(identity_false_ready),
            "identity_unstable_samples": len([
                sample for sample in samples
                if sample.get("identity_stable") is False
            ]),
            "acl_probe_replies": len(acl_replies),
            "traffic_false_ready_replies": len(traffic_false_ready),
            "ovs_canary": canary,
            "netlink_delete_seen": has_delete,
            "netlink_new_seen": has_new,
            "single_port_replay_seen": has_scoped_replay,
            "tc_ingress_present": bool(tc_ingress.strip()),
            "tc_egress_present": bool(tc_egress.strip()),
            "final": final,
        }
        cycle_results.append(result)
        with open(os.path.join(cycle_dir, "result.json"), "w") as stream:
            json.dump(result, stream, indent=2, sort_keys=True)

        checks = [
            (new_ifindex is not None, "tap ifindex did not change"),
            (ready_seen_ms is not None, "replacement never reached ready/enforce"),
            (not identity_false_ready, "ready/enforce observed with stale or missing ifindex"),
            (not traffic_false_ready, "ACL traffic admitted while status was ready/enforce"),
            (canary["transmitted"] > 0 and canary["loss_percent"] == 0.0,
             "OVS canary lost packets"),
            (has_delete, "netlink DELLINK was not observed"),
            (has_new, "netlink NEWLINK was not observed"),
            (has_scoped_replay, "internal single-port replay was not observed"),
            (bool(tc_ingress.strip()), "TC ingress identity is missing"),
            (bool(tc_egress.strip()), "TC egress identity is missing"),
            (final.get("port_status") == "ready"
             and final.get("effective_action") == "enforce"
             and final.get("managed_ifindex") == new_ifindex,
             "final runtime status is not ready/enforce on replacement ifindex"),
        ]
        for passed, message in checks:
            if not passed:
                failures.append("cycle-%d: %s" % (cycle, message))

        old_ifindex = new_ifindex if new_ifindex is not None else read_ifindex(args.ifname)

    summary = {
        "result": "pass" if not failures else "fail",
        "failures": failures,
        "cycles": cycle_results,
    }
    with open(os.path.join(args.work_dir, "summary.json"), "w") as stream:
        json.dump(summary, stream, indent=2, sort_keys=True)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
PY

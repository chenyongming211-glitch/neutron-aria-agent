#!/usr/bin/env python3

import argparse
import json
import subprocess
import sys
import textwrap


def parse_packet_counts(value: str) -> list[int]:
    counts = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            count = int(part)
        except ValueError as exc:
            raise argparse.ArgumentTypeError(f"invalid packet count '{part}'") from exc
        if count <= 0:
            raise argparse.ArgumentTypeError("packet counts must be > 0")
        counts.append(count)
    if not counts:
        raise argparse.ArgumentTypeError("at least one packet count is required")
    return counts


def build_remote_script(config: dict) -> str:
    config_json = json.dumps(config, separators=(",", ":"))
    return textwrap.dedent(
        f"""\
        import json
        import socket
        import subprocess
        import sys
        import time
        import urllib.error
        import urllib.request

        CONFIG = json.loads({config_json!r})
        API_ROOT = f"http://{{CONFIG['api_host']}}:{{CONFIG['api_port']}}"
        TRACE_ROOT = API_ROOT + f"/api/v1/{{CONFIG['tap']}}"


        def run(cmd, check=True):
            proc = subprocess.run(cmd, text=True, capture_output=True)
            if check and proc.returncode != 0:
                raise RuntimeError(
                    f"command failed: {{cmd}}\\nstdout={{proc.stdout}}\\nstderr={{proc.stderr}}"
                )
            return proc


        def get_json(url, method="GET", payload=None, timeout=5.0):
            data = None
            headers = {{}}
            if payload is not None:
                data = json.dumps(payload).encode()
                headers["Content-Type"] = "application/json"
            req = urllib.request.Request(url, data=data, method=method, headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode())


        def list_instances():
            return get_json(API_ROOT + "/api/v1/instances")["instances"]


        def wait_for_instance():
            deadline = time.time() + CONFIG["setup_wait_secs"]
            while time.time() < deadline:
                try:
                    instances = list_instances()
                except Exception:
                    time.sleep(0.5)
                    continue
                for inst in instances:
                    if inst.get("name") == CONFIG["tap"] and inst.get("active"):
                        return
                time.sleep(0.5)
            raise RuntimeError(f"instance '{{CONFIG['tap']}}' did not register in time")


        def setup_tap():
            run(["ip", "link", "del", CONFIG["tap"]], check=False)
            run(["ip", "link", "del", CONFIG["peer"]], check=False)
            run(
                [
                    "ip",
                    "link",
                    "add",
                    CONFIG["tap"],
                    "type",
                    "veth",
                    "peer",
                    "name",
                    CONFIG["peer"],
                ]
            )
            run(["ip", "addr", "add", f"{{CONFIG['src_ip']}}/24", "dev", CONFIG["tap"]])
            run(["ip", "link", "set", CONFIG["tap"], "up"])
            run(["ip", "link", "set", CONFIG["peer"], "up"])
            with open(f"/sys/class/net/{{CONFIG['peer']}}/address", "r", encoding="utf-8") as fh:
                peer_mac = fh.read().strip()
            run(
                [
                    "ip",
                    "neigh",
                    "replace",
                    CONFIG["dst_ip"],
                    "lladdr",
                    peer_mac,
                    "nud",
                    "permanent",
                    "dev",
                    CONFIG["tap"],
                ]
            )


        def cleanup():
            try:
                get_json(TRACE_ROOT + "/trace", method="DELETE")
            except Exception:
                pass
            if CONFIG["cleanup_tap"]:
                run(["ip", "link", "del", CONFIG["tap"]], check=False)


        def iface_packets(name, direction):
            proc = run(["ip", "-j", "-s", "link", "show", "dev", name])
            stats = json.loads(proc.stdout)[0]["stats64"]
            return int(stats[direction]["packets"])


        def send_udp(src_ip, dst_ip, dst_port, count):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((src_ip, 0))
            sport = sock.getsockname()[1]
            for _ in range(count):
                sock.sendto(b"x", (dst_ip, dst_port))
            sock.close()
            return sport


        def trace_delete():
            try:
                get_json(TRACE_ROOT + "/trace", method="DELETE")
            except urllib.error.HTTPError as exc:
                if exc.code not in (400, 404):
                    raise


        def run_round(packet_count, round_index, dport, expected_flushed):
            trace_delete()
            flushed = get_json(TRACE_ROOT + "/trace/flush", method="DELETE")["flushed"]
            empty = len(get_json(TRACE_ROOT + f"/trace?top={{CONFIG['read_limit']}}")["events"])
            get_json(
                TRACE_ROOT + "/trace",
                method="POST",
                payload={{
                    "src_ip": CONFIG["src_ip"],
                    "dst_ip": CONFIG["dst_ip"],
                    "dst_port": dport,
                    "proto": "udp",
                }},
            )

            before_tx = iface_packets(CONFIG["tap"], "tx")
            before_peer_rx = iface_packets(CONFIG["peer"], "rx")
            sport = send_udp(CONFIG["src_ip"], CONFIG["dst_ip"], dport, packet_count)
            time.sleep(CONFIG["read_wait_secs"])
            after_tx = iface_packets(CONFIG["tap"], "tx")
            after_peer_rx = iface_packets(CONFIG["peer"], "rx")
            events = get_json(TRACE_ROOT + f"/trace?top={{CONFIG['read_limit']}}")["events"]

            seqs = [event["seq"] for event in events]
            count = len(events)
            unique = len(set(seqs))
            min_seq = min(seqs) if seqs else None
            max_seq = max(seqs) if seqs else None
            first_ct = events[-1]["ct_state"] if events else None
            last_ct = events[0]["ct_state"] if events else None
            tx_delta = after_tx - before_tx
            peer_rx_delta = after_peer_rx - before_peer_rx

            ok = (
                flushed == expected_flushed
                and empty == 0
                and count == packet_count
                and unique == packet_count
                and min_seq is not None
                and max_seq is not None
                and max_seq - min_seq + 1 == packet_count
                and first_ct == "new"
                and last_ct == "established"
            )

            return {{
                "packet_count": packet_count,
                "round": round_index,
                "dport": dport,
                "sport": sport,
                "flushed": flushed,
                "expected_flushed": expected_flushed,
                "empty": empty,
                "tx_delta": tx_delta,
                "peer_rx_delta": peer_rx_delta,
                "count": count,
                "unique": unique,
                "min_seq": min_seq,
                "max_seq": max_seq,
                "first_ct": first_ct,
                "last_ct": last_ct,
                "ok": ok,
            }}


        def main():
            results = []
            try:
                setup_tap()
                wait_for_instance()
                time.sleep(CONFIG["post_setup_wait_secs"])
                dport = CONFIG["dport_base"]
                previous_visible_count = 0
                for packet_count in CONFIG["packet_counts"]:
                    for round_index in range(1, CONFIG["rounds"] + 1):
                        result = run_round(
                            packet_count,
                            round_index,
                            dport,
                            previous_visible_count,
                        )
                        results.append(result)
                        previous_visible_count = result["count"]
                        dport += 1
                trace_delete()
                print(json.dumps({{"ok": all(item["ok"] for item in results), "results": results}}))
            finally:
                cleanup()


        if __name__ == "__main__":
            try:
                main()
            except Exception as exc:
                print(json.dumps({{"ok": False, "error": str(exc)}}))
                sys.exit(1)
        """
    )


def render_summary(payload: dict) -> int:
    if "error" in payload:
        print(f"remote error: {payload['error']}", file=sys.stderr)
        return 1

    results = payload.get("results", [])
    print(
        "packet round dport  flushed/exp empty tx peer count uniq seq-range first->last status"
    )
    for item in results:
        seq_range = (
            f"{item['min_seq']}..{item['max_seq']}"
            if item["min_seq"] is not None
            else "-"
        )
        state_range = f"{item['first_ct']}->{item['last_ct']}"
        status = "ok" if item["ok"] else "FAIL"
        print(
            f"{item['packet_count']:>6} "
            f"{item['round']:>5} "
            f"{item['dport']:>5} "
            f"{item['flushed']:>7}/{item['expected_flushed']:<7} "
            f"{item['empty']:>5} "
            f"{item['tx_delta']:>2} "
            f"{item['peer_rx_delta']:>4} "
            f"{item['count']:>5} "
            f"{item['unique']:>4} "
            f"{seq_range:>11} "
            f"{state_range:>17} "
            f"{status}"
        )

    return 0 if payload.get("ok") else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run remote perf trace first-read/flush regression checks over SSH."
    )
    parser.add_argument("--host", required=True, help="SSH target, e.g. root@118.195.135.53")
    parser.add_argument(
        "--packet-counts",
        default="5,200",
        type=parse_packet_counts,
        help="Comma-separated packet counts to validate exactly (default: 5,200)",
    )
    parser.add_argument("--rounds", type=int, default=5, help="Rounds per packet count")
    parser.add_argument("--tap", default="taptrace0", help="Managed tap name to create")
    parser.add_argument("--peer", default="peertrace0", help="Peer veth name")
    parser.add_argument("--src-ip", default="10.200.0.1", help="Source IPv4 on the managed tap")
    parser.add_argument("--dst-ip", default="10.200.0.2", help="Destination IPv4 on the peer side")
    parser.add_argument("--api-host", default="127.0.0.1", help="Remote aria-agent API host")
    parser.add_argument("--api-port", type=int, default=8080, help="Remote aria-agent API port")
    parser.add_argument("--dport-base", type=int, default=12000, help="Base UDP destination port")
    parser.add_argument(
        "--read-wait-secs",
        type=float,
        default=1.0,
        help="Seconds to wait between send and first /trace read",
    )
    parser.add_argument(
        "--setup-wait-secs",
        type=float,
        default=20.0,
        help="Seconds to wait for the managed tap to register",
    )
    parser.add_argument(
        "--post-setup-wait-secs",
        type=float,
        default=2.0,
        help="Extra settle time after instance registration before the first round",
    )
    parser.add_argument(
        "--keep-tap",
        action="store_true",
        help="Keep the temporary veth pair on the remote host after the run",
    )
    args = parser.parse_args()

    if args.rounds <= 0:
        print("--rounds must be > 0", file=sys.stderr)
        return 2

    max_packets = max(args.packet_counts)
    config = {
        "packet_counts": args.packet_counts,
        "rounds": args.rounds,
        "tap": args.tap,
        "peer": args.peer,
        "src_ip": args.src_ip,
        "dst_ip": args.dst_ip,
        "api_host": args.api_host,
        "api_port": args.api_port,
        "dport_base": args.dport_base,
        "read_wait_secs": args.read_wait_secs,
        "setup_wait_secs": args.setup_wait_secs,
        "post_setup_wait_secs": args.post_setup_wait_secs,
        "cleanup_tap": not args.keep_tap,
        "read_limit": max_packets + 64,
    }

    proc = subprocess.run(
        ["ssh", args.host, "python3", "-"],
        input=build_remote_script(config),
        text=True,
        capture_output=True,
    )

    if proc.stderr:
        sys.stderr.write(proc.stderr)

    if not proc.stdout.strip():
        print("remote script produced no JSON output", file=sys.stderr)
        return 1

    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        print(proc.stdout, file=sys.stderr)
        raise

    rc = render_summary(payload)
    if proc.returncode != 0 and rc == 0:
        return proc.returncode
    return rc


if __name__ == "__main__":
    raise SystemExit(main())

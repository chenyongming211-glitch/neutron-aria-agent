#!/usr/bin/env python3

import argparse
import json
import subprocess
import sys
import textwrap


SUPPORTED_CASES = (
    "system_vanished_iface",
    "system_preexisting_fq",
    "managed_crash_recovery_delink",
)


def parse_cases(value: str) -> list[str]:
    cases = []
    for part in value.split(","):
        case = part.strip()
        if not case:
            continue
        if case not in SUPPORTED_CASES:
            raise argparse.ArgumentTypeError(
                f"unsupported case '{case}', expected one of: {', '.join(SUPPORTED_CASES)}"
            )
        cases.append(case)
    if not cases:
        raise argparse.ArgumentTypeError("at least one case is required")
    return cases


def build_remote_script(config: dict) -> str:
    config_json = json.dumps(config, separators=(",", ":"))
    return textwrap.dedent(
        f"""\
        import json
        import os
        import subprocess
        import sys
        import time
        import urllib.request

        CONFIG = json.loads({config_json!r})
        API_ROOT = f"http://{{CONFIG['api_host']}}:{{CONFIG['api_port']}}"
        GLOBAL_PIN_PATH = "/sys/fs/bpf/aria/global-v2"
        SYSTEM_PIN_PATH = "/sys/fs/bpf/aria/system"
        SYSTEM_MARKER = "/var/lib/aria-agent/system/.fq-root-qdisc-owned"


        def run(cmd, check=True):
            proc = subprocess.run(cmd, text=True, capture_output=True)
            if check and proc.returncode != 0:
                raise RuntimeError(
                    f"command failed: {{cmd}}\\nstdout={{proc.stdout}}\\nstderr={{proc.stderr}}"
                )
            return proc


        def list_instances():
            with urllib.request.urlopen(API_ROOT + "/api/v1/instances", timeout=5) as resp:
                return json.loads(resp.read().decode())["instances"]


        def instance_names():
            return [inst.get("name") for inst in list_instances()]


        def wait_instance_active(name, timeout):
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    for inst in list_instances():
                        if inst.get("name") == name and inst.get("active"):
                            return True
                except Exception:
                    pass
                time.sleep(0.5)
            return False


        def wait_instance_absent(name, timeout):
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    names = instance_names()
                except Exception:
                    names = []
                if name not in names:
                    return True
                time.sleep(1.0)
            return False


        def wait_health_ok(timeout):
            deadline = time.time() + timeout
            while time.time() < deadline:
                proc = subprocess.run(
                    ["/usr/local/bin/ariactl", "health"],
                    text=True,
                    capture_output=True,
                )
                if proc.returncode == 0 and "Status:    ok" in proc.stdout:
                    return True
                time.sleep(0.5)
            return False


        def qdisc_show(dev):
            return run(["tc", "qdisc", "show", "dev", dev], check=False).stdout.strip()


        def cleanup_system_only():
            run(["/usr/local/bin/ariactl", "system", "stop"], check=False)
            run(["rm", "-f", SYSTEM_MARKER], check=False)


        def cleanup_link_pair(iface, peer):
            run(["ip", "link", "del", iface], check=False)
            run(["ip", "link", "del", peer], check=False)


        def create_veth_pair(iface, peer):
            cleanup_link_pair(iface, peer)
            run(["ip", "link", "add", iface, "type", "veth", "peer", "name", peer])
            run(["ip", "link", "set", iface, "up"])
            run(["ip", "link", "set", peer, "up"])


        def path_exists(path):
            return os.path.exists(path)


        def current_main_pid():
            return run(
                ["systemctl", "show", "-p", "MainPID", "--value", "aria-agent.service"]
            ).stdout.strip()


        def wait_new_pid(old_pid, timeout):
            deadline = time.time() + timeout
            while time.time() < deadline:
                pid = current_main_pid()
                if pid and pid != "0" and pid != old_pid:
                    return pid
                time.sleep(0.5)
            return None


        def cleanup_managed_runtime(iface, peer):
            cleanup_link_pair(iface, peer)
            run(["rm", "-rf", f"/var/lib/aria-agent/{{iface}}"], check=False)
            run(
                ["sh", "-c", f"rm -f /sys/fs/bpf/aria/global-v2/{{iface}}_* 2>/dev/null || true"],
                check=False,
            )


        def system_vanished_iface():
            iface = "sysgone0"
            peer = "peersysgone0"
            try:
                cleanup_system_only()
                cleanup_link_pair(iface, peer)
                create_veth_pair(iface, peer)
                run(
                    ["/usr/local/bin/ariactl", "system", "start", "--iface", iface],
                    check=True,
                )
                start_marker = path_exists(SYSTEM_MARKER)
                run(["ip", "link", "del", iface], check=False)
                stop = run(["/usr/local/bin/ariactl", "system", "stop"], check=False)
                stop_marker = path_exists(SYSTEM_MARKER)
                pin_exists = path_exists(SYSTEM_PIN_PATH)
                names = instance_names()
                ok = (
                    start_marker
                    and stop.returncode == 0
                    and not stop_marker
                    and not pin_exists
                    and "system" not in names
                )
                return {{
                    "case": "system_vanished_iface",
                    "ok": ok,
                    "start_marker": start_marker,
                    "stop_rc": stop.returncode,
                    "stop_marker": stop_marker,
                    "pin_exists": pin_exists,
                    "instances": names,
                }}
            finally:
                cleanup_system_only()
                cleanup_link_pair(iface, peer)


        def system_preexisting_fq():
            iface = "sysfqkeep0"
            peer = "peersysfqkeep0"
            try:
                cleanup_system_only()
                cleanup_link_pair(iface, peer)
                create_veth_pair(iface, peer)
                run(["tc", "qdisc", "replace", "dev", iface, "root", "fq"])
                before_qdisc = qdisc_show(iface)
                run(
                    ["/usr/local/bin/ariactl", "system", "start", "--iface", iface],
                    check=True,
                )
                marker_during = path_exists(SYSTEM_MARKER)
                start_qdisc = qdisc_show(iface)
                stop = run(["/usr/local/bin/ariactl", "system", "stop"], check=False)
                after_qdisc = qdisc_show(iface)
                marker_after = path_exists(SYSTEM_MARKER)
                names = instance_names()
                ok = (
                    "qdisc fq " in before_qdisc
                    and "qdisc fq " in start_qdisc
                    and stop.returncode == 0
                    and not marker_during
                    and not marker_after
                    and "qdisc fq " in after_qdisc
                    and "system" not in names
                )
                return {{
                    "case": "system_preexisting_fq",
                    "ok": ok,
                    "marker_during": marker_during,
                    "marker_after": marker_after,
                    "stop_rc": stop.returncode,
                    "before_qdisc": before_qdisc,
                    "start_qdisc": start_qdisc,
                    "after_qdisc": after_qdisc,
                    "instances": names,
                }}
            finally:
                cleanup_system_only()
                cleanup_link_pair(iface, peer)


        def managed_crash_recovery_delink():
            iface = "tapghost2"
            peer = "peerghost2"
            marker = f"/var/lib/aria-agent/{{iface}}/.fq-root-qdisc-owned"
            xdp_pin = f"{{GLOBAL_PIN_PATH}}/{{iface}}_xdp_link"
            tc_eg_pin = f"{{GLOBAL_PIN_PATH}}/{{iface}}_tc_egress_link"
            tc_ing_pin = f"{{GLOBAL_PIN_PATH}}/{{iface}}_tc_ingress_link"
            old_pid = None
            try:
                cleanup_system_only()
                cleanup_managed_runtime(iface, peer)
                create_veth_pair(iface, peer)
                if not wait_instance_active(iface, CONFIG["setup_wait_secs"]):
                    raise RuntimeError(f"instance '{{iface}}' did not become active")

                run(
                    [
                        "/usr/local/bin/ariactl",
                        "--tap",
                        iface,
                        "qos",
                        "add",
                        "--group",
                        "default",
                        "--direction",
                        "egress",
                        "--rate",
                        "100mbps",
                        "--mode",
                        "shaping",
                    ]
                )
                old_pid = current_main_pid()
                if not old_pid or old_pid == "0":
                    raise RuntimeError("could not read aria-agent MainPID")
                run(["kill", "-9", old_pid])
                time.sleep(1.0)

                run(["rm", "-f", tc_eg_pin, tc_ing_pin], check=False)
                run(["tc", "qdisc", "del", "dev", iface, "root"], check=False)

                new_pid = wait_new_pid(old_pid, CONFIG["restart_wait_secs"])
                if not new_pid:
                    raise RuntimeError("aria-agent did not restart with a new pid")
                if not wait_health_ok(CONFIG["restart_wait_secs"]):
                    raise RuntimeError("aria-agent did not become healthy after restart")
                if not wait_instance_active(iface, CONFIG["restart_wait_secs"]):
                    raise RuntimeError(f"instance '{{iface}}' did not recover active")

                recovered_pins = {{
                    "xdp": path_exists(xdp_pin),
                    "tc_eg": path_exists(tc_eg_pin),
                    "tc_ing": path_exists(tc_ing_pin),
                }}
                qdisc_after_recovery = qdisc_show(iface)
                marker_before_delete = path_exists(marker)

                run(["ip", "link", "del", iface], check=False)
                instance_absent = wait_instance_absent(iface, CONFIG["detach_wait_secs"])
                marker_after_delete = path_exists(marker)
                names = instance_names()

                ok = (
                    recovered_pins["xdp"]
                    and recovered_pins["tc_eg"]
                    and recovered_pins["tc_ing"]
                    and "qdisc fq " in qdisc_after_recovery
                    and marker_before_delete
                    and instance_absent
                    and not marker_after_delete
                    and iface not in names
                )
                return {{
                    "case": "managed_crash_recovery_delink",
                    "ok": ok,
                    "old_pid": old_pid,
                    "new_pid": new_pid,
                    "recovered_pins": recovered_pins,
                    "qdisc_after_recovery": qdisc_after_recovery,
                    "marker_before_delete": marker_before_delete,
                    "instance_absent_after_delete": instance_absent,
                    "marker_after_delete": marker_after_delete,
                    "instances": names,
                }}
            finally:
                run(["systemctl", "restart", "aria-agent"], check=False)
                time.sleep(2.0)
                cleanup_managed_runtime(iface, peer)


        def main():
            handlers = {{
                "system_vanished_iface": system_vanished_iface,
                "system_preexisting_fq": system_preexisting_fq,
                "managed_crash_recovery_delink": managed_crash_recovery_delink,
            }}
            results = []
            for case in CONFIG["cases"]:
                try:
                    results.append(handlers[case]())
                except Exception as exc:
                    results.append({{"case": case, "ok": False, "error": str(exc)}})
            print(json.dumps({{"ok": all(item.get("ok") for item in results), "results": results}}))


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
    print("case                              status details")
    for item in results:
        case = item.get("case", "-")
        status = "ok" if item.get("ok") else "FAIL"
        if case == "system_vanished_iface":
            details = (
                f"marker(start/stop)={item.get('start_marker')}/{item.get('stop_marker')} "
                f"pin_exists={item.get('pin_exists')} stop_rc={item.get('stop_rc')}"
            )
        elif case == "system_preexisting_fq":
            details = (
                f"marker(during/after)={item.get('marker_during')}/{item.get('marker_after')} "
                f"stop_rc={item.get('stop_rc')}"
            )
        elif case == "managed_crash_recovery_delink":
            pins = item.get("recovered_pins") or {}
            details = (
                f"pins=xdp:{pins.get('xdp')} eg:{pins.get('tc_eg')} ing:{pins.get('tc_ing')} "
                f"marker(before/after)={item.get('marker_before_delete')}/{item.get('marker_after_delete')} "
                f"absent={item.get('instance_absent_after_delete')}"
            )
        else:
            details = item.get("error", "-")
        print(f"{case:<33} {status:<6} {details}")

    return 0 if payload.get("ok") else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Run remote runtime lifecycle regressions for system and managed recovery paths."
    )
    parser.add_argument("--host", required=True, help="SSH target, e.g. root@118.195.135.53")
    parser.add_argument(
        "--cases",
        default="system_vanished_iface,system_preexisting_fq,managed_crash_recovery_delink",
        type=parse_cases,
        help=f"Comma-separated cases to run (default: {','.join(SUPPORTED_CASES)})",
    )
    parser.add_argument("--api-host", default="127.0.0.1", help="Remote aria-agent API host")
    parser.add_argument("--api-port", type=int, default=8080, help="Remote aria-agent API port")
    parser.add_argument(
        "--setup-wait-secs",
        type=float,
        default=20.0,
        help="Seconds to wait for a managed tap to register",
    )
    parser.add_argument(
        "--restart-wait-secs",
        type=float,
        default=30.0,
        help="Seconds to wait for aria-agent restart and managed recovery",
    )
    parser.add_argument(
        "--detach-wait-secs",
        type=float,
        default=10.0,
        help="Seconds to wait for a deleted managed tap to disappear from instances",
    )
    args = parser.parse_args()

    config = {
        "cases": args.cases,
        "api_host": args.api_host,
        "api_port": args.api_port,
        "setup_wait_secs": args.setup_wait_secs,
        "restart_wait_secs": args.restart_wait_secs,
        "detach_wait_secs": args.detach_wait_secs,
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

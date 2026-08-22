from __future__ import print_function

import json
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "openstack/neutron_aria"))
from neutron_aria.agent.state import SnapshotStateStore, desired_snapshot_hash


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "deploy/kolla/package/install_aria_joint_rc.sh"
DATAPATH_INSTALLER = ROOT / "deploy/kolla/package/install_aria_datapath_rc_image.sh"
AGENT_INSTALLER = ROOT / "deploy/kolla/package/install_neutron_aria_agent_rc_image.sh"
UPGRADE_CONTROL = ROOT / "deploy/kolla/package/aria_upgrade_control.py"

OLD_DP = "sha256:" + "1" * 64
OLD_AGENT = "sha256:" + "2" * 64
NEW_DP = "sha256:" + "3" * 64
NEW_AGENT = "sha256:" + "4" * 64
OLD_HASH = "a" * 64
NEW_HASH = "b" * 64


class KollaJointUpgradeTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.trace = self.root / "trace.log"
        self.phase = self.root / "release-state/operations/task7-op.json"
        self.api_state = self.root / "api-state"
        self.current_manifest = self.root / "current.json"
        self.candidate_manifest = self.root / "candidate.json"
        self.current_artifacts = self.root / "current-artifacts"
        self.candidate_artifacts = self.root / "candidate-artifacts"
        self.current_artifacts.mkdir()
        self.candidate_artifacts.mkdir()
        for directory, marker in (
            (self.current_artifacts, b"old"),
            (self.candidate_artifacts, b"new"),
        ):
            (directory / "aria-agent").write_bytes(marker + b"-agent")
            (directory / "libebpf_firewall.so").write_bytes(marker + b"-ebpf")
            (directory / "libebpf_firewall_perf.so").write_bytes(marker + b"-perf")
        self.current_manifest.write_text(json.dumps(self.manifest(
            OLD_AGENT, OLD_DP, self.current_artifacts, "1" * 40
        )), encoding="utf-8")
        self.candidate_manifest.write_text(json.dumps(self.manifest(
            NEW_AGENT, NEW_DP, self.candidate_artifacts, "2" * 40
        )), encoding="utf-8")
        self.make_fakes()

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def manifest(agent, datapath, artifact_root, source_commit):
        artifacts = []
        for name in ("aria-agent", "libebpf_firewall.so", "libebpf_firewall_perf.so"):
            payload = (artifact_root / name).read_bytes()
            artifacts.append({
                "name": name,
                "size_bytes": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
        return {
            "schema_version": 1,
            "product": "aria-firewall-neutron",
            "product_version": "0.9-test",
            "release_version": "v0.9-test",
            "source_commit": source_commit,
            "artifacts": artifacts,
            "contracts": {
                "runtime_compatibility_sha256": "e" * 64,
                "neutron_uds_sha256": "f" * 64,
                "support_matrix_sha256": "9" * 64,
            },
            "images": [
                {
                    "name": "neutron-aria-agent",
                    "identity": "registry/agent@%s" % agent,
                },
                {
                    "name": "aria-datapath",
                    "identity": "registry/datapath@%s" % datapath,
                },
            ],
            "runtime_compatibility": {
                "schema_version": 1,
                "uds_schema_min": 1,
                "uds_schema_max": 1,
                "snapshot_schema_version": 1,
                "ebpf_abi_version": 1,
                "map_schema_version": 1,
                "wal_schema_version": 1,
                "runtime_state_schema_version": 1,
                "minimum_kernel_profile": "el8-4.18",
                "managed_domain_contract_version": "acl-v1",
                "maintenance_gate_capable": False,
                "ebpf_abi_hash": "c" * 64,
                "map_schema_hash": "d" * 64,
            },
        }

    def write_executable(self, name, body):
        path = self.bin / name
        path.write_text(body, encoding="utf-8")
        path.chmod(path.stat().st_mode | stat.S_IXUSR)
        return path

    def make_fakes(self):
        self.write_executable(
            "docker",
            r'''#!/usr/bin/env bash
set -eu
printf 'docker %s\n' "$*" >>"$TRACE_FILE"
args=" $* "
case "$args" in
  *" image inspect -f {{.Id}} registry/datapath:current"*) printf '%s\n' "$OLD_DP" ;;
  *" image inspect -f {{.Id}} registry/datapath"*) printf '%s\n' "$NEW_DP" ;;
  *" image inspect -f {{.Id}} registry/agent"*) printf '%s\n' "$NEW_AGENT" ;;
  *" inspect -f {{.Image}} aria_datapath "*) if [ -f "$DP_IMAGE_STATE" ]; then cat "$DP_IMAGE_STATE"; else printf '%s\n' "$OLD_DP"; fi ;;
  *" inspect -f {{.Image}} neutron_aria_agent "*) if [ -f "$AGENT_IMAGE_STATE" ]; then cat "$AGENT_IMAGE_STATE"; else printf '%s\n' "$OLD_AGENT"; fi ;;
  *" inspect -f {{.State.Running}} neutron_aria_agent "*) printf 'true\n' ;;
  *" exec neutron_aria_agent python -c "*) shift 3; exec python "$@" ;;
  *" exec neutron_openvswitch_agent ovs-vsctl --no-wait get bridge br-int _uuid"*) printf 'br-int-test\n' ;;
  *" exec neutron_openvswitch_agent ovs-appctl -t ovs-vswitchd version"*)
    [ "${FAIL_AT:-}" != ovs_canary ] || [ ! -f "$API_STATE" ] || [ "$(cat "$API_STATE")" != bypass ] || exit 71
    printf 'ovs-vswitchd (Open vSwitch) 2.17.9\n' ;;
  *" inspect -f {{.Id}} neutron_openvswitch_agent "*) printf 'ovs-agent-id\n' ;;
  *" inspect -f {{.State.StartedAt}} neutron_openvswitch_agent "*) printf '2026-08-22T00:00:00Z\n' ;;
  *" inspect -f {{.State.Health.Status}} "*) printf 'healthy\n' ;;
  *" inspect -f {{if .State.Health}}"*) printf 'healthy\n' ;;
  *" inspect "*) printf '{}\n' ;;
esac
''',
        )
        self.write_executable(
            "curl",
            r'''#!/usr/bin/env python3
import json, os, sys

args = sys.argv[1:]
text = " ".join(args)
with open(os.environ["TRACE_FILE"], "a") as stream:
    stream.write("curl %s\n" % text)

def env(name, default=None):
    return os.environ.get(name, default)

def api_state():
    try:
        with open(os.environ["API_STATE"]) as stream:
            return stream.read().strip()
    except IOError:
        return "baseline"

def set_api_state(value):
    with open(os.environ["API_STATE"], "w") as stream:
        stream.write(value)

def emit(body):
    sys.stdout.write(json.dumps(body, sort_keys=True, separators=(",", ":")) + "\n")

def maintenance_state(phase, generation, desired_hash, active):
    return {
        "schema_version": 1,
        "operation_id": env("ADMIN_OPERATION_ID", env("OPERATION_ID")) if active else None,
        "phase": env("ADMIN_PHASE", phase),
        "active_domains": [env("ADMIN_DOMAIN", "acl")] if active else [],
        "expected_generation": int(env("ADMIN_EXPECTED_GENERATION", "41")) if active else 0,
        "expected_desired_hash": env("OLD_HASH") if active else None,
        "applied_generation": generation,
        "applied_desired_hash": desired_hash,
        "bypass_started_at_ms": 1 if active else None,
        "last_progress_at_ms": 2,
        "last_error": None,
    }

if "/maintenance/enter" in text:
    if env("FAIL_AT") == "enter":
        raise SystemExit(40)
    if "same_operation_rollback" in text:
        for required in (
            '"expected_applied_generation":41',
            '"expected_desired_hash":"%s"' % env("OLD_HASH"),
        ):
            if required not in text:
                raise SystemExit(94)
        set_api_state("resynced")
    else:
        set_api_state("bypass")
    emit({"status": "accepted", "accepted": True,
          "state": maintenance_state("maintenance_bypass", 41, env("OLD_HASH"), True)})
elif "/maintenance/exit" in text:
    if env("FAIL_AT") == "activation":
        raise SystemExit(43)
    for required in (
        '"operation_id":"%s"' % env("OPERATION_ID"),
        '"expected_applied_generation":42',
        '"expected_applied_desired_hash":"%s"' % env("NEW_HASH"),
    ):
        if required not in text:
            raise SystemExit(91)
    set_api_state("active")
    terminal = maintenance_state("committed", 42, env("NEW_HASH"), True)
    terminal["active_domains"] = []
    emit({"status": "committed", "accepted": True, "state": terminal})
elif "/api/v1/livez" in text or text.endswith("/livez"):
    emit({"service_liveness": "alive"})
elif text.endswith("/readyz"):
    emit({"overall_readiness": "ready"})
elif "/api/v1/admin/maintenance" in text:
    current = api_state()
    if current in ("bypass", "resynced"):
        generation = 42 if current == "resynced" else 41
        desired = env("NEW_HASH") if current == "resynced" else env("OLD_HASH")
        emit({"status": "active", "accepted": False,
              "state": maintenance_state("maintenance_bypass", generation, desired, True)})
    else:
        emit({"status": "ready", "accepted": False,
              "state": maintenance_state("ready", 42, env("NEW_HASH"), False)})
elif "/api/v1/neutron/status" in text:
    current = api_state()
    if current == "bypass" and env("FAIL_AT") == "after_bypass":
        raise SystemExit(41)
    resynced = current in ("resynced", "hot-resynced", "active")
    generation = int(env("SYNC_ACCEPTED", "42")) if resynced else 41
    applied = int(env("SYNC_APPLIED", str(generation))) if resynced else 41
    desired = env("SYNC_HASH", env("NEW_HASH")) if resynced else env("OLD_HASH")
    pending_text = env("SYNC_PENDING", "null") if resynced else (
        env("BYPASS_PENDING", "null") if current == "bypass" else "null"
    )
    pending = None if pending_text == "null" else int(pending_text)
    port_ids = [] if env("ZERO_PORTS", "false") == "true" else env(
        "SYNC_PORTS" if resynced else "BASELINE_PORTS", "tap-a,tap-b"
    ).split(",")
    port_ids = [item for item in port_ids if item]
    managed = [{"port_id": item, "ifname": item, "ifindex": index + 10,
                "managed_domains": ["acl"], "domain_desired_hashes": {"acl": desired}}
               for index, item in enumerate(port_ids)]
    port_status = env("SYNC_PORT_STATUS", "ready") if resynced else "ready"
    rows = [{"port_id": item, "ifname": item, "generation": applied,
             "desired_hash": desired, "status": port_status, "reason": None,
             "managed_domains": ["acl"], "domains": [{"domain": "acl",
             "status": port_status, "reason": None, "effective_action": "enforce",
             "support_disposition": env("SYNC_SUPPORT", "supported") if resynced else "supported"}]}
            for item in port_ids]
    maintenance = current in ("bypass", "resynced")
    emit({"status_schema_version": 4,
          "status_contract_hash": "v0.9-neutron-status-4",
          "transaction_state": "blocked" if maintenance else "ready",
          "overall_readiness": "degraded" if maintenance else "ready",
          "required_action": "complete_or_repair_maintenance" if maintenance else "none",
          "recovery_cause": None, "last_classified_generation": applied,
          "generation": generation, "accepted_generation": generation,
          "applied_generation": applied, "pending_generation": pending,
          "desired_hash": desired, "applied_desired_hash": desired,
          "wal_status": "committed", "wal_replay_failures": 0,
          "authority_state": "ready",
          "maintenance_phase": "maintenance_bypass" if maintenance else None,
          "maintenance_operation_id": env("STATUS_OPERATION_ID", env("OPERATION_ID")) if maintenance else None,
          "maintenance_reason": "planned_upgrade_bypass" if maintenance else None,
          "maintenance_action": "complete_or_repair_maintenance" if maintenance else None,
          "acl_enforcement": env("BYPASS_ACL_ENFORCEMENT", "bypass") if maintenance else "enforce",
          "managed_ports": managed, "port_statuses": rows,
          "active_instances": [item[0:15] for item in port_ids]})
else:
    raise SystemExit(88)
''',
        )
        self.write_executable(
            "pgrep",
            "#!/usr/bin/env bash\nprintf 'pgrep %s\\n' \"$*\" >>\"$TRACE_FILE\"\nprintf '9001\\n'\n",
        )
        self.write_executable(
            "id",
            "#!/usr/bin/env bash\nif [ \"${1:-}\" = -u ]; then printf '0\\n'; else exec /usr/bin/id \"$@\"; fi\n",
        )
        self.write_executable(
            "stat",
            "#!/usr/bin/env bash\ncase \"${2:-}\" in %u) printf '0\\n' ;; %a) printf '600\\n' ;; *) exit 2 ;; esac\n",
        )
        self.write_executable(
            "df",
            "#!/usr/bin/env bash\nprintf 'df %s\\n' \"$*\" >>\"$TRACE_FILE\"\nif [ \"${REALISTIC_DF:-false}\" = true ]; then printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n/dev/test 9999999 1000 %s 1%% /var/lib\\n' \"${DF_AVAILABLE:-1048576}\"; else printf '%s\\n' \"${DF_AVAILABLE:-1048576}\"; fi\n",
        )
        self.write_executable("flock", "#!/usr/bin/env bash\nprintf 'flock %s\\n' \"$*\" >>\"$TRACE_FILE\"\nexit 0\n")
        self.control_entrypoint = self.write_executable(
            "upgrade-control",
            '#!/usr/bin/env bash\nexec python3 "%s" "$@"\n' % UPGRADE_CONTROL,
        )
        component = r'''#!/usr/bin/env bash
set -eu
component=${0##*/}
case "$component" in *datapath*) component=datapath ;; *) component=agent ;; esac
action=${1:-}
printf '%s %s\n' "$component" "$action" >>"$TRACE_FILE"
[ "${FAIL_AT:-}" != "${component}_${action}" ] || exit 51
if [ "$component" = agent ] && [ "$action" = verify ]; then
  [ "${FAIL_AT:-}" != resync ] || exit 42
  if [ "${HOT_AGENT:-false}" = true ]; then printf hot-resynced >"$API_STATE"; else printf resynced >"$API_STATE"; fi
fi
if [ "$component" = agent ] && [ "$action" = resync-status ]; then
  ports=${SYNC_COMPLETION_PORTS:-${SYNC_PORTS:-tap-a,tap-b}}
  [ "${ZERO_PORTS:-false}" != true ] || ports=
  python3 - "$ports" <<'PY'
import json,os,sys
ports=[item for item in sys.argv[1].split(',') if item]
print(json.dumps({"schema_version":1,"operation_id":os.environ.get("SYNC_OPERATION_ID",os.environ["OPERATION_ID"]),"stable_read_attempts":int(os.environ.get("SYNC_STABLE_READS","2")),"stable_desired_hash":os.environ.get("SYNC_STABLE_HASH",os.environ["NEW_HASH"]),"completed_generation":int(os.environ.get("SYNC_APPLIED","42")),"completed_desired_hash":os.environ.get("SYNC_HASH",os.environ["NEW_HASH"]),"completed_managed_port_ids":ports,"buffer_overflow":os.environ.get("SYNC_BUFFER_OVERFLOW","false")=="true","foreign_host_ambiguity":os.environ.get("SYNC_FOREIGN","[]")!="[]","complete":True},sort_keys=True,separators=(",",":")))
PY
fi
if [ "$component" = datapath ] && [ "$action" = replace ]; then printf '%s\n' "$NEW_DP" >"$DP_IMAGE_STATE"; fi
if [ "$component" = agent ] && [ "$action" = replace ]; then printf '%s\n' "$NEW_AGENT" >"$AGENT_IMAGE_STATE"; fi
if [ "$component" = datapath ] && [ "$action" = restore ]; then printf '%s\n' "$OLD_DP" >"$DP_IMAGE_STATE"; fi
if [ "$component" = agent ] && [ "$action" = restore ]; then printf '%s\n' "$OLD_AGENT" >"$AGENT_IMAGE_STATE"; fi
if [ "$component" = agent ] && [ "$action" = restore ]; then printf resynced >"$API_STATE"; fi
'''
        self.datapath_fake = self.write_executable("datapath-installer", component)
        self.agent_fake = self.write_executable("agent-installer", component)

    def environment(self, classification="planned_maintenance", fail_at="", extra=None):
        env = os.environ.copy()
        env.update(
            {
                "PATH": str(self.bin) + os.pathsep + env.get("PATH", ""),
                "TRACE_FILE": str(self.trace),
                "API_STATE": str(self.api_state),
                "DP_IMAGE_STATE": str(self.root / "dp-image-state"),
                "AGENT_IMAGE_STATE": str(self.root / "agent-image-state"),
                "CURRENT_MANIFEST": str(self.current_manifest),
                "CANDIDATE_MANIFEST": str(self.candidate_manifest),
                "OPERATION_ID": "task7-op",
                "FAIL_AT": fail_at,
                "UPGRADE_CONTROL": str(self.control_entrypoint),
                "DATAPATH_INSTALLER": str(self.datapath_fake),
                "AGENT_INSTALLER": str(self.agent_fake),
                "JOINT_STATE_DIR": str(self.root / "release-state"),
                "JOINT_LOCK_PATH": str(self.root / "joint.lock"),
                "CURRENT_ARTIFACT_ROOT": str(self.current_artifacts),
                "CANDIDATE_ARTIFACT_ROOT": str(self.candidate_artifacts),
                "DATAPATH_IMAGE_REF": "registry/datapath:task7",
                "DATAPATH_EXPECTED_IMAGE_ID": NEW_DP,
                "AGENT_IMAGE_REF": "registry/agent:task7",
                "AGENT_EXPECTED_IMAGE_ID": NEW_AGENT,
                "ADMIN_SOCKET": str(self.root / "aria-admin.sock"),
                "NEUTRON_SOCKET": str(self.root / "aria-agent.sock"),
                "ROLLBACK_DATAPATH_CONFIG": str(self.root / "datapath.rollback"),
                "ROLLBACK_AGENT_CONFIG": str(self.root / "agent.rollback"),
                "CANDIDATE_DATAPATH_CONFIG": str(self.root / "datapath.candidate"),
                "CANDIDATE_AGENT_CONFIG": str(self.root / "agent.candidate"),
                "MIN_FREE_KIB": "1024",
                "NEW_DP": NEW_DP,
                "NEW_AGENT": NEW_AGENT,
                "OLD_DP": OLD_DP,
                "OLD_AGENT": OLD_AGENT,
                "OLD_HASH": OLD_HASH,
                "NEW_HASH": NEW_HASH,
                "ARIA_JOINT_ALLOW_UNPRIVILEGED": "true",
            }
        )
        if classification == "hot_agent":
            candidate = self.manifest(NEW_AGENT, OLD_DP, self.candidate_artifacts, "2" * 40)
            self.candidate_manifest.write_text(json.dumps(candidate), encoding="utf-8")
            env["DATAPATH_IMAGE_REF"] = "registry/datapath:current"
            env["DATAPATH_EXPECTED_IMAGE_ID"] = OLD_DP
            env["HOT_AGENT"] = "true"
        for path in (
            env["ADMIN_SOCKET"],
            env["NEUTRON_SOCKET"],
            env["ROLLBACK_DATAPATH_CONFIG"],
            env["ROLLBACK_AGENT_CONFIG"],
            env["CANDIDATE_DATAPATH_CONFIG"],
            env["CANDIDATE_AGENT_CONFIG"],
        ):
            Path(path).touch()
        env.update(extra or {})
        return env

    def phase_value(self):
        if not self.phase.exists():
            return "<missing-ledger>"
        return json.loads(self.phase.read_text(encoding="utf-8"))["phase"]

    def reset_operation(self):
        shutil.rmtree(self.root / "release-state", ignore_errors=True)
        self.api_state.unlink(missing_ok=True)
        (self.root / "dp-image-state").unlink(missing_ok=True)
        (self.root / "agent-image-state").unlink(missing_ok=True)
        self.trace.unlink(missing_ok=True)

    @staticmethod
    def _config_pair_hash(*paths):
        digest = hashlib.sha256()
        for path in paths:
            digest.update(Path(path).read_bytes())
            digest.update(b"\0")
        return digest.hexdigest()

    def seed_ledger_phase(
        self, phase, classification="planned_maintenance",
        live_datapath=None, live_agent=None, api_state="baseline",
    ):
        env = self.environment(classification)
        candidate_datapath = OLD_DP if classification == "hot_agent" else NEW_DP
        evidence = {
            "affected_domains": ["acl"],
            "old_image_ids": {"aria-datapath": OLD_DP,
                              "neutron-aria-agent": OLD_AGENT},
            "candidate_image_ids": {"aria-datapath": candidate_datapath,
                                    "neutron-aria-agent": NEW_AGENT},
            "old_manifest_hash": hashlib.sha256(
                self.current_manifest.read_bytes()).hexdigest(),
            "candidate_manifest_hash": hashlib.sha256(
                self.candidate_manifest.read_bytes()).hexdigest(),
            "old_config_hash": self._config_pair_hash(
                env["ROLLBACK_DATAPATH_CONFIG"], env["ROLLBACK_AGENT_CONFIG"]),
            "candidate_config_hash": self._config_pair_hash(
                env["CANDIDATE_DATAPATH_CONFIG"], env["CANDIDATE_AGENT_CONFIG"]),
            "pre_accepted_generation": 41,
            "pre_applied_generation": 41,
            "pre_desired_hash": OLD_HASH,
            "pre_managed_port_ids": ["tap-a", "tap-b"],
            "ovs_vswitchd_pid": 9001,
            "ovs_agent_container_id": "ovs-agent-id",
            "ovs_agent_started_at": "2026-08-22T00:00:00Z",
            "br_int_uuid": "br-int-test",
        }
        env.update({
            "ARIA_RELEASE_OPERATIONS_DIR": str(
                self.root / "release-state/operations"),
            "ARIA_RELEASE_LOCK_PATH": str(self.root / "joint.lock.ledger"),
        })
        begin = [str(self.control_entrypoint), "ledger", "begin", "task7-op",
                 "compute-1", classification, json.dumps(evidence)]
        subprocess.run(begin, env=env, check=True, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, text=True)
        paths = {
            "planned_maintenance": [
                "preflight", "quiescing", "bypass_preparing",
                "bypass_confirmed", "datapath_upgrading", "datapath_live",
                "agent_upgrading", "agent_buffering", "full_resync",
                "shadow_apply", "activating", "verifying", "committed",
            ],
            "hot_agent": [
                "preflight", "agent_upgrading", "agent_buffering",
                "full_resync", "shadow_apply", "activating", "verifying",
                "committed",
            ],
        }[classification]
        self.assertIn(phase, paths)
        for old_phase, next_phase in zip(paths, paths[1:]):
            if old_phase == phase:
                break
            transition = [str(self.control_entrypoint), "ledger", "transition",
                          old_phase, next_phase, "task7-op", "{}"]
            subprocess.run(transition, env=env, check=True,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True)
            if next_phase == phase:
                break
        if live_datapath is not None:
            (self.root / "dp-image-state").write_text(live_datapath,
                                                       encoding="utf-8")
        if live_agent is not None:
            (self.root / "agent-image-state").write_text(live_agent,
                                                          encoding="utf-8")
        if api_state != "baseline":
            self.api_state.write_text(api_state, encoding="utf-8")

    def run_joint(
        self, action, classification="planned_maintenance", fail_at="", expected=0,
        extra=None,
    ):
        self.assertTrue(INSTALLER.is_file(), "joint installer is absent")
        result = subprocess.run(
            ["bash", str(INSTALLER), action],
            cwd=str(ROOT),
            env=self.environment(classification, fail_at, extra),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(
            expected,
            result.returncode,
            "stdout:\n%s\nstderr:\n%s\ntrace:\n%s"
            % (result.stdout, result.stderr, self.read_trace()),
        )
        return result

    def read_trace(self):
        return self.trace.read_text(encoding="utf-8") if self.trace.exists() else ""

    def test_operator_and_component_action_contracts_are_exposed(self):
        self.assertTrue(INSTALLER.is_file(), "joint installer is absent")
        source = INSTALLER.read_text(encoding="utf-8")
        for action in ("dry-run", "install", "status", "resume", "rollback", "check"):
            self.assertIn(action, source)
        for path in (DATAPATH_INSTALLER, AGENT_INSTALLER):
            component_source = path.read_text(encoding="utf-8")
            for action in ("prepare", "replace", "verify", "restore"):
                self.assertIn(action, component_source)
        self.assertIn(
            "resync-status", AGENT_INSTALLER.read_text(encoding="utf-8")
        )

    def test_planned_upgrade_orders_bypass_replacements_resync_and_one_activation(self):
        self.run_joint("install")
        trace = self.read_trace()
        ordered = (
            "datapath prepare",
            "agent prepare",
            "/maintenance/enter",
            "/api/v1/admin/maintenance",
            "ovs-appctl -t ovs-vswitchd version",
            "datapath replace",
            "datapath verify",
            "agent replace",
            "agent verify",
            "agent resync-status",
            "/maintenance/exit",
        )
        offset = -1
        for item in ordered:
            next_offset = trace.find(item, offset + 1)
            self.assertGreater(next_offset, offset, trace)
            offset = next_offset
        self.assertEqual(1, trace.count("/maintenance/exit"), trace)
        self.assertNotIn("/api/v1/admin/full-resync", trace)
        self.assertNotIn("http://localhost/status", trace)
        self.assertIn("http://localhost/api/v1/neutron/status", trace)
        self.assertIn('"expected_applied_generation":42', trace)
        self.assertIn('"expected_applied_desired_hash":"%s"' % NEW_HASH, trace)
        self.assertIn("docker inspect -f {{.State.Health.Status}} aria_datapath", trace)
        self.assertIn("docker inspect -f {{.State.Health.Status}} neutron_aria_agent", trace)
        self.assertEqual("committed", self.phase_value())

    def test_all_required_failure_boundaries_persist_safe_phase(self):
        cases = (
            ("datapath_prepare", "failed_before_mutation"),
            ("after_bypass", "bypass_preparing"),
            ("datapath_replace", "maintenance_bypass"),
            ("datapath_verify", "maintenance_bypass"),
            ("agent_replace", "maintenance_bypass"),
            ("agent_verify", "maintenance_bypass"),
            ("resync", "maintenance_bypass"),
            ("activation", "maintenance_bypass"),
        )
        for fail_at, phase in cases:
            with self.subTest(fail_at=fail_at):
                self.reset_operation()
                self.run_joint("install", fail_at=fail_at, expected=1)
                self.assertEqual(phase, self.phase_value())
                trace = self.read_trace()
                self.assertNotIn("docker restart", trace)
                if phase == "maintenance_bypass" and fail_at != "activation":
                    self.assertNotIn("/maintenance/exit", trace)
                if fail_at == "activation":
                    self.assertEqual(1, trace.count("/maintenance/exit"), trace)

    def test_unproven_bypass_never_allows_datapath_mutation_or_claims_safe_bypass(self):
        cases = (
            ("admin-operation", {"ADMIN_OPERATION_ID": "foreign-op"}),
            ("admin-domain", {"ADMIN_DOMAIN": "qos"}),
            ("admin-phase", {"ADMIN_PHASE": "gate_unknown"}),
            ("admin-generation", {"ADMIN_EXPECTED_GENERATION": "40"}),
            ("status-operation", {"STATUS_OPERATION_ID": "foreign-op"}),
            ("enforcement", {"BYPASS_ACL_ENFORCEMENT": "unknown"}),
            ("pending", {"BYPASS_PENDING": "43"}),
            ("canary", {"FAIL_AT": "ovs_canary"}),
        )
        for label, extra in cases:
            with self.subTest(boundary=label):
                self.reset_operation()
                self.run_joint("install", expected=1, extra=extra)
                self.assertEqual("bypass_preparing", self.phase_value())
                trace = self.read_trace()
                self.assertNotIn("datapath replace", trace)
                self.assertNotIn("/maintenance/exit", trace)

    def test_activation_requires_exact_stable_complete_same_operation_status(self):
        cases = (
            ("operation", {"SYNC_OPERATION_ID": "sync-7"}),
            ("accepted", {"SYNC_ACCEPTED": "41"}),
            ("applied", {"SYNC_APPLIED": "41"}),
            ("pending", {"SYNC_PENDING": "43"}),
            ("hash", {"SYNC_HASH": OLD_HASH}),
            ("stable-hash", {"SYNC_STABLE_HASH": OLD_HASH}),
            ("stable-proof", {"SYNC_STABLE_READS": "0"}),
            ("buffer-overflow", {"SYNC_BUFFER_OVERFLOW": "true"}),
            ("unsupported", {"SYNC_SUPPORT": "unsupported"}),
            ("foreign-host", {"SYNC_FOREIGN": '["tap-y"]'}),
            ("port-incomplete", {"SYNC_PORT_STATUS": "pending"}),
            ("completion-port-mismatch", {"SYNC_PORTS": "tap-a,tap-c",
                                           "SYNC_COMPLETION_PORTS": "tap-a"}),
        )
        for label, extra in cases:
            with self.subTest(boundary=label):
                self.reset_operation()
                self.run_joint("install", expected=1, extra=extra)
                self.assertEqual("maintenance_bypass", self.phase_value())
                trace = self.read_trace()
                self.assertIn("agent verify", trace)
                self.assertNotIn("/maintenance/exit", trace)

    def test_real_ledger_preserves_upgrade_class_and_bound_artifacts(self):
        self.run_joint("install", fail_at="resync", expected=1)
        self.assertTrue(self.phase.exists(),
                        "real-contract preflight never created the ledger")
        state = json.loads(self.phase.read_text(encoding="utf-8"))
        self.assertEqual("planned_maintenance", state["upgrade_class"])
        self.assertEqual(OLD_DP, state["old_image_ids"]["aria-datapath"])
        self.assertEqual(NEW_DP, state["candidate_image_ids"]["aria-datapath"])
        self.assertEqual(
            hashlib.sha256(self.current_manifest.read_bytes()).hexdigest(),
            state["old_manifest_hash"],
        )
        self.assertEqual(
            hashlib.sha256(self.candidate_manifest.read_bytes()).hexdigest(),
            state["candidate_manifest_hash"],
        )

    def test_preflight_parses_df_available_column(self):
        self.run_joint("dry-run", extra={"REALISTIC_DF": "true"})
        self.reset_operation()
        result = self.run_joint(
            "dry-run", expected=1,
            extra={"REALISTIC_DF": "true", "DF_AVAILABLE": "100"},
        )
        self.assertIn("insufficient release-state disk space", result.stderr)

    def test_resume_from_maintenance_restarts_at_resync_without_replacement(self):
        self.run_joint("install", fail_at="resync", expected=1)
        before = self.read_trace()
        self.trace.write_text("", encoding="utf-8")
        self.api_state.write_text("resynced", encoding="utf-8")
        self.run_joint("resume")
        resumed = self.read_trace()
        self.assertGreaterEqual(
            resumed.count("http://localhost/api/v1/neutron/status"), 2
        )
        self.assertNotIn("/api/v1/admin/full-resync", resumed)
        self.assertIn("/maintenance/exit", resumed)
        self.assertNotIn(" replace", resumed)
        self.assertEqual("committed", self.phase_value())
        self.assertNotIn("/maintenance/exit", before)

    def test_resume_branches_on_exact_durable_phase_class_and_live_state(self):
        cases = (
            ("planned_maintenance", "quiescing", OLD_DP, OLD_AGENT,
             "baseline", "datapath replace"),
            ("planned_maintenance", "agent_buffering", NEW_DP, NEW_AGENT,
             "resynced", None),
            ("hot_agent", "agent_upgrading", OLD_DP, OLD_AGENT,
             "baseline", "agent replace"),
            ("hot_agent", "agent_buffering", OLD_DP, NEW_AGENT,
             "hot-resynced", None),
        )
        for upgrade_class, phase, live_dp, live_agent, api_state, replacement in cases:
            with self.subTest(upgrade_class=upgrade_class, phase=phase):
                self.reset_operation()
                self.seed_ledger_phase(
                    phase, classification=upgrade_class,
                    live_datapath=live_dp, live_agent=live_agent,
                    api_state=api_state,
                )
                self.trace.write_text("", encoding="utf-8")
                self.run_joint("resume", classification=upgrade_class)
                trace = self.read_trace()
                if replacement is None:
                    self.assertNotIn(" replace", trace)
                else:
                    self.assertIn(replacement, trace)
                if upgrade_class == "hot_agent":
                    self.assertNotIn("/maintenance/enter", trace)
                    self.assertNotIn("/maintenance/exit", trace)
                self.assertEqual("committed", self.phase_value())

    def test_convergence_uses_current_authoritative_ports_and_allows_empty_host(self):
        for label, extra in (
            ("added-and-migrated", {"SYNC_PORTS": "tap-b,tap-c"}),
            ("empty-host", {"ZERO_PORTS": "true"}),
        ):
            with self.subTest(case=label):
                self.reset_operation()
                self.run_joint("install", extra=extra)
                self.assertEqual("committed", self.phase_value())

    def test_ovs_identity_probe_is_fixed_bounded_and_not_caller_executable(self):
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertNotIn("OVS_CANARY_COMMAND", source)
        self.assertNotIn("/bin/true", source)
        self.run_joint("install")
        trace = self.read_trace()
        probe = (
            "docker exec neutron_openvswitch_agent "
            "ovs-appctl -t ovs-vswitchd version"
        )
        self.assertGreaterEqual(trace.count(probe), 10, trace)
        self.assertNotIn("ovs-canary", trace)

    def test_core_rollback_restores_both_components_then_rebuilds_current_policy(self):
        self.run_joint("install", fail_at="resync", expected=1)
        self.trace.write_text("", encoding="utf-8")
        self.run_joint("rollback")
        trace = self.read_trace()
        order = (
            "/maintenance/enter",
            "datapath restore",
            "agent restore",
            "/api/v1/neutron/status",
            "/maintenance/exit",
        )
        offset = -1
        for item in order:
            next_offset = trace.find(item, offset + 1)
            self.assertGreater(next_offset, offset, trace)
            offset = next_offset
        self.assertEqual("committed", self.phase_value())

    def test_core_rollback_accepts_each_ledger_bound_live_image_combination(self):
        cases = (
            ("both-auto-restored", "datapath_replace", OLD_DP, OLD_AGENT,
             False, False),
            ("agent-auto-restored", "agent_replace", NEW_DP, OLD_AGENT,
             True, False),
            ("datapath-auto-restored", "resync", OLD_DP, NEW_AGENT,
             False, True),
            ("both-candidates", "resync", NEW_DP, NEW_AGENT, True, True),
        )
        for label, fail_at, live_dp, live_agent, restore_dp, restore_agent in cases:
            with self.subTest(case=label):
                self.reset_operation()
                self.run_joint("install", fail_at=fail_at, expected=1)
                (self.root / "dp-image-state").write_text(live_dp, encoding="utf-8")
                (self.root / "agent-image-state").write_text(live_agent,
                                                               encoding="utf-8")
                self.trace.write_text("", encoding="utf-8")
                self.run_joint("rollback")
                trace = self.read_trace()
                self.assertEqual(restore_dp, "datapath restore" in trace)
                self.assertEqual(restore_agent, "agent restore" in trace)
                self.assertIn('"expected_applied_generation":41', trace)
                self.assertIn(
                    '"expected_desired_hash":"%s"' % OLD_HASH, trace
                )
                self.assertLess(
                    trace.index("/api/v1/admin/maintenance"),
                    trace.index(" restore") if " restore" in trace
                    else trace.index("/api/v1/neutron/status"),
                )
                self.assertEqual("committed", self.phase_value())

    def test_rollback_failure_stays_in_explicit_maintenance_bypass(self):
        self.run_joint("install", fail_at="resync", expected=1)
        self.trace.write_text("", encoding="utf-8")
        self.run_joint("rollback", fail_at="datapath_restore", expected=1)
        self.assertEqual("maintenance_bypass", self.phase_value())
        self.assertNotIn("/maintenance/exit", self.read_trace())

    def test_compatible_agent_only_path_preserves_datapath_and_skips_bypass(self):
        self.run_joint("install", classification="hot_agent")
        trace = self.read_trace()
        self.assertIn("agent prepare", trace)
        self.assertIn("agent replace", trace)
        self.assertIn("agent verify", trace)
        self.assertGreaterEqual(
            trace.count("http://localhost/api/v1/neutron/status"), 3
        )
        self.assertNotIn("/api/v1/admin/full-resync", trace)
        self.assertNotIn("datapath replace", trace)
        self.assertNotIn("/maintenance/enter", trace)
        self.assertNotIn("/maintenance/exit", trace)
        self.assertEqual("committed", self.phase_value())

    def test_trace_proves_immutable_preflight_and_ovs_non_interference(self):
        self.run_joint("dry-run")
        trace = self.read_trace()
        for evidence in (
            "docker image inspect -f {{.Id}} registry/datapath:task7",
            "docker image inspect -f {{.Id}} registry/agent:task7",
            "docker inspect -f {{.Image}} aria_datapath",
            "docker inspect -f {{.Image}} neutron_aria_agent",
            "docker inspect -f {{.Id}} neutron_openvswitch_agent",
            "docker inspect -f {{.State.StartedAt}} neutron_openvswitch_agent",
            "pgrep -xo ovs-vswitchd",
            "df",
        ):
            self.assertIn(evidence, trace)
        forbidden = (
            "docker restart",
            "docker stop neutron_openvswitch_agent",
            "docker rm neutron_openvswitch_agent",
            "ovs-vsctl del-port",
            "ovs-vsctl set",
            "ovs-vsctl clear",
        )
        for invocation in forbidden:
            self.assertNotIn(invocation, trace)
        for path in (INSTALLER, DATAPATH_INSTALLER, AGENT_INSTALLER):
            source = path.read_text(encoding="utf-8")
            self.assertNotRegex(
                source,
                r"docker\s+(?:restart|stop|rm|rename)\s+"
                r"(?:neutron_openvswitch_agent|\$\{?OVS_AGENT_SERVICE\}?)",
            )
            self.assertNotRegex(
                source,
                r"ovs-vsctl(?:\s+--[^ ]+)*\s+"
                r"(?:add-port|del-port|set|clear|create|destroy)",
            )
        self.assertNotIn("cleanup", INSTALLER.read_text(encoding="utf-8").lower())

    def test_joint_coordinator_uses_fd_lock_and_never_masks_ledger_failure(self):
        source = INSTALLER.read_text(encoding="utf-8")
        self.assertRegex(source, r'exec\s+[0-9]+>"\$\{JOINT_LOCK_PATH\}"')
        self.assertRegex(source, r'flock\s+-n\s+[0-9]+')
        self.assertNotIn('"${JOINT_LOCK_PATH}.held"', source)
        self.assertNotRegex(source, r'ledger\s+fail[^\n]*(?:\|\|\s*true|\|\|\s*:)')

    def test_component_verifier_uses_root_admin_socket_and_typed_json(self):
        self.api_state.write_text("bypass", encoding="utf-8")
        env = self.environment()
        body = '''
ARIA_INSTALLER_LIBRARY_ONLY=true
. "%s"
JOINT_MAINTENANCE_MODE=true
ADMIN_SOCKET="%s"
OPERATION_ID=task7-op
verify_candidate_convergence
''' % (DATAPATH_INSTALLER, self.root / "aria-admin.sock")
        result = subprocess.run(
            ["bash", "-c", body], cwd=str(ROOT), env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.assertEqual(0, result.returncode, result.stderr + self.read_trace())
        trace = self.read_trace()
        self.assertIn("/api/v1/admin/maintenance", trace)
        self.assertNotIn("docker exec -u neutron", trace)
        self.assertNotIn("grep", trace)

    def test_agent_resync_status_entrypoint_reads_operation_bound_completion(self):
        runtime = self.root / "runtime-state"
        store = SnapshotStateStore(str(runtime))
        snapshot = {"host": "compute-1", "ports": [],
                    "maintenance_operation_id": "task7-op"}
        desired_hash = desired_snapshot_hash(snapshot)
        store.record_maintenance_progress("task7-op", 1, desired_hash)
        prepared = store.prepare_snapshot(snapshot)
        store.commit_snapshot(prepared["generation"], prepared["desired_hash"])
        store.record_maintenance_completion(
            "task7-op", prepared["generation"], prepared["desired_hash"], []
        )
        release_state = self.root / "agent-release"
        release_state.mkdir()
        state_file = release_state / "active.env"
        state_file.write_text("\n".join((
            "IMAGE_REF=registry/agent:task7",
            "OPERATION_ID=task7-op",
            "EXPECTED_IMAGE_ID=%s" % NEW_AGENT,
            "BACKUP_CONTAINER=neutron_aria_agent_pre_rc_test",
            "BACKUP_IMAGE_ID=%s" % OLD_AGENT,
            "BACKUP_IMAGE_REF=registry/agent:old",
            "SERVICE_HOSTNAME=compute-1",
            "DATAPATH_ID=datapath-id",
            "DATAPATH_STARTED=2026-08-22T00:00:00Z",
            "OVS_AGENT_ID=ovs-agent-id",
            "OVS_AGENT_STARTED=2026-08-22T00:00:00Z",
            "RUNTIME_STATE_SOURCE=%s" % runtime,
            "CONTAINER_STATE_DIR=%s" % runtime,
            "",
        )), encoding="utf-8")
        state_file.chmod(0o600)
        env = self.environment()
        env.update({
            "STATE_DIR": str(release_state),
            "STATE_FILE": str(state_file),
            "CONTAINER_STATE_DIR": str(runtime),
            "PYTHONPATH": str(ROOT / "openstack/neutron_aria"),
        })
        result = subprocess.run(
            ["bash", str(AGENT_INSTALLER), "resync-status"], env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        self.assertEqual(0, result.returncode, result.stderr + self.read_trace())
        progress = json.loads(result.stdout)
        self.assertEqual("task7-op", progress["operation_id"])
        self.assertTrue(progress["complete"])
        self.assertEqual([], progress["completed_managed_port_ids"])

    def test_datapath_suite_does_not_reexport_joint_testcase(self):
        source = (ROOT / "ci/test_kolla_datapath_runtime_upgrade.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("KollaJointUpgradeTest", source)


if __name__ == "__main__":
    unittest.main()

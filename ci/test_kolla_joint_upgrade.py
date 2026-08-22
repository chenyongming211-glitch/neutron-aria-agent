from __future__ import print_function

import json
import hashlib
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


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
        for name in ("aria-agent", "libebpf_firewall.so"):
            payload = (artifact_root / name).read_bytes()
            artifacts.append({
                "name": name,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
            })
        return {
            "release_version": "v0.9-test",
            "source_commit": source_commit,
            "artifacts": artifacts,
            "contracts": {
                "runtime_compatibility_sha256": "e" * 64,
                "uds_contract_sha256": "f" * 64,
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
  *" inspect -f {{.Image}} aria_datapath "*) printf '%s\n' "$OLD_DP" ;;
  *" inspect -f {{.Image}} neutron_aria_agent "*) printf '%s\n' "$OLD_AGENT" ;;
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
            r'''#!/usr/bin/env bash
set -eu
printf 'curl %s\n' "$*" >>"$TRACE_FILE"
args=" $* "
if [[ "$args" == *"/maintenance/enter"* ]]; then
  [ "${FAIL_AT:-}" != enter ] || exit 40
  printf bypass >"$API_STATE"
  printf '{"status":"accepted","accepted":true,"state":{"schema_version":1,"operation_id":"%s","phase":"maintenance_bypass","active_domains":["acl"],"expected_applied_generation":41,"expected_desired_hash":"%s","applied_generation":41,"applied_desired_hash":"%s","entered_at":1,"updated_at":2,"last_error":null}}\n' "$OPERATION_ID" "$OLD_HASH" "$OLD_HASH"
elif [[ "$args" == *"/maintenance/exit"* ]]; then
  [ "${FAIL_AT:-}" != activation ] || exit 43
  [[ "$args" == *'"operation_id":"'"$OPERATION_ID"'"'* ]] || exit 91
  [[ "$args" == *'"expected_applied_generation":42'* ]] || exit 92
  [[ "$args" == *'"expected_applied_desired_hash":"'"$NEW_HASH"'"'* ]] || exit 93
  printf active >"$API_STATE"
  printf '{"status":"committed","accepted":true,"state":{"schema_version":1,"operation_id":"%s","phase":"committed","active_domains":[],"expected_applied_generation":42,"expected_desired_hash":"%s","applied_generation":42,"applied_desired_hash":"%s","entered_at":1,"updated_at":3,"last_error":null}}\n' "$OPERATION_ID" "$NEW_HASH" "$NEW_HASH"
elif [[ "$args" == *"/api/v1/livez"* || "$args" == *"/livez"* ]]; then
  printf '{"service_liveness":"alive"}\n'
elif [[ "$args" == *"/readyz"* ]]; then
  printf '{"overall_readiness":"ready"}\n'
elif [[ "$args" == *"/api/v1/admin/maintenance"* ]]; then
  state=baseline
  [ ! -f "$API_STATE" ] || state=$(cat "$API_STATE")
  if [ "$state" = bypass ] || [ "$state" = resynced ]; then
    printf '{"status":"active","accepted":true,"state":{"schema_version":1,"operation_id":"%s","phase":"%s","active_domains":["%s"],"expected_applied_generation":41,"expected_desired_hash":"%s","applied_generation":41,"applied_desired_hash":"%s","entered_at":1,"updated_at":2,"last_error":null}}\n' "${ADMIN_OPERATION_ID:-$OPERATION_ID}" "${ADMIN_PHASE:-maintenance_bypass}" "${ADMIN_DOMAIN:-acl}" "$OLD_HASH" "$OLD_HASH"
  else
    printf '{"status":"ready","accepted":true,"state":{"schema_version":1,"operation_id":null,"phase":"ready","active_domains":[],"expected_applied_generation":null,"expected_desired_hash":null,"applied_generation":42,"applied_desired_hash":"%s","entered_at":null,"updated_at":3,"last_error":null}}\n' "$NEW_HASH"
  fi
else
  state=baseline
  [ ! -f "$API_STATE" ] || state=$(cat "$API_STATE")
  if [ "$state" = bypass ] && [ "${FAIL_AT:-}" = after_bypass ]; then exit 41; fi
  if [ "$state" = baseline ]; then
    printf '{"accepted_generation":41,"applied_generation":41,"pending_generation":null,"desired_hash":"%s","last_desired_hash":"%s","managed_port_ids":["tap-a","tap-b"],"last_managed_ports":2,"last_managed_ports_detail":[{"port_id":"tap-a","domains":[{"domain":"acl","status":"complete","effective_action":"enforce"}]},{"port_id":"tap-b","domains":[{"domain":"acl","status":"complete","effective_action":"enforce"}]}],"overall_readiness":"ready","acl_enforcement":"enforce","maintenance_phase":null,"maintenance_operation_id":null,"buffer_overflow":false,"unsupported_ports":[],"foreign_host_ports":[],"conntrack_mode":"neutral"}\n' "$OLD_HASH" "$OLD_HASH"
  elif [ "$state" = active ]; then
    printf '{"accepted_generation":42,"applied_generation":42,"pending_generation":null,"last_desired_hash":"%s","last_managed_ports":2,"last_managed_ports_detail":[{"port_id":"tap-a","domains":[{"domain":"acl","status":"complete","effective_action":"enforce","ingress_complete":true,"egress_complete":true}]},{"port_id":"tap-b","domains":[{"domain":"acl","status":"complete","effective_action":"enforce","ingress_complete":true,"egress_complete":true}]}],"overall_readiness":"ready","acl_enforcement":"enforce","maintenance_phase":null,"maintenance_operation_id":null,"buffer_overflow":false,"unsupported_ports":[],"foreign_host_ports":[],"conntrack_mode":"neutral","stable_read_attempts":2,"stable_desired_hash":"%s"}\n' "$NEW_HASH" "$NEW_HASH"
  elif [ "$state" = resynced ]; then
    printf '{"accepted_generation":%s,"applied_generation":%s,"pending_generation":%s,"last_desired_hash":"%s","last_managed_ports":2,"last_managed_ports_detail":[{"port_id":"tap-a","domains":[{"domain":"acl","status":"%s","effective_action":"bypass","ingress_complete":%s,"egress_complete":%s}]},{"port_id":"tap-b","domains":[{"domain":"acl","status":"complete","effective_action":"bypass","ingress_complete":true,"egress_complete":true}]}],"overall_readiness":"degraded","acl_enforcement":"bypass","maintenance_phase":"maintenance_bypass","maintenance_operation_id":"%s","buffer_overflow":%s,"unsupported_ports":%s,"foreign_host_ports":%s,"conntrack_mode":"neutral","stable_read_attempts":%s,"stable_desired_hash":"%s","ingress_bypass":true,"egress_bypass":true}\n' "${SYNC_ACCEPTED:-42}" "${SYNC_APPLIED:-42}" "${SYNC_PENDING:-null}" "${SYNC_HASH:-$NEW_HASH}" "${SYNC_PORT_STATUS:-complete}" "${SYNC_INGRESS:-true}" "${SYNC_EGRESS:-true}" "${STATUS_OPERATION_ID:-$OPERATION_ID}" "${SYNC_BUFFER_OVERFLOW:-false}" "${SYNC_UNSUPPORTED:-[]}" "${SYNC_FOREIGN:-[]}" "${SYNC_STABLE_READS:-2}" "${SYNC_STABLE_HASH:-$NEW_HASH}"
  else
    printf '{"accepted_generation":42,"applied_generation":42,"pending_generation":%s,"last_desired_hash":"%s","last_managed_ports":2,"last_managed_ports_detail":[{"port_id":"tap-a","domains":[{"domain":"acl","status":"complete","effective_action":"bypass","ingress_complete":true,"egress_complete":true}]},{"port_id":"tap-b","domains":[{"domain":"acl","status":"complete","effective_action":"bypass","ingress_complete":true,"egress_complete":true}]}],"overall_readiness":"degraded","acl_enforcement":"%s","maintenance_phase":"maintenance_bypass","maintenance_operation_id":"%s","buffer_overflow":false,"unsupported_ports":[],"foreign_host_ports":[],"conntrack_mode":"%s","stable_read_attempts":2,"stable_desired_hash":"%s","ingress_bypass":%s,"egress_bypass":%s}\n' "${BYPASS_PENDING:-null}" "$NEW_HASH" "${BYPASS_ACL_ENFORCEMENT:-bypass}" "${STATUS_OPERATION_ID:-$OPERATION_ID}" "${BYPASS_CONNTRACK:-neutral}" "$NEW_HASH" "${BYPASS_INGRESS:-true}" "${BYPASS_EGRESS:-true}"
  fi
fi
''',
        )
        self.write_executable(
            "pgrep",
            "#!/usr/bin/env bash\nprintf 'pgrep %s\\n' \"$*\" >>\"$TRACE_FILE\"\nprintf '9001\\n'\n",
        )
        self.write_executable(
            "df",
            "#!/usr/bin/env bash\nprintf 'df %s\\n' \"$*\" >>\"$TRACE_FILE\"\nif [ \"${REALISTIC_DF:-false}\" = true ]; then printf 'Filesystem 1024-blocks Used Available Capacity Mounted on\\n/dev/test 9999999 1000 %s 1%% /var/lib\\n' \"${DF_AVAILABLE:-1048576}\"; else printf '%s\\n' \"${DF_AVAILABLE:-1048576}\"; fi\n",
        )
        self.write_executable("flock", "#!/usr/bin/env bash\nprintf 'flock %s\\n' \"$*\" >>\"$TRACE_FILE\"\nexit 0\n")
        self.write_executable("ovs-canary", "#!/usr/bin/env bash\nprintf 'ovs-canary %s\\n' \"$*\" >>\"$TRACE_FILE\"\n[ \"${FAIL_AT:-}\" != ovs_canary ]\n")
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
  printf resynced >"$API_STATE"
fi
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
                "CURRENT_MANIFEST": str(self.current_manifest),
                "CANDIDATE_MANIFEST": str(self.candidate_manifest),
                "OPERATION_ID": "task7-op",
                "FAIL_AT": fail_at,
                "UPGRADE_CONTROL": str(self.control_entrypoint),
                "DATAPATH_INSTALLER": str(self.datapath_fake),
                "AGENT_INSTALLER": str(self.agent_fake),
                "JOINT_STATE_DIR": str(self.root / "release-state"),
                "JOINT_LOCK_PATH": str(self.root / "joint.lock"),
                "OVS_CANARY_COMMAND": str(self.bin / "ovs-canary"),
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
        return json.loads(self.phase.read_text(encoding="utf-8"))["phase"]

    def reset_operation(self):
        shutil.rmtree(self.root / "release-state", ignore_errors=True)
        self.api_state.unlink(missing_ok=True)
        self.trace.unlink(missing_ok=True)

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

    def test_planned_upgrade_orders_bypass_replacements_resync_and_one_activation(self):
        self.run_joint("install")
        trace = self.read_trace()
        ordered = (
            "datapath prepare",
            "agent prepare",
            "/maintenance/enter",
            "/api/v1/admin/maintenance",
            "ovs-canary",
            "datapath replace",
            "datapath verify",
            "agent replace",
            "agent verify",
            "/maintenance/exit",
        )
        offset = -1
        for item in ordered:
            next_offset = trace.find(item, offset + 1)
            self.assertGreater(next_offset, offset, trace)
            offset = next_offset
        self.assertEqual(1, trace.count("/maintenance/exit"), trace)
        self.assertNotIn("/api/v1/admin/full-resync", trace)
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
                self.assertNotIn("ovs-vsctl", trace)
                if phase == "maintenance_bypass" and fail_at != "activation":
                    self.assertNotIn("/maintenance/exit", trace)
                if fail_at == "activation":
                    self.assertEqual(1, trace.count("/maintenance/exit"), trace)

    def test_unproven_bypass_never_allows_datapath_mutation_or_claims_safe_bypass(self):
        cases = (
            ("admin-operation", {"ADMIN_OPERATION_ID": "foreign-op"}),
            ("admin-domain", {"ADMIN_DOMAIN": "qos"}),
            ("admin-phase", {"ADMIN_PHASE": "gate_unknown"}),
            ("status-operation", {"STATUS_OPERATION_ID": "foreign-op"}),
            ("enforcement", {"BYPASS_ACL_ENFORCEMENT": "unknown"}),
            ("pending", {"BYPASS_PENDING": "43"}),
            ("ingress", {"BYPASS_INGRESS": "false"}),
            ("egress", {"BYPASS_EGRESS": "false"}),
            ("conntrack", {"BYPASS_CONNTRACK": "enforce"}),
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
            ("operation", {"STATUS_OPERATION_ID": "sync-7"}),
            ("accepted", {"SYNC_ACCEPTED": "41"}),
            ("applied", {"SYNC_APPLIED": "41"}),
            ("pending", {"SYNC_PENDING": "43"}),
            ("hash", {"SYNC_HASH": OLD_HASH}),
            ("stable-hash", {"SYNC_STABLE_HASH": OLD_HASH}),
            ("stable-double-read", {"SYNC_STABLE_READS": "1"}),
            ("buffer-overflow", {"SYNC_BUFFER_OVERFLOW": "true"}),
            ("unsupported", {"SYNC_UNSUPPORTED": '["tap-x"]'}),
            ("foreign-host", {"SYNC_FOREIGN": '["tap-y"]'}),
            ("port-incomplete", {"SYNC_PORT_STATUS": "pending"}),
            ("ingress", {"SYNC_INGRESS": "false"}),
            ("egress", {"SYNC_EGRESS": "false"}),
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
        self.run_joint("resume")
        resumed = self.read_trace()
        self.assertIn("/full-resync", resumed)
        self.assertIn("/maintenance/exit", resumed)
        self.assertNotIn(" replace", resumed)
        self.assertEqual("committed", self.phase_value())
        self.assertNotIn("/maintenance/exit", before)

    def test_core_rollback_restores_both_components_then_rebuilds_current_policy(self):
        self.run_joint("install", fail_at="resync", expected=1)
        self.trace.write_text("", encoding="utf-8")
        self.run_joint("rollback")
        trace = self.read_trace()
        order = (
            "/maintenance/enter",
            "datapath restore",
            "datapath verify",
            "agent restore",
            "agent verify",
            "/full-resync",
            "/maintenance/exit",
        )
        offset = -1
        for item in order:
            next_offset = trace.find(item, offset + 1)
            self.assertGreater(next_offset, offset, trace)
            offset = next_offset
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
        self.assertIn("/full-resync", trace)
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
            "ovs-vsctl",
        )
        for invocation in forbidden:
            self.assertNotIn(invocation, trace)
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

    def test_datapath_suite_does_not_reexport_joint_testcase(self):
        source = (ROOT / "ci/test_kolla_datapath_runtime_upgrade.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("KollaJointUpgradeTest", source)


if __name__ == "__main__":
    unittest.main()

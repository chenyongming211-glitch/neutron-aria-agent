from __future__ import print_function

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "deploy/kolla/package/install_aria_joint_rc.sh"
DATAPATH_INSTALLER = ROOT / "deploy/kolla/package/install_aria_datapath_rc_image.sh"
AGENT_INSTALLER = ROOT / "deploy/kolla/package/install_neutron_aria_agent_rc_image.sh"

OLD_DP = "sha256:" + "1" * 64
OLD_AGENT = "sha256:" + "2" * 64
NEW_DP = "sha256:" + "3" * 64
NEW_AGENT = "sha256:" + "4" * 64
OLD_HASH = "a" * 64
NEW_HASH = "b" * 64


class KollaJointUpgradeTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.trace = self.root / "trace.log"
        self.phase = self.root / "phase"
        self.api_state = self.root / "api-state"
        self.current_manifest = self.root / "current.json"
        self.candidate_manifest = self.root / "candidate.json"
        self.current_manifest.write_text(
            json.dumps(self.manifest(OLD_AGENT, OLD_DP)), encoding="utf-8"
        )
        self.candidate_manifest.write_text(
            json.dumps(self.manifest(NEW_AGENT, NEW_DP)), encoding="utf-8"
        )
        self.make_fakes()

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def manifest(agent, datapath):
        return {
            "release_version": "v0.9-test",
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
  printf bypass >"$API_STATE"
  printf '{"accepted":true,"operation_id":"%s","maintenance_token":"token-7"}\n' "$OPERATION_ID"
elif [[ "$args" == *"/full-resync"* ]]; then
  [ "${FAIL_AT:-}" != resync ] || exit 42
  printf resynced >"$API_STATE"
  printf '{"operation_id":"sync-7","phase":"complete","generation":42,"desired_hash":"%s","stable":true,"buffer_overflow":false}\n' "$NEW_HASH"
elif [[ "$args" == *"/maintenance/exit"* ]]; then
  [ "${FAIL_AT:-}" != activation ] || exit 43
  printf active >"$API_STATE"
  printf '{"activated":true,"generation":42,"desired_hash":"%s"}\n' "$NEW_HASH"
elif [[ "$args" == *"/livez"* ]]; then
  printf '{"service_liveness":"alive"}\n'
elif [[ "$args" == *"/readyz"* ]]; then
  printf '{"overall_readiness":"ready"}\n'
else
  state=baseline
  [ ! -f "$API_STATE" ] || state=$(cat "$API_STATE")
  if [ "$state" = bypass ] && [ "${FAIL_AT:-}" = after_bypass ]; then exit 41; fi
  if [ "$state" = baseline ]; then
    printf '{"accepted_generation":41,"applied_generation":41,"pending_generation":null,"desired_hash":"%s","managed_port_ids":["tap-a","tap-b"],"overall_readiness":"ready"}\n' "$OLD_HASH"
  elif [ "$state" = active ]; then
    printf '{"operation_id":"%s","accepted_generation":42,"applied_generation":42,"pending_generation":null,"desired_hash":"%s","all_ports_ready":true,"ingress_complete":true,"egress_complete":true,"overall_readiness":"ready"}\n' "$OPERATION_ID" "$NEW_HASH"
  else
    printf '{"operation_id":"%s","maintenance_token":"token-7","acl_enforcement":"bypass","pending_generation":null,"ingress_bypass":true,"egress_bypass":true,"accepted_generation":42,"applied_generation":42,"desired_hash":"%s","all_ports_ready":true,"ingress_complete":true,"egress_complete":true,"overall_readiness":"degraded"}\n' "$OPERATION_ID" "$NEW_HASH"
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
            "#!/usr/bin/env bash\nprintf 'df %s\\n' \"$*\" >>\"$TRACE_FILE\"\nprintf '1048576\\n'\n",
        )
        self.write_executable(
            "joint-control",
            r'''#!/usr/bin/env bash
set -eu
printf 'control %s\n' "$*" >>"$TRACE_FILE"
case "${1:-}" in
  classify)
    printf '{"path":"%s","reasons":["test"]}\n' "${CLASSIFICATION:-planned_maintenance}"
    ;;
  ledger)
    action=$2
    case "$action" in
      begin)
        if [ ! -f "$PHASE_FILE" ]; then printf preflight >"$PHASE_FILE"; fi
        ;;
      transition)
        expected=$3 next=$4
        [ "$(cat "$PHASE_FILE")" = "$expected" ] || exit 71
        printf '%s' "$next" >"$PHASE_FILE"
        ;;
      fail)
        current=$(cat "$PHASE_FILE")
        if [ "$current" = preflight ]; then printf failed_before_mutation >"$PHASE_FILE"; else printf maintenance_bypass >"$PHASE_FILE"; fi
        ;;
      recover|status) ;;
      *) exit 72 ;;
    esac
    printf '{"phase":"%s","operation_id":"%s"}\n' "$(cat "$PHASE_FILE")" "$OPERATION_ID"
    ;;
  *) exit 73 ;;
esac
''',
        )
        component = r'''#!/usr/bin/env bash
set -eu
component=${0##*/}
case "$component" in *datapath*) component=datapath ;; *) component=agent ;; esac
action=${1:-}
printf '%s %s\n' "$component" "$action" >>"$TRACE_FILE"
[ "${FAIL_AT:-}" != "${component}_${action}" ] || exit 51
'''
        self.datapath_fake = self.write_executable("datapath-installer", component)
        self.agent_fake = self.write_executable("agent-installer", component)

    def environment(self, classification="planned_maintenance", fail_at=""):
        env = os.environ.copy()
        env.update(
            {
                "PATH": str(self.bin) + os.pathsep + env.get("PATH", ""),
                "TRACE_FILE": str(self.trace),
                "PHASE_FILE": str(self.phase),
                "API_STATE": str(self.api_state),
                "CURRENT_MANIFEST": str(self.current_manifest),
                "CANDIDATE_MANIFEST": str(self.candidate_manifest),
                "OPERATION_ID": "task7-op",
                "CLASSIFICATION": classification,
                "FAIL_AT": fail_at,
                "UPGRADE_CONTROL": str(self.bin / "joint-control"),
                "DATAPATH_INSTALLER": str(self.datapath_fake),
                "AGENT_INSTALLER": str(self.agent_fake),
                "JOINT_STATE_DIR": str(self.root / "release-state"),
                "JOINT_LOCK_PATH": str(self.root / "joint.lock"),
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
        for path in (
            env["ADMIN_SOCKET"],
            env["NEUTRON_SOCKET"],
            env["ROLLBACK_DATAPATH_CONFIG"],
            env["ROLLBACK_AGENT_CONFIG"],
            env["CANDIDATE_DATAPATH_CONFIG"],
            env["CANDIDATE_AGENT_CONFIG"],
        ):
            Path(path).touch()
        return env

    def run_joint(self, action, classification="planned_maintenance", fail_at="", expected=0):
        self.assertTrue(INSTALLER.is_file(), "joint installer is absent")
        result = subprocess.run(
            ["bash", str(INSTALLER), action],
            cwd=str(ROOT),
            env=self.environment(classification, fail_at),
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
            "datapath replace",
            "datapath verify",
            "agent replace",
            "agent verify",
            "/full-resync",
            "/maintenance/exit",
        )
        offset = -1
        for item in ordered:
            next_offset = trace.find(item, offset + 1)
            self.assertGreater(next_offset, offset, trace)
            offset = next_offset
        self.assertEqual(1, trace.count("/maintenance/exit"), trace)
        self.assertIn("docker inspect -f {{.State.Health.Status}} aria_datapath", trace)
        self.assertIn("docker inspect -f {{.State.Health.Status}} neutron_aria_agent", trace)
        self.assertEqual("committed", self.phase.read_text(encoding="utf-8"))

    def test_all_required_failure_boundaries_persist_safe_phase(self):
        cases = (
            ("datapath_prepare", "failed_before_mutation"),
            ("after_bypass", "maintenance_bypass"),
            ("datapath_replace", "maintenance_bypass"),
            ("datapath_verify", "maintenance_bypass"),
            ("agent_replace", "maintenance_bypass"),
            ("agent_verify", "maintenance_bypass"),
            ("resync", "maintenance_bypass"),
            ("activation", "maintenance_bypass"),
        )
        for fail_at, phase in cases:
            with self.subTest(fail_at=fail_at):
                self.phase.unlink(missing_ok=True)
                self.api_state.unlink(missing_ok=True)
                self.trace.unlink(missing_ok=True)
                self.run_joint("install", fail_at=fail_at, expected=1)
                self.assertEqual(phase, self.phase.read_text(encoding="utf-8"))
                trace = self.read_trace()
                self.assertNotIn("docker restart", trace)
                self.assertNotIn("ovs-vsctl", trace)
                if phase == "maintenance_bypass" and fail_at != "activation":
                    self.assertNotIn("/maintenance/exit", trace)
                if fail_at == "activation":
                    self.assertEqual(1, trace.count("/maintenance/exit"), trace)

    def test_resume_from_maintenance_restarts_at_resync_without_replacement(self):
        self.run_joint("install", fail_at="resync", expected=1)
        before = self.read_trace()
        self.trace.write_text("", encoding="utf-8")
        self.run_joint("resume")
        resumed = self.read_trace()
        self.assertIn("/full-resync", resumed)
        self.assertIn("/maintenance/exit", resumed)
        self.assertNotIn(" replace", resumed)
        self.assertEqual("committed", self.phase.read_text(encoding="utf-8"))
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
        self.assertEqual("committed", self.phase.read_text(encoding="utf-8"))

    def test_rollback_failure_stays_in_explicit_maintenance_bypass(self):
        self.run_joint("install", fail_at="resync", expected=1)
        self.trace.write_text("", encoding="utf-8")
        self.run_joint("rollback", fail_at="datapath_restore", expected=1)
        self.assertEqual("maintenance_bypass", self.phase.read_text(encoding="utf-8"))
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
        self.assertEqual("committed", self.phase.read_text(encoding="utf-8"))

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


if __name__ == "__main__":
    unittest.main()

from __future__ import print_function

import os
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "deploy/kolla/package/install_aria_datapath_rc_image.sh"


class KollaDatapathRuntimeUpgradeTest(unittest.TestCase):
    def run_bash(self, body, expected=0):
        env = os.environ.copy()
        env["ARIA_INSTALLER_LIBRARY_ONLY"] = "true"
        installer_path = INSTALLER.as_posix()
        if os.name == "nt":
            installer_path = "/mnt/%s/%s" % (
                installer_path[0].lower(),
                installer_path[3:],
            )
        result = subprocess.run(
            ["bash", "-c", '. "%s"\n%s' % (installer_path, body)],
            cwd=str(ROOT),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(
            expected,
            result.returncode,
            "stdout:\n%s\nstderr:\n%s" % (result.stdout, result.stderr),
        )
        return result

    def test_runtime_migration_decision_is_hash_aware(self):
        result = self.run_bash(
            """
runtime_migration_required aaaa aaaa false && exit 10
runtime_migration_required aaaa bbbb false || exit 11
runtime_migration_required aaaa aaaa true || exit 12
printf 'decision=ok\\n'
"""
        )
        self.assertIn("decision=ok", result.stdout)

    def test_changed_hash_orders_quiesce_detach_switch_resume_verify(self):
        result = self.run_bash(
            """
events=()
stop_agent_writer() { events+=(stop_writer); }
detach_all_managed_ports() { events+=(detach_all verify_zero); }
switch_to_candidate() { events+=(switch_candidate); }
start_agent_writer() { events+=(start_writer); }
verify_candidate_convergence() { events+=(full_resync verify_candidate); }
run_runtime_migration_sequence
printf '%s\\n' "${events[*]}"
"""
        )
        self.assertEqual(
            "stop_writer detach_all verify_zero switch_candidate "
            "start_writer full_resync verify_candidate",
            result.stdout.strip(),
        )

    def test_detach_failure_prevents_candidate_switch(self):
        result = self.run_bash(
            """
events=()
stop_agent_writer() { events+=(stop_writer); }
detach_all_managed_ports() { events+=(detach_failed); return 41; }
switch_to_candidate() { events+=(BUG_switch_candidate); }
start_agent_writer() { events+=(BUG_start_writer); }
verify_candidate_convergence() { events+=(BUG_verify); }
set +e
run_runtime_migration_sequence
rc=$?
set -e
printf 'rc=%s events=%s\\n' "$rc" "${events[*]}"
[ "$rc" -eq 41 ]
[[ "${events[*]}" != *BUG* ]]
"""
        )
        self.assertIn("rc=41 events=stop_writer detach_failed", result.stdout)

    def test_hash_aware_rollback_detaches_before_restore(self):
        result = self.run_bash(
            """
events=()
stop_agent_writer() { events+=(stop_writer); }
detach_all_managed_ports() { events+=(detach_candidate verify_zero); }
restore_backup_container() { events+=(restore_backup); }
start_agent_writer() { events+=(start_writer); }
verify_rollback_convergence() { events+=(full_resync verify_rollback); }
run_hash_aware_rollback_sequence
printf '%s\\n' "${events[*]}"
"""
        )
        self.assertEqual(
            "stop_writer detach_candidate verify_zero restore_backup "
            "start_writer full_resync verify_rollback",
            result.stdout.strip(),
        )

    def test_rollback_failure_does_not_resume_writer(self):
        result = self.run_bash(
            """
events=()
stop_agent_writer() { events+=(stop_writer); }
detach_all_managed_ports() { events+=(detach_candidate verify_zero); }
restore_backup_container() { events+=(restore_failed); return 52; }
start_agent_writer() { events+=(BUG_start_writer); }
verify_rollback_convergence() { events+=(BUG_verify); }
set +e
run_hash_aware_rollback_sequence
rc=$?
set -e
printf 'rc=%s events=%s\\n' "$rc" "${events[*]}"
[ "$rc" -eq 52 ]
[[ "${events[*]}" != *BUG* ]]
"""
        )
        self.assertIn(
            "rc=52 events=stop_writer detach_candidate verify_zero restore_failed",
            result.stdout,
        )

    def test_installer_never_mutates_ovs_services(self):
        source = INSTALLER.read_text(encoding="utf-8")
        forbidden = (
            "docker restart neutron_openvswitch_agent",
            "docker stop neutron_openvswitch_agent",
            "systemctl restart openvswitch",
            "systemctl stop openvswitch",
            "ovs-vsctl del-port",
        )
        for term in forbidden:
            self.assertNotIn(term, source)


if __name__ == "__main__":
    unittest.main()

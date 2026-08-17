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
        installer_path = INSTALLER.as_posix()
        bash = "bash"
        if os.name == "nt":
            git_bash = Path(r"C:\Program Files\Git\bin\bash.exe")
            if git_bash.is_file():
                bash = str(git_bash)
            else:
                self.skipTest("Git Bash is required for shell lifecycle tests")
        result = subprocess.run(
            [
                bash,
                "-c",
                'ARIA_INSTALLER_LIBRARY_ONLY=true\n. "%s"\n%s'
                % (installer_path, body),
            ],
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

    def test_managed_pin_path_is_derived_from_datapath_config(self):
        result = self.run_bash(
            """
SERVICE_NAME=aria_datapath
docker() { printf '/sys/fs/bpf/aria\\n'; }
discover_managed_pin_path
printf 'managed-pin=%s\\n' "$MANAGED_PIN_PATH"
"""
        )
        self.assertIn("managed-pin=/sys/fs/bpf/aria/shared", result.stdout)

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

    def test_schema_change_preserves_old_state_and_pin_namespace(self):
        result = self.run_bash(
            """
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
RUNTIME_MIGRATION_REQUIRED=true
LIFECYCLE_TRACKING_ENABLED=false
BACKUP_DATAPATH_STATE_SOURCE="$root/state-old"
CANDIDATE_DATAPATH_STATE_SOURCE="$root/state-new"
DATAPATH_STATE_SOURCE="$BACKUP_DATAPATH_STATE_SOURCE"
MANAGED_PIN_PATH="$root/shared"
PIN_BACKUP_PATH="$root/shared.pre-rc"
CANDIDATE_PIN_QUARANTINE="$root/shared.failed-rc"
PIN_BACKUP_PRESENT=false
PERSISTENT_RUNTIME_PREPARED=false
mkdir -p "$BACKUP_DATAPATH_STATE_SOURCE" "$MANAGED_PIN_PATH"
printf old-state >"$BACKUP_DATAPATH_STATE_SOURCE/schema"
printf old-pin >"$MANAGED_PIN_PATH/map"
preserve_persistent_runtime
[ "$(cat "$CANDIDATE_DATAPATH_STATE_SOURCE/schema")" = old-state ]
[ "$(cat "$PIN_BACKUP_PATH/map")" = old-pin ]
[ "$DATAPATH_STATE_SOURCE" = "$CANDIDATE_DATAPATH_STATE_SOURCE" ]
mkdir -p "$MANAGED_PIN_PATH"
printf new-pin >"$MANAGED_PIN_PATH/map"
LIFECYCLE_PHASE=runtime_detached
container_running() { return 1; }
restore_persistent_runtime
[ "$(cat "$MANAGED_PIN_PATH/map")" = old-pin ]
[ "$(cat "$CANDIDATE_PIN_QUARANTINE/map")" = new-pin ]
[ "$DATAPATH_STATE_SOURCE" = "$BACKUP_DATAPATH_STATE_SOURCE" ]
printf 'dual-track=ok\\n'
"""
        )
        self.assertIn("dual-track=ok", result.stdout)

    def test_prepared_flag_protects_old_pin_in_copy_crash_window(self):
        result = self.run_bash(
            """
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
RUNTIME_MIGRATION_REQUIRED=true
LIFECYCLE_TRACKING_ENABLED=false
LIFECYCLE_PHASE=runtime_detached
PERSISTENT_RUNTIME_PREPARED=false
PIN_BACKUP_PRESENT=false
BACKUP_DATAPATH_STATE_SOURCE="$root/state-old"
CANDIDATE_DATAPATH_STATE_SOURCE="$root/state-new"
DATAPATH_STATE_SOURCE="$CANDIDATE_DATAPATH_STATE_SOURCE"
MANAGED_PIN_PATH="$root/shared"
PIN_BACKUP_PATH="$root/shared.pre-rc"
CANDIDATE_PIN_QUARANTINE="$root/shared.failed-rc"
mkdir -p "$BACKUP_DATAPATH_STATE_SOURCE" "$CANDIDATE_DATAPATH_STATE_SOURCE" "$MANAGED_PIN_PATH"
printf old-pin >"$MANAGED_PIN_PATH/map"
container_running() { return 1; }
restore_persistent_runtime
[ "$(cat "$MANAGED_PIN_PATH/map")" = old-pin ]
[ ! -e "$CANDIDATE_PIN_QUARANTINE" ]
[ "$DATAPATH_STATE_SOURCE" = "$BACKUP_DATAPATH_STATE_SOURCE" ]
printf 'copy-crash-window=ok\\n'
"""
        )
        self.assertIn("copy-crash-window=ok", result.stdout)

    def test_pin_restore_replay_accepts_completed_name_swap(self):
        result = self.run_bash(
            """
root=$(mktemp -d)
trap 'rm -rf "$root"' EXIT
RUNTIME_MIGRATION_REQUIRED=true
LIFECYCLE_TRACKING_ENABLED=false
LIFECYCLE_PHASE=runtime_detached
PERSISTENT_RUNTIME_PREPARED=true
PIN_BACKUP_PRESENT=true
BACKUP_DATAPATH_STATE_SOURCE="$root/state-old"
CANDIDATE_DATAPATH_STATE_SOURCE="$root/state-new"
DATAPATH_STATE_SOURCE="$CANDIDATE_DATAPATH_STATE_SOURCE"
MANAGED_PIN_PATH="$root/shared"
PIN_BACKUP_PATH="$root/shared.pre-rc"
CANDIDATE_PIN_QUARANTINE="$root/shared.failed-rc"
mkdir -p "$BACKUP_DATAPATH_STATE_SOURCE" "$CANDIDATE_DATAPATH_STATE_SOURCE"
mkdir -p "$MANAGED_PIN_PATH" "$CANDIDATE_PIN_QUARANTINE"
printf old-pin >"$MANAGED_PIN_PATH/map"
printf new-pin >"$CANDIDATE_PIN_QUARANTINE/map"
container_running() { return 1; }
restore_persistent_runtime
[ "$(cat "$MANAGED_PIN_PATH/map")" = old-pin ]
[ "$(cat "$CANDIDATE_PIN_QUARANTINE/map")" = new-pin ]
[ "$DATAPATH_STATE_SOURCE" = "$BACKUP_DATAPATH_STATE_SOURCE" ]
printf 'pin-restore-replay=ok\\n'
"""
        )
        self.assertIn("pin-restore-replay=ok", result.stdout)

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
restore_persistent_runtime() { events+=(restore_old_state_and_pins); }
start_agent_writer() { events+=(start_writer); }
verify_rollback_convergence() { events+=(full_resync verify_rollback); }
run_hash_aware_rollback_sequence
printf '%s\\n' "${events[*]}"
"""
        )
        self.assertEqual(
            "stop_writer detach_candidate verify_zero restore_old_state_and_pins restore_backup "
            "start_writer full_resync verify_rollback",
            result.stdout.strip(),
        )

    def test_candidate_failure_uses_hash_aware_recovery(self):
        result = self.run_bash(
            """
events=()
BACKUP_CONTAINER=aria_datapath_pre_rc_test
SERVICE_NAME=aria_datapath
LIFECYCLE_PHASE=candidate_started
RUNTIME_MIGRATION_REQUIRED=true
stop_agent_writer() { events+=(stop_writer); }
container_exists() { return 0; }
container_running() { return 0; }
uds_socket_available() { return 0; }
detach_all_managed_ports() { events+=(detach_candidate verify_zero); }
restore_persistent_runtime() { events+=(restore_old_state_and_pins); }
restore_backup_container() { events+=(restore_backup); }
start_agent_writer() { events+=(start_writer); }
wait_ready() { events+=(full_resync); }
verify_generation_convergence() { events+=(verify_generation); }
check_ovs_identity() { events+=(verify_ovs); }
recover_failed_install
printf '%s\\n' "${events[*]}"
"""
        )
        self.assertEqual(
            "stop_writer detach_candidate verify_zero restore_old_state_and_pins restore_backup "
            "start_writer full_resync verify_generation verify_ovs",
            result.stdout.strip(),
        )

    def test_exited_candidate_without_uds_is_not_assumed_clean(self):
        result = self.run_bash(
            """
events=()
BACKUP_CONTAINER=aria_datapath_pre_rc_test
SERVICE_NAME=aria_datapath
LIFECYCLE_PHASE=candidate_started
stop_agent_writer() { events+=(stop_writer); }
container_exists() { return 0; }
container_running() { return 1; }
restore_backup_container() { events+=(BUG_restore_backup); }
start_agent_writer() { events+=(BUG_start_writer); }
set +e
recover_failed_install
rc=$?
set -e
printf 'rc=%s events=%s\\n' "$rc" "${events[*]}"
[ "$rc" -ne 0 ]
[[ "${events[*]}" != *BUG* ]]
"""
        )
        self.assertIn("rc=1 events=stop_writer", result.stdout)

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

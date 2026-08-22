import contextlib
import unittest
from unittest import mock

from ci import check_neutron_stage1 as checker


class NeutronMaintenanceContractCheckerTests(unittest.TestCase):
    def test_fast_contracts_executes_status_contract_checker(self):
        dependencies = (
            "check_required_python_behaviors",
            "run_python_tests",
            "run_neutronclient_extension_tests",
            "check_packaged_ini_contract",
            "check_documented_ini_contract",
            "check_documented_status_contract",
            "check_drop_reason_name_sync",
            "check_uds_contract_artifact",
            "check_public_smoke_entrypoints",
            "check_dual_stack_smoke_contract",
            "run_smoke_syntax",
            "run_readiness_endpoint_smoke_contract_test",
            "run_heartbeat_v2_smoke_contract_test",
            "run_fragment_tracking_field_driver_self_test",
            "run_agent_package_installer_test",
            "run_acl_enforcement_gap_smoke_test",
            "check_tap_recreate_identity_smoke_contract",
            "run_plugin_policy_rollback_test",
            "run_transaction_state_smoke_test",
            "run_db_crud_adminrc_test",
        )
        with contextlib.ExitStack() as stack:
            for name in dependencies:
                stack.enter_context(mock.patch.object(checker, name))
            status_check = stack.enter_context(
                mock.patch.object(checker, "check_status_v1_contract")
            )
            checker.run_fast_contracts()
        status_check.assert_called_once_with()

    def test_status_required_action_vocabulary_includes_maintenance_repair(self):
        self.assertIn(
            "complete_or_repair_maintenance",
            checker.STATUS_VOCABULARY["required_actions"],
        )
        api = checker.read_text(checker.RUST_API_PATH)
        self.assertIn(
            "CompleteOrRepairMaintenance",
            checker.public_enum_variants(api, "NeutronStatusRequiredAction"),
        )


if __name__ == "__main__":
    unittest.main()

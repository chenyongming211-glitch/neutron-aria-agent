from __future__ import print_function

import os
import unittest


class NeutronAriaAgentReleaseInstallerContractTestCase(unittest.TestCase):

    def _installer_source(self):
        repo_root = os.path.abspath(os.path.join(
            os.path.dirname(__file__),
            "..", "..", "..", "..", "..",
        ))
        installer_path = os.path.join(
            repo_root,
            "deploy",
            "kolla",
            "package",
            "install_neutron_aria_agent_rc_image.sh",
        )
        with open(installer_path, "r") as source:
            return source.read()

    def _function_body(self, installer, name):
        start = installer.index("%s() {" % name)
        end = installer.index("\n}\n", start)
        return installer[start:end]

    def test_candidate_preserves_durable_snapshot_state(self):
        installer = self._installer_source()

        self.assertIn('RUNTIME_STATE_SOURCE="${RUNTIME_STATE_SOURCE:-', installer)
        self.assertIn('CONTAINER_STATE_DIR="${CONTAINER_STATE_DIR:-', installer)
        self.assertIn(
            'docker cp "${SERVICE_NAME}:${CONTAINER_STATE_DIR}/."',
            installer,
        )

    def test_post_install_check_allows_planned_datapath_upgrade(self):
        installer = self._installer_source()
        check_body = self._function_body(installer, "check_candidate")
        rollback_body = self._function_body(installer, "rollback_candidate")

        self.assertNotIn("check_non_interference", check_body)
        self.assertIn("record_non_interference_baseline", rollback_body)
        self.assertIn("check_non_interference", rollback_body)
        self.assertIn(
            '-v "${RUNTIME_STATE_SOURCE}:${CONTAINER_STATE_DIR}:rw"',
            installer,
        )


if __name__ == "__main__":
    unittest.main()

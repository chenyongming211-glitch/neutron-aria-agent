from __future__ import print_function

import os
import unittest


class NeutronAriaAgentReleaseInstallerContractTestCase(unittest.TestCase):

    def test_candidate_preserves_durable_snapshot_state(self):
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
            installer = source.read()

        self.assertIn('RUNTIME_STATE_SOURCE="${RUNTIME_STATE_SOURCE:-', installer)
        self.assertIn('CONTAINER_STATE_DIR="${CONTAINER_STATE_DIR:-', installer)
        self.assertIn(
            'docker cp "${SERVICE_NAME}:${CONTAINER_STATE_DIR}/."',
            installer,
        )
        self.assertIn(
            '-v "${RUNTIME_STATE_SOURCE}:${CONTAINER_STATE_DIR}:rw"',
            installer,
        )


if __name__ == "__main__":
    unittest.main()

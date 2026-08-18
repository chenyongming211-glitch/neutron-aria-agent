from __future__ import print_function

import os
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read_repo_file(relative_path):
    path = os.path.join(REPO_ROOT, *relative_path.split("/"))
    with open(path, "r") as stream:
        return stream.read()


class NeutronAgentImageUpgradeContractTest(unittest.TestCase):

    def test_image_installs_prebuilt_egg_without_in_process_rebuild(self):
        dockerfile = read_repo_file(
            "deploy/kolla/neutron-aria-agent/Dockerfile"
        )

        self.assertIn(
            "COPY dist/kolla/neutron_aria-0.1.0-py2.7.egg",
            dockerfile,
        )
        self.assertIn("install-neutron-aria-egg-image.sh", dockerfile)
        self.assertNotIn("python setup.py install", dockerfile)


if __name__ == "__main__":
    unittest.main()

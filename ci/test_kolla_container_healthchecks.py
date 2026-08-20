from __future__ import print_function

import os
import subprocess
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read_repo_file(relative_path):
    path = os.path.join(REPO_ROOT, *relative_path.split("/"))
    with open(path, "r") as stream:
        return stream.read()


class KollaContainerHealthcheckContractTest(unittest.TestCase):

    def assert_shell_syntax(self, relative_path):
        subprocess.check_call(["bash", "-n", relative_path], cwd=REPO_ROOT)

    def test_datapath_probe_is_strict_and_uses_neutron_peer_identity(self):
        relative_path = (
            "deploy/kolla/aria-datapath/healthcheck-aria-datapath.sh"
        )
        content = read_repo_file(relative_path)

        self.assertIn("/api/v1/health", content)
        self.assertIn("/readyz", content)
        self.assertIn("--unix-socket", content)
        self.assertIn("sudo -u neutron", content)
        self.assertNotIn("docker restart", content)
        self.assertNotIn("ovs-vsctl", content)
        self.assert_shell_syntax(relative_path)

    def test_python_agent_probe_requires_strict_uds_readiness(self):
        relative_path = (
            "deploy/kolla/neutron-aria-agent/"
            "healthcheck-neutron-aria-agent.sh"
        )
        content = read_repo_file(relative_path)

        self.assertIn("/readyz", content)
        self.assertIn("--unix-socket", content)
        self.assertNotIn("/api/v1/health", content)
        self.assertNotIn("docker restart", content)
        self.assertNotIn("ovs-vsctl", content)
        self.assert_shell_syntax(relative_path)

    def test_formal_images_declare_the_frozen_health_policy(self):
        cases = (
            (
                "deploy/kolla/aria-datapath/Dockerfile",
                "/usr/local/bin/healthcheck-aria-datapath",
            ),
            (
                "deploy/kolla/neutron-aria-agent/Dockerfile",
                "/usr/local/bin/healthcheck-neutron-aria-agent",
            ),
        )
        policy = (
            "HEALTHCHECK --interval=30s --timeout=5s "
            "--start-period=60s --retries=3"
        )
        for dockerfile, command in cases:
            content = read_repo_file(dockerfile)
            self.assertIn(policy, content)
            self.assertIn('CMD ["%s"]' % command, content)

    def test_generated_datapath_images_keep_the_same_health_contract(self):
        for relative_path in (
            "deploy/kolla/package/build_aria_datapath_image.sh",
            "deploy/kolla/smoke/aria_datapath_container_smoke.sh",
        ):
            content = read_repo_file(relative_path)
            self.assertIn("healthcheck-aria-datapath", content)
            self.assertIn("--interval=30s --timeout=5s", content)
            self.assertIn("--start-period=60s --retries=3", content)

    def test_datapath_smoke_healthcheck_follows_isolated_endpoints(self):
        content = read_repo_file(
            "deploy/kolla/smoke/aria_datapath_container_smoke.sh"
        )
        self.assertIn('ARIA_HEALTH_SOCKET_PATH=${SOCKET_PATH}', content)
        self.assertIn('ARIA_HEALTH_TCP_URL=${HEALTH_TCP_URL}', content)
        self.assertIn(
            'HEALTH_TCP_URL="http://${HEALTH_LISTEN_ADDR}/api/v1/health"',
            content,
        )

    def test_datapath_smoke_uses_the_kolla_runtime_command(self):
        content = read_repo_file(
            "deploy/kolla/smoke/aria_datapath_container_smoke.sh"
        )
        self.assertIn(
            'KOLLA_START_COMMAND="${KOLLA_START_COMMAND:-kolla_start}"',
            content,
        )

    def test_datapath_smoke_can_defer_health_for_fault_fixtures(self):
        content = read_repo_file(
            "deploy/kolla/smoke/aria_datapath_container_smoke.sh"
        )
        self.assertIn(
            'CHECK_CONTAINER_HEALTH="${CHECK_CONTAINER_HEALTH:-true}"',
            content,
        )
        self.assertIn(
            'if [ "${CHECK_CONTAINER_HEALTH}" = "true" ]; then',
            content,
        )
        self.assertIn("Skipping Docker health gate for fault fixture", content)
        self.assertIn(
            'docker run "${docker_run_args[@]}" "${IMAGE}" '
            '"${KOLLA_START_COMMAND}"',
            content,
        )

    def test_negative_agent_smoke_waits_past_the_unhealthy_threshold(self):
        content = read_repo_file(
            "deploy/kolla/smoke/neutron_aria_container_smoke.sh"
        )
        self.assertIn('HEALTH_TIMEOUT="${HEALTH_TIMEOUT:-210}"', content)
        self.assertIn("EXPECTED_DOCKER_HEALTH=unhealthy", content)

    def test_rc_installers_require_candidate_docker_health(self):
        for relative_path in (
            "deploy/kolla/package/install_aria_datapath_rc_image.sh",
            "deploy/kolla/package/install_neutron_aria_agent_rc_image.sh",
        ):
            content = read_repo_file(relative_path)
            self.assertIn("candidate_image_has_healthcheck", content)
            self.assertIn("wait_container_healthy", content)
            self.assertIn(".State.Health.Status", content)

    def test_ci_and_operator_docs_publish_the_strict_contract(self):
        workflow = read_repo_file(".github/workflows/build.yml")
        self.assertIn(
            "python3 -m unittest ci.test_kolla_container_healthchecks",
            workflow,
        )

        for relative_path in (
            "deploy/kolla/aria-datapath/README.md",
            "deploy/kolla/neutron-aria-agent/README.md",
        ):
            content = read_repo_file(relative_path)
            self.assertIn("degraded", content)
            self.assertIn("bypass", content)
            self.assertIn("unhealthy", content)
            self.assertIn("does not mean that OVS forwarding is down", content)


if __name__ == "__main__":
    unittest.main()

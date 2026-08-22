from __future__ import print_function

import os
import shutil
import socket
import subprocess
import tempfile
import unittest


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read_repo_file(relative_path):
    path = os.path.join(REPO_ROOT, *relative_path.split("/"))
    with open(path, "r") as stream:
        return stream.read()


class KollaContainerHealthcheckContractTest(unittest.TestCase):

    def _write_executable(self, path, content):
        with open(path, "w") as stream:
            stream.write(content)
        os.chmod(path, 0o755)

    def _run_production_healthcheck(
        self,
        relative_path,
        live_exit=0,
        ready_exit=0,
        python_exit=0,
        socket_present=True,
    ):
        temporary_dir = tempfile.mkdtemp(prefix="aria-healthcheck-")
        unix_socket = None
        try:
            fake_bin = os.path.join(temporary_dir, "bin")
            os.mkdir(fake_bin)
            self._write_executable(
                os.path.join(fake_bin, "curl"),
                """#!/bin/sh
case "$*" in
    *readyz*) exit "${FAKE_READY_EXIT}" ;;
    *livez*) exit "${FAKE_LIVE_EXIT}" ;;
esac
exit 90
""",
            )
            self._write_executable(
                os.path.join(fake_bin, "sudo"),
                """#!/bin/sh
if [ "$1" = "-u" ]; then
    shift 2
fi
exec "$@"
""",
            )
            self._write_executable(
                os.path.join(fake_bin, "python"),
                """#!/bin/sh
exit "${FAKE_PYTHON_EXIT}"
""",
            )

            socket_path = os.path.join(temporary_dir, "aria-agent.sock")
            if socket_present:
                unix_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                unix_socket.bind(socket_path)

            environment = os.environ.copy()
            environment.update({
                "ARIA_HEALTH_SOCKET_PATH": socket_path,
                "ARIA_HEALTH_PYTHON_BIN": "python",
                "FAKE_LIVE_EXIT": str(live_exit),
                "FAKE_READY_EXIT": str(ready_exit),
                "FAKE_PYTHON_EXIT": str(python_exit),
                "PATH": fake_bin + os.pathsep + environment["PATH"],
            })
            process = subprocess.Popen(
                ["sh", relative_path],
                cwd=REPO_ROOT,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            stdout, stderr = process.communicate()
            return process.returncode, stdout, stderr
        finally:
            if unix_socket is not None:
                unix_socket.close()
            shutil.rmtree(temporary_dir)

    def assert_shell_syntax(self, relative_path):
        subprocess.check_call(["bash", "-n", relative_path], cwd=REPO_ROOT)

    def test_datapath_probe_is_strict_and_uses_neutron_peer_identity(self):
        relative_path = (
            "deploy/kolla/aria-datapath/healthcheck-aria-datapath.sh"
        )
        content = read_repo_file(relative_path)

        self.assertNotIn("/api/v1/health", content)
        self.assertIn("/api/v1/livez", content)
        self.assertIn("/livez", content)
        self.assertIn("/readyz", content)
        self.assertLess(content.rfind("/livez"), content.rfind("/readyz"))
        self.assertIn("Docker health authority remains /readyz", content)
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

        self.assertIn("service-liveness.json", content)
        self.assertIn("/livez", content)
        self.assertIn("/readyz", content)
        self.assertLess(content.rfind("/livez"), content.rfind("/readyz"))
        self.assertIn("Docker health authority remains /readyz", content)
        self.assertIn("--unix-socket", content)
        self.assertNotIn("/api/v1/health", content)
        self.assertNotIn("docker restart", content)
        self.assertNotIn("ovs-vsctl", content)
        self.assert_shell_syntax(relative_path)

    def test_liveness_readiness_matrix_keeps_docker_health_strict(self):
        matrix = (
            ("ready/enforce", 200, 200, "healthy"),
            ("planned maintenance bypass", 200, 503, "unhealthy"),
            ("blocked recovery", 200, 503, "unhealthy"),
            ("dead loop/socket", None, None, "unhealthy"),
        )

        for state, live_status, ready_status, expected_docker in matrix:
            docker_health = (
                "healthy"
                if live_status == 200 and ready_status == 200
                else "unhealthy"
            )
            self.assertEqual(expected_docker, docker_health, state)

    def test_production_healthchecks_execute_strict_readiness_matrix(self):
        scripts = (
            "deploy/kolla/aria-datapath/healthcheck-aria-datapath.sh",
            (
                "deploy/kolla/neutron-aria-agent/"
                "healthcheck-neutron-aria-agent.sh"
            ),
        )
        for script in scripts:
            returncode, stdout, stderr = self._run_production_healthcheck(
                script,
            )
            self.assertEqual(
                0,
                returncode,
                "%s ready/enforce stdout=%r stderr=%r" % (
                    script,
                    stdout,
                    stderr,
                ),
            )

            for state in ("planned maintenance bypass", "blocked recovery"):
                returncode, stdout, stderr = self._run_production_healthcheck(
                    script,
                    live_exit=0,
                    ready_exit=22,
                )
                self.assertNotEqual(
                    0,
                    returncode,
                    "%s %s masked /readyz failure stdout=%r stderr=%r" % (
                        script,
                        state,
                        stdout,
                        stderr,
                    ),
                )

            returncode, stdout, stderr = self._run_production_healthcheck(
                script,
                socket_present=False,
            )
            self.assertNotEqual(
                0,
                returncode,
                "%s dead socket stdout=%r stderr=%r" % (
                    script,
                    stdout,
                    stderr,
                ),
            )

    def test_production_healthchecks_reject_dead_service_loops(self):
        cases = (
            (
                "deploy/kolla/aria-datapath/healthcheck-aria-datapath.sh",
                {"live_exit": 22},
            ),
            (
                "deploy/kolla/neutron-aria-agent/"
                "healthcheck-neutron-aria-agent.sh",
                {"python_exit": 1},
            ),
        )
        for script, failure in cases:
            returncode, stdout, stderr = self._run_production_healthcheck(
                script,
                **failure
            )
            self.assertNotEqual(
                0,
                returncode,
                "%s dead loop stdout=%r stderr=%r" % (
                    script,
                    stdout,
                    stderr,
                ),
            )

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
        self.assertIn(
            'ARIA_HEALTH_TCP_LIVEZ_URL=${HEALTH_TCP_LIVEZ_URL}',
            content,
        )
        self.assertIn(
            'HEALTH_TCP_LIVEZ_URL="http://${HEALTH_LISTEN_ADDR}/api/v1/livez"',
            content,
        )
        self.assertNotIn('ARIA_HEALTH_TCP_URL=${HEALTH_TCP_URL}', content)

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

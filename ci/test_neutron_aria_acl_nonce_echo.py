#!/usr/bin/env python
from __future__ import print_function

import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import uuid


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HELPER = os.path.join(
    ROOT, "deploy", "kolla", "smoke", "neutron_aria_acl_nonce_echo.py"
)


class NonceEchoTests(unittest.TestCase):
    def setUp(self):
        self.work_dir = tempfile.mkdtemp(prefix="aria-nonce-echo-")
        self.processes = []

    def tearDown(self):
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except TypeError:  # Python 2.7
                    deadline = time.time() + 3
                    while process.poll() is None and time.time() < deadline:
                        time.sleep(0.05)
                if process.poll() is None:
                    process.kill()
                    process.wait()
            for stream in (process.stdout, process.stderr):
                if stream is not None:
                    stream.close()
        shutil.rmtree(self.work_dir)

    def unused_port(self, protocol):
        sock_type = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
        sock = socket.socket(socket.AF_INET, sock_type)
        try:
            sock.bind(("127.0.0.1", 0))
            return sock.getsockname()[1]
        finally:
            sock.close()

    def start_server(self, protocol):
        port = self.unused_port(protocol)
        ready_file = os.path.join(self.work_dir, "%s.ready" % protocol)
        process = subprocess.Popen(
            [sys.executable, HELPER, "serve", protocol, "127.0.0.1", str(port), ready_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.processes.append(process)
        deadline = time.time() + 4
        while time.time() < deadline:
            if os.path.exists(ready_file):
                return port
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                self.fail("server exited early: %r %r" % (stdout, stderr))
            time.sleep(0.05)
        self.fail("server did not create ready file")

    def probe(self, protocol, port, nonce, timeout="0.5"):
        return subprocess.Popen(
            [
                sys.executable,
                HELPER,
                "probe",
                protocol,
                "127.0.0.1",
                str(port),
                nonce,
                timeout,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def assert_round_trip(self, protocol):
        port = self.start_server(protocol)
        nonce = "%s-%s" % (protocol, uuid.uuid4())
        process = self.probe(protocol, port, nonce)
        stdout, stderr = process.communicate()
        self.assertEqual(0, process.returncode, (stdout, stderr))
        self.assertEqual(nonce.encode("utf-8"), stdout.rstrip(b"\r\n"))
        self.assertEqual(b"", stderr)

    def test_tcp_exact_nonce(self):
        self.assert_round_trip("tcp")

    def test_udp_exact_nonce(self):
        self.assert_round_trip("udp")

    def test_closed_udp_port_is_not_reachable(self):
        process = self.probe("udp", self.unused_port("udp"), "must-not-return", "0.2")
        stdout, stderr = process.communicate()
        self.assertEqual(2, process.returncode, (stdout, stderr))
        self.assertEqual(b"", stdout)

    def test_invalid_port_fails_before_ready(self):
        ready_file = os.path.join(self.work_dir, "invalid.ready")
        process = subprocess.Popen(
            [sys.executable, HELPER, "serve", "tcp", "127.0.0.1", "0", ready_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        stdout, stderr = process.communicate()
        self.assertNotEqual(0, process.returncode, (stdout, stderr))
        self.assertFalse(os.path.exists(ready_file))

    def test_payload_over_256_bytes_is_rejected(self):
        process = self.probe("tcp", self.unused_port("tcp"), "x" * 257)
        stdout, stderr = process.communicate()
        self.assertNotEqual(0, process.returncode, (stdout, stderr))
        self.assertIn(b"nonce", stderr.lower())


if __name__ == "__main__":
    unittest.main()

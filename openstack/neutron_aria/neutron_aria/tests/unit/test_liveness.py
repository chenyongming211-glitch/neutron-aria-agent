from __future__ import absolute_import

import json
import os
import shutil
import stat
import tempfile
import unittest

from neutron_aria.agent.liveness import LIVENESS_RECORD_FILENAME
from neutron_aria.agent.liveness import LivenessError
from neutron_aria.agent.liveness import ServiceLivenessPublisher
from neutron_aria.agent.liveness import validate_service_liveness
from neutron_aria.agent.service import AgentService


class ServiceLivenessRecordTestCase(unittest.TestCase):
    def setUp(self):
        self.state_dir = tempfile.mkdtemp(prefix="neutron-aria-liveness-")
        self.path = os.path.join(self.state_dir, LIVENESS_RECORD_FILENAME)

    def tearDown(self):
        shutil.rmtree(self.state_dir)

    def _write(self, payload):
        with open(self.path, "w") as stream:
            json.dump(payload, stream)

    def test_publish_is_atomic_bounded_and_fsyncs_file_and_directory(self):
        real_fsync = os.fsync
        real_rename = os.rename
        fsync_modes = []
        renames = []

        def recording_fsync(fd):
            fsync_modes.append(os.fstat(fd).st_mode)
            return real_fsync(fd)

        def recording_rename(source, target):
            renames.append((source, target))
            return real_rename(source, target)

        os.fsync = recording_fsync
        os.rename = recording_rename
        try:
            publisher = ServiceLivenessPublisher(
                self.state_dir,
                "compute-1.example.test",
                pid=4242,
                clock=lambda: 1000.25,
            )
            record = publisher.publish()
        finally:
            os.fsync = real_fsync
            os.rename = real_rename

        self.assertEqual(
            {
                "schema_version": 1,
                "pid": 4242,
                "host": "compute-1.example.test",
                "updated_at": 1000.25,
            },
            record,
        )
        self.assertEqual([LIVENESS_RECORD_FILENAME], os.listdir(self.state_dir))
        self.assertEqual(1, len(renames))
        self.assertEqual(self.path, renames[0][1])
        self.assertEqual(self.state_dir, os.path.dirname(renames[0][0]))
        self.assertTrue(any(stat.S_ISREG(mode) for mode in fsync_modes))
        self.assertTrue(any(stat.S_ISDIR(mode) for mode in fsync_modes))
        self.assertLess(os.path.getsize(self.path), 4096)

    def test_validate_accepts_fresh_exact_pid_at_age_limit(self):
        self._write({
            "schema_version": 1,
            "pid": 4242,
            "host": "compute-1.example.test",
            "updated_at": 880.0,
        })

        record = validate_service_liveness(
            self.path,
            expected_pid=4242,
            now=1000.0,
        )

        self.assertEqual(4242, record["pid"])

    def test_validate_rejects_missing_record(self):
        self.assertRaises(
            LivenessError,
            validate_service_liveness,
            self.path,
            expected_pid=4242,
            now=1000.0,
        )

    def test_validate_rejects_pid_mismatch(self):
        self._write({
            "schema_version": 1,
            "pid": 4241,
            "host": "compute-1.example.test",
            "updated_at": 1000.0,
        })

        self.assertRaises(
            LivenessError,
            validate_service_liveness,
            self.path,
            expected_pid=4242,
            now=1000.0,
        )

    def test_validate_rejects_malformed_record(self):
        with open(self.path, "w") as stream:
            stream.write("{not-json")

        self.assertRaises(
            LivenessError,
            validate_service_liveness,
            self.path,
            expected_pid=4242,
            now=1000.0,
        )

    def test_validate_rejects_wrong_schema_and_shape(self):
        invalid_records = (
            {
                "schema_version": 2,
                "pid": 4242,
                "host": "compute-1.example.test",
                "updated_at": 1000.0,
            },
            {
                "schema_version": 1,
                "pid": "4242",
                "host": "compute-1.example.test",
                "updated_at": 1000.0,
            },
            {
                "schema_version": 1,
                "pid": 4242,
                "host": "",
                "updated_at": 1000.0,
            },
        )
        for record in invalid_records:
            self._write(record)
            self.assertRaises(
                LivenessError,
                validate_service_liveness,
                self.path,
                expected_pid=4242,
                now=1000.0,
            )

    def test_validate_rejects_record_older_than_120_seconds(self):
        self._write({
            "schema_version": 1,
            "pid": 4242,
            "host": "compute-1.example.test",
            "updated_at": 879.999,
        })

        self.assertRaises(
            LivenessError,
            validate_service_liveness,
            self.path,
            expected_pid=4242,
            now=1000.0,
        )

    def test_validate_rejects_oversized_record_before_json_decode(self):
        with open(self.path, "w") as stream:
            stream.write(" " * 4097)

        self.assertRaises(
            LivenessError,
            validate_service_liveness,
            self.path,
            expected_pid=4242,
            now=1000.0,
        )


class _RuntimeStatus(object):
    def __init__(self):
        self.status = {}

    def mark_degraded(self, reason, error):
        self.status = {"degraded": True, "reason": reason, "error": error}

    def to_dict(self):
        return dict(self.status)


class _Synchronizer(object):
    host = "compute-1.example.test"

    def __init__(self):
        self.runtime_status = _RuntimeStatus()

    def report_status(self):
        return {"ok": True, "status": self.runtime_status.to_dict()}


class _Publisher(object):
    def __init__(self):
        self.calls = 0

    def publish(self):
        self.calls += 1


class AgentServiceLivenessTestCase(unittest.TestCase):
    def test_service_publishes_at_initialize_and_after_every_run_once(self):
        publisher = _Publisher()
        service = AgentService(
            _Synchronizer(),
            full_resync_enabled=False,
            report_interval=30,
            clock=lambda: 0,
            liveness_publisher=publisher,
        )

        service.initialize()
        self.assertEqual(1, publisher.calls)

        service.run_once()
        service.run_once()
        self.assertEqual(3, publisher.calls)


if __name__ == "__main__":
    unittest.main()

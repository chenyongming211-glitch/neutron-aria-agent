from __future__ import absolute_import

import json
import math
import optparse
import os
import sys
import tempfile
import time


LIVENESS_SCHEMA_VERSION = 1
LIVENESS_RECORD_FILENAME = "service-liveness.json"
DEFAULT_LIVENESS_RECORD_PATH = os.path.join(
    "/var/lib/neutron-aria-agent/state",
    LIVENESS_RECORD_FILENAME,
)
MAX_LIVENESS_AGE_SECONDS = 120
MAX_LIVENESS_RECORD_BYTES = 4096
_REQUIRED_FIELDS = frozenset(("schema_version", "pid", "host", "updated_at"))
try:
    _STRING_TYPES = (basestring,)
except NameError:
    _STRING_TYPES = (str,)


class LivenessError(Exception):
    pass


def _is_number(value):
    return (
        isinstance(value, (int, float)) and
        not isinstance(value, bool) and
        not math.isnan(float(value)) and
        not math.isinf(float(value))
    )


class ServiceLivenessPublisher(object):
    """Publish bounded service-loop evidence using a durable atomic replace."""

    def __init__(self, state_dir, host, pid=None, clock=None):
        self.state_dir = state_dir
        self.host = host
        self.pid = os.getpid() if pid is None else pid
        self.clock = clock or time.time
        self.path = os.path.join(state_dir, LIVENESS_RECORD_FILENAME)

    def publish(self):
        record = {
            "schema_version": LIVENESS_SCHEMA_VERSION,
            "pid": self.pid,
            "host": self.host,
            "updated_at": self.clock(),
        }
        encoded = json.dumps(
            record,
            separators=(",", ":"),
            sort_keys=True,
        )
        if len(encoded.encode("utf-8")) > MAX_LIVENESS_RECORD_BYTES:
            raise LivenessError("service liveness record exceeds size limit")

        if not os.path.isdir(self.state_dir):
            os.makedirs(self.state_dir)
        fd, temporary_path = tempfile.mkstemp(
            prefix=".%s." % LIVENESS_RECORD_FILENAME,
            dir=self.state_dir,
        )
        try:
            with os.fdopen(fd, "w") as stream:
                fd = None
                stream.write(encoded)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.rename(temporary_path, self.path)
            temporary_path = None
            directory_fd = os.open(self.state_dir, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if fd is not None:
                os.close(fd)
            if temporary_path is not None:
                try:
                    os.unlink(temporary_path)
                except OSError:
                    pass
        return record


def validate_service_liveness(
    path=DEFAULT_LIVENESS_RECORD_PATH,
    expected_pid=None,
    now=None,
    max_age=MAX_LIVENESS_AGE_SECONDS,
):
    if expected_pid is None:
        raise LivenessError("expected service PID is required")
    try:
        with open(path, "rb") as stream:
            encoded = stream.read(MAX_LIVENESS_RECORD_BYTES + 1)
    except (IOError, OSError) as exc:
        raise LivenessError("service liveness record unavailable: %s" % exc)
    if len(encoded) > MAX_LIVENESS_RECORD_BYTES:
        raise LivenessError("service liveness record exceeds size limit")
    try:
        record = json.loads(encoded)
    except (TypeError, ValueError) as exc:
        raise LivenessError("service liveness record is malformed: %s" % exc)
    if not isinstance(record, dict) or set(record) != _REQUIRED_FIELDS:
        raise LivenessError("service liveness record has an invalid shape")
    if record.get("schema_version") != LIVENESS_SCHEMA_VERSION:
        raise LivenessError("service liveness schema version mismatch")
    pid = record.get("pid")
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        raise LivenessError("service liveness PID is malformed")
    if pid != expected_pid:
        raise LivenessError("service liveness PID mismatch")
    host = record.get("host")
    if not isinstance(host, _STRING_TYPES) or not host.strip():
        raise LivenessError("service liveness host is malformed")
    updated_at = record.get("updated_at")
    if not _is_number(updated_at) or updated_at <= 0:
        raise LivenessError("service liveness updated_at is malformed")
    observed_at = time.time() if now is None else now
    if not _is_number(observed_at):
        raise LivenessError("service liveness observation time is malformed")
    if observed_at - updated_at > max_age:
        raise LivenessError("service liveness record is stale")
    return record


def main(argv=None):
    parser = optparse.OptionParser()
    parser.add_option(
        "--record",
        dest="record",
        default=DEFAULT_LIVENESS_RECORD_PATH,
    )
    parser.add_option(
        "--expected-pid",
        dest="expected_pid",
        type="int",
        default=int(os.environ.get("ARIA_SERVICE_PID", "1")),
    )
    options, _args = parser.parse_args(argv)
    try:
        validate_service_liveness(
            options.record,
            expected_pid=options.expected_pid,
        )
    except LivenessError as exc:
        sys.stderr.write("neutron-aria-agent liveness failed: %s\n" % exc)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

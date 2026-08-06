import importlib.util
import errno
import io
import os
import tempfile
import unittest
from unittest import mock


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DRIVER_PATH = os.path.join(
    ROOT, "deploy", "smoke", "lib", "fragment_tracking_field_driver.py"
)


def load_driver():
    spec = importlib.util.spec_from_file_location("fragment_tracking_field_driver", DRIVER_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Python36Popen:
    def __init__(self, command, **kwargs):
        if "text" in kwargs:
            raise TypeError("__init__() got an unexpected keyword argument 'text'")
        if kwargs.get("universal_newlines") is not True:
            raise AssertionError("receiver stderr must use text mode")
        self.stderr = io.StringIO()
        self.returncode = None
        self._running = True
        with open(command[-3], "w", encoding="utf-8"):
            pass

    def poll(self):
        return None if self._running else self.returncode

    def kill(self):
        self._running = False
        self.returncode = -9

    def wait(self):
        self._running = False
        return self.returncode


class FragmentTrackingDriverCompatibilityTests(unittest.TestCase):
    def test_receiver_uses_python36_compatible_text_mode(self):
        driver = load_driver()
        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.object(driver.subprocess, "Popen", Python36Popen):
                with driver.receiver(
                    None, "ipv4", "127.0.0.1", "token", timeout=0.5,
                    directory=os.path.join(directory, "receiver"),
                ):
                    pass

    def test_expected_drop_continues_after_tc_enobufs(self):
        driver = load_driver()
        raw = mock.MagicMock()
        raw.__enter__.return_value = raw
        raw.sendto.side_effect = [OSError(errno.ENOBUFS, "drop"), None]
        with mock.patch.object(driver.socket, "AF_PACKET", 17, create=True), \
                mock.patch.object(driver.socket, "socket", return_value=raw):
            driver.send_frames("tap-test", [b"first", b"second"],
                               tolerate_no_buffer=True)
        self.assertEqual(raw.sendto.call_count, 2)

    def test_allowed_delivery_does_not_hide_tc_enobufs(self):
        driver = load_driver()
        raw = mock.MagicMock()
        raw.__enter__.return_value = raw
        raw.sendto.side_effect = OSError(errno.ENOBUFS, "drop")
        with mock.patch.object(driver.socket, "AF_PACKET", 17, create=True), \
                mock.patch.object(driver.socket, "socket", return_value=raw):
            with self.assertRaises(OSError):
                driver.send_frames("tap-test", [b"first"])

    def test_lru_pressure_accepts_bounded_old_kernel_batch_reclaim(self):
        driver = load_driver()
        snapshot = driver.parse_metrics(
            driver._metric_fixture("/p", "ipv4", occupancy=1, maximum=8)
        )
        self.assertEqual(
            driver.require_pressure_range(snapshot, "/p", "ipv4", 1, 8, 8),
            1,
        )
        with self.assertRaises(RuntimeError):
            driver.require_pressure_range(snapshot, "/p", "ipv4", 2, 8, 8)


if __name__ == "__main__":
    unittest.main()

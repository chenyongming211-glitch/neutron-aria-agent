import importlib.util
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


if __name__ == "__main__":
    unittest.main()

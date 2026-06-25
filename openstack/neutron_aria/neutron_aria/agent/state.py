from __future__ import absolute_import

import copy
import errno
import hashlib
import json
import os
import time


STATE_SCHEMA_VERSION = 1
DEFAULT_STATE_DIR = "/var/lib/neutron-aria-agent/state"
DEFAULT_STATE_FILENAME = "snapshot-state.json"


def _now():
    return time.time()


def _json_bytes(payload):
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    if isinstance(text, bytes):
        return text
    return text.encode("utf-8")


def desired_snapshot_hash(snapshot):
    """Return a deterministic hash for desired state, excluding generation."""
    payload = copy.deepcopy(snapshot)
    payload.pop("generation", None)
    payload.pop("desired_hash", None)
    payload.pop("schema_version", None)
    ports = payload.get("ports")
    if isinstance(ports, list):
        payload["ports"] = sorted(
            ports,
            key=lambda port: (
                port.get("port_id") or "",
                port.get("ifname") or "",
            ),
        )
    return hashlib.sha256(_json_bytes(payload)).hexdigest()


def _int_value(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class SnapshotStateStore(object):
    """Durable local transaction state for neutron-aria-agent snapshots."""

    def __init__(self, state_dir=None, filename=DEFAULT_STATE_FILENAME):
        self.state_dir = state_dir or DEFAULT_STATE_DIR
        self.path = os.path.join(self.state_dir, filename)
        self._state = self._load()

    def prepare_snapshot(self, snapshot):
        desired_hash = desired_snapshot_hash(snapshot)
        pending_generation = _int_value(self._state.get("pending_generation"))
        pending_hash = self._state.get("pending_desired_hash")
        reused_pending = bool(
            pending_generation and pending_hash == desired_hash
        )
        generation = self._select_generation(desired_hash)
        self._state["pending_generation"] = generation
        self._state["pending_desired_hash"] = desired_hash
        self._state["pending_since"] = _now()
        self._state["updated_at"] = _now()
        self._write()
        return {
            "generation": generation,
            "desired_hash": desired_hash,
            "reused_pending": reused_pending,
        }

    def commit_snapshot(self, generation, desired_hash, snapshot_ports=0, managed_ports=0):
        generation = _int_value(generation)
        self._state["last_generation"] = generation
        self._state["last_desired_hash"] = desired_hash
        self._state["last_snapshot_ports"] = int(snapshot_ports or 0)
        self._state["last_managed_ports"] = int(managed_ports or 0)
        self._state["last_committed_at"] = _now()
        if (
            _int_value(self._state.get("pending_generation")) == generation and
            self._state.get("pending_desired_hash") == desired_hash
        ):
            self._state["pending_generation"] = None
            self._state["pending_desired_hash"] = None
            self._state["pending_since"] = None
        self._state["updated_at"] = _now()
        self._write()

    def to_dict(self):
        return copy.deepcopy(self._state)

    def _select_generation(self, desired_hash):
        pending_generation = _int_value(self._state.get("pending_generation"))
        pending_hash = self._state.get("pending_desired_hash")
        if pending_generation and pending_hash == desired_hash:
            return pending_generation

        last_generation = _int_value(self._state.get("last_generation"))
        last_hash = self._state.get("last_desired_hash")
        if last_generation and last_hash == desired_hash:
            return last_generation

        return max(last_generation, pending_generation) + 1

    def _load(self):
        try:
            with open(self.path, "r") as fh:
                payload = json.load(fh)
        except IOError as exc:
            if exc.errno != errno.ENOENT:
                raise
            payload = {}
        payload.setdefault("schema_version", STATE_SCHEMA_VERSION)
        payload.setdefault("last_generation", 0)
        payload.setdefault("last_desired_hash", None)
        payload.setdefault("pending_generation", None)
        payload.setdefault("pending_desired_hash", None)
        payload.setdefault("pending_since", None)
        payload.setdefault("last_snapshot_ports", 0)
        payload.setdefault("last_managed_ports", 0)
        payload.setdefault("last_committed_at", None)
        payload.setdefault("updated_at", None)
        return payload

    def _write(self):
        try:
            os.makedirs(self.state_dir)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise
        tmp_path = "%s.tmp.%s" % (self.path, os.getpid())
        with open(tmp_path, "w") as fh:
            json.dump(self._state, fh, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        self._replace(tmp_path, self.path)

    def _replace(self, tmp_path, path):
        replace = getattr(os, "replace", None)
        if replace is not None:
            replace(tmp_path, path)
            return
        try:
            os.rename(tmp_path, path)
        except OSError as exc:
            if exc.errno != errno.EEXIST:
                raise
            os.unlink(path)
            os.rename(tmp_path, path)


class InMemorySnapshotStateStore(SnapshotStateStore):
    def __init__(self):
        self.state_dir = None
        self.path = None
        self._state = self._load()

    def _load(self):
        payload = {}
        payload.setdefault("schema_version", STATE_SCHEMA_VERSION)
        payload.setdefault("last_generation", 0)
        payload.setdefault("last_desired_hash", None)
        payload.setdefault("pending_generation", None)
        payload.setdefault("pending_desired_hash", None)
        payload.setdefault("pending_since", None)
        payload.setdefault("last_snapshot_ports", 0)
        payload.setdefault("last_managed_ports", 0)
        payload.setdefault("last_committed_at", None)
        payload.setdefault("updated_at", None)
        return payload

    def _write(self):
        return None

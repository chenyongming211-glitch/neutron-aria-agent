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


def _projected_port_ids(snapshot):
    ports = snapshot.get("ports") or []
    return sorted([
        port.get("port_id") for port in ports
        if port.get("port_id") and (
            port.get("eligible") or port.get("managed_domains")
        )
    ])


def _scoped_projected_port_ids(snapshot, current_projected_port_ids):
    projected = set(current_projected_port_ids or [])
    for port in snapshot.get("ports") or []:
        port_id = port.get("port_id")
        if not port_id:
            continue
        if port.get("eligible") or port.get("managed_domains"):
            projected.add(port_id)
        else:
            projected.discard(port_id)
    return sorted(projected)


class SnapshotStateStore(object):
    """Durable local transaction state for neutron-aria-agent snapshots."""

    def __init__(self, state_dir=None, filename=DEFAULT_STATE_FILENAME):
        self.state_dir = state_dir or DEFAULT_STATE_DIR
        self.path = os.path.join(self.state_dir, filename)
        self._state = self._load()

    def prepare_snapshot(self, snapshot, minimum_generation=0):
        minimum_generation = _int_value(minimum_generation)
        desired_hash = desired_snapshot_hash(snapshot)
        pending_generation = _int_value(self._state.get("pending_generation"))
        pending_hash = self._state.get("pending_desired_hash")
        generation = self._select_generation(desired_hash, minimum_generation)
        reused_pending = bool(
            pending_generation and
            pending_hash == desired_hash and
            pending_generation == generation
        )
        self._state["pending_generation"] = generation
        self._state["pending_desired_hash"] = desired_hash
        self._state["pending_snapshot_ports"] = len(snapshot.get("ports") or [])
        self._state["pending_projected_port_ids"] = _projected_port_ids(snapshot)
        self._state["pending_since"] = _now()
        self._state["updated_at"] = _now()
        self._write()
        return {
            "generation": generation,
            "desired_hash": desired_hash,
            "reused_pending": reused_pending,
        }

    def prepare_scoped_snapshot(self, snapshot, minimum_generation=0):
        minimum_generation = _int_value(minimum_generation)
        desired_hash = desired_snapshot_hash(snapshot)
        pending_generation = _int_value(self._state.get("pending_generation"))
        pending_hash = self._state.get("pending_desired_hash")
        generation = self._select_generation(desired_hash, minimum_generation)
        reused_pending = bool(
            pending_generation and
            pending_hash == desired_hash and
            pending_generation == generation
        )
        projected_port_ids = _scoped_projected_port_ids(
            snapshot,
            self._state.get("last_projected_port_ids") or [],
        )
        self._state["pending_generation"] = generation
        self._state["pending_desired_hash"] = desired_hash
        self._state["pending_snapshot_ports"] = (
            _int_value(self._state.get("last_snapshot_ports")) or
            len(projected_port_ids)
        )
        self._state["pending_projected_port_ids"] = projected_port_ids
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
        self._state["last_projected_port_ids"] = list(
            self._state.get("pending_projected_port_ids") or []
        )
        self._state["last_committed_at"] = _now()
        if (
            _int_value(self._state.get("pending_generation")) == generation and
            self._state.get("pending_desired_hash") == desired_hash
        ):
            self._state["pending_generation"] = None
            self._state["pending_desired_hash"] = None
            self._state["pending_snapshot_ports"] = 0
            self._state["pending_projected_port_ids"] = []
            self._state["pending_since"] = None
        self._state["updated_at"] = _now()
        self._write()

    def commit_scoped_snapshot(self, generation, desired_hash, managed_ports=0):
        generation = _int_value(generation)
        self._state["last_generation"] = generation
        self._state["last_desired_hash"] = desired_hash
        self._state["last_snapshot_ports"] = (
            _int_value(self._state.get("pending_snapshot_ports")) or
            _int_value(self._state.get("last_snapshot_ports"))
        )
        self._state["last_managed_ports"] = int(managed_ports or 0)
        self._state["last_projected_port_ids"] = list(
            self._state.get("pending_projected_port_ids") or
            self._state.get("last_projected_port_ids") or []
        )
        self._state["last_committed_at"] = _now()
        if (
            _int_value(self._state.get("pending_generation")) == generation and
            self._state.get("pending_desired_hash") == desired_hash
        ):
            self._state["pending_generation"] = None
            self._state["pending_desired_hash"] = None
            self._state["pending_snapshot_ports"] = 0
            self._state["pending_projected_port_ids"] = []
            self._state["pending_since"] = None
        self._state["updated_at"] = _now()
        self._write()

    def prepare_delete(self, port_id, reason=None):
        self._state["pending_delete_port_id"] = port_id
        self._state["pending_delete_reason"] = reason
        self._state["pending_delete_since"] = _now()
        self._state["updated_at"] = _now()
        self._write()
        return {
            "port_id": port_id,
            "reason": reason,
        }

    def commit_delete(self, port_id):
        if self._state.get("pending_delete_port_id") == port_id:
            self._state["pending_delete_port_id"] = None
            self._state["pending_delete_reason"] = None
            self._state["pending_delete_since"] = None
        projected = [
            projected for projected in self._state.get("last_projected_port_ids") or []
            if projected != port_id
        ]
        self._state["last_projected_port_ids"] = projected
        self._state["last_deleted_port_id"] = port_id
        self._state["last_delete_committed_at"] = _now()
        self._state["updated_at"] = _now()
        self._write()

    def pending_snapshot(self):
        generation = _int_value(self._state.get("pending_generation"))
        desired_hash = self._state.get("pending_desired_hash")
        if not generation or not desired_hash:
            return None
        return {
            "generation": generation,
            "desired_hash": desired_hash,
            "snapshot_ports": _int_value(self._state.get("pending_snapshot_ports")),
            "projected_port_ids": list(
                self._state.get("pending_projected_port_ids") or []
            ),
            "pending_since": self._state.get("pending_since"),
        }

    def pending_delete(self):
        port_id = self._state.get("pending_delete_port_id")
        if not port_id:
            return None
        return {
            "port_id": port_id,
            "reason": self._state.get("pending_delete_reason"),
            "pending_since": self._state.get("pending_delete_since"),
        }

    def last_projected_port_ids(self):
        return list(self._state.get("last_projected_port_ids") or [])

    def to_dict(self):
        return copy.deepcopy(self._state)

    def _select_generation(self, desired_hash, minimum_generation=0):
        minimum_generation = _int_value(minimum_generation)
        pending_generation = _int_value(self._state.get("pending_generation"))
        pending_hash = self._state.get("pending_desired_hash")
        if (
            pending_generation and
            pending_hash == desired_hash and
            pending_generation >= minimum_generation
        ):
            return pending_generation

        last_generation = _int_value(self._state.get("last_generation"))
        last_hash = self._state.get("last_desired_hash")
        if (
            last_generation and
            last_hash == desired_hash and
            last_generation >= minimum_generation
        ):
            return last_generation

        return max(last_generation, pending_generation, minimum_generation) + 1

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
        payload.setdefault("pending_snapshot_ports", 0)
        payload.setdefault("pending_projected_port_ids", [])
        payload.setdefault("pending_since", None)
        payload.setdefault("last_snapshot_ports", 0)
        payload.setdefault("last_managed_ports", 0)
        payload.setdefault("last_projected_port_ids", [])
        payload.setdefault("last_committed_at", None)
        payload.setdefault("pending_delete_port_id", None)
        payload.setdefault("pending_delete_reason", None)
        payload.setdefault("pending_delete_since", None)
        payload.setdefault("last_deleted_port_id", None)
        payload.setdefault("last_delete_committed_at", None)
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
        payload.setdefault("pending_snapshot_ports", 0)
        payload.setdefault("pending_projected_port_ids", [])
        payload.setdefault("pending_since", None)
        payload.setdefault("last_snapshot_ports", 0)
        payload.setdefault("last_managed_ports", 0)
        payload.setdefault("last_projected_port_ids", [])
        payload.setdefault("last_committed_at", None)
        payload.setdefault("pending_delete_port_id", None)
        payload.setdefault("pending_delete_reason", None)
        payload.setdefault("pending_delete_since", None)
        payload.setdefault("last_deleted_port_id", None)
        payload.setdefault("last_delete_committed_at", None)
        payload.setdefault("updated_at", None)
        return payload

    def _write(self):
        return None

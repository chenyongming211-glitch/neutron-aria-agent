from __future__ import absolute_import

import copy
import errno
import hashlib
import json
import os
import time

try:
    _STRING_TYPES = (basestring,)
except NameError:
    _STRING_TYPES = (str,)


STATE_SCHEMA_VERSION = 1
DEFAULT_STATE_DIR = "/var/lib/neutron-aria-agent/state"
DEFAULT_STATE_FILENAME = "snapshot-state.json"
SNAPSHOT_REQUEST_MAX_BYTES = 1048576


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


def _state_defaults():
    """Return a fresh state payload with legacy and explicit track fields."""
    return {
        "schema_version": STATE_SCHEMA_VERSION,
        "last_generation": 0,
        "last_desired_hash": None,
        "last_projected_port_ids": [],
        "last_classified_generation": 0,
        "last_classified_desired_hash": None,
        "last_classified_projected_port_ids": [],
        "last_feature_ready_generation": 0,
        "last_feature_ready_desired_hash": None,
        "last_feature_ready_projected_port_ids": [],
        "last_feature_ready_generation_by_domain": {},
        "pending_generation": None,
        "pending_desired_hash": None,
        "pending_snapshot_ports": 0,
        "pending_projected_port_ids": [],
        "pending_scope": None,
        "pending_affected_port_ids": None,
        "pending_since": None,
        "pending_request": None,
        "pending_retry_count": 0,
        "pending_last_retry_at": None,
        "last_snapshot_ports": 0,
        "last_managed_ports": 0,
        "last_committed_at": None,
        "pending_delete_port_id": None,
        "pending_delete_reason": None,
        "pending_delete_since": None,
        "last_deleted_port_id": None,
        "last_delete_committed_at": None,
        "last_cleared_pending_generation": None,
        "last_cleared_pending_desired_hash": None,
        "last_cleared_pending_reason": None,
        "last_cleared_pending_at": None,
        "updated_at": None,
    }


def _normalize_state(payload):
    """Migrate version-1 legacy state into the two explicit live tracks."""
    payload = payload or {}
    legacy_generation = payload.get(
        "last_generation",
        payload.get("last_feature_ready_generation", 0),
    )
    legacy_desired_hash = payload.get(
        "last_desired_hash",
        payload.get("last_feature_ready_desired_hash"),
    )
    legacy_projected_port_ids = list(
        payload.get(
            "last_projected_port_ids",
            payload.get("last_feature_ready_projected_port_ids") or [],
        ) or []
    )

    payload.setdefault("last_classified_generation", legacy_generation)
    payload.setdefault("last_classified_desired_hash", legacy_desired_hash)
    payload.setdefault(
        "last_classified_projected_port_ids",
        list(legacy_projected_port_ids),
    )
    payload.setdefault("last_feature_ready_generation", legacy_generation)
    payload.setdefault("last_feature_ready_desired_hash", legacy_desired_hash)
    payload.setdefault(
        "last_feature_ready_projected_port_ids",
        list(legacy_projected_port_ids),
    )
    payload.setdefault("last_feature_ready_generation_by_domain", {})

    defaults = _state_defaults()
    for key, value in defaults.items():
        if key not in payload:
            payload[key] = copy.deepcopy(value)
    return payload


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


def _affected_port_ids(snapshot):
    return sorted(set(
        port.get("port_id") for port in snapshot.get("ports") or []
        if port.get("port_id")
    ))


class SnapshotStateStore(object):
    """Durable local transaction state for neutron-aria-agent snapshots."""

    def __init__(self, state_dir=None, filename=DEFAULT_STATE_FILENAME):
        self.state_dir = state_dir or DEFAULT_STATE_DIR
        self.path = os.path.join(self.state_dir, filename)
        self._state = self._load()

    def prepare_snapshot(
        self,
        snapshot,
        minimum_generation=0,
        force_new_generation=False,
    ):
        minimum_generation = _int_value(minimum_generation)
        desired_hash = desired_snapshot_hash(snapshot)
        pending_generation = _int_value(self._state.get("pending_generation"))
        pending_hash = self._state.get("pending_desired_hash")
        generation = self._select_generation(
            desired_hash,
            minimum_generation,
            force_new_generation=force_new_generation,
        )
        request = self._build_pending_request(
            snapshot,
            generation,
            desired_hash,
            {"type": "full_host"},
        )
        self._require_pending_snapshot_match(desired_hash)
        reused_pending = bool(
            not force_new_generation and
            pending_generation and
            pending_hash == desired_hash and
            pending_generation == generation
        )
        self._state["pending_generation"] = generation
        self._state["pending_desired_hash"] = desired_hash
        self._state["pending_snapshot_ports"] = len(snapshot.get("ports") or [])
        self._state["pending_projected_port_ids"] = _projected_port_ids(snapshot)
        self._state["pending_scope"] = "full_host"
        self._state["pending_affected_port_ids"] = list(
            self._state["pending_projected_port_ids"]
        )
        self._state["pending_since"] = _now()
        self._set_pending_request(request, reused_pending)
        self._state["updated_at"] = _now()
        self._write()
        return {
            "generation": generation,
            "desired_hash": desired_hash,
            "reused_pending": reused_pending,
        }

    def prepare_snapshot_at_generation(self, snapshot, generation, desired_hash=None):
        generation = _int_value(generation)
        if generation <= 0:
            generation = 1
        desired_hash = desired_hash or desired_snapshot_hash(snapshot)
        request = self._build_pending_request(
            snapshot,
            generation,
            desired_hash,
            {"type": "full_host"},
        )
        self._require_pending_snapshot_match(desired_hash)
        pending_generation = _int_value(self._state.get("pending_generation"))
        pending_hash = self._state.get("pending_desired_hash")
        reused_pending = bool(
            pending_generation and
            pending_hash == desired_hash and
            pending_generation == generation
        )
        self._state["pending_generation"] = generation
        self._state["pending_desired_hash"] = desired_hash
        self._state["pending_snapshot_ports"] = len(snapshot.get("ports") or [])
        self._state["pending_projected_port_ids"] = _projected_port_ids(snapshot)
        self._state["pending_scope"] = "full_host"
        self._state["pending_affected_port_ids"] = list(
            self._state["pending_projected_port_ids"]
        )
        self._state["pending_since"] = _now()
        self._set_pending_request(request, reused_pending)
        self._state["updated_at"] = _now()
        self._write()
        return {
            "generation": generation,
            "desired_hash": desired_hash,
            "reused_pending": reused_pending,
        }

    def prepare_scoped_snapshot(
        self,
        snapshot,
        minimum_generation=0,
        force_new_generation=False,
    ):
        minimum_generation = _int_value(minimum_generation)
        desired_hash = desired_snapshot_hash(snapshot)
        pending_generation = _int_value(self._state.get("pending_generation"))
        pending_hash = self._state.get("pending_desired_hash")
        generation = self._select_generation(
            desired_hash,
            minimum_generation,
            force_new_generation=force_new_generation,
        )
        reused_pending = bool(
            not force_new_generation and
            pending_generation and
            pending_hash == desired_hash and
            pending_generation == generation
        )
        projected_port_ids = _scoped_projected_port_ids(
            snapshot,
            self._state.get("last_classified_projected_port_ids") or [],
        )
        affected_port_ids = _affected_port_ids(snapshot)
        if len(affected_port_ids) != 1:
            raise ValueError("scoped pending request requires exactly one port")
        request = self._build_pending_request(
            snapshot,
            generation,
            desired_hash,
            {"type": "port", "port_id": affected_port_ids[0]},
        )
        self._require_pending_snapshot_match(desired_hash)
        self._state["pending_generation"] = generation
        self._state["pending_desired_hash"] = desired_hash
        self._state["pending_snapshot_ports"] = (
            _int_value(self._state.get("last_snapshot_ports")) or
            len(projected_port_ids)
        )
        self._state["pending_projected_port_ids"] = projected_port_ids
        self._state["pending_scope"] = "port"
        self._state["pending_affected_port_ids"] = affected_port_ids
        self._state["pending_since"] = _now()
        self._set_pending_request(request, reused_pending)
        self._state["updated_at"] = _now()
        self._write()
        return {
            "generation": generation,
            "desired_hash": desired_hash,
            "reused_pending": reused_pending,
        }

    def _require_pending_snapshot_match(self, desired_hash):
        pending_delete = self.pending_delete()
        if pending_delete is not None:
            raise RuntimeError(
                "pending delete for port %s blocks snapshot prepare" %
                pending_delete["port_id"]
            )
        pending = self.pending_snapshot()
        if pending is None:
            return
        if pending["desired_hash"] == desired_hash:
            return
        raise RuntimeError(
            "unresolved pending snapshot generation %s cannot be replaced" %
            pending["generation"]
        )

    def _build_pending_request(
        self,
        snapshot,
        generation,
        desired_hash,
        scope,
    ):
        body = copy.deepcopy(snapshot)
        body["generation"] = generation
        body["desired_hash"] = desired_hash
        if len(_json_bytes(body)) > SNAPSHOT_REQUEST_MAX_BYTES:
            raise ValueError("snapshot request body exceeds durable limit")
        return {"scope": copy.deepcopy(scope), "body": body}

    def _set_pending_request(self, request, reused_pending):
        if reused_pending and self._validated_pending_request() is not None:
            return
        self._state["pending_request"] = copy.deepcopy(request)
        self._state["pending_retry_count"] = 0
        self._state["pending_last_retry_at"] = None

    def _validated_pending_request(self):
        request = self._state.get("pending_request")
        if not isinstance(request, dict):
            return None
        scope = request.get("scope")
        body = request.get("body")
        if not isinstance(scope, dict) or not isinstance(body, dict):
            return None
        scope_type = scope.get("type")
        if scope_type not in ("full_host", "port"):
            return None
        if scope_type == "full_host":
            if set(scope) != set(("type",)):
                return None
        else:
            port_id = scope.get("port_id")
            ports = body.get("ports")
            if (
                set(scope) != set(("type", "port_id")) or
                not isinstance(port_id, _STRING_TYPES) or
                not port_id.strip() or
                not isinstance(ports, list) or
                len(ports) != 1 or
                not isinstance(ports[0], dict) or
                ports[0].get("port_id") != port_id
            ):
                return None
        generation = _int_value(self._state.get("pending_generation"))
        desired_hash = self._state.get("pending_desired_hash")
        if (
            _int_value(body.get("generation")) != generation or
            body.get("desired_hash") != desired_hash or
            desired_snapshot_hash(body) != desired_hash or
            len(_json_bytes(body)) > SNAPSHOT_REQUEST_MAX_BYTES
        ):
            return None
        return copy.deepcopy(request)

    def _pending_matches(self, generation, desired_hash):
        return bool(
            _int_value(self._state.get("pending_generation")) == generation and
            self._state.get("pending_desired_hash") == desired_hash
        )

    def _clear_pending_fields(self):
        self._state["pending_generation"] = None
        self._state["pending_desired_hash"] = None
        self._state["pending_snapshot_ports"] = 0
        self._state["pending_projected_port_ids"] = []
        self._state["pending_scope"] = None
        self._state["pending_affected_port_ids"] = None
        self._state["pending_since"] = None
        self._state["pending_request"] = None
        self._state["pending_retry_count"] = 0
        self._state["pending_last_retry_at"] = None

    def _clear_pending_if_matches(self, generation, desired_hash):
        if not self._pending_matches(generation, desired_hash):
            return False
        self._clear_pending_fields()
        return True

    def _update_classified_track(
        self,
        generation,
        desired_hash,
        projected_port_ids,
    ):
        self._state["last_classified_generation"] = generation
        self._state["last_classified_desired_hash"] = desired_hash
        self._state["last_classified_projected_port_ids"] = list(
            projected_port_ids or []
        )

    def _update_feature_ready_track(
        self,
        generation,
        desired_hash,
        projected_port_ids,
        feature_ready_domains=None,
    ):
        self._state["last_feature_ready_generation"] = generation
        self._state["last_feature_ready_desired_hash"] = desired_hash
        self._state["last_feature_ready_projected_port_ids"] = list(
            projected_port_ids or []
        )
        history = dict(
            self._state.get("last_feature_ready_generation_by_domain") or {}
        )
        for domain in feature_ready_domains or []:
            if domain:
                history[domain] = generation
        self._state["last_feature_ready_generation_by_domain"] = history

    def _update_legacy_ready_aliases(
        self,
        generation,
        desired_hash,
        projected_port_ids,
    ):
        self._state["last_generation"] = generation
        self._state["last_desired_hash"] = desired_hash
        self._state["last_projected_port_ids"] = list(projected_port_ids or [])

    def commit_snapshot(
        self,
        generation,
        desired_hash,
        snapshot_ports=0,
        managed_ports=0,
        feature_ready_domains=None,
    ):
        generation = _int_value(generation)
        projected_port_ids = list(
            self._state.get("pending_projected_port_ids") or []
        )
        self._update_classified_track(
            generation,
            desired_hash,
            projected_port_ids,
        )
        self._update_feature_ready_track(
            generation,
            desired_hash,
            projected_port_ids,
            feature_ready_domains=feature_ready_domains,
        )
        self._update_legacy_ready_aliases(
            generation,
            desired_hash,
            projected_port_ids,
        )
        self._state["last_snapshot_ports"] = int(snapshot_ports or 0)
        self._state["last_managed_ports"] = int(managed_ports or 0)
        self._state["last_committed_at"] = _now()
        self._clear_pending_if_matches(generation, desired_hash)
        self._state["updated_at"] = _now()
        self._write()

    def commit_classified_snapshot(
        self,
        generation,
        desired_hash,
        snapshot_ports=0,
        managed_ports=0,
    ):
        generation = _int_value(generation)
        projected_port_ids = list(
            self._state.get("pending_projected_port_ids") or []
        )
        self._update_classified_track(
            generation,
            desired_hash,
            projected_port_ids,
        )
        self._state["last_snapshot_ports"] = int(snapshot_ports or 0)
        self._state["last_managed_ports"] = int(managed_ports or 0)
        self._clear_pending_if_matches(generation, desired_hash)
        self._state["updated_at"] = _now()
        self._write()

    def clear_pending_snapshot(self, reason=None):
        pending = self.pending_snapshot()
        self._clear_pending_fields()
        if pending:
            self._state["last_cleared_pending_generation"] = pending["generation"]
            self._state["last_cleared_pending_desired_hash"] = pending["desired_hash"]
            self._state["last_cleared_pending_reason"] = reason
            self._state["last_cleared_pending_at"] = _now()
        self._state["updated_at"] = _now()
        self._write()
        return pending

    def commit_scoped_snapshot(
        self,
        generation,
        desired_hash,
        managed_ports=0,
        feature_ready_domains=None,
    ):
        generation = _int_value(generation)
        if self._pending_matches(generation, desired_hash):
            projected_port_ids = list(
                self._state.get("pending_projected_port_ids") or []
            )
        else:
            projected_port_ids = list(
                self._state.get("last_classified_projected_port_ids") or []
            )
        self._update_classified_track(
            generation,
            desired_hash,
            projected_port_ids,
        )
        self._update_feature_ready_track(
            generation,
            desired_hash,
            projected_port_ids,
            feature_ready_domains=feature_ready_domains,
        )
        self._update_legacy_ready_aliases(
            generation,
            desired_hash,
            projected_port_ids,
        )
        self._state["last_snapshot_ports"] = (
            _int_value(self._state.get("pending_snapshot_ports")) or
            _int_value(self._state.get("last_snapshot_ports"))
        )
        self._state["last_managed_ports"] = int(managed_ports or 0)
        self._state["last_committed_at"] = _now()
        self._clear_pending_if_matches(generation, desired_hash)
        self._state["updated_at"] = _now()
        self._write()

    def commit_classified_scoped_snapshot(
        self,
        generation,
        desired_hash,
        managed_ports=0,
    ):
        generation = _int_value(generation)
        if self._pending_matches(generation, desired_hash):
            projected_port_ids = list(
                self._state.get("pending_projected_port_ids") or []
            )
        else:
            projected_port_ids = list(
                self._state.get("last_classified_projected_port_ids") or []
            )
        self._update_classified_track(
            generation,
            desired_hash,
            projected_port_ids,
        )
        self._state["last_snapshot_ports"] = (
            _int_value(self._state.get("pending_snapshot_ports")) or
            _int_value(self._state.get("last_snapshot_ports"))
        )
        self._state["last_managed_ports"] = int(managed_ports or 0)
        self._clear_pending_if_matches(generation, desired_hash)
        self._state["updated_at"] = _now()
        self._write()

    def realign_classified_snapshot(
        self,
        generation,
        desired_hash,
        projected_port_ids,
        recovered_pending_generation=None,
        recovered_pending_desired_hash=None,
    ):
        generation = _int_value(generation)
        self._update_classified_track(
            generation,
            desired_hash,
            projected_port_ids,
        )
        recovered_pending_generation = _int_value(
            recovered_pending_generation
        )
        if (
            recovered_pending_generation and
            recovered_pending_desired_hash is not None
        ):
            self._clear_pending_if_matches(
                recovered_pending_generation,
                recovered_pending_desired_hash,
            )
        self._state["updated_at"] = _now()
        self._write()

    def feature_ready_history(self):
        return copy.deepcopy({
            "last_classified_generation": _int_value(
                self._state.get("last_classified_generation")
            ),
            "last_feature_ready_generation": _int_value(
                self._state.get("last_feature_ready_generation")
            ),
            "last_feature_ready_desired_hash": self._state.get(
                "last_feature_ready_desired_hash"
            ),
            "last_feature_ready_projected_port_ids": list(
                self._state.get("last_feature_ready_projected_port_ids") or []
            ),
            "last_feature_ready_generation_by_domain": dict(
                self._state.get(
                    "last_feature_ready_generation_by_domain"
                ) or {}
            ),
        })

    def prepare_delete(self, port_id, reason=None):
        pending_snapshot = self.pending_snapshot()
        if pending_snapshot is not None:
            raise RuntimeError(
                "pending snapshot generation %s blocks delete prepare" %
                pending_snapshot["generation"]
            )
        pending_delete = self.pending_delete()
        if pending_delete is not None:
            if pending_delete["port_id"] == port_id:
                return pending_delete
            raise RuntimeError(
                "pending delete for port %s cannot be replaced" %
                pending_delete["port_id"]
            )
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
            projected for projected in
            self._state.get("last_classified_projected_port_ids") or []
            if projected != port_id
        ]
        self._state["last_classified_projected_port_ids"] = projected
        self._state["last_deleted_port_id"] = port_id
        self._state["last_delete_committed_at"] = _now()
        self._state["updated_at"] = _now()
        self._write()

    def pending_snapshot(self):
        generation = _int_value(self._state.get("pending_generation"))
        desired_hash = self._state.get("pending_desired_hash")
        if not generation or not desired_hash:
            return None
        request = self._validated_pending_request()
        return {
            "generation": generation,
            "desired_hash": desired_hash,
            "snapshot_ports": _int_value(self._state.get("pending_snapshot_ports")),
            "projected_port_ids": list(
                self._state.get("pending_projected_port_ids") or []
            ),
            "scope": self._state.get("pending_scope"),
            "affected_port_ids": copy.deepcopy(
                self._state.get("pending_affected_port_ids")
            ),
            "pending_since": self._state.get("pending_since"),
            "request": request,
            "retryable": request is not None,
            "retry_count": _int_value(
                self._state.get("pending_retry_count")
            ),
            "last_retry_at": self._state.get("pending_last_retry_at"),
        }

    def record_snapshot_retry(self, generation, desired_hash):
        generation = _int_value(generation)
        if (
            not self._pending_matches(generation, desired_hash) or
            self._validated_pending_request() is None
        ):
            raise RuntimeError("pending snapshot is not retryable")
        self._state["pending_retry_count"] = (
            _int_value(self._state.get("pending_retry_count")) + 1
        )
        self._state["pending_last_retry_at"] = _now()
        self._state["updated_at"] = _now()
        self._write()
        return self.pending_snapshot()

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
        return list(
            self._state.get("last_classified_projected_port_ids") or []
        )

    def to_dict(self):
        return copy.deepcopy(self._state)

    def _select_generation(
        self,
        desired_hash,
        minimum_generation=0,
        force_new_generation=False,
    ):
        minimum_generation = _int_value(minimum_generation)
        pending_generation = _int_value(self._state.get("pending_generation"))
        pending_hash = self._state.get("pending_desired_hash")
        classified_generation = _int_value(
            self._state.get("last_classified_generation")
        )
        classified_hash = self._state.get("last_classified_desired_hash")
        feature_ready_generation = _int_value(
            self._state.get("last_feature_ready_generation")
        )
        feature_ready_hash = self._state.get(
            "last_feature_ready_desired_hash"
        )
        generation_floor = max(
            classified_generation,
            feature_ready_generation,
            pending_generation,
            minimum_generation,
        )

        if force_new_generation:
            return generation_floor + 1

        if (
            pending_generation and
            pending_hash == desired_hash and
            pending_generation >= generation_floor
        ):
            return pending_generation

        if (
            classified_generation and
            classified_hash == desired_hash and
            classified_generation >= generation_floor
        ):
            return classified_generation

        if (
            feature_ready_generation and
            feature_ready_hash == desired_hash and
            feature_ready_generation >= generation_floor
        ):
            return feature_ready_generation

        return generation_floor + 1

    def _load(self):
        try:
            with open(self.path, "r") as fh:
                payload = json.load(fh)
        except IOError as exc:
            if exc.errno != errno.ENOENT:
                raise
            payload = {}
        return _normalize_state(payload)

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
        return _normalize_state({})

    def _write(self):
        return None

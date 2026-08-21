#!/usr/bin/env python3
"""Classify an Aria runtime upgrade without changing host state."""

import argparse
import copy
import errno
import fcntl
import json
import logging
import os
import re
import stat
import tempfile
import time
from collections import namedtuple
from pathlib import Path


DATAPATH_KEYS = (
    "snapshot_schema_version",
    "ebpf_abi_version",
    "map_schema_version",
    "ebpf_abi_hash",
    "map_schema_hash",
    "wal_schema_version",
    "runtime_state_schema_version",
    "minimum_kernel_profile",
    "managed_domain_contract_version",
)
REQUIRED_COMPATIBILITY = {
    "schema_version": int,
    "uds_schema_min": int,
    "uds_schema_max": int,
    "snapshot_schema_version": int,
    "ebpf_abi_version": int,
    "map_schema_version": int,
    "wal_schema_version": int,
    "runtime_state_schema_version": int,
    "minimum_kernel_profile": str,
    "managed_domain_contract_version": str,
    "maintenance_gate_capable": bool,
    "ebpf_abi_hash": str,
    "map_schema_hash": str,
}
IMAGE_COMPONENT_RE = re.compile(r"^[a-z0-9]+(?:(?:__|[._]|-+)[a-z0-9]+)*$")
REQUIRED_IMAGES = ("neutron-aria-agent", "aria-datapath")
UpgradeClassification = namedtuple("UpgradeClassification", ("path", "reasons"))

ALLOWED = {
    "preflight": ("bypass_preparing", "failed_before_mutation"),
    "bypass_preparing": ("bypass_confirmed",),
    "bypass_confirmed": ("datapath_upgrading", "maintenance_bypass", "rollback"),
    "datapath_upgrading": ("datapath_live", "maintenance_bypass", "rollback"),
    "datapath_live": ("agent_upgrading", "maintenance_bypass", "rollback"),
    "agent_upgrading": ("full_resync", "maintenance_bypass", "rollback"),
    "full_resync": ("shadow_apply", "maintenance_bypass", "rollback"),
    "shadow_apply": ("activating", "maintenance_bypass", "rollback"),
    "activating": ("verifying", "maintenance_bypass", "rollback"),
    "verifying": ("committed", "maintenance_bypass", "rollback"),
    "maintenance_bypass": ("full_resync", "rollback"),
    "rollback": ("full_resync", "maintenance_bypass"),
}
LEDGER_SCHEMA_VERSION = 1
DEFAULT_OPERATIONS_DIR = Path("/var/lib/aria-release/operations")
DEFAULT_LOCK_PATH = Path("/run/lock/aria-release.lock")
MAX_LEDGER_BYTES = 1024 * 1024
MAX_AUDIT_BYTES = 4096
OPERATION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
TERMINAL_PHASES = ("committed", "failed_before_mutation")
REQUIRED_LEDGER_FIELDS = (
    "schema_version",
    "operation_id",
    "host",
    "phase",
    "started_at",
    "last_progress_at",
    "upgrade_class",
    "affected_domains",
    "old_image_ids",
    "candidate_image_ids",
    "old_manifest_hash",
    "candidate_manifest_hash",
    "old_config_hash",
    "candidate_config_hash",
    "pre_accepted_generation",
    "pre_applied_generation",
    "pre_desired_hash",
    "pre_managed_port_ids",
    "maintenance_token",
    "ovs_vswitchd_pid",
    "ovs_agent_container_id",
    "ovs_agent_started_at",
    "br_int_uuid",
    "last_error",
    "recovery_action",
)
EVIDENCE_FIELDS = frozenset(REQUIRED_LEDGER_FIELDS) | frozenset(
    ("generation", "desired_hash")
)
IMMUTABLE_LEDGER_FIELDS = frozenset(
    ("schema_version", "operation_id", "host", "phase", "started_at")
)
LEGAL_PHASES = frozenset(ALLOWED) | frozenset(
    phase for destinations in ALLOWED.values() for phase in destinations
) | frozenset(("quiescing", "agent_buffering"))


class UpgradeLedgerError(Exception):
    """Base class for durable upgrade-ledger failures."""


class UpgradeLedgerLocked(UpgradeLedgerError):
    """Raised when another process owns the host upgrade lock."""


class UpgradeLedgerConflict(UpgradeLedgerError):
    """Raised when another operation is already pending on this host."""


class UpgradeLedgerTransitionError(UpgradeLedgerError):
    """Raised when a phase compare-and-swap or legal-edge check fails."""


class UpgradeLedgerTrustError(UpgradeLedgerError):
    """Raised when existing release state is not trusted root state."""


class UpgradeLedger(object):
    """Own the host lock and persist one crash-safe upgrade transaction.

    ``owner_uid`` remains zero for production.  Tests may inject their current
    uid because unprivileged temporary files cannot be root-owned.
    """

    def __init__(
        self,
        operations_dir=DEFAULT_OPERATIONS_DIR,
        lock_path=DEFAULT_LOCK_PATH,
        owner_uid=0,
        audit_sink=None,
        clock=None,
    ):
        self.operations_dir = Path(operations_dir)
        self.lock_path = Path(lock_path)
        self.owner_uid = owner_uid
        self.audit_sink = audit_sink
        self.clock = clock or time.time
        self._lock_fd = None
        self._state = None
        self._path = None

    @property
    def state(self):
        """Return a copy of the currently owned operation state."""
        return copy.deepcopy(self._state)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()

    def close(self):
        """Release the host lock; ledger files deliberately remain durable."""
        if self._lock_fd is not None:
            try:
                fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(self._lock_fd)
                self._lock_fd = None

    def begin(self, operation_id, host=None, upgrade_class=None, evidence=None):
        """Create or idempotently reopen an operation in ``preflight``."""
        operation_id = self._validate_operation_id(operation_id)
        self._acquire_lock()
        self._ensure_operations_dir()
        if self._state is not None:
            if self._state["operation_id"] != operation_id:
                raise UpgradeLedgerConflict("this ledger already owns another operation")
            return self.state

        pending = self._pending_ledgers()
        conflicts = [
            item for item in pending if item["operation_id"] != operation_id
        ]
        if conflicts:
            raise UpgradeLedgerConflict(
                "pending operation %s owns the host" % conflicts[0]["operation_id"]
            )

        path = self._ledger_path(operation_id)
        if path.exists() or path.is_symlink():
            state = self._read_ledger(path, operation_id)
            self._set_current(path, state)
            return self.state

        if not isinstance(host, str) or not host:
            raise ValueError("host must be a non-empty string")
        if not isinstance(upgrade_class, str) or not upgrade_class:
            raise ValueError("upgrade_class must be a non-empty string")
        if evidence is None:
            evidence = {}
        if not isinstance(evidence, dict):
            raise ValueError("evidence must be a JSON object")

        now = self.clock()
        state = {
            "schema_version": LEDGER_SCHEMA_VERSION,
            "operation_id": operation_id,
            "host": host,
            "phase": "preflight",
            "started_at": now,
            "last_progress_at": now,
            "upgrade_class": upgrade_class,
            "affected_domains": [],
            "old_image_ids": {},
            "candidate_image_ids": {},
            "old_manifest_hash": None,
            "candidate_manifest_hash": None,
            "old_config_hash": None,
            "candidate_config_hash": None,
            "pre_accepted_generation": None,
            "pre_applied_generation": None,
            "pre_desired_hash": None,
            "pre_managed_port_ids": [],
            "maintenance_token": None,
            "ovs_vswitchd_pid": None,
            "ovs_agent_container_id": None,
            "ovs_agent_started_at": None,
            "br_int_uuid": None,
            "last_error": None,
            "recovery_action": None,
        }
        self._merge_evidence(state, evidence)
        self._write_ledger(path, state)
        self._set_current(path, state)
        return self.state

    def transition(self, expected_phase, next_phase, evidence=None):
        """Atomically compare the current phase and persist one legal edge."""
        self._require_current()
        self._state = self._read_ledger(
            self._path, self._state["operation_id"]
        )
        old_phase = self._state["phase"]
        if old_phase != expected_phase:
            self._audit(old_phase, next_phase, evidence, "compare_and_swap_rejected")
            raise UpgradeLedgerTransitionError(
                "phase compare-and-swap failed: expected %s, found %s"
                % (expected_phase, old_phase)
            )
        if next_phase not in ALLOWED.get(old_phase, ()):
            self._audit(old_phase, next_phase, evidence, "invalid_transition")
            raise UpgradeLedgerTransitionError(
                "transition %s -> %s is not allowed" % (old_phase, next_phase)
            )
        next_state = copy.deepcopy(self._state)
        self._merge_evidence(next_state, evidence or {})
        next_state["phase"] = next_phase
        next_state["last_progress_at"] = self.clock()
        try:
            self._write_ledger(self._path, next_state)
        except Exception:
            self._refresh_after_write_failure()
            self._audit(old_phase, next_phase, evidence, "persistence_failed")
            raise
        self._state = next_state
        self._audit(old_phase, next_phase, evidence, "success")
        return self.state

    def fail(self, expected_phase, error, evidence=None):
        """Persist a failure without ever reactivating ACL enforcement."""
        self._require_current()
        if self._state["phase"] != expected_phase:
            raise UpgradeLedgerTransitionError(
                "phase compare-and-swap failed: expected %s, found %s"
                % (expected_phase, self._state["phase"])
            )
        if not isinstance(error, str):
            error = str(error)
        merged = dict(evidence or {})
        merged["last_error"] = error[:4096]
        if expected_phase == "preflight":
            return self.transition(expected_phase, "failed_before_mutation", merged)
        if "maintenance_bypass" in ALLOWED.get(expected_phase, ()):
            merged.setdefault("recovery_action", "operator_action_required")
            return self.transition(expected_phase, "maintenance_bypass", merged)
        merged.setdefault("recovery_action", "resume_exact_phase")
        return self._update_same_phase(merged, "failed")

    def commit(self, evidence=None):
        """Commit only the final verified phase."""
        return self.transition("verifying", "committed", evidence or {})

    def recover(self, operation_id):
        """Reopen stale state without automatically activating old ACL state."""
        operation_id = self._validate_operation_id(operation_id)
        self._acquire_lock()
        self._ensure_operations_dir()
        pending = self._pending_ledgers()
        conflicts = [
            item for item in pending if item["operation_id"] != operation_id
        ]
        if conflicts:
            raise UpgradeLedgerConflict(
                "pending operation %s owns the host" % conflicts[0]["operation_id"]
            )
        path = self._ledger_path(operation_id)
        if not path.exists() and not path.is_symlink():
            raise UpgradeLedgerError("operation ledger does not exist")
        state = self._read_ledger(path, operation_id)
        self._set_current(path, state)
        phase = state["phase"]
        if phase in TERMINAL_PHASES:
            return self.state
        if phase == "maintenance_bypass":
            if state.get("recovery_action") == "operator_action_required":
                return self.state
            return self._update_same_phase(
                {"recovery_action": "operator_action_required"}, "recovered"
            )
        if "maintenance_bypass" in ALLOWED.get(phase, ()):
            return self.transition(
                phase,
                "maintenance_bypass",
                {"recovery_action": "operator_action_required"},
            )
        return self._update_same_phase(
            {"recovery_action": "resume_exact_phase"}, "recovered"
        )

    def _validate_operation_id(self, operation_id):
        if not isinstance(operation_id, str) or OPERATION_ID_RE.fullmatch(operation_id) is None:
            raise ValueError("operation_id is not a safe identifier")
        if operation_id in (".", ".."):
            raise ValueError("operation_id is not a safe identifier")
        return operation_id

    def _ledger_path(self, operation_id):
        return self.operations_dir / (operation_id + ".json")

    def _acquire_lock(self):
        if self._lock_fd is not None:
            return
        parent = self.lock_path.parent
        if not parent.exists():
            raise UpgradeLedgerTrustError("lock directory does not exist")
        if parent.is_symlink() or not parent.is_dir():
            raise UpgradeLedgerTrustError("lock directory is not a trusted directory")
        existed = self.lock_path.exists() or self.lock_path.is_symlink()
        if existed and self.lock_path.is_symlink():
            raise UpgradeLedgerTrustError("lock path must not be a symlink")
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(str(self.lock_path), flags, 0o600)
        except OSError as error:
            raise UpgradeLedgerTrustError("lock file cannot be opened: %s" % error)
        try:
            file_stat = os.fstat(fd)
            if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_uid != self.owner_uid:
                raise UpgradeLedgerTrustError("lock file has untrusted ownership or type")
            if existed and stat.S_IMODE(file_stat.st_mode) != 0o600:
                raise UpgradeLedgerTrustError("lock file mode must be 0600")
            if not existed:
                os.fchmod(fd, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                if error.errno in (errno.EACCES, errno.EAGAIN):
                    raise UpgradeLedgerLocked("another upgrade owns the host lock")
                raise
        except Exception:
            os.close(fd)
            raise
        self._lock_fd = fd

    def _ensure_operations_dir(self):
        existed = self.operations_dir.exists() or self.operations_dir.is_symlink()
        if not existed:
            try:
                self.operations_dir.mkdir(mode=0o700, parents=True)
            except OSError as error:
                raise UpgradeLedgerTrustError(
                    "operations directory cannot be created: %s" % error
                )
        directory_stat = os.lstat(str(self.operations_dir))
        if not stat.S_ISDIR(directory_stat.st_mode):
            raise UpgradeLedgerTrustError("operations path must be a directory")
        if directory_stat.st_uid != self.owner_uid:
            raise UpgradeLedgerTrustError("operations directory owner is not trusted")
        if stat.S_IMODE(directory_stat.st_mode) & 0o022:
            raise UpgradeLedgerTrustError("operations directory must not be group/world writable")
        if not existed:
            os.chmod(str(self.operations_dir), 0o700)

    def _validate_file_stat(self, file_stat):
        if not stat.S_ISREG(file_stat.st_mode):
            raise UpgradeLedgerTrustError("ledger must be a regular file")
        if file_stat.st_uid != self.owner_uid:
            raise UpgradeLedgerTrustError("ledger owner is not trusted")
        if stat.S_IMODE(file_stat.st_mode) != 0o600:
            raise UpgradeLedgerTrustError("ledger mode must be 0600")
        if file_stat.st_nlink != 1:
            raise UpgradeLedgerTrustError("ledger must have exactly one link")

    def _read_ledger(self, path, operation_id=None):
        try:
            path_stat = os.lstat(str(path))
        except OSError as error:
            raise UpgradeLedgerTrustError("ledger cannot be inspected: %s" % error)
        self._validate_file_stat(path_stat)
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(str(path), flags)
        except OSError as error:
            raise UpgradeLedgerTrustError("ledger cannot be opened safely: %s" % error)
        try:
            opened_stat = os.fstat(fd)
            self._validate_file_stat(opened_stat)
            if (opened_stat.st_dev, opened_stat.st_ino) != (path_stat.st_dev, path_stat.st_ino):
                raise UpgradeLedgerTrustError("ledger changed while it was opened")
            chunks = []
            total = 0
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_LEDGER_BYTES:
                    raise UpgradeLedgerTrustError("ledger exceeds the size limit")
                chunks.append(chunk)
        finally:
            os.close(fd)
        try:
            state = json.loads(
                b"".join(chunks).decode("utf-8"),
                object_pairs_hook=reject_duplicate_members,
            )
        except (UnicodeError, ValueError, RecursionError) as error:
            raise UpgradeLedgerTrustError("ledger is not valid JSON: %s" % error)
        if not isinstance(state, dict):
            raise UpgradeLedgerTrustError("ledger must be a JSON object")
        missing = [field for field in REQUIRED_LEDGER_FIELDS if field not in state]
        if missing:
            raise UpgradeLedgerTrustError("ledger is missing required fields")
        if state.get("schema_version") != LEDGER_SCHEMA_VERSION:
            raise UpgradeLedgerTrustError("ledger schema version is unsupported")
        if operation_id is not None and state.get("operation_id") != operation_id:
            raise UpgradeLedgerTrustError("ledger operation identity does not match its path")
        if state.get("phase") not in LEGAL_PHASES:
            raise UpgradeLedgerTrustError("ledger phase is not recognized")
        return state

    def _pending_ledgers(self):
        pending = []
        for name in sorted(os.listdir(str(self.operations_dir))):
            if not name.endswith(".json"):
                continue
            operation_id = name[:-5]
            self._validate_operation_id(operation_id)
            state = self._read_ledger(self.operations_dir / name, operation_id)
            if state["phase"] not in TERMINAL_PHASES:
                pending.append(state)
        return pending

    def _merge_evidence(self, state, evidence):
        if not isinstance(evidence, dict):
            raise ValueError("evidence must be a JSON object")
        for key, value in evidence.items():
            if key in EVIDENCE_FIELDS and key not in IMMUTABLE_LEDGER_FIELDS:
                state[key] = copy.deepcopy(value)

    def _write_ledger(self, path, state):
        if path.exists() or path.is_symlink():
            self._read_ledger(path, state["operation_id"])
        payload = (
            json.dumps(state, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            + "\n"
        ).encode("utf-8")
        if len(payload) > MAX_LEDGER_BYTES:
            raise ValueError("ledger exceeds the size limit")
        fd = None
        temporary_path = None
        try:
            fd, temporary_path = tempfile.mkstemp(
                prefix=".%s." % state["operation_id"],
                suffix=".tmp",
                dir=str(self.operations_dir),
            )
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb") as output:
                fd = None
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.rename(temporary_path, str(path))
            temporary_path = None
            flags = os.O_RDONLY
            if hasattr(os, "O_DIRECTORY"):
                flags |= os.O_DIRECTORY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            directory_fd = os.open(str(self.operations_dir), flags)
            try:
                directory_stat = os.fstat(directory_fd)
                if (
                    not stat.S_ISDIR(directory_stat.st_mode)
                    or directory_stat.st_uid != self.owner_uid
                ):
                    raise UpgradeLedgerTrustError(
                        "operations directory changed during persistence"
                    )
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            if fd is not None:
                os.close(fd)
            if temporary_path is not None:
                try:
                    os.unlink(temporary_path)
                except FileNotFoundError:
                    pass

    def _set_current(self, path, state):
        self._path = path
        self._state = copy.deepcopy(state)

    def _require_current(self):
        if self._lock_fd is None or self._state is None or self._path is None:
            raise UpgradeLedgerError("no operation is currently owned")

    def _refresh_after_write_failure(self):
        try:
            self._state = self._read_ledger(
                self._path, self._state["operation_id"]
            )
        except UpgradeLedgerError:
            pass

    def _update_same_phase(self, evidence, result):
        self._require_current()
        old_phase = self._state["phase"]
        next_state = copy.deepcopy(self._state)
        self._merge_evidence(next_state, evidence)
        next_state["last_progress_at"] = self.clock()
        try:
            self._write_ledger(self._path, next_state)
        except Exception:
            self._refresh_after_write_failure()
            self._audit(old_phase, old_phase, evidence, "persistence_failed")
            raise
        self._state = next_state
        self._audit(old_phase, old_phase, evidence, result)
        return self.state

    def _audit_value(self, value):
        if isinstance(value, str):
            return value[:256]
        if isinstance(value, dict):
            return {
                str(key)[:128]: self._audit_value(value[key])
                for key in sorted(value, key=lambda item: str(item))[:16]
            }
        if isinstance(value, (list, tuple)):
            return [self._audit_value(item) for item in value[:16]]
        if value is None or isinstance(value, (bool, int, float)):
            return value
        return str(value)[:256]

    def _audit(self, old_phase, new_phase, evidence, result):
        evidence = evidence if isinstance(evidence, dict) else {}
        state = self._state or {}
        started_at = state.get("started_at")
        elapsed_ms = 0
        if isinstance(started_at, (int, float)):
            elapsed_ms = max(0, int((self.clock() - started_at) * 1000))
        record = {
            "operation_id": self._audit_value(state.get("operation_id")),
            "host": self._audit_value(state.get("host")),
            "old_phase": self._audit_value(old_phase),
            "new_phase": self._audit_value(new_phase),
            "elapsed_ms": elapsed_ms,
            "generation": self._audit_value(
                evidence.get("generation", state.get("generation"))
            ),
            "desired_hash": self._audit_value(
                evidence.get(
                    "desired_hash",
                    state.get("desired_hash", state.get("pre_desired_hash")),
                )
            ),
            "old_image_ids": self._audit_value(state.get("old_image_ids", {})),
            "candidate_image_ids": self._audit_value(
                state.get("candidate_image_ids", {})
            ),
            "result": self._audit_value(result),
        }
        line = json.dumps(record, sort_keys=True, separators=(",", ":"))
        if len(line.encode("utf-8")) > MAX_AUDIT_BYTES:
            record["old_image_ids"] = "<truncated>"
            record["candidate_image_ids"] = "<truncated>"
            line = json.dumps(record, sort_keys=True, separators=(",", ":"))
        if self.audit_sink is not None:
            try:
                self.audit_sink(line)
            except Exception:
                logging.getLogger(__name__).exception("upgrade ledger audit sink failed")
        else:
            logging.getLogger(__name__).info("%s", line)


def load_manifest(path):
    """Load one release manifest as a JSON object."""
    try:
        manifest = json.loads(
            Path(path).read_text(encoding="utf-8"),
            object_pairs_hook=reject_duplicate_members,
        )
    except (OSError, ValueError, RecursionError) as error:
        raise ValueError(f"manifest cannot be loaded: {error}") from error
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be a JSON object")
    return manifest


def reject_duplicate_members(pairs):
    """Build a JSON object only when each member name occurs once."""
    payload = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError("duplicate JSON object member: %s" % key)
        payload[key] = value
    return payload


def _valid_compatibility(manifest):
    if not isinstance(manifest, dict):
        return None
    compatibility = manifest.get("runtime_compatibility")
    if not isinstance(compatibility, dict):
        return None
    if set(compatibility) != set(REQUIRED_COMPATIBILITY):
        return None
    for key, expected_type in REQUIRED_COMPATIBILITY.items():
        value = compatibility[key]
        if expected_type is int:
            if type(value) is not int or value < 0:
                return None
        elif type(value) is not expected_type:
            return None
        elif expected_type is str and not value:
            return None
    if not all(
        re.fullmatch(r"[0-9a-f]{64}", compatibility[key])
        for key in ("ebpf_abi_hash", "map_schema_hash")
    ):
        return None
    if compatibility["schema_version"] != 1:
        return None
    if compatibility["uds_schema_min"] > compatibility["uds_schema_max"]:
        return None
    return compatibility


def is_valid_image_identity(identity):
    """Return true only for a conservative named immutable image reference."""
    if not isinstance(identity, str) or "@sha256:" not in identity:
        return False
    name, digest = identity.rsplit("@sha256:", 1)
    if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        return False
    parts = name.split("/")
    if not parts or any(not part for part in parts):
        return False
    for index, part in enumerate(parts):
        if ":" not in part:
            if IMAGE_COMPONENT_RE.fullmatch(part) is None:
                return False
            continue
        value, separator = part.rsplit(":", 1)
        if not value or not separator:
            return False
        if index == 0 and len(parts) > 1:
            if IMAGE_COMPONENT_RE.fullmatch(value) is None:
                return False
            if not separator.isdigit() or not 1 <= int(separator) <= 65535:
                return False
        elif index == len(parts) - 1:
            if IMAGE_COMPONENT_RE.fullmatch(value) is None:
                return False
            if IMAGE_COMPONENT_RE.fullmatch(separator) is None:
                return False
        else:
            return False
    return True


def _image_identities(manifest):
    if not isinstance(manifest, dict) or not isinstance(manifest.get("images"), list):
        return None
    identities = {}
    for image in manifest["images"]:
        if not isinstance(image, dict):
            return None
        name = image.get("name")
        identity = image.get("identity")
        if not isinstance(name, str) or not isinstance(identity, str):
            return None
        if name in identities or not is_valid_image_identity(identity):
            return None
        identities[name] = identity
    if not all(name in identities for name in REQUIRED_IMAGES):
        return None
    return identities


def _unknown():
    return UpgradeClassification("planned_maintenance", ("unknown_compatibility",))


def classify_upgrade(current, candidate, force_maintenance=False):
    """Choose a deterministic path from two immutable release manifests."""
    if force_maintenance:
        return UpgradeClassification("planned_maintenance", ("operator_forced",))

    current_compatibility = _valid_compatibility(current)
    candidate_compatibility = _valid_compatibility(candidate)
    current_images = _image_identities(current)
    candidate_images = _image_identities(candidate)
    if not all(
        (current_compatibility, candidate_compatibility, current_images, candidate_images)
    ):
        return _unknown()

    agent_changed = (
        current_images["neutron-aria-agent"]
        != candidate_images["neutron-aria-agent"]
    )
    datapath_changed = (
        current_images["aria-datapath"] != candidate_images["aria-datapath"]
    )
    if agent_changed and datapath_changed:
        return UpgradeClassification(
            "planned_maintenance", ("joint_agent_datapath_change",)
        )
    if (
        current_compatibility["uds_schema_min"]
        > candidate_compatibility["uds_schema_max"]
        or candidate_compatibility["uds_schema_min"]
        > current_compatibility["uds_schema_max"]
    ):
        return UpgradeClassification(
            "planned_maintenance", ("uds_schema_incompatible",)
        )
    if (
        current_compatibility["maintenance_gate_capable"]
        != candidate_compatibility["maintenance_gate_capable"]
    ):
        return UpgradeClassification(
            "planned_maintenance", ("maintenance_gate_capability_changed",)
        )
    changed_keys = tuple(
        sorted(
            key
            for key in DATAPATH_KEYS
            if current_compatibility[key] != candidate_compatibility[key]
        )
    )
    if changed_keys:
        return UpgradeClassification("planned_maintenance", changed_keys)
    if agent_changed and not datapath_changed:
        return UpgradeClassification("hot_agent", ("agent_only",))
    if datapath_changed:
        return UpgradeClassification("hot_datapath", ("compatible_datapath",))
    return UpgradeClassification("hot_agent", ("no_runtime_change",))


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    command = parser.add_subparsers(dest="command")
    classify = command.add_parser("classify", help="print a read-only upgrade path")
    classify.add_argument("--current", type=Path, required=True)
    classify.add_argument("--candidate", type=Path, required=True)
    classify.add_argument("--force-maintenance", action="store_true")
    return parser.parse_args(argv)


def _print_result(result):
    print(json.dumps(
        {"path": result.path, "reasons": list(result.reasons)},
        sort_keys=True,
        separators=(",", ":"),
    ))


def main(argv=None):
    args = parse_args(argv)
    if args.command != "classify":
        _print_result(_unknown())
        return 0
    try:
        current = load_manifest(args.current)
        candidate = load_manifest(args.candidate)
        result = classify_upgrade(current, candidate, args.force_maintenance)
    except (OSError, ValueError, RecursionError):
        result = _unknown()
    _print_result(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

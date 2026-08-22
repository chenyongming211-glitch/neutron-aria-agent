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
import time
import uuid
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
    "preflight": ("quiescing", "agent_upgrading", "failed_before_mutation"),
    "quiescing": ("bypass_preparing",),
    "bypass_preparing": ("bypass_confirmed", "maintenance_bypass"),
    "bypass_confirmed": ("datapath_upgrading", "maintenance_bypass"),
    "datapath_upgrading": ("datapath_live", "maintenance_bypass"),
    "datapath_live": ("agent_upgrading", "maintenance_bypass"),
    "agent_upgrading": ("agent_buffering", "maintenance_bypass"),
    "agent_buffering": ("full_resync", "maintenance_bypass"),
    "full_resync": ("shadow_apply", "maintenance_bypass"),
    "shadow_apply": ("activating", "maintenance_bypass"),
    "activating": ("verifying", "maintenance_bypass"),
    "verifying": ("committed", "maintenance_bypass"),
    "maintenance_bypass": ("full_resync", "rollback"),
    "rollback": ("full_resync", "maintenance_bypass"),
}
LEDGER_SCHEMA_VERSION = 1
DEFAULT_OPERATIONS_DIR = Path("/var/lib/aria-release/operations")
DEFAULT_LOCK_PATH = Path("/run/lock/aria-release.lock")
MAX_LEDGER_BYTES = 1024 * 1024
MAX_AUDIT_BYTES = 4096
OPERATION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
AUDIT_IMAGE_ID_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
RAW_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
AUDIT_HOST_LABEL_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
AUDIT_RESULTS = frozenset(
    (
        "compare_and_swap_rejected",
        "failed",
        "invalid_transition",
        "persistence_failed",
        "recovered",
        "success",
    )
)
MAX_AUDIT_INTEGER = (1 << 63) - 1
TERMINAL_PHASES = ("committed", "failed_before_mutation")
SAFE_EXACT_RESUME_PHASES = ("quiescing", "agent_buffering")
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
COORDINATOR_LEDGER_FIELDS = frozenset(
    (
        "schema_version", "operation_id", "host", "phase", "started_at",
        "last_progress_at", "upgrade_class", "last_error", "recovery_action",
    )
)
EXTERNAL_EVIDENCE_FIELDS = EVIDENCE_FIELDS - COORDINATOR_LEDGER_FIELDS
UPGRADE_CLASSES = frozenset(("planned_maintenance", "hot_agent"))
SAFE_EVIDENCE_STRING_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
RFC3339_RE = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z$"
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
        trusted_gid=0,
        audit_sink=None,
        clock=None,
    ):
        self.operations_dir = Path(operations_dir)
        self.lock_path = Path(lock_path)
        self.owner_uid = owner_uid
        self.trusted_gid = trusted_gid
        self.audit_sink = audit_sink
        self.clock = clock or time.time
        self._lock_fd = None
        self._lock_anchor_fd = None
        self._lock_parent_fd = None
        self._operations_fd = None
        self._state = None
        self._path = None
        self._durability_uncertain = False

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
        try:
            if self._lock_fd is not None:
                try:
                    fcntl.flock(self._lock_fd, fcntl.LOCK_UN)
                finally:
                    os.close(self._lock_fd)
                    self._lock_fd = None
        finally:
            if self._lock_parent_fd is not None:
                os.close(self._lock_parent_fd)
                self._lock_parent_fd = None
            if self._lock_anchor_fd is not None:
                os.close(self._lock_anchor_fd)
                self._lock_anchor_fd = None
            if self._operations_fd is not None:
                os.close(self._operations_fd)
                self._operations_fd = None
            self._state = None
            self._path = None
            self._durability_uncertain = False

    def begin(self, operation_id, host=None, upgrade_class=None, evidence=None):
        """Create or idempotently reopen an operation in ``preflight``."""
        operation_id = self._validate_operation_id(operation_id)
        acquired_here = self._lock_fd is None
        try:
            self._acquire_lock()
            self._ensure_operations_dir()
            if self._state is not None:
                if self._state["operation_id"] != operation_id:
                    raise UpgradeLedgerConflict(
                        "this ledger already owns another operation"
                    )
                self._fsync_operations_dir()
                state = self._read_ledger(self._path, operation_id)
                self._set_current(self._path, state)
                self._durability_uncertain = False
                self._validate_lock_binding()
                return self.state

            pending = self._pending_ledgers()
            conflicts = [
                item for item in pending if item["operation_id"] != operation_id
            ]
            if conflicts:
                raise UpgradeLedgerConflict(
                    "pending operation %s owns the host"
                    % conflicts[0]["operation_id"]
                )

            path = self._ledger_path(operation_id)
            if self._ledger_exists(path):
                state = self._read_ledger(path, operation_id)
                self._fsync_operations_dir()
                self._set_current(path, state)
                self._durability_uncertain = False
                self._validate_lock_binding()
                return self.state

            if not isinstance(host, str) or not host:
                raise ValueError("host must be a non-empty string")
            if upgrade_class not in UPGRADE_CLASSES:
                raise ValueError("upgrade_class is not recognized")
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
            self._validate_lock_binding()
            return self.state
        except Exception:
            if acquired_here:
                self.close()
            raise

    def transition(self, expected_phase, next_phase, evidence=None):
        """Atomically compare the current phase and persist one legal edge."""
        return self._transition(expected_phase, next_phase, evidence, "success")

    def _transition(
        self, expected_phase, next_phase, evidence=None, result="success",
        internal=None,
    ):
        if evidence is None:
            evidence = {}
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
        self._merge_evidence(next_state, evidence)
        next_state["phase"] = next_phase
        next_state["last_progress_at"] = self.clock()
        self._derive_transition_metadata(next_state, old_phase, next_phase)
        self._merge_internal(next_state, internal or {})
        try:
            self._write_ledger(self._path, next_state)
        except Exception:
            self._refresh_after_write_failure()
            self._audit(old_phase, next_phase, evidence, "persistence_failed")
            raise
        self._state = next_state
        self._audit(old_phase, next_phase, evidence, result)
        self._validate_lock_binding()
        return self.state

    def fail(self, expected_phase, error, evidence=None):
        """Persist a failure without ever reactivating ACL enforcement."""
        self._require_current()
        self._state = self._read_ledger(
            self._path, self._state["operation_id"]
        )
        durable_phase = self._state["phase"]
        if durable_phase != expected_phase:
            raise UpgradeLedgerTransitionError(
                "phase compare-and-swap failed: expected %s, found %s"
                % (expected_phase, durable_phase)
            )
        if durable_phase in TERMINAL_PHASES:
            raise UpgradeLedgerTransitionError(
                "terminal phase %s is immutable" % durable_phase
            )
        if not isinstance(error, str):
            error = str(error)
        internal = {"last_error": error[:4096]}
        if expected_phase == "preflight":
            return self._transition(
                expected_phase, "failed_before_mutation", evidence, "failed", internal
            )
        if "maintenance_bypass" in ALLOWED.get(expected_phase, ()):
            internal["recovery_action"] = "operator_action_required"
            return self._transition(
                expected_phase, "maintenance_bypass", evidence, "failed", internal
            )
        if expected_phase == "maintenance_bypass":
            internal["recovery_action"] = "operator_action_required"
        else:
            internal["recovery_action"] = "resume_exact_phase"
        return self._update_same_phase(
            evidence if evidence is not None else {},
            "failed", expected_phase, internal,
        )

    def commit(self, evidence=None):
        """Commit only the final verified phase."""
        return self.transition(
            "verifying", "committed", evidence if evidence is not None else {}
        )

    def _derive_transition_metadata(self, state, old_phase, next_phase):
        if next_phase == "maintenance_bypass":
            state["recovery_action"] = "operator_action_required"
            return
        if (
            old_phase == "maintenance_bypass"
            or next_phase == "committed"
            or self._state.get("recovery_action") == "resume_exact_phase"
        ):
            state["recovery_action"] = None
            state["last_error"] = None

    def recover(self, operation_id):
        """Reopen stale state without automatically activating old ACL state."""
        operation_id = self._validate_operation_id(operation_id)
        acquired_here = self._lock_fd is None
        try:
            self._acquire_lock()
            self._ensure_operations_dir()
            pending = self._pending_ledgers()
            conflicts = [
                item for item in pending if item["operation_id"] != operation_id
            ]
            if conflicts:
                raise UpgradeLedgerConflict(
                    "pending operation %s owns the host"
                    % conflicts[0]["operation_id"]
                )
            path = self._ledger_path(operation_id)
            if not self._ledger_exists(path):
                raise UpgradeLedgerError("operation ledger does not exist")
            state = self._read_ledger(path, operation_id)
            self._fsync_operations_dir()
            self._set_current(path, state)
            self._durability_uncertain = False
            phase = state["phase"]
            if phase in TERMINAL_PHASES:
                self._validate_lock_binding()
                return self.state
            if phase == "maintenance_bypass":
                if state.get("recovery_action") == "operator_action_required":
                    self._validate_lock_binding()
                    return self.state
                return self._update_same_phase(
                    {}, "recovered", phase,
                    {"recovery_action": "operator_action_required"},
                )
            if phase in SAFE_EXACT_RESUME_PHASES:
                return self._update_same_phase(
                    {}, "recovered", phase,
                    {"recovery_action": "resume_exact_phase"},
                )
            if "maintenance_bypass" in ALLOWED.get(phase, ()):
                return self._transition(
                    phase, "maintenance_bypass", {}, "recovered",
                    {"recovery_action": "operator_action_required"},
                )
            return self._update_same_phase(
                {}, "recovered", phase,
                {"recovery_action": "resume_exact_phase"},
            )
        except Exception:
            if acquired_here:
                self.close()
            raise

    def inspect(self, operation_id):
        """Read one trusted ledger without changing its recovery phase."""
        operation_id = self._validate_operation_id(operation_id)
        acquired_here = self._lock_fd is None
        try:
            self._acquire_lock()
            self._ensure_operations_dir()
            path = self._ledger_path(operation_id)
            if not self._ledger_exists(path):
                raise UpgradeLedgerError("operation ledger does not exist")
            state = self._read_ledger(path, operation_id)
            self._fsync_operations_dir()
            self._set_current(path, state)
            self._validate_lock_binding()
            return self.state
        except Exception:
            if acquired_here:
                self.close()
            raise

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
            self._validate_lock_binding()
            return
        self._state = None
        self._path = None
        parent = self.lock_path.parent
        anchor = parent.parent
        if anchor == parent or not parent.name:
            raise UpgradeLedgerTrustError("lock directory has no trusted anchor")
        anchor_fd = self._open_anchor_directory(anchor, "lock directory anchor")
        parent_fd = None
        fd = None
        try:
            parent_stat = self._stat_directory_at(
                anchor_fd, parent.name, "lock directory", missing_ok=False
            )
            self._validate_lock_directory_stat(parent_stat)
            parent_fd = self._open_directory_at(
                anchor_fd, parent.name, parent_stat, "lock directory"
            )
            self._validate_directory_binding(
                anchor_fd, parent.name, parent_fd, "lock directory"
            )
            try:
                path_stat = os.stat(
                    self.lock_path.name,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except OSError as error:
                if error.errno == errno.ENOENT:
                    path_stat = None
                else:
                    raise UpgradeLedgerTrustError(
                        "lock file cannot be inspected: %s" % error
                    )
            if path_stat is not None and not stat.S_ISREG(path_stat.st_mode):
                raise UpgradeLedgerTrustError("lock path must be a regular file")
            flags = os.O_RDWR | os.O_CREAT
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            try:
                fd = os.open(
                    self.lock_path.name, flags, 0o600, dir_fd=parent_fd
                )
            except OSError as error:
                raise UpgradeLedgerTrustError("lock file cannot be opened: %s" % error)
            try:
                file_stat = os.fstat(fd)
                if (
                    not stat.S_ISREG(file_stat.st_mode)
                    or file_stat.st_uid != self.owner_uid
                ):
                    raise UpgradeLedgerTrustError(
                        "lock file has untrusted ownership or type"
                    )
                if file_stat.st_nlink != 1:
                    raise UpgradeLedgerTrustError(
                        "lock file must have exactly one link"
                    )
                if path_stat is not None:
                    if stat.S_IMODE(file_stat.st_mode) != 0o600:
                        raise UpgradeLedgerTrustError("lock file mode must be 0600")
                    if (file_stat.st_dev, file_stat.st_ino) != (
                        path_stat.st_dev, path_stat.st_ino,
                    ):
                        raise UpgradeLedgerTrustError(
                            "lock file changed while it was opened"
                        )
                else:
                    os.fchmod(fd, 0o600)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except OSError as error:
                    if error.errno in (errno.EACCES, errno.EAGAIN):
                        raise UpgradeLedgerLocked("another upgrade owns the host lock")
                    raise
                self._lock_fd = fd
                self._lock_anchor_fd = anchor_fd
                self._lock_parent_fd = parent_fd
                fd = None
                anchor_fd = None
                parent_fd = None
                self._validate_lock_binding()
            except Exception:
                if fd is not None:
                    os.close(fd)
                    fd = None
                raise
        except Exception:
            if self._lock_fd is not None:
                self.close()
            raise
        finally:
            if fd is not None:
                os.close(fd)
            if parent_fd is not None:
                os.close(parent_fd)
            if anchor_fd is not None:
                os.close(anchor_fd)

    def _validate_lock_binding(self):
        if (
            self._lock_fd is None
            or self._lock_anchor_fd is None
            or self._lock_parent_fd is None
        ):
            raise UpgradeLedgerError("host lock is not fully pinned")
        parent = self.lock_path.parent
        anchor = parent.parent
        self._validate_lock_directory_stat(os.fstat(self._lock_parent_fd))
        self._validate_directory_binding(
            self._lock_anchor_fd,
            parent.name,
            self._lock_parent_fd,
            "lock directory",
        )
        fresh_anchor_fd = self._open_anchor_directory(
            anchor, "lock directory anchor"
        )
        try:
            pinned_anchor = os.fstat(self._lock_anchor_fd)
            fresh_anchor = os.fstat(fresh_anchor_fd)
            if (pinned_anchor.st_dev, pinned_anchor.st_ino) != (
                fresh_anchor.st_dev, fresh_anchor.st_ino,
            ):
                raise UpgradeLedgerTrustError("lock directory anchor binding changed")
        finally:
            os.close(fresh_anchor_fd)
        try:
            path_stat = os.stat(
                self.lock_path.name,
                dir_fd=self._lock_parent_fd,
                follow_symlinks=False,
            )
        except OSError as error:
            raise UpgradeLedgerTrustError(
                "lock file cannot be revalidated: %s" % error
            )
        file_stat = os.fstat(self._lock_fd)
        self._validate_lock_file_stat(file_stat)
        self._validate_lock_file_stat(path_stat)
        if (file_stat.st_dev, file_stat.st_ino) != (
            path_stat.st_dev, path_stat.st_ino,
        ):
            raise UpgradeLedgerTrustError("lock file binding changed")

    def _validate_lock_file_stat(self, file_stat):
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_uid != self.owner_uid:
            raise UpgradeLedgerTrustError("lock file has untrusted ownership or type")
        if stat.S_IMODE(file_stat.st_mode) != 0o600:
            raise UpgradeLedgerTrustError("lock file mode must be 0600")
        if file_stat.st_nlink != 1:
            raise UpgradeLedgerTrustError("lock file must have exactly one link")

    def _ensure_operations_dir(self):
        release = self.operations_dir.parent
        anchor = release.parent
        if anchor == release or not release.name or not self.operations_dir.name:
            raise UpgradeLedgerTrustError(
                "operations directory has no existing trusted parent"
            )
        anchor_fd = self._open_anchor_directory(anchor, "release state anchor")
        release_fd = None
        operations_fd = None
        created_release = False
        created_operations = False
        try:
            release_stat = self._stat_directory_at(
                anchor_fd, release.name, "release state directory", missing_ok=True
            )
            if release_stat is None:
                os.mkdir(release.name, 0o700, dir_fd=anchor_fd)
                created_release = True
                release_stat = self._stat_directory_at(
                    anchor_fd,
                    release.name,
                    "release state directory",
                    missing_ok=False,
                )
            self._validate_directory_stat(
                release_stat, "release state directory", created_release
            )
            release_fd = self._open_directory_at(
                anchor_fd,
                release.name,
                release_stat,
                "release state directory",
            )
            if created_release:
                os.fchmod(release_fd, 0o700)
            self._validate_directory_binding(
                anchor_fd,
                release.name,
                release_fd,
                "release state directory",
            )

            operations_stat = self._stat_directory_at(
                release_fd,
                self.operations_dir.name,
                "operations directory",
                missing_ok=True,
            )
            if operations_stat is None:
                os.mkdir(self.operations_dir.name, 0o700, dir_fd=release_fd)
                created_operations = True
                operations_stat = self._stat_directory_at(
                    release_fd,
                    self.operations_dir.name,
                    "operations directory",
                    missing_ok=False,
                )
            self._validate_directory_stat(
                operations_stat, "operations directory", created_operations
            )
            operations_fd = self._open_directory_at(
                release_fd,
                self.operations_dir.name,
                operations_stat,
                "operations directory",
            )
            if created_operations:
                os.fchmod(operations_fd, 0o700)
            self._validate_directory_binding(
                anchor_fd,
                release.name,
                release_fd,
                "release state directory",
            )
            self._validate_directory_binding(
                release_fd,
                self.operations_dir.name,
                operations_fd,
                "operations directory",
            )

            os.fsync(anchor_fd)
            os.fsync(release_fd)
            self._validate_directory_binding(
                anchor_fd,
                release.name,
                release_fd,
                "release state directory",
            )
            self._validate_directory_binding(
                release_fd,
                self.operations_dir.name,
                operations_fd,
                "operations directory",
            )
            if self._operations_fd is not None:
                previous_stat = os.fstat(self._operations_fd)
                current_stat = os.fstat(operations_fd)
                if (previous_stat.st_dev, previous_stat.st_ino) != (
                    current_stat.st_dev, current_stat.st_ino,
                ):
                    raise UpgradeLedgerTrustError(
                        "operations directory changed while the lock was held"
                    )
                os.close(self._operations_fd)
            self._operations_fd = operations_fd
            operations_fd = None
        except Exception:
            if created_operations and release_fd is not None:
                self._cleanup_created_directory(
                    release_fd, self.operations_dir.name
                )
            if created_release:
                self._cleanup_created_directory(anchor_fd, release.name)
            raise
        finally:
            if operations_fd is not None:
                os.close(operations_fd)
            if release_fd is not None:
                os.close(release_fd)
            os.close(anchor_fd)

    def _open_anchor_directory(self, path, label):
        path = Path(path)
        if not path.is_absolute():
            raise UpgradeLedgerTrustError("%s must be an absolute path" % label)
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        directory_fd = None
        try:
            directory_fd = os.open(os.path.sep, flags)
            root_stat = os.fstat(directory_fd)
            if not stat.S_ISDIR(root_stat.st_mode):
                raise UpgradeLedgerTrustError("filesystem root is not a directory")
            for component in path.parts[1:]:
                expected_stat = self._stat_directory_at(
                    directory_fd, component, label, missing_ok=False
                )
                child_fd = self._open_directory_at(
                    directory_fd, component, expected_stat, label
                )
                parent_fd = directory_fd
                directory_fd = child_fd
                os.close(parent_fd)
            result = directory_fd
            directory_fd = None
            return result
        except UpgradeLedgerError:
            raise
        except OSError as error:
            raise UpgradeLedgerTrustError(
                "%s cannot be opened safely: %s" % (label, error)
            )
        finally:
            if directory_fd is not None:
                os.close(directory_fd)

    def _stat_directory_at(self, parent_fd, name, label, missing_ok):
        try:
            return os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except OSError as error:
            if missing_ok and error.errno == errno.ENOENT:
                return None
            raise UpgradeLedgerTrustError("%s cannot be inspected: %s" % (label, error))

    def _validate_directory_stat(self, directory_stat, label, require_private=False):
        if not stat.S_ISDIR(directory_stat.st_mode):
            raise UpgradeLedgerTrustError("%s must be a directory" % label)
        if directory_stat.st_uid != self.owner_uid:
            raise UpgradeLedgerTrustError("%s owner is not trusted" % label)
        if stat.S_IMODE(directory_stat.st_mode) & 0o022:
            raise UpgradeLedgerTrustError("%s must not be group/world writable" % label)
        if require_private and stat.S_IMODE(directory_stat.st_mode) != 0o700:
            raise UpgradeLedgerTrustError("new %s mode must be 0700" % label)

    def _validate_lock_directory_stat(self, directory_stat):
        if not stat.S_ISDIR(directory_stat.st_mode):
            raise UpgradeLedgerTrustError("lock directory must be a directory")
        if directory_stat.st_uid != self.owner_uid:
            raise UpgradeLedgerTrustError("lock directory owner is not trusted")
        directory_mode = stat.S_IMODE(directory_stat.st_mode)
        if directory_mode & 0o002:
            raise UpgradeLedgerTrustError("lock directory must not be world writable")
        if directory_mode & 0o020 and directory_stat.st_gid != self.trusted_gid:
            raise UpgradeLedgerTrustError(
                "group-writable lock directory group is not trusted"
            )

    def _open_directory_at(self, parent_fd, name, expected_stat, label):
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            directory_fd = os.open(name, flags, dir_fd=parent_fd)
        except OSError as error:
            raise UpgradeLedgerTrustError("%s cannot be opened safely: %s" % (label, error))
        try:
            opened_stat = os.fstat(directory_fd)
            if (
                not stat.S_ISDIR(opened_stat.st_mode)
                or (opened_stat.st_dev, opened_stat.st_ino)
                != (expected_stat.st_dev, expected_stat.st_ino)
            ):
                raise UpgradeLedgerTrustError("%s changed while it was opened" % label)
            return directory_fd
        except Exception:
            os.close(directory_fd)
            raise

    def _validate_directory_binding(self, parent_fd, name, directory_fd, label):
        bound_stat = self._stat_directory_at(
            parent_fd, name, label, missing_ok=False
        )
        opened_stat = os.fstat(directory_fd)
        if (
            not stat.S_ISDIR(bound_stat.st_mode)
            or (bound_stat.st_dev, bound_stat.st_ino)
            != (opened_stat.st_dev, opened_stat.st_ino)
        ):
            raise UpgradeLedgerTrustError("%s binding changed" % label)

    def _cleanup_created_directory(self, parent_fd, name):
        try:
            os.rmdir(name, dir_fd=parent_fd)
        except OSError:
            return
        try:
            os.fsync(parent_fd)
        except OSError:
            pass

    def _fsync_operations_dir(self):
        if self._operations_fd is None:
            raise UpgradeLedgerError("operations directory is not pinned")
        directory_stat = os.fstat(self._operations_fd)
        self._validate_directory_stat(directory_stat, "operations directory")
        os.fsync(self._operations_fd)
        self._validate_operations_binding()

    def _validate_operations_binding(self):
        if self._operations_fd is None:
            raise UpgradeLedgerError("operations directory is not pinned")
        fresh_fd = self._open_anchor_directory(
            self.operations_dir, "operations directory path"
        )
        try:
            pinned_stat = os.fstat(self._operations_fd)
            fresh_stat = os.fstat(fresh_fd)
            self._validate_directory_stat(pinned_stat, "operations directory")
            self._validate_directory_stat(fresh_stat, "operations directory")
            if (pinned_stat.st_dev, pinned_stat.st_ino) != (
                fresh_stat.st_dev, fresh_stat.st_ino,
            ):
                raise UpgradeLedgerTrustError(
                    "operations directory path binding changed"
                )
        finally:
            os.close(fresh_fd)

    def _ledger_name(self, path):
        path = Path(path)
        if path.parent != self.operations_dir or not path.name:
            raise UpgradeLedgerTrustError("ledger path escapes operations directory")
        return path.name

    def _ledger_exists(self, path):
        if self._operations_fd is None:
            raise UpgradeLedgerError("operations directory is not pinned")
        try:
            os.stat(
                self._ledger_name(path),
                dir_fd=self._operations_fd,
                follow_symlinks=False,
            )
        except OSError as error:
            if error.errno == errno.ENOENT:
                return False
            raise UpgradeLedgerTrustError("ledger cannot be inspected: %s" % error)
        return True

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
        if self._operations_fd is None:
            raise UpgradeLedgerError("operations directory is not pinned")
        name = self._ledger_name(path)
        try:
            path_stat = os.stat(
                name, dir_fd=self._operations_fd, follow_symlinks=False
            )
        except OSError as error:
            raise UpgradeLedgerTrustError("ledger cannot be inspected: %s" % error)
        self._validate_file_stat(path_stat)
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(name, flags, dir_fd=self._operations_fd)
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
        if self._operations_fd is None:
            raise UpgradeLedgerError("operations directory is not pinned")
        for name in sorted(os.listdir(self._operations_fd)):
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
            if key in COORDINATOR_LEDGER_FIELDS or key not in EXTERNAL_EVIDENCE_FIELDS:
                continue
            state[key] = copy.deepcopy(self._validate_evidence_value(key, value))

    def _merge_internal(self, state, evidence):
        if not isinstance(evidence, dict):
            raise UpgradeLedgerError("internal evidence must be a JSON object")
        for key, value in evidence.items():
            if key not in ("last_error", "recovery_action"):
                raise UpgradeLedgerError("internal ledger field is not coordinator-owned")
            if value is not None and not isinstance(value, str):
                raise UpgradeLedgerError("internal ledger value must be a string")
            state[key] = value

    def _validate_evidence_value(self, field, value):
        if field == "affected_domains":
            if (
                not isinstance(value, list)
                or len(value) > 64
                or any(
                    not isinstance(item, str)
                    or SAFE_EVIDENCE_STRING_RE.fullmatch(item) is None
                    for item in value
                )
            ):
                raise ValueError("affected_domains must be safe string identities")
            return value
        if field in ("old_image_ids", "candidate_image_ids"):
            if not isinstance(value, dict) or len(value) > len(REQUIRED_IMAGES):
                raise ValueError("image identities must be a component mapping")
            for component, identity in value.items():
                if component not in REQUIRED_IMAGES or not self._valid_image_identity(
                    identity
                ):
                    raise ValueError("image identity is not immutable or recognized")
            return value
        if field in (
            "old_manifest_hash", "candidate_manifest_hash", "old_config_hash",
            "candidate_config_hash", "pre_desired_hash", "desired_hash",
        ):
            if value is not None and self._audit_digest(value) is None:
                raise ValueError("%s must be a sha256 digest" % field)
            return value
        if field in (
            "pre_accepted_generation", "pre_applied_generation", "generation",
            "ovs_vswitchd_pid",
        ):
            if value is not None and self._audit_nonnegative_integer(value) is None:
                raise ValueError("%s must be a bounded nonnegative integer" % field)
            return value
        if field == "pre_managed_port_ids":
            if (
                not isinstance(value, list)
                or len(value) > 8192
                or any(
                    not isinstance(item, str)
                    or SAFE_EVIDENCE_STRING_RE.fullmatch(item) is None
                    for item in value
                )
            ):
                raise ValueError("pre_managed_port_ids must be safe string identities")
            return value
        if field == "maintenance_token":
            if value is not None and (
                not isinstance(value, str) or not 1 <= len(value) <= 4096
            ):
                raise ValueError("maintenance_token must be a bounded string")
            return value
        if field in ("ovs_agent_container_id", "br_int_uuid"):
            if value is not None and (
                not isinstance(value, str)
                or SAFE_EVIDENCE_STRING_RE.fullmatch(value) is None
            ):
                raise ValueError("%s must be a safe identity" % field)
            return value
        if field == "ovs_agent_started_at":
            if value is not None and (
                not isinstance(value, str) or RFC3339_RE.fullmatch(value) is None
            ):
                raise ValueError("ovs_agent_started_at must be an RFC3339 timestamp")
            return value
        raise ValueError("evidence field has no validation schema")

    def _valid_image_identity(self, value):
        return (
            isinstance(value, str)
            and len(value) <= 512
            and (
                AUDIT_IMAGE_ID_RE.fullmatch(value) is not None
                or is_valid_image_identity(value)
            )
        )

    def _write_ledger(self, path, state):
        if self._operations_fd is None:
            raise UpgradeLedgerError("operations directory is not pinned")
        name = self._ledger_name(path)
        if self._ledger_exists(path):
            self._read_ledger(path, state["operation_id"])
        payload = (
            json.dumps(state, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            + "\n"
        ).encode("utf-8")
        if len(payload) > MAX_LEDGER_BYTES:
            raise ValueError("ledger exceeds the size limit")
        fd = None
        temporary_name = None
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            for unused_attempt in range(128):
                temporary_name = ".%s.%s.tmp" % (
                    state["operation_id"], uuid.uuid4().hex,
                )
                try:
                    fd = os.open(
                        temporary_name,
                        flags,
                        0o600,
                        dir_fd=self._operations_fd,
                    )
                    break
                except OSError as error:
                    if error.errno != errno.EEXIST:
                        raise
            if fd is None:
                raise UpgradeLedgerError("temporary ledger name space is exhausted")
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "wb", closefd=False) as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            temporary_stat = os.stat(
                temporary_name,
                dir_fd=self._operations_fd,
                follow_symlinks=False,
            )
            opened_stat = os.fstat(fd)
            self._validate_file_stat(temporary_stat)
            self._validate_file_stat(opened_stat)
            if (temporary_stat.st_dev, temporary_stat.st_ino) != (
                opened_stat.st_dev, opened_stat.st_ino,
            ):
                raise UpgradeLedgerTrustError(
                    "temporary ledger changed before rename"
                )
            self._durability_uncertain = True
            os.rename(
                temporary_name,
                name,
                src_dir_fd=self._operations_fd,
                dst_dir_fd=self._operations_fd,
            )
            temporary_name = None
            self._fsync_operations_dir()
            durable_state = self._read_ledger(path, state["operation_id"])
            if durable_state != state:
                raise UpgradeLedgerTrustError(
                    "durable ledger content changed after rename"
                )
            self._durability_uncertain = False
        finally:
            if fd is not None:
                os.close(fd)
            if temporary_name is not None:
                try:
                    os.unlink(temporary_name, dir_fd=self._operations_fd)
                except FileNotFoundError:
                    pass

    def _set_current(self, path, state):
        self._path = path
        self._state = copy.deepcopy(state)

    def _require_current(self):
        if self._lock_fd is None or self._state is None or self._path is None:
            raise UpgradeLedgerError("no operation is currently owned")
        self._validate_lock_binding()

    def _refresh_after_write_failure(self):
        try:
            self._state = self._read_ledger(
                self._path, self._state["operation_id"]
            )
        except UpgradeLedgerError:
            pass

    def _update_same_phase(self, evidence, result, expected_phase, internal=None):
        self._require_current()
        self._state = self._read_ledger(
            self._path, self._state["operation_id"]
        )
        old_phase = self._state["phase"]
        if old_phase != expected_phase:
            raise UpgradeLedgerTransitionError(
                "phase compare-and-swap failed: expected %s, found %s"
                % (expected_phase, old_phase)
            )
        next_state = copy.deepcopy(self._state)
        self._merge_evidence(next_state, evidence)
        self._merge_internal(next_state, internal or {})
        next_state["last_progress_at"] = self.clock()
        try:
            self._write_ledger(self._path, next_state)
        except Exception:
            self._refresh_after_write_failure()
            self._audit(old_phase, old_phase, evidence, "persistence_failed")
            raise
        self._state = next_state
        self._audit(old_phase, old_phase, evidence, result)
        self._validate_lock_binding()
        return self.state

    def _audit_operation_id(self, value):
        try:
            return self._validate_operation_id(value)
        except ValueError:
            return None

    def _audit_host(self, value):
        if not isinstance(value, str) or not 1 <= len(value) <= 253:
            return None
        labels = value.split(".")
        if all(AUDIT_HOST_LABEL_RE.fullmatch(label) is not None for label in labels):
            return value
        return None

    def _audit_phase(self, value):
        if isinstance(value, str) and value in LEGAL_PHASES:
            return value
        return None

    def _audit_result(self, value):
        if isinstance(value, str) and value in AUDIT_RESULTS:
            return value
        return None

    def _audit_nonnegative_integer(self, value):
        if type(value) is int and 0 <= value <= MAX_AUDIT_INTEGER:
            return value
        return None

    def _audit_digest(self, value):
        if isinstance(value, str) and (
            AUDIT_IMAGE_ID_RE.fullmatch(value) is not None
            or RAW_SHA256_RE.fullmatch(value) is not None
        ):
            return value
        return None

    def _audit_image_ids(self, value):
        if not isinstance(value, dict):
            return {}
        identities = {}
        for component in REQUIRED_IMAGES:
            if component not in value:
                continue
            identity = value[component]
            if not self._valid_image_identity(identity):
                continue
            identities[component] = identity
        return identities

    def _audit(self, old_phase, new_phase, evidence, result):
        evidence = evidence if isinstance(evidence, dict) else {}
        state = self._state or {}
        started_at = state.get("started_at")
        elapsed_ms = 0
        if isinstance(started_at, (int, float)):
            elapsed_ms = max(0, int((self.clock() - started_at) * 1000))
        record = {
            "operation_id": self._audit_operation_id(state.get("operation_id")),
            "host": self._audit_host(state.get("host")),
            "old_phase": self._audit_phase(old_phase),
            "new_phase": self._audit_phase(new_phase),
            "elapsed_ms": self._audit_nonnegative_integer(elapsed_ms),
            "generation": self._audit_nonnegative_integer(
                evidence.get("generation", state.get("generation"))
            ),
            "desired_hash": self._audit_digest(
                evidence.get(
                    "desired_hash",
                    state.get("desired_hash", state.get("pre_desired_hash")),
                )
            ),
            "old_image_ids": self._audit_image_ids(state.get("old_image_ids", {})),
            "candidate_image_ids": self._audit_image_ids(
                state.get("candidate_image_ids", {})
            ),
            "result": self._audit_result(result),
        }
        line = json.dumps(record, sort_keys=True, separators=(",", ":"))
        if len(line.encode("utf-8")) > MAX_AUDIT_BYTES:
            record["old_image_ids"] = {}
            record["candidate_image_ids"] = {}
            line = json.dumps(record, sort_keys=True, separators=(",", ":"))
        if len(line.encode("utf-8")) > MAX_AUDIT_BYTES:
            record = {
                "operation_id": None,
                "host": None,
                "old_phase": None,
                "new_phase": None,
                "elapsed_ms": 0,
                "generation": None,
                "desired_hash": None,
                "old_image_ids": {},
                "candidate_image_ids": {},
                "result": None,
            }
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
    ledger = command.add_parser("ledger", help="mutate one trusted host ledger")
    ledger.add_argument(
        "action", choices=("begin", "transition", "fail", "recover", "status")
    )
    ledger.add_argument("values", nargs="*")
    return parser.parse_args(argv)


def _print_result(result):
    print(json.dumps(
        {"path": result.path, "reasons": list(result.reasons)},
        sort_keys=True,
        separators=(",", ":"),
    ))


def _ledger_result(args):
    operations_dir = Path(os.environ.get(
        "ARIA_RELEASE_OPERATIONS_DIR", str(DEFAULT_OPERATIONS_DIR)
    ))
    lock_path = Path(os.environ.get(
        "ARIA_RELEASE_LOCK_PATH", str(DEFAULT_LOCK_PATH)
    ))
    owner_uid = os.geteuid()
    values = args.values
    with UpgradeLedger(
        operations_dir=operations_dir,
        lock_path=lock_path,
        owner_uid=owner_uid,
        trusted_gid=os.getegid(),
    ) as ledger:
        if args.action == "begin" and len(values) == 4:
            operation_id, host, upgrade_class, evidence_json = values
            return ledger.begin(
                operation_id,
                host=host,
                upgrade_class=upgrade_class,
                evidence=json.loads(evidence_json),
            )
        if args.action == "transition" and len(values) == 4:
            expected, next_phase, operation_id, evidence_json = values
            ledger.inspect(operation_id)
            return ledger.transition(expected, next_phase, json.loads(evidence_json))
        if args.action == "fail" and len(values) == 3:
            expected, operation_id, error = values
            ledger.inspect(operation_id)
            return ledger.fail(expected, error)
        if args.action == "recover" and len(values) == 1:
            return ledger.recover(values[0])
        if args.action == "status" and len(values) == 1:
            return ledger.inspect(values[0])
    raise ValueError("ledger action arguments are invalid")


def main(argv=None):
    args = parse_args(argv)
    if args.command == "ledger":
        try:
            print(json.dumps(_ledger_result(args), sort_keys=True, separators=(",", ":")))
            return 0
        except (OSError, ValueError, UpgradeLedgerError) as error:
            print("ledger error: %s" % error, file=os.sys.stderr)
            return 1
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

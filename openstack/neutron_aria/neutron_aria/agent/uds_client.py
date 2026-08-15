from __future__ import absolute_import

import json
import socket

try:
    import httplib as http_client
except ImportError:
    import http.client as http_client

try:
    from urllib import quote as urlquote
except ImportError:
    from urllib.parse import quote as urlquote


NEUTRON_API_VERSION = "v1"
NEUTRON_CONTRACT_VERSION = "2026-06-v0.9"
NEUTRON_SCHEMA_VERSION = 1
NEUTRON_BODY_MAX_BYTES = 1048576
NEUTRON_TIMEOUT_MS = 3000
NEUTRON_ERROR_CODES_HASH = "v0.9-neutron-errors-2"
NEUTRON_CAPABILITY_HASH = "v0.9-neutron-capabilities-3"
NEUTRON_ATTACH_AUTHORITY = "neutron_snapshot"
NEUTRON_STATUS_SCHEMA_VERSION = 1
NEUTRON_STATUS_CONTRACT_HASH = "v0.9-neutron-status-1"
NEUTRON_ERROR_CODES_HASH_V2 = "v0.9-neutron-errors-3"
NEUTRON_CAPABILITY_HASH_V2 = "v0.9-neutron-capabilities-4"
NEUTRON_STATUS_SCHEMA_VERSION_V2 = 2
NEUTRON_STATUS_CONTRACT_HASH_V2 = "v0.9-neutron-status-2"
NEUTRON_CAPABILITY_HASH_V3 = "v0.9-neutron-capabilities-5"
NEUTRON_STATUS_SCHEMA_VERSION_V3 = 3
NEUTRON_STATUS_CONTRACT_HASH_V3 = "v0.9-neutron-status-3"
DEFAULT_SOCKET_PATH = "/run/aria/aria-agent.sock"


STATUS_CONTRACT_V1 = "v1"
STATUS_CONTRACT_V2 = "v2"
STATUS_CONTRACT_V3 = "v3"
STATUS_CONTRACT_LEGACY_V0 = "legacy_v0"

_STATUS_CONTRACTS = {
    (
        NEUTRON_STATUS_SCHEMA_VERSION,
        NEUTRON_STATUS_SCHEMA_VERSION,
        NEUTRON_STATUS_CONTRACT_HASH,
    ): STATUS_CONTRACT_V1,
    (
        NEUTRON_STATUS_SCHEMA_VERSION_V2,
        NEUTRON_STATUS_SCHEMA_VERSION_V2,
        NEUTRON_STATUS_CONTRACT_HASH_V2,
    ): STATUS_CONTRACT_V2,
    (
        NEUTRON_STATUS_SCHEMA_VERSION_V2,
        NEUTRON_STATUS_SCHEMA_VERSION_V3,
        NEUTRON_STATUS_CONTRACT_HASH_V3,
    ): STATUS_CONTRACT_V3,
    (
        NEUTRON_STATUS_SCHEMA_VERSION_V3,
        NEUTRON_STATUS_SCHEMA_VERSION_V3,
        NEUTRON_STATUS_CONTRACT_HASH_V3,
    ): STATUS_CONTRACT_V3,
}
_STATUS_CONTRACT_PROFILES = {
    STATUS_CONTRACT_V1: (
        NEUTRON_ERROR_CODES_HASH,
        NEUTRON_CAPABILITY_HASH,
    ),
    STATUS_CONTRACT_V2: (
        NEUTRON_ERROR_CODES_HASH_V2,
        NEUTRON_CAPABILITY_HASH_V2,
    ),
    STATUS_CONTRACT_LEGACY_V0: (
        NEUTRON_ERROR_CODES_HASH,
        NEUTRON_CAPABILITY_HASH,
    ),
}

_STATUS_CONTRACT_CAPABILITY_FIELDS = (
    "status_schema_version_min",
    "status_schema_version_max",
    "status_contract_hash",
)
_STATUS_CONTRACT_RESPONSE_FIELDS = (
    "status_schema_version",
    "status_contract_hash",
)
_STATUS_V1_TRIPLES = frozenset((
    ("idle", "unknown", "full_resync"),
    ("pending", "unknown", "poll"),
    ("classified", "ready", "none"),
    ("classified", "degraded", "none"),
    ("classified", "degraded", "full_resync"),
    ("blocked", "blocked", "recover_pending"),
    ("blocked", "blocked", "operator"),
    ("recovery", "degraded", "full_resync"),
))
_STATUS_V2_TRIPLES = frozenset(
    tuple(_STATUS_V1_TRIPLES) + (
        ("blocked", "blocked", "retry_snapshot"),
    )
)
_STATUS_V1_RECOVERY_CAUSES = frozenset((None, "inventory_unavailable"))
_STATUS_V1_DOMAIN_STATES = frozenset((
    "ready", "not_requested", "degraded", "blocked",
))
_STATUS_V1_EFFECTIVE_ACTIONS = frozenset((
    "enforce", "bypass", "unchanged", "cleanup", "no_op",
))
_STATUS_V1_SUPPORT_DISPOSITIONS = frozenset((
    "supported", "unsupported", "unknown", "not_applicable",
))
_STATUS_V1_PORT_STATES = frozenset((
    "ready", "not_requested", "degraded", "unsupported",
    "blocked", "error", "recovered", "detached",
))

_LEGACY_PENDING_AUTHORITIES = frozenset(("applying", "accepted"))
_LEGACY_DEGRADED_AUTHORITIES = frozenset((
    "runtime_degraded", "degraded",
))
_LEGACY_RECOVERABLE_AUTHORITIES = frozenset((
    "partial",
    "blocked_recovery_required",
    "recovered_pending_full_resync",
))
_LEGACY_OPERATOR_AUTHORITIES = frozenset((
    "wal_commit_failed",
    "wal_recovery_commit_failed",
    "wal_runtime_reconcile_commit_failed",
    "pending_recovery_commit_failed",
    "wal_intent_without_commit",
    "runtime_reconcile_requires_full_resync",
    "wal_replay_uncertain",
    "blocked",
    "error",
    "unsupported",
    "detached",
))

try:
    _INTEGER_TYPES = (int, long)
except NameError:
    _INTEGER_TYPES = (int,)

try:
    _STRING_TYPES = (basestring,)
except NameError:
    _STRING_TYPES = (str,)


class LocalApiError(Exception):
    pass


class LocalApiTransportError(LocalApiError):
    pass


class LocalApiTimeoutError(LocalApiTransportError):
    pass


class LocalApiResponseError(LocalApiError):
    def __init__(self, status, reason, body):
        LocalApiError.__init__(self, "local API returned %s %s" % (status, reason))
        self.status = status
        self.reason = reason
        self.body = body


class LocalApiContractError(LocalApiError):
    pass


def _optional_int(value, field):
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        raise LocalApiContractError("invalid %s %r" % (field, value))


def _required(body, field):
    if field not in body:
        raise LocalApiContractError("missing %s" % field)
    return body[field]


def _strict_int(value, field, nullable=False, minimum=None):
    if value is None and nullable:
        return None
    if isinstance(value, bool) or not isinstance(value, _INTEGER_TYPES):
        raise LocalApiContractError("invalid %s %r" % (field, value))
    if minimum is not None and value < minimum:
        raise LocalApiContractError("invalid %s %r" % (field, value))
    return value


def _strict_string(value, field, nullable=False, nonempty=False):
    if value is None and nullable:
        return None
    if not isinstance(value, _STRING_TYPES):
        raise LocalApiContractError("invalid %s %r" % (field, value))
    if nonempty and not value.strip():
        raise LocalApiContractError("empty %s" % field)
    return value


def _strict_list(value, field):
    if not isinstance(value, list):
        raise LocalApiContractError("invalid %s %r" % (field, value))
    return value


def _normalized_unique_names(value, field):
    names = _strict_list(value, field)
    normalized = []
    seen = set()
    for index, name in enumerate(names):
        item = _strict_string(
            name,
            "%s[%s]" % (field, index),
            nonempty=True,
        )
        stripped = item.strip()
        if stripped != item or stripped in seen:
            raise LocalApiContractError("invalid or duplicate %s %r" % (field, item))
        seen.add(stripped)
        normalized.append(stripped)
    return sorted(normalized)


def _negotiate_status_contract(body):
    if not isinstance(body, dict):
        raise LocalApiContractError("capabilities response must be an object")
    present = [field in body for field in _STATUS_CONTRACT_CAPABILITY_FIELDS]
    if not any(present):
        return STATUS_CONTRACT_LEGACY_V0
    if not all(present):
        raise LocalApiContractError("partial status contract capability declaration")

    schema_min = _strict_int(
        body["status_schema_version_min"],
        "status_schema_version_min",
    )
    schema_max = _strict_int(
        body["status_schema_version_max"],
        "status_schema_version_max",
    )
    contract_hash = _strict_string(
        body["status_contract_hash"],
        "status_contract_hash",
        nonempty=True,
    )
    mode = _STATUS_CONTRACTS.get((schema_min, schema_max, contract_hash))
    if mode is None:
        raise LocalApiContractError(
            "unsupported status contract %s-%s %r" % (
                schema_min,
                schema_max,
                contract_hash,
            )
        )
    return mode


def _status_declared_mode(body):
    if not isinstance(body, dict):
        raise LocalApiContractError("status response must be an object")
    present = [field in body for field in _STATUS_CONTRACT_RESPONSE_FIELDS]
    if not any(present):
        return STATUS_CONTRACT_LEGACY_V0
    if not all(present):
        raise LocalApiContractError("partial status contract response declaration")
    schema_version = _strict_int(
        body["status_schema_version"],
        "status_schema_version",
    )
    contract_hash = _strict_string(
        body["status_contract_hash"],
        "status_contract_hash",
        nonempty=True,
    )
    mode = _STATUS_CONTRACTS.get((
        schema_version,
        schema_version,
        contract_hash,
    ))
    if mode is None:
        raise LocalApiContractError(
            "unsupported status response contract %s %r" % (
                schema_version,
                contract_hash,
            )
        )
    return mode


def _status_common_scalars(body, v1):
    values = {}
    if v1:
        values["last_classified_generation"] = _strict_int(
            _required(body, "last_classified_generation"),
            "last_classified_generation",
            minimum=0,
        )
    values["generation"] = _strict_int(
        _required(body, "generation"), "generation", minimum=0,
    )
    values["accepted_generation"] = _strict_int(
        _required(body, "accepted_generation"),
        "accepted_generation",
        minimum=0,
    )
    values["applied_generation"] = _strict_int(
        _required(body, "applied_generation"),
        "applied_generation",
        minimum=0,
    )
    values["pending_generation"] = _strict_int(
        _required(body, "pending_generation"),
        "pending_generation",
        nullable=True,
        minimum=0,
    )
    values["desired_hash"] = _strict_string(
        _required(body, "desired_hash"), "desired_hash", nullable=True,
    )
    values["applied_desired_hash"] = _strict_string(
        _required(body, "applied_desired_hash"),
        "applied_desired_hash",
        nullable=True,
    )
    values["wal_status"] = _strict_string(
        _required(body, "wal_status"), "wal_status",
    )
    values["wal_replay_failures"] = _strict_int(
        _required(body, "wal_replay_failures"),
        "wal_replay_failures",
        minimum=0,
    )
    values["authority_state"] = _strict_string(
        _required(body, "authority_state"), "authority_state",
    )
    values["managed_ports"] = _strict_list(
        _required(body, "managed_ports"), "managed_ports",
    )
    values["port_statuses"] = _strict_list(
        _required(body, "port_statuses"), "port_statuses",
    )
    values["active_instances"] = _strict_list(
        _required(body, "active_instances"), "active_instances",
    )
    for index, ifname in enumerate(values["active_instances"]):
        _strict_string(ifname, "active_instances[%s]" % index)
    return values


def _validate_applied_hash(values, field_prefix=""):
    applied = values["applied_generation"]
    applied_hash = values["applied_desired_hash"]
    field = field_prefix + "applied_desired_hash"
    if applied == 0:
        if applied_hash is not None:
            raise LocalApiContractError("%s must be null at generation 0" % field)
    elif applied_hash is None or not applied_hash.strip():
        raise LocalApiContractError("%s must be non-empty" % field)


def _validate_complete_pending(values):
    pending = values["pending_generation"]
    applied = values["applied_generation"]
    accepted = values["accepted_generation"]
    if values["generation"] != applied:
        raise LocalApiContractError("generation alias does not match applied")
    if pending is None or pending <= 0 or pending < applied:
        raise LocalApiContractError("incomplete pending generation identity")
    if accepted not in (applied, pending):
        raise LocalApiContractError("ambiguous accepted pending lineage")
    desired_hash = values["desired_hash"]
    if desired_hash is None or not desired_hash.strip():
        raise LocalApiContractError("pending desired_hash must be non-empty")
    _validate_applied_hash(values)
    if pending == applied:
        if applied <= 0 or desired_hash != values["applied_desired_hash"]:
            raise LocalApiContractError("same-generation pending hash mismatch")


def _validate_complete_applied(values):
    applied = values["applied_generation"]
    if values["generation"] != applied:
        raise LocalApiContractError("generation alias does not match applied")
    if values["pending_generation"] is not None:
        raise LocalApiContractError("classified identity retains pending generation")
    if values["accepted_generation"] != applied:
        raise LocalApiContractError("accepted generation does not match applied")
    _validate_applied_hash(values)
    if applied == 0:
        if values["desired_hash"] is not None:
            raise LocalApiContractError("desired_hash must be null at generation 0")
    elif values["desired_hash"] != values["applied_desired_hash"]:
        raise LocalApiContractError("desired and applied hash mismatch")


def _parse_managed_rows(rows):
    indexed = {}
    for index, row in enumerate(rows):
        field = "managed_ports[%s]" % index
        if not isinstance(row, dict):
            raise LocalApiContractError("%s must be an object" % field)
        port_id = _strict_string(
            _required(row, "port_id"), field + ".port_id", nonempty=True,
        )
        if port_id in indexed:
            raise LocalApiContractError("duplicate managed port %r" % port_id)
        indexed[port_id] = {
            "row": row,
            "ifname": _strict_string(
                _required(row, "ifname"), field + ".ifname",
            ),
            "managed_domains": _normalized_unique_names(
                _required(row, "managed_domains"),
                field + ".managed_domains",
            ),
        }
    return indexed


def _parse_v1_status_rows(rows, applied_generation, applied_hash):
    indexed = {}
    for index, row in enumerate(rows):
        field = "port_statuses[%s]" % index
        if not isinstance(row, dict):
            raise LocalApiContractError("%s must be an object" % field)
        port_id = _strict_string(
            _required(row, "port_id"), field + ".port_id", nonempty=True,
        )
        if port_id in indexed:
            raise LocalApiContractError("duplicate port status %r" % port_id)
        generation = _strict_int(
            _required(row, "generation"), field + ".generation", minimum=1,
        )
        if generation > applied_generation:
            raise LocalApiContractError("future port status generation for %s" % port_id)
        desired_hash = _strict_string(
            _required(row, "desired_hash"),
            field + ".desired_hash",
            nonempty=True,
        )
        if desired_hash.strip() != desired_hash:
            raise LocalApiContractError(
                "port status hash must be trimmed for %s" % port_id
            )
        if generation == applied_generation and desired_hash != applied_hash:
            raise LocalApiContractError("current port status hash mismatch for %s" % port_id)
        port_state = _strict_string(
            _required(row, "status"), field + ".status", nonempty=True,
        )
        if port_state not in _STATUS_V1_PORT_STATES:
            raise LocalApiContractError("unknown port status %r" % port_state)
        _strict_string(_required(row, "reason"), field + ".reason", nullable=True)
        managed_domains = _normalized_unique_names(
            _required(row, "managed_domains"), field + ".managed_domains",
        )
        domains = _strict_list(_required(row, "domains"), field + ".domains")
        domain_index = {}
        for domain_offset, domain in enumerate(domains):
            domain_field = "%s.domains[%s]" % (field, domain_offset)
            if not isinstance(domain, dict):
                raise LocalApiContractError("%s must be an object" % domain_field)
            name = _strict_string(
                _required(domain, "domain"),
                domain_field + ".domain",
                nonempty=True,
            )
            if name.strip() != name or name in domain_index:
                raise LocalApiContractError("invalid or duplicate domain %r" % name)
            state = _strict_string(
                _required(domain, "status"),
                domain_field + ".status",
                nonempty=True,
            )
            if state not in _STATUS_V1_DOMAIN_STATES:
                raise LocalApiContractError("unknown domain status %r" % state)
            _strict_string(
                _required(domain, "reason"),
                domain_field + ".reason",
                nullable=True,
            )
            action = _strict_string(
                _required(domain, "effective_action"),
                domain_field + ".effective_action",
                nullable=True,
            )
            if action is not None and action not in _STATUS_V1_EFFECTIVE_ACTIONS:
                raise LocalApiContractError("unknown effective action %r" % action)
            support = _strict_string(
                _required(domain, "support_disposition"),
                domain_field + ".support_disposition",
                nonempty=True,
            )
            if support not in _STATUS_V1_SUPPORT_DISPOSITIONS:
                raise LocalApiContractError("unknown support disposition %r" % support)
            domain_index[name] = {
                "row": domain,
                "status": state,
                "action": action,
                "support": support,
            }
        if sorted(domain_index) != managed_domains:
            raise LocalApiContractError("domain set mismatch for port %s" % port_id)
        indexed[port_id] = {
            "row": row,
            "ifname": _strict_string(
                _required(row, "ifname"), field + ".ifname",
            ),
            "generation": generation,
            "desired_hash": desired_hash,
            "status": port_state,
            "managed_domains": managed_domains,
            "domains": domain_index,
        }
    return indexed


def _v1_managed_row_class(status):
    domain_classes = []
    for name in status["managed_domains"]:
        domain = status["domains"][name]
        state = domain["status"]
        action = domain["action"]
        support = domain["support"]
        if state == "ready":
            valid = (
                (name == "acl" and action == "enforce") or
                (name == "attach" and action is None)
            ) and support == "supported"
            if not valid:
                raise LocalApiContractError("invalid ready evidence for domain %s" % name)
            domain_classes.append("ready")
        elif state == "not_requested":
            if not (
                name == "acl" and
                action in ("bypass", "no_op") and
                support == "not_applicable"
            ):
                raise LocalApiContractError(
                    "invalid not-requested evidence for domain %s" % name
                )
            domain_classes.append("ready")
        elif state == "degraded":
            if not (
                name == "acl" and
                action in ("bypass", "unchanged") and
                support in ("supported", "unsupported", "unknown")
            ):
                raise LocalApiContractError("invalid degraded evidence for domain %s" % name)
            domain_classes.append("degraded")
        else:
            raise LocalApiContractError("blocked domain evidence for %s" % name)

    port_state = status["status"]
    if port_state == "ready":
        if any(item != "ready" for item in domain_classes):
            raise LocalApiContractError("ready port contains degraded domain")
        return "ready"
    if port_state == "not_requested":
        if not (
            status["managed_domains"] == ["acl"] and
            status["domains"]["acl"]["status"] == "not_requested"
        ):
            raise LocalApiContractError("invalid not-requested port evidence")
        return "ready"
    if port_state in ("degraded", "unsupported"):
        if "degraded" not in domain_classes:
            raise LocalApiContractError("degraded port lacks degraded domain")
        return "degraded"
    raise LocalApiContractError("unsafe managed port status %r" % port_state)


def _validate_v1_tombstone(status):
    if not status["ifname"].strip() or status["status"] != "detached":
        raise LocalApiContractError("invalid detached tombstone identity")
    for name in status["managed_domains"]:
        domain = status["domains"][name]
        if not (
            domain["status"] == "not_requested" and
            domain["action"] == "cleanup" and
            domain["support"] == "not_applicable"
        ):
            raise LocalApiContractError("invalid detached tombstone domain %s" % name)


def _is_terminal_unsupported_empty_ifname(status):
    if (
        status["status"] not in ("degraded", "unsupported") or
        status["managed_domains"] != ["acl"]
    ):
        return False
    acl = status["domains"].get("acl")
    return bool(
        acl and
        acl["status"] == "degraded" and
        acl["action"] == "bypass" and
        acl["support"] == "unsupported"
    )


def _validate_classified_rows(values, expected_readiness=None):
    managed = _parse_managed_rows(values["managed_ports"])
    statuses = _parse_v1_status_rows(
        values["port_statuses"],
        values["applied_generation"],
        values["applied_desired_hash"],
    )
    row_classes = []
    for port_id, managed_row in managed.items():
        status = statuses.get(port_id)
        if status is None:
            raise LocalApiContractError("missing status row for managed port %s" % port_id)
        row_class = _v1_managed_row_class(status)
        if managed_row["ifname"] != status["ifname"]:
            raise LocalApiContractError("ifname mismatch for port %s" % port_id)
        if (
            not managed_row["ifname"] and
            not _is_terminal_unsupported_empty_ifname(status)
        ):
            raise LocalApiContractError(
                "port %s has an unsupported empty ifname shape" % port_id
            )
        if managed_row["managed_domains"] != status["managed_domains"]:
            raise LocalApiContractError("managed domain mismatch for port %s" % port_id)
        row_classes.append(row_class)
    for port_id, status in statuses.items():
        if port_id not in managed:
            _validate_v1_tombstone(status)

    if expected_readiness == "ready" and any(
        row_class != "ready" for row_class in row_classes
    ):
        raise LocalApiContractError("ready classification contains degraded evidence")
    if expected_readiness == "degraded" and "degraded" not in row_classes:
        raise LocalApiContractError("degraded classification lacks degraded evidence")


def _decode_status_versioned(
    body,
    expected_schema_version,
    expected_contract_hash,
    allowed_triples,
    allow_retry_snapshot=False,
):
    if not isinstance(body, dict):
        raise LocalApiContractError("status response must be an object")
    schema_version = _strict_int(
        _required(body, "status_schema_version"), "status_schema_version",
    )
    contract_hash = _strict_string(
        _required(body, "status_contract_hash"),
        "status_contract_hash",
        nonempty=True,
    )
    if (
        schema_version != expected_schema_version or
        contract_hash != expected_contract_hash
    ):
        raise LocalApiContractError(
            "unsupported status response contract %s %r" % (
                schema_version,
                contract_hash,
            )
        )

    transaction_state = _strict_string(
        _required(body, "transaction_state"),
        "transaction_state",
        nonempty=True,
    )
    readiness = _strict_string(
        _required(body, "overall_readiness"),
        "overall_readiness",
        nonempty=True,
    )
    action = _strict_string(
        _required(body, "required_action"),
        "required_action",
        nonempty=True,
    )
    triple = (transaction_state, readiness, action)
    if triple not in allowed_triples:
        raise LocalApiContractError("invalid status state/readiness/action %r" % (triple,))
    recovery_cause = _strict_string(
        _required(body, "recovery_cause"),
        "recovery_cause",
        nullable=True,
    )
    if recovery_cause not in _STATUS_V1_RECOVERY_CAUSES:
        raise LocalApiContractError("unknown recovery_cause %r" % recovery_cause)

    values = _status_common_scalars(body, v1=True)
    applied = values["applied_generation"]
    if values["generation"] != applied:
        raise LocalApiContractError("generation alias does not match applied")
    if values["last_classified_generation"] != applied:
        raise LocalApiContractError("last classified generation does not match applied")

    if transaction_state == "idle":
        if recovery_cause is not None or any((
            values["generation"],
            values["accepted_generation"],
            values["applied_generation"],
            values["last_classified_generation"],
            values["wal_replay_failures"],
        )):
            raise LocalApiContractError("invalid idle identity")
        if (
            values["pending_generation"] is not None or
            values["desired_hash"] is not None or
            values["applied_desired_hash"] is not None or
            values["managed_ports"] or
            values["port_statuses"] or
            values["active_instances"]
        ):
            raise LocalApiContractError("idle status retains runtime evidence")
    elif transaction_state == "pending":
        if recovery_cause is not None or values["wal_replay_failures"] != 0:
            raise LocalApiContractError("invalid pending diagnostics")
        _validate_complete_pending(values)
    elif transaction_state == "classified":
        if recovery_cause is not None or values["wal_replay_failures"] != 0:
            raise LocalApiContractError("invalid classified diagnostics")
        if applied <= 0:
            raise LocalApiContractError(
                "classified generation must be positive"
            )
        _validate_complete_applied(values)
        _validate_classified_rows(values, expected_readiness=readiness)
    elif transaction_state == "recovery":
        if recovery_cause is not None or values["wal_replay_failures"] != 0:
            raise LocalApiContractError("invalid recovery diagnostics")
        _validate_complete_applied(values)
        _validate_classified_rows(values)
    elif action in ("recover_pending", "retry_snapshot"):
        if action == "retry_snapshot" and not allow_retry_snapshot:
            raise LocalApiContractError("retry_snapshot requires status V2")
        if recovery_cause not in (None, "inventory_unavailable"):
            raise LocalApiContractError("invalid recovery cause/action pair")
        if values["wal_replay_failures"] != 0:
            raise LocalApiContractError("recoverable status has WAL replay failures")
        _validate_complete_pending(values)
        managed = _parse_managed_rows(values["managed_ports"])
        statuses = _parse_v1_status_rows(
            values["port_statuses"],
            values["applied_generation"],
            values["applied_desired_hash"],
        )
        if action == "retry_snapshot":
            if recovery_cause is not None:
                raise LocalApiContractError(
                    "snapshot retry cannot carry a recovery cause"
                )
            if (
                values["authority_state"] != "partial" or
                values["wal_status"] != "committed" or
                values["accepted_generation"] != values["pending_generation"]
            ):
                raise LocalApiContractError(
                    "snapshot retry requires a durable partial commit"
                )
            if applied == 0:
                if (
                    values["applied_desired_hash"] is not None or
                    managed or statuses or values["active_instances"]
                ):
                    raise LocalApiContractError(
                        "generation-0 retry retains applied evidence"
                    )
            else:
                _validate_classified_rows(values)
        elif recovery_cause == "inventory_unavailable":
            if values["accepted_generation"] != values["pending_generation"]:
                raise LocalApiContractError("inventory recovery requires committed lineage")
            if applied == 0 and (
                values["applied_desired_hash"] is not None or
                values["managed_ports"] or
                values["port_statuses"]
            ):
                raise LocalApiContractError("invalid generation-0 recovery baseline")
        elif applied == 0:
            raise LocalApiContractError("generation-0 recovery requires typed cause")
    else:
        if recovery_cause is not None:
            raise LocalApiContractError("operator status cannot carry recovery cause")
        # Operator is the producer's fail-closed projection for inconsistent
        # pending/applied diagnostics.  Those fields are never executable in
        # this triple, so validating them as a recoverable identity would
        # reject the exact state that safely reports the inconsistency.

    return dict(body)


def _decode_status_v1(body):
    return _decode_status_versioned(
        body,
        NEUTRON_STATUS_SCHEMA_VERSION,
        NEUTRON_STATUS_CONTRACT_HASH,
        _STATUS_V1_TRIPLES,
    )


def _decode_status_v2(body):
    return _decode_status_versioned(
        body,
        NEUTRON_STATUS_SCHEMA_VERSION_V2,
        NEUTRON_STATUS_CONTRACT_HASH_V2,
        _STATUS_V2_TRIPLES,
        allow_retry_snapshot=True,
    )


def _decode_status_v3(body):
    decoded = _decode_status_versioned(
        body,
        NEUTRON_STATUS_SCHEMA_VERSION_V3,
        NEUTRON_STATUS_CONTRACT_HASH_V3,
        _STATUS_V2_TRIPLES,
        allow_retry_snapshot=True,
    )
    if isinstance(body.get("counters"), dict):
        decoded["counters"] = body["counters"]
    return decoded


def _legacy_identity_is_applied(values):
    applied = values["applied_generation"]
    if (
        values["generation"] != applied or
        values["accepted_generation"] != applied or
        values["pending_generation"] is not None or
        values["wal_replay_failures"] != 0
    ):
        return False
    try:
        _validate_applied_hash(values)
    except LocalApiContractError:
        return False
    if applied == 0:
        return values["desired_hash"] is None
    return values["desired_hash"] == values["applied_desired_hash"]


def _legacy_ready_rows_valid(values):
    try:
        managed = _parse_managed_rows(values["managed_ports"])
        statuses = {}
        for index, row in enumerate(values["port_statuses"]):
            if not isinstance(row, dict):
                return False
            port_id = _strict_string(
                _required(row, "port_id"),
                "port_statuses[%s].port_id" % index,
                nonempty=True,
            )
            if port_id in statuses:
                return False
            statuses[port_id] = row
        for port_id, managed_row in managed.items():
            row = statuses.get(port_id)
            if row is None:
                return False
            ifname = _strict_string(_required(row, "ifname"), "ifname")
            if not ifname or ifname != managed_row["ifname"]:
                return False
            _strict_string(_required(row, "reason"), "reason", nullable=True)
            generation = _strict_int(_required(row, "generation"), "generation", minimum=1)
            if generation > values["applied_generation"]:
                return False
            row_hash = _strict_string(
                _required(row, "desired_hash"), "desired_hash", nonempty=True,
            )
            if (
                generation == values["applied_generation"] and
                row_hash != values["applied_desired_hash"]
            ):
                return False
            row_domains = _normalized_unique_names(
                _required(row, "managed_domains"), "managed_domains",
            )
            if row_domains != managed_row["managed_domains"]:
                return False
            domains = _strict_list(_required(row, "domains"), "domains")
            domain_index = {}
            not_requested = False
            for domain in domains:
                if not isinstance(domain, dict):
                    return False
                name = _strict_string(
                    _required(domain, "domain"), "domain", nonempty=True,
                )
                if name.strip() != name or name in domain_index:
                    return False
                state = _strict_string(_required(domain, "status"), "status")
                action = _strict_string(
                    _required(domain, "effective_action"),
                    "effective_action",
                    nullable=True,
                )
                _strict_string(
                    _required(domain, "reason"), "reason", nullable=True,
                )
                if name == "acl":
                    if (state, action) == ("not_requested", "bypass"):
                        not_requested = True
                    elif (state, action) != ("ready", "enforce"):
                        return False
                elif state != "ready":
                    return False
                domain_index[name] = domain
            if sorted(domain_index) != row_domains:
                return False
            expected_port_state = "not_requested" if not_requested else "ready"
            if _strict_string(_required(row, "status"), "status") != expected_port_state:
                return False
        return True
    except LocalApiContractError:
        return False


def _decode_legacy_status_v0(body):
    if not isinstance(body, dict):
        raise LocalApiContractError("legacy status response must be an object")
    if any(field in body for field in _STATUS_CONTRACT_RESPONSE_FIELDS):
        raise LocalApiContractError("legacy status contains V1 metadata")
    values = _status_common_scalars(body, v1=False)
    authority = values["authority_state"]
    triple = None

    if authority == "ready":
        if (
            values["applied_generation"] > 0 and
            _legacy_identity_is_applied(values) and
            _legacy_ready_rows_valid(values)
        ):
            triple = ("classified", "ready", "none")
        else:
            triple = ("blocked", "blocked", "operator")
    elif authority == "idle":
        if (
            values["generation"] == 0 and
            values["accepted_generation"] == 0 and
            values["applied_generation"] == 0 and
            values["pending_generation"] is None and
            values["desired_hash"] is None and
            values["applied_desired_hash"] is None and
            values["wal_replay_failures"] == 0 and
            not values["managed_ports"] and
            not values["port_statuses"] and
            not values["active_instances"]
        ):
            triple = ("idle", "unknown", "full_resync")
        else:
            triple = ("blocked", "blocked", "operator")
    elif authority in _LEGACY_PENDING_AUTHORITIES:
        try:
            _validate_complete_pending(values)
            if values["wal_replay_failures"] != 0:
                raise LocalApiContractError("pending status has replay failures")
            triple = ("pending", "unknown", "poll")
        except LocalApiContractError:
            triple = ("blocked", "blocked", "operator")
    elif authority in _LEGACY_DEGRADED_AUTHORITIES:
        if values["pending_generation"] is not None:
            triple = ("blocked", "blocked", "operator")
        elif _legacy_identity_is_applied(values):
            triple = ("classified", "degraded", "full_resync")
        else:
            triple = ("blocked", "blocked", "operator")
    elif authority in _LEGACY_RECOVERABLE_AUTHORITIES:
        try:
            _validate_complete_pending(values)
            if values["wal_replay_failures"] != 0:
                raise LocalApiContractError("recoverable status has replay failures")
            triple = ("blocked", "blocked", "recover_pending")
        except LocalApiContractError:
            triple = ("blocked", "blocked", "operator")
    elif authority == "recovered_pending_full_resync_required":
        if _legacy_identity_is_applied(values):
            triple = ("recovery", "degraded", "full_resync")
        else:
            triple = ("blocked", "blocked", "operator")
    elif authority in _LEGACY_OPERATOR_AUTHORITIES:
        triple = ("blocked", "blocked", "operator")
    else:
        raise LocalApiContractError("unknown legacy authority_state %r" % authority)

    decoded = dict(body)
    decoded.update({
        "transaction_state": triple[0],
        "overall_readiness": triple[1],
        "required_action": triple[2],
        "recovery_cause": None,
        "last_classified_generation": values["applied_generation"],
    })
    return decoded


def _decode_status(body, negotiated_mode=None):
    declared_mode = _status_declared_mode(body)
    if negotiated_mode is not None and declared_mode != negotiated_mode:
        raise LocalApiContractError(
            "status mode %s conflicts with negotiated mode %s" % (
                declared_mode,
                negotiated_mode,
            )
        )
    if declared_mode == STATUS_CONTRACT_V1:
        return _decode_status_v1(body)
    if declared_mode == STATUS_CONTRACT_V2:
        return _decode_status_v2(body)
    if declared_mode == STATUS_CONTRACT_V3:
        return _decode_status_v3(body)
    return _decode_legacy_status_v0(body)


def _plain_error_body(status, reason, raw):
    if status == 413:
        return {"error": "UDS_BODY_TOO_LARGE", "details": raw}
    return {"error": raw or reason}


class UnixHTTPConnection(http_client.HTTPConnection):
    def __init__(self, socket_path, timeout=None):
        http_client.HTTPConnection.__init__(self, "localhost", timeout=timeout)
        self.socket_path = socket_path

    def connect(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        if self.timeout is not None:
            sock.settimeout(self.timeout)
        sock.connect(self.socket_path)
        self.sock = sock


class LocalClient(object):
    def __init__(
        self,
        socket_path=DEFAULT_SOCKET_PATH,
        timeout=NEUTRON_TIMEOUT_MS / 1000.0,
        max_response_bytes=1048576,
        max_request_bytes=NEUTRON_BODY_MAX_BYTES,
        connection_factory=None,
    ):
        self.socket_path = socket_path
        self.timeout = timeout
        self.max_response_bytes = max_response_bytes
        self.max_request_bytes = max_request_bytes
        self.connection_factory = connection_factory
        self._status_contract_mode = None
        self._status_contract_write_blocked = False
        self._status_contract_fresh_handshake = False

    def capabilities(self, required_domains=None):
        try:
            body = self._request(
                "GET",
                "/api/v1/neutron/capabilities",
                contract_response=True,
            )
            mode = _negotiate_status_contract(body)
            self._validate_capabilities(
                body,
                required_domains or [],
                status_contract_mode=mode,
            )
        except LocalApiContractError:
            self._latch_status_contract_error()
            raise
        except (TypeError, ValueError) as exc:
            self._latch_status_contract_error()
            raise LocalApiContractError(
                "invalid capabilities response: %s" % exc
            )
        self._status_contract_mode = mode
        self._status_contract_fresh_handshake = (
            self._status_contract_write_blocked
        )
        return body

    def status(self):
        try:
            body = self._request(
                "GET",
                "/api/v1/neutron/status",
                contract_response=True,
            )
            declared_mode = _status_declared_mode(body)
            decoded = _decode_status(body, self._status_contract_mode)
        except LocalApiContractError:
            self._latch_status_contract_error()
            raise
        except (TypeError, ValueError) as exc:
            self._latch_status_contract_error()
            raise LocalApiContractError(
                "invalid status response: %s" % exc
            )
        if (
            self._status_contract_mode is None and
            declared_mode in (STATUS_CONTRACT_V1, STATUS_CONTRACT_V2)
        ):
            self._status_contract_write_blocked = True
            self._status_contract_fresh_handshake = False
        elif (
            self._status_contract_write_blocked and
            self._status_contract_fresh_handshake
        ):
            self._status_contract_write_blocked = False
            self._status_contract_fresh_handshake = False
        return decoded

    def readiness(self):
        return self._request(
            "GET",
            "/readyz",
            contract_response=True,
        )

    def put_snapshot(self, snapshot):
        self._require_status_contract_write_allowed()
        return self._request("PUT", "/api/v1/neutron/snapshot", snapshot)

    def recover_pending_snapshot(self, expected_generation, expected_desired_hash=None):
        self._require_status_contract_write_allowed()
        return self._request("POST", "/api/v1/neutron/snapshot/recover-pending", {
            "expected_pending_generation": expected_generation,
            "expected_desired_hash": expected_desired_hash,
            "mode": "rollback_to_last_applied",
        })

    def put_port_snapshot(self, port_id, snapshot, required_domains=None):
        self._validate_port_snapshot_request(port_id, snapshot)
        if self._status_contract_write_blocked:
            self._require_status_contract_write_allowed()
        capabilities = self.capabilities(required_domains=required_domains or [])
        self._require_status_contract_write_allowed()
        if not capabilities.get("supports_port_scoped_snapshot"):
            raise LocalApiContractError(
                "local API does not advertise supports_port_scoped_snapshot"
            )
        request_timeout = self._capability_request_timeout(capabilities)
        encoded = urlquote(port_id, safe="")
        return self._request(
            "PUT",
            "/api/v1/neutron/ports/%s/snapshot" % encoded,
            snapshot,
            request_timeout=request_timeout,
        )

    def delete_port(self, port_id):
        self._require_status_contract_write_allowed()
        encoded = urlquote(port_id, safe="")
        return self._request("DELETE", "/api/v1/neutron/ports/%s" % encoded)

    def _latch_status_contract_error(self):
        self._status_contract_write_blocked = True
        self._status_contract_fresh_handshake = False

    def _require_status_contract_write_allowed(self):
        if (
            self._status_contract_mode is None or
            self._status_contract_write_blocked
        ):
            raise LocalApiContractError(
                "status contract write gate is latched closed"
            )

    def _connection(self, request_timeout=None):
        timeout = self.timeout if request_timeout is None else request_timeout
        if self.connection_factory is not None:
            return self.connection_factory(self.socket_path, timeout)
        return UnixHTTPConnection(self.socket_path, timeout)

    def _request(
        self,
        method,
        path,
        body=None,
        contract_response=False,
        request_timeout=None,
    ):
        headers = {"Accept": "application/json"}
        payload = None
        if body is not None:
            payload = json.dumps(body, sort_keys=True)
            payload_len = len(payload.encode("utf-8"))
            if payload_len > self.max_request_bytes:
                raise LocalApiContractError(
                    "request body too large: %s > %s"
                    % (payload_len, self.max_request_bytes)
                )
            headers["Content-Type"] = "application/json"

        conn = self._connection(request_timeout=request_timeout)
        try:
            conn.request(method, path, body=payload, headers=headers)
            response = conn.getresponse()
            raw = response.read(self.max_response_bytes + 1)
            if len(raw) > self.max_response_bytes:
                if contract_response and response.status < 400:
                    raise LocalApiContractError(
                        "contract response is too large"
                    )
                raise LocalApiResponseError(response.status, response.reason, "response too large")
            if not raw:
                decoded = {}
            else:
                if not isinstance(raw, str):
                    try:
                        raw = raw.decode("utf-8")
                    except UnicodeError as exc:
                        if contract_response and response.status < 400:
                            raise LocalApiContractError(
                                "contract response is not valid UTF-8: %s" % exc
                            )
                        raise
                try:
                    decoded = json.loads(raw)
                except ValueError as exc:
                    if response.status < 400:
                        if contract_response:
                            raise LocalApiContractError(
                                "contract response is not valid JSON: %s" % exc
                            )
                        raise
                    decoded = _plain_error_body(response.status, response.reason, raw)
            if response.status >= 400:
                raise LocalApiResponseError(response.status, response.reason, decoded)
            return decoded
        except LocalApiError:
            raise
        except socket.timeout as exc:
            raise LocalApiTimeoutError(str(exc) or "timed out")
        except Exception as exc:
            raise LocalApiTransportError(str(exc))
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def _validate_capabilities(
        self,
        body,
        required_domains,
        status_contract_mode=STATUS_CONTRACT_LEGACY_V0,
    ):
        if not isinstance(body, dict):
            raise LocalApiContractError("capabilities response must be an object")
        if body.get("api_version") != NEUTRON_API_VERSION:
            raise LocalApiContractError("unsupported api_version %r" % body.get("api_version"))
        if body.get("attach_authority") != NEUTRON_ATTACH_AUTHORITY:
            raise LocalApiContractError(
                "unsupported attach_authority %r" % body.get("attach_authority")
            )
        if not body.get("supports_full_snapshot"):
            raise LocalApiContractError("local API does not support full snapshot")
        if not body.get("supports_port_delete"):
            raise LocalApiContractError("local API does not support port delete")

        supported = set(body.get("supported_domains") or [])
        missing = [domain for domain in required_domains if domain not in supported]
        if missing:
            raise LocalApiContractError("unsupported managed domains: %s" % ",".join(missing))

        contract_version = body.get("contract_version")
        if contract_version is not None and contract_version != NEUTRON_CONTRACT_VERSION:
            raise LocalApiContractError(
                "unsupported contract_version %r" % contract_version
            )

        schema_min = body.get("schema_version_min")
        schema_max = body.get("schema_version_max")
        if schema_min is not None or schema_max is not None:
            schema_min = _optional_int(schema_min, "schema_version_min") or 0
            schema_max = _optional_int(schema_max, "schema_version_max") or 0
            if schema_min > NEUTRON_SCHEMA_VERSION or schema_max < NEUTRON_SCHEMA_VERSION:
                raise LocalApiContractError(
                    "unsupported schema version range %s-%s" % (schema_min, schema_max)
                )

        body_max_bytes = body.get("body_max_bytes")
        body_max_bytes = _optional_int(body_max_bytes, "body_max_bytes")
        if body_max_bytes is not None and body_max_bytes <= 0:
            raise LocalApiContractError("invalid body_max_bytes %r" % body.get("body_max_bytes"))
        if body_max_bytes is not None:
            self.max_request_bytes = min(self.max_request_bytes, body_max_bytes)

        self._capability_request_timeout(body)

        expected_error_hash, expected_capability_hash = (
            _STATUS_CONTRACT_PROFILES[status_contract_mode]
        )
        error_codes_hash = body.get("error_codes_hash")
        if (
            error_codes_hash is not None and
            error_codes_hash != expected_error_hash
        ):
            raise LocalApiContractError(
                "unsupported error_codes_hash %r" % error_codes_hash
            )

        peer_auth_policy = body.get("peer_auth_policy")
        if peer_auth_policy is not None and not str(peer_auth_policy).strip():
            raise LocalApiContractError("empty peer_auth_policy")

        capability_hash = body.get("capability_hash")
        if (
            capability_hash is not None and
            capability_hash != expected_capability_hash
        ):
            raise LocalApiContractError(
                "unsupported capability_hash %r" % capability_hash
            )

    def _capability_request_timeout(self, body):
        timeout_ms = body.get("timeout_ms")
        timeout_ms = _optional_int(timeout_ms, "timeout_ms")
        if timeout_ms is not None and timeout_ms <= 0:
            raise LocalApiContractError(
                "invalid timeout_ms %r" % body.get("timeout_ms")
            )
        if timeout_ms is None:
            return self.timeout
        timeout = timeout_ms / 1000.0
        return min(self.timeout, timeout) if self.timeout is not None else timeout

    def _validate_port_snapshot_request(self, port_id, snapshot):
        if not isinstance(snapshot, dict):
            raise LocalApiContractError("port-scoped snapshot body must be an object")
        ports = snapshot.get("ports")
        if not isinstance(ports, list) or len(ports) != 1:
            raise LocalApiContractError(
                "port-scoped snapshot requires exactly one body port"
            )
        actual_port_id = ports[0].get("port_id") if isinstance(ports[0], dict) else None
        if actual_port_id != port_id:
            raise LocalApiContractError(
                "port-scoped snapshot path/body mismatch: expected %s, got %s"
                % (port_id, actual_port_id)
            )

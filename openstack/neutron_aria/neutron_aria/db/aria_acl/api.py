from __future__ import absolute_import

import copy
import contextlib
import datetime
import json
import sqlite3
import threading
import uuid

from neutron_aria.db.aria_acl.errors import AriaAclConflictError
from neutron_aria.db.aria_acl.errors import AriaAclError
from neutron_aria.db.aria_acl.errors import AriaAclNotFound
from neutron_aria.db.aria_acl.errors import AriaAclValidationError
from neutron_aria.db.aria_acl.query import apply_memory_query
from neutron_aria.db.aria_acl.query import decode_port_status_id
from neutron_aria.db.aria_acl.query import is_port_status_id
from neutron_aria.db.aria_acl.query import normalize_query
from neutron_aria.db.aria_acl.query import project_fields
from neutron_aria.db.aria_acl.query import require_one_legacy_port_status
from neutron_aria.db.aria_acl.sql_query import build_select
from neutron_aria.db.aria_acl.sql_query import build_sqlite_select
from neutron_aria.db.aria_acl.write_invariants import ADDRESS_SET_IMMUTABLE_FIELDS
from neutron_aria.db.aria_acl.write_invariants import BINDING_IMMUTABLE_FIELDS
from neutron_aria.db.aria_acl.write_invariants import POLICY_IMMUTABLE_FIELDS
from neutron_aria.db.aria_acl.write_invariants import RULE_IMMUTABLE_FIELDS
from neutron_aria.db.aria_acl.write_invariants import prepare_address_set
from neutron_aria.db.aria_acl.write_invariants import prepare_binding
from neutron_aria.db.aria_acl.write_invariants import prepare_policy
from neutron_aria.db.aria_acl.write_invariants import prepare_rule
from neutron_aria.db.aria_acl.write_invariants import reject_immutable_changes


try:
    STRING_TYPES = (basestring,)
    INTEGER_TYPES = (int, long)
except NameError:
    STRING_TYPES = (str,)
    INTEGER_TYPES = (int,)


def _clone(value):
    return copy.deepcopy(value)


def _row_dict(row):
    mapping = getattr(row, "_mapping", None)
    return dict(mapping if mapping is not None else row)


def _new_id():
    return str(uuid.uuid4())


def _require(obj, fields, object_type):
    missing = [
        field for field in fields
        if field not in obj or obj.get(field) is None
    ]
    if missing:
        raise AriaAclValidationError(
            "%s missing required field(s): %s" % (object_type, ",".join(missing))
        )


def _enabled(obj):
    value = (obj or {}).get("enabled", True)
    if isinstance(value, STRING_TYPES):
        return value.strip().lower() not in ("0", "false", "no", "off")
    return value is not False


def _next_revision(values):
    try:
        revision = int(values.get("revision_number") or 0)
    except (TypeError, ValueError):
        revision = 0
    return revision + 1


def _normalize_project_id(obj):
    project_id = obj.get("project_id") or obj.get("tenant_id")
    if project_id:
        obj["project_id"] = project_id
    return obj


def _matches_filters(value, filters):
    for key, expected in (filters or {}).items():
        actual = value.get(key)
        if isinstance(expected, (list, tuple, set)):
            if actual not in expected:
                return False
        elif actual != expected:
                return False
    return True


def _sqlite_json_scalar(payload, field):
    try:
        value = json.loads(payload).get(field)
    except (AttributeError, TypeError, ValueError):
        return None
    if isinstance(value, bool):
        return 1 if value else 0
    if value is None or isinstance(
        value,
        INTEGER_TYPES + (float,) + STRING_TYPES,
    ):
        return value
    return None


def _utcnow():
    if hasattr(datetime, "timezone"):
        now = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    else:
        now = datetime.datetime.utcnow()
    return "%s.%06dZ" % (now.strftime("%Y-%m-%dT%H:%M:%S"), now.microsecond)


def _stamp_create(values):
    now = _utcnow()
    values.setdefault("created_at", now)
    values.setdefault("updated_at", values["created_at"])
    return values


def _stamp_update(values):
    values.setdefault("created_at", _utcnow())
    values["updated_at"] = _utcnow()
    return values


def _stamp_status(values):
    values["updated_at"] = _utcnow()
    return values


def _parse_time(value):
    if value is None or isinstance(value, datetime.datetime):
        return value
    if isinstance(value, str):
        value = value.rstrip("Z")
        try:
            return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%f")
        except ValueError:
            try:
                return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")
            except ValueError:
                return datetime.datetime.utcnow()
    return value


def _format_time(value):
    if isinstance(value, datetime.datetime):
        return "%s.%06dZ" % (value.strftime("%Y-%m-%dT%H:%M:%S"), value.microsecond)
    return value


def _locked_access(method):
    def locked(self, *args, **kwargs):
        with self._write_lock:
            return method(self, *args, **kwargs)
    locked.__name__ = method.__name__
    locked.__doc__ = method.__doc__
    return locked


def _constraint_name(exc):
    direct = getattr(exc, "constraint_name", None)
    if direct:
        return direct
    original = getattr(exc, "orig", None)
    diagnostic = getattr(original, "diag", None)
    diagnostic_name = getattr(diagnostic, "constraint_name", None)
    if diagnostic_name:
        return diagnostic_name
    message = str(exc)
    for name in (
        "uq_aria_acl_rules_enabled_priority",
        "uq_aria_acl_bindings_enabled_target",
    ):
        if name in message:
            return name
    return None


def _neutron_write(constraint_kind=None):
    def decorate(method):
        def transactional(self, *args, **kwargs):
            with self._write_transaction():
                try:
                    return method(self, *args, **kwargs)
                except Exception as exc:
                    if constraint_kind is not None:
                        self._raise_known_constraint(exc, constraint_kind)
                    raise
        transactional.__name__ = method.__name__
        transactional.__doc__ = method.__doc__
        return transactional
    return decorate


def _sqlite_write(constraint_kind=None):
    def decorate(method):
        def transactional(self, *args, **kwargs):
            if getattr(self, "_bulk_write_active", False):
                try:
                    return method(self, *args, **kwargs)
                except sqlite3.IntegrityError as exc:
                    if constraint_kind is not None:
                        self._raise_known_constraint(exc, constraint_kind)
                    raise
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                result = method(self, *args, **kwargs)
                self.connection.commit()
                return result
            except sqlite3.IntegrityError as exc:
                self.connection.rollback()
                if constraint_kind is not None:
                    self._raise_known_constraint(exc, constraint_kind)
                raise
            except Exception:
                self.connection.rollback()
                raise
        transactional.__name__ = method.__name__
        transactional.__doc__ = method.__doc__
        return transactional
    return decorate


class InMemoryAriaAclRepository(object):
    """Minimal aria_acl repository contract.

    This repository intentionally stays stdlib-only so the agent package can be
    tested before the product neutron-server DB wiring is available. The method
    names and payload shapes are the contract consumed by NeutronAclSource.
    """

    def __init__(self):
        self._write_lock = threading.RLock()
        self.policies = {}
        self.rules = {}
        self.address_sets = {}
        self.bindings = {}
        self.port_statuses = {}
        self.port_counters = {}

    def bulk_create(self, resource, values_list):
        creators = {
            "policy": self.create_policy,
            "rule": self.create_rule,
            "address_set": self.create_address_set,
            "binding": self.create_binding,
            "port_status": self.upsert_port_status,
        }
        creator = creators[resource]
        with self._write_lock:
            snapshot = {
                "policies": _clone(self.policies),
                "rules": _clone(self.rules),
                "address_sets": _clone(self.address_sets),
                "bindings": _clone(self.bindings),
                "port_statuses": _clone(self.port_statuses),
                "port_counters": _clone(self.port_counters),
            }
            try:
                return [creator(values) for values in values_list]
            except Exception:
                self.policies = snapshot["policies"]
                self.rules = snapshot["rules"]
                self.address_sets = snapshot["address_sets"]
                self.bindings = snapshot["bindings"]
                self.port_statuses = snapshot["port_statuses"]
                self.port_counters = snapshot["port_counters"]
                raise

    @_locked_access
    def create_policy(self, values):
        values = _normalize_project_id(_clone(values))
        _require(values, ("project_id",), "aria_acl_policy")
        values.setdefault("id", _new_id())
        values.setdefault("name", "")
        values.setdefault("default_action", "allow")
        values.setdefault("stateful", True)
        values.setdefault("enabled", True)
        values.setdefault("revision_number", 1)
        values = prepare_policy(values)
        _stamp_create(values)
        self.policies[values["id"]] = values
        return _clone(values)

    @_locked_access
    def list_policies(
        self,
        filters=None,
        fields=None,
        sorts=None,
        limit=None,
        marker=None,
        page_reverse=False,
    ):
        query = normalize_query(
            "policies", filters, fields, sorts, limit, marker, page_reverse
        )
        return apply_memory_query(self.policies.values(), query)

    @_locked_access
    def get_policy(self, policy_id, fields=None):
        return project_fields(
            self._get(self.policies, policy_id, "aria_acl_policy"),
            fields,
        )

    @_locked_access
    def update_policy(self, policy_id, values):
        existing = self._get(self.policies, policy_id, "aria_acl_policy")
        reject_immutable_changes(
            existing,
            values,
            POLICY_IMMUTABLE_FIELDS,
            "aria_acl_policy",
        )
        current = _clone(existing)
        current.update(_clone(values))
        _normalize_project_id(current)
        _require(current, ("project_id",), "aria_acl_policy")
        current = prepare_policy(current)
        current["revision_number"] = _next_revision(current)
        _stamp_update(current)
        self.policies[policy_id] = current
        return _clone(current)

    @_locked_access
    def delete_policy(self, policy_id):
        self._reject_policy_in_use(policy_id)
        self._delete(self.policies, policy_id, "aria_acl_policy")

    @_locked_access
    def create_rule(self, values):
        values = _normalize_project_id(_clone(values))
        _require(values, ("policy_id", "direction", "priority", "action"), "aria_acl_rule")
        values.setdefault("id", _new_id())
        values.setdefault("enabled", True)
        values.setdefault("revision_number", 1)
        values = prepare_rule(self, values)
        _stamp_create(values)
        self.rules[values["id"]] = values
        return _clone(values)

    @_locked_access
    def list_rules(
        self,
        filters=None,
        fields=None,
        sorts=None,
        limit=None,
        marker=None,
        page_reverse=False,
    ):
        query = normalize_query(
            "rules", filters, fields, sorts, limit, marker, page_reverse
        )
        return apply_memory_query(self.rules.values(), query)

    @_locked_access
    def get_rule(self, rule_id, fields=None):
        return project_fields(
            self._get(self.rules, rule_id, "aria_acl_rule"),
            fields,
        )

    @_locked_access
    def update_rule(self, rule_id, values):
        existing = self._get(self.rules, rule_id, "aria_acl_rule")
        reject_immutable_changes(
            existing,
            values,
            RULE_IMMUTABLE_FIELDS,
            "aria_acl_rule",
        )
        current = _clone(existing)
        current.update(_clone(values))
        _normalize_project_id(current)
        _require(current, ("policy_id", "direction", "priority", "action"), "aria_acl_rule")
        current = prepare_rule(self, current, existing=existing)
        current["revision_number"] = _next_revision(current)
        _stamp_update(current)
        self.rules[rule_id] = current
        return _clone(current)

    @_locked_access
    def delete_rule(self, rule_id):
        self._delete(self.rules, rule_id, "aria_acl_rule")

    @_locked_access
    def create_address_set(self, values):
        values = _normalize_project_id(_clone(values))
        _require(values, ("project_id",), "aria_acl_address_set")
        values.setdefault("id", _new_id())
        values.setdefault("name", "")
        values.setdefault("members", [])
        values.setdefault("enabled", True)
        values.setdefault("revision_number", 1)
        values = prepare_address_set(self, values)
        _stamp_create(values)
        self.address_sets[values["id"]] = values
        return _clone(values)

    @_locked_access
    def list_address_sets(
        self,
        filters=None,
        fields=None,
        sorts=None,
        limit=None,
        marker=None,
        page_reverse=False,
    ):
        query = normalize_query(
            "address_sets", filters, fields, sorts, limit, marker, page_reverse
        )
        return apply_memory_query(self.address_sets.values(), query)

    @_locked_access
    def get_address_set(self, address_set_id, fields=None):
        return project_fields(
            self._get(
                self.address_sets,
                address_set_id,
                "aria_acl_address_set",
            ),
            fields,
        )

    @_locked_access
    def update_address_set(self, address_set_id, values):
        existing = self._get(
            self.address_sets,
            address_set_id,
            "aria_acl_address_set",
        )
        reject_immutable_changes(
            existing,
            values,
            ADDRESS_SET_IMMUTABLE_FIELDS,
            "aria_acl_address_set",
        )
        current = _clone(existing)
        current.update(_clone(values))
        _normalize_project_id(current)
        _require(current, ("project_id",), "aria_acl_address_set")
        current = prepare_address_set(self, current, existing=existing)
        current["revision_number"] = _next_revision(current)
        _stamp_update(current)
        self.address_sets[address_set_id] = current
        return _clone(current)

    @_locked_access
    def delete_address_set(self, address_set_id):
        self._reject_address_set_in_use(address_set_id)
        self._delete(self.address_sets, address_set_id, "aria_acl_address_set")

    @_locked_access
    def create_binding(self, values):
        values = _normalize_project_id(_clone(values))
        _require(
            values,
            ("project_id", "policy_id", "target_type", "target_id"),
            "aria_acl_binding",
        )
        values.setdefault("id", _new_id())
        values.setdefault("enabled", True)
        values.setdefault("revision_number", 1)
        values = prepare_binding(self, values)
        _stamp_create(values)
        self.bindings[values["id"]] = values
        return _clone(values)

    @_locked_access
    def list_bindings(
        self,
        filters=None,
        fields=None,
        sorts=None,
        limit=None,
        marker=None,
        page_reverse=False,
    ):
        query = normalize_query(
            "bindings", filters, fields, sorts, limit, marker, page_reverse
        )
        return apply_memory_query(self.bindings.values(), query)

    @_locked_access
    def get_binding(self, binding_id, fields=None):
        return project_fields(
            self._get(self.bindings, binding_id, "aria_acl_binding"),
            fields,
        )

    @_locked_access
    def update_binding(self, binding_id, values):
        existing = self._get(self.bindings, binding_id, "aria_acl_binding")
        reject_immutable_changes(
            existing,
            values,
            BINDING_IMMUTABLE_FIELDS,
            "aria_acl_binding",
        )
        current = _clone(existing)
        current.update(_clone(values))
        _normalize_project_id(current)
        _require(
            current,
            ("project_id", "policy_id", "target_type", "target_id"),
            "aria_acl_binding",
        )
        current = prepare_binding(self, current, existing=existing)
        current["revision_number"] = _next_revision(current)
        _stamp_update(current)
        self.bindings[binding_id] = current
        return _clone(current)

    @_locked_access
    def delete_binding(self, binding_id):
        self._delete(self.bindings, binding_id, "aria_acl_binding")

    @_locked_access
    def upsert_port_status(self, values):
        values = _clone(values)
        _require(values, ("port_id", "host"), "aria_acl_port_status")
        _stamp_status(values)
        key = (values["port_id"], values["host"])
        # Merge like the DB-backed repository: unspecified columns keep their
        # previous values so e.g. counter-less reports do not wipe the last
        # good counter snapshot (spec §10).
        merged = dict(self.port_statuses.get(key) or {})
        merged.update(values)
        self.port_statuses[key] = merged
        return _clone(merged)

    @_locked_access
    def get_port_status(self, port_id, host=None):
        if host is not None:
            return _clone(self.port_statuses.get((port_id, host)))
        statuses = [
            status for (status_port_id, _host), status in self.port_statuses.items()
            if status_port_id == port_id
        ]
        return _clone(statuses)

    @_locked_access
    def upsert_port_counters(self, port_id, host, rows):
        rows = _clone(rows or [])
        for row in rows:
            row.setdefault("id", _new_id())
            row.setdefault("port_id", port_id)
            row.setdefault("host", host)
        self.port_counters[(port_id, host)] = rows
        return _clone(rows)

    @_locked_access
    def get_port_counters(self, port_id, host=None):
        if host is not None:
            rows = _clone(self.port_counters.get((port_id, host), []))
        else:
            rows = []
            for (row_port_id, _host), values in self.port_counters.items():
                if row_port_id == port_id:
                    rows.extend(_clone(values))
        return sorted(rows, key=lambda row: (row.get("kind") or "", row.get("id") or ""))

    @_locked_access
    def list_port_statuses(
        self,
        filters=None,
        fields=None,
        sorts=None,
        limit=None,
        marker=None,
        page_reverse=False,
        projection=None,
    ):
        query = normalize_query(
            "port_statuses",
            filters,
            fields,
            sorts,
            limit,
            marker,
            page_reverse,
        )
        return apply_memory_query(
            self.port_statuses.values(),
            query,
            projection=projection,
        )

    @_locked_access
    def delete_port_status(self, port_id, host=None):
        if host is not None:
            key = (port_id, host)
            if key not in self.port_statuses:
                raise AriaAclNotFound("aria_acl_port_status %s/%s not found" % (port_id, host))
            del self.port_statuses[key]
            self.port_counters.pop(key, None)
            return
        keys = [
            key for key in self.port_statuses
            if key[0] == port_id
        ]
        if not keys:
            raise AriaAclNotFound("aria_acl_port_status %s not found" % port_id)
        for key in keys:
            del self.port_statuses[key]
            self.port_counters.pop(key, None)

    @_locked_access
    def get_port_status_resource(self, resource_id):
        if is_port_status_id(resource_id):
            port_id, host = decode_port_status_id(resource_id)
            value = self.get_port_status(port_id, host=host)
            if value is None:
                raise AriaAclNotFound(
                    "aria_acl_port_status %s/%s not found" % (port_id, host)
                )
            return value
        return require_one_legacy_port_status(
            resource_id,
            self.get_port_status(resource_id),
        )

    @_locked_access
    def delete_port_status_resource(self, resource_id):
        if is_port_status_id(resource_id):
            port_id, host = decode_port_status_id(resource_id)
            return self.delete_port_status(port_id, host=host)
        return self.delete_port_status(resource_id, host=None)

    @_locked_access
    def to_effective_payload(self):
        return {
            "policies": self.list_policies(),
            "rules": self.list_rules(),
            "address_sets": self.list_address_sets(),
            "bindings": self.list_bindings(),
        }

    def _list(self, store, filters=None):
        filters = filters or {}
        result = []
        for value in store.values():
            if _matches_filters(value, filters):
                result.append(_clone(value))
        return result

    def _get(self, store, object_id, object_type):
        if object_id not in store:
            raise AriaAclNotFound("%s %s not found" % (object_type, object_id))
        return _clone(store[object_id])

    def _delete(self, store, object_id, object_type):
        if object_id not in store:
            raise AriaAclNotFound("%s %s not found" % (object_type, object_id))
        del store[object_id]

    def _reject_policy_in_use(self, policy_id):
        for rule in self.rules.values():
            if rule.get("policy_id") == policy_id:
                raise AriaAclValidationError("aria_acl_policy is referenced by rule")
        for binding in self.bindings.values():
            if binding.get("policy_id") == policy_id:
                raise AriaAclValidationError("aria_acl_policy is referenced by binding")

    def _reject_address_set_in_use(self, address_set_id):
        for rule in self.rules.values():
            if (
                rule.get("src_address_set_id") == address_set_id or
                rule.get("dst_address_set_id") == address_set_id
            ):
                raise AriaAclValidationError("aria_acl_address_set is referenced by rule")

class NeutronDbAriaAclRepository(object):
    """Neutron context/session backed aria_acl repository.

    The target product neutron-server is a Python 2, pre-neutron-lib runtime.
    Keep this repository close to SQLAlchemy Core and the existing
    ``context.session`` contract so it can load inside that environment.
    """

    def __init__(self, context, auto_create=True):
        if context is None or not getattr(context, "session", None):
            raise AriaAclValidationError("neutron context with session is required")
        self.context = context
        self.session = context.session
        self.sa = self._load_sqlalchemy()
        self.metadata = self.sa.MetaData()
        self.tables = self._define_tables()
        if auto_create:
            self.ensure_schema()

    def bulk_create(self, resource, values_list):
        creators = {
            "policy": self.create_policy,
            "rule": self.create_rule,
            "address_set": self.create_address_set,
            "binding": self.create_binding,
            "port_status": self.upsert_port_status,
        }
        creator = creators[resource]
        with self._write_transaction():
            return [creator(values) for values in values_list]

    @_neutron_write()
    def create_policy(self, values):
        values = _normalize_project_id(_clone(values))
        _require(values, ("project_id",), "aria_acl_policy")
        values.setdefault("id", _new_id())
        values.setdefault("name", "")
        values.setdefault("default_action", "allow")
        values.setdefault("stateful", True)
        values.setdefault("enabled", True)
        values.setdefault("revision_number", 1)
        values = prepare_policy(values)
        _stamp_create(values)
        self._insert("policies", self._db_values("policies", values))
        return _clone(values)

    def list_policies(
        self, filters=None, fields=None, sorts=None, limit=None,
        marker=None, page_reverse=False,
    ):
        return self._list_query(
            "policies", filters, fields, sorts, limit, marker, page_reverse
        )

    def get_policy(self, policy_id, fields=None):
        if not hasattr(self, "tables"):
            return project_fields(
                self._get("policies", policy_id, "aria_acl_policy"),
                fields,
            )
        return self._get("policies", policy_id, "aria_acl_policy", fields)

    @_neutron_write()
    def update_policy(self, policy_id, values):
        self._lock_write_rows(policy_id=policy_id)
        existing = self.get_policy(policy_id)
        reject_immutable_changes(
            existing,
            values,
            POLICY_IMMUTABLE_FIELDS,
            "aria_acl_policy",
        )
        current = _clone(existing)
        current.update(_clone(values))
        _normalize_project_id(current)
        _require(current, ("project_id",), "aria_acl_policy")
        current = prepare_policy(current)
        current["revision_number"] = _next_revision(current)
        _stamp_update(current)
        self._update("policies", policy_id, self._db_values("policies", current))
        return _clone(current)

    @_neutron_write()
    def delete_policy(self, policy_id):
        self._lock_write_rows(policy_id=policy_id)
        self._reject_policy_in_use(policy_id)
        self._delete("policies", policy_id, "aria_acl_policy")

    @_neutron_write("rule")
    def create_rule(self, values):
        values = _normalize_project_id(_clone(values))
        _require(values, ("policy_id", "direction", "priority", "action"), "aria_acl_rule")
        values.setdefault("id", _new_id())
        values.setdefault("enabled", True)
        values.setdefault("revision_number", 1)
        self._lock_write_rows(
            address_set_ids=self._address_set_ids(values),
            policy_id=values.get("policy_id"),
        )
        values = prepare_rule(self, values)
        _stamp_create(values)
        self._insert("rules", self._db_values("rules", values))
        return _clone(values)

    def list_rules(
        self, filters=None, fields=None, sorts=None, limit=None,
        marker=None, page_reverse=False,
    ):
        return self._list_query(
            "rules", filters, fields, sorts, limit, marker, page_reverse
        )

    def get_rule(self, rule_id, fields=None):
        if not hasattr(self, "tables"):
            return project_fields(
                self._get("rules", rule_id, "aria_acl_rule"),
                fields,
            )
        return self._get("rules", rule_id, "aria_acl_rule", fields)

    @_neutron_write("rule")
    def update_rule(self, rule_id, values):
        existing = self.get_rule(rule_id)
        reject_immutable_changes(
            existing,
            values,
            RULE_IMMUTABLE_FIELDS,
            "aria_acl_rule",
        )
        current = _clone(existing)
        current.update(_clone(values))
        self._lock_write_rows(
            address_set_ids=self._address_set_ids(current),
            policy_id=current.get("policy_id"),
            object_table="rules",
            object_id=rule_id,
        )
        existing = self.get_rule(rule_id)
        current = _clone(existing)
        current.update(_clone(values))
        _normalize_project_id(current)
        _require(current, ("policy_id", "direction", "priority", "action"), "aria_acl_rule")
        current = prepare_rule(self, current, existing=existing)
        current["revision_number"] = _next_revision(current)
        _stamp_update(current)
        self._update("rules", rule_id, self._db_values("rules", current))
        return _clone(current)

    def delete_rule(self, rule_id):
        self._delete("rules", rule_id, "aria_acl_rule")

    @_neutron_write()
    def create_address_set(self, values):
        values = _normalize_project_id(_clone(values))
        _require(values, ("project_id",), "aria_acl_address_set")
        values.setdefault("id", _new_id())
        values.setdefault("name", "")
        values.setdefault("members", [])
        values.setdefault("enabled", True)
        values.setdefault("revision_number", 1)
        values = prepare_address_set(self, values)
        _stamp_create(values)
        self._insert("address_sets", self._db_values("address_sets", values))
        self._replace_members(values["id"], values.get("members", []))
        return _clone(values)

    def list_address_sets(
        self, filters=None, fields=None, sorts=None, limit=None,
        marker=None, page_reverse=False,
    ):
        return self._list_query(
            "address_sets", filters, fields, sorts, limit, marker, page_reverse
        )

    def get_address_set(self, address_set_id, fields=None):
        if not hasattr(self, "tables"):
            return project_fields(
                self._get(
                    "address_sets",
                    address_set_id,
                    "aria_acl_address_set",
                ),
                fields,
            )
        return self._get(
            "address_sets",
            address_set_id,
            "aria_acl_address_set",
            fields,
        )

    @_neutron_write()
    def update_address_set(self, address_set_id, values):
        self._lock_write_rows(address_set_ids=(address_set_id,))
        existing = self.get_address_set(address_set_id)
        reject_immutable_changes(
            existing,
            values,
            ADDRESS_SET_IMMUTABLE_FIELDS,
            "aria_acl_address_set",
        )
        current = _clone(existing)
        current.update(_clone(values))
        _normalize_project_id(current)
        _require(current, ("project_id",), "aria_acl_address_set")
        current = prepare_address_set(self, current, existing=existing)
        current["revision_number"] = _next_revision(current)
        _stamp_update(current)
        self._update("address_sets", address_set_id, self._db_values("address_sets", current))
        if "members" in values:
            self._replace_members(address_set_id, current.get("members", []))
        return _clone(current)

    @_neutron_write()
    def delete_address_set(self, address_set_id):
        self._lock_write_rows(address_set_ids=(address_set_id,))
        self._reject_address_set_in_use(address_set_id)
        with self._write_transaction():
            self.session.execute(
                self.tables["address_set_members"].delete().where(
                    self.tables["address_set_members"].c.address_set_id == address_set_id
                )
            )
        self._delete("address_sets", address_set_id, "aria_acl_address_set")

    @_neutron_write("binding")
    def create_binding(self, values):
        values = _normalize_project_id(_clone(values))
        _require(
            values,
            ("project_id", "policy_id", "target_type", "target_id"),
            "aria_acl_binding",
        )
        values.setdefault("id", _new_id())
        values.setdefault("enabled", True)
        values.setdefault("revision_number", 1)
        self._lock_write_rows(policy_id=values.get("policy_id"))
        values = prepare_binding(self, values)
        _stamp_create(values)
        self._insert("bindings", self._db_values("bindings", values))
        return _clone(values)

    def list_bindings(
        self, filters=None, fields=None, sorts=None, limit=None,
        marker=None, page_reverse=False,
    ):
        return self._list_query(
            "bindings", filters, fields, sorts, limit, marker, page_reverse
        )

    def get_binding(self, binding_id, fields=None):
        if not hasattr(self, "tables"):
            return project_fields(
                self._get("bindings", binding_id, "aria_acl_binding"),
                fields,
            )
        return self._get("bindings", binding_id, "aria_acl_binding", fields)

    @_neutron_write("binding")
    def update_binding(self, binding_id, values):
        existing = self.get_binding(binding_id)
        reject_immutable_changes(
            existing,
            values,
            BINDING_IMMUTABLE_FIELDS,
            "aria_acl_binding",
        )
        current = _clone(existing)
        current.update(_clone(values))
        self._lock_write_rows(
            policy_id=current.get("policy_id"),
            object_table="bindings",
            object_id=binding_id,
        )
        existing = self.get_binding(binding_id)
        current = _clone(existing)
        current.update(_clone(values))
        _normalize_project_id(current)
        _require(
            current,
            ("project_id", "policy_id", "target_type", "target_id"),
            "aria_acl_binding",
        )
        current = prepare_binding(self, current, existing=existing)
        current["revision_number"] = _next_revision(current)
        _stamp_update(current)
        self._update("bindings", binding_id, self._db_values("bindings", current))
        return _clone(current)

    def delete_binding(self, binding_id):
        self._delete("bindings", binding_id, "aria_acl_binding")

    @_neutron_write()
    def upsert_port_status(self, values):
        values = _clone(values)
        _require(values, ("port_id", "host"), "aria_acl_port_status")
        _stamp_status(values)
        table = self.tables["port_statuses"]
        db_values = self._db_values("port_statuses", values)
        row_identity = (
            (table.c.port_id == values["port_id"]) &
            (table.c.host == values["host"])
        )
        update = table.update().where(row_identity).values(**db_values)
        result = self.session.execute(update)
        if result.rowcount == 0:
            if self._port_status_row_exists(table, row_identity):
                return _clone(values)
            insert_error = None
            try:
                with self.session.begin_nested():
                    self.session.execute(table.insert().values(**db_values))
            except self.sa.exc.IntegrityError as exc:
                insert_error = exc
            if insert_error is not None:
                result = self.session.execute(update)
                if result.rowcount == 0:
                    if self._port_status_row_exists(table, row_identity):
                        return _clone(values)
                    raise insert_error
        return _clone(values)

    def _port_status_row_exists(self, table, row_identity):
        presence = self.session.execute(
            table.select().where(row_identity).limit(1)
        ).first()
        return presence is not None

    def get_port_status(self, port_id, host=None):
        table = self.tables["port_statuses"]
        query = table.select().where(table.c.port_id == port_id)
        if host is not None:
            query = query.where(table.c.host == host)
        rows = self.session.execute(query).fetchall()
        values = [self._row_to_dict("port_statuses", row) for row in rows]
        if host is not None:
            return values[0] if values else None
        return values

    def list_port_statuses(
        self, filters=None, fields=None, sorts=None, limit=None,
        marker=None, page_reverse=False, projection=None,
    ):
        return self._list_query(
            "port_statuses",
            filters,
            fields,
            sorts,
            limit,
            marker,
            page_reverse,
            projection=projection,
        )

    def delete_port_status(self, port_id, host=None):
        table = self.tables["port_statuses"]
        clause = table.c.port_id == port_id
        if host is not None:
            clause = clause & (table.c.host == host)
        with self._write_transaction():
            result = self.session.execute(table.delete().where(clause))
            counters_table = self.tables["port_counters"]
            counters_clause = counters_table.c.port_id == port_id
            if host is not None:
                counters_clause = counters_clause & (
                    counters_table.c.host == host
                )
            self.session.execute(
                counters_table.delete().where(counters_clause)
            )
        if result.rowcount == 0:
            if host is not None:
                raise AriaAclNotFound(
                    "aria_acl_port_status %s/%s not found" % (port_id, host)
                )
            raise AriaAclNotFound("aria_acl_port_status %s not found" % port_id)

    @_neutron_write()
    def upsert_port_counters(self, port_id, host, rows):
        table = self.tables["port_counters"]
        self.session.execute(
            table.delete().where(
                (table.c.port_id == port_id) &
                (table.c.host == host)
            )
        )
        for row in rows or []:
            values = dict(row)
            values.setdefault("id", _new_id())
            values.setdefault("port_id", port_id)
            values.setdefault("host", host)
            self.session.execute(
                table.insert().values(
                    **self._db_values("port_counters", values)
                )
            )
        return _clone(rows or [])

    def get_port_counters(self, port_id, host=None):
        table = self.tables["port_counters"]
        query = table.select().where(table.c.port_id == port_id)
        if host is not None:
            query = query.where(table.c.host == host)
        query = query.order_by(table.c.kind, table.c.sampled_at)
        rows = self.session.execute(query).fetchall()
        return [self._row_to_dict("port_counters", row) for row in rows]

    def get_port_status_resource(self, resource_id):
        if is_port_status_id(resource_id):
            port_id, host = decode_port_status_id(resource_id)
            value = self.get_port_status(port_id, host=host)
            if value is None:
                raise AriaAclNotFound(
                    "aria_acl_port_status %s/%s not found" % (port_id, host)
                )
            return value
        return require_one_legacy_port_status(
            resource_id,
            self.get_port_status(resource_id),
        )

    def delete_port_status_resource(self, resource_id):
        if is_port_status_id(resource_id):
            port_id, host = decode_port_status_id(resource_id)
            return self.delete_port_status(port_id, host=host)
        return self.delete_port_status(resource_id, host=None)

    def to_effective_payload(self):
        return {
            "policies": self.list_policies(),
            "rules": self.list_rules(),
            "address_sets": self.list_address_sets(),
            "bindings": self.list_bindings(),
        }

    def ensure_schema(self):
        bind = self.session.get_bind()
        for table in self.tables.values():
            table.create(bind=bind, checkfirst=True)
        inspector = self.sa.inspect(bind)
        missing = []
        for table_key in ("rules", "bindings"):
            table = self.tables.get(table_key)
            if table is None:
                continue
            columns = set(
                column["name"]
                for column in inspector.get_columns(table.name)
            )
            if "enabled_guard" not in columns:
                missing.append(table.name)
        if missing:
            raise AriaAclValidationError(
                "aria_acl_schema_migration_required: %s missing enabled_guard"
                % ",".join(sorted(missing))
            )

    @contextlib.contextmanager
    def _write_transaction(self):
        session = getattr(self, "session", None)
        if session is None:
            yield
            return
        in_transaction = getattr(session, "in_transaction", None)
        if in_transaction is not None:
            active = in_transaction()
        else:
            active = getattr(session, "transaction", None) is not None
        if active:
            yield
            return
        with session.begin():
            yield

    def _raise_known_constraint(self, exc, constraint_kind):
        name = _constraint_name(exc)
        expected = {
            "rule": "uq_aria_acl_rules_enabled_priority",
            "binding": "uq_aria_acl_bindings_enabled_target",
        }.get(constraint_kind)
        if name != expected:
            return
        reason = {
            "rule": "duplicate_enabled_rule_priority",
            "binding": "duplicate_enabled_binding_target",
        }[constraint_kind]
        raise AriaAclConflictError("%s: %s" % (reason, exc))

    @staticmethod
    def _address_set_ids(values):
        return sorted(set(
            values.get(field)
            for field in ("src_address_set_id", "dst_address_set_id")
            if values.get(field)
        ))

    def _lock_write_rows(
            self,
            address_set_ids=(),
            policy_id=None,
            object_table=None,
            object_id=None):
        if not hasattr(self, "session") or not hasattr(self, "tables"):
            return
        ordered = [
            ("address_sets", address_set_id)
            for address_set_id in sorted(set(address_set_ids or ()))
        ]
        if policy_id:
            ordered.append(("policies", policy_id))
        if object_table and object_id:
            ordered.append((object_table, object_id))
        bind = self.session.get_bind()
        sqlite_write_lock = (
            getattr(getattr(bind, "dialect", None), "name", None) == "sqlite"
        )
        for table_name, row_id in ordered:
            table = self.tables[table_name]
            if sqlite_write_lock:
                query = table.update().where(
                    table.c.id == row_id
                ).values(id=row_id)
                self.session.execute(query)
                continue
            query = table.select().where(table.c.id == row_id)
            if hasattr(query, "with_for_update"):
                query = query.with_for_update()
            self.session.execute(query).fetchall()

    def _load_sqlalchemy(self):
        try:
            import sqlalchemy as sa
        except Exception as exc:
            raise AriaAclValidationError("sqlalchemy unavailable: %s" % exc)
        return sa

    def _define_tables(self):
        sa = self.sa
        md = self.metadata
        return {
            "policies": sa.Table(
                "aria_acl_policies", md,
                sa.Column("id", sa.String(36), primary_key=True),
                sa.Column("project_id", sa.String(36), nullable=False),
                sa.Column("name", sa.String(255)),
                sa.Column("default_action", sa.String(64), nullable=False),
                sa.Column("stateful", sa.Boolean(), nullable=False),
                sa.Column("enabled", sa.Boolean(), nullable=False),
                sa.Column("revision_number", sa.Integer(), nullable=False),
                sa.Column("created_at", sa.DateTime()),
                sa.Column("updated_at", sa.DateTime()),
            ),
            "rules": sa.Table(
                "aria_acl_rules", md,
                sa.Column("id", sa.String(36), primary_key=True),
                sa.Column("project_id", sa.String(36)),
                sa.Column("policy_id", sa.String(36), nullable=False),
                sa.Column("direction", sa.String(64), nullable=False),
                sa.Column("priority", sa.Integer(), nullable=False),
                sa.Column("action", sa.String(64), nullable=False),
                sa.Column("protocol", sa.String(64)),
                sa.Column("src_cidr", sa.String(128)),
                sa.Column("dst_cidr", sa.String(128)),
                sa.Column("src_address_set_id", sa.String(36)),
                sa.Column("dst_address_set_id", sa.String(36)),
                sa.Column("src_port_min", sa.Integer()),
                sa.Column("src_port_max", sa.Integer()),
                sa.Column("dst_port_min", sa.Integer()),
                sa.Column("dst_port_max", sa.Integer()),
                sa.Column("ethertype", sa.String(64)),
                sa.Column("enabled", sa.Boolean(), nullable=False),
                sa.Column("enabled_guard", sa.SmallInteger(), nullable=True),
                sa.Column("revision_number", sa.Integer(), nullable=False),
                sa.Column("created_at", sa.DateTime()),
                sa.Column("updated_at", sa.DateTime()),
                sa.UniqueConstraint(
                    "policy_id",
                    "direction",
                    "priority",
                    "enabled_guard",
                    name="uq_aria_acl_rules_enabled_priority",
                ),
            ),
            "address_sets": sa.Table(
                "aria_acl_address_sets", md,
                sa.Column("id", sa.String(36), primary_key=True),
                sa.Column("project_id", sa.String(36), nullable=False),
                sa.Column("name", sa.String(255)),
                sa.Column("enabled", sa.Boolean(), nullable=False),
                sa.Column("revision_number", sa.Integer(), nullable=False),
                sa.Column("created_at", sa.DateTime()),
                sa.Column("updated_at", sa.DateTime()),
            ),
            "address_set_members": sa.Table(
                "aria_acl_address_set_members", md,
                sa.Column("id", sa.String(36), primary_key=True),
                sa.Column("address_set_id", sa.String(36), nullable=False),
                sa.Column("address", sa.String(128), nullable=False),
                sa.Column("created_at", sa.DateTime()),
                sa.Column("updated_at", sa.DateTime()),
            ),
            "bindings": sa.Table(
                "aria_acl_bindings", md,
                sa.Column("id", sa.String(36), primary_key=True),
                sa.Column("project_id", sa.String(36), nullable=False),
                sa.Column("policy_id", sa.String(36), nullable=False),
                sa.Column("target_type", sa.String(64), nullable=False),
                sa.Column("target_id", sa.String(36), nullable=False),
                sa.Column("enabled", sa.Boolean(), nullable=False),
                sa.Column("enabled_guard", sa.SmallInteger(), nullable=True),
                sa.Column("revision_number", sa.Integer(), nullable=False),
                sa.Column("created_at", sa.DateTime()),
                sa.Column("updated_at", sa.DateTime()),
                sa.UniqueConstraint(
                    "target_type",
                    "target_id",
                    "enabled_guard",
                    name="uq_aria_acl_bindings_enabled_target",
                ),
            ),
            "rbac": sa.Table(
                "aria_acl_rbac", md,
                sa.Column("id", sa.String(36), primary_key=True),
                sa.Column("project_id", sa.String(36), nullable=False),
                sa.Column("object_type", sa.String(64), nullable=False),
                sa.Column("object_id", sa.String(36), nullable=False),
                sa.Column("target_project_id", sa.String(36), nullable=False),
                sa.Column("action", sa.String(64), nullable=False),
                sa.Column("created_at", sa.DateTime()),
                sa.Column("updated_at", sa.DateTime()),
            ),
            "port_statuses": sa.Table(
                "aria_acl_port_statuses", md,
                sa.Column("port_id", sa.String(36), primary_key=True),
                sa.Column("host", sa.String(255), primary_key=True),
                sa.Column("effective_policy_id", sa.String(36)),
                sa.Column("binding_id", sa.String(36)),
                sa.Column("status", sa.String(64), nullable=False),
                sa.Column("reason", sa.Text()),
                sa.Column("effective_action", sa.String(64)),
                sa.Column("generation", sa.BigInteger()),
                sa.Column("updated_at", sa.DateTime()),
                sa.Column("counters_sampled_at", sa.DateTime()),
                sa.Column("counters_policy_packets", sa.BigInteger()),
                sa.Column("counters_policy_bytes", sa.BigInteger()),
                sa.Column("counters_policy_allow_packets", sa.BigInteger()),
                sa.Column("counters_policy_dropped_packets", sa.BigInteger()),
                sa.Column("counters_policy_dropped_bytes", sa.BigInteger()),
                sa.Column("counters_policy_pps", sa.Float()),
                sa.Column("counters_drop_packets", sa.BigInteger()),
                sa.Column("counters_drop_bytes", sa.BigInteger()),
                sa.Column("counters_drop_pps", sa.Float()),
                sa.Column("counters_truncated", sa.Boolean()),
                sa.Column("counters_reset_detected", sa.Boolean()),
            ),
            "port_counters": sa.Table(
                "aria_acl_port_counters", md,
                sa.Column("id", sa.String(36), primary_key=True),
                sa.Column("port_id", sa.String(36), nullable=False),
                sa.Column("host", sa.String(255), nullable=False),
                sa.Column("kind", sa.String(16), nullable=False),
                sa.Column("src_id", sa.Integer()),
                sa.Column("dst_id", sa.Integer()),
                sa.Column("proto", sa.Integer()),
                sa.Column("direction", sa.String(16)),
                sa.Column("reason", sa.Integer()),
                sa.Column("packets", sa.BigInteger(), nullable=False),
                sa.Column("bytes", sa.BigInteger(), nullable=False),
                sa.Column("dropped_packets", sa.BigInteger()),
                sa.Column("dropped_bytes", sa.BigInteger()),
                sa.Column("pps", sa.Float()),
                sa.Column("bps", sa.Float()),
                sa.Column("sampled_at", sa.DateTime()),
            ),
        }

    def _insert(self, table_name, values):
        with self._write_transaction():
            self.session.execute(self.tables[table_name].insert().values(**values))

    def _update(self, table_name, object_id, values):
        table = self.tables[table_name]
        with self._write_transaction():
            result = self.session.execute(
                table.update().where(table.c.id == object_id).values(**values)
            )
        if result.rowcount == 0:
            raise AriaAclNotFound("%s %s not found" % (table.name, object_id))

    def _delete(self, table_name, object_id, object_type):
        table = self.tables[table_name]
        with self._write_transaction():
            result = self.session.execute(table.delete().where(table.c.id == object_id))
        if result.rowcount == 0:
            raise AriaAclNotFound("%s %s not found" % (object_type, object_id))

    def _list_query(
        self,
        table_name,
        filters=None,
        fields=None,
        sorts=None,
        limit=None,
        marker=None,
        page_reverse=False,
        projection=None,
    ):
        query = normalize_query(
            table_name, filters, fields, sorts, limit, marker, page_reverse
        )
        if not hasattr(self, "tables"):
            return apply_memory_query(self._list(table_name), query)
        table = self.tables[table_name]
        marker_row = self._query_marker_row(table_name, query)
        statement = build_select(
            self.sa,
            table,
            query,
            marker_row=marker_row,
            projection=projection,
        )
        rows = self.session.execute(statement).fetchall()
        if query.page_reverse:
            rows = list(reversed(rows))
        values = [
            self._row_to_dict(table_name, row, include_members=False)
            for row in rows
        ]
        if table_name == "port_statuses" and projection is not None:
            values = [projection.project(value) for value in values]
        if table_name == "address_sets" and (
            not query.fields or "members" in query.fields
        ):
            grouped = self._members_for_sets([value["id"] for value in values])
            for value in values:
                value["members"] = grouped[value["id"]]
        return [project_fields(value, query.fields) for value in values]

    def _query_marker_row(self, table_name, query):
        if query.marker is None:
            return None
        table = self.tables[table_name]
        if table_name == "port_statuses":
            port_id, host = decode_port_status_id(query.marker)
            clause = (
                (table.c.port_id == port_id) &
                (table.c.host == host)
            )
        else:
            clause = table.c.id == query.marker
        row = self.session.execute(table.select().where(clause)).fetchone()
        if not row:
            raise AriaAclNotFound(
                "%s marker %s not found" % (table_name, query.marker)
            )
        return _row_dict(row)

    def _get(self, table_name, object_id, object_type, fields=None):
        table = self.tables[table_name]
        row = self.session.execute(table.select().where(table.c.id == object_id)).fetchone()
        if not row:
            raise AriaAclNotFound("%s %s not found" % (object_type, object_id))
        include_members = table_name != "address_sets" or (
            not fields or "members" in fields
        )
        return project_fields(
            self._row_to_dict(
                table_name,
                row,
                include_members=include_members,
            ),
            fields,
        )

    def _replace_members(self, address_set_id, members):
        table = self.tables["address_set_members"]
        now = datetime.datetime.utcnow()
        with self._write_transaction():
            self.session.execute(table.delete().where(table.c.address_set_id == address_set_id))
            for member in members or []:
                address = member.get("address") if isinstance(member, dict) else member
                self.session.execute(table.insert().values(
                    id=_new_id(),
                    address_set_id=address_set_id,
                    address=address,
                    created_at=now,
                    updated_at=now,
                ))

    def _members_for_set(self, address_set_id):
        return self._members_for_sets((address_set_id,))[address_set_id]

    def _members_for_sets(self, address_set_ids):
        grouped = dict(
            (address_set_id, []) for address_set_id in address_set_ids
        )
        if not address_set_ids:
            return grouped
        table = self.tables["address_set_members"]
        rows = self.session.execute(
            table.select().where(
                table.c.address_set_id.in_(address_set_ids)
            ).order_by(
                table.c.address_set_id.asc(),
                table.c.address.asc(),
                table.c.id.asc(),
            )
        ).fetchall()
        for row in rows:
            value = _row_dict(row)
            grouped[value["address_set_id"]].append({"address": value["address"]})
        return grouped

    def _row_to_dict(self, table_name, row, include_members=True):
        value = _row_dict(row)
        for key in ("created_at", "updated_at"):
            if key in value:
                value[key] = _format_time(value[key])
        if table_name == "address_sets" and include_members:
            value["members"] = self._members_for_set(value["id"])
        return value

    def _db_values(self, table_name, values):
        table = self.tables[table_name]
        result = {}
        for column in table.c:
            if column.name in values:
                if column.name in ("created_at", "updated_at"):
                    result[column.name] = _parse_time(values[column.name])
                else:
                    result[column.name] = values[column.name]
        if table_name in ("rules", "bindings"):
            result["enabled_guard"] = 1 if _enabled(values) else None
        return result

    def _reject_policy_in_use(self, policy_id):
        for rule in self.list_rules():
            if rule.get("policy_id") == policy_id:
                raise AriaAclValidationError("aria_acl_policy is referenced by rule")
        for binding in self.list_bindings():
            if binding.get("policy_id") == policy_id:
                raise AriaAclValidationError("aria_acl_policy is referenced by binding")

    def _reject_address_set_in_use(self, address_set_id):
        for rule in self.list_rules():
            if (
                rule.get("src_address_set_id") == address_set_id or
                rule.get("dst_address_set_id") == address_set_id
            ):
                raise AriaAclValidationError("aria_acl_address_set is referenced by rule")

class SqliteAriaAclRepository(object):
    """Small persistent repository with the same aria_acl contract.

    This is a local, stdlib-backed DB contract test bed. Product Neutron server
    integration can replace it with SQLAlchemy models while preserving the
    public repository methods and payload shape.
    """

    TABLES = (
        ("aria_acl_policies", "id TEXT PRIMARY KEY, project_id TEXT NOT NULL, payload TEXT NOT NULL"),
        (
            "aria_acl_rules",
            "id TEXT PRIMARY KEY, project_id TEXT, policy_id TEXT NOT NULL, "
            "direction TEXT, priority INTEGER, enabled_guard INTEGER, "
            "payload TEXT NOT NULL",
        ),
        ("aria_acl_address_sets", "id TEXT PRIMARY KEY, project_id TEXT NOT NULL, payload TEXT NOT NULL"),
        (
            "aria_acl_bindings",
            "id TEXT PRIMARY KEY, project_id TEXT NOT NULL, policy_id TEXT NOT NULL, "
            "target_type TEXT NOT NULL, target_id TEXT NOT NULL, "
            "enabled_guard INTEGER, payload TEXT NOT NULL",
        ),
        (
            "aria_acl_port_statuses",
            "port_id TEXT NOT NULL, host TEXT NOT NULL, payload TEXT NOT NULL, "
            "PRIMARY KEY (port_id, host)",
        ),
    )

    def __init__(self, path):
        self.path = path
        self.connection = sqlite3.connect(path)
        self._bulk_write_active = False
        self.connection.create_function(
            "aria_json_scalar",
            2,
            _sqlite_json_scalar,
        )
        self._ensure_schema()

    def bulk_create(self, resource, values_list):
        creators = {
            "policy": self.create_policy,
            "rule": self.create_rule,
            "address_set": self.create_address_set,
            "binding": self.create_binding,
            "port_status": self.upsert_port_status,
        }
        creator = creators[resource]
        self.connection.execute("BEGIN IMMEDIATE")
        self._bulk_write_active = True
        try:
            result = [creator(values) for values in values_list]
            self.connection.commit()
            return result
        except Exception:
            self.connection.rollback()
            raise
        finally:
            self._bulk_write_active = False

    def close(self):
        self.connection.close()

    @_sqlite_write()
    def create_policy(self, values):
        values = _normalize_project_id(_clone(values))
        _require(values, ("project_id",), "aria_acl_policy")
        values.setdefault("id", _new_id())
        values.setdefault("name", "")
        values.setdefault("default_action", "allow")
        values.setdefault("stateful", True)
        values.setdefault("enabled", True)
        values.setdefault("revision_number", 1)
        values = prepare_policy(values)
        _stamp_create(values)
        self._upsert(
            "aria_acl_policies",
            values["id"],
            values,
            project_id=values["project_id"],
        )
        return _clone(values)

    def list_policies(
        self, filters=None, fields=None, sorts=None, limit=None,
        marker=None, page_reverse=False,
    ):
        return self._list_query(
            "policies", filters, fields, sorts, limit, marker, page_reverse
        )

    def get_policy(self, policy_id, fields=None):
        return self._get(
            "aria_acl_policies", policy_id, "aria_acl_policy", fields
        )

    @_sqlite_write()
    def update_policy(self, policy_id, values):
        existing = self.get_policy(policy_id)
        reject_immutable_changes(
            existing,
            values,
            POLICY_IMMUTABLE_FIELDS,
            "aria_acl_policy",
        )
        current = _clone(existing)
        current.update(_clone(values))
        _normalize_project_id(current)
        _require(current, ("project_id",), "aria_acl_policy")
        current = prepare_policy(current)
        current["revision_number"] = _next_revision(current)
        _stamp_update(current)
        self._upsert(
            "aria_acl_policies",
            policy_id,
            current,
            project_id=current["project_id"],
        )
        return _clone(current)

    @_sqlite_write()
    def delete_policy(self, policy_id):
        self._reject_policy_in_use(policy_id)
        self._delete(
            "aria_acl_policies",
            policy_id,
            "aria_acl_policy",
            commit=False,
        )

    @_sqlite_write("rule")
    def create_rule(self, values):
        values = _normalize_project_id(_clone(values))
        _require(values, ("policy_id", "direction", "priority", "action"), "aria_acl_rule")
        values.setdefault("id", _new_id())
        values.setdefault("enabled", True)
        values.setdefault("revision_number", 1)
        values = prepare_rule(self, values)
        _stamp_create(values)
        self._upsert(
            "aria_acl_rules",
            values["id"],
            values,
            project_id=values.get("project_id"),
            policy_id=values["policy_id"],
            direction=values["direction"],
            priority=int(values["priority"]),
            enabled_guard=1 if _enabled(values) else None,
        )
        return _clone(values)

    def list_rules(
        self, filters=None, fields=None, sorts=None, limit=None,
        marker=None, page_reverse=False,
    ):
        return self._list_query(
            "rules", filters, fields, sorts, limit, marker, page_reverse
        )

    def get_rule(self, rule_id, fields=None):
        return self._get("aria_acl_rules", rule_id, "aria_acl_rule", fields)

    @_sqlite_write("rule")
    def update_rule(self, rule_id, values):
        existing = self.get_rule(rule_id)
        reject_immutable_changes(
            existing,
            values,
            RULE_IMMUTABLE_FIELDS,
            "aria_acl_rule",
        )
        current = _clone(existing)
        current.update(_clone(values))
        _normalize_project_id(current)
        _require(current, ("policy_id", "direction", "priority", "action"), "aria_acl_rule")
        current = prepare_rule(self, current, existing=existing)
        current["revision_number"] = _next_revision(current)
        _stamp_update(current)
        self._upsert(
            "aria_acl_rules",
            rule_id,
            current,
            project_id=current.get("project_id"),
            policy_id=current["policy_id"],
            direction=current["direction"],
            priority=int(current["priority"]),
            enabled_guard=1 if _enabled(current) else None,
        )
        return _clone(current)

    def delete_rule(self, rule_id):
        self._delete("aria_acl_rules", rule_id, "aria_acl_rule")

    @_sqlite_write()
    def create_address_set(self, values):
        values = _normalize_project_id(_clone(values))
        _require(values, ("project_id",), "aria_acl_address_set")
        values.setdefault("id", _new_id())
        values.setdefault("name", "")
        values.setdefault("members", [])
        values.setdefault("enabled", True)
        values.setdefault("revision_number", 1)
        values = prepare_address_set(self, values)
        _stamp_create(values)
        self._upsert(
            "aria_acl_address_sets",
            values["id"],
            values,
            project_id=values["project_id"],
        )
        return _clone(values)

    def list_address_sets(
        self, filters=None, fields=None, sorts=None, limit=None,
        marker=None, page_reverse=False,
    ):
        return self._list_query(
            "address_sets", filters, fields, sorts, limit, marker, page_reverse
        )

    def get_address_set(self, address_set_id, fields=None):
        return self._get(
            "aria_acl_address_sets",
            address_set_id,
            "aria_acl_address_set",
            fields,
        )

    @_sqlite_write()
    def update_address_set(self, address_set_id, values):
        existing = self.get_address_set(address_set_id)
        reject_immutable_changes(
            existing,
            values,
            ADDRESS_SET_IMMUTABLE_FIELDS,
            "aria_acl_address_set",
        )
        current = _clone(existing)
        current.update(_clone(values))
        _normalize_project_id(current)
        _require(current, ("project_id",), "aria_acl_address_set")
        current = prepare_address_set(self, current, existing=existing)
        current["revision_number"] = _next_revision(current)
        _stamp_update(current)
        self._upsert(
            "aria_acl_address_sets",
            address_set_id,
            current,
            project_id=current["project_id"],
        )
        return _clone(current)

    @_sqlite_write()
    def delete_address_set(self, address_set_id):
        self._reject_address_set_in_use(address_set_id)
        self._delete(
            "aria_acl_address_sets",
            address_set_id,
            "aria_acl_address_set",
            commit=False,
        )

    @_sqlite_write("binding")
    def create_binding(self, values):
        values = _normalize_project_id(_clone(values))
        _require(
            values,
            ("project_id", "policy_id", "target_type", "target_id"),
            "aria_acl_binding",
        )
        values.setdefault("id", _new_id())
        values.setdefault("enabled", True)
        values.setdefault("revision_number", 1)
        values = prepare_binding(self, values)
        _stamp_create(values)
        self._upsert(
            "aria_acl_bindings",
            values["id"],
            values,
            project_id=values["project_id"],
            policy_id=values["policy_id"],
            target_type=values["target_type"],
            target_id=values["target_id"],
            enabled_guard=1 if _enabled(values) else None,
        )
        return _clone(values)

    def list_bindings(
        self, filters=None, fields=None, sorts=None, limit=None,
        marker=None, page_reverse=False,
    ):
        return self._list_query(
            "bindings", filters, fields, sorts, limit, marker, page_reverse
        )

    def get_binding(self, binding_id, fields=None):
        return self._get(
            "aria_acl_bindings", binding_id, "aria_acl_binding", fields
        )

    @_sqlite_write("binding")
    def update_binding(self, binding_id, values):
        existing = self.get_binding(binding_id)
        reject_immutable_changes(
            existing,
            values,
            BINDING_IMMUTABLE_FIELDS,
            "aria_acl_binding",
        )
        current = _clone(existing)
        current.update(_clone(values))
        _normalize_project_id(current)
        _require(
            current,
            ("project_id", "policy_id", "target_type", "target_id"),
            "aria_acl_binding",
        )
        current = prepare_binding(self, current, existing=existing)
        current["revision_number"] = _next_revision(current)
        _stamp_update(current)
        self._upsert(
            "aria_acl_bindings",
            binding_id,
            current,
            project_id=current["project_id"],
            policy_id=current["policy_id"],
            target_type=current["target_type"],
            target_id=current["target_id"],
            enabled_guard=1 if _enabled(current) else None,
        )
        return _clone(current)

    def delete_binding(self, binding_id):
        self._delete("aria_acl_bindings", binding_id, "aria_acl_binding")

    def upsert_port_status(self, values):
        values = _clone(values)
        _require(values, ("port_id", "host"), "aria_acl_port_status")
        _stamp_status(values)
        payload = json.dumps(values, sort_keys=True)
        self.connection.execute(
            "INSERT OR REPLACE INTO aria_acl_port_statuses "
            "(port_id, host, payload) VALUES (?, ?, ?)",
            (values["port_id"], values["host"], payload),
        )
        self.connection.commit()
        return _clone(values)

    def get_port_status(self, port_id, host=None):
        if host is not None:
            cursor = self.connection.execute(
                "SELECT payload FROM aria_acl_port_statuses WHERE port_id=? AND host=?",
                (port_id, host),
            )
            row = cursor.fetchone()
            return json.loads(row[0]) if row else None
        cursor = self.connection.execute(
            "SELECT payload FROM aria_acl_port_statuses WHERE port_id=?",
            (port_id,),
        )
        return [json.loads(row[0]) for row in cursor.fetchall()]

    def list_port_statuses(
        self, filters=None, fields=None, sorts=None, limit=None,
        marker=None, page_reverse=False, projection=None,
    ):
        return self._list_query(
            "port_statuses",
            filters,
            fields,
            sorts,
            limit,
            marker,
            page_reverse,
            projection=projection,
        )

    def delete_port_status(self, port_id, host=None):
        if host is not None:
            cursor = self.connection.execute(
                "DELETE FROM aria_acl_port_statuses WHERE port_id=? AND host=?",
                (port_id, host),
            )
        else:
            cursor = self.connection.execute(
                "DELETE FROM aria_acl_port_statuses WHERE port_id=?",
                (port_id,),
            )
        self.connection.commit()
        if cursor.rowcount == 0:
            if host is not None:
                raise AriaAclNotFound(
                    "aria_acl_port_status %s/%s not found" % (port_id, host)
                )
            raise AriaAclNotFound("aria_acl_port_status %s not found" % port_id)

    def get_port_status_resource(self, resource_id):
        if is_port_status_id(resource_id):
            port_id, host = decode_port_status_id(resource_id)
            value = self.get_port_status(port_id, host=host)
            if value is None:
                raise AriaAclNotFound(
                    "aria_acl_port_status %s/%s not found" % (port_id, host)
                )
            return value
        return require_one_legacy_port_status(
            resource_id,
            self.get_port_status(resource_id),
        )

    def delete_port_status_resource(self, resource_id):
        if is_port_status_id(resource_id):
            port_id, host = decode_port_status_id(resource_id)
            return self.delete_port_status(port_id, host=host)
        return self.delete_port_status(resource_id, host=None)

    def to_effective_payload(self):
        return {
            "policies": self.list_policies(),
            "rules": self.list_rules(),
            "address_sets": self.list_address_sets(),
            "bindings": self.list_bindings(),
        }

    def _ensure_schema(self):
        for table, columns in self.TABLES:
            self.connection.execute("CREATE TABLE IF NOT EXISTS %s (%s)" % (table, columns))
        self._ensure_columns(
            "aria_acl_rules",
            (
                ("direction", "TEXT"),
                ("priority", "INTEGER"),
                ("enabled_guard", "INTEGER"),
            ),
        )
        self._ensure_columns(
            "aria_acl_bindings",
            (("enabled_guard", "INTEGER"),),
        )
        self._backfill_sqlite_guards()
        conflicts = self._sqlite_historical_conflicts()
        if conflicts:
            self.connection.rollback()
            raise AriaAclValidationError(
                "aria_acl_schema_conflicts: %s" % "; ".join(conflicts)
            )
        self.connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS "
            "uq_aria_acl_rules_enabled_priority ON aria_acl_rules "
            "(policy_id, direction, priority, enabled_guard)"
        )
        self.connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS "
            "uq_aria_acl_bindings_enabled_target ON aria_acl_bindings "
            "(target_type, target_id, enabled_guard)"
        )
        self.connection.commit()

    def _upsert(self, table, object_id, values, **columns):
        payload = json.dumps(values, sort_keys=True)
        exists = self.connection.execute(
            "SELECT 1 FROM %s WHERE id=?" % table,
            (object_id,),
        ).fetchone() is not None
        if table == "aria_acl_bindings":
            ordered = (
                columns.get("project_id"),
                columns.get("policy_id"),
                columns.get("target_type"),
                columns.get("target_id"),
                columns.get("enabled_guard"),
                payload,
            )
            if exists:
                self.connection.execute(
                    "UPDATE aria_acl_bindings SET project_id=?, policy_id=?, "
                    "target_type=?, target_id=?, enabled_guard=?, payload=? "
                    "WHERE id=?",
                    ordered + (object_id,),
                )
            else:
                self.connection.execute(
                    "INSERT INTO aria_acl_bindings "
                    "(project_id, policy_id, target_type, target_id, "
                    "enabled_guard, payload, id) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    ordered + (object_id,),
                )
        elif table == "aria_acl_rules":
            ordered = (
                columns.get("project_id"),
                columns.get("policy_id"),
                columns.get("direction"),
                columns.get("priority"),
                columns.get("enabled_guard"),
                payload,
            )
            if exists:
                self.connection.execute(
                    "UPDATE aria_acl_rules SET project_id=?, policy_id=?, "
                    "direction=?, priority=?, enabled_guard=?, payload=? "
                    "WHERE id=?",
                    ordered + (object_id,),
                )
            else:
                self.connection.execute(
                    "INSERT INTO aria_acl_rules "
                    "(project_id, policy_id, direction, priority, "
                    "enabled_guard, payload, id) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    ordered + (object_id,),
                )
        else:
            ordered = (columns.get("project_id"), payload)
            if exists:
                self.connection.execute(
                    "UPDATE %s SET project_id=?, payload=? WHERE id=?" % table,
                    ordered + (object_id,),
                )
            else:
                self.connection.execute(
                    "INSERT INTO %s (project_id, payload, id) VALUES (?, ?, ?)" % table,
                    ordered + (object_id,),
                )

    def _ensure_columns(self, table, columns):
        existing = set(
            row[1]
            for row in self.connection.execute(
                "PRAGMA table_info(%s)" % table
            ).fetchall()
        )
        for name, column_type in columns:
            if name not in existing:
                self.connection.execute(
                    "ALTER TABLE %s ADD COLUMN %s %s"
                    % (table, name, column_type)
                )

    def _backfill_sqlite_guards(self):
        for row in self.connection.execute(
            "SELECT id, payload FROM aria_acl_rules"
        ).fetchall():
            values = json.loads(row[1])
            self.connection.execute(
                "UPDATE aria_acl_rules SET project_id=?, policy_id=?, "
                "direction=?, priority=?, enabled_guard=? WHERE id=?",
                (
                    values.get("project_id") or values.get("tenant_id"),
                    values.get("policy_id"),
                    values.get("direction"),
                    values.get("priority"),
                    1 if _enabled(values) else None,
                    row[0],
                ),
            )
        for row in self.connection.execute(
            "SELECT id, payload FROM aria_acl_bindings"
        ).fetchall():
            values = json.loads(row[1])
            self.connection.execute(
                "UPDATE aria_acl_bindings SET project_id=?, policy_id=?, "
                "target_type=?, target_id=?, enabled_guard=? WHERE id=?",
                (
                    values.get("project_id") or values.get("tenant_id"),
                    values.get("policy_id"),
                    values.get("target_type"),
                    values.get("target_id"),
                    1 if _enabled(values) else None,
                    row[0],
                ),
            )

    def _sqlite_historical_conflicts(self):
        conflicts = []
        rule_rows = self.connection.execute(
            "SELECT policy_id, direction, priority, GROUP_CONCAT(id) "
            "FROM aria_acl_rules WHERE enabled_guard=1 "
            "GROUP BY policy_id, direction, priority HAVING COUNT(*) > 1"
        ).fetchall()
        for policy_id, direction, priority, object_ids in rule_rows:
            conflicts.append(
                "rule policy=%s direction=%s priority=%s ids=%s" % (
                    policy_id,
                    direction,
                    priority,
                    ",".join(sorted((object_ids or "").split(","))),
                )
            )
        binding_rows = self.connection.execute(
            "SELECT target_type, target_id, GROUP_CONCAT(id) "
            "FROM aria_acl_bindings WHERE enabled_guard=1 "
            "GROUP BY target_type, target_id HAVING COUNT(*) > 1"
        ).fetchall()
        for target_type, target_id, object_ids in binding_rows:
            conflicts.append(
                "binding target_type=%s target_id=%s ids=%s" % (
                    target_type,
                    target_id,
                    ",".join(sorted((object_ids or "").split(","))),
                )
            )
        return sorted(conflicts)

    def _raise_known_constraint(self, exc, constraint_kind):
        text = str(exc)
        signatures = {
            "rule": (
                "aria_acl_rules.policy_id",
                "aria_acl_rules.direction",
                "aria_acl_rules.priority",
                "aria_acl_rules.enabled_guard",
            ),
            "binding": (
                "aria_acl_bindings.target_type",
                "aria_acl_bindings.target_id",
                "aria_acl_bindings.enabled_guard",
            ),
        }
        if not all(fragment in text for fragment in signatures[constraint_kind]):
            return
        reason = {
            "rule": "duplicate_enabled_rule_priority",
            "binding": "duplicate_enabled_binding_target",
        }[constraint_kind]
        raise AriaAclConflictError("%s: %s" % (reason, exc))

    def _list_query(
        self,
        resource,
        filters=None,
        fields=None,
        sorts=None,
        limit=None,
        marker=None,
        page_reverse=False,
        projection=None,
    ):
        query = normalize_query(
            resource, filters, fields, sorts, limit, marker, page_reverse
        )
        table = {
            "policies": "aria_acl_policies",
            "rules": "aria_acl_rules",
            "address_sets": "aria_acl_address_sets",
            "bindings": "aria_acl_bindings",
            "port_statuses": "aria_acl_port_statuses",
        }[resource]
        marker_row = self._sqlite_marker_row(table, resource, query)
        sql, parameters = build_sqlite_select(
            table,
            query,
            marker_row=marker_row,
            projection=projection,
        )
        rows = self.connection.execute(sql, parameters).fetchall()
        if query.page_reverse:
            rows = list(reversed(rows))
        values = [json.loads(row[0]) for row in rows]
        if resource == "port_statuses" and projection is not None:
            values = [projection.project(value) for value in values]
        return [project_fields(value, query.fields) for value in values]

    def _sqlite_marker_row(self, table, resource, query):
        if query.marker is None:
            return None
        if resource == "port_statuses":
            port_id, host = decode_port_status_id(query.marker)
            row = self.connection.execute(
                "SELECT payload FROM aria_acl_port_statuses "
                "WHERE port_id=? AND host=?",
                (port_id, host),
            ).fetchone()
        else:
            row = self.connection.execute(
                "SELECT payload FROM %s WHERE id=?" % table,
                (query.marker,),
            ).fetchone()
        if not row:
            raise AriaAclNotFound(
                "%s marker %s not found" % (resource, query.marker)
            )
        return json.loads(row[0])

    def _get(self, table, object_id, object_type, fields=None):
        cursor = self.connection.execute(
            "SELECT payload FROM %s WHERE id=?" % table,
            (object_id,),
        )
        row = cursor.fetchone()
        if not row:
            raise AriaAclNotFound("%s %s not found" % (object_type, object_id))
        return project_fields(json.loads(row[0]), fields)

    def _delete(self, table, object_id, object_type, commit=True):
        cursor = self.connection.execute("DELETE FROM %s WHERE id=?" % table, (object_id,))
        if commit:
            self.connection.commit()
        if cursor.rowcount == 0:
            raise AriaAclNotFound("%s %s not found" % (object_type, object_id))

    def _reject_policy_in_use(self, policy_id):
        for rule in self.list_rules():
            if rule.get("policy_id") == policy_id:
                raise AriaAclValidationError("aria_acl_policy is referenced by rule")
        for binding in self.list_bindings():
            if binding.get("policy_id") == policy_id:
                raise AriaAclValidationError("aria_acl_policy is referenced by binding")

    def _reject_address_set_in_use(self, address_set_id):
        for rule in self.list_rules():
            if (
                rule.get("src_address_set_id") == address_set_id or
                rule.get("dst_address_set_id") == address_set_id
            ):
                raise AriaAclValidationError("aria_acl_address_set is referenced by rule")

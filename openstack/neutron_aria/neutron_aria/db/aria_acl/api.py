from __future__ import absolute_import

import copy
import datetime
import json
import sqlite3
import uuid

from neutron_aria.acl_contract import AclContractError
from neutron_aria.acl_contract import validate_policy
from neutron_aria.acl_contract import validate_rule


try:
    STRING_TYPES = (basestring,)
except NameError:
    STRING_TYPES = (str,)


class AriaAclError(Exception):
    pass


class AriaAclNotFound(AriaAclError):
    pass


class AriaAclValidationError(AriaAclError):
    pass


def _clone(value):
    return copy.deepcopy(value)


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


def _validate_contract(validator, values):
    try:
        validator(values)
    except AclContractError as exc:
        raise AriaAclValidationError(str(exc))


def _enabled(obj):
    value = (obj or {}).get("enabled", True)
    if isinstance(value, STRING_TYPES):
        return value.strip().lower() not in ("0", "false", "no", "off")
    return value is not False


def _reject_duplicate_rule_priority(repository, values, exclude_id=None):
    if not _enabled(values):
        return
    policy_id = values.get("policy_id")
    direction = values.get("direction")
    priority = int(values.get("priority"))
    for rule in repository.list_rules(filters={"policy_id": [policy_id]}):
        if rule.get("id") == exclude_id or not _enabled(rule):
            continue
        if rule.get("direction") == direction and int(rule.get("priority")) == priority:
            raise AriaAclValidationError(
                "duplicate enabled rule priority for policy=%s direction=%s priority=%s"
                % (policy_id, direction, priority)
            )


def _reject_duplicate_binding_target(repository, values, exclude_id=None):
    if not _enabled(values):
        return
    target_type = values.get("target_type")
    target_id = values.get("target_id")
    filters = {"target_type": [target_type], "target_id": [target_id]}
    for binding in repository.list_bindings(filters=filters):
        if binding.get("id") == exclude_id or not _enabled(binding):
            continue
        raise AriaAclValidationError(
            "duplicate enabled binding for target_type=%s target_id=%s"
            % (target_type, target_id)
        )


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


class InMemoryAriaAclRepository(object):
    """Minimal aria_acl repository contract.

    This repository intentionally stays stdlib-only so the agent package can be
    tested before the product neutron-server DB wiring is available. The method
    names and payload shapes are the contract consumed by NeutronAclSource.
    """

    def __init__(self):
        self.policies = {}
        self.rules = {}
        self.address_sets = {}
        self.bindings = {}
        self.port_statuses = {}

    def create_policy(self, values):
        values = _normalize_project_id(_clone(values))
        _require(values, ("project_id",), "aria_acl_policy")
        values.setdefault("id", _new_id())
        values.setdefault("name", "")
        values.setdefault("default_action", "allow")
        values.setdefault("stateful", True)
        values.setdefault("enabled", True)
        values.setdefault("revision_number", 1)
        _validate_contract(validate_policy, values)
        _stamp_create(values)
        self.policies[values["id"]] = values
        return _clone(values)

    def list_policies(self, filters=None):
        return self._list(self.policies, filters)

    def get_policy(self, policy_id):
        return self._get(self.policies, policy_id, "aria_acl_policy")

    def update_policy(self, policy_id, values):
        current = self._get(self.policies, policy_id, "aria_acl_policy")
        current.update(_clone(values))
        current["id"] = policy_id
        _normalize_project_id(current)
        _require(current, ("project_id",), "aria_acl_policy")
        _validate_contract(validate_policy, current)
        current["revision_number"] = _next_revision(current)
        _stamp_update(current)
        self.policies[policy_id] = current
        return _clone(current)

    def delete_policy(self, policy_id):
        self._reject_policy_in_use(policy_id)
        self._delete(self.policies, policy_id, "aria_acl_policy")

    def create_rule(self, values):
        values = _normalize_project_id(_clone(values))
        _require(values, ("policy_id", "direction", "priority", "action"), "aria_acl_rule")
        if values["policy_id"] not in self.policies:
            raise AriaAclValidationError("aria_acl_rule references missing policy")
        self._validate_policy_project(values)
        values.setdefault("id", _new_id())
        values.setdefault("enabled", True)
        values.setdefault("revision_number", 1)
        _validate_contract(validate_rule, values)
        _reject_duplicate_rule_priority(self, values)
        _stamp_create(values)
        self.rules[values["id"]] = values
        return _clone(values)

    def list_rules(self, filters=None):
        return self._list(self.rules, filters)

    def get_rule(self, rule_id):
        return self._get(self.rules, rule_id, "aria_acl_rule")

    def update_rule(self, rule_id, values):
        current = self._get(self.rules, rule_id, "aria_acl_rule")
        current.update(_clone(values))
        current["id"] = rule_id
        current["policy_id"] = self.rules[rule_id]["policy_id"]
        _normalize_project_id(current)
        _require(current, ("policy_id", "direction", "priority", "action"), "aria_acl_rule")
        self._validate_policy_project(current)
        _validate_contract(validate_rule, current)
        _reject_duplicate_rule_priority(self, current, exclude_id=rule_id)
        current["revision_number"] = _next_revision(current)
        _stamp_update(current)
        self.rules[rule_id] = current
        return _clone(current)

    def delete_rule(self, rule_id):
        self._delete(self.rules, rule_id, "aria_acl_rule")

    def create_address_set(self, values):
        values = _normalize_project_id(_clone(values))
        _require(values, ("project_id",), "aria_acl_address_set")
        values.setdefault("id", _new_id())
        values.setdefault("name", "")
        values.setdefault("members", [])
        values.setdefault("enabled", True)
        values.setdefault("revision_number", 1)
        _stamp_create(values)
        self.address_sets[values["id"]] = values
        return _clone(values)

    def list_address_sets(self, filters=None):
        return self._list(self.address_sets, filters)

    def get_address_set(self, address_set_id):
        return self._get(self.address_sets, address_set_id, "aria_acl_address_set")

    def update_address_set(self, address_set_id, values):
        current = self._get(self.address_sets, address_set_id, "aria_acl_address_set")
        current.update(_clone(values))
        current["id"] = address_set_id
        _normalize_project_id(current)
        _require(current, ("project_id",), "aria_acl_address_set")
        current["revision_number"] = _next_revision(current)
        _stamp_update(current)
        self.address_sets[address_set_id] = current
        return _clone(current)

    def delete_address_set(self, address_set_id):
        self._reject_address_set_in_use(address_set_id)
        self._delete(self.address_sets, address_set_id, "aria_acl_address_set")

    def create_binding(self, values):
        values = _normalize_project_id(_clone(values))
        _require(
            values,
            ("project_id", "policy_id", "target_type", "target_id"),
            "aria_acl_binding",
        )
        if values["policy_id"] not in self.policies:
            raise AriaAclValidationError("aria_acl_binding references missing policy")
        self._validate_policy_project(values)
        if values["target_type"] not in ("port", "network"):
            raise AriaAclValidationError("aria_acl_binding target_type must be port or network")
        values.setdefault("id", _new_id())
        values.setdefault("enabled", True)
        values.setdefault("revision_number", 1)
        _reject_duplicate_binding_target(self, values)
        _stamp_create(values)
        self.bindings[values["id"]] = values
        return _clone(values)

    def list_bindings(self, filters=None):
        return self._list(self.bindings, filters)

    def get_binding(self, binding_id):
        return self._get(self.bindings, binding_id, "aria_acl_binding")

    def update_binding(self, binding_id, values):
        current = self._get(self.bindings, binding_id, "aria_acl_binding")
        current.update(_clone(values))
        current["id"] = binding_id
        current["policy_id"] = self.bindings[binding_id]["policy_id"]
        current["target_type"] = self.bindings[binding_id]["target_type"]
        current["target_id"] = self.bindings[binding_id]["target_id"]
        _normalize_project_id(current)
        _require(
            current,
            ("project_id", "policy_id", "target_type", "target_id"),
            "aria_acl_binding",
        )
        self._validate_policy_project(current)
        _reject_duplicate_binding_target(self, current, exclude_id=binding_id)
        current["revision_number"] = _next_revision(current)
        _stamp_update(current)
        self.bindings[binding_id] = current
        return _clone(current)

    def delete_binding(self, binding_id):
        self._delete(self.bindings, binding_id, "aria_acl_binding")

    def upsert_port_status(self, values):
        values = _clone(values)
        _require(values, ("port_id", "host"), "aria_acl_port_status")
        _stamp_status(values)
        key = (values["port_id"], values["host"])
        self.port_statuses[key] = values
        return _clone(values)

    def get_port_status(self, port_id, host=None):
        if host is not None:
            return _clone(self.port_statuses.get((port_id, host)))
        statuses = [
            status for (status_port_id, _host), status in self.port_statuses.items()
            if status_port_id == port_id
        ]
        return _clone(statuses)

    def list_port_statuses(self, filters=None):
        return self._list(self.port_statuses, filters)

    def delete_port_status(self, port_id, host=None):
        if host is not None:
            key = (port_id, host)
            if key not in self.port_statuses:
                raise AriaAclNotFound("aria_acl_port_status %s/%s not found" % (port_id, host))
            del self.port_statuses[key]
            return
        keys = [
            key for key in self.port_statuses
            if key[0] == port_id
        ]
        if not keys:
            raise AriaAclNotFound("aria_acl_port_status %s not found" % port_id)
        for key in keys:
            del self.port_statuses[key]

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

    def _validate_policy_project(self, values):
        project_id = values.get("project_id")
        if not project_id:
            return
        policy = self.policies.get(values.get("policy_id"))
        if policy and policy.get("project_id") and policy.get("project_id") != project_id:
            raise AriaAclValidationError("aria_acl object project_id does not match policy")


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

    def create_policy(self, values):
        values = _normalize_project_id(_clone(values))
        _require(values, ("project_id",), "aria_acl_policy")
        values.setdefault("id", _new_id())
        values.setdefault("name", "")
        values.setdefault("default_action", "allow")
        values.setdefault("stateful", True)
        values.setdefault("enabled", True)
        values.setdefault("revision_number", 1)
        _validate_contract(validate_policy, values)
        _stamp_create(values)
        self._insert("policies", self._db_values("policies", values))
        return _clone(values)

    def list_policies(self, filters=None):
        return self._list("policies", filters=filters)

    def get_policy(self, policy_id):
        return self._get("policies", policy_id, "aria_acl_policy")

    def update_policy(self, policy_id, values):
        current = self.get_policy(policy_id)
        current.update(_clone(values))
        current["id"] = policy_id
        _normalize_project_id(current)
        _require(current, ("project_id",), "aria_acl_policy")
        _validate_contract(validate_policy, current)
        current["revision_number"] = _next_revision(current)
        _stamp_update(current)
        self._update("policies", policy_id, self._db_values("policies", current))
        return _clone(current)

    def delete_policy(self, policy_id):
        self._reject_policy_in_use(policy_id)
        self._delete("policies", policy_id, "aria_acl_policy")

    def create_rule(self, values):
        values = _normalize_project_id(_clone(values))
        _require(values, ("policy_id", "direction", "priority", "action"), "aria_acl_rule")
        self._validate_policy_project(values)
        values.setdefault("id", _new_id())
        values.setdefault("enabled", True)
        values.setdefault("revision_number", 1)
        _validate_contract(validate_rule, values)
        _reject_duplicate_rule_priority(self, values)
        _stamp_create(values)
        self._insert("rules", self._db_values("rules", values))
        return _clone(values)

    def list_rules(self, filters=None):
        return self._list("rules", filters=filters)

    def get_rule(self, rule_id):
        return self._get("rules", rule_id, "aria_acl_rule")

    def update_rule(self, rule_id, values):
        existing = self.get_rule(rule_id)
        current = _clone(existing)
        current.update(_clone(values))
        current["id"] = rule_id
        current["policy_id"] = existing["policy_id"]
        _normalize_project_id(current)
        _require(current, ("policy_id", "direction", "priority", "action"), "aria_acl_rule")
        self._validate_policy_project(current)
        _validate_contract(validate_rule, current)
        _reject_duplicate_rule_priority(self, current, exclude_id=rule_id)
        current["revision_number"] = _next_revision(current)
        _stamp_update(current)
        self._update("rules", rule_id, self._db_values("rules", current))
        return _clone(current)

    def delete_rule(self, rule_id):
        self._delete("rules", rule_id, "aria_acl_rule")

    def create_address_set(self, values):
        values = _normalize_project_id(_clone(values))
        _require(values, ("project_id",), "aria_acl_address_set")
        values.setdefault("id", _new_id())
        values.setdefault("name", "")
        values.setdefault("members", [])
        values.setdefault("enabled", True)
        values.setdefault("revision_number", 1)
        _stamp_create(values)
        self._insert("address_sets", self._db_values("address_sets", values))
        self._replace_members(values["id"], values.get("members", []))
        return _clone(values)

    def list_address_sets(self, filters=None):
        return self._list("address_sets", filters=filters)

    def get_address_set(self, address_set_id):
        return self._get("address_sets", address_set_id, "aria_acl_address_set")

    def update_address_set(self, address_set_id, values):
        current = self.get_address_set(address_set_id)
        current.update(_clone(values))
        current["id"] = address_set_id
        _normalize_project_id(current)
        _require(current, ("project_id",), "aria_acl_address_set")
        current["revision_number"] = _next_revision(current)
        _stamp_update(current)
        self._update("address_sets", address_set_id, self._db_values("address_sets", current))
        if "members" in current:
            self._replace_members(address_set_id, current.get("members", []))
        return _clone(current)

    def delete_address_set(self, address_set_id):
        self._reject_address_set_in_use(address_set_id)
        with self.session.begin(subtransactions=True):
            self.session.execute(
                self.tables["address_set_members"].delete().where(
                    self.tables["address_set_members"].c.address_set_id == address_set_id
                )
            )
        self._delete("address_sets", address_set_id, "aria_acl_address_set")

    def create_binding(self, values):
        values = _normalize_project_id(_clone(values))
        _require(
            values,
            ("project_id", "policy_id", "target_type", "target_id"),
            "aria_acl_binding",
        )
        self._validate_policy_project(values)
        if values["target_type"] not in ("port", "network"):
            raise AriaAclValidationError("aria_acl_binding target_type must be port or network")
        values.setdefault("id", _new_id())
        values.setdefault("enabled", True)
        values.setdefault("revision_number", 1)
        _reject_duplicate_binding_target(self, values)
        _stamp_create(values)
        self._insert("bindings", self._db_values("bindings", values))
        return _clone(values)

    def list_bindings(self, filters=None):
        return self._list("bindings", filters=filters)

    def get_binding(self, binding_id):
        return self._get("bindings", binding_id, "aria_acl_binding")

    def update_binding(self, binding_id, values):
        existing = self.get_binding(binding_id)
        current = _clone(existing)
        current.update(_clone(values))
        current["id"] = binding_id
        current["policy_id"] = existing["policy_id"]
        current["target_type"] = existing["target_type"]
        current["target_id"] = existing["target_id"]
        _normalize_project_id(current)
        _require(
            current,
            ("project_id", "policy_id", "target_type", "target_id"),
            "aria_acl_binding",
        )
        self._validate_policy_project(current)
        _reject_duplicate_binding_target(self, current, exclude_id=binding_id)
        current["revision_number"] = _next_revision(current)
        _stamp_update(current)
        self._update("bindings", binding_id, self._db_values("bindings", current))
        return _clone(current)

    def delete_binding(self, binding_id):
        self._delete("bindings", binding_id, "aria_acl_binding")

    def upsert_port_status(self, values):
        values = _clone(values)
        _require(values, ("port_id", "host"), "aria_acl_port_status")
        _stamp_status(values)
        table = self.tables["port_statuses"]
        existing = self.get_port_status(values["port_id"], host=values["host"])
        db_values = self._db_values("port_statuses", values)
        with self.session.begin(subtransactions=True):
            if existing:
                self.session.execute(
                    table.update().where(
                        (table.c.port_id == values["port_id"]) &
                        (table.c.host == values["host"])
                    ).values(**db_values)
                )
            else:
                self.session.execute(table.insert().values(**db_values))
        return _clone(values)

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

    def list_port_statuses(self, filters=None):
        return self._list("port_statuses", filters=filters)

    def delete_port_status(self, port_id, host=None):
        table = self.tables["port_statuses"]
        clause = table.c.port_id == port_id
        if host is not None:
            clause = clause & (table.c.host == host)
        with self.session.begin(subtransactions=True):
            result = self.session.execute(table.delete().where(clause))
        if result.rowcount == 0:
            if host is not None:
                raise AriaAclNotFound(
                    "aria_acl_port_status %s/%s not found" % (port_id, host)
                )
            raise AriaAclNotFound("aria_acl_port_status %s not found" % port_id)

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
                sa.Column("revision_number", sa.Integer(), nullable=False),
                sa.Column("created_at", sa.DateTime()),
                sa.Column("updated_at", sa.DateTime()),
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
                sa.Column("revision_number", sa.Integer(), nullable=False),
                sa.Column("created_at", sa.DateTime()),
                sa.Column("updated_at", sa.DateTime()),
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
            ),
        }

    def _insert(self, table_name, values):
        with self.session.begin(subtransactions=True):
            self.session.execute(self.tables[table_name].insert().values(**values))

    def _update(self, table_name, object_id, values):
        table = self.tables[table_name]
        with self.session.begin(subtransactions=True):
            result = self.session.execute(
                table.update().where(table.c.id == object_id).values(**values)
            )
        if result.rowcount == 0:
            raise AriaAclNotFound("%s %s not found" % (table.name, object_id))

    def _delete(self, table_name, object_id, object_type):
        table = self.tables[table_name]
        with self.session.begin(subtransactions=True):
            result = self.session.execute(table.delete().where(table.c.id == object_id))
        if result.rowcount == 0:
            raise AriaAclNotFound("%s %s not found" % (object_type, object_id))

    def _list(self, table_name, filters=None):
        rows = self.session.execute(self.tables[table_name].select()).fetchall()
        values = [self._row_to_dict(table_name, row) for row in rows]
        return [value for value in values if _matches_filters(value, filters or {})]

    def _get(self, table_name, object_id, object_type):
        table = self.tables[table_name]
        row = self.session.execute(table.select().where(table.c.id == object_id)).fetchone()
        if not row:
            raise AriaAclNotFound("%s %s not found" % (object_type, object_id))
        return self._row_to_dict(table_name, row)

    def _replace_members(self, address_set_id, members):
        table = self.tables["address_set_members"]
        now = datetime.datetime.utcnow()
        with self.session.begin(subtransactions=True):
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
        table = self.tables["address_set_members"]
        rows = self.session.execute(
            table.select().where(table.c.address_set_id == address_set_id)
        ).fetchall()
        return [{"address": row["address"]} for row in rows]

    def _row_to_dict(self, table_name, row):
        value = dict(row)
        for key in ("created_at", "updated_at"):
            if key in value:
                value[key] = _format_time(value[key])
        if table_name == "address_sets":
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

    def _validate_policy_project(self, values):
        try:
            policy = self.get_policy(values.get("policy_id"))
        except AriaAclNotFound:
            raise AriaAclValidationError("aria_acl object references missing policy")
        project_id = values.get("project_id")
        if project_id and policy.get("project_id") and policy.get("project_id") != project_id:
            raise AriaAclValidationError("aria_acl object project_id does not match policy")


class SqliteAriaAclRepository(object):
    """Small persistent repository with the same aria_acl contract.

    This is a local, stdlib-backed DB contract test bed. Product Neutron server
    integration can replace it with SQLAlchemy models while preserving the
    public repository methods and payload shape.
    """

    TABLES = (
        ("aria_acl_policies", "id TEXT PRIMARY KEY, project_id TEXT NOT NULL, payload TEXT NOT NULL"),
        ("aria_acl_rules", "id TEXT PRIMARY KEY, project_id TEXT, policy_id TEXT NOT NULL, payload TEXT NOT NULL"),
        ("aria_acl_address_sets", "id TEXT PRIMARY KEY, project_id TEXT NOT NULL, payload TEXT NOT NULL"),
        (
            "aria_acl_bindings",
            "id TEXT PRIMARY KEY, project_id TEXT NOT NULL, policy_id TEXT NOT NULL, "
            "target_type TEXT NOT NULL, target_id TEXT NOT NULL, payload TEXT NOT NULL",
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
        self._ensure_schema()

    def close(self):
        self.connection.close()

    def create_policy(self, values):
        values = _normalize_project_id(_clone(values))
        _require(values, ("project_id",), "aria_acl_policy")
        values.setdefault("id", _new_id())
        values.setdefault("name", "")
        values.setdefault("default_action", "allow")
        values.setdefault("stateful", True)
        values.setdefault("enabled", True)
        values.setdefault("revision_number", 1)
        _validate_contract(validate_policy, values)
        _stamp_create(values)
        self._upsert(
            "aria_acl_policies",
            values["id"],
            values,
            project_id=values["project_id"],
        )
        return _clone(values)

    def list_policies(self, filters=None):
        return self._list("aria_acl_policies", filters=filters)

    def get_policy(self, policy_id):
        return self._get("aria_acl_policies", policy_id, "aria_acl_policy")

    def update_policy(self, policy_id, values):
        current = self.get_policy(policy_id)
        current.update(_clone(values))
        current["id"] = policy_id
        _normalize_project_id(current)
        _require(current, ("project_id",), "aria_acl_policy")
        _validate_contract(validate_policy, current)
        current["revision_number"] = _next_revision(current)
        _stamp_update(current)
        self._upsert(
            "aria_acl_policies",
            policy_id,
            current,
            project_id=current["project_id"],
        )
        return _clone(current)

    def delete_policy(self, policy_id):
        self._reject_policy_in_use(policy_id)
        self._delete("aria_acl_policies", policy_id, "aria_acl_policy")

    def create_rule(self, values):
        values = _normalize_project_id(_clone(values))
        _require(values, ("policy_id", "direction", "priority", "action"), "aria_acl_rule")
        self._validate_policy_project(values)
        values.setdefault("id", _new_id())
        values.setdefault("enabled", True)
        values.setdefault("revision_number", 1)
        _validate_contract(validate_rule, values)
        _reject_duplicate_rule_priority(self, values)
        _stamp_create(values)
        self._upsert(
            "aria_acl_rules",
            values["id"],
            values,
            project_id=values.get("project_id"),
            policy_id=values["policy_id"],
        )
        return _clone(values)

    def list_rules(self, filters=None):
        return self._list("aria_acl_rules", filters=filters)

    def get_rule(self, rule_id):
        return self._get("aria_acl_rules", rule_id, "aria_acl_rule")

    def update_rule(self, rule_id, values):
        current = self.get_rule(rule_id)
        current.update(_clone(values))
        current["id"] = rule_id
        current["policy_id"] = self.get_rule(rule_id)["policy_id"]
        _normalize_project_id(current)
        _require(current, ("policy_id", "direction", "priority", "action"), "aria_acl_rule")
        self._validate_policy_project(current)
        _validate_contract(validate_rule, current)
        _reject_duplicate_rule_priority(self, current, exclude_id=rule_id)
        current["revision_number"] = _next_revision(current)
        _stamp_update(current)
        self._upsert(
            "aria_acl_rules",
            rule_id,
            current,
            project_id=current.get("project_id"),
            policy_id=current["policy_id"],
        )
        return _clone(current)

    def delete_rule(self, rule_id):
        self._delete("aria_acl_rules", rule_id, "aria_acl_rule")

    def create_address_set(self, values):
        values = _normalize_project_id(_clone(values))
        _require(values, ("project_id",), "aria_acl_address_set")
        values.setdefault("id", _new_id())
        values.setdefault("name", "")
        values.setdefault("members", [])
        values.setdefault("enabled", True)
        values.setdefault("revision_number", 1)
        _stamp_create(values)
        self._upsert(
            "aria_acl_address_sets",
            values["id"],
            values,
            project_id=values["project_id"],
        )
        return _clone(values)

    def list_address_sets(self, filters=None):
        return self._list("aria_acl_address_sets", filters=filters)

    def get_address_set(self, address_set_id):
        return self._get("aria_acl_address_sets", address_set_id, "aria_acl_address_set")

    def update_address_set(self, address_set_id, values):
        current = self.get_address_set(address_set_id)
        current.update(_clone(values))
        current["id"] = address_set_id
        _normalize_project_id(current)
        _require(current, ("project_id",), "aria_acl_address_set")
        current["revision_number"] = _next_revision(current)
        _stamp_update(current)
        self._upsert(
            "aria_acl_address_sets",
            address_set_id,
            current,
            project_id=current["project_id"],
        )
        return _clone(current)

    def delete_address_set(self, address_set_id):
        self._reject_address_set_in_use(address_set_id)
        self._delete("aria_acl_address_sets", address_set_id, "aria_acl_address_set")

    def create_binding(self, values):
        values = _normalize_project_id(_clone(values))
        _require(
            values,
            ("project_id", "policy_id", "target_type", "target_id"),
            "aria_acl_binding",
        )
        self._validate_policy_project(values)
        if values["target_type"] not in ("port", "network"):
            raise AriaAclValidationError("aria_acl_binding target_type must be port or network")
        values.setdefault("id", _new_id())
        values.setdefault("enabled", True)
        values.setdefault("revision_number", 1)
        _reject_duplicate_binding_target(self, values)
        _stamp_create(values)
        self._upsert(
            "aria_acl_bindings",
            values["id"],
            values,
            project_id=values["project_id"],
            policy_id=values["policy_id"],
            target_type=values["target_type"],
            target_id=values["target_id"],
        )
        return _clone(values)

    def list_bindings(self, filters=None):
        return self._list("aria_acl_bindings", filters=filters)

    def get_binding(self, binding_id):
        return self._get("aria_acl_bindings", binding_id, "aria_acl_binding")

    def update_binding(self, binding_id, values):
        existing = self.get_binding(binding_id)
        current = _clone(existing)
        current.update(_clone(values))
        current["id"] = binding_id
        current["policy_id"] = existing["policy_id"]
        current["target_type"] = existing["target_type"]
        current["target_id"] = existing["target_id"]
        _normalize_project_id(current)
        _require(
            current,
            ("project_id", "policy_id", "target_type", "target_id"),
            "aria_acl_binding",
        )
        self._validate_policy_project(current)
        _reject_duplicate_binding_target(self, current, exclude_id=binding_id)
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

    def list_port_statuses(self, filters=None):
        return self._list("aria_acl_port_statuses", filters=filters)

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
        self.connection.commit()

    def _upsert(self, table, object_id, values, **columns):
        payload = json.dumps(values, sort_keys=True)
        if table == "aria_acl_bindings":
            self.connection.execute(
                "INSERT OR REPLACE INTO aria_acl_bindings "
                "(id, project_id, policy_id, target_type, target_id, payload) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    object_id,
                    columns.get("project_id"),
                    columns.get("policy_id"),
                    columns.get("target_type"),
                    columns.get("target_id"),
                    payload,
                ),
            )
        elif table == "aria_acl_rules":
            self.connection.execute(
                "INSERT OR REPLACE INTO aria_acl_rules "
                "(id, project_id, policy_id, payload) VALUES (?, ?, ?, ?)",
                (object_id, columns.get("project_id"), columns.get("policy_id"), payload),
            )
        else:
            self.connection.execute(
                "INSERT OR REPLACE INTO %s (id, project_id, payload) VALUES (?, ?, ?)" % table,
                (object_id, columns.get("project_id"), payload),
            )
        self.connection.commit()

    def _list(self, table, filters=None):
        cursor = self.connection.execute("SELECT payload FROM %s" % table)
        values = [json.loads(row[0]) for row in cursor.fetchall()]
        filters = filters or {}
        return [
            value for value in values
            if _matches_filters(value, filters)
        ]

    def _get(self, table, object_id, object_type):
        cursor = self.connection.execute(
            "SELECT payload FROM %s WHERE id=?" % table,
            (object_id,),
        )
        row = cursor.fetchone()
        if not row:
            raise AriaAclNotFound("%s %s not found" % (object_type, object_id))
        return json.loads(row[0])

    def _delete(self, table, object_id, object_type):
        cursor = self.connection.execute("DELETE FROM %s WHERE id=?" % table, (object_id,))
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

    def _validate_policy_project(self, values):
        try:
            policy = self.get_policy(values.get("policy_id"))
        except AriaAclNotFound:
            raise AriaAclValidationError("aria_acl object references missing policy")
        project_id = values.get("project_id")
        if project_id and policy.get("project_id") and policy.get("project_id") != project_id:
            raise AriaAclValidationError("aria_acl object project_id does not match policy")

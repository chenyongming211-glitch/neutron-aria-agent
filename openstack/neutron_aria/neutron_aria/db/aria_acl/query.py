from __future__ import absolute_import

import base64
import binascii
import calendar
import datetime
import functools
import re

from neutron_aria.db.aria_acl.errors import AriaAclNotFound
from neutron_aria.db.aria_acl.errors import AriaAclConflictError
from neutron_aria.db.aria_acl.errors import AriaAclValidationError


try:
    STRING_TYPES = (basestring,)
    TEXT_TYPE = unicode
    INTEGER_TYPES = (int, long)
except NameError:
    STRING_TYPES = (str,)
    TEXT_TYPE = str
    INTEGER_TYPES = (int,)


_PORT_STATUS_ID_PREFIX = "aria-status-v1_"
_LEGACY_PORT_STATUS_ID_PREFIX = "aria-status-v1."
_PORT_STATUS_ID_PREFIXES = (
    _PORT_STATUS_ID_PREFIX,
    _LEGACY_PORT_STATUS_ID_PREFIX,
)


class QuerySpec(object):
    def __init__(
        self,
        name,
        public_identity_field,
        identity_fields,
        aliases,
        field_types,
        visible_fields,
        filterable_fields,
        sortable_fields,
    ):
        self.name = name
        self.public_identity_field = public_identity_field
        self.identity_fields = tuple(identity_fields)
        self.aliases = dict(aliases)
        self.field_types = dict(field_types)
        self.visible_fields = frozenset(visible_fields)
        self.filterable_fields = frozenset(filterable_fields)
        self.sortable_fields = frozenset(sortable_fields)


class NormalizedQuery(object):
    def __init__(self, spec, filters, fields, sorts, limit, marker, page_reverse):
        self.spec = spec
        self.filters = filters
        self.fields = tuple(fields) if fields else None
        self.sorts = tuple(sorts)
        self.limit = limit
        self.marker = marker
        self.page_reverse = bool(page_reverse)


class PortStatusProjection(object):
    def __init__(self, now_epoch, stale_seconds):
        self.now_epoch = float(now_epoch)
        self.stale_seconds = int(stale_seconds)

    def project(self, row):
        value = dict(row)
        value["id"] = encode_port_status_id(value["port_id"], value["host"])
        value.setdefault("last_reported_at", value.get("updated_at"))
        value["stale"] = self._is_stale(value.get("updated_at"))
        value["runtime_status"] = (
            "stale" if value["stale"] else value.get("status") or "unknown"
        )
        return value

    def _is_stale(self, value):
        if self.stale_seconds < 0:
            return False
        timestamp = _timestamp_seconds(value)
        if timestamp is None:
            return True
        return (self.now_epoch - timestamp) > self.stale_seconds


_DESIRED_COMMON = (
    "id",
    "tenant_id",
    "project_id",
    "enabled",
    "revision_number",
)
_DESIRED_TYPES = {
    "enabled": bool,
    "revision_number": int,
}
_DESIRED_ALIASES = {"tenant_id": "project_id"}


def _desired_spec(name, extra_fields, field_types=None, non_query_fields=()):
    visible = frozenset(_DESIRED_COMMON + tuple(extra_fields))
    blocked = frozenset(non_query_fields)
    types = dict(_DESIRED_TYPES)
    types.update(field_types or {})
    return QuerySpec(
        name=name,
        public_identity_field="id",
        identity_fields=("id",),
        aliases=_DESIRED_ALIASES,
        field_types=types,
        visible_fields=visible,
        filterable_fields=visible - blocked,
        sortable_fields=visible - blocked,
    )


QUERY_SPECS = {
    "policies": _desired_spec(
        "policies",
        ("name", "default_action", "stateful"),
        {"stateful": bool},
    ),
    "rules": _desired_spec(
        "rules",
        (
            "policy_id",
            "direction",
            "priority",
            "action",
            "protocol",
            "src_cidr",
            "dst_cidr",
            "src_address_set_id",
            "dst_address_set_id",
            "src_port_min",
            "src_port_max",
            "dst_port_min",
            "dst_port_max",
            "ethertype",
        ),
        {
            "priority": int,
            "src_port_min": int,
            "src_port_max": int,
            "dst_port_min": int,
            "dst_port_max": int,
        },
    ),
    "address_sets": _desired_spec(
        "address_sets",
        ("name", "members"),
        non_query_fields=("members",),
    ),
    "bindings": _desired_spec(
        "bindings",
        ("policy_id", "target_type", "target_id"),
    ),
}

_STATUS_VISIBLE = frozenset((
    "id",
    "port_id",
    "tenant_id",
    "host",
    "effective_policy_id",
    "binding_id",
    "status",
    "reason",
    "effective_action",
    "generation",
    "updated_at",
    "last_reported_at",
    "stale",
    "runtime_status",
))
_STATUS_FILTERABLE = _STATUS_VISIBLE - frozenset(("tenant_id",))
_STATUS_SORTABLE = _STATUS_VISIBLE - frozenset(
    ("tenant_id", "stale", "runtime_status")
)
QUERY_SPECS["port_statuses"] = QuerySpec(
    name="port_statuses",
    public_identity_field="id",
    identity_fields=("port_id", "host"),
    aliases={"last_reported_at": "updated_at"},
    field_types={
        "generation": int,
        "stale": bool,
        "updated_at": "timestamp",
        "last_reported_at": "timestamp",
    },
    visible_fields=_STATUS_VISIBLE,
    filterable_fields=_STATUS_FILTERABLE,
    sortable_fields=_STATUS_SORTABLE,
)


def get_query_spec(resource):
    try:
        return QUERY_SPECS[resource]
    except KeyError:
        raise AriaAclValidationError("unsupported aria_acl query resource %s" % resource)


def normalize_query(
    resource,
    filters=None,
    fields=None,
    sorts=None,
    limit=None,
    marker=None,
    page_reverse=False,
):
    spec = get_query_spec(resource)
    return NormalizedQuery(
        spec=spec,
        filters=_normalize_filters(spec, filters or {}),
        fields=_normalize_fields(spec, fields),
        sorts=_normalize_sorts(spec, sorts or []),
        limit=_normalize_limit(limit),
        marker=marker,
        page_reverse=page_reverse,
    )


def encode_port_status_id(port_id, host):
    port_bytes = _identity_utf8(port_id, "port_id", 36)
    host_bytes = _identity_utf8(host, "host", 255)
    payload = port_bytes + b"\x00" + host_bytes
    encoded = base64.urlsafe_b64encode(payload).rstrip(b"=")
    return _PORT_STATUS_ID_PREFIX + encoded.decode("ascii")


def is_port_status_id(value):
    return (
        isinstance(value, STRING_TYPES) and
        value.startswith(_PORT_STATUS_ID_PREFIXES)
    )


def decode_port_status_id(value):
    if not is_port_status_id(value):
        raise AriaAclValidationError("invalid aria_acl_port_status id prefix")
    prefix = next(
        candidate for candidate in _PORT_STATUS_ID_PREFIXES
        if value.startswith(candidate)
    )
    encoded = value[len(prefix):]
    if (
        not encoded or
        "=" in encoded or
        re.match(r"^[A-Za-z0-9_-]+$", encoded) is None
    ):
        raise AriaAclValidationError("invalid aria_acl_port_status id encoding")
    try:
        payload = base64.urlsafe_b64decode(
            encoded.encode("ascii") + b"=" * (-len(encoded) % 4)
        )
    except (TypeError, ValueError, binascii.Error):
        raise AriaAclValidationError("invalid aria_acl_port_status id encoding")
    if payload.count(b"\x00") != 1:
        raise AriaAclValidationError("invalid aria_acl_port_status id payload")
    port_bytes, host_bytes = payload.split(b"\x00", 1)
    try:
        port_id = port_bytes.decode("utf-8")
        host = host_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise AriaAclValidationError("invalid aria_acl_port_status id utf8")
    _identity_utf8(port_id, "port_id", 36)
    _identity_utf8(host, "host", 255)
    canonical = encode_port_status_id(port_id, host)
    if canonical[len(_PORT_STATUS_ID_PREFIX):] != encoded:
        raise AriaAclValidationError("noncanonical aria_acl_port_status id")
    return port_id, host


def require_one_legacy_port_status(port_id, statuses):
    if not statuses:
        raise AriaAclNotFound("aria_acl_port_status %s not found" % port_id)
    if len(statuses) > 1:
        hosts = sorted(status.get("host") or "" for status in statuses)
        raise AriaAclConflictError(
            "ambiguous_port_status port_id=%s hosts=%s" % (
                port_id,
                ",".join(hosts),
            )
        )
    return statuses[0]


def apply_memory_query(rows, query, projection=None):
    if query.spec.name == "port_statuses" and projection is None:
        projected_filters = frozenset(("stale", "runtime_status"))
        projected_fields = frozenset(query.fields or ())
        if projected_filters.intersection(query.filters) or projected_filters.intersection(
            projected_fields
        ):
            raise AriaAclValidationError(
                "port_statuses projected query requires a status projection"
            )
    projected = [_project_row(row, query.spec, projection) for row in rows]
    marker_row = _marker_row(projected, query)
    filters = dict(query.filters)
    status_identities = None
    if query.spec.name == "port_statuses" and "id" in filters:
        status_identities = frozenset(
            decode_port_status_id(value) for value in filters.pop("id")
        )
    filtered = [
        row for row in projected
        if _matches(row, filters) and (
            status_identities is None or
            (row.get("port_id"), row.get("host")) in status_identities
        )
    ]
    ordered = sorted(filtered, key=_sort_key(query.sorts))

    if marker_row is not None:
        compare = _row_compare(query.sorts)
        if query.page_reverse:
            ordered = [row for row in ordered if compare(row, marker_row) < 0]
        else:
            ordered = [row for row in ordered if compare(row, marker_row) > 0]

    if query.limit is not None:
        if query.page_reverse:
            ordered = ordered[-query.limit:] if query.limit else []
        else:
            ordered = ordered[:query.limit]
    elif query.page_reverse:
        ordered = list(ordered)

    return [project_fields(row, query.fields) for row in ordered]


def project_fields(row, fields):
    if not fields:
        return dict(row)
    projected = {}
    for field in fields:
        if field in row:
            projected[field] = row[field]
        elif field == "tenant_id" and "project_id" in row:
            projected[field] = row["project_id"]
        elif field == "project_id" and "tenant_id" in row:
            projected[field] = row["tenant_id"]
    return projected


def _normalize_filters(spec, filters):
    normalized = {}
    for public_field, supplied in filters.items():
        if public_field not in spec.filterable_fields:
            raise AriaAclValidationError(
                "%s field %s is not filterable" % (spec.name, public_field)
            )
        field = spec.aliases.get(public_field, public_field)
        values = supplied if isinstance(supplied, (list, tuple, set)) else [supplied]
        converted = tuple(_typed_value(spec, public_field, value) for value in values)
        if field in normalized:
            converted = tuple(value for value in normalized[field] if value in converted)
        normalized[field] = converted
    return normalized


def _normalize_fields(spec, fields):
    if not fields:
        return None
    normalized = []
    for field in fields:
        if field not in spec.visible_fields:
            raise AriaAclValidationError(
                "%s field %s is not visible" % (spec.name, field)
            )
        if field not in normalized:
            normalized.append(field)
    return tuple(normalized)


def _normalize_sorts(spec, sorts):
    normalized = []
    seen = set()
    for item in sorts:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise AriaAclValidationError("%s sort must be a field/direction pair" % spec.name)
        public_field, ascending = item
        if public_field not in spec.sortable_fields:
            raise AriaAclValidationError(
                "%s field %s is not sortable" % (spec.name, public_field)
            )
        if not isinstance(ascending, bool):
            raise AriaAclValidationError(
                "%s sort direction for %s must be boolean" % (spec.name, public_field)
            )
        fields = spec.identity_fields if (
            public_field == spec.public_identity_field and
            len(spec.identity_fields) > 1
        ) else (spec.aliases.get(public_field, public_field),)
        for field in fields:
            if field not in seen:
                normalized.append((field, ascending))
                seen.add(field)
    for field in spec.identity_fields:
        if field not in seen:
            normalized.append((field, True))
    return tuple(normalized)


def _normalize_limit(limit):
    if limit is None:
        return None
    value = _integer_value(limit, "limit")
    if value < 0:
        raise AriaAclValidationError("query limit cannot be negative")
    return value


def _typed_value(spec, field, value):
    value_type = spec.field_types.get(field)
    if value is None:
        return None
    if value_type is bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, STRING_TYPES):
            lowered = value.strip().lower()
            if lowered in ("true", "1"):
                return True
            if lowered in ("false", "0"):
                return False
        raise AriaAclValidationError(
            "%s filter %s requires a boolean" % (spec.name, field)
        )
    if value_type is int:
        try:
            return _integer_value(value, "%s filter %s" % (spec.name, field))
        except AriaAclValidationError:
            raise
    if value_type == "timestamp":
        return _canonical_timestamp(value, spec.name, field)
    if not isinstance(value, STRING_TYPES):
        raise AriaAclValidationError(
            "%s filter %s requires text" % (spec.name, field)
        )
    return value


def _integer_value(value, label):
    if isinstance(value, bool):
        raise AriaAclValidationError("%s requires a canonical integer" % label)
    if isinstance(value, INTEGER_TYPES):
        return value
    if isinstance(value, STRING_TYPES) and re.match(
        r"^(0|-?[1-9][0-9]*)$", value
    ):
        return int(value)
    raise AriaAclValidationError("%s requires a canonical integer" % label)


def _canonical_timestamp(value, resource, field):
    if not isinstance(value, STRING_TYPES):
        raise AriaAclValidationError(
            "%s filter %s requires an ISO timestamp" % (resource, field)
        )
    text = value.rstrip("Z")
    parsed = None
    for pattern in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            parsed = datetime.datetime.strptime(text, pattern)
            break
        except ValueError:
            pass
    if parsed is None:
        raise AriaAclValidationError(
            "%s filter %s requires an ISO timestamp" % (resource, field)
        )
    return "%s.%06dZ" % (
        parsed.strftime("%Y-%m-%dT%H:%M:%S"),
        parsed.microsecond,
    )


def _identity_utf8(value, field, maximum):
    if isinstance(value, bytes):
        try:
            text_value = value.decode("utf-8")
        except UnicodeDecodeError:
            raise AriaAclValidationError("invalid %s utf8" % field)
    elif isinstance(value, TEXT_TYPE):
        text_value = value
    else:
        raise AriaAclValidationError("invalid %s identity type" % field)
    encoded = text_value.encode("utf-8")
    if not encoded or b"\x00" in encoded:
        raise AriaAclValidationError("invalid %s identity" % field)
    if len(encoded) > maximum:
        raise AriaAclValidationError("%s identity exceeds %d bytes" % (field, maximum))
    return encoded


def _project_row(row, spec, projection):
    if spec.name != "port_statuses":
        return dict(row)
    if projection is not None:
        return projection.project(row)
    value = dict(row)
    value["id"] = encode_port_status_id(value["port_id"], value["host"])
    value.setdefault("last_reported_at", value.get("updated_at"))
    return value


def _marker_row(rows, query):
    if query.marker is None:
        return None
    if query.spec.name == "port_statuses":
        marker_identity = decode_port_status_id(query.marker)
        for row in rows:
            if (row.get("port_id"), row.get("host")) == marker_identity:
                return row
        raise AriaAclNotFound(
            "%s marker %s not found" % (query.spec.name, query.marker)
        )
    for row in rows:
        if row.get(query.spec.public_identity_field) == query.marker:
            return row
    raise AriaAclNotFound(
        "%s marker %s not found" % (query.spec.name, query.marker)
    )


def _matches(row, filters):
    for field, expected in filters.items():
        if not expected or row.get(field) not in expected:
            return False
    return True


def _row_compare(sorts):
    def compare(left, right):
        for field, ascending in sorts:
            result = _value_compare(left.get(field), right.get(field), ascending)
            if result:
                return result
        return 0
    return compare


def _sort_key(sorts):
    compare = _row_compare(sorts)
    if hasattr(functools, "cmp_to_key"):
        return functools.cmp_to_key(compare)

    class Key(object):
        def __init__(self, value):
            self.value = value

        def __lt__(self, other):
            return compare(self.value, other.value) < 0

    return Key


def _value_compare(left, right, ascending):
    if left is None and right is None:
        return 0
    if left is None:
        return -1 if ascending else 1
    if right is None:
        return 1 if ascending else -1
    if left < right:
        result = -1
    elif left > right:
        result = 1
    else:
        result = 0
    return result if ascending else -result


def _timestamp_seconds(value):
    if isinstance(value, datetime.datetime):
        parsed = value
    else:
        if value is None:
            return None
        text = str(value).rstrip("Z")
        parsed = None
        for pattern in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
            try:
                parsed = datetime.datetime.strptime(text, pattern)
                break
            except ValueError:
                pass
        if parsed is None:
            return None
    return calendar.timegm(parsed.timetuple()) + (
        parsed.microsecond / 1000000.0
    )

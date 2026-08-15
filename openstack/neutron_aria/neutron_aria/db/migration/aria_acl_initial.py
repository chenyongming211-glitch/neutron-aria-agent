from __future__ import absolute_import


revision = "8b9c2d1e4f60"
down_revision = ("4af11ca47297", "2948f8b16a0c")
branch_labels = None
depends_on = None


ARIA_ACL_TABLES = {
    "aria_acl_policies": (
        "id",
        "project_id",
        "name",
        "default_action",
        "stateful",
        "enabled",
        "revision_number",
        "created_at",
        "updated_at",
    ),
    "aria_acl_rules": (
        "id",
        "project_id",
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
        "enabled",
        "revision_number",
        "created_at",
        "updated_at",
    ),
    "aria_acl_address_sets": (
        "id",
        "project_id",
        "name",
        "enabled",
        "revision_number",
        "created_at",
        "updated_at",
    ),
    "aria_acl_address_set_members": (
        "id",
        "address_set_id",
        "address",
        "created_at",
        "updated_at",
    ),
    "aria_acl_bindings": (
        "id",
        "project_id",
        "policy_id",
        "target_type",
        "target_id",
        "enabled",
        "revision_number",
        "created_at",
        "updated_at",
    ),
    "aria_acl_rbac": (
        "id",
        "project_id",
        "object_type",
        "object_id",
        "target_project_id",
        "action",
        "created_at",
        "updated_at",
    ),
    "aria_acl_port_statuses": (
        "port_id",
        "host",
        "effective_policy_id",
        "binding_id",
        "status",
        "reason",
        "effective_action",
        "generation",
        "updated_at",
        "counters_sampled_at",
        "counters_policy_packets",
        "counters_policy_bytes",
        "counters_policy_allow_packets",
        "counters_policy_dropped_packets",
        "counters_policy_dropped_bytes",
        "counters_policy_pps",
        "counters_drop_packets",
        "counters_drop_bytes",
        "counters_drop_pps",
        "counters_truncated",
        "counters_reset_detected",
    ),
    "aria_acl_port_counters": (
        "id",
        "port_id",
        "host",
        "kind",
        "src_id",
        "dst_id",
        "proto",
        "direction",
        "reason",
        "packets",
        "bytes",
        "dropped_packets",
        "dropped_bytes",
        "pps",
        "bps",
        "sampled_at",
    ),
}


_TABLE_DEFINITIONS = {
    "aria_acl_policies": (
        ("id", "uuid", False, True),
        ("project_id", "uuid", False, False),
        ("name", "name", True, False),
        ("default_action", "short", False, False),
        ("stateful", "bool", False, False),
        ("enabled", "bool", False, False),
        ("revision_number", "int", False, False),
        ("created_at", "datetime", True, False),
        ("updated_at", "datetime", True, False),
    ),
    "aria_acl_rules": (
        ("id", "uuid", False, True),
        ("project_id", "uuid", True, False),
        ("policy_id", "uuid", False, False),
        ("direction", "short", False, False),
        ("priority", "int", False, False),
        ("action", "short", False, False),
        ("protocol", "short", True, False),
        ("src_cidr", "cidr", True, False),
        ("dst_cidr", "cidr", True, False),
        ("src_address_set_id", "uuid", True, False),
        ("dst_address_set_id", "uuid", True, False),
        ("src_port_min", "int", True, False),
        ("src_port_max", "int", True, False),
        ("dst_port_min", "int", True, False),
        ("dst_port_max", "int", True, False),
        ("ethertype", "short", True, False),
        ("enabled", "bool", False, False),
        ("revision_number", "int", False, False),
        ("created_at", "datetime", True, False),
        ("updated_at", "datetime", True, False),
    ),
    "aria_acl_address_sets": (
        ("id", "uuid", False, True),
        ("project_id", "uuid", False, False),
        ("name", "name", True, False),
        ("enabled", "bool", False, False),
        ("revision_number", "int", False, False),
        ("created_at", "datetime", True, False),
        ("updated_at", "datetime", True, False),
    ),
    "aria_acl_address_set_members": (
        ("id", "uuid", False, True),
        ("address_set_id", "uuid", False, False),
        ("address", "cidr", False, False),
        ("created_at", "datetime", True, False),
        ("updated_at", "datetime", True, False),
    ),
    "aria_acl_bindings": (
        ("id", "uuid", False, True),
        ("project_id", "uuid", False, False),
        ("policy_id", "uuid", False, False),
        ("target_type", "short", False, False),
        ("target_id", "uuid", False, False),
        ("enabled", "bool", False, False),
        ("revision_number", "int", False, False),
        ("created_at", "datetime", True, False),
        ("updated_at", "datetime", True, False),
    ),
    "aria_acl_rbac": (
        ("id", "uuid", False, True),
        ("project_id", "uuid", False, False),
        ("object_type", "short", False, False),
        ("object_id", "uuid", False, False),
        ("target_project_id", "uuid", False, False),
        ("action", "short", False, False),
        ("created_at", "datetime", True, False),
        ("updated_at", "datetime", True, False),
    ),
    "aria_acl_port_statuses": (
        ("port_id", "uuid", False, True),
        ("host", "name", False, True),
        ("effective_policy_id", "uuid", True, False),
        ("binding_id", "uuid", True, False),
        ("status", "short", False, False),
        ("reason", "text", True, False),
        ("effective_action", "short", True, False),
        ("generation", "bigint", True, False),
        ("updated_at", "datetime", True, False),
        ("counters_sampled_at", "datetime", True, False),
        ("counters_policy_packets", "bigint", True, False),
        ("counters_policy_bytes", "bigint", True, False),
        ("counters_policy_allow_packets", "bigint", True, False),
        ("counters_policy_dropped_packets", "bigint", True, False),
        ("counters_policy_dropped_bytes", "bigint", True, False),
        ("counters_policy_pps", "float", True, False),
        ("counters_drop_packets", "bigint", True, False),
        ("counters_drop_bytes", "bigint", True, False),
        ("counters_drop_pps", "float", True, False),
        ("counters_truncated", "bool", True, False),
        ("counters_reset_detected", "bool", True, False),
    ),
    "aria_acl_port_counters": (
        ("id", "uuid", False, True),
        ("port_id", "uuid", False, False),
        ("host", "name", False, False),
        ("kind", "short", False, False),
        ("src_id", "int", True, False),
        ("dst_id", "int", True, False),
        ("proto", "int", True, False),
        ("direction", "short", True, False),
        ("reason", "int", True, False),
        ("packets", "bigint", False, False),
        ("bytes", "bigint", False, False),
        ("dropped_packets", "bigint", True, False),
        ("dropped_bytes", "bigint", True, False),
        ("pps", "float", True, False),
        ("bps", "float", True, False),
        ("sampled_at", "datetime", True, False),
    ),
}


_INDEXES = (
    ("ix_aria_acl_rules_policy_id", "aria_acl_rules", ("policy_id",), False),
    (
        "ix_aria_acl_address_set_members_set_id",
        "aria_acl_address_set_members",
        ("address_set_id",),
        False,
    ),
    ("ix_aria_acl_bindings_target", "aria_acl_bindings", ("target_type", "target_id"), False),
    ("ix_aria_acl_bindings_policy_id", "aria_acl_bindings", ("policy_id",), False),
)


def table_names():
    return sorted(ARIA_ACL_TABLES)


def table_definitions():
    return dict((name, tuple(columns)) for name, columns in _TABLE_DEFINITIONS.items())


def _load_alembic_modules():
    try:
        from alembic import op as alembic_op
        import sqlalchemy as sa
    except Exception:
        return None, None
    return alembic_op, sa


def _type(sa, type_name):
    if type_name == "uuid":
        return sa.String(length=36)
    if type_name == "name":
        return sa.String(length=255)
    if type_name == "short":
        return sa.String(length=64)
    if type_name == "cidr":
        return sa.String(length=128)
    if type_name == "text":
        return sa.Text()
    if type_name == "bool":
        return sa.Boolean()
    if type_name == "int":
        return sa.Integer()
    if type_name == "bigint":
        return sa.BigInteger()
    if type_name == "float":
        return sa.Float()
    if type_name == "datetime":
        return sa.DateTime()
    raise ValueError("unsupported aria_acl column type: %s" % type_name)


def _column(sa, name, type_name, nullable, primary_key):
    return sa.Column(
        name,
        _type(sa, type_name),
        nullable=nullable,
        primary_key=primary_key,
    )


def _create_tables(op_handle, sa):
    for table in table_names():
        columns = [
            _column(sa, name, type_name, nullable, primary_key)
            for name, type_name, nullable, primary_key in _TABLE_DEFINITIONS[table]
        ]
        op_handle.create_table(table, *columns)
    for name, table, columns, unique in _INDEXES:
        op_handle.create_index(name, table, list(columns), unique=unique)


def upgrade(op_handle=None, sa_module=None):
    """Create the minimum aria_acl product tables when Alembic is available.

    Local unit tests import this module without Neutron/Alembic installed. In
    that mode, returning the table contract keeps the package testable while
    real `neutron-db-manage upgrade` receives create_table operations.
    """
    if op_handle is None or sa_module is None:
        loaded_op, loaded_sa = _load_alembic_modules()
        op_handle = op_handle or loaded_op
        sa_module = sa_module or loaded_sa
    if op_handle is None or sa_module is None:
        return ARIA_ACL_TABLES
    _create_tables(op_handle, sa_module)
    return table_names()


def downgrade(op_handle=None):
    if op_handle is None:
        loaded_op, _loaded_sa = _load_alembic_modules()
        op_handle = loaded_op
    if op_handle is None:
        return table_names()
    for name, table, _columns, _unique in reversed(_INDEXES):
        op_handle.drop_index(name, table_name=table)
    for table in reversed(table_names()):
        op_handle.drop_table(table)
    return table_names()

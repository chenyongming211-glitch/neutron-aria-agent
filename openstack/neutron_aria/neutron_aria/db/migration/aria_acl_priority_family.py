from __future__ import absolute_import


revision = "d8f1a2c3b470"
down_revision = "c7d4e9a1b260"
branch_labels = None
depends_on = None


RULE_TABLE = "aria_acl_rules"
RULE_INDEX = "uq_aria_acl_rules_enabled_priority"
RULE_INDEX_COLUMNS_V1 = (
    "policy_id", "direction", "priority", "enabled_guard",
)
RULE_INDEX_COLUMNS_V2 = (
    "policy_id", "direction", "ethertype", "priority", "enabled_guard",
)


def _load_alembic_modules():
    try:
        from alembic import op as alembic_op
        import sqlalchemy as sa
    except Exception:
        return None, None
    return alembic_op, sa


def _row_dict(row):
    if isinstance(row, dict):
        return dict(row)
    mapping = getattr(row, "_mapping", None)
    if mapping is not None:
        return dict(mapping)
    try:
        return dict(row)
    except (TypeError, ValueError):
        return {}


def _backfill_family(op_handle, sa_module):
    op_handle.execute(sa_module.text(
        "UPDATE aria_acl_rules SET direction = LOWER(TRIM(direction))"
    ))
    op_handle.execute(sa_module.text(
        "UPDATE aria_acl_rules SET ethertype = CASE "
        "WHEN LOWER(TRIM(ethertype)) = 'ipv6' THEN 'IPv6' "
        "ELSE 'IPv4' END WHERE ethertype IS NULL OR TRIM(ethertype) = '' "
        "OR LOWER(TRIM(ethertype)) IN ('ipv4', 'ipv6')"
    ))


def _create_v2_index(op_handle):
    op_handle.create_index(
        RULE_INDEX,
        RULE_TABLE,
        list(RULE_INDEX_COLUMNS_V2),
        unique=True,
    )


def _downgrade_conflicts(bind, sa_module):
    rows = bind.execute(sa_module.text(
        "SELECT id, policy_id, direction, priority "
        "FROM aria_acl_rules WHERE enabled_guard = 1"
    )).fetchall()
    grouped = {}
    for raw_row in rows:
        row = _row_dict(raw_row)
        key = (
            row.get("policy_id"),
            row.get("direction"),
            row.get("priority"),
        )
        grouped.setdefault(key, []).append(str(row.get("id")))
    conflicts = []
    for key, object_ids in sorted(grouped.items(), key=lambda item: str(item[0])):
        if len(object_ids) < 2:
            continue
        conflicts.append(
            "policy=%s direction=%s priority=%s ids=%s" % (
                key[0],
                key[1],
                key[2],
                ",".join(sorted(object_ids)),
            )
        )
    return conflicts


def upgrade(op_handle=None, sa_module=None, inspector=None):
    if op_handle is None or sa_module is None:
        loaded_op, loaded_sa = _load_alembic_modules()
        op_handle = op_handle or loaded_op
        sa_module = sa_module or loaded_sa
    if op_handle is None or sa_module is None:
        return False

    bind = op_handle.get_bind()
    if inspector is None:
        inspector = sa_module.inspect(bind)
    return upgrade_existing_schema(
        bind,
        op_handle=op_handle,
        sa_module=sa_module,
        inspector=inspector,
    )


def upgrade_existing_schema(
        bind, op_handle=None, sa_module=None, inspector=None):
    if sa_module is None:
        try:
            import sqlalchemy as sa_module
        except Exception:
            raise RuntimeError("sqlalchemy is required for aria_acl migration")
    connection_type = getattr(
        getattr(sa_module, "engine", None),
        "Connection",
        (),
    )
    if op_handle is None and not isinstance(bind, connection_type):
        with bind.begin() as connection:
            return upgrade_existing_schema(
                connection,
                sa_module=sa_module,
                inspector=sa_module.inspect(connection),
            )
    if inspector is None:
        inspector = sa_module.inspect(bind)
    if op_handle is None:
        try:
            from alembic.migration import MigrationContext
            from alembic.operations import Operations
        except Exception:
            raise RuntimeError("alembic is required for aria_acl migration")
        op_handle = Operations(MigrationContext.configure(bind))

    columns = set(
        column["name"] for column in inspector.get_columns(RULE_TABLE)
    )
    indexes = dict(
        (index["name"], index)
        for index in inspector.get_indexes(RULE_TABLE)
    )
    get_unique_constraints = getattr(
        inspector,
        "get_unique_constraints",
        None,
    )
    if get_unique_constraints is not None:
        for constraint in get_unique_constraints(RULE_TABLE):
            indexes[constraint["name"]] = constraint
    current = indexes.get(RULE_INDEX)
    current_columns = tuple((current or {}).get("column_names") or ())
    if "ethertype" in columns and current_columns == RULE_INDEX_COLUMNS_V2:
        return False

    if "ethertype" not in columns:
        op_handle.add_column(
            RULE_TABLE,
            sa_module.Column(
                "ethertype",
                sa_module.String(length=64),
                nullable=True,
            ),
        )
    _backfill_family(op_handle, sa_module)
    if current is not None:
        op_handle.drop_index(RULE_INDEX, table_name=RULE_TABLE)
    op_handle.alter_column(
        RULE_TABLE,
        "ethertype",
        existing_type=sa_module.String(length=64),
        nullable=False,
    )
    _create_v2_index(op_handle)
    return True


def downgrade(op_handle=None, sa_module=None):
    if op_handle is None or sa_module is None:
        loaded_op, loaded_sa = _load_alembic_modules()
        op_handle = op_handle or loaded_op
        sa_module = sa_module or loaded_sa
    if op_handle is None or sa_module is None:
        return False

    conflicts = _downgrade_conflicts(op_handle.get_bind(), sa_module)
    if conflicts:
        raise RuntimeError(
            "aria_acl_priority_family_downgrade_conflicts: %s"
            % "; ".join(conflicts)
        )
    op_handle.drop_index(RULE_INDEX, table_name=RULE_TABLE)
    op_handle.create_index(
        RULE_INDEX,
        RULE_TABLE,
        list(RULE_INDEX_COLUMNS_V1),
        unique=True,
    )
    return True

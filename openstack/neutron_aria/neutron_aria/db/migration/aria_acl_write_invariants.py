from __future__ import absolute_import


revision = "f61a2c4e7b90"
down_revision = "8b9c2d1e4f60"
branch_labels = None
depends_on = None


RULE_INDEX = "uq_aria_acl_rules_enabled_priority"
BINDING_INDEX = "uq_aria_acl_bindings_enabled_target"
GUARD_TABLES = ("aria_acl_rules", "aria_acl_bindings")


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


def _object_ids(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return sorted(str(item) for item in value)
    return sorted(
        item.strip()
        for item in str(value).split(",")
        if item.strip()
    )


def _collect_conflicts(rows, key_fields):
    grouped = {}
    for raw_row in rows:
        row = _row_dict(raw_row)
        key = tuple(row.get(field) for field in key_fields)
        if "priority" in key_fields:
            priority_index = key_fields.index("priority")
            key = list(key)
            try:
                key[priority_index] = int(key[priority_index])
            except (TypeError, ValueError):
                pass
            key = tuple(key)
        ids = _object_ids(row.get("object_ids"))
        if not ids and row.get("id") is not None:
            ids = [str(row.get("id"))]
        grouped.setdefault(key, []).extend(ids)
    return [
        (key, sorted(set(ids)))
        for key, ids in sorted(grouped.items(), key=lambda item: str(item[0]))
        if len(set(ids)) > 1
    ]


def _historical_conflicts(bind, sa):
    rules = bind.execute(sa.text(
        "SELECT id, policy_id, direction, priority "
        "FROM aria_acl_rules WHERE enabled = 1"
    )).fetchall()
    bindings = bind.execute(sa.text(
        "SELECT id, target_type, target_id "
        "FROM aria_acl_bindings WHERE enabled = 1"
    )).fetchall()
    return (
        _collect_conflicts(
            rules,
            ("policy_id", "direction", "priority"),
        ),
        _collect_conflicts(
            bindings,
            ("target_type", "target_id"),
        ),
    )


def _conflict_message(rule_conflicts, binding_conflicts):
    details = []
    for key, ids in rule_conflicts:
        details.append(
            "rule policy=%s direction=%s priority=%s ids=%s" % (
                key[0],
                key[1],
                key[2],
                ",".join(ids),
            )
        )
    for key, ids in binding_conflicts:
        details.append(
            "binding target_type=%s target_id=%s ids=%s" % (
                key[0],
                key[1],
                ",".join(ids),
            )
        )
    return "aria_acl_write_invariant_conflicts: %s" % "; ".join(details)


def upgrade(op_handle=None, sa_module=None):
    if op_handle is None or sa_module is None:
        loaded_op, loaded_sa = _load_alembic_modules()
        op_handle = op_handle or loaded_op
        sa_module = sa_module or loaded_sa
    if op_handle is None or sa_module is None:
        return

    rule_conflicts, binding_conflicts = _historical_conflicts(
        op_handle.get_bind(),
        sa_module,
    )
    if rule_conflicts or binding_conflicts:
        raise RuntimeError(
            _conflict_message(rule_conflicts, binding_conflicts)
        )

    op_handle.add_column(
        "aria_acl_rules",
        sa_module.Column(
            "enabled_guard",
            sa_module.SmallInteger(),
            nullable=True,
        ),
    )
    op_handle.add_column(
        "aria_acl_bindings",
        sa_module.Column(
            "enabled_guard",
            sa_module.SmallInteger(),
            nullable=True,
        ),
    )
    op_handle.execute(
        sa_module.text(
            "UPDATE aria_acl_rules SET enabled_guard = "
            "CASE WHEN enabled = 1 THEN 1 ELSE NULL END"
        )
    )
    op_handle.execute(
        sa_module.text(
            "UPDATE aria_acl_bindings SET enabled_guard = "
            "CASE WHEN enabled = 1 THEN 1 ELSE NULL END"
        )
    )
    op_handle.create_index(
        RULE_INDEX,
        "aria_acl_rules",
        ["policy_id", "direction", "priority", "enabled_guard"],
        unique=True,
    )
    op_handle.create_index(
        BINDING_INDEX,
        "aria_acl_bindings",
        ["target_type", "target_id", "enabled_guard"],
        unique=True,
    )


def upgrade_existing_schema(
        bind,
        op_handle=None,
        sa_module=None,
        inspector=None):
    """Apply the write-invariant migration to an existing product schema.

    The legacy Kolla environment does not discover this package through
    neutron-db-manage. Keep that compatibility bridge explicit and idempotent
    while still using the authoritative Alembic migration above.
    """
    if sa_module is None:
        try:
            import sqlalchemy as sa_module
        except Exception:
            raise RuntimeError("sqlalchemy is required for aria_acl migration")
    if inspector is None:
        inspector = sa_module.inspect(bind)

    migrated = []
    for table_name in GUARD_TABLES:
        columns = set(
            column["name"]
            for column in inspector.get_columns(table_name)
        )
        if "enabled_guard" in columns:
            migrated.append(table_name)

    if len(migrated) == len(GUARD_TABLES):
        return False
    if migrated:
        raise RuntimeError(
            "aria_acl_partial_write_invariant_schema: migrated=%s"
            % ",".join(sorted(migrated))
        )

    if op_handle is None:
        try:
            from alembic.migration import MigrationContext
            from alembic.operations import Operations
        except Exception:
            raise RuntimeError("alembic is required for aria_acl migration")
        op_handle = Operations(MigrationContext.configure(bind))

    upgrade(op_handle=op_handle, sa_module=sa_module)
    return True


def downgrade(op_handle=None):
    if op_handle is None:
        loaded_op, _loaded_sa = _load_alembic_modules()
        op_handle = loaded_op
    if op_handle is None:
        return
    op_handle.drop_index(RULE_INDEX, table_name="aria_acl_rules")
    op_handle.drop_index(BINDING_INDEX, table_name="aria_acl_bindings")
    op_handle.drop_column("aria_acl_rules", "enabled_guard")
    op_handle.drop_column("aria_acl_bindings", "enabled_guard")

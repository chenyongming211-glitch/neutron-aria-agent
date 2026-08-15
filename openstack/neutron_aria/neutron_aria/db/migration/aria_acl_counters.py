from __future__ import absolute_import


revision = "a4e7c2d9b610"
down_revision = "f61a2c4e7b90"
branch_labels = None
depends_on = None


STATUS_TABLE = "aria_acl_port_statuses"
COUNTER_TABLE = "aria_acl_port_counters"
COUNTER_INDEX = "uq_aria_acl_port_counters_natural"


def _load_alembic_modules():
    try:
        from alembic import op as alembic_op
        import sqlalchemy as sa
    except Exception:
        return None, None
    return alembic_op, sa


def _status_columns(sa):
    return (
        sa.Column("counters_sampled_at", sa.DateTime(), nullable=True),
        sa.Column("counters_policy_packets", sa.BigInteger(), nullable=True),
        sa.Column("counters_policy_bytes", sa.BigInteger(), nullable=True),
        sa.Column("counters_policy_allow_packets", sa.BigInteger(), nullable=True),
        sa.Column("counters_policy_dropped_packets", sa.BigInteger(), nullable=True),
        sa.Column("counters_policy_dropped_bytes", sa.BigInteger(), nullable=True),
        sa.Column("counters_policy_pps", sa.Float(), nullable=True),
        sa.Column("counters_drop_packets", sa.BigInteger(), nullable=True),
        sa.Column("counters_drop_bytes", sa.BigInteger(), nullable=True),
        sa.Column("counters_drop_pps", sa.Float(), nullable=True),
        sa.Column("counters_truncated", sa.Boolean(), nullable=True),
        sa.Column("counters_reset_detected", sa.Boolean(), nullable=True),
        sa.Column("counters_group_map", sa.Text(), nullable=True),
    )


def _create_counter_table(op_handle, sa):
    op_handle.create_table(
        COUNTER_TABLE,
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("port_id", sa.String(length=36), nullable=False),
        sa.Column("host", sa.String(length=255), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("src_id", sa.Integer(), nullable=True),
        sa.Column("dst_id", sa.Integer(), nullable=True),
        sa.Column("proto", sa.Integer(), nullable=True),
        sa.Column("direction", sa.String(length=16), nullable=True),
        sa.Column("reason", sa.Integer(), nullable=True),
        sa.Column("packets", sa.BigInteger(), nullable=False),
        sa.Column("bytes", sa.BigInteger(), nullable=False),
        sa.Column("dropped_packets", sa.BigInteger(), nullable=True),
        sa.Column("dropped_bytes", sa.BigInteger(), nullable=True),
        sa.Column("pps", sa.Float(), nullable=True),
        sa.Column("bps", sa.Float(), nullable=True),
        sa.Column("sampled_at", sa.DateTime(), nullable=True),
    )


def _create_counter_index(op_handle):
    op_handle.create_index(
        COUNTER_INDEX,
        COUNTER_TABLE,
        [
            "port_id",
            "host",
            "kind",
            "src_id",
            "dst_id",
            "proto",
            "direction",
            "reason",
        ],
        unique=True,
    )


def upgrade(op_handle=None, sa_module=None):
    if op_handle is None or sa_module is None:
        loaded_op, loaded_sa = _load_alembic_modules()
        op_handle = op_handle or loaded_op
        sa_module = sa_module or loaded_sa
    if op_handle is None or sa_module is None:
        return False
    for column in _status_columns(sa_module):
        op_handle.add_column(STATUS_TABLE, column)
    _create_counter_table(op_handle, sa_module)
    _create_counter_index(op_handle)
    return True


def upgrade_existing_schema(
        bind,
        op_handle=None,
        sa_module=None,
        inspector=None):
    """Idempotently upgrade a deployed ACL schema to counter support."""
    if sa_module is None:
        try:
            import sqlalchemy as sa_module
        except Exception:
            raise RuntimeError("sqlalchemy is required for aria_acl migration")
    if inspector is None:
        inspector = sa_module.inspect(bind)
    if op_handle is None:
        try:
            from alembic.migration import MigrationContext
            from alembic.operations import Operations
        except Exception:
            raise RuntimeError("alembic is required for aria_acl migration")
        op_handle = Operations(MigrationContext.configure(bind))

    existing_status_columns = set(
        column["name"]
        for column in inspector.get_columns(STATUS_TABLE)
    )
    changed = False
    for column in _status_columns(sa_module):
        if column.name not in existing_status_columns:
            op_handle.add_column(STATUS_TABLE, column)
            changed = True

    table_names = set(inspector.get_table_names())
    if COUNTER_TABLE not in table_names:
        _create_counter_table(op_handle, sa_module)
        _create_counter_index(op_handle)
        return True

    index_names = set(
        index["name"]
        for index in inspector.get_indexes(COUNTER_TABLE)
    )
    if COUNTER_INDEX not in index_names:
        _create_counter_index(op_handle)
        changed = True
    return changed


def downgrade(op_handle=None):
    if op_handle is None:
        loaded_op, _loaded_sa = _load_alembic_modules()
        op_handle = loaded_op
    if op_handle is None:
        return False
    op_handle.drop_index(COUNTER_INDEX, table_name=COUNTER_TABLE)
    op_handle.drop_table(COUNTER_TABLE)
    for column_name in reversed([
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
        "counters_group_map",
    ]):
        op_handle.drop_column(STATUS_TABLE, column_name)
    return True

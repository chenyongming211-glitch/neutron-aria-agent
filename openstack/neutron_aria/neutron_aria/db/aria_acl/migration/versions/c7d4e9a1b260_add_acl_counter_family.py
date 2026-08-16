from __future__ import absolute_import

from neutron_aria.db.migration.aria_acl_counters import downgrade_counter_family
from neutron_aria.db.migration.aria_acl_counters import upgrade_counter_family
from neutron_aria.db.migration.aria_acl_counters import upgrade_counter_family_existing_schema


revision = "c7d4e9a1b260"
down_revision = "a4e7c2d9b610"
branch_labels = None
depends_on = None


def upgrade():
    return upgrade_counter_family()


def downgrade():
    return downgrade_counter_family()


def upgrade_existing_schema(bind, op_handle=None, sa_module=None, inspector=None):
    return upgrade_counter_family_existing_schema(
        bind,
        op_handle=op_handle,
        sa_module=sa_module,
        inspector=inspector,
    )

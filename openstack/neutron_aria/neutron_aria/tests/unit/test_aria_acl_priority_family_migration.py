from __future__ import absolute_import

import importlib
import unittest


class FakeSqlAlchemy(object):
    def Column(self, name, column_type, nullable=True, server_default=None):
        return {
            "name": name,
            "type": column_type,
            "nullable": nullable,
            "server_default": server_default,
        }

    def String(self, length=None):
        return ("String", length)

    def text(self, statement):
        return statement


class FakeResult(object):
    def __init__(self, rows=None):
        self.rows = rows or []

    def fetchall(self):
        return list(self.rows)


class FakeBind(object):
    def __init__(self, conflicts=None):
        self.conflicts = conflicts or []

    def execute(self, statement):
        if "FROM aria_acl_rules" in str(statement):
            return FakeResult(self.conflicts)
        return FakeResult()


class FakeOp(object):
    def __init__(self, bind=None):
        self.bind = bind or FakeBind()
        self.added_columns = []
        self.altered_columns = []
        self.created_indexes = []
        self.dropped_indexes = []
        self.executed = []

    def get_bind(self):
        return self.bind

    def add_column(self, table_name, column):
        self.added_columns.append((table_name, column))

    def alter_column(self, table_name, column_name, **kwargs):
        self.altered_columns.append((table_name, column_name, kwargs))

    def create_index(self, name, table_name, columns, unique=False):
        self.created_indexes.append((name, table_name, tuple(columns), unique))

    def drop_index(self, name, table_name=None):
        self.dropped_indexes.append((name, table_name))

    def execute(self, statement):
        self.executed.append(str(statement))


class FakeInspector(object):
    def __init__(self, columns, index_columns):
        self.columns = columns
        self.index_columns = index_columns

    def get_columns(self, table_name):
        return [{"name": name} for name in self.columns]

    def get_indexes(self, table_name):
        if self.index_columns is None:
            return []
        return [{
            "name": "uq_aria_acl_rules_enabled_priority",
            "column_names": list(self.index_columns),
            "unique": True,
        }]


class AriaAclPriorityFamilyMigrationTestCase(unittest.TestCase):
    def _migration(self):
        module_name = (
            "neutron_aria.db.aria_acl.migration.versions."
            "d8f1a2c3b470_scope_acl_priority_by_family"
        )
        try:
            return importlib.import_module(module_name)
        except ImportError:
            self.fail("ACL family-qualified priority migration is missing")

    def test_upgrade_replaces_priority_index_with_family_qualified_index(self):
        migration = self._migration()
        op = FakeOp()

        migration.upgrade(
            op_handle=op,
            sa_module=FakeSqlAlchemy(),
            inspector=FakeInspector(
                ("id", "ethertype", "enabled_guard"),
                migration.RULE_INDEX_COLUMNS_V1,
            ),
        )

        self.assertEqual("c7d4e9a1b260", migration.down_revision)
        self.assertIn(
            ("uq_aria_acl_rules_enabled_priority", "aria_acl_rules"),
            op.dropped_indexes,
        )
        self.assertIn(
            (
                "uq_aria_acl_rules_enabled_priority",
                "aria_acl_rules",
                ("policy_id", "direction", "ethertype", "priority", "enabled_guard"),
                True,
            ),
            op.created_indexes,
        )
        self.assertTrue(any(
            "SET ethertype = CASE" in statement and "'IPv4'" in statement
            for statement in op.executed
        ))
        self.assertTrue(any(
            "SET direction = LOWER(TRIM(direction))" in statement
            for statement in op.executed
        ))

    def test_runtime_upgrade_recovers_when_old_index_was_already_dropped(self):
        migration = self._migration()
        op = FakeOp()
        inspector = FakeInspector(
            ("id", "ethertype", "enabled_guard"),
            None,
        )

        changed = migration.upgrade_existing_schema(
            op.bind,
            op_handle=op,
            sa_module=FakeSqlAlchemy(),
            inspector=inspector,
        )

        self.assertTrue(changed)
        self.assertEqual([], op.dropped_indexes)
        self.assertIn(
            (
                migration.RULE_INDEX,
                migration.RULE_TABLE,
                migration.RULE_INDEX_COLUMNS_V2,
                True,
            ),
            op.created_indexes,
        )

    def test_runtime_upgrade_is_idempotent_for_new_index(self):
        migration = self._migration()
        op = FakeOp()
        inspector = FakeInspector(
            ("id", "ethertype", "enabled_guard"),
            migration.RULE_INDEX_COLUMNS_V2,
        )

        changed = migration.upgrade_existing_schema(
            op.bind,
            op_handle=op,
            sa_module=FakeSqlAlchemy(),
            inspector=inspector,
        )

        self.assertFalse(changed)
        self.assertEqual([], op.dropped_indexes)
        self.assertEqual([], op.created_indexes)

    def test_downgrade_refuses_cross_family_priority_collisions(self):
        migration = self._migration()
        op = FakeOp(bind=FakeBind(conflicts=[{
            "id": "rule-v4",
            "policy_id": "policy-1",
            "direction": "ingress",
            "priority": 10,
        }, {
            "id": "rule-v6",
            "policy_id": "policy-1",
            "direction": "ingress",
            "priority": 10,
        }]))

        with self.assertRaises(RuntimeError) as raised:
            migration.downgrade(op_handle=op, sa_module=FakeSqlAlchemy())

        self.assertIn("aria_acl_priority_family_downgrade_conflicts", str(raised.exception))
        self.assertEqual([], op.dropped_indexes)


if __name__ == "__main__":
    unittest.main()

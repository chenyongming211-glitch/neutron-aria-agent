from __future__ import absolute_import

import importlib
import unittest

from neutron_aria.db.aria_acl import api as aria_acl_api
from neutron_aria.services.aria_acl.exceptions import map_repository_error
from neutron_aria.services.aria_acl.plugin import AriaAclPlugin


class FakeSqlAlchemy(object):
    def Column(self, name, column_type, nullable=True, primary_key=False):
        return {
            "name": name,
            "type": column_type,
            "nullable": nullable,
            "primary_key": primary_key,
        }

    def SmallInteger(self):
        return ("SmallInteger", None)

    def text(self, statement):
        return statement


class FakeAlembicOp(object):
    def __init__(self, bind=None):
        self.bind = bind
        self.created_indexes = []
        self.added_columns = []
        self.executed = []
        self.dropped_indexes = []
        self.dropped_columns = []

    def create_index(self, name, table_name, columns, unique=False):
        self.created_indexes.append((name, table_name, tuple(columns), unique))

    def add_column(self, table_name, column):
        self.added_columns.append((table_name, column))

    def execute(self, statement):
        self.executed.append(statement)

    def get_bind(self):
        return self.bind

    def drop_index(self, name, table_name=None):
        self.dropped_indexes.append((name, table_name))

    def drop_column(self, table_name, column_name):
        self.dropped_columns.append((table_name, column_name))


class FakeMigrationResult(object):
    def __init__(self, rows):
        self.rows = rows

    def fetchall(self):
        return list(self.rows)


class FakeMigrationBind(object):
    def __init__(self, rule_conflicts=None, binding_conflicts=None):
        self.rule_conflicts = rule_conflicts or []
        self.binding_conflicts = binding_conflicts or []

    def execute(self, statement):
        statement = str(statement)
        if "aria_acl_rules" in statement:
            return FakeMigrationResult(self.rule_conflicts)
        if "aria_acl_bindings" in statement:
            return FakeMigrationResult(self.binding_conflicts)
        raise AssertionError("unexpected migration query: %s" % statement)


class FakeNotifier(object):
    def __init__(self):
        self.events = []

    def notify(self, context, **payload):
        self.events.append((context, payload))


class AriaAclWriteMigrationTestCase(unittest.TestCase):
    def test_repository_conflicts_map_to_http_409(self):
        conflict_type = getattr(aria_acl_api, "AriaAclConflictError", None)
        self.assertIsNotNone(conflict_type, "repository conflict type is missing")
        conflict = conflict_type(
            "duplicate_enabled_rule_priority policy=policy-1 "
            "direction=ingress priority=10"
        )
        mapped = map_repository_error(conflict)
        self.assertEqual(409, mapped.status_code)
        self.assertIn("duplicate_enabled_rule_priority", str(mapped))

    def test_duplicate_rule_failure_does_not_emit_notifier_event(self):
        notifier = FakeNotifier()
        plugin = AriaAclPlugin(notifier=notifier)
        plugin.create_aria_acl_policy(None, {
            "aria_acl_policy": {
                "id": "policy-1",
                "project_id": "project-1",
                "default_action": "allow",
            }
        })
        plugin.create_aria_acl_rule(None, {
            "aria_acl_rule": {
                "id": "rule-1",
                "project_id": "project-1",
                "policy_id": "policy-1",
                "direction": "ingress",
                "priority": 10,
                "action": "allow",
            }
        })
        before = plugin.get_aria_acl_rule(None, "rule-1")
        notifier.events = []
        error = None
        try:
            plugin.create_aria_acl_rule(None, {
                "aria_acl_rule": {
                    "id": "rule-2",
                    "project_id": "project-1",
                    "policy_id": "policy-1",
                    "direction": "ingress",
                    "priority": 10,
                    "action": "deny",
                }
            })
        except Exception as exc:
            error = exc
        self.assertIsNotNone(error)
        self.assertEqual(409, getattr(error, "status_code", None))
        self.assertEqual([], notifier.events)
        self.assertEqual(before, plugin.get_aria_acl_rule(None, "rule-1"))
        self.assertEqual(["rule-1"], [
            rule["id"] for rule in plugin.get_aria_acl_rules(None)
        ])

    def test_duplicate_binding_failure_does_not_emit_notifier_event(self):
        notifier = FakeNotifier()
        plugin = AriaAclPlugin(notifier=notifier)
        for policy_id in ("policy-1", "policy-2"):
            plugin.create_aria_acl_policy(None, {
                "aria_acl_policy": {
                    "id": policy_id,
                    "project_id": "project-1",
                    "default_action": "allow",
                }
            })
        plugin.create_aria_acl_binding(None, {
            "aria_acl_binding": {
                "id": "binding-1",
                "project_id": "project-1",
                "policy_id": "policy-1",
                "target_type": "port",
                "target_id": "port-1",
            }
        })
        before = plugin.get_aria_acl_binding(None, "binding-1")
        notifier.events = []
        error = None
        try:
            plugin.create_aria_acl_binding(None, {
                "aria_acl_binding": {
                    "id": "binding-2",
                    "project_id": "project-1",
                    "policy_id": "policy-2",
                    "target_type": "port",
                    "target_id": "port-1",
                }
            })
        except Exception as exc:
            error = exc
        self.assertIsNotNone(error)
        self.assertEqual(409, getattr(error, "status_code", None))
        self.assertEqual([], notifier.events)
        self.assertEqual(before, plugin.get_aria_acl_binding(None, "binding-1"))
        self.assertEqual(["binding-1"], [
            binding["id"] for binding in plugin.get_aria_acl_bindings(None)
        ])

    def test_write_invariant_migration_adds_named_unique_guards(self):
        migration = self._load_write_invariant_migration()
        op = FakeAlembicOp(bind=FakeMigrationBind())

        migration.upgrade(op_handle=op, sa_module=FakeSqlAlchemy())

        added_column_names = [
            (table_name, column["name"])
            for table_name, column in op.added_columns
        ]
        self.assertEqual("8b9c2d1e4f60", migration.down_revision)
        self.assertIn(("aria_acl_rules", "enabled_guard"), added_column_names)
        self.assertIn(("aria_acl_bindings", "enabled_guard"), added_column_names)
        self.assertIn(
            (
                "uq_aria_acl_rules_enabled_priority",
                "aria_acl_rules",
                ("policy_id", "direction", "priority", "enabled_guard"),
                True,
            ),
            op.created_indexes,
        )
        self.assertIn(
            (
                "uq_aria_acl_bindings_enabled_target",
                "aria_acl_bindings",
                ("target_type", "target_id", "enabled_guard"),
                True,
            ),
            op.created_indexes,
        )

        migration.downgrade(op_handle=op)
        self.assertIn(
            ("uq_aria_acl_rules_enabled_priority", "aria_acl_rules"),
            op.dropped_indexes,
        )
        self.assertIn(
            ("uq_aria_acl_bindings_enabled_target", "aria_acl_bindings"),
            op.dropped_indexes,
        )
        self.assertIn(
            ("aria_acl_rules", "enabled_guard"),
            op.dropped_columns,
        )
        self.assertIn(
            ("aria_acl_bindings", "enabled_guard"),
            op.dropped_columns,
        )

    def test_write_invariant_migration_reports_all_historical_conflicts(self):
        migration = self._load_write_invariant_migration()
        op = FakeAlembicOp(bind=FakeMigrationBind(
            rule_conflicts=[
                {
                    "policy_id": "policy-1",
                    "direction": "ingress",
                    "priority": 10,
                    "object_ids": "rule-2,rule-1",
                },
                {
                    "policy_id": "policy-2",
                    "direction": "egress",
                    "priority": 20,
                    "object_ids": "rule-4,rule-3",
                },
            ],
            binding_conflicts=[
                {
                    "target_type": "port",
                    "target_id": "port-1",
                    "object_ids": "binding-2,binding-1",
                },
            ],
        ))

        error = None
        try:
            migration.upgrade(op_handle=op, sa_module=FakeSqlAlchemy())
        except Exception as exc:
            error = exc

        self.assertIsNotNone(error)
        message = str(error)
        for expected in (
            "policy-1",
            "ingress",
            "priority=10",
            "rule-1,rule-2",
            "policy-2",
            "egress",
            "priority=20",
            "rule-3,rule-4",
            "port",
            "port-1",
            "binding-1,binding-2",
        ):
            self.assertIn(expected, message)
        self.assertEqual([], op.added_columns)
        self.assertEqual([], op.created_indexes)
        self.assertEqual([], op.executed)

    def _load_write_invariant_migration(self):
        module_name = (
            "neutron_aria.db.aria_acl.migration.versions."
            "f61a2c4e7b90_add_acl_write_invariants"
        )
        try:
            return importlib.import_module(module_name)
        except ImportError:
            self.fail("ACL write-invariant migration is missing")


if __name__ == "__main__":
    unittest.main()

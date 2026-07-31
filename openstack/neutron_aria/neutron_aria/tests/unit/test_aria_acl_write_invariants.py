from __future__ import absolute_import

import copy
import json
import os
import sqlite3
import tempfile
import threading
import unittest

from neutron_aria.db.aria_acl import api as aria_acl_api
from neutron_aria.db.aria_acl.api import AriaAclNotFound
from neutron_aria.db.aria_acl.api import AriaAclValidationError
from neutron_aria.db.aria_acl.api import InMemoryAriaAclRepository
from neutron_aria.db.aria_acl.api import NeutronDbAriaAclRepository
from neutron_aria.db.aria_acl.api import SqliteAriaAclRepository


class NeutronDbMethodAdapter(NeutronDbAriaAclRepository):
    """Run the real Neutron DB write methods without local SQLAlchemy."""

    def __init__(self):
        self.rows = dict(
            (name, {})
            for name in ("policies", "rules", "address_sets", "bindings")
        )

    def _db_values(self, _table_name, values):
        return copy.deepcopy(values)

    def _insert(self, table_name, values):
        self.rows[table_name][values["id"]] = copy.deepcopy(values)

    def _update(self, table_name, object_id, values):
        if object_id not in self.rows[table_name]:
            raise AriaAclNotFound("%s not found" % object_id)
        self.rows[table_name][object_id] = copy.deepcopy(values)

    def _list(self, table_name, filters=None):
        result = []
        for value in self.rows[table_name].values():
            if self._matches(value, filters or {}):
                result.append(copy.deepcopy(value))
        return result

    def _get(self, table_name, object_id, object_type):
        if object_id not in self.rows[table_name]:
            raise AriaAclNotFound("%s %s not found" % (object_type, object_id))
        return copy.deepcopy(self.rows[table_name][object_id])

    def _replace_members(self, address_set_id, members):
        self.rows["address_sets"][address_set_id]["members"] = copy.deepcopy(
            members
        )

    @staticmethod
    def _matches(value, filters):
        for key, expected in filters.items():
            actual = value.get(key)
            if isinstance(expected, (list, tuple, set)):
                if actual not in expected:
                    return False
            elif actual != expected:
                return False
        return True


class FakeConstraintError(Exception):
    def __init__(self, constraint_name):
        self.constraint_name = constraint_name
        super(FakeConstraintError, self).__init__(constraint_name)


class ConstraintFailureNeutronAdapter(NeutronDbMethodAdapter):
    def __init__(self):
        super(ConstraintFailureNeutronAdapter, self).__init__()
        self.failed_constraint = None

    def _insert(self, table_name, values):
        if self.failed_constraint is not None:
            raise FakeConstraintError(self.failed_constraint)
        super(ConstraintFailureNeutronAdapter, self)._insert(table_name, values)


class FakeExistingTable(object):
    def __init__(self, name):
        self.name = name

    def create(self, bind=None, checkfirst=True):
        return None


class FakeSchemaInspector(object):
    def get_columns(self, table_name):
        columns = ["id", "enabled"]
        if table_name == "aria_acl_rules":
            columns.extend(["policy_id", "direction", "priority"])
        elif table_name == "aria_acl_bindings":
            columns.extend(["target_type", "target_id"])
        return [{"name": name} for name in columns]


class FakeSchemaSqlAlchemy(object):
    @staticmethod
    def inspect(_bind):
        return FakeSchemaInspector()


class FakeSchemaSession(object):
    @staticmethod
    def get_bind():
        return object()


class RepositoryWriteInvariantBehavior(object):
    def setUp(self):
        self.repository = self.make_repository()

    def tearDown(self):
        self.close_repository()

    def make_repository(self):
        raise NotImplementedError

    def close_repository(self):
        pass

    def seed_legacy_address_set(self, members):
        raise NotImplementedError

    def create_policy(self, policy_id="policy-1", project_id="project-1"):
        return self.repository.create_policy({
            "id": policy_id,
            "project_id": project_id,
            "default_action": "allow",
        })

    def create_address_set(
        self,
        address_set_id="set-1",
        project_id="project-1",
        enabled=True,
        members=None,
    ):
        if members is None:
            members = ["10.0.0.1/32"]
        return self.repository.create_address_set({
            "id": address_set_id,
            "project_id": project_id,
            "enabled": enabled,
            "members": members,
        })

    @staticmethod
    def rule_values(rule_id="rule-1", **overrides):
        values = {
            "id": rule_id,
            "project_id": "project-1",
            "policy_id": "policy-1",
            "direction": "ingress",
            "priority": 10,
            "action": "allow",
        }
        values.update(overrides)
        return values

    @staticmethod
    def binding_values(binding_id="binding-1", **overrides):
        values = {
            "id": binding_id,
            "project_id": "project-1",
            "policy_id": "policy-1",
            "target_type": "port",
            "target_id": "port-1",
        }
        values.update(overrides)
        return values

    @staticmethod
    def raw_members(count):
        return [
            "10.%d.%d.%d/32" % (
                (index >> 16) & 0xff,
                (index >> 8) & 0xff,
                index & 0xff,
            )
            for index in range(count)
        ]

    def assert_create_rule_rejected(self, values):
        before = self.repository.list_rules()
        error = None
        try:
            self.repository.create_rule(values)
        except AriaAclValidationError as exc:
            error = exc
        self.assertIsInstance(error, AriaAclValidationError)
        self.assertEqual(before, self.repository.list_rules())

    def assert_rule_update_rejected(self, rule_id, values):
        before = self.repository.get_rule(rule_id)
        error = None
        try:
            self.repository.update_rule(rule_id, values)
        except AriaAclValidationError as exc:
            error = exc
        self.assertIsInstance(error, AriaAclValidationError)
        self.assertEqual(before, self.repository.get_rule(rule_id))

    def assert_address_set_update_rejected(self, address_set_id, values):
        before = self.repository.get_address_set(address_set_id)
        error = None
        try:
            self.repository.update_address_set(address_set_id, values)
        except AriaAclValidationError as exc:
            error = exc
        self.assertIsInstance(error, AriaAclValidationError)
        self.assertEqual(before, self.repository.get_address_set(address_set_id))

    def create_referenced_set(self):
        self.create_policy()
        self.create_address_set()
        self.repository.create_rule(self.rule_values(src_address_set_id="set-1"))

    def test_rule_write_canonicalizes_direct_cidrs(self):
        self.create_policy()
        rule = self.repository.create_rule(self.rule_values(
            src_cidr=" 10.1.2.3/24 ",
            dst_cidr="192.0.2.19/28",
        ))
        self.assertEqual("10.1.2.0/24", rule["src_cidr"])
        self.assertEqual("192.0.2.16/28", rule["dst_cidr"])
        self.assertEqual(rule, self.repository.get_rule("rule-1"))

    def test_address_set_write_canonicalizes_deduplicates_and_sorts(self):
        address_set = self.create_address_set(members=[
            "10.0.1.9/24",
            {"address": "10.0.0.2/24"},
            {"address": "10.0.1.1/24"},
        ])
        expected = [
            {"address": "10.0.0.0/24"},
            {"address": "10.0.1.0/24"},
        ]
        self.assertEqual(expected, address_set["members"])
        self.assertEqual(
            expected,
            self.repository.get_address_set("set-1")["members"],
        )

    def test_address_set_accepts_2048_raw_members(self):
        address_set = self.create_address_set(members=self.raw_members(2048))
        self.assertEqual(2048, len(address_set["members"]))

    def test_address_set_rejects_2049_raw_members_before_deduplication(self):
        repeated = ["10.0.0.1/32"] * 2049
        before = self.repository.list_address_sets()
        error = None
        try:
            self.create_address_set(members=repeated)
        except AriaAclValidationError as exc:
            error = exc
        self.assertIsInstance(error, AriaAclValidationError)
        self.assertEqual(before, self.repository.list_address_sets())

    def test_rule_create_rejects_missing_address_set(self):
        self.create_policy()
        self.assert_create_rule_rejected(
            self.rule_values(src_address_set_id="missing")
        )

    def test_rule_create_rejects_disabled_address_set(self):
        self.create_policy()
        self.create_address_set(enabled=False)
        self.assert_create_rule_rejected(
            self.rule_values(src_address_set_id="set-1")
        )

    def test_rule_create_rejects_empty_address_set(self):
        self.create_policy()
        self.create_address_set(members=[])
        self.assert_create_rule_rejected(
            self.rule_values(dst_address_set_id="set-1")
        )

    def test_rule_create_rejects_invalid_address_set_member(self):
        self.create_policy()
        self.seed_legacy_address_set(["10.1/16"])
        self.assert_create_rule_rejected(
            self.rule_values(src_address_set_id="set-1")
        )

    def test_rule_create_rejects_cross_project_address_set(self):
        self.create_policy()
        self.create_address_set(project_id="project-2")
        self.assert_create_rule_rejected(
            self.rule_values(dst_address_set_id="set-1")
        )

    def test_rule_create_rejects_oversized_address_set(self):
        self.create_policy()
        self.seed_legacy_address_set(self.raw_members(2049))
        self.assert_create_rule_rejected(
            self.rule_values(src_address_set_id="set-1")
        )

    def test_rule_update_rejects_invalid_reference_and_preserves_preimage(self):
        self.create_policy()
        self.repository.create_rule(self.rule_values())
        self.assert_rule_update_rejected(
            "rule-1",
            {"src_address_set_id": "missing"},
        )

    def test_referenced_address_set_cannot_be_disabled(self):
        self.create_referenced_set()
        self.assert_address_set_update_rejected("set-1", {"enabled": False})

    def test_referenced_address_set_cannot_be_emptied(self):
        self.create_referenced_set()
        self.assert_address_set_update_rejected("set-1", {"members": []})

    def test_referenced_address_set_rejects_invalid_members(self):
        self.create_referenced_set()
        self.assert_address_set_update_rejected(
            "set-1",
            {"members": ["10.1/16"]},
        )

    def test_referenced_address_set_rejects_oversized_members(self):
        self.create_referenced_set()
        self.assert_address_set_update_rejected(
            "set-1",
            {"members": self.raw_members(2049)},
        )

    def test_referenced_address_set_rejects_project_change(self):
        self.create_referenced_set()
        self.assert_address_set_update_rejected(
            "set-1",
            {"project_id": "project-2"},
        )

    def test_unreferenced_address_set_may_be_empty_or_disabled(self):
        empty = self.create_address_set(members=[])
        self.assertEqual([], empty["members"])
        updated = self.repository.update_address_set(
            "set-1",
            {"enabled": False},
        )
        self.assertFalse(updated["enabled"])

    def test_rule_update_rejects_immutable_identity_changes(self):
        self.create_policy()
        self.create_policy(policy_id="policy-2")
        self.repository.create_rule(self.rule_values())
        self.assert_rule_update_rejected(
            "rule-1",
            {
                "id": "rule-other",
                "policy_id": "policy-2",
            },
        )

    def test_policy_update_rejects_immutable_identity_changes(self):
        self.create_policy()
        before = self.repository.get_policy("policy-1")
        error = None
        try:
            self.repository.update_policy("policy-1", {
                "id": "policy-other",
                "project_id": "project-2",
            })
        except AriaAclValidationError as exc:
            error = exc
        self.assertIsInstance(error, AriaAclValidationError)
        self.assertEqual(before, self.repository.get_policy("policy-1"))

    def test_address_set_update_rejects_immutable_identity_changes(self):
        self.create_address_set()
        self.assert_address_set_update_rejected(
            "set-1",
            {
                "id": "set-other",
                "project_id": "project-2",
            },
        )

    def test_binding_update_rejects_immutable_identity_changes(self):
        self.create_policy()
        self.create_policy(policy_id="policy-2")
        self.repository.create_binding(self.binding_values())
        before = self.repository.get_binding("binding-1")
        error = None
        try:
            self.repository.update_binding("binding-1", {
                "id": "binding-other",
                "policy_id": "policy-2",
                "target_type": "network",
                "target_id": "network-2",
            })
        except AriaAclValidationError as exc:
            error = exc
        self.assertEqual(before, self.repository.get_binding("binding-1"))
        self.assertIsInstance(error, AriaAclValidationError)

    def test_repository_exposes_distinct_conflict_type(self):
        conflict_type = getattr(aria_acl_api, "AriaAclConflictError", None)
        self.assertIsNotNone(
            conflict_type,
            "repository conflict type is missing",
        )
        self.assertTrue(issubclass(conflict_type, aria_acl_api.AriaAclError))
        self.assertFalse(issubclass(conflict_type, AriaAclValidationError))

    def test_duplicate_enabled_rule_raises_conflict(self):
        self.create_policy()
        self.repository.create_rule(self.rule_values())
        conflict_type = getattr(aria_acl_api, "AriaAclConflictError", None)
        self.assertIsNotNone(conflict_type, "repository conflict type is missing")
        with self.assertRaises(conflict_type):
            self.repository.create_rule(self.rule_values(
                rule_id="rule-2",
                action="deny",
            ))

    def test_duplicate_enabled_binding_raises_conflict(self):
        self.create_policy()
        self.repository.create_binding(self.binding_values())
        conflict_type = getattr(aria_acl_api, "AriaAclConflictError", None)
        self.assertIsNotNone(conflict_type, "repository conflict type is missing")
        with self.assertRaises(conflict_type):
            self.repository.create_binding(self.binding_values(
                binding_id="binding-2",
                policy_id="policy-1",
            ))

    def test_conflicting_rule_update_preserves_preimage(self):
        self.create_policy()
        self.repository.create_rule(self.rule_values())
        self.repository.create_rule(self.rule_values(
            rule_id="rule-2",
            priority=20,
        ))
        before = self.repository.get_rule("rule-2")
        conflict_type = getattr(aria_acl_api, "AriaAclConflictError", None)
        self.assertIsNotNone(conflict_type, "repository conflict type is missing")
        with self.assertRaises(conflict_type):
            self.repository.update_rule("rule-2", {"priority": 10})
        self.assertEqual(before, self.repository.get_rule("rule-2"))

    def test_disabled_rule_cannot_enable_into_conflicting_key(self):
        self.create_policy()
        self.repository.create_rule(self.rule_values())
        self.repository.create_rule(self.rule_values(
            rule_id="rule-2",
            enabled=False,
        ))
        before = self.repository.get_rule("rule-2")
        conflict_type = getattr(aria_acl_api, "AriaAclConflictError", None)
        self.assertIsNotNone(conflict_type, "repository conflict type is missing")
        with self.assertRaises(conflict_type):
            self.repository.update_rule("rule-2", {"enabled": True})
        self.assertEqual(before, self.repository.get_rule("rule-2"))

    def test_disabled_binding_cannot_enable_into_conflicting_key(self):
        self.create_policy()
        self.repository.create_binding(self.binding_values())
        self.repository.create_binding(self.binding_values(
            binding_id="binding-2",
            enabled=False,
        ))
        before = self.repository.get_binding("binding-2")
        conflict_type = getattr(aria_acl_api, "AriaAclConflictError", None)
        self.assertIsNotNone(conflict_type, "repository conflict type is missing")
        with self.assertRaises(conflict_type):
            self.repository.update_binding("binding-2", {"enabled": True})
        self.assertEqual(before, self.repository.get_binding("binding-2"))

    def test_disabled_duplicate_keys_remain_legal(self):
        self.create_policy()
        first = self.repository.create_rule(self.rule_values(enabled=False))
        second = self.repository.create_rule(self.rule_values(
            rule_id="rule-2",
            enabled=False,
        ))
        self.assertFalse(first["enabled"])
        self.assertFalse(second["enabled"])
        binding_one = self.repository.create_binding(
            self.binding_values(enabled=False)
        )
        binding_two = self.repository.create_binding(self.binding_values(
            binding_id="binding-2",
            enabled=False,
        ))
        self.assertFalse(binding_one["enabled"])
        self.assertFalse(binding_two["enabled"])


class InMemoryWriteInvariantTestCase(
    RepositoryWriteInvariantBehavior,
    unittest.TestCase,
):
    def make_repository(self):
        return InMemoryAriaAclRepository()

    def seed_legacy_address_set(self, members):
        self.repository.address_sets["set-1"] = {
            "id": "set-1",
            "project_id": "project-1",
            "enabled": True,
            "members": copy.deepcopy(members),
            "revision_number": 1,
        }


class SqliteWriteInvariantTestCase(
    RepositoryWriteInvariantBehavior,
    unittest.TestCase,
):
    def make_repository(self):
        file_descriptor, self.path = tempfile.mkstemp()
        os.close(file_descriptor)
        return SqliteAriaAclRepository(self.path)

    def close_repository(self):
        self.repository.close()
        os.unlink(self.path)

    def seed_legacy_address_set(self, members):
        payload = {
            "id": "set-1",
            "project_id": "project-1",
            "enabled": True,
            "members": copy.deepcopy(members),
            "revision_number": 1,
        }
        self.repository.connection.execute(
            "INSERT INTO aria_acl_address_sets (id, project_id, payload) "
            "VALUES (?, ?, ?)",
            ("set-1", "project-1", json.dumps(payload, sort_keys=True)),
        )
        self.repository.connection.commit()

    def test_sqlite_schema_has_enabled_guard_unique_indexes(self):
        rule_columns = [
            row[1]
            for row in self.repository.connection.execute(
                "PRAGMA table_info(aria_acl_rules)"
            ).fetchall()
        ]
        binding_columns = [
            row[1]
            for row in self.repository.connection.execute(
                "PRAGMA table_info(aria_acl_bindings)"
            ).fetchall()
        ]
        self.assertIn("enabled_guard", rule_columns)
        self.assertIn("direction", rule_columns)
        self.assertIn("priority", rule_columns)
        self.assertIn("enabled_guard", binding_columns)

        rule_indexes = dict(
            (row[1], bool(row[2]))
            for row in self.repository.connection.execute(
                "PRAGMA index_list(aria_acl_rules)"
            ).fetchall()
        )
        binding_indexes = dict(
            (row[1], bool(row[2]))
            for row in self.repository.connection.execute(
                "PRAGMA index_list(aria_acl_bindings)"
            ).fetchall()
        )
        self.assertTrue(rule_indexes["uq_aria_acl_rules_enabled_priority"])
        self.assertTrue(binding_indexes["uq_aria_acl_bindings_enabled_target"])

    def test_sqlite_unique_indexes_are_final_concurrency_authority(self):
        self.test_sqlite_schema_has_enabled_guard_unique_indexes()
        connection = self.repository.connection
        connection.execute(
            "INSERT INTO aria_acl_rules "
            "(id, project_id, policy_id, direction, priority, enabled_guard, payload) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            ("rule-raw-1", "project-1", "policy-1", "ingress", 10, 1, "{}"),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO aria_acl_rules "
                "(id, project_id, policy_id, direction, priority, enabled_guard, payload) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                ("rule-raw-2", "project-1", "policy-1", "ingress", 10, 1, "{}"),
            )
        connection.execute(
            "INSERT INTO aria_acl_bindings "
            "(id, project_id, policy_id, target_type, target_id, "
            "enabled_guard, payload) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                "binding-raw-1",
                "project-1",
                "policy-1",
                "port",
                "port-1",
                1,
                "{}",
            ),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            connection.execute(
                "INSERT INTO aria_acl_bindings "
                "(id, project_id, policy_id, target_type, target_id, "
                "enabled_guard, payload) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    "binding-raw-2",
                    "project-1",
                    "policy-1",
                    "port",
                    "port-1",
                    1,
                    "{}",
                ),
            )


class NeutronDbMethodWriteInvariantTestCase(
    RepositoryWriteInvariantBehavior,
    unittest.TestCase,
):
    def make_repository(self):
        return NeutronDbMethodAdapter()

    def seed_legacy_address_set(self, members):
        self.repository.rows["address_sets"]["set-1"] = {
            "id": "set-1",
            "project_id": "project-1",
            "enabled": True,
            "members": copy.deepcopy(members),
            "revision_number": 1,
        }


class ConcurrentWriteInvariantTestCase(unittest.TestCase):
    def test_in_memory_concurrent_rule_writers_return_conflicts(self):
        repository = InMemoryAriaAclRepository()
        repository.create_policy({
            "id": "policy-1",
            "project_id": "project-1",
            "default_action": "allow",
        })
        start_gate = threading.Event()
        results = []
        results_lock = threading.Lock()

        def create_rule(index):
            start_gate.wait()
            try:
                repository.create_rule({
                    "id": "rule-%d" % index,
                    "project_id": "project-1",
                    "policy_id": "policy-1",
                    "direction": "ingress",
                    "priority": 10,
                    "action": "allow",
                })
                result = "success"
            except Exception as exc:
                result = exc
            with results_lock:
                results.append(result)

        threads = [
            threading.Thread(target=create_rule, args=(index,))
            for index in range(8)
        ]
        for thread in threads:
            thread.start()
        start_gate.set()
        for thread in threads:
            thread.join(5)
            self.assertFalse(thread.is_alive(), "concurrent writer did not terminate")

        conflict_type = getattr(aria_acl_api, "AriaAclConflictError", None)
        self.assertIsNotNone(conflict_type, "repository conflict type is missing")
        self.assertEqual(1, results.count("success"))
        conflicts = [result for result in results if result != "success"]
        self.assertEqual(7, len(conflicts))
        self.assertTrue(all(isinstance(error, conflict_type) for error in conflicts))
        self.assertEqual(1, len(repository.list_rules()))

    def test_named_database_constraint_failure_maps_to_repository_conflict(self):
        repository = ConstraintFailureNeutronAdapter()
        repository.create_policy({
            "id": "policy-1",
            "project_id": "project-1",
            "default_action": "allow",
        })
        cases = (
            (
                "uq_aria_acl_rules_enabled_priority",
                "duplicate_enabled_rule_priority",
                lambda: repository.create_rule({
                    "id": "rule-1",
                    "project_id": "project-1",
                    "policy_id": "policy-1",
                    "direction": "ingress",
                    "priority": 10,
                    "action": "allow",
                }),
            ),
            (
                "uq_aria_acl_bindings_enabled_target",
                "duplicate_enabled_binding_target",
                lambda: repository.create_binding({
                    "id": "binding-1",
                    "project_id": "project-1",
                    "policy_id": "policy-1",
                    "target_type": "port",
                    "target_id": "port-1",
                }),
            ),
        )
        conflict_type = getattr(aria_acl_api, "AriaAclConflictError", None)
        self.assertIsNotNone(conflict_type, "repository conflict type is missing")
        for constraint_name, reason, operation in cases:
            repository.failed_constraint = constraint_name
            error = None
            try:
                operation()
            except Exception as exc:
                error = exc
            self.assertIsInstance(error, conflict_type)
            self.assertIn(reason, str(error))

    def test_unknown_database_constraint_failure_is_not_reclassified(self):
        repository = ConstraintFailureNeutronAdapter()
        repository.create_policy({
            "id": "policy-1",
            "project_id": "project-1",
            "default_action": "allow",
        })
        repository.failed_constraint = "uq_unrelated_storage_contract"
        with self.assertRaises(FakeConstraintError):
            repository.create_rule({
                "id": "rule-1",
                "project_id": "project-1",
                "policy_id": "policy-1",
                "direction": "ingress",
                "priority": 10,
                "action": "allow",
            })

    def test_neutron_repository_rejects_schema_without_guard_columns(self):
        repository = object.__new__(NeutronDbAriaAclRepository)
        repository.session = FakeSchemaSession()
        repository.sa = FakeSchemaSqlAlchemy()
        repository.tables = {
            "rules": FakeExistingTable("aria_acl_rules"),
            "bindings": FakeExistingTable("aria_acl_bindings"),
        }
        error = None
        try:
            repository.ensure_schema()
        except AriaAclValidationError as exc:
            error = exc
        self.assertIsInstance(error, AriaAclValidationError)
        self.assertIn("aria_acl_schema_migration_required", str(error))


if __name__ == "__main__":
    unittest.main()

from __future__ import absolute_import

import inspect
import os
import tempfile
import unittest

from neutron_aria.db.aria_acl.api import AriaAclNotFound
from neutron_aria.db.aria_acl.api import AriaAclValidationError
from neutron_aria.db.aria_acl.api import SqliteAriaAclRepository
from neutron_aria.db.migration import aria_acl_initial
from neutron_aria.extensions import aria_acl
from neutron_aria.policies import aria_acl as aria_acl_policy
from neutron_aria.services.aria_acl.exceptions import AriaAclBadRequest
from neutron_aria.services.aria_acl.exceptions import AriaAclConflict
from neutron_aria.services.aria_acl.exceptions import map_repository_error
from neutron_aria.services.aria_acl.plugin import AriaAclAgentNotifier
from neutron_aria.services.aria_acl.plugin import AriaAclPlugin


class FakeSqlAlchemy(object):
    def Column(self, name, column_type, nullable=True, primary_key=False):
        return {
            "name": name,
            "type": column_type,
            "nullable": nullable,
            "primary_key": primary_key,
        }

    def String(self, length=None):
        return ("String", length)

    def Text(self):
        return ("Text", None)

    def Boolean(self):
        return ("Boolean", None)

    def Integer(self):
        return ("Integer", None)

    def BigInteger(self):
        return ("BigInteger", None)

    def DateTime(self):
        return ("DateTime", None)


class FakeAlembicOp(object):
    def __init__(self):
        self.created_tables = []
        self.created_indexes = []
        self.dropped_indexes = []
        self.dropped_tables = []

    def create_table(self, table_name, *columns):
        self.created_tables.append((table_name, columns))

    def create_index(self, name, table_name, columns, unique=False):
        self.created_indexes.append((name, table_name, tuple(columns), unique))

    def drop_index(self, name, table_name=None):
        self.dropped_indexes.append((name, table_name))

    def drop_table(self, table_name):
        self.dropped_tables.append(table_name)


class FakeResourceHelper(object):
    def __init__(self):
        self.resource_maps = []
        self.service_types = []
        self.special_mappings = []

    def build_plural_mappings(self, special_mappings, resource_map):
        self.special_mappings.append(special_mappings)
        self.resource_maps.append(resource_map)
        return dict((name, name) for name in resource_map)

    def build_resource_info(
        self,
        _plural_mappings,
        resource_map,
        service_type,
        translate_name=True,
        allow_bulk=True,
    ):
        self.resource_maps.append(resource_map)
        self.service_types.append(service_type)
        return sorted(resource_map)


class FakeNotifier(object):
    def __init__(self):
        self.events = []

    def notify(self, context, **payload):
        self.events.append((context, payload))


class FakeTopics(object):
    AGENT = "q-agent-notifier"
    UPDATE = "update"


class FakeRpcClient(object):
    def __init__(self):
        self.prepared = []

    def prepare(self, **kwargs):
        cctxt = FakePreparedClient(kwargs)
        self.prepared.append(cctxt)
        return cctxt


class FakePreparedClient(object):
    def __init__(self, prepare_kwargs):
        self.prepare_kwargs = prepare_kwargs
        self.casts = []

    def cast(self, context, method, **payload):
        self.casts.append((context, method, payload))


class RecordingListRepository(object):
    def __init__(self):
        self.calls = []

    def _record(self, collection, values):
        self.calls.append((collection, values))
        if collection == "policies":
            return [{"id": "policy-1"}]
        return []

    def list_policies(self, **kwargs):
        return self._record("policies", kwargs)

    def list_rules(self, **kwargs):
        return self._record("rules", kwargs)

    def list_address_sets(self, **kwargs):
        return self._record("address_sets", kwargs)

    def list_bindings(self, **kwargs):
        return self._record("bindings", kwargs)

    def list_port_statuses(self, **kwargs):
        return self._record("port_statuses", kwargs)


class AriaAclPluginTestCase(unittest.TestCase):
    def test_repository_errors_map_to_legacy_http_semantics(self):
        bad_request = map_repository_error(AriaAclValidationError("invalid"))
        not_found = map_repository_error(AriaAclNotFound("missing"))
        self.assertEqual(400, bad_request.status_code)
        self.assertEqual(404, not_found.status_code)

    def test_unexpected_repository_error_is_not_mapped(self):
        error = RuntimeError("database offline")
        self.assertIs(error, map_repository_error(error))

    def test_policy_rejects_unsupported_default_deny(self):
        plugin = AriaAclPlugin()
        with self.assertRaises(AriaAclBadRequest):
            plugin.create_aria_acl_policy(None, {
                "aria_acl_policy": {
                    "project_id": "project-1",
                    "default_action": "deny",
                }
            })

    def test_priority_zero_is_valid_but_duplicate_priority_is_rejected(self):
        plugin = AriaAclPlugin()
        policy = plugin.create_aria_acl_policy(None, {
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
                "policy_id": policy["id"],
                "direction": "ingress",
                "priority": 0,
                "action": "allow",
            }
        })
        with self.assertRaises(AriaAclConflict):
            plugin.create_aria_acl_rule(None, {
                "aria_acl_rule": {
                    "id": "rule-2",
                    "project_id": "project-1",
                    "policy_id": policy["id"],
                    "direction": "ingress",
                    "priority": 0,
                    "action": "drop",
                }
            })

    def test_duplicate_enabled_binding_for_target_is_rejected(self):
        plugin = AriaAclPlugin()
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
        with self.assertRaises(AriaAclConflict):
            plugin.create_aria_acl_binding(None, {
                "aria_acl_binding": {
                    "id": "binding-2",
                    "project_id": "project-1",
                    "policy_id": "policy-2",
                    "target_type": "port",
                    "target_id": "port-1",
                }
            })

    def test_extension_exposes_expected_resources_and_port_summary_fields(self):
        resources = aria_acl.get_resources()
        extended = aria_acl.get_extended_resources("2.0")
        plugin = AriaAclPlugin()

        self.assertEqual("aria-acl", aria_acl.get_alias())
        self.assertEqual("aria-acl", aria_acl.Aria_acl.get_alias())
        self.assertEqual("Aria ACL", aria_acl.Aria_acl.get_name())
        self.assertEqual("aria_acl", plugin.get_plugin_type())
        self.assertIn("Aria ACL", plugin.get_plugin_description())
        self.assertIn("aria_acl_policies", resources)
        self.assertIn("aria_acl_rules", resources)
        self.assertIn("aria_acl_address_sets", resources)
        self.assertIn("aria_acl_bindings", resources)
        self.assertIn("aria_acl_port_statuses", resources)
        self.assertIn("ports", extended)
        self.assertIn("aria_acl_policies", extended)
        self.assertIn("aria_acl_rules", extended)
        self.assertIn("aria_acl_address_sets", extended)
        self.assertIn("aria_acl_bindings", extended)
        self.assertIn("aria_acl_port_statuses", extended)
        self.assertIn("members", extended["aria_acl_address_sets"])
        self.assertIn("target_type", extended["aria_acl_bindings"])
        self.assertIn("status", extended["aria_acl_port_statuses"])
        self.assertIn("effective_action", extended["aria_acl_port_statuses"])
        self.assertIn("last_reported_at", extended["aria_acl_port_statuses"])
        self.assertIn("stale", extended["aria_acl_port_statuses"])
        self.assertIn("runtime_status", extended["aria_acl_port_statuses"])
        self.assertFalse(extended["aria_acl_port_statuses"]["stale"]["allow_post"])
        self.assertFalse(extended["aria_acl_port_statuses"]["runtime_status"]["allow_put"])
        self.assertIn("tenant_id", extended["aria_acl_policies"])
        self.assertIn("tenant_id", extended["aria_acl_rules"])
        self.assertIn("tenant_id", extended["aria_acl_address_sets"])
        self.assertIn("tenant_id", extended["aria_acl_bindings"])
        self.assertIn("tenant_id", extended["aria_acl_port_statuses"])
        self.assertIn("aria_acl_enabled", extended["ports"])
        self.assertFalse(extended["ports"]["aria_acl_enabled"]["allow_post"])
        self.assertFalse(extended["ports"]["aria_acl_enabled"]["allow_put"])

    def test_plugin_advertises_native_sorting_and_pagination(self):
        plugin = AriaAclPlugin()
        self.assertTrue(
            hasattr(plugin, "_AriaAclPlugin__native_sorting_support")
        )
        self.assertTrue(
            hasattr(plugin, "_AriaAclPlugin__native_pagination_support")
        )
        self.assertTrue(
            getattr(plugin, "_AriaAclPlugin__native_sorting_support")
        )
        self.assertTrue(
            getattr(plugin, "_AriaAclPlugin__native_pagination_support")
        )

    def test_all_public_collections_declare_one_primary_id(self):
        for collection in aria_acl.RESOURCE_COLLECTIONS.values():
            attributes = aria_acl.API_RESOURCE_ATTRIBUTE_MAP[collection]
            primary = sorted(
                name for name, descriptor in attributes.items()
                if descriptor.get("primary_key")
            )
            self.assertEqual(["id"], primary, collection)

    def test_plugin_forwards_complete_list_contract(self):
        repository = RecordingListRepository()
        plugin = AriaAclPlugin(repository=repository, now=lambda: 200.0)
        list_methods = (
            ("policies", plugin.get_aria_acl_policies),
            ("rules", plugin.get_aria_acl_rules),
            ("address_sets", plugin.get_aria_acl_address_sets),
            ("bindings", plugin.get_aria_acl_bindings),
        )
        expected = {
            "filters": {"enabled": ["true"]},
            "fields": ["id"],
            "sorts": [("name", False)],
            "limit": 10,
            "marker": "policy-2",
            "page_reverse": True,
        }

        for collection, method in list_methods:
            method(
                None,
                filters=expected["filters"],
                fields=expected["fields"],
                sorts=expected["sorts"],
                limit=expected["limit"],
                marker=expected["marker"],
                page_reverse=expected["page_reverse"],
            )
            self.assertEqual(collection, repository.calls[-1][0])
            self.assertEqual(expected, repository.calls[-1][1])

    def test_plugin_forwards_one_immutable_status_projection(self):
        repository = RecordingListRepository()
        plugin = AriaAclPlugin(
            repository=repository,
            port_status_stale_seconds=90,
            now=lambda: 200.0,
        )
        plugin.get_aria_acl_port_statuses(
            None,
            filters={"stale": ["true"]},
            fields=["id", "runtime_status"],
            sorts=[("id", True)],
            limit=10,
            marker="status-1",
            page_reverse=True,
        )

        collection, kwargs = repository.calls[-1]
        self.assertEqual("port_statuses", collection)
        self.assertEqual(
            {
                "filters",
                "fields",
                "sorts",
                "limit",
                "marker",
                "page_reverse",
                "projection",
            },
            set(kwargs),
        )
        self.assertEqual({"stale": ["true"]}, kwargs["filters"])
        self.assertEqual(["id", "runtime_status"], kwargs["fields"])
        self.assertEqual([("id", True)], kwargs["sorts"])
        self.assertEqual(10, kwargs["limit"])
        self.assertEqual("status-1", kwargs["marker"])
        self.assertTrue(kwargs["page_reverse"])
        self.assertEqual(200.0, kwargs["projection"].now_epoch)
        self.assertEqual(90, kwargs["projection"].stale_seconds)

    def test_multi_host_legacy_status_show_is_conflict(self):
        plugin = AriaAclPlugin(now=lambda: 200.0)
        for host in ("ostack2", "ostack3"):
            plugin.report_aria_acl_port_status(None, {
                "aria_acl_port_status": {
                    "port_id": "port-1",
                    "host": host,
                    "status": "ready",
                }
            })

        with self.assertRaises(AriaAclConflict):
            plugin.get_aria_acl_port_status(None, "port-1")

    def test_derived_status_id_show_is_exact(self):
        try:
            from neutron_aria.db.aria_acl import query as query_contract
        except ImportError:
            query_contract = None
        self.assertIsNotNone(
            query_contract,
            "the versioned status identity contract must exist",
        )
        plugin = AriaAclPlugin(now=lambda: 200.0)
        for host in ("ostack2", "ostack3"):
            plugin.report_aria_acl_port_status(None, {
                "aria_acl_port_status": {
                    "port_id": "port-1",
                    "host": host,
                    "status": "ready",
                }
            })
        exact_id = query_contract.encode_port_status_id("port-1", "ostack3")
        status = plugin.get_aria_acl_port_status(None, exact_id)
        self.assertIsNotNone(status)
        self.assertEqual("ostack3", status["host"])

    def test_missing_status_for_explicit_host_remains_none(self):
        plugin = AriaAclPlugin(now=lambda: 200.0)

        self.assertIsNone(
            plugin.get_aria_acl_port_status(
                None,
                "port-missing",
                host="ostack2",
            )
        )

    def test_derived_status_id_delete_removes_only_exact_host(self):
        from neutron_aria.db.aria_acl.query import encode_port_status_id

        plugin = AriaAclPlugin(now=lambda: 200.0)
        for host in ("ostack2", "ostack3"):
            plugin.report_aria_acl_port_status(None, {
                "port_id": "port-1",
                "host": host,
                "status": "ready",
            })

        plugin.delete_aria_acl_port_status(
            None,
            encode_port_status_id("port-1", "ostack2"),
        )

        statuses = plugin.get_aria_acl_port_statuses(
            None,
            filters={"port_id": ["port-1"]},
        )
        self.assertEqual(["ostack3"], [status["host"] for status in statuses])

    def test_legacy_status_delete_removes_all_hosts(self):
        plugin = AriaAclPlugin(now=lambda: 200.0)
        for host in ("ostack2", "ostack3"):
            plugin.report_aria_acl_port_status(None, {
                "port_id": "port-1",
                "host": host,
                "status": "ready",
            })

        plugin.delete_aria_acl_port_status(None, "port-1")

        self.assertEqual(
            [],
            plugin.get_aria_acl_port_statuses(
                None,
                filters={"port_id": ["port-1"]},
            ),
        )

    def test_resource_helper_does_not_create_ports_resource(self):
        original_helper = aria_acl.resource_helper
        fake_helper = FakeResourceHelper()
        try:
            aria_acl.resource_helper = fake_helper

            resources = aria_acl.get_resources()

            self.assertNotIn("ports", resources)
            self.assertIn(
                {"aria_acl_port_statuses": "aria_acl_port_status"},
                fake_helper.special_mappings,
            )
            for resource_map in fake_helper.resource_maps:
                self.assertNotIn("ports", resource_map)
            self.assertEqual(["aria_acl"], fake_helper.service_types)
            self.assertIn("ports", aria_acl.get_extended_resources("2.0"))
        finally:
            aria_acl.resource_helper = original_helper

    def test_migration_contract_names_all_product_tables(self):
        tables = aria_acl_initial.table_names()

        self.assertIn("aria_acl_policies", tables)
        self.assertIn("aria_acl_rules", tables)
        self.assertIn("aria_acl_address_sets", tables)
        self.assertIn("aria_acl_address_set_members", tables)
        self.assertIn("aria_acl_bindings", tables)
        self.assertIn("aria_acl_rbac", tables)
        self.assertIn("aria_acl_port_statuses", tables)
        self.assertEqual(("4af11ca47297", "2948f8b16a0c"), aria_acl_initial.down_revision)

    def test_migration_upgrade_and_downgrade_emit_alembic_operations(self):
        op = FakeAlembicOp()

        upgraded = aria_acl_initial.upgrade(op_handle=op, sa_module=FakeSqlAlchemy())
        downgraded = aria_acl_initial.downgrade(op_handle=op)

        self.assertEqual(aria_acl_initial.table_names(), upgraded)
        self.assertEqual(aria_acl_initial.table_names(), downgraded)
        self.assertEqual(aria_acl_initial.table_names(), [
            table_name for table_name, _columns in op.created_tables
        ])
        self.assertIn(
            ("ix_aria_acl_bindings_target", "aria_acl_bindings",
             ("target_type", "target_id"), False),
            op.created_indexes,
        )
        self.assertEqual(aria_acl_initial.table_names(), sorted(op.dropped_tables))

    def test_rbac_contract_is_admin_write_and_agent_read_status(self):
        rules = aria_acl_policy.list_rules()

        self.assertEqual("role:admin", rules["create_aria_acl_policy"])
        self.assertEqual("role:admin", rules["create_aria_acl_binding"])
        self.assertEqual("role:admin", rules["update_aria_acl_binding"])
        self.assertEqual("role:admin or role:service", rules["get_aria_acl_effective"])
        self.assertEqual(
            "role:admin or role:service",
            rules["report_aria_acl_port_status"],
        )
        self.assertEqual(
            "role:admin or role:service",
            rules["create_aria_acl_port_status"],
        )
        self.assertEqual(
            "role:admin or role:service",
            rules["update_aria_acl_port_status"],
        )
        self.assertEqual(
            "role:admin or role:service",
            rules["get_aria_acl_port_status:runtime_status"],
        )
        self.assertEqual(
            "role:admin or role:service",
            rules["get_aria_acl_port_status:stale"],
        )
        self.assertEqual(
            "role:admin or role:service",
            rules["get_aria_acl_port_status:last_reported_at"],
        )
        self.assertEqual(
            "role:admin or role:service",
            rules["delete_aria_acl_port_status"],
        )

    def test_policy_rule_binding_effective_read(self):
        plugin = AriaAclPlugin()
        policy = plugin.create_aria_acl_policy(None, {
            "aria_acl_policy": {
                "id": "policy-1",
                "project_id": "project-1",
                "name": "web",
                "default_action": "allow",
            }
        })
        plugin.create_aria_acl_rule(None, {
            "aria_acl_rule": {
                "id": "rule-1",
                "project_id": "project-1",
                "policy_id": policy["id"],
                "direction": "ingress",
                "priority": 100,
                "action": "drop",
                "protocol": "tcp",
                "dst_port_min": 22,
                "dst_port_max": 22,
                "src_cidr": "10.58.159.2/32",
            }
        })
        plugin.create_aria_acl_binding(None, {
            "aria_acl_binding": {
                "id": "binding-1",
                "project_id": "project-1",
                "policy_id": policy["id"],
                "target_type": "port",
                "target_id": "port-1",
            }
        })

        result = plugin.get_aria_acl_effective_for_port(None, {
            "id": "port-1",
            "network_id": "net-1",
        })

        self.assertTrue(result["enabled"])
        self.assertEqual("enforce", result["effective_action"])
        self.assertEqual("policy-1", result["policy_id"])
        self.assertEqual("rule-1", result["rules"][0]["id"])

    def test_minimum_crud_updates_revision_and_effective_acl(self):
        plugin = AriaAclPlugin()
        plugin.create_aria_acl_policy(None, {
            "id": "policy-1",
            "project_id": "project-1",
            "name": "web",
            "default_action": "allow",
        })
        plugin.create_aria_acl_address_set(None, {
            "id": "set-1",
            "project_id": "project-1",
            "members": [{"address": "10.58.159.2/32"}],
        })
        plugin.create_aria_acl_rule(None, {
            "id": "rule-1",
            "project_id": "project-1",
            "policy_id": "policy-1",
            "direction": "ingress",
            "priority": 100,
            "action": "drop",
            "src_address_set_id": "set-1",
        })
        plugin.create_aria_acl_binding(None, {
            "id": "binding-1",
            "project_id": "project-1",
            "policy_id": "policy-1",
            "target_type": "port",
            "target_id": "port-1",
        })

        policy = plugin.update_aria_acl_policy(None, "policy-1", {
            "name": "web-updated",
        })
        rule = plugin.update_aria_acl_rule(None, "rule-1", {"priority": 90})
        address_set = plugin.update_aria_acl_address_set(None, "set-1", {
            "members": [{"address": "10.58.159.3/32"}],
        })
        binding = plugin.update_aria_acl_binding(None, "binding-1", {
            "enabled": False,
        })

        self.assertEqual(2, policy["revision_number"])
        self.assertEqual(2, rule["revision_number"])
        self.assertEqual(2, address_set["revision_number"])
        self.assertEqual(2, binding["revision_number"])
        self.assertIn("T", policy["created_at"])
        self.assertIn("T", policy["updated_at"])
        self.assertNotEqual("", policy["updated_at"])
        disabled_result = plugin.get_aria_acl_effective_for_port(None, {
            "id": "port-1",
            "network_id": "net-1",
        })
        self.assertFalse(disabled_result["enabled"])
        self.assertEqual("not_requested", disabled_result["status"])
        plugin.update_aria_acl_binding(None, "binding-1", {"enabled": True})
        result = plugin.get_aria_acl_effective_for_port(None, {
            "id": "port-1",
            "network_id": "net-1",
        })
        self.assertEqual("allow", result["default_action"])
        self.assertEqual(90, result["rules"][0]["priority"])
        self.assertEqual(["10.58.159.3/32"], result["rules"][0]["src_cidrs"])

        plugin.delete_aria_acl_binding(None, "binding-1")
        plugin.delete_aria_acl_rule(None, "rule-1")
        plugin.delete_aria_acl_address_set(None, "set-1")
        plugin.delete_aria_acl_policy(None, "policy-1")
        self.assertEqual([], plugin.get_aria_acl_policies(None))

    def test_acl_policy_rule_and_binding_writes_emit_rpc_notifications(self):
        notifier = FakeNotifier()
        plugin = AriaAclPlugin(notifier=notifier)

        policy = plugin.create_aria_acl_policy("ctx", {
            "id": "policy-1",
            "project_id": "project-1",
            "name": "web",
        })
        rule = plugin.create_aria_acl_rule("ctx", {
            "id": "rule-1",
            "project_id": "project-1",
            "policy_id": policy["id"],
            "direction": "ingress",
            "priority": 100,
            "action": "drop",
            "protocol": "tcp",
            "dst_port_min": 8080,
            "dst_port_max": 8080,
        })
        binding = plugin.create_aria_acl_binding("ctx", {
            "id": "binding-1",
            "project_id": "project-1",
            "policy_id": policy["id"],
            "target_type": "port",
            "target_id": "port-1",
        })
        plugin.update_aria_acl_policy("ctx", policy["id"], {"enabled": False})
        plugin.delete_aria_acl_rule("ctx", rule["id"])
        plugin.delete_aria_acl_binding("ctx", binding["id"])

        payloads = [event[1] for event in notifier.events]

        self.assertEqual(
            [
                ("policy", "create", "policy-1"),
                ("rule", "create", "rule-1"),
                ("binding", "create", "binding-1"),
                ("policy", "update", "policy-1"),
                ("rule", "delete", "rule-1"),
                ("binding", "delete", "binding-1"),
            ],
            [
                (
                    payload["resource"],
                    payload["operation"],
                    payload["resource_id"],
                )
                for payload in payloads
            ],
        )
        self.assertEqual("acl", payloads[0]["domain"])
        self.assertEqual("policy-1", payloads[1]["policy_id"])
        self.assertEqual("port", payloads[2]["target_type"])
        self.assertEqual("port-1", payloads[2]["target_id"])
        self.assertEqual("port", payloads[-1]["target_type"])
        self.assertEqual("port-1", payloads[-1]["target_id"])

    def test_acl_agent_notifier_uses_legacy_agent_fanout_topic(self):
        client = FakeRpcClient()
        notifier = AriaAclAgentNotifier(client, FakeTopics)

        notifier.notify("ctx", domain="acl", resource="policy", operation="update")

        self.assertEqual(1, len(client.prepared))
        self.assertEqual(
            {"topic": "q-agent-notifier-aria_acl-update", "fanout": True},
            client.prepared[0].prepare_kwargs,
        )
        self.assertEqual(
            (
                "ctx",
                "aria_acl_update",
                {"domain": "acl", "resource": "policy", "operation": "update"},
            ),
            client.prepared[0].casts[0],
        )

    def test_delete_rejects_referenced_policy_and_address_set(self):
        plugin = AriaAclPlugin()
        plugin.create_aria_acl_policy(None, {
            "id": "policy-1",
            "project_id": "project-1",
        })
        plugin.create_aria_acl_address_set(None, {
            "id": "set-1",
            "project_id": "project-1",
            "members": [{"address": "10.58.159.2/32"}],
        })
        plugin.create_aria_acl_rule(None, {
            "id": "rule-1",
            "project_id": "project-1",
            "policy_id": "policy-1",
            "direction": "ingress",
            "priority": 100,
            "action": "drop",
            "src_address_set_id": "set-1",
        })

        self.assertRaises(
            AriaAclBadRequest,
            plugin.delete_aria_acl_policy,
            None,
            "policy-1",
        )
        self.assertRaises(
            AriaAclBadRequest,
            plugin.delete_aria_acl_address_set,
            None,
            "set-1",
        )

    def test_port_binding_overrides_network_binding(self):
        plugin = AriaAclPlugin()
        plugin.create_aria_acl_policy(None, {
            "id": "policy-port",
            "project_id": "project-1",
        })
        plugin.create_aria_acl_policy(None, {
            "id": "policy-net",
            "project_id": "project-1",
        })
        plugin.create_aria_acl_binding(None, {
            "id": "binding-net",
            "project_id": "project-1",
            "policy_id": "policy-net",
            "target_type": "network",
            "target_id": "net-1",
        })
        plugin.create_aria_acl_binding(None, {
            "id": "binding-port",
            "project_id": "project-1",
            "policy_id": "policy-port",
            "target_type": "port",
            "target_id": "port-1",
        })

        result = plugin.get_aria_acl_effective_for_port(None, {
            "id": "port-1",
            "network_id": "net-1",
        })

        self.assertEqual("port", result["source"])
        self.assertEqual("policy-port", result["policy_id"])

    def test_effective_acl_can_resolve_network_binding_by_port_id(self):
        plugin = AriaAclPlugin()
        plugin.create_aria_acl_policy(None, {
            "id": "policy-net",
            "project_id": "project-1",
        })
        plugin.create_aria_acl_binding(None, {
            "id": "binding-net",
            "project_id": "project-1",
            "policy_id": "policy-net",
            "target_type": "network",
            "target_id": "net-1",
        })

        def get_port(context, port_id):
            self.assertIsNone(context)
            self.assertEqual("port-1", port_id)
            return {
                "port": {
                    "id": port_id,
                    "network_id": "net-1",
                    "project_id": "project-1",
                }
            }

        result = plugin.get_aria_acl_effective_for_port_id(
            None,
            "port-1",
            neutron_port_getter=get_port,
        )

        self.assertEqual("network", result["source"])
        self.assertEqual("policy-net", result["policy_id"])

    def test_effective_acl_by_port_id_keeps_port_binding_without_getter(self):
        plugin = AriaAclPlugin()
        plugin.create_aria_acl_policy(None, {
            "id": "policy-port",
            "project_id": "project-1",
        })
        plugin.create_aria_acl_binding(None, {
            "id": "binding-port",
            "project_id": "project-1",
            "policy_id": "policy-port",
            "target_type": "port",
            "target_id": "port-1",
        })

        result = plugin.get_aria_acl_effective_for_port_id(None, "port-1")

        self.assertEqual("port", result["source"])
        self.assertEqual("policy-port", result["policy_id"])

    def test_effective_api_uses_real_port_contract_eligibility(self):
        plugin = AriaAclPlugin()

        result = plugin.get_aria_acl_effective_for_port(None, {
            "id": "port-1",
            "device_owner": "compute:nova",
            "binding:vif_type": "binding_failed",
            "binding:vnic_type": "normal",
        })

        self.assertFalse(result["enabled"])
        self.assertEqual("unsupported", result["status"])
        self.assertEqual("bypass", result["effective_action"])
        self.assertIn("unsupported_vif_type", result["reason"])

    def test_binding_rejects_missing_policy(self):
        plugin = AriaAclPlugin()

        self.assertRaises(
            AriaAclBadRequest,
            plugin.create_aria_acl_binding,
            None,
            {
                "id": "binding-1",
                "project_id": "project-1",
                "policy_id": "missing",
                "target_type": "port",
                "target_id": "port-1",
            },
        )

    def test_rule_rejects_cross_project_policy_reference(self):
        plugin = AriaAclPlugin()
        plugin.create_aria_acl_policy(None, {
            "id": "policy-1",
            "project_id": "project-1",
        })

        self.assertRaises(
            AriaAclBadRequest,
            plugin.create_aria_acl_rule,
            None,
            {
                "id": "rule-1",
                "project_id": "project-2",
                "policy_id": "policy-1",
                "direction": "ingress",
                "priority": 100,
                "action": "drop",
            },
        )

    def test_binding_rejects_cross_project_policy_reference(self):
        plugin = AriaAclPlugin()
        plugin.create_aria_acl_policy(None, {
            "id": "policy-1",
            "project_id": "project-1",
        })

        self.assertRaises(
            AriaAclBadRequest,
            plugin.create_aria_acl_binding,
            None,
            {
                "id": "binding-1",
                "project_id": "project-2",
                "policy_id": "policy-1",
                "target_type": "port",
                "target_id": "port-1",
            },
        )

    def test_status_report_is_stored_separately_from_desired_state(self):
        plugin = AriaAclPlugin()
        status = plugin.report_aria_acl_port_status(None, {
            "port_id": "port-1",
            "host": "host-1",
            "policy_id": "policy-1",
            "status": "ready",
            "generation": 7,
        })

        self.assertEqual("ready", status["status"])
        self.assertIn("T", status["updated_at"])
        self.assertEqual(
            "ready",
            plugin.get_aria_acl_port_status(None, "port-1", host="host-1")["status"],
        )
        projected = plugin.get_aria_acl_port_status(None, "port-1", host="host-1")
        self.assertEqual(projected["updated_at"], projected["last_reported_at"])
        self.assertFalse(projected["stale"])
        self.assertEqual("ready", projected["runtime_status"])
        self.assertEqual([], plugin.get_aria_acl_policies(None))

    def test_port_status_query_marks_stale_rows(self):
        plugin = AriaAclPlugin(
            port_status_stale_seconds=1,
            now=lambda: 4102444800,
        )
        plugin.report_aria_acl_port_status(None, {
            "port_id": "port-1",
            "host": "host-1",
            "status": "ready",
            "generation": 7,
        })

        status = plugin.get_aria_acl_port_status(None, "port-1", host="host-1")

        self.assertTrue(status["stale"])
        self.assertEqual("stale", status["runtime_status"])
        self.assertIn("T", status["last_reported_at"])

    def test_port_status_resource_methods_match_neutron_controller_shape(self):
        plugin = AriaAclPlugin()
        created = plugin.create_aria_acl_port_status(None, {
            "aria_acl_port_status": {
                "port_id": "port-1",
                "host": "host-1",
                "effective_policy_id": "policy-1",
                "binding_id": "binding-1",
                "status": "ready",
                "effective_action": "enforce",
                "generation": 7,
            }
        })
        updated = plugin.update_aria_acl_port_status(None, "port-1", {
            "aria_acl_port_status": {
                "host": "host-1",
                "status": "degraded",
                "effective_action": "bypass",
                "reason": "apply_failed",
                "generation": 8,
            }
        })

        listed = plugin.get_aria_acl_port_statuses(None, filters={"port_id": "port-1"})

        self.assertEqual("policy-1", created["effective_policy_id"])
        self.assertEqual("port-1", updated["port_id"])
        self.assertEqual("degraded", updated["status"])
        self.assertEqual("bypass", updated["effective_action"])
        self.assertEqual(1, len(listed))
        self.assertEqual("apply_failed", listed[0]["reason"])
        plugin.delete_aria_acl_port_status(None, "port-1", host="host-1")
        self.assertEqual([], plugin.get_aria_acl_port_statuses(None))
        self.assertEqual([], plugin.get_aria_acl_policies(None))

    def test_list_methods_accept_neutron_list_style_filters(self):
        plugin = AriaAclPlugin()
        plugin.create_aria_acl_policy(None, {
            "id": "policy-1",
            "project_id": "project-1",
            "name": "web",
        })
        plugin.create_aria_acl_policy(None, {
            "id": "policy-2",
            "project_id": "project-2",
            "name": "db",
        })
        plugin.create_aria_acl_binding(None, {
            "id": "binding-1",
            "project_id": "project-1",
            "policy_id": "policy-1",
            "target_type": "port",
            "target_id": "port-1",
        })
        plugin.create_aria_acl_port_status(None, {
            "port_id": "port-1",
            "host": "host-1",
            "status": "ready",
        })

        self.assertEqual(
            ["policy-1"],
            [
                policy["id"] for policy in plugin.get_aria_acl_policies(
                    None,
                    filters={"project_id": ["project-1"]},
                )
            ],
        )
        self.assertEqual(
            ["binding-1"],
            [
                binding["id"] for binding in plugin.get_aria_acl_bindings(
                    None,
                    filters={"target_id": ["port-1"]},
                )
            ],
        )
        self.assertEqual(
            ["host-1"],
            [
                status["host"] for status in plugin.get_aria_acl_port_statuses(
                    None,
                    filters={"port_id": ["port-1"]},
                )
            ],
        )

    def test_sqlite_repository_persists_effective_acl_contract(self):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        try:
            repository = SqliteAriaAclRepository(path)
            plugin = AriaAclPlugin(repository=repository)
            plugin.create_aria_acl_policy(None, {
                "id": "policy-1",
                "project_id": "project-1",
                "default_action": "allow",
            })
            updated_policy = plugin.update_aria_acl_policy(None, "policy-1", {
                "name": "persisted-policy",
            })
            plugin.create_aria_acl_rule(None, {
                "id": "rule-1",
                "project_id": "project-1",
                "policy_id": "policy-1",
                "direction": "ingress",
                "priority": 100,
                "action": "drop",
                "protocol": "icmp",
                "src_cidr": "10.58.159.2/32",
            })
            plugin.create_aria_acl_binding(None, {
                "id": "binding-1",
                "project_id": "project-1",
                "policy_id": "policy-1",
                "target_type": "port",
                "target_id": "port-1",
            })
            plugin.report_aria_acl_port_status(None, {
                "port_id": "port-1",
                "host": "host-1",
                "status": "ready",
                "generation": 9,
            })
            repository.close()

            reopened = SqliteAriaAclRepository(path)
            plugin = AriaAclPlugin(repository=reopened)
            result = plugin.get_aria_acl_effective_for_port(None, {
                "id": "port-1",
                "network_id": "net-1",
            })

            self.assertTrue(result["enabled"])
            self.assertIn("T", updated_policy["updated_at"])
            self.assertEqual("policy-1", result["policy_id"])
            self.assertEqual("rule-1", result["rules"][0]["id"])
            self.assertEqual(
                "ready",
                plugin.get_aria_acl_port_status(None, "port-1", host="host-1")["status"],
            )
            plugin.delete_aria_acl_port_status(None, "port-1", host="host-1")
            self.assertEqual([], plugin.get_aria_acl_port_statuses(None))
            reopened.close()
        finally:
            os.unlink(path)

    def test_sqlite_repository_accepts_neutron_list_style_filters(self):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        try:
            repository = SqliteAriaAclRepository(path)
            plugin = AriaAclPlugin(repository=repository)
            plugin.create_aria_acl_policy(None, {
                "id": "policy-1",
                "project_id": "project-1",
            })
            plugin.create_aria_acl_policy(None, {
                "id": "policy-2",
                "project_id": "project-2",
            })

            self.assertEqual(
                ["policy-2"],
                [
                    policy["id"] for policy in plugin.get_aria_acl_policies(
                        None,
                        filters={"project_id": ["project-2"]},
                    )
                ],
            )
            repository.close()
        finally:
            os.unlink(path)

    def test_sqlite_repository_uses_native_query_contract(self):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        try:
            repository = SqliteAriaAclRepository(path)
            if hasattr(inspect, "signature"):
                parameters = inspect.signature(
                    repository.list_policies
                ).parameters
            else:
                parameters = inspect.getargspec(repository.list_policies).args
            self.assertIn("sorts", parameters)
            for policy_id, name, revision in (
                ("p3", "same", 3),
                ("p1", "same", 1),
                ("p2", "", 2),
            ):
                repository.create_policy({
                    "id": policy_id,
                    "project_id": "project-1",
                    "name": name,
                    "revision_number": revision,
                })

            first = repository.list_policies(
                sorts=[("name", True)],
                limit=2,
                fields=["id", "name"],
            )
            self.assertEqual(["p2", "p1"], [row["id"] for row in first])
            reverse = repository.list_policies(
                sorts=[("name", True)],
                limit=2,
                marker="p3",
                page_reverse=True,
                fields=["id"],
            )
            self.assertEqual([{"id": "p2"}, {"id": "p1"}], reverse)
            self.assertEqual(
                {"id": "p1"},
                repository.get_policy("p1", fields=["id"]),
            )
            self.assertEqual(
                [{"id": "p1"}, {"id": "p3"}],
                repository.list_policies(
                    filters={
                        "enabled": ["true"],
                        "revision_number": ["1", "3"],
                    },
                    fields=["id"],
                ),
            )

            from neutron_aria.db.aria_acl.query import PortStatusProjection
            for port_id, host in (
                ("port-1", "ostack2"),
                ("port-1", "ostack3"),
                ("port-2", "ostack2"),
            ):
                repository.upsert_port_status({
                    "port_id": port_id,
                    "host": host,
                    "status": "ready",
                })
            projection = PortStatusProjection(200.0, -1)
            marker = None
            status_ids = []
            while True:
                page = repository.list_port_statuses(
                    filters={"runtime_status": ["ready"]},
                    fields=["id"],
                    sorts=[("id", True)],
                    limit=1,
                    marker=marker,
                    projection=projection,
                )
                if not page:
                    break
                marker = page[0]["id"]
                self.assertNotIn(marker, status_ids)
                status_ids.append(marker)
            self.assertEqual(3, len(status_ids))
            repository.close()
        finally:
            os.unlink(path)

    def test_sqlite_status_resource_identity_is_exact(self):
        from neutron_aria.db.aria_acl.query import encode_port_status_id

        fd, path = tempfile.mkstemp()
        os.close(fd)
        try:
            repository = SqliteAriaAclRepository(path)
            plugin = AriaAclPlugin(repository=repository, now=lambda: 200.0)
            for host in ("ostack2", "ostack3"):
                plugin.report_aria_acl_port_status(None, {
                    "port_id": "port-1",
                    "host": host,
                    "status": "ready",
                })

            with self.assertRaises(AriaAclConflict):
                plugin.get_aria_acl_port_status(None, "port-1")
            exact_id = encode_port_status_id("port-1", "ostack3")
            self.assertEqual(
                "ostack3",
                plugin.get_aria_acl_port_status(None, exact_id)["host"],
            )
            plugin.delete_aria_acl_port_status(None, exact_id)
            self.assertEqual(
                "ostack2",
                plugin.get_aria_acl_port_status(None, "port-1")["host"],
            )
            repository.close()
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()

from __future__ import absolute_import

import inspect
import json
import os
import sys
import tempfile
import types
import unittest

from neutron_aria.db.aria_acl.api import AriaAclNotFound
from neutron_aria.db.aria_acl.api import AriaAclValidationError
from neutron_aria.db.aria_acl.api import InMemoryAriaAclRepository
from neutron_aria.db.aria_acl.api import SqliteAriaAclRepository
from neutron_aria.db.migration import aria_acl_initial
from neutron_aria.extensions import aria_acl
from neutron_aria.policies import aria_acl as aria_acl_policy
from neutron_aria.services.aria_acl.exceptions import AriaAclBadRequest
from neutron_aria.services.aria_acl.exceptions import AriaAclConflict
from neutron_aria.services.aria_acl.exceptions import map_repository_error
from neutron_aria.services.aria_acl import plugin as aria_acl_plugin
from neutron_aria.services.aria_acl import port_projection
from neutron_aria.services.aria_acl.plugin import AriaAclAgentNotifier
from neutron_aria.services.aria_acl.plugin import AriaAclPlugin
from neutron_aria.services.aria_acl.port_projection import install_legacy_port_projection


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


class RecordingPortProjectionRepository(InMemoryAriaAclRepository):
    def __init__(self):
        super(RecordingPortProjectionRepository, self).__init__()
        self.effective_payload_calls = 0
        self.port_status_list_calls = []

    def to_effective_payload(self):
        self.effective_payload_calls += 1
        return super(RecordingPortProjectionRepository, self).to_effective_payload()

    def list_port_statuses(self, **kwargs):
        self.port_status_list_calls.append(kwargs)
        return super(RecordingPortProjectionRepository, self).list_port_statuses(
            **kwargs
        )


class FailingPortProjectionRepository(InMemoryAriaAclRepository):
    def list_port_statuses(self, **kwargs):
        raise RuntimeError("database offline")


class FakeCorePlugin(object):
    def __init__(self, ports):
        self.ports = dict((port["id"], dict(port)) for port in ports)
        self.get_port_calls = []
        self.get_ports_calls = []

    def get_port(self, context, port_id, fields=None):
        self.get_port_calls.append((context, port_id, fields))
        return dict(self.ports[port_id])

    def get_ports(
        self,
        context,
        filters=None,
        fields=None,
        sorts=None,
        limit=None,
        marker=None,
        page_reverse=False,
    ):
        self.get_ports_calls.append({
            "context": context,
            "filters": filters,
            "fields": fields,
            "sorts": sorts,
            "limit": limit,
            "marker": marker,
            "page_reverse": page_reverse,
        })
        return [dict(port) for port in self.ports.values()]


class AriaAclPluginTestCase(unittest.TestCase):
    def test_collection_lists_enforce_read_policy_before_repository_access(self):
        class ListDenied(Exception):
            pass

        class DenyPolicy(object):
            calls = []

            @classmethod
            def enforce(cls, context, action, target, pluralized=None):
                cls.calls.append((context, action, target, pluralized))
                raise ListDenied(action)

        repository = RecordingListRepository()
        plugin = AriaAclPlugin(repository=repository, now=lambda: 200.0)
        context = object()
        methods = (
            ("get_aria_acl_policy", "aria_acl_policies", plugin.get_aria_acl_policies),
            ("get_aria_acl_rule", "aria_acl_rules", plugin.get_aria_acl_rules),
            (
                "get_aria_acl_address_set",
                "aria_acl_address_sets",
                plugin.get_aria_acl_address_sets,
            ),
            ("get_aria_acl_binding", "aria_acl_bindings", plugin.get_aria_acl_bindings),
            (
                "get_aria_acl_port_status",
                "aria_acl_port_statuses",
                plugin.get_aria_acl_port_statuses,
            ),
        )
        saved_policy = getattr(aria_acl_plugin, "neutron_policy", None)
        had_policy = hasattr(aria_acl_plugin, "neutron_policy")
        aria_acl_plugin.neutron_policy = DenyPolicy
        try:
            for _action, _collection, method in methods:
                with self.assertRaises(ListDenied):
                    method(context)
        finally:
            if had_policy:
                aria_acl_plugin.neutron_policy = saved_policy
            else:
                del aria_acl_plugin.neutron_policy

        self.assertEqual([], repository.calls)
        self.assertEqual(
            [
                (context, action, {}, collection)
                for action, collection, _method in methods
            ],
            DenyPolicy.calls,
        )

    def test_plugin_constructor_does_not_reenter_neutron_manager(self):
        fake_neutron = types.ModuleType("neutron")
        fake_manager = types.ModuleType("neutron.manager")

        class ReentrantManager(object):
            calls = 0

            @classmethod
            def get_plugin(cls):
                cls.calls += 1
                raise AssertionError("service plugin constructor re-entered manager")

        fake_manager.NeutronManager = ReentrantManager
        fake_neutron.manager = fake_manager
        saved_neutron = sys.modules.get("neutron")
        saved_manager = sys.modules.get("neutron.manager")
        sys.modules["neutron"] = fake_neutron
        sys.modules["neutron.manager"] = fake_manager
        try:
            AriaAclPlugin(notifier=FakeNotifier())
        finally:
            if saved_neutron is None:
                sys.modules.pop("neutron", None)
            else:
                sys.modules["neutron"] = saved_neutron
            if saved_manager is None:
                sys.modules.pop("neutron.manager", None)
            else:
                sys.modules["neutron.manager"] = saved_manager

        self.assertEqual(0, ReentrantManager.calls)

    def test_manager_projection_install_waits_until_manager_is_ready(self):
        plugin = AriaAclPlugin(notifier=FakeNotifier())
        core = FakeCorePlugin([])
        fake_neutron = types.ModuleType("neutron")
        fake_manager = types.ModuleType("neutron.manager")

        class ReadyManager(object):
            ready = False

            @classmethod
            def has_instance(cls):
                return cls.ready

            @classmethod
            def get_plugin(cls):
                return core

            @classmethod
            def get_service_plugins(cls):
                return {"aria_acl": plugin}

        fake_manager.NeutronManager = ReadyManager
        fake_neutron.manager = fake_manager
        saved_neutron = sys.modules.get("neutron")
        saved_manager = sys.modules.get("neutron.manager")
        sys.modules["neutron"] = fake_neutron
        sys.modules["neutron.manager"] = fake_manager
        try:
            self.assertFalse(
                port_projection.install_legacy_port_projection_from_manager()
            )
            ReadyManager.ready = True
            self.assertTrue(
                port_projection.install_legacy_port_projection_from_manager()
            )
        finally:
            if saved_neutron is None:
                sys.modules.pop("neutron", None)
            else:
                sys.modules["neutron"] = saved_neutron
            if saved_manager is None:
                sys.modules.pop("neutron.manager", None)
            else:
                sys.modules["neutron.manager"] = saved_manager

        self.assertTrue(core._aria_acl_port_projection_installed)

    def test_extension_resource_registration_installs_port_projection(self):
        calls = []
        original = getattr(
            aria_acl,
            "install_legacy_port_projection_from_manager",
            None,
        )
        aria_acl.install_legacy_port_projection_from_manager = (
            lambda: calls.append(True)
        )
        try:
            aria_acl.get_resources()
        finally:
            if original is None:
                delattr(
                    aria_acl,
                    "install_legacy_port_projection_from_manager",
                )
            else:
                aria_acl.install_legacy_port_projection_from_manager = original

        self.assertEqual([True], calls)

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

    def test_port_summary_projects_effective_acl_and_exact_host_runtime(self):
        plugin = AriaAclPlugin(now=lambda: 0.0)
        plugin.create_aria_acl_policy(None, {
            "id": "policy-1",
            "project_id": "project-1",
            "name": "web",
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
            "host": "old-host",
            "effective_policy_id": "policy-1",
            "binding_id": "binding-1",
            "status": "degraded",
            "reason": "old-host-state",
        })
        plugin.report_aria_acl_port_status(None, {
            "port_id": "port-1",
            "host": "compute-1",
            "effective_policy_id": "policy-1",
            "binding_id": "binding-1",
            "status": "ready",
            "reason": "ready",
        })
        port = {
            "id": "port-1",
            "network_id": "network-1",
            "device_owner": "compute:nova",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
            "binding:host_id": "compute-1",
        }

        projected = plugin.extend_aria_acl_port_dict(port)

        self.assertIs(port, projected)
        self.assertTrue(projected["aria_acl_enabled"])
        self.assertEqual("policy-1", projected["aria_acl_effective_policy_id"])
        self.assertEqual("web", projected["aria_acl_effective_policy_name"])
        self.assertEqual("port", projected["aria_acl_effective_source"])
        self.assertEqual("binding-1", projected["aria_acl_binding_id"])
        self.assertEqual(1, projected["aria_acl_effective_revision"])
        self.assertEqual("applied", projected["aria_acl_runtime_status"])
        self.assertEqual("compute-1", projected["aria_acl_runtime_host"])
        self.assertEqual("ready", projected["aria_acl_runtime_reason"])

    def test_port_summary_does_not_reuse_runtime_from_previous_host(self):
        plugin = AriaAclPlugin(now=lambda: 0.0)
        plugin.create_aria_acl_policy(None, {
            "id": "policy-1",
            "project_id": "project-1",
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
            "host": "old-host",
            "effective_policy_id": "policy-1",
            "binding_id": "binding-1",
            "status": "ready",
        })
        port = {
            "id": "port-1",
            "network_id": "network-1",
            "device_owner": "compute:nova",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
            "binding:host_id": "new-host",
        }

        plugin.extend_aria_acl_port_dict(port)

        self.assertEqual("pending", port["aria_acl_runtime_status"])
        self.assertIsNone(port["aria_acl_runtime_host"])
        self.assertEqual("status_not_reported", port["aria_acl_runtime_reason"])

    def test_port_summary_degrades_stale_runtime_to_unknown(self):
        plugin = AriaAclPlugin(
            now=lambda: 4102444800.0,
            port_status_stale_seconds=1,
        )
        plugin.create_aria_acl_policy(None, {
            "id": "policy-1",
            "project_id": "project-1",
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
            "host": "compute-1",
            "effective_policy_id": "policy-1",
            "binding_id": "binding-1",
            "status": "ready",
            "reason": "ready",
        })
        port = {
            "id": "port-1",
            "network_id": "network-1",
            "device_owner": "compute:nova",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
            "binding:host_id": "compute-1",
        }

        plugin.extend_aria_acl_port_dict(port)

        self.assertEqual("unknown", port["aria_acl_runtime_status"])
        self.assertEqual("compute-1", port["aria_acl_runtime_host"])
        self.assertEqual("status_stale", port["aria_acl_runtime_reason"])

    def test_port_summary_rejects_runtime_for_previous_effective_policy(self):
        plugin = AriaAclPlugin(now=lambda: 0.0)
        plugin.create_aria_acl_policy(None, {
            "id": "policy-1",
            "project_id": "project-1",
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
            "host": "compute-1",
            "effective_policy_id": "old-policy",
            "binding_id": "old-binding",
            "status": "ready",
        })
        port = {
            "id": "port-1",
            "network_id": "network-1",
            "device_owner": "compute:nova",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
            "binding:host_id": "compute-1",
        }

        plugin.extend_aria_acl_port_dict(port)

        self.assertEqual("pending", port["aria_acl_runtime_status"])
        self.assertEqual("compute-1", port["aria_acl_runtime_host"])
        self.assertEqual(
            "status_projection_mismatch",
            port["aria_acl_runtime_reason"],
        )

    def test_port_summary_has_complete_defaults_without_effective_acl(self):
        plugin = AriaAclPlugin(now=lambda: 0.0)
        port = {
            "id": "port-1",
            "network_id": "network-1",
            "device_owner": "compute:nova",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
            "binding:host_id": "compute-1",
        }

        plugin.extend_aria_acl_port_dict(port)

        self.assertFalse(port["aria_acl_enabled"])
        self.assertIsNone(port["aria_acl_effective_policy_id"])
        self.assertIsNone(port["aria_acl_effective_policy_name"])
        self.assertEqual("none", port["aria_acl_effective_source"])
        self.assertIsNone(port["aria_acl_binding_id"])
        self.assertIsNone(port["aria_acl_effective_revision"])
        self.assertEqual("not_requested", port["aria_acl_runtime_status"])
        self.assertIsNone(port["aria_acl_runtime_host"])
        self.assertEqual("no_enabled_binding", port["aria_acl_runtime_reason"])

    def test_legacy_port_read_wrapper_batches_projection_and_preserves_fields(self):
        repository = RecordingPortProjectionRepository()
        plugin = AriaAclPlugin(repository=repository, now=lambda: 0.0)
        plugin.create_aria_acl_policy(None, {
            "id": "policy-1",
            "project_id": "project-1",
        })
        plugin.create_aria_acl_binding(None, {
            "id": "binding-1",
            "project_id": "project-1",
            "policy_id": "policy-1",
            "target_type": "network",
            "target_id": "network-1",
        })
        ports = [
            {
                "id": "port-1",
                "network_id": "network-1",
                "device_owner": "compute:nova",
                "binding:vif_type": "ovs",
                "binding:vnic_type": "normal",
                "binding:host_id": "compute-1",
            },
            {
                "id": "port-2",
                "network_id": "network-1",
                "device_owner": "compute:nova",
                "binding:vif_type": "ovs",
                "binding:vnic_type": "normal",
                "binding:host_id": "compute-2",
            },
        ]
        core = FakeCorePlugin(ports)
        install_legacy_port_projection(plugin, core_plugin=core)
        install_legacy_port_projection(plugin, core_plugin=core)
        repository.effective_payload_calls = 0
        repository.port_status_list_calls = []

        projected = core.get_ports(
            "ctx",
            filters={"network_id": ["network-1"]},
            fields=["id", "aria_acl_enabled", "aria_acl_runtime_status"],
            sorts=[("id", True)],
            limit=10,
            marker="port-0",
            page_reverse=True,
        )

        self.assertEqual(1, len(core.get_ports_calls))
        self.assertIsNone(core.get_ports_calls[0]["fields"])
        self.assertEqual(1, repository.effective_payload_calls)
        self.assertEqual(1, len(repository.port_status_list_calls))
        self.assertEqual(
            {"port_id": ["port-1", "port-2"]},
            repository.port_status_list_calls[0]["filters"],
        )
        self.assertEqual(
            [
                {
                    "id": "port-1",
                    "aria_acl_enabled": True,
                    "aria_acl_runtime_status": "pending",
                },
                {
                    "id": "port-2",
                    "aria_acl_enabled": True,
                    "aria_acl_runtime_status": "pending",
                },
            ],
            projected,
        )

    def test_legacy_port_show_wrapper_projects_before_field_selection(self):
        plugin = AriaAclPlugin(now=lambda: 0.0)
        core = FakeCorePlugin([{
            "id": "port-1",
            "network_id": "network-1",
            "device_owner": "compute:nova",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
            "binding:host_id": "compute-1",
        }])
        install_legacy_port_projection(plugin, core_plugin=core)

        projected = core.get_port(
            "ctx",
            "port-1",
            fields=["id", "aria_acl_enabled", "aria_acl_runtime_status"],
        )

        self.assertEqual([("ctx", "port-1", None)], core.get_port_calls)
        self.assertEqual(
            {
                "id": "port-1",
                "aria_acl_enabled": False,
                "aria_acl_runtime_status": "not_requested",
            },
            projected,
        )

    def test_port_projection_failure_does_not_break_core_port_show(self):
        plugin = AriaAclPlugin(
            repository=FailingPortProjectionRepository(),
            now=lambda: 0.0,
        )
        core = FakeCorePlugin([{
            "id": "port-1",
            "network_id": "network-1",
            "device_owner": "compute:nova",
            "binding:vif_type": "ovs",
            "binding:vnic_type": "normal",
            "binding:host_id": "compute-1",
        }])
        install_legacy_port_projection(plugin, core_plugin=core)

        projected = core.get_port("ctx", "port-1")

        self.assertIsNone(projected["aria_acl_enabled"])
        self.assertEqual("unknown", projected["aria_acl_effective_source"])
        self.assertEqual("unknown", projected["aria_acl_runtime_status"])
        self.assertEqual(
            "projection_unavailable",
            projected["aria_acl_runtime_reason"],
        )

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
        for host in ("compute-1", "compute-2"):
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
        for host in ("compute-1", "compute-2"):
            plugin.report_aria_acl_port_status(None, {
                "aria_acl_port_status": {
                    "port_id": "port-1",
                    "host": host,
                    "status": "ready",
                }
            })
        exact_id = query_contract.encode_port_status_id("port-1", "compute-2")
        status = plugin.get_aria_acl_port_status(None, exact_id)
        self.assertIsNotNone(status)
        self.assertEqual("compute-2", status["host"])

    def test_missing_status_for_explicit_host_remains_none(self):
        plugin = AriaAclPlugin(now=lambda: 200.0)

        self.assertIsNone(
            plugin.get_aria_acl_port_status(
                None,
                "port-missing",
                host="compute-1",
            )
        )

    def test_derived_status_id_delete_removes_only_exact_host(self):
        from neutron_aria.db.aria_acl.query import encode_port_status_id

        plugin = AriaAclPlugin(now=lambda: 200.0)
        for host in ("compute-1", "compute-2"):
            plugin.report_aria_acl_port_status(None, {
                "port_id": "port-1",
                "host": host,
                "status": "ready",
            })

        plugin.delete_aria_acl_port_status(
            None,
            encode_port_status_id("port-1", "compute-1"),
        )

        statuses = plugin.get_aria_acl_port_statuses(
            None,
            filters={"port_id": ["port-1"]},
        )
        self.assertEqual(["compute-2"], [status["host"] for status in statuses])

    def test_derived_status_id_update_changes_only_exact_host(self):
        from neutron_aria.db.aria_acl.query import encode_port_status_id

        plugin = AriaAclPlugin(now=lambda: 200.0)
        for host in ("compute-1", "compute-2"):
            plugin.report_aria_acl_port_status(None, {
                "port_id": "port-1",
                "host": host,
                "status": "ready",
            })

        updated = plugin.update_aria_acl_port_status(
            None,
            encode_port_status_id("port-1", "compute-2"),
            {"status": "degraded"},
        )

        self.assertEqual("compute-2", updated["host"])
        self.assertEqual("degraded", updated["status"])
        self.assertEqual(
            "ready",
            plugin.get_aria_acl_port_status(
                None,
                "port-1",
                host="compute-1",
            )["status"],
        )

    def test_legacy_status_delete_removes_all_hosts(self):
        plugin = AriaAclPlugin(now=lambda: 200.0)
        for host in ("compute-1", "compute-2"):
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

    def test_policy_merge_preserves_existing_file_mode(self):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        try:
            with open(path, "w") as handle:
                json.dump({"existing:rule": "role:admin"}, handle)
            os.chmod(path, 0o644)

            changed = aria_acl_policy.merge_policy_file(path)

            self.assertTrue(changed)
            if os.name != "nt":
                self.assertEqual(0o644, os.stat(path).st_mode & 0o777)
            with open(path, "r") as handle:
                merged = json.load(handle)
            self.assertEqual("role:admin", merged["existing:rule"])
            self.assertEqual(
                "role:admin",
                merged["create_aria_acl_policy"],
            )
        finally:
            if os.path.exists(path):
                os.unlink(path)

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
                "src_cidr": "192.0.2.2/32",
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
            "members": [{"address": "192.0.2.2/32"}],
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
            "members": [{"address": "192.0.2.3/32"}],
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
        self.assertEqual(["192.0.2.3/32"], result["rules"][0]["src_cidrs"])

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

    def test_native_rule_bulk_create_emits_one_transaction_notification(self):
        notifier = FakeNotifier()
        repository = InMemoryAriaAclRepository()
        plugin = AriaAclPlugin(repository=repository, notifier=notifier)
        plugin.create_aria_acl_policy(None, {
            "id": "policy-1",
            "project_id": "project-1",
        })
        notifier.events = []

        rules = plugin.create_aria_acl_rule_bulk(None, {
            "aria_acl_rules": [
                {"aria_acl_rule": {
                    "id": "rule-1",
                    "project_id": "project-1",
                    "policy_id": "policy-1",
                    "direction": "ingress",
                    "priority": 100,
                    "action": "drop",
                    "protocol": "tcp",
                    "dst_port_min": 8080,
                    "dst_port_max": 8080,
                }},
                {"aria_acl_rule": {
                    "id": "rule-2",
                    "project_id": "project-1",
                    "policy_id": "policy-1",
                    "direction": "ingress",
                    "priority": 101,
                    "action": "drop",
                    "protocol": "udp",
                    "dst_port_min": 1080,
                    "dst_port_max": 1080,
                }},
            ],
        })

        self.assertTrue(
            getattr(plugin, "_AriaAclPlugin__native_bulk_support")
        )
        self.assertEqual(["rule-1", "rule-2"], [rule["id"] for rule in rules])
        self.assertEqual(1, len(notifier.events))
        payload = notifier.events[0][1]
        self.assertEqual("rule", payload["resource"])
        self.assertEqual("bulk_create", payload["operation"])
        self.assertEqual(2, payload["resource_count"])
        self.assertEqual("policy-1", payload["policy_id"])

    def test_failed_native_rule_bulk_create_rolls_back_without_notification(self):
        notifier = FakeNotifier()
        repository = InMemoryAriaAclRepository()
        plugin = AriaAclPlugin(repository=repository, notifier=notifier)
        plugin.create_aria_acl_policy(None, {
            "id": "policy-1",
            "project_id": "project-1",
        })
        notifier.events = []

        with self.assertRaises(AriaAclConflict):
            plugin.create_aria_acl_rule_bulk(None, {
                "aria_acl_rules": [
                    {"aria_acl_rule": {
                        "id": "rule-1",
                        "project_id": "project-1",
                        "policy_id": "policy-1",
                        "direction": "ingress",
                        "priority": 100,
                        "action": "drop",
                    }},
                    {"aria_acl_rule": {
                        "id": "rule-2",
                        "project_id": "project-1",
                        "policy_id": "policy-1",
                        "direction": "ingress",
                        "priority": 100,
                        "action": "drop",
                    }},
                ],
            })

        self.assertEqual([], repository.list_rules())
        self.assertEqual([], notifier.events)

    def test_sqlite_native_rule_bulk_failure_is_atomic(self):
        fd, path = tempfile.mkstemp()
        os.close(fd)
        repository = None
        try:
            repository = SqliteAriaAclRepository(path)
            plugin = AriaAclPlugin(repository=repository, notifier=FakeNotifier())
            plugin.create_aria_acl_policy(None, {
                "id": "policy-1",
                "project_id": "project-1",
            })

            with self.assertRaises(AriaAclConflict):
                plugin.create_aria_acl_rule_bulk(None, {
                    "aria_acl_rules": [
                        {"aria_acl_rule": {
                            "id": "rule-1",
                            "project_id": "project-1",
                            "policy_id": "policy-1",
                            "direction": "ingress",
                            "priority": 100,
                            "action": "drop",
                        }},
                        {"aria_acl_rule": {
                            "id": "rule-2",
                            "project_id": "project-1",
                            "policy_id": "policy-1",
                            "direction": "ingress",
                            "priority": 100,
                            "action": "drop",
                        }},
                    ],
                })

            self.assertEqual([], repository.list_rules())
        finally:
            if repository is not None:
                repository.close()
            os.unlink(path)

    def test_native_bulk_entry_points_cover_creatable_resources(self):
        notifier = FakeNotifier()
        plugin = AriaAclPlugin(notifier=notifier)

        policies = plugin.create_aria_acl_policy_bulk(None, {
            "aria_acl_policies": [{"aria_acl_policy": {
                "id": "policy-1",
                "project_id": "project-1",
            }}],
        })
        address_sets = plugin.create_aria_acl_address_set_bulk(None, {
            "aria_acl_address_sets": [{"aria_acl_address_set": {
                "id": "set-1",
                "project_id": "project-1",
                "members": [{"address": "192.0.2.2/32"}],
            }}],
        })
        bindings = plugin.create_aria_acl_binding_bulk(None, {
            "aria_acl_bindings": [{"aria_acl_binding": {
                "id": "binding-1",
                "project_id": "project-1",
                "policy_id": "policy-1",
                "target_type": "port",
                "target_id": "port-1",
            }}],
        })
        statuses = plugin.create_aria_acl_port_status_bulk(None, {
            "aria_acl_port_statuses": [{"aria_acl_port_status": {
                "port_id": "port-1",
                "host": "compute-1.example.test",
                "status": "ready",
            }}],
        })

        self.assertEqual("policy-1", policies[0]["id"])
        self.assertEqual("set-1", address_sets[0]["id"])
        self.assertEqual("binding-1", bindings[0]["id"])
        self.assertEqual("port-1", statuses[0]["port_id"])
        self.assertEqual(
            ["policy", "address_set", "binding"],
            [event[1]["resource"] for event in notifier.events],
        )

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
            "members": [{"address": "192.0.2.2/32"}],
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
                "src_cidr": "192.0.2.2/32",
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
                ("port-1", "compute-1"),
                ("port-1", "compute-2"),
                ("port-2", "compute-1"),
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
            for host in ("compute-1", "compute-2"):
                plugin.report_aria_acl_port_status(None, {
                    "port_id": "port-1",
                    "host": host,
                    "status": "ready",
                })

            with self.assertRaises(AriaAclConflict):
                plugin.get_aria_acl_port_status(None, "port-1")
            exact_id = encode_port_status_id("port-1", "compute-2")
            self.assertEqual(
                "compute-2",
                plugin.get_aria_acl_port_status(None, exact_id)["host"],
            )
            plugin.delete_aria_acl_port_status(None, exact_id)
            self.assertEqual(
                "compute-1",
                plugin.get_aria_acl_port_status(None, "port-1")["host"],
            )
            repository.close()
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()

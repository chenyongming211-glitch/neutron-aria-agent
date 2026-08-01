from __future__ import absolute_import

import types

from neutron_aria.acl_contract import port_contract_eligibility
from neutron_aria.agent.effective_acl import ACL_DEGRADED
from neutron_aria.agent.effective_acl import ACL_NOT_REQUESTED
from neutron_aria.agent.effective_acl import ACL_UNSUPPORTED
from neutron_aria.agent.effective_acl import EffectiveAclIndex


PORT_SUMMARY_FIELDS = (
    "aria_acl_enabled",
    "aria_acl_effective_policy_id",
    "aria_acl_effective_policy_name",
    "aria_acl_effective_source",
    "aria_acl_binding_id",
    "aria_acl_effective_revision",
    "aria_acl_runtime_status",
    "aria_acl_runtime_host",
    "aria_acl_runtime_reason",
)


class PortSummarySnapshot(object):
    """One immutable desired/runtime view shared by a port read operation."""

    def __init__(self, effective_payload, statuses):
        self.effective_index = EffectiveAclIndex.from_payload(effective_payload)
        self.statuses = dict(
            ((row.get("port_id"), row.get("host")), dict(row))
            for row in statuses or []
            if row.get("port_id") and row.get("host")
        )

    def extend(self, port):
        eligible, disposition = port_contract_eligibility(port)
        effective = self.effective_index.effective_for_port(port, {
            "eligible": eligible,
            "disposition": disposition,
        })
        port.update(self._desired_fields(effective))
        port.update(self._runtime_fields(port, effective))
        return port

    @staticmethod
    def extend_unavailable(port, reason="projection_unavailable"):
        port.update({
            "aria_acl_enabled": None,
            "aria_acl_effective_policy_id": None,
            "aria_acl_effective_policy_name": None,
            "aria_acl_effective_source": "unknown",
            "aria_acl_binding_id": None,
            "aria_acl_effective_revision": None,
            "aria_acl_runtime_status": "unknown",
            "aria_acl_runtime_host": None,
            "aria_acl_runtime_reason": reason,
        })
        return port

    def _desired_fields(self, effective):
        return {
            "aria_acl_enabled": effective.get("enabled") is True,
            "aria_acl_effective_policy_id": effective.get("policy_id"),
            "aria_acl_effective_policy_name": effective.get("policy_name"),
            "aria_acl_effective_source": effective.get("source") or "none",
            "aria_acl_binding_id": effective.get("binding_id"),
            "aria_acl_effective_revision": effective.get("revision"),
        }

    def _runtime_fields(self, port, effective):
        if effective.get("enabled") is not True:
            status = effective.get("status")
            if status not in (ACL_NOT_REQUESTED, ACL_DEGRADED, ACL_UNSUPPORTED):
                status = "unknown"
            return self._runtime(status, None, effective.get("reason"))

        binding_host = port.get("binding:host_id")
        if not binding_host:
            return self._runtime("pending", None, "port_unbound")

        row = self.statuses.get((port.get("id"), binding_host))
        if row is None:
            return self._runtime("pending", None, "status_not_reported")
        if row.get("stale"):
            return self._runtime("unknown", binding_host, "status_stale")
        if (
            row.get("effective_policy_id") != effective.get("policy_id") or
            row.get("binding_id") != effective.get("binding_id")
        ):
            return self._runtime(
                "pending",
                binding_host,
                "status_projection_mismatch",
            )

        runtime_status = row.get("runtime_status") or row.get("status") or "unknown"
        runtime_status = self._legacy_runtime_status(
            runtime_status,
            row.get("effective_action"),
        )
        reason = row.get("reason")
        if reason is None and runtime_status != "applied":
            reason = runtime_status
        return self._runtime(runtime_status, binding_host, reason)

    @staticmethod
    def _legacy_runtime_status(status, effective_action):
        value = str(status or "unknown").strip().lower()
        if value in ("ready", "applied"):
            return "degraded" if effective_action == "bypass" else "applied"
        if value in ("degraded", "blocked", "error", "failed"):
            return "degraded"
        if value == "unsupported":
            return "unsupported"
        if value in ("pending", "not_requested"):
            return "pending"
        return "unknown"

    @staticmethod
    def _runtime(status, host, reason):
        return {
            "aria_acl_runtime_status": status,
            "aria_acl_runtime_host": host,
            "aria_acl_runtime_reason": reason,
        }


def install_legacy_port_projection(service_plugin, core_plugin=None):
    """Install one batch-aware read wrapper on a legacy Neutron core plugin."""

    if core_plugin is None:
        try:
            from neutron import manager
        except ImportError:
            return False
        core_plugin = manager.NeutronManager.get_plugin()
        if core_plugin is None:
            raise RuntimeError("Neutron core plugin is unavailable for aria_acl projection")

    # Legacy Neutron applies dict extenders once per ORM row. Wrapping only the
    # two read methods lets get_ports build one filtered projection snapshot
    # instead of issuing policy/status queries for every port.
    core_plugin._aria_acl_port_projection_plugin = service_plugin
    if getattr(core_plugin, "_aria_acl_port_projection_installed", False):
        return True

    original_get_port = getattr(core_plugin, "get_port", None)
    original_get_ports = getattr(core_plugin, "get_ports", None)
    if not callable(original_get_port) or not callable(original_get_ports):
        raise RuntimeError("Neutron core plugin lacks get_port/get_ports projection hooks")

    core_plugin._aria_acl_original_get_port = original_get_port
    core_plugin._aria_acl_original_get_ports = original_get_ports
    core_plugin.get_port = _bound_method(_projected_get_port, core_plugin)
    core_plugin.get_ports = _bound_method(_projected_get_ports, core_plugin)
    core_plugin._aria_acl_port_projection_installed = True
    return True


def _projected_get_port(core_plugin, context, port_id, fields=None):
    port = core_plugin._aria_acl_original_get_port(
        context,
        port_id,
        fields=None,
    )
    core_plugin._aria_acl_port_projection_plugin.extend_aria_acl_port_dicts(
        context,
        [port],
    )
    return _select_fields(port, fields)


def _projected_get_ports(
    core_plugin,
    context,
    filters=None,
    fields=None,
    sorts=None,
    limit=None,
    marker=None,
    page_reverse=False,
):
    ports = core_plugin._aria_acl_original_get_ports(
        context,
        filters=filters,
        fields=None,
        sorts=sorts,
        limit=limit,
        marker=marker,
        page_reverse=page_reverse,
    )
    core_plugin._aria_acl_port_projection_plugin.extend_aria_acl_port_dicts(
        context,
        ports,
    )
    return [_select_fields(port, fields) for port in ports]


def _select_fields(value, fields):
    if not fields:
        return value
    return dict((field, value[field]) for field in fields if field in value)


def _bound_method(function, instance):
    try:
        return types.MethodType(function, instance)
    except TypeError:
        return types.MethodType(function, instance, instance.__class__)

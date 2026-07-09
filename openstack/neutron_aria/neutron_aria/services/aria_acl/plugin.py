from __future__ import absolute_import

import calendar
import datetime
import logging
import os
import time

from neutron_aria.agent.effective_acl import EffectiveAclIndex
from neutron_aria.db.aria_acl.api import InMemoryAriaAclRepository
from neutron_aria.db.aria_acl.api import NeutronDbAriaAclRepository


LOG = logging.getLogger(__name__)
PLUGIN_TYPE = "aria_acl"
PLUGIN_DESCRIPTION = "Aria ACL Neutron service plugin"
DEFAULT_PORT_STATUS_STALE_SECONDS = 90


class AriaAclPlugin(object):
    supported_extension_aliases = ["aria-acl"]

    def __init__(
        self,
        repository=None,
        port_status_stale_seconds=None,
        now=None,
        notifier=None,
    ):
        self.repository = repository
        self._fallback_repository = InMemoryAriaAclRepository()
        self.port_status_stale_seconds = port_status_stale_seconds
        self.now = now or time.time
        self.notifier = notifier if notifier is not None else build_aria_acl_notifier()

    def get_plugin_type(self):
        return PLUGIN_TYPE

    def get_plugin_description(self):
        return PLUGIN_DESCRIPTION

    def create_aria_acl_policy(self, context, aria_acl_policy):
        policy = self._repo(context).create_policy(
            self._unwrap(aria_acl_policy, "aria_acl_policy")
        )
        self._notify_acl_change(context, "policy", "create", current=policy)
        return policy

    def get_aria_acl_policies(
        self,
        context,
        filters=None,
        fields=None,
        sorts=None,
        limit=None,
        marker=None,
        page_reverse=False,
    ):
        return self._repo(context).list_policies(filters=filters)

    def get_aria_acl_policy(self, context, policy_id, fields=None):
        return self._repo(context).get_policy(policy_id)

    def update_aria_acl_policy(self, context, policy_id, aria_acl_policy):
        policy = self._repo(context).update_policy(
            policy_id,
            self._unwrap(aria_acl_policy, "aria_acl_policy"),
        )
        self._notify_acl_change(context, "policy", "update", current=policy)
        return policy

    def delete_aria_acl_policy(self, context, policy_id):
        repo = self._repo(context)
        policy = repo.get_policy(policy_id)
        repo.delete_policy(policy_id)
        self._notify_acl_change(
            context,
            "policy",
            "delete",
            current=policy,
            resource_id=policy_id,
        )

    def create_aria_acl_rule(self, context, aria_acl_rule):
        rule = self._repo(context).create_rule(
            self._unwrap(aria_acl_rule, "aria_acl_rule")
        )
        self._notify_acl_change(context, "rule", "create", current=rule)
        return rule

    def get_aria_acl_rules(
        self,
        context,
        filters=None,
        fields=None,
        sorts=None,
        limit=None,
        marker=None,
        page_reverse=False,
    ):
        return self._repo(context).list_rules(filters=filters)

    def get_aria_acl_rule(self, context, rule_id, fields=None):
        return self._repo(context).get_rule(rule_id)

    def update_aria_acl_rule(self, context, rule_id, aria_acl_rule):
        rule = self._repo(context).update_rule(
            rule_id,
            self._unwrap(aria_acl_rule, "aria_acl_rule"),
        )
        self._notify_acl_change(context, "rule", "update", current=rule)
        return rule

    def delete_aria_acl_rule(self, context, rule_id):
        repo = self._repo(context)
        rule = repo.get_rule(rule_id)
        repo.delete_rule(rule_id)
        self._notify_acl_change(
            context,
            "rule",
            "delete",
            current=rule,
            resource_id=rule_id,
        )

    def create_aria_acl_address_set(self, context, aria_acl_address_set):
        address_set = self._repo(context).create_address_set(
            self._unwrap(aria_acl_address_set, "aria_acl_address_set")
        )
        self._notify_acl_change(
            context,
            "address_set",
            "create",
            current=address_set,
        )
        return address_set

    def get_aria_acl_address_sets(
        self,
        context,
        filters=None,
        fields=None,
        sorts=None,
        limit=None,
        marker=None,
        page_reverse=False,
    ):
        return self._repo(context).list_address_sets(filters=filters)

    def get_aria_acl_address_set(self, context, address_set_id, fields=None):
        return self._repo(context).get_address_set(address_set_id)

    def update_aria_acl_address_set(self, context, address_set_id, aria_acl_address_set):
        address_set = self._repo(context).update_address_set(
            address_set_id,
            self._unwrap(aria_acl_address_set, "aria_acl_address_set"),
        )
        self._notify_acl_change(
            context,
            "address_set",
            "update",
            current=address_set,
        )
        return address_set

    def delete_aria_acl_address_set(self, context, address_set_id):
        repo = self._repo(context)
        address_set = repo.get_address_set(address_set_id)
        repo.delete_address_set(address_set_id)
        self._notify_acl_change(
            context,
            "address_set",
            "delete",
            current=address_set,
            resource_id=address_set_id,
        )

    def create_aria_acl_binding(self, context, aria_acl_binding):
        binding = self._repo(context).create_binding(
            self._unwrap(aria_acl_binding, "aria_acl_binding")
        )
        self._notify_acl_change(context, "binding", "create", current=binding)
        return binding

    def get_aria_acl_bindings(
        self,
        context,
        filters=None,
        fields=None,
        sorts=None,
        limit=None,
        marker=None,
        page_reverse=False,
    ):
        return self._repo(context).list_bindings(filters=filters)

    def get_aria_acl_binding(self, context, binding_id, fields=None):
        return self._repo(context).get_binding(binding_id)

    def update_aria_acl_binding(self, context, binding_id, aria_acl_binding):
        binding = self._repo(context).update_binding(
            binding_id,
            self._unwrap(aria_acl_binding, "aria_acl_binding"),
        )
        self._notify_acl_change(context, "binding", "update", current=binding)
        return binding

    def delete_aria_acl_binding(self, context, binding_id):
        repo = self._repo(context)
        binding = repo.get_binding(binding_id)
        repo.delete_binding(binding_id)
        self._notify_acl_change(
            context,
            "binding",
            "delete",
            current=binding,
            resource_id=binding_id,
        )

    def report_aria_acl_port_status(self, context, aria_acl_port_status):
        return self._project_port_status(
            self._repo(context).upsert_port_status(
                self._unwrap(aria_acl_port_status, "aria_acl_port_status")
            )
        )

    def create_aria_acl_port_status(self, context, aria_acl_port_status):
        return self.report_aria_acl_port_status(context, aria_acl_port_status)

    def update_aria_acl_port_status(self, context, port_id, aria_acl_port_status):
        values = self._unwrap(aria_acl_port_status, "aria_acl_port_status")
        values.setdefault("port_id", port_id)
        return self._project_port_status(self._repo(context).upsert_port_status(values))

    def get_aria_acl_port_statuses(
        self,
        context,
        filters=None,
        fields=None,
        sorts=None,
        limit=None,
        marker=None,
        page_reverse=False,
    ):
        return [
            self._project_port_status(status)
            for status in self._repo(context).list_port_statuses(filters=filters)
        ]

    def get_aria_acl_port_status(self, context, port_id, host=None, fields=None):
        status = self._repo(context).get_port_status(port_id, host=host)
        if host is None and isinstance(status, list):
            return self._project_port_status(status[0]) if status else None
        return self._project_port_status(status)

    def delete_aria_acl_port_status(self, context, port_id, host=None):
        status = self.get_aria_acl_port_status(context, port_id, host=host)
        self._repo(context).delete_port_status(port_id, host=host)
        return status or {}

    def get_aria_acl_effective_payload(self, context):
        return self._repo(context).to_effective_payload()

    def get_aria_acl_effective_for_port(self, context, port):
        index = EffectiveAclIndex.from_payload(self.get_aria_acl_effective_payload(context))
        return index.effective_for_port(port, {"eligible": True})

    def get_aria_acl_effective_for_port_id(
        self,
        context,
        port_id,
        port=None,
        neutron_port_getter=None,
    ):
        resolved_port = self._unwrap(port, "port")
        if neutron_port_getter is not None:
            resolved_port = self._unwrap(neutron_port_getter(context, port_id), "port")
        resolved_port = dict(resolved_port or {})
        resolved_port.setdefault("id", port_id)
        return self.get_aria_acl_effective_for_port(context, resolved_port)

    def _unwrap(self, body, key):
        if body is None:
            return {}
        return body.get(key, body)

    def _repo(self, context):
        if self.repository is not None:
            return self.repository
        if context is not None and getattr(context, "session", None) is not None:
            return NeutronDbAriaAclRepository(
                context,
                auto_create=_env_flag("ARIA_ACL_DB_AUTO_CREATE", default=False),
            )
        return self._fallback_repository

    def _notify_acl_change(self, context, resource, operation, current=None, resource_id=None):
        payload = {
            "domain": "acl",
            "resource": resource,
            "operation": operation,
            "resource_id": resource_id or (current or {}).get("id"),
        }
        for field in (
            "policy_id",
            "target_type",
            "target_id",
            "revision_number",
        ):
            if current and current.get(field) is not None:
                payload[field] = current.get(field)
        try:
            self.notifier.notify(context, **payload)
        except Exception as exc:
            LOG.warning(
                "aria_acl_rpc_notification_failed resource=%s operation=%s "
                "resource_id=%s error=%s",
                resource,
                operation,
                payload.get("resource_id"),
                exc,
            )

    def _project_port_status(self, status):
        if status is None:
            return None
        result = dict(status)
        result.setdefault("last_reported_at", result.get("updated_at"))
        stale = self._port_status_is_stale(result)
        result["stale"] = stale
        result["runtime_status"] = "stale" if stale else (
            result.get("status") or "unknown"
        )
        return result

    def _port_status_is_stale(self, status):
        stale_seconds = self._port_status_stale_seconds()
        if stale_seconds < 0:
            return False
        updated_at = status.get("updated_at")
        if not updated_at:
            return True
        updated_ts = _timestamp_seconds(updated_at)
        if updated_ts is None:
            return True
        return (float(self.now()) - updated_ts) > stale_seconds

    def _port_status_stale_seconds(self):
        if self.port_status_stale_seconds is not None:
            return int(self.port_status_stale_seconds)
        return _env_int(
            "ARIA_ACL_PORT_STATUS_STALE_SECONDS",
            DEFAULT_PORT_STATUS_STALE_SECONDS,
        )


class NoopAriaAclNotifier(object):
    def notify(self, context, **payload):
        return None


class AriaAclAgentNotifier(object):
    def __init__(self, client, topics):
        self.client = client
        self.topics = topics

    def notify(self, context, **payload):
        topic = _rpc_topic_name(
            self.topics,
            getattr(self.topics, "AGENT", "q-agent-notifier"),
            "aria_acl",
            getattr(self.topics, "UPDATE", "update"),
        )
        cctxt = self.client.prepare(topic=topic, fanout=True)
        cctxt.cast(context, "aria_acl_update", **payload)


def build_aria_acl_notifier():
    try:
        from neutron.common import rpc as n_rpc
        from neutron.common import topics
        import oslo_messaging
    except Exception:
        return NoopAriaAclNotifier()
    try:
        target = oslo_messaging.Target(
            topic=getattr(topics, "AGENT", "q-agent-notifier"),
            version="1.4",
        )
        return AriaAclAgentNotifier(n_rpc.get_client(target), topics)
    except Exception as exc:
        LOG.warning("aria_acl_rpc_notifier_init_failed error=%s", exc)
        return NoopAriaAclNotifier()


def _rpc_topic_name(topics, topic, resource, operation):
    get_topic_name = getattr(topics, "get_topic_name", None)
    if get_topic_name is not None:
        return get_topic_name(topic, resource, operation)
    return "%s-%s-%s" % (topic, resource, operation)


def _env_flag(name, default=False):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name, default):
    value = os.environ.get(name)
    if value is None:
        return int(default)
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)


def _timestamp_seconds(value):
    if isinstance(value, datetime.datetime):
        dt = value
    else:
        if value is None:
            return None
        value = str(value).rstrip("Z")
        dt = None
        for pattern in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
            try:
                dt = datetime.datetime.strptime(value, pattern)
                break
            except ValueError:
                pass
        if dt is None:
            return None
    return calendar.timegm(dt.timetuple()) + (dt.microsecond / 1000000.0)

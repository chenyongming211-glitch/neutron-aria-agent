from __future__ import absolute_import

import datetime
import json
import logging
import os
import time

try:
    from neutron import policy as neutron_policy
except ImportError:
    neutron_policy = None

from neutron_aria.agent.effective_acl import EffectiveAclIndex
from neutron_aria.acl_contract import port_contract_eligibility
from neutron_aria.db.aria_acl.api import InMemoryAriaAclRepository
from neutron_aria.db.aria_acl.api import NeutronDbAriaAclRepository
from neutron_aria.db.aria_acl.query import PortStatusProjection
from neutron_aria.db.aria_acl.query import decode_port_status_id
from neutron_aria.db.aria_acl.query import is_port_status_id
from neutron_aria.db.aria_acl.query import project_fields
from neutron_aria.services.aria_acl.exceptions import ErrorMappingRepositoryProxy
from neutron_aria.services.aria_acl.port_projection import PortSummarySnapshot


LOG = logging.getLogger(__name__)
PLUGIN_TYPE = "aria_acl"
PLUGIN_DESCRIPTION = "Aria ACL Neutron service plugin"
DEFAULT_PORT_STATUS_STALE_SECONDS = 90


def _enforce_collection_read(context, action, collection):
    if neutron_policy is not None:
        neutron_policy.enforce(
            context,
            action,
            {},
            pluralized=collection,
        )


class AriaAclPlugin(object):
    __native_sorting_support = True
    __native_pagination_support = True
    __native_bulk_support = True
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

    def create_aria_acl_policy_bulk(self, context, aria_acl_policies):
        return self._create_acl_bulk(
            context,
            "policy",
            "aria_acl_policy",
            "aria_acl_policies",
            aria_acl_policies,
        )

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
        _enforce_collection_read(
            context,
            "get_aria_acl_policy",
            "aria_acl_policies",
        )
        return self._repo(context).list_policies(
            filters=filters,
            fields=fields,
            sorts=sorts,
            limit=limit,
            marker=marker,
            page_reverse=page_reverse,
        )

    def get_aria_acl_policy(self, context, policy_id, fields=None):
        return self._repo(context).get_policy(policy_id, fields=fields)

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

    def create_aria_acl_rule_bulk(self, context, aria_acl_rules):
        return self._create_acl_bulk(
            context,
            "rule",
            "aria_acl_rule",
            "aria_acl_rules",
            aria_acl_rules,
        )

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
        _enforce_collection_read(
            context,
            "get_aria_acl_rule",
            "aria_acl_rules",
        )
        return self._repo(context).list_rules(
            filters=filters,
            fields=fields,
            sorts=sorts,
            limit=limit,
            marker=marker,
            page_reverse=page_reverse,
        )

    def get_aria_acl_rule(self, context, rule_id, fields=None):
        return self._repo(context).get_rule(rule_id, fields=fields)

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

    def create_aria_acl_address_set_bulk(self, context, aria_acl_address_sets):
        return self._create_acl_bulk(
            context,
            "address_set",
            "aria_acl_address_set",
            "aria_acl_address_sets",
            aria_acl_address_sets,
        )

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
        _enforce_collection_read(
            context,
            "get_aria_acl_address_set",
            "aria_acl_address_sets",
        )
        return self._repo(context).list_address_sets(
            filters=filters,
            fields=fields,
            sorts=sorts,
            limit=limit,
            marker=marker,
            page_reverse=page_reverse,
        )

    def get_aria_acl_address_set(self, context, address_set_id, fields=None):
        return self._repo(context).get_address_set(
            address_set_id,
            fields=fields,
        )

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

    def create_aria_acl_binding_bulk(self, context, aria_acl_bindings):
        return self._create_acl_bulk(
            context,
            "binding",
            "aria_acl_binding",
            "aria_acl_bindings",
            aria_acl_bindings,
        )

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
        _enforce_collection_read(
            context,
            "get_aria_acl_binding",
            "aria_acl_bindings",
        )
        return self._repo(context).list_bindings(
            filters=filters,
            fields=fields,
            sorts=sorts,
            limit=limit,
            marker=marker,
            page_reverse=page_reverse,
        )

    def get_aria_acl_binding(self, context, binding_id, fields=None):
        return self._repo(context).get_binding(binding_id, fields=fields)

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

    COUNTER_SUMMARY_FIELDS = (
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
    )

    def report_aria_acl_port_status(self, context, aria_acl_port_status):
        payload = dict(
            self._unwrap(aria_acl_port_status, "aria_acl_port_status")
        )
        counter_blobs = payload.pop("counters_rows", None)
        sampled_at_ms = payload.pop("counters_sampled_at_ms", None)
        counters_error = payload.pop("counters_error", None)
        if counters_error is not None:
            # Datapath reported a read failure: keep the last good snapshot
            # (spec §10); staleness stays visible via counters_sampled_at age.
            LOG.warning(
                "aria_acl port counters unavailable port_id=%s error=%s",
                payload.get("port_id"),
                counters_error,
            )
        elif counter_blobs:
            self._attach_counter_summary(payload, counter_blobs, sampled_at_ms)
        else:
            # No counter sample this cycle and no error: clear the summary so
            # stale values from a previous cycle are never re-presented.
            for field in self.COUNTER_SUMMARY_FIELDS:
                payload[field] = None
        self._persist_counter_rows(context, payload, counter_blobs, sampled_at_ms)
        return self._project_port_status(
            self._repo(context).upsert_port_status(payload)
        )

    @staticmethod
    def _counter_sampled_at(sampled_at_ms):
        if sampled_at_ms is None:
            return None
        try:
            seconds = float(sampled_at_ms) / 1000.0
        except (TypeError, ValueError):
            return None
        if seconds <= 0:
            return None
        if hasattr(datetime, "timezone"):
            return datetime.datetime.fromtimestamp(
                seconds, datetime.timezone.utc
            ).replace(tzinfo=None)
        return datetime.datetime.utcfromtimestamp(seconds)

    @classmethod
    def _attach_counter_summary(cls, payload, counter_blobs, sampled_at_ms):
        if not counter_blobs:
            return
        port_id = payload.get("port_id")
        blob = None
        for candidate in counter_blobs:
            if candidate.get("port_id") == port_id:
                blob = candidate
                break
        if blob is None:
            return
        summary = blob.get("summary") or {}
        payload["counters_sampled_at"] = cls._counter_sampled_at(
            sampled_at_ms
        )
        payload["counters_policy_packets"] = summary.get("policy_packets")
        payload["counters_policy_bytes"] = summary.get("policy_bytes")
        payload["counters_policy_allow_packets"] = summary.get(
            "policy_allow_packets"
        )
        payload["counters_policy_dropped_packets"] = summary.get(
            "policy_dropped_packets"
        )
        payload["counters_policy_dropped_bytes"] = summary.get(
            "policy_dropped_bytes"
        )
        payload["counters_drop_packets"] = summary.get("drop_packets")
        payload["counters_drop_bytes"] = summary.get("drop_bytes")
        payload["counters_truncated"] = bool(blob.get("truncated"))
        payload["counters_reset_detected"] = bool(blob.get("reset_detected"))
        groups = blob.get("groups")
        if groups is not None:
            payload["counters_group_map"] = json.dumps(groups)
        else:
            payload["counters_group_map"] = None
        port_row = None
        for row in blob.get("rows") or []:
            if row.get("kind") == "port":
                port_row = row
                break
        if port_row is not None:
            payload["counters_policy_pps"] = port_row.get("pps")
        payload["counters_drop_pps"] = blob.get("drop_pps")

    @staticmethod
    def _direction_name(direction):
        if direction == 0:
            return "ingress"
        if direction == 1:
            return "egress"
        return None

    @classmethod
    def _counter_rows(cls, counter_blobs, sampled_at_ms):
        sampled_at = cls._counter_sampled_at(sampled_at_ms)
        rows = []
        for blob in counter_blobs or []:
            for row in blob.get("rows") or []:
                key = row.get("key") or {}
                rows.append({
                    "kind": row.get("kind"),
                    "src_id": key.get("src_id"),
                    "dst_id": key.get("dst_id"),
                    "proto": key.get("proto"),
                    "direction": cls._direction_name(key.get("direction")),
                    "reason": key.get("reason"),
                    "packets": row.get("packets") or 0,
                    "bytes": row.get("bytes") or 0,
                    "dropped_packets": row.get("dropped_packets"),
                    "dropped_bytes": row.get("dropped_bytes"),
                    "pps": row.get("pps"),
                    "bps": row.get("bps"),
                    "sampled_at": sampled_at,
                })
        return rows

    def _persist_counter_rows(
        self, context, payload, counter_blobs, sampled_at_ms
    ):
        if not counter_blobs:
            return
        port_id = payload.get("port_id")
        host = payload.get("host")
        if not port_id or not host:
            return
        repository = self._repo(context)
        upsert = getattr(repository, "upsert_port_counters", None)
        if upsert is None:
            return
        try:
            upsert(
                port_id,
                host,
                self._counter_rows(counter_blobs, sampled_at_ms),
            )
        except Exception as exc:
            LOG.warning(
                "aria_acl port counter persistence failed port_id=%s "
                "host=%s error=%s",
                port_id,
                host,
                exc,
            )

    def create_aria_acl_port_status(self, context, aria_acl_port_status):
        return self.report_aria_acl_port_status(context, aria_acl_port_status)

    def create_aria_acl_port_status_bulk(self, context, aria_acl_port_statuses):
        return self._create_acl_bulk(
            context,
            "port_status",
            "aria_acl_port_status",
            "aria_acl_port_statuses",
            aria_acl_port_statuses,
            notify=False,
        )

    def update_aria_acl_port_status(self, context, port_id, aria_acl_port_status):
        values = self._unwrap(aria_acl_port_status, "aria_acl_port_status")
        repository = self._repo(context)
        if is_port_status_id(port_id):
            exact_port_id, exact_host = decode_port_status_id(port_id)
            existing = repository.get_port_status(
                exact_port_id,
                host=exact_host,
            )
            if existing is None:
                repository.get_port_status_resource(port_id)
            current = dict(existing)
            current.update(values)
            current["port_id"] = exact_port_id
            current["host"] = exact_host
            values = current
        else:
            values.setdefault("port_id", port_id)
        return self._project_port_status(repository.upsert_port_status(values))

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
        _enforce_collection_read(
            context,
            "get_aria_acl_port_status",
            "aria_acl_port_statuses",
        )
        return self._repo(context).list_port_statuses(
            filters=filters,
            fields=fields,
            sorts=sorts,
            limit=limit,
            marker=marker,
            page_reverse=page_reverse,
            projection=self._port_status_projection(),
        )

    def get_aria_acl_port_status(self, context, port_id, host=None, fields=None):
        repository = self._repo(context)
        if host is not None:
            status = repository.get_port_status(port_id, host=host)
        else:
            status = repository.get_port_status_resource(port_id)
        if status is None:
            return None
        projected = self._project_port_status(status)
        group_map = projected.get("counters_group_map")
        if isinstance(group_map, str) and group_map.strip():
            try:
                parsed = json.loads(group_map)
                if isinstance(parsed, list):
                    projected["aria_acl_port_group_map"] = dict(
                        (int(group.get("id")), group.get("cidrs") or [])
                        for group in parsed
                        if isinstance(group, dict) and group.get("id") is not None
                    )
            except (TypeError, ValueError) as exc:
                LOG.warning(
                    "aria_acl port group map parse failed port_id=%s error=%s",
                    port_id,
                    exc,
                )
        counter_rows = getattr(repository, "get_port_counters", None)
        if counter_rows is not None:
            try:
                projected["aria_acl_port_counters"] = counter_rows(
                    port_id,
                    host=status.get("host"),
                )
            except Exception as exc:
                LOG.warning(
                    "aria_acl port counter read failed port_id=%s error=%s",
                    port_id,
                    exc,
                )
        return project_fields(projected, fields)

    def delete_aria_acl_port_status(self, context, port_id, host=None):
        repository = self._repo(context)
        if host is not None:
            repository.delete_port_status(port_id, host=host)
        else:
            repository.delete_port_status_resource(port_id)
        return {}

    def get_aria_acl_effective_payload(self, context):
        return self._repo(context).to_effective_payload()

    def get_aria_acl_effective_for_port(self, context, port):
        index = EffectiveAclIndex.from_payload(self.get_aria_acl_effective_payload(context))
        eligible, disposition = port_contract_eligibility(port)
        return index.effective_for_port(port, {
            "eligible": eligible,
            "disposition": disposition,
        })

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

    def extend_aria_acl_port_dict(self, port, context=None):
        return self.extend_aria_acl_port_dicts(context, [port])[0]

    def extend_aria_acl_port_dicts(self, context, ports):
        ports = list(ports or [])
        if not ports:
            return ports
        try:
            repository = self._repo(context)
            port_ids = sorted(set(
                port.get("id") for port in ports if port.get("id")
            ))
            statuses = repository.list_port_statuses(
                filters={"port_id": port_ids},
                projection=self._port_status_projection(),
            ) if port_ids else []
            snapshot = PortSummarySnapshot(
                repository.to_effective_payload(),
                statuses,
            )
        except Exception as exc:
            LOG.warning(
                "aria_acl_port_projection_unavailable ports=%s error=%s",
                len(ports),
                exc,
            )
            for port in ports:
                PortSummarySnapshot.extend_unavailable(port)
            return ports
        for port in ports:
            snapshot.extend(port)
        return ports

    def _unwrap(self, body, key):
        if body is None:
            return {}
        return body.get(key, body)

    def _repo(self, context):
        if self.repository is not None:
            return ErrorMappingRepositoryProxy(self.repository)
        if context is None:
            return ErrorMappingRepositoryProxy(self._fallback_repository)
        if getattr(context, "session", None) is not None:
            return ErrorMappingRepositoryProxy(
                NeutronDbAriaAclRepository(
                    context,
                    auto_create=_env_flag("ARIA_ACL_DB_AUTO_CREATE", default=False),
                )
            )
        raise RuntimeError("aria_acl_database_session_required")

    def _create_acl_bulk(
        self,
        context,
        resource,
        item_key,
        collection_key,
        body,
        notify=True,
    ):
        items = self._unwrap(body, collection_key)
        values_list = [self._unwrap(item, item_key) for item in (items or [])]
        created = self._repo(context).bulk_create(resource, values_list)
        if notify and created:
            summary = {"resource_count": len(created)}
            for field in ("policy_id", "target_type", "target_id"):
                values = set(
                    value.get(field)
                    for value in created
                    if value.get(field) is not None
                )
                if len(values) == 1:
                    summary[field] = values.pop()
            self._notify_acl_change(
                context,
                resource,
                "bulk_create",
                current=summary,
            )
        return created

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
            "resource_count",
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
        return self._port_status_projection().project(status)

    def _port_status_projection(self):
        return PortStatusProjection(
            now_epoch=float(self.now()),
            stale_seconds=self._port_status_stale_seconds(),
        )

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

from __future__ import absolute_import

import json

from neutron_aria.agent.config import resolved_acl_page_size
from neutron_aria.agent.effective_acl import EffectiveAclIndex


ACL_SOURCE_DISABLED = "disabled"
ACL_SOURCE_FIXTURE = "fixture"
ACL_SOURCE_NEUTRON = "neutron"
ACL_PAYLOAD_COLLECTIONS = ("policies", "rules", "address_sets", "bindings")


class AclSourceError(Exception):
    pass


class DisabledAclSource(object):
    name = ACL_SOURCE_DISABLED

    def load_index(self):
        return None


class FixtureAclSource(object):
    name = ACL_SOURCE_FIXTURE

    def __init__(self, path, ipv6_acl_enabled=False):
        if not path:
            raise AclSourceError("acl fixture source requires fixture_path")
        self.path = path
        self.ipv6_acl_enabled = bool(ipv6_acl_enabled)

    def load_index(self):
        with open(self.path, "r") as stream:
            payload = json.load(stream)
        return EffectiveAclIndex.from_payload(
            _validated_payload(payload, self.name),
            ipv6_acl_enabled=self.ipv6_acl_enabled,
        )


class NeutronAclSource(object):
    name = ACL_SOURCE_NEUTRON

    def __init__(self, neutron_client=None, ipv6_acl_enabled=False):
        self.neutron_client = neutron_client
        self.ipv6_acl_enabled = bool(ipv6_acl_enabled)

    def load_index(self):
        if self.neutron_client is None:
            raise AclSourceError(
                "neutron acl source requires an aria_acl-capable neutron client"
            )
        try:
            payload = self._load_payload()
        except AclSourceError:
            raise
        except Exception as exc:
            raise AclSourceError("neutron acl source failed: %s" % exc)
        return EffectiveAclIndex.from_payload(
            _validated_payload(payload, self.name),
            ipv6_acl_enabled=self.ipv6_acl_enabled,
        )

    def _load_payload(self):
        if hasattr(self.neutron_client, "get_aria_acl_effective_payload"):
            payload = self.neutron_client.get_aria_acl_effective_payload()
            if not isinstance(payload, dict):
                raise AclSourceError("aria_acl effective payload must be a dict")
            return payload

        return {
            "policies": self._list("aria_acl_policies", "list_aria_acl_policies"),
            "rules": self._list("aria_acl_rules", "list_aria_acl_rules"),
            "address_sets": self._list(
                "aria_acl_address_sets",
                "list_aria_acl_address_sets",
            ),
            "bindings": self._list("aria_acl_bindings", "list_aria_acl_bindings"),
        }

    def _list(self, collection, method_name):
        method = getattr(self.neutron_client, method_name, None)
        if method is None:
            raise AclSourceError(
                "neutron client does not expose aria_acl method %s" % method_name
            )
        result = method()
        if isinstance(result, dict):
            if collection not in result:
                raise AclSourceError(
                    "neutron aria_acl method %s response missing collection %s"
                    % (method_name, collection)
                )
            values = result[collection]
        else:
            values = result or []
        _validate_collection(collection, values, self.name)
        return values


def _validated_payload(payload, source_name):
    if not isinstance(payload, dict):
        raise AclSourceError("%s acl payload must be a JSON object" % source_name)
    validated = {}
    for name in ACL_PAYLOAD_COLLECTIONS:
        values = payload.get(name, [])
        _validate_collection(name, values, source_name)
        validated[name] = values
    return validated


def _validate_collection(collection, values, source_name):
    if not isinstance(values, list):
        raise AclSourceError(
            "%s acl payload collection %s must be a list" % (source_name, collection)
        )
    for index, value in enumerate(values):
        if not isinstance(value, dict):
            raise AclSourceError(
                "%s acl payload collection %s item %s must be an object"
                % (source_name, collection, index)
            )


def build_acl_source(config, neutron_client=None):
    source = getattr(config, "acl_source", None) or ACL_SOURCE_DISABLED
    ipv6_acl_enabled = getattr(config, "ipv6_acl_enabled", False)
    if source == ACL_SOURCE_DISABLED:
        return DisabledAclSource()
    if source == ACL_SOURCE_FIXTURE:
        return FixtureAclSource(
            getattr(config, "acl_fixture_path", ""),
            ipv6_acl_enabled=ipv6_acl_enabled,
        )
    if source == ACL_SOURCE_NEUTRON:
        if neutron_client is None:
            try:
                from neutron_aria.agent.neutron_client import build_aria_acl_client_from_env
                neutron_client = build_aria_acl_client_from_env(
                    page_size=resolved_acl_page_size(config),
                    timeout=config.neutron_api_timeout,
                )
            except Exception as exc:
                raise AclSourceError(
                    "neutron acl source requires aria_acl Neutron API/DB extension: %s" % exc
                )
        return NeutronAclSource(
            neutron_client,
            ipv6_acl_enabled=ipv6_acl_enabled,
        )
    raise AclSourceError("unsupported acl source: %s" % source)


def build_acl_index(config, neutron_client=None):
    return build_acl_source(config, neutron_client=neutron_client).load_index()

from __future__ import absolute_import

import json

from neutron_aria.agent.effective_acl import EffectiveAclIndex


ACL_SOURCE_DISABLED = "disabled"
ACL_SOURCE_FIXTURE = "fixture"
ACL_SOURCE_NEUTRON = "neutron"


class AclSourceError(Exception):
    pass


class DisabledAclSource(object):
    name = ACL_SOURCE_DISABLED

    def load_index(self):
        return None


class FixtureAclSource(object):
    name = ACL_SOURCE_FIXTURE

    def __init__(self, path):
        if not path:
            raise AclSourceError("acl fixture source requires fixture_path")
        self.path = path

    def load_index(self):
        with open(self.path, "r") as stream:
            payload = json.load(stream)
        if not isinstance(payload, dict):
            raise AclSourceError("acl fixture payload must be a JSON object")
        return EffectiveAclIndex.from_payload(payload)


class NeutronAclSource(object):
    name = ACL_SOURCE_NEUTRON

    def load_index(self):
        raise AclSourceError(
            "neutron acl source requires the aria-acl Neutron API/DB extension"
        )


def build_acl_source(config):
    source = getattr(config, "acl_source", None) or ACL_SOURCE_DISABLED
    if source == ACL_SOURCE_DISABLED:
        return DisabledAclSource()
    if source == ACL_SOURCE_FIXTURE:
        return FixtureAclSource(getattr(config, "acl_fixture_path", ""))
    if source == ACL_SOURCE_NEUTRON:
        return NeutronAclSource()
    raise AclSourceError("unsupported acl source: %s" % source)


def build_acl_index(config):
    return build_acl_source(config).load_index()

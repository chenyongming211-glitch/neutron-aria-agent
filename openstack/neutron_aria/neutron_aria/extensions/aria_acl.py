from __future__ import absolute_import


ALIAS = "aria-acl"
SERVICE_TYPE = "aria_acl"
NAME = "Aria ACL"
DESCRIPTION = "Explicit Aria ACL enhancement objects for neutron-aria-agent"
UPDATED = "2026-06-26T00:00:00-00:00"

try:
    from neutron.api import extensions as api_extensions
except Exception:
    api_extensions = None

try:
    from neutron.api.v2 import resource_helper
except Exception:
    resource_helper = None


_BASE_DESCRIPTOR = (
    api_extensions.APIExtensionDescriptor
    if api_extensions is not None and hasattr(api_extensions, "APIExtensionDescriptor")
    else object
)


RESOURCE_COLLECTIONS = {
    "policies": "aria_acl_policies",
    "rules": "aria_acl_rules",
    "address_sets": "aria_acl_address_sets",
    "bindings": "aria_acl_bindings",
    "port_statuses": "aria_acl_port_statuses",
}

PORT_READONLY_ATTRIBUTES = {
    "aria_acl_enabled": {"allow_post": False, "allow_put": False, "is_visible": True},
    "aria_acl_effective_policy_id": {
        "allow_post": False,
        "allow_put": False,
        "is_visible": True,
    },
    "aria_acl_effective_policy_name": {
        "allow_post": False,
        "allow_put": False,
        "is_visible": True,
    },
    "aria_acl_effective_source": {
        "allow_post": False,
        "allow_put": False,
        "is_visible": True,
    },
    "aria_acl_binding_id": {"allow_post": False, "allow_put": False, "is_visible": True},
    "aria_acl_effective_revision": {
        "allow_post": False,
        "allow_put": False,
        "is_visible": True,
    },
    "aria_acl_runtime_status": {
        "allow_post": False,
        "allow_put": False,
        "is_visible": True,
    },
    "aria_acl_runtime_host": {"allow_post": False, "allow_put": False, "is_visible": True},
    "aria_acl_runtime_reason": {"allow_post": False, "allow_put": False, "is_visible": True},
}

RESOURCE_ATTRIBUTE_MAP = {
    RESOURCE_COLLECTIONS["policies"]: {
        "id": {
            "allow_post": False,
            "allow_put": False,
            "is_visible": True,
            "primary_key": True,
        },
        "tenant_id": {"allow_post": True, "allow_put": False, "is_visible": True},
        "project_id": {"allow_post": True, "allow_put": False, "is_visible": True, "default": None},
        "name": {"allow_post": True, "allow_put": True, "is_visible": True, "default": ""},
        "default_action": {"allow_post": True, "allow_put": True, "is_visible": True, "default": "allow"},
        "stateful": {"allow_post": True, "allow_put": True, "is_visible": True, "default": True},
        "enabled": {"allow_post": True, "allow_put": True, "is_visible": True, "default": True},
        "revision_number": {"allow_post": False, "allow_put": False, "is_visible": True},
    },
    RESOURCE_COLLECTIONS["rules"]: {
        "id": {
            "allow_post": False,
            "allow_put": False,
            "is_visible": True,
            "primary_key": True,
        },
        "tenant_id": {"allow_post": True, "allow_put": False, "is_visible": True},
        "project_id": {"allow_post": True, "allow_put": False, "is_visible": True, "default": None},
        "policy_id": {"allow_post": True, "allow_put": False, "is_visible": True},
        "direction": {"allow_post": True, "allow_put": True, "is_visible": True},
        "priority": {"allow_post": True, "allow_put": True, "is_visible": True},
        "action": {"allow_post": True, "allow_put": True, "is_visible": True},
        "protocol": {"allow_post": True, "allow_put": True, "is_visible": True, "default": None},
        "src_cidr": {"allow_post": True, "allow_put": True, "is_visible": True, "default": None},
        "dst_cidr": {"allow_post": True, "allow_put": True, "is_visible": True, "default": None},
        "src_address_set_id": {"allow_post": True, "allow_put": True, "is_visible": True, "default": None},
        "dst_address_set_id": {"allow_post": True, "allow_put": True, "is_visible": True, "default": None},
        "src_port_min": {"allow_post": True, "allow_put": True, "is_visible": True, "default": None},
        "src_port_max": {"allow_post": True, "allow_put": True, "is_visible": True, "default": None},
        "dst_port_min": {"allow_post": True, "allow_put": True, "is_visible": True, "default": None},
        "dst_port_max": {"allow_post": True, "allow_put": True, "is_visible": True, "default": None},
        "ethertype": {"allow_post": True, "allow_put": True, "is_visible": True, "default": None},
        "enabled": {"allow_post": True, "allow_put": True, "is_visible": True, "default": True},
        "revision_number": {"allow_post": False, "allow_put": False, "is_visible": True},
    },
    RESOURCE_COLLECTIONS["address_sets"]: {
        "id": {
            "allow_post": False,
            "allow_put": False,
            "is_visible": True,
            "primary_key": True,
        },
        "tenant_id": {"allow_post": True, "allow_put": False, "is_visible": True},
        "project_id": {"allow_post": True, "allow_put": False, "is_visible": True, "default": None},
        "name": {"allow_post": True, "allow_put": True, "is_visible": True, "default": ""},
        "members": {"allow_post": True, "allow_put": True, "is_visible": True, "default": []},
        "enabled": {"allow_post": True, "allow_put": True, "is_visible": True, "default": True},
        "revision_number": {"allow_post": False, "allow_put": False, "is_visible": True},
    },
    RESOURCE_COLLECTIONS["bindings"]: {
        "id": {
            "allow_post": False,
            "allow_put": False,
            "is_visible": True,
            "primary_key": True,
        },
        "tenant_id": {"allow_post": True, "allow_put": False, "is_visible": True},
        "project_id": {"allow_post": True, "allow_put": False, "is_visible": True, "default": None},
        "policy_id": {"allow_post": True, "allow_put": False, "is_visible": True},
        "target_type": {"allow_post": True, "allow_put": False, "is_visible": True},
        "target_id": {"allow_post": True, "allow_put": False, "is_visible": True},
        "enabled": {"allow_post": True, "allow_put": True, "is_visible": True, "default": True},
        "revision_number": {"allow_post": False, "allow_put": False, "is_visible": True},
    },
    RESOURCE_COLLECTIONS["port_statuses"]: {
        "id": {
            "allow_post": False,
            "allow_put": False,
            "is_visible": True,
            "primary_key": True,
        },
        "port_id": {"allow_post": True, "allow_put": False, "is_visible": True},
        "tenant_id": {"allow_post": True, "allow_put": False, "is_visible": True},
        "host": {"allow_post": True, "allow_put": False, "is_visible": True},
        "effective_policy_id": {"allow_post": True, "allow_put": True, "is_visible": True, "default": None},
        "binding_id": {"allow_post": True, "allow_put": True, "is_visible": True, "default": None},
        "status": {"allow_post": True, "allow_put": True, "is_visible": True},
        "reason": {"allow_post": True, "allow_put": True, "is_visible": True, "default": None},
        "effective_action": {"allow_post": True, "allow_put": True, "is_visible": True, "default": None},
        "generation": {"allow_post": True, "allow_put": True, "is_visible": True, "default": None},
        "updated_at": {"allow_post": False, "allow_put": False, "is_visible": True},
        "last_reported_at": {"allow_post": False, "allow_put": False, "is_visible": True},
        "stale": {"allow_post": False, "allow_put": False, "is_visible": True},
        "runtime_status": {"allow_post": False, "allow_put": False, "is_visible": True},
    },
    "ports": PORT_READONLY_ATTRIBUTES,
}

API_RESOURCE_ATTRIBUTE_MAP = dict(
    (collection, RESOURCE_ATTRIBUTE_MAP[collection])
    for collection in RESOURCE_COLLECTIONS.values()
)


def get_alias():
    return ALIAS


def get_name():
    return NAME


def get_description():
    return DESCRIPTION


def get_updated():
    return UPDATED


def get_resources():
    if resource_helper is not None:
        special_mappings = {
            RESOURCE_COLLECTIONS["port_statuses"]: "aria_acl_port_status",
        }
        plural_mappings = resource_helper.build_plural_mappings(
            special_mappings,
            API_RESOURCE_ATTRIBUTE_MAP,
        )
        return resource_helper.build_resource_info(
            plural_mappings,
            API_RESOURCE_ATTRIBUTE_MAP,
            SERVICE_TYPE,
            translate_name=True,
            allow_bulk=True,
        )
    return list(RESOURCE_COLLECTIONS.values())


def get_extended_resources(version):
    if version == "2.0":
        return RESOURCE_ATTRIBUTE_MAP
    return {}


class Aria_acl(_BASE_DESCRIPTOR):
    """Neutron API extension descriptor for aria_acl.

    The class name follows Neutron's legacy module-to-class lookup convention
    for extension modules with underscores. The module-level helpers above keep
    stdlib-only unit tests simple while this descriptor gives neutron-server a
    conventional API extension object when Neutron is installed.
    """

    @classmethod
    def get_name(cls):
        return get_name()

    @classmethod
    def get_alias(cls):
        return get_alias()

    @classmethod
    def get_description(cls):
        return get_description()

    @classmethod
    def get_updated(cls):
        return get_updated()

    @classmethod
    def get_resources(cls):
        return get_resources()

    @classmethod
    def get_extended_resources(cls, version):
        return get_extended_resources(version)

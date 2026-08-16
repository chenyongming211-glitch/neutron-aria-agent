from __future__ import absolute_import

import copy

import netaddr

from neutron_aria.acl_contract import AclContractError
from neutron_aria.acl_contract import address_set_ethertype
from neutron_aria.acl_contract import normalize_cidr
from neutron_aria.acl_contract import normalize_ethertype
from neutron_aria.acl_contract import validate_policy
from neutron_aria.acl_contract import validate_rule
from neutron_aria.db.aria_acl.errors import AriaAclConflictError
from neutron_aria.db.aria_acl.errors import AriaAclNotFound
from neutron_aria.db.aria_acl.errors import AriaAclValidationError


MAX_ADDRESS_SET_MEMBERS = 2048

POLICY_IMMUTABLE_FIELDS = ("id", "project_id", "tenant_id")
RULE_IMMUTABLE_FIELDS = ("id", "project_id", "tenant_id", "policy_id")
ADDRESS_SET_IMMUTABLE_FIELDS = ("id", "project_id", "tenant_id")
BINDING_IMMUTABLE_FIELDS = (
    "id",
    "project_id",
    "tenant_id",
    "policy_id",
    "target_type",
    "target_id",
)


try:
    STRING_TYPES = (basestring,)
except NameError:
    STRING_TYPES = (str,)


def enabled(values):
    value = (values or {}).get("enabled", True)
    if isinstance(value, STRING_TYPES):
        return value.strip().lower() not in ("0", "false", "no", "off")
    return value is not False


def reject_immutable_changes(existing, patch, fields, object_type):
    existing = existing or {}
    patch = patch or {}
    for field in fields:
        if field not in patch:
            continue
        old_value = existing.get(field)
        new_value = patch.get(field)
        if field == "tenant_id":
            old_value = old_value or existing.get("project_id")
            new_value = new_value or patch.get("project_id")
        elif field == "project_id":
            old_value = old_value or existing.get("tenant_id")
            new_value = new_value or patch.get("tenant_id")
        if new_value != old_value:
            raise AriaAclValidationError(
                "%s field %s is immutable" % (object_type, field)
            )


def _contract(validator, values):
    try:
        validator(values)
    except AclContractError as exc:
        raise AriaAclValidationError(str(exc))


def _canonical_sort_key(value):
    network = netaddr.IPNetwork(value)
    return network.version, int(network.network), network.prefixlen


def normalize_address_set_members(members):
    raw_members = list(members or [])
    if len(raw_members) > MAX_ADDRESS_SET_MEMBERS:
        raise AriaAclValidationError(
            "address set exceeds %d raw members" % MAX_ADDRESS_SET_MEMBERS
        )
    raw_addresses = []
    for member in raw_members:
        if isinstance(member, dict):
            if "address" not in member:
                raise AriaAclValidationError(
                    "address set member object requires address"
                )
            address = member.get("address")
        elif isinstance(member, STRING_TYPES):
            address = member
        else:
            raise AriaAclValidationError(
                "address set member must be a CIDR string or address object"
            )
        if address is None or not str(address).strip():
            continue
        raw_addresses.append(address)
    try:
        family = address_set_ethertype(raw_addresses)
    except AclContractError as exc:
        raise AriaAclValidationError(str(exc))
    canonical = set()
    for address in raw_addresses:
        try:
            canonical.add(normalize_cidr(address, family))
        except AclContractError as exc:
            raise AriaAclValidationError(str(exc))
    return [
        {"address": address}
        for address in sorted(canonical, key=_canonical_sort_key)
    ]


def _policy(repository, policy_id):
    try:
        return repository.get_policy(policy_id)
    except AriaAclNotFound:
        raise AriaAclValidationError("aria_acl object references missing policy")


def _project_id(values):
    return (values or {}).get("project_id") or (values or {}).get("tenant_id")


def _require_policy_project(repository, values):
    policy = _policy(repository, values.get("policy_id"))
    policy_project = _project_id(policy)
    object_project = _project_id(values)
    if object_project and policy_project and object_project != policy_project:
        raise AriaAclValidationError(
            "aria_acl object project_id does not match policy"
        )
    if not object_project and policy_project:
        values["project_id"] = policy_project
    return policy


def _valid_referenced_address_set(repository, address_set_id, policy_project):
    try:
        address_set = repository.get_address_set(address_set_id)
    except AriaAclNotFound:
        raise AriaAclValidationError(
            "aria_acl_rule references missing address set %s" % address_set_id
        )
    if not enabled(address_set):
        raise AriaAclValidationError("address set is disabled")
    members = normalize_address_set_members(address_set.get("members") or [])
    if not members:
        raise AriaAclValidationError("address set has no members")
    if (
        policy_project and _project_id(address_set) and
        _project_id(address_set) != policy_project
    ):
        raise AriaAclValidationError(
            "address set project_id does not match policy"
        )
    try:
        family = address_set_ethertype(members)
    except AclContractError as exc:
        raise AriaAclValidationError(str(exc))
    return address_set, family


def prepare_policy(values):
    final_values = copy.deepcopy(values)
    _contract(validate_policy, final_values)
    return final_values


def prepare_rule(repository, values, existing=None):
    final_values = copy.deepcopy(values)
    policy = _require_policy_project(repository, final_values)
    try:
        family = normalize_ethertype(final_values.get("ethertype") or "IPv4")
    except AclContractError as exc:
        raise AriaAclValidationError(str(exc))
    final_values["ethertype"] = family
    for field in ("src_cidr", "dst_cidr"):
        if final_values.get(field):
            try:
                final_values[field] = normalize_cidr(final_values[field], family)
            except AclContractError as exc:
                raise AriaAclValidationError(str(exc))
    policy_project = _project_id(policy)
    references = set()
    for field in ("src_address_set_id", "dst_address_set_id"):
        if final_values.get(field):
            references.add(final_values[field])
    for address_set_id in sorted(references):
        _, address_set_family = _valid_referenced_address_set(
            repository,
            address_set_id,
            policy_project,
        )
        if address_set_family != family:
            raise AriaAclValidationError(
                "rule ethertype does not match address set family"
            )
    _contract(validate_rule, final_values)
    if enabled(final_values):
        for rule in repository.list_rules(
            filters={"policy_id": [final_values.get("policy_id")]}
        ):
            if existing and rule.get("id") == existing.get("id"):
                continue
            if not enabled(rule):
                continue
            if (
                rule.get("direction") == final_values.get("direction") and
                int(rule.get("priority")) == int(final_values.get("priority"))
            ):
                raise AriaAclConflictError(
                    "duplicate_enabled_rule_priority "
                    "policy=%s direction=%s priority=%s" % (
                        final_values.get("policy_id"),
                        final_values.get("direction"),
                        final_values.get("priority"),
                    )
                )
    return final_values


def prepare_address_set(repository, values, existing=None):
    final_values = copy.deepcopy(values)
    final_values["members"] = normalize_address_set_members(
        final_values.get("members") or []
    )
    address_set_id = final_values.get("id")
    referencing_rules = []
    if address_set_id:
        for rule in repository.list_rules():
            if not enabled(rule):
                continue
            if (
                rule.get("src_address_set_id") == address_set_id or
                rule.get("dst_address_set_id") == address_set_id
            ):
                referencing_rules.append(rule)
    if referencing_rules:
        if not enabled(final_values):
            raise AriaAclValidationError("address set is disabled")
        if not final_values["members"]:
            raise AriaAclValidationError("address set has no members")
        set_project = _project_id(final_values)
        for rule in referencing_rules:
            policy = _policy(repository, rule.get("policy_id"))
            policy_project = _project_id(policy)
            if (
                policy_project and set_project and
                policy_project != set_project
            ):
                raise AriaAclValidationError(
                    "address set project_id does not match policy"
                )
            try:
                rule_family = normalize_ethertype(
                    rule.get("ethertype") or "IPv4"
                )
                set_family = address_set_ethertype(final_values["members"])
            except AclContractError as exc:
                raise AriaAclValidationError(str(exc))
            if rule_family != set_family:
                raise AriaAclValidationError(
                    "address set family does not match enabled rule ethertype"
                )
    return final_values


def prepare_binding(repository, values, existing=None):
    final_values = copy.deepcopy(values)
    _require_policy_project(repository, final_values)
    if final_values.get("target_type") not in ("port", "network"):
        raise AriaAclValidationError(
            "aria_acl_binding target_type must be port or network"
        )
    if enabled(final_values):
        filters = {
            "target_type": [final_values.get("target_type")],
            "target_id": [final_values.get("target_id")],
        }
        for binding in repository.list_bindings(filters=filters):
            if existing and binding.get("id") == existing.get("id"):
                continue
            if not enabled(binding):
                continue
            raise AriaAclConflictError(
                "duplicate_enabled_binding_target "
                "target_type=%s target_id=%s" % (
                    final_values.get("target_type"),
                    final_values.get("target_id"),
                )
            )
    return final_values

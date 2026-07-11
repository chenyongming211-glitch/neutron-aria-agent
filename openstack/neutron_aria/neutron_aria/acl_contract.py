from __future__ import absolute_import

import socket


class AclContractError(ValueError):
    pass


def _text(value):
    return str(value).strip().lower()


def _integer(value, field):
    try:
        return int(value)
    except (TypeError, ValueError):
        raise AclContractError("%s must be an integer" % field)


def _protocol_number(value):
    normalized = _text(value if value is not None else "any")
    aliases = {"any": 0, "tcp": 6, "udp": 17, "icmp": 1}
    if normalized in aliases:
        return aliases[normalized]
    number = _integer(normalized, "protocol")
    if number < 0 or number > 255:
        raise AclContractError("protocol must be in 0..255")
    return number


def _validate_ipv4_cidr(value):
    parts = str(value).strip().split("/")
    if len(parts) != 2 or ":" in parts[0]:
        raise AclContractError("only IPv4 CIDR is supported")
    try:
        packed = socket.inet_aton(parts[0])
    except (socket.error, OSError):
        raise AclContractError("invalid IPv4 CIDR: %s" % value)
    if len(packed) != 4:
        raise AclContractError("invalid IPv4 CIDR: %s" % value)
    prefix = _integer(parts[1], "IPv4 prefix")
    if prefix < 0 or prefix > 32:
        raise AclContractError("invalid IPv4 prefix: %s" % parts[1])


def validate_policy(values):
    default_action = _text((values or {}).get("default_action") or "allow")
    if default_action != "allow":
        raise AclContractError("default_action must be allow")


def validate_rule(values):
    values = values or {}
    direction = _text(values.get("direction") or "")
    if direction not in ("ingress", "egress"):
        raise AclContractError("direction must be ingress or egress")

    if values.get("priority") is None:
        raise AclContractError("priority is required")
    priority = _integer(values.get("priority"), "priority")
    if priority < 0:
        raise AclContractError("priority must be non-negative")

    action = _text(values.get("action") or "")
    if action not in ("allow", "deny", "drop"):
        raise AclContractError("action must be allow, deny, or drop")

    ethertype = _text(values.get("ethertype") or "IPv4")
    if ethertype != "ipv4":
        raise AclContractError("only IPv4 is supported")

    if values.get("src_cidr") and values.get("src_address_set_id"):
        raise AclContractError("source CIDR and address set are mutually exclusive")
    if values.get("dst_cidr") and values.get("dst_address_set_id"):
        raise AclContractError("destination CIDR and address set are mutually exclusive")
    for field in ("src_cidr", "dst_cidr"):
        if values.get(field):
            _validate_ipv4_cidr(values[field])

    if values.get("src_port_min") is not None or values.get("src_port_max") is not None:
        raise AclContractError("source port matching is unsupported")

    protocol = _protocol_number(values.get("protocol"))
    low_value = values.get("dst_port_min")
    high_value = values.get("dst_port_max")
    if low_value is not None or high_value is not None:
        low = _integer(low_value if low_value is not None else high_value, "dst_port_min")
        high = _integer(high_value if high_value is not None else low_value, "dst_port_max")
        if protocol not in (6, 17):
            raise AclContractError("destination ports require tcp or udp")
        if low < 0 or high > 65535 or low > high:
            raise AclContractError("invalid destination port range")


def validate_address_set_reference(values):
    values = values or {}
    if values.get("enabled") is False:
        raise AclContractError("address set is disabled")
    members = [member for member in values.get("members") or [] if str(member).strip()]
    if not members:
        raise AclContractError("address set has no members")
    for member in members:
        _validate_ipv4_cidr(member)


def port_contract_eligibility(port):
    port = port or {}
    owner = port.get("device_owner") or ""
    vif_type = port.get("binding:vif_type")
    vnic_type = port.get("binding:vnic_type")
    if owner and not owner.startswith("compute:"):
        return False, "not_applicable_device_owner:%s" % owner
    if vif_type not in (None, "", "ovs"):
        return False, "unsupported_vif_type:%s" % vif_type
    if vnic_type not in (None, "", "normal"):
        return False, "unsupported_vnic_type:%s" % vnic_type
    return True, "pending_local_validation"

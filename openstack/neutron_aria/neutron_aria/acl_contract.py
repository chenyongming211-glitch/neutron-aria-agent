from __future__ import absolute_import

import netaddr

class AclContractError(ValueError):
    pass


def _text(value):
    return str(value).strip().lower()


def _integer(value, field):
    try:
        return int(value)
    except (TypeError, ValueError):
        raise AclContractError("%s must be an integer" % field)


def normalize_ethertype(value):
    token = _text(value or "IPv4")
    if token == "ipv4":
        return "IPv4"
    if token == "ipv6":
        return "IPv6"
    raise AclContractError("ethertype must be IPv4 or IPv6")


def normalize_cidr(value, ethertype):
    text = str(value).strip()
    if not text or "%" in text or any(char.isspace() for char in text):
        raise AclContractError("invalid %s CIDR: %s" % (ethertype, value))
    try:
        network = netaddr.IPNetwork(text)
    except (netaddr.AddrFormatError, ValueError):
        raise AclContractError("invalid %s CIDR: %s" % (ethertype, value))
    expected = 4 if normalize_ethertype(ethertype) == "IPv4" else 6
    if network.version != expected:
        raise AclContractError("ethertype and CIDR family must match")
    if expected == 4:
        parts = text.split("/")
        octets = parts[0].split(".")
        if len(parts) not in (1, 2) or len(octets) != 4:
            raise AclContractError("invalid IPv4 CIDR: %s" % value)
        for octet in octets:
            if (
                not octet or not octet.isdigit() or
                (len(octet) > 1 and octet.startswith("0"))
            ):
                raise AclContractError("invalid IPv4 CIDR: %s" % value)
    original_ip = netaddr.IPAddress(text.split("/", 1)[0])
    if network.version == 6 and (int(original_ip) >> 32) == 0xffff:
        raise AclContractError("IPv4-mapped IPv6 CIDR is unsupported")
    return str(network.cidr)


def normalize_ipv4_cidr(value):
    return normalize_cidr(value, "IPv4")


def protocol_number(value, ethertype):
    family = normalize_ethertype(ethertype)
    token = _text(value if value is not None else "any")
    aliases = {"any": 0, "tcp": 6, "udp": 17}
    if token in aliases:
        return aliases[token]
    if token == "icmp":
        return 1 if family == "IPv4" else 58
    if token in ("icmpv6", "ipv6-icmp"):
        if family != "IPv6":
            raise AclContractError("ICMPv6 requires IPv6 ethertype")
        return 58
    number = _integer(token, "protocol")
    if number not in range(0, 256):
        raise AclContractError("protocol must be in 0..255")
    if (family == "IPv4" and number == 58) or (family == "IPv6" and number == 1):
        raise AclContractError("ICMP protocol number does not match ethertype")
    return number


def address_set_ethertype(members):
    families = set()
    for member in members or []:
        value = member.get("address") if isinstance(member, dict) else member
        text = str(value).strip()
        if not text:
            continue
        family = "IPv6" if ":" in text else "IPv4"
        normalize_cidr(text, family)
        families.add(family)
    if len(families) > 1:
        raise AclContractError("address set must contain one IP family")
    return next(iter(families), None)


def _validate_ipv4_cidr(value):
    normalize_ipv4_cidr(value)


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

    ethertype = normalize_ethertype(values.get("ethertype") or "IPv4")

    if values.get("src_cidr") and values.get("src_address_set_id"):
        raise AclContractError("source CIDR and address set are mutually exclusive")
    if values.get("dst_cidr") and values.get("dst_address_set_id"):
        raise AclContractError("destination CIDR and address set are mutually exclusive")
    for field in ("src_cidr", "dst_cidr"):
        if values.get(field):
            normalize_cidr(values[field], ethertype)

    if values.get("src_port_min") is not None or values.get("src_port_max") is not None:
        raise AclContractError("source port matching is unsupported")

    protocol = protocol_number(values.get("protocol"), ethertype)
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
    if address_set_ethertype(members) is None:
        raise AclContractError("address set has no members")


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

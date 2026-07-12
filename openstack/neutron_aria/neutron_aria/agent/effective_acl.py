from __future__ import absolute_import

import copy
import heapq

from neutron_aria.acl_contract import AclContractError
from neutron_aria.acl_contract import validate_address_set_reference
from neutron_aria.acl_contract import validate_policy
from neutron_aria.acl_contract import validate_rule


try:
    _INTEGER_TYPES = (int, long)
    _STRING_TYPES = (basestring,)
except NameError:
    _INTEGER_TYPES = (int,)
    _STRING_TYPES = (str,)


ACL_NOT_REQUESTED = "not_requested"
ACL_READY = "ready"
ACL_DEGRADED = "degraded"
ACL_UNSUPPORTED = "unsupported"

REVISION_NEWER = "newer"
REVISION_SAME = "same"
REVISION_OLDER = "older"
REVISION_UNKNOWN = "unknown"

MAX_ACL_RULES_PER_POLICY = 1000
MAX_ACL_SELECTOR_MEMBERS = 2048

SELECTOR_IDENTICAL = "identical"
SELECTOR_DISJOINT = "disjoint"
SELECTOR_INTERSECTING = "intersecting"


def _get(obj, key, default=None):
    if obj is None:
        return default
    return obj.get(key, default)


def _revision(obj):
    value = _get(obj, "revision_number", 0)
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _optional_revision(value):
    if value in (None, ""):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _enabled(obj):
    return _get(obj, "enabled", True) is not False


def _members(address_set):
    result = []
    for member in _get(address_set, "members", []) or []:
        if isinstance(member, dict):
            address = member.get("address")
        else:
            address = member
        if address:
            result.append(address)
    return result


def _ip_version(address):
    return "IPv6" if ":" in address else "IPv4"


def _strict_priority(value):
    if isinstance(value, bool):
        raise ValueError("priority must be an integer")
    if isinstance(value, _INTEGER_TYPES):
        return int(value)
    if isinstance(value, _STRING_TYPES):
        text = value.strip()
        digits = text[1:] if text[:1] in ("+", "-") else text
        if digits and all(character in "0123456789" for character in digits):
            return int(text, 10)
    raise ValueError("priority must be an integer")


def _rule_priority(rule):
    try:
        return _strict_priority(rule.get("priority"))
    except (TypeError, ValueError):
        return 0


def _strict_ipv4_cidr(value):
    text = str(value).strip()
    pieces = text.split("/")
    if len(pieces) != 2:
        raise ValueError("invalid IPv4 CIDR")
    address, prefix_text = pieces
    octets = address.split(".")
    if len(octets) != 4:
        raise ValueError("invalid IPv4 address")
    values = []
    for octet in octets:
        if (not octet or
                not all(character in "0123456789" for character in octet) or
                (len(octet) > 1 and octet.startswith("0"))):
            raise ValueError("invalid IPv4 octet")
        number = int(octet, 10)
        if number > 255:
            raise ValueError("invalid IPv4 octet")
        values.append(number)
    if (not prefix_text or
            not all(character in "0123456789" for character in prefix_text)):
        raise ValueError("invalid IPv4 prefix")
    prefix = int(prefix_text, 10)
    if prefix > 32:
        raise ValueError("invalid IPv4 prefix")
    value = ((values[0] << 24) | (values[1] << 16) |
             (values[2] << 8) | values[3])
    mask = 0 if prefix == 0 else ((0xffffffff << (32 - prefix)) & 0xffffffff)
    network = value & mask
    canonical = "%s.%s.%s.%s/%s" % (
        (network >> 24) & 0xff,
        (network >> 16) & 0xff,
        (network >> 8) & 0xff,
        network & 0xff,
        prefix,
    )
    return network, prefix, canonical


def _canonical_ipv4_cidrs(cidrs):
    return tuple(sorted(set(
        _strict_ipv4_cidr(cidr)[:2] for cidr in cidrs or []
    )))


def _canonical_ipv4_strings(cidrs):
    parsed = {}
    for cidr in cidrs or []:
        network, prefix, canonical = _strict_ipv4_cidr(cidr)
        parsed[(network, prefix)] = canonical
    return [parsed[key] for key in sorted(parsed)]


def _normalized_protocol(protocol):
    value = str(protocol or "any").strip().lower()
    known = {"any": 0, "tcp": 6, "udp": 17, "icmp": 1}
    if value in known:
        return known[value]
    return int(value)


def _normalized_action(action):
    value = str(action or "allow").strip().lower()
    if value in ("allow", "accept", "pass"):
        return "allow"
    if value in ("deny", "drop"):
        return "deny"
    return value


def _normalized_ports(rule):
    minimum = rule.get("dst_port_min")
    maximum = rule.get("dst_port_max")
    if minimum is None and maximum is None:
        return ()
    minimum = int(minimum if minimum is not None else maximum)
    maximum = int(maximum if maximum is not None else minimum)
    return ((minimum, maximum),)


def _normalized_direction(direction):
    return str(direction or "ingress").strip().lower()


def _datapath_directions(direction):
    value = _normalized_direction(direction)
    if value == "both":
        return frozenset((0, 1))
    return frozenset((1,)) if value == "ingress" else frozenset((0,))


def _intern_selector(cidrs, selectors, selector_ids):
    selector = tuple(cidrs or ())
    if not selector:
        return 0
    selector_id = selector_ids.get(selector)
    if selector_id is None:
        selector_id = len(selectors)
        selector_ids[selector] = selector_id
        selectors.append(selector)
    return selector_id


def _acl_validation_view(compiled_rules):
    src_selectors = [()]
    dst_selectors = [()]
    src_selector_ids = {}
    dst_selector_ids = {}
    normalized = []
    for rule in sorted(compiled_rules, key=lambda item: (
            _normalized_direction(item.get("direction")),
            int(item.get("priority") or 0),
            str(item.get("id") or ""),
    )):
        normalized.append({
            "id": str(rule.get("id") or ""),
            "direction": _normalized_direction(rule.get("direction")),
            "priority": int(rule.get("priority") or 0),
            "action": _normalized_action(rule.get("action")),
            "protocol": _normalized_protocol(rule.get("protocol")),
            "directions": _datapath_directions(rule.get("direction")),
            "src_selector_id": _intern_selector(
                rule.get("src_cidrs"), src_selectors, src_selector_ids,
            ),
            "dst_selector_id": _intern_selector(
                rule.get("dst_cidrs"), dst_selectors, dst_selector_ids,
            ),
            "ports": _normalized_ports(rule),
        })
    return {
        "rules": normalized,
        "src_selectors": tuple(src_selectors),
        "dst_selectors": tuple(dst_selectors),
    }


def _selector_relation(left_id, right_id):
    if left_id == right_id:
        return SELECTOR_IDENTICAL
    if left_id == 0 or right_id == 0:
        return SELECTOR_INTERSECTING
    return SELECTOR_DISJOINT


def _selector_best_overlap(selectors, first_rule_indexes):
    intervals = []
    for selector_id, selector in enumerate(selectors):
        if selector_id == 0 or first_rule_indexes[selector_id] is None:
            continue
        selector_intervals = []
        for network, prefix in _canonical_ipv4_cidrs(selector):
            host_mask = 0 if prefix == 32 else (1 << (32 - prefix)) - 1
            selector_intervals.append((network, network | host_mask))
        selector_intervals.sort()
        merged = []
        for start, end in selector_intervals:
            if merged and start <= merged[-1][1]:
                merged[-1] = (merged[-1][0], max(merged[-1][1], end))
            else:
                merged.append((start, end))
        intervals.extend(
            (start, end, selector_id) for start, end in merged
        )
    intervals.sort()

    active_intervals = []
    active_counts = {}
    active_generations = {}
    active_selectors = []
    next_generation = 0
    best = None

    def discard_inactive_selectors():
        while active_selectors:
            _, active_id, generation = active_selectors[0]
            if active_generations.get(active_id) == generation:
                return
            heapq.heappop(active_selectors)

    for start, end, selector_id in intervals:
        while active_intervals and active_intervals[0][0] < start:
            _, expired_selector_id = heapq.heappop(active_intervals)
            remaining = active_counts[expired_selector_id] - 1
            if remaining:
                active_counts[expired_selector_id] = remaining
            else:
                del active_counts[expired_selector_id]
                del active_generations[expired_selector_id]

        discard_inactive_selectors()
        skipped_current = None
        if (active_selectors and
                active_selectors[0][1] == selector_id):
            skipped_current = heapq.heappop(active_selectors)
            discard_inactive_selectors()
        if active_selectors:
            other_selector_id = active_selectors[0][1]
            candidate = tuple(sorted((
                first_rule_indexes[selector_id],
                first_rule_indexes[other_selector_id],
            )))
            if best is None or candidate < best:
                best = candidate
        if skipped_current is not None:
            heapq.heappush(active_selectors, skipped_current)

        if selector_id not in active_counts:
            next_generation += 1
            active_generations[selector_id] = next_generation
            heapq.heappush(active_selectors, (
                first_rule_indexes[selector_id],
                selector_id,
                next_generation,
            ))
        active_counts[selector_id] = active_counts.get(selector_id, 0) + 1
        heapq.heappush(active_intervals, (end, selector_id))
    return best


def _acl_overlap_reason(validation):
    normalized = validation["rules"]
    best_by_side = {}
    for side in ("src", "dst"):
        selectors = validation[side + "_selectors"]
        first_rule_indexes = [None] * len(selectors)
        for rule_index, rule in enumerate(normalized):
            selector_id = rule[side + "_selector_id"]
            if (selector_id and
                    first_rule_indexes[selector_id] is None):
                first_rule_indexes[selector_id] = rule_index
        best_by_side[side] = _selector_best_overlap(
            selectors, first_rule_indexes,
        )

    src_best = best_by_side["src"]
    dst_best = best_by_side["dst"]
    if src_best is not None or dst_best is not None:
        if dst_best is None or (src_best is not None and src_best <= dst_best):
            side = "src"
            left_index, right_index = src_best
        else:
            side = "dst"
            left_index, right_index = dst_best
        left = normalized[left_index]
        right = normalized[right_index]
        return "unsupported_acl_cidr_overlap:%s:%s:%s:%s:%s" % (
            side, left["id"], left["priority"],
            right["id"], right["priority"],
        )

    for left_index, left in enumerate(normalized):
        for right in normalized[left_index + 1:]:
            relations = {}
            for side in ("src", "dst"):
                left_selector_id = left[side + "_selector_id"]
                right_selector_id = right[side + "_selector_id"]
                relations[side] = _selector_relation(
                    left_selector_id, right_selector_id,
                )

            if not (left["directions"] & right["directions"]):
                continue
            if (left["protocol"] and right["protocol"] and
                    left["protocol"] != right["protocol"]):
                continue
            if relations["src"] == SELECTOR_DISJOINT:
                continue
            if relations["dst"] == SELECTOR_DISJOINT:
                continue

            same_key = (
                left["protocol"] == right["protocol"] and
                left["src_selector_id"] == right["src_selector_id"] and
                left["dst_selector_id"] == right["dst_selector_id"]
            )
            same_behavior = (
                left["action"] == right["action"] and
                left["ports"] == right["ports"]
            )
            if same_behavior or (same_key and left["action"] == right["action"]):
                continue
            return "unsupported_acl_priority_overlap:%s:%s:%s:%s" % (
                left["id"], left["priority"], right["id"], right["priority"],
            )
    return None


class EffectiveAclIndex(object):
    @classmethod
    def from_payload(cls, payload):
        return cls(
            policies=payload.get("policies") or [],
            rules=payload.get("rules") or [],
            address_sets=payload.get("address_sets") or [],
            bindings=payload.get("bindings") or [],
        )

    def __init__(
        self,
        policies=None,
        rules=None,
        address_sets=None,
        bindings=None,
    ):
        self.policies = dict((policy.get("id"), policy) for policy in policies or [])
        self.address_sets = dict(
            (address_set.get("id"), address_set) for address_set in address_sets or []
        )
        self.rules_by_policy = {}
        for rule in rules or []:
            self.rules_by_policy.setdefault(rule.get("policy_id"), []).append(rule)
        self.bindings_by_target = {}
        for binding in bindings or []:
            if not _enabled(binding):
                continue
            key = (binding.get("target_type"), binding.get("target_id"))
            self.bindings_by_target.setdefault(key, []).append(binding)
        self._compiled_rules_by_policy = {}

    def effective_for_port(self, neutron_port, snapshot_port=None):
        snapshot_port = snapshot_port or {}
        if not snapshot_port.get("eligible", True):
            return {
                "enabled": False,
                "status": ACL_UNSUPPORTED,
                "reason": snapshot_port.get("disposition") or "port_not_eligible",
                "effective_action": "bypass",
            }

        binding_result = self._select_binding(neutron_port)
        if binding_result.get("status") == ACL_DEGRADED:
            return binding_result

        binding = binding_result.get("binding")
        source = binding_result.get("source")
        if binding is None:
            return {
                "enabled": False,
                "status": ACL_NOT_REQUESTED,
                "reason": "no_enabled_binding",
                "effective_action": "bypass",
            }

        policy = self.policies.get(binding.get("policy_id"))
        if policy is None or not _enabled(policy):
            return {
                "enabled": False,
                "status": ACL_DEGRADED,
                "reason": "policy_missing_or_disabled",
                "effective_action": "bypass",
                "binding_id": binding.get("id"),
                "source": source,
                "policy_id": binding.get("policy_id"),
            }

        try:
            validate_policy(policy)
        except AclContractError as exc:
            return {
                "enabled": False,
                "status": ACL_DEGRADED,
                "reason": "unsupported_policy:%s" % exc,
                "effective_action": "bypass",
                "binding_id": binding.get("id"),
                "source": source,
                "policy_id": policy.get("id"),
            }

        policy_rules = self.rules_by_policy.get(policy.get("id"), [])
        compiled_rules = self._compile_rules(policy)
        acl_ready = compiled_rules["status"] == ACL_READY
        result = {
            "enabled": acl_ready,
            "status": compiled_rules["status"],
            "reason": compiled_rules["reason"],
            "effective_action": "enforce" if acl_ready else "bypass",
            "policy_id": policy.get("id"),
            "policy_name": policy.get("name"),
            "binding_id": binding.get("id"),
            "source": source,
            "default_action": policy.get("default_action", "deny"),
            "stateful": policy.get("stateful", True) is not False,
            "revision": max(
                [_revision(policy), _revision(binding)] +
                [_revision(rule) for rule in policy_rules] +
                self._address_set_revisions(policy_rules)
            ),
            "rules": compiled_rules["rules"],
        }
        return result

    def revision_for_port(self, neutron_port, snapshot_port=None):
        effective = self.effective_for_port(neutron_port, snapshot_port)
        return _optional_revision(effective.get("revision"))

    def compare_revision_for_port(self, neutron_port, projected_revision, snapshot_port=None):
        current_revision = self.revision_for_port(neutron_port, snapshot_port)
        projected_revision = _optional_revision(projected_revision)
        if current_revision is None or projected_revision is None:
            return {
                "status": REVISION_UNKNOWN,
                "current_revision": current_revision,
                "projected_revision": projected_revision,
            }
        if current_revision > projected_revision:
            status = REVISION_NEWER
        elif current_revision == projected_revision:
            status = REVISION_SAME
        else:
            status = REVISION_OLDER
        return {
            "status": status,
            "current_revision": current_revision,
            "projected_revision": projected_revision,
        }

    def _select_binding(self, neutron_port):
        port_id = neutron_port.get("id") or neutron_port.get("port_id")
        network_id = neutron_port.get("network_id")
        port_bindings = self.bindings_by_target.get(("port", port_id), [])
        network_bindings = self.bindings_by_target.get(("network", network_id), [])

        if len(port_bindings) > 1:
            return {
                "enabled": False,
                "status": ACL_DEGRADED,
                "reason": "multiple_enabled_port_bindings",
                "effective_action": "bypass",
                "source": "port",
            }
        if port_bindings:
            return {"binding": port_bindings[0], "source": "port"}

        if len(network_bindings) > 1:
            return {
                "enabled": False,
                "status": ACL_DEGRADED,
                "reason": "multiple_enabled_network_bindings",
                "effective_action": "bypass",
                "source": "network",
            }
        if network_bindings:
            return {"binding": network_bindings[0], "source": "network"}

        return {"binding": None, "source": "none"}

    def _compile_rules(self, policy):
        policy_id = policy.get("id")
        if policy_id not in self._compiled_rules_by_policy:
            self._compiled_rules_by_policy[policy_id] = self._compile_rules_uncached(policy)
        return copy.deepcopy(self._compiled_rules_by_policy[policy_id])

    def _compile_rules_uncached(self, policy):
        policy_id = policy.get("id")
        rules = [rule for rule in self.rules_by_policy.get(policy_id, []) if _enabled(rule)]
        if len(rules) > MAX_ACL_RULES_PER_POLICY:
            return {
                "status": ACL_DEGRADED,
                "reason": "acl_rule_limit_exceeded:%s:%s" % (
                    len(rules), MAX_ACL_RULES_PER_POLICY,
                ),
                "rules": [],
            }
        priority_keys = {}
        compiled = []
        reasons = []
        for rule in sorted(rules, key=lambda r: (
                _normalized_direction(r.get("direction")), _rule_priority(r))):
            if self._invalid_priority(rule):
                reasons.append("invalid_acl_priority:%s:%s" % (
                    rule.get("id"), rule.get("priority"),
                ))
                continue

            priority = _rule_priority(rule)
            key = (_normalized_direction(rule.get("direction")), priority)
            if key in priority_keys:
                reasons.append("duplicate_acl_priority:%s:%s:%s:%s" % (
                    key[0], key[1], priority_keys[key], rule.get("id"),
                ))
                continue
            priority_keys[key] = rule.get("id")
            compiled_rule, error = self._compile_rule(rule)
            if error:
                reasons.append(error)
                continue
            compiled.append(compiled_rule)

        overlap_reason = _acl_overlap_reason(_acl_validation_view(compiled))
        if overlap_reason:
            reasons.append(overlap_reason)

        return {
            "status": ACL_DEGRADED if reasons else ACL_READY,
            "reason": ",".join(reasons) if reasons else "ready",
            "rules": compiled,
        }

    def _compile_rule(self, rule):
        try:
            validate_rule(rule)
        except AclContractError as exc:
            return None, "unsupported_rule:%s:%s" % (rule.get("id"), exc)

        protocol = rule.get("protocol")
        if self._has_l4_ports(rule) and str(protocol).lower() not in ("tcp", "udp", "6", "17"):
            return None, "l4_ports_require_tcp_or_udp:%s" % rule.get("id")

        src_cidrs, error = self._compile_address_match(rule, "src")
        if error:
            return None, error
        dst_cidrs, error = self._compile_address_match(rule, "dst")
        if error:
            return None, error

        for side, cidrs in (("src", src_cidrs), ("dst", dst_cidrs)):
            try:
                canonical = _canonical_ipv4_strings(cidrs)
            except (TypeError, ValueError):
                invalid = None
                for raw_value in cidrs:
                    try:
                        _strict_ipv4_cidr(raw_value)
                    except (TypeError, ValueError):
                        invalid = raw_value
                        break
                return None, "invalid_acl_ipv4_cidr:%s:%s:%s" % (
                    side, rule.get("id"), invalid,
                )
            if side == "src":
                src_cidrs = canonical
            else:
                dst_cidrs = canonical

        ethertype = rule.get("ethertype")
        if ethertype:
            for cidr in src_cidrs + dst_cidrs:
                if _ip_version(cidr) != ethertype:
                    return None, "ethertype_cidr_mismatch:%s" % rule.get("id")

        return {
            "id": rule.get("id"),
            "direction": rule.get("direction"),
            "priority": _rule_priority(rule),
            "action": rule.get("action"),
            "ethertype": ethertype,
            "protocol": protocol,
            "src_cidrs": src_cidrs,
            "dst_cidrs": dst_cidrs,
            "src_port_min": rule.get("src_port_min"),
            "src_port_max": rule.get("src_port_max"),
            "dst_port_min": rule.get("dst_port_min"),
            "dst_port_max": rule.get("dst_port_max"),
        }, None

    def _compile_address_match(self, rule, prefix):
        cidr_key = "%s_cidr" % prefix
        address_set_key = "%s_address_set_id" % prefix
        cidr = rule.get(cidr_key)
        address_set_id = rule.get(address_set_key)
        if cidr and address_set_id:
            return [], "%s_cidr_and_address_set_conflict:%s" % (prefix, rule.get("id"))
        if cidr:
            return [cidr], None
        if address_set_id:
            address_set = self.address_sets.get(address_set_id)
            if address_set is None:
                return [], "%s_address_set_missing:%s" % (prefix, address_set_id)
            raw_members = _get(address_set, "members", []) or []
            if len(raw_members) > MAX_ACL_SELECTOR_MEMBERS:
                return [], "acl_selector_member_limit_exceeded:%s:%s:%s:%s" % (
                    prefix,
                    rule.get("id"),
                    len(raw_members),
                    MAX_ACL_SELECTOR_MEMBERS,
                )
            try:
                contract_address_set = dict(address_set)
                contract_address_set["members"] = _members(address_set)
                validate_address_set_reference(contract_address_set)
            except AclContractError as exc:
                return [], "%s_address_set_invalid:%s:%s" % (
                    prefix,
                    address_set_id,
                    exc,
                )
            return _members(address_set), None
        return [], None

    def _has_l4_ports(self, rule):
        return any(
            rule.get(key) is not None for key in (
                "src_port_min",
                "src_port_max",
                "dst_port_min",
                "dst_port_max",
            )
        )

    def _invalid_priority(self, rule):
        try:
            priority = _strict_priority(rule.get("priority"))
        except (TypeError, ValueError):
            return True
        return priority < 0

    def _address_set_revisions(self, rules):
        revisions = []
        for rule in rules:
            for key in ("src_address_set_id", "dst_address_set_id"):
                address_set = self.address_sets.get(rule.get(key))
                if address_set is not None:
                    revisions.append(_revision(address_set))
        return revisions

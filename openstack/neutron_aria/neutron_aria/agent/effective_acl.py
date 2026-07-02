from __future__ import absolute_import


ACL_NOT_REQUESTED = "not_requested"
ACL_READY = "ready"
ACL_DEGRADED = "degraded"
ACL_UNSUPPORTED = "unsupported"

REVISION_NEWER = "newer"
REVISION_SAME = "same"
REVISION_OLDER = "older"
REVISION_UNKNOWN = "unknown"


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


def _rule_priority(rule):
    try:
        return int(rule.get("priority") or 0)
    except (TypeError, ValueError):
        return 0


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
        rules = [rule for rule in self.rules_by_policy.get(policy_id, []) if _enabled(rule)]
        priority_keys = set()
        compiled = []
        reasons = []
        for rule in sorted(rules, key=lambda r: (r.get("direction") or "", _rule_priority(r))):
            if self._invalid_priority(rule):
                reasons.append("invalid_rule_priority:%s" % rule.get("id"))
                continue

            priority = _rule_priority(rule)
            key = (rule.get("direction"), priority)
            if key in priority_keys:
                reasons.append("duplicate_rule_priority:%s:%s" % key)
                continue
            priority_keys.add(key)
            compiled_rule, error = self._compile_rule(rule)
            if error:
                reasons.append(error)
                continue
            compiled.append(compiled_rule)

        return {
            "status": ACL_DEGRADED if reasons else ACL_READY,
            "reason": ",".join(reasons) if reasons else "ready",
            "rules": compiled,
        }

    def _compile_rule(self, rule):
        protocol = rule.get("protocol")
        if self._has_l4_ports(rule) and str(protocol).lower() not in ("tcp", "udp", "6", "17"):
            return None, "l4_ports_require_tcp_or_udp:%s" % rule.get("id")

        src_cidrs, error = self._compile_address_match(rule, "src")
        if error:
            return None, error
        dst_cidrs, error = self._compile_address_match(rule, "dst")
        if error:
            return None, error

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
            int(rule.get("priority") or 0)
            return False
        except (TypeError, ValueError):
            return True

    def _address_set_revisions(self, rules):
        revisions = []
        for rule in rules:
            for key in ("src_address_set_id", "dst_address_set_id"):
                address_set = self.address_sets.get(rule.get(key))
                if address_set is not None:
                    revisions.append(_revision(address_set))
        return revisions

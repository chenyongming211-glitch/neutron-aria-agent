from __future__ import absolute_import


QOS_NOT_REQUESTED = "not_requested"
QOS_READY = "ready"
QOS_DEGRADED = "degraded"


SUPPORTED_RULE_TYPES = ("bandwidth_limit", "bandwidth_limit_rule")


def _revision(obj):
    try:
        return int((obj or {}).get("revision_number") or 0)
    except (TypeError, ValueError):
        return 0


def _policy_rules(policy):
    return list(policy.get("rules") or policy.get("bandwidth_limit_rules") or [])


class EffectiveQosIndex(object):
    """Compute Aria QoS from native Neutron QoS policy semantics."""

    def __init__(self, policies=None, networks=None):
        self.policies = dict((policy.get("id"), policy) for policy in policies or [])
        self.networks = dict((network.get("id"), network) for network in networks or [])

    def effective_for_port(self, neutron_port, snapshot_port=None):
        snapshot_port = snapshot_port or {}
        if not snapshot_port.get("eligible", True):
            return {
                "enabled": False,
                "status": QOS_DEGRADED,
                "reason": snapshot_port.get("disposition") or "port_not_eligible",
            }

        policy_id, source = self._select_policy_id(neutron_port)
        if not policy_id:
            return {
                "enabled": False,
                "status": QOS_NOT_REQUESTED,
                "reason": "no_qos_policy",
            }

        policy = self.policies.get(policy_id)
        if policy is None:
            return {
                "enabled": False,
                "status": QOS_DEGRADED,
                "reason": "qos_policy_missing",
                "policy_id": policy_id,
                "source": source,
            }

        compiled = self._compile_policy(policy)
        return {
            "enabled": compiled["status"] == QOS_READY,
            "status": compiled["status"],
            "reason": compiled["reason"],
            "policy_id": policy.get("id"),
            "policy_name": policy.get("name"),
            "source": source,
            "revision": max([_revision(policy)] + [_revision(rule) for rule in _policy_rules(policy)]),
            "rules": compiled["rules"],
        }

    def _select_policy_id(self, neutron_port):
        port_policy = neutron_port.get("qos_policy_id")
        if port_policy:
            return port_policy, "port"
        network = self.networks.get(neutron_port.get("network_id")) or {}
        network_policy = network.get("qos_policy_id")
        if network_policy:
            return network_policy, "network"
        return None, "none"

    def _compile_policy(self, policy):
        rules = []
        reasons = []
        for rule in _policy_rules(policy):
            rule_type = rule.get("type") or rule.get("rule_type") or "bandwidth_limit"
            if rule_type not in SUPPORTED_RULE_TYPES:
                reasons.append("unsupported_qos_rule:%s" % rule_type)
                continue
            max_kbps = rule.get("max_kbps")
            if max_kbps is None:
                reasons.append("missing_max_kbps:%s" % rule.get("id"))
                continue
            try:
                max_kbps = int(max_kbps)
            except (TypeError, ValueError):
                reasons.append("invalid_max_kbps:%s" % rule.get("id"))
                continue
            max_burst_kbps = rule.get("max_burst_kbps")
            if max_burst_kbps is not None:
                try:
                    max_burst_kbps = int(max_burst_kbps)
                except (TypeError, ValueError):
                    reasons.append("invalid_max_burst_kbps:%s" % rule.get("id"))
                    continue
            rules.append({
                "id": rule.get("id"),
                "type": "bandwidth_limit",
                "max_kbps": max_kbps,
                "max_burst_kbps": max_burst_kbps,
                "direction": rule.get("direction") or "egress",
            })

        return {
            "status": QOS_DEGRADED if reasons else QOS_READY,
            "reason": ",".join(reasons) if reasons else "ready",
            "rules": rules,
        }

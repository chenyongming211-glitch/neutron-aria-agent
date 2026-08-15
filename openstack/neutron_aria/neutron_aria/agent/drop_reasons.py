from __future__ import absolute_import

# Numeric drop-reason vocabulary shared with the eBPF ABI
# (abi/src/lib.rs ACL/QoS family and abi/src/fragment.rs fragment family).
# Reason names render as text in CLI output; never expose bare numbers.
DROP_REASON_NAMES = {
    1: "ACL_DENY",
    2: "ACL_PORT_DENY",
    3: "ACL_DEFAULT_DENY",
    4: "QOS_INGRESS",
    5: "QOS_EGRESS",
    6: "FRAGMENT_CONFIG_MISSING",
    7: "FRAGMENT_TRACKING_DISABLED",
    8: "FRAGMENT_CONFIG_INVALID",
    9: "FRAGMENT_EPOCH_MISSING",
    10: "FRAGMENT_CONTEXT_MISSING",
    11: "FRAGMENT_CONTEXT_INVALID",
    12: "FRAGMENT_CONTEXT_EXPIRED",
    13: "FRAGMENT_CONTEXT_STALE",
    14: "FRAGMENT_CONTEXT_OVERLAP",
    15: "FRAGMENT_CONTEXT_UPDATE_FAILED",
    16: "FRAGMENT_TAP_UNASSIGNED",
    17: "FRAGMENT_EXPIRY_OVERFLOW",
    18: "MALFORMED_IP",
    19: "FRAGMENT_INVALID_L4",
}


def drop_reason_name(reason):
    if reason is None:
        return "UNKNOWN"
    return DROP_REASON_NAMES.get(reason, "UNKNOWN(%s)" % reason)

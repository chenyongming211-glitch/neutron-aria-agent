from __future__ import absolute_import


ADMIN_OR_AGENT = "role:admin or role:service"
ADMIN_ONLY = "role:admin"


ARIA_ACL_POLICIES = {
    "create_aria_acl_policy": ADMIN_ONLY,
    "get_aria_acl_policy": ADMIN_OR_AGENT,
    "update_aria_acl_policy": ADMIN_ONLY,
    "delete_aria_acl_policy": ADMIN_ONLY,
    "create_aria_acl_rule": ADMIN_ONLY,
    "get_aria_acl_rule": ADMIN_OR_AGENT,
    "update_aria_acl_rule": ADMIN_ONLY,
    "delete_aria_acl_rule": ADMIN_ONLY,
    "create_aria_acl_address_set": ADMIN_ONLY,
    "get_aria_acl_address_set": ADMIN_OR_AGENT,
    "update_aria_acl_address_set": ADMIN_ONLY,
    "delete_aria_acl_address_set": ADMIN_ONLY,
    "create_aria_acl_binding": ADMIN_ONLY,
    "get_aria_acl_binding": ADMIN_OR_AGENT,
    "update_aria_acl_binding": ADMIN_ONLY,
    "delete_aria_acl_binding": ADMIN_ONLY,
    "get_aria_acl_effective": ADMIN_OR_AGENT,
    "report_aria_acl_port_status": ADMIN_OR_AGENT,
    "create_aria_acl_port_status": ADMIN_OR_AGENT,
    "update_aria_acl_port_status": ADMIN_OR_AGENT,
    "get_aria_acl_port_statuses": ADMIN_OR_AGENT,
    "get_aria_acl_port_status": ADMIN_OR_AGENT,
    "get_aria_acl_port_status:last_reported_at": ADMIN_OR_AGENT,
    "get_aria_acl_port_status:runtime_status": ADMIN_OR_AGENT,
    "get_aria_acl_port_status:stale": ADMIN_OR_AGENT,
    "get_aria_acl_port_statuses:last_reported_at": ADMIN_OR_AGENT,
    "get_aria_acl_port_statuses:runtime_status": ADMIN_OR_AGENT,
    "get_aria_acl_port_statuses:stale": ADMIN_OR_AGENT,
    "delete_aria_acl_port_status": ADMIN_OR_AGENT,
}


def list_rules():
    return dict(ARIA_ACL_POLICIES)

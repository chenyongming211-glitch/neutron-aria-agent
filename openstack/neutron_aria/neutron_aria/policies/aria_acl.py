from __future__ import absolute_import

import json
import os
import stat


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


def merge_policy_file(path):
    """Merge ACL rules without changing an existing policy file's identity."""
    previous_stat = None
    if os.path.exists(path):
        previous_stat = os.stat(path)
        with open(path, "r") as handle:
            try:
                data = json.load(handle)
            except ValueError:
                data = {}
    else:
        data = {}

    changed = False
    for key, value in list_rules().items():
        if data.get(key) != value:
            data[key] = value
            changed = True

    if changed or previous_stat is None:
        tmp = "%s.tmp" % path
        with open(tmp, "w") as handle:
            json.dump(data, handle, indent=4, sort_keys=True)
            handle.write("\n")
        os.rename(tmp, path)
        if previous_stat is None:
            os.chmod(path, 0o644)
        else:
            if hasattr(os, "chown"):
                os.chown(path, previous_stat.st_uid, previous_stat.st_gid)
            os.chmod(path, stat.S_IMODE(previous_stat.st_mode))
    return changed

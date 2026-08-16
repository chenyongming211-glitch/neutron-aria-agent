from __future__ import absolute_import
from __future__ import print_function

import argparse

from neutronclient.common import extension


def _bool(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    return str(value).lower() in ("1", "true", "yes", "on")


def _protocol(value):
    normalized = str(value).strip().lower()
    if normalized in ("any", "tcp", "udp", "icmp", "icmpv6", "ipv6-icmp"):
        return normalized
    try:
        number = int(normalized)
    except (TypeError, ValueError):
        raise argparse.ArgumentTypeError(
            "protocol must be any/tcp/udp/icmp/icmpv6/ipv6-icmp or 0..255"
        )
    if number < 0 or number > 255:
        raise argparse.ArgumentTypeError("protocol number must be in 0..255")
    return str(number)


class _AriaAclCommandMixin(object):
    pagination_support = True
    sorting_support = True
    resource = None
    collection = None
    path = None
    id_path = None
    list_columns = []
    allow_names = False

    def _client(self, parsed_args):
        neutron_client = self.get_client()
        neutron_client.format = parsed_args.request_format
        return neutron_client

    def _add_enabled(self, parser):
        parser.add_argument(
            "--enabled",
            choices=["true", "false"],
            help="Whether this Aria ACL object is enabled.",
        )

    def _project_body(self, parsed_args):
        body = {}
        tenant_id = getattr(parsed_args, "tenant_id", None)
        project_id = getattr(parsed_args, "project_id", None)
        if project_id:
            body["project_id"] = project_id
        if tenant_id:
            body["tenant_id"] = tenant_id
        return body

    def _add_project_arguments(self, parser):
        parser.add_argument("--project-id", dest="project_id")

    def _show_rows(self, data):
        resource = data.get(self.resource) or {}
        return zip(*sorted(resource.items()))


class _AriaAclList(_AriaAclCommandMixin, extension.ClientExtensionList):
    versions = []

    def retrieve_list(self, parsed_args):
        neutron_client = self._client(parsed_args)
        search_opts = self.args2search_opts(parsed_args)
        if self.pagination_support:
            page_size = getattr(parsed_args, "page_size", None)
            if page_size:
                search_opts["limit"] = page_size
        if self.sorting_support:
            keys = list(getattr(parsed_args, "sort_key", None) or [])
            dirs = list(getattr(parsed_args, "sort_dir", None) or [])
            if keys:
                search_opts["sort_key"] = keys
            if len(keys) > len(dirs):
                dirs.extend(["asc"] * (len(keys) - len(dirs)))
            elif len(dirs) > len(keys):
                dirs = dirs[:len(keys)]
            if dirs:
                search_opts["sort_dir"] = dirs
        return self.call_server(
            neutron_client,
            search_opts,
            parsed_args,
        ).get(self.collection, [])

    def args2search_opts(self, parsed_args):
        opts = {}
        for field in ("policy_id", "target_type", "target_id", "port_id", "host"):
            value = getattr(parsed_args, field, None)
            if value:
                opts[field] = value
        return opts

    def call_server(self, neutron_client, search_opts, parsed_args):
        return neutron_client.list_ext(
            self.path,
            **search_opts
        )


class _AriaAclShow(_AriaAclCommandMixin, extension.ClientExtensionShow):
    versions = []

    def execute(self, parsed_args):
        data = self._client(parsed_args).show_ext(self.id_path, parsed_args.id)
        self.format_output_data(data)
        return self._show_rows(data)


class _AriaAclDelete(_AriaAclCommandMixin, extension.ClientExtensionDelete):
    versions = []

    def execute(self, parsed_args):
        self._client(parsed_args).delete_ext(self.id_path, parsed_args.id)
        print("Deleted %s: %s" % (self.resource, parsed_args.id), file=self.app.stdout)


class _AriaAclCreate(_AriaAclCommandMixin, extension.ClientExtensionCreate):
    versions = []

    def execute(self, parsed_args):
        body = self.args2body(parsed_args)
        data = self._client(parsed_args).create_ext(self.path, body)
        self.format_output_data(data)
        print("Created a new %s:" % self.resource, file=self.app.stdout)
        return self._show_rows(data)


class _AriaAclUpdate(_AriaAclCommandMixin, extension.ClientExtensionUpdate):
    versions = []

    def execute(self, parsed_args):
        body = self.args2body(parsed_args)
        self._client(parsed_args).update_ext(self.id_path, parsed_args.id, body)
        print("Updated %s: %s" % (self.resource, parsed_args.id), file=self.app.stdout)


class AriaAclPolicyList(_AriaAclList):
    """List Aria ACL policies."""

    shell_command = "aria-acl-policy-list"
    resource = "aria_acl_policy"
    collection = "aria_acl_policies"
    resource_plural = "aria_acl_policies"
    path = "/aria-acl-policies"
    object_path = "/aria-acl-policies"
    list_columns = ["id", "name", "default_action", "stateful", "enabled", "revision_number"]


class AriaAclPolicyShow(_AriaAclShow):
    """Show an Aria ACL policy."""

    shell_command = "aria-acl-policy-show"
    resource = "aria_acl_policy"
    path = "/aria-acl-policies"
    id_path = "/aria-acl-policies/%s"
    resource_path = "/aria-acl-policies/%s"

    def add_known_arguments(self, parser):
        parser.add_argument(
            "--with-rules",
            action="store_true",
            help=(
                "Include rule IDs for this policy, ordered by direction, "
                "priority, and rule ID."
            ),
        )

    def execute(self, parsed_args):
        neutron_client = self._client(parsed_args)
        data = neutron_client.show_ext(self.id_path, parsed_args.id)
        if getattr(parsed_args, "with_rules", False):
            rule_data = neutron_client.list_ext(
                "/aria-acl-rules",
                policy_id=parsed_args.id,
            )
            rules = sorted(
                rule_data.get("aria_acl_rules") or [],
                key=self._rule_sort_key,
            )
            policy = data.get(self.resource) or {}
            policy["rule_count"] = len(rules)
            policy["rule_ids"] = self._format_rule_ids(rules)
            data[self.resource] = policy
        self.format_output_data(data)
        return self._show_rows(data)

    def _rule_sort_key(self, rule):
        direction_order = {"ingress": 0, "egress": 1}
        direction = rule.get("direction") or ""
        try:
            priority = int(rule.get("priority"))
        except (TypeError, ValueError):
            priority = 2147483647
        return (
            direction_order.get(direction, 2),
            priority,
            str(rule.get("id") or ""),
        )

    def _format_rule_ids(self, rules):
        if not rules:
            return "(none)"
        return "\n".join(str(rule.get("id") or "") for rule in rules)


class AriaAclPolicyCreate(_AriaAclCreate):
    """Create an Aria ACL policy."""

    shell_command = "aria-acl-policy-create"
    resource = "aria_acl_policy"
    path = "/aria-acl-policies"
    object_path = "/aria-acl-policies"

    def add_known_arguments(self, parser):
        self._add_project_arguments(parser)
        parser.add_argument("--name", default="")
        parser.add_argument("--default-action", choices=["allow"], default="allow")
        parser.add_argument("--stateful", choices=["true", "false"], default=None)
        self._add_enabled(parser)

    def args2body(self, parsed_args):
        body = self._project_body(parsed_args)
        body.update({
            "name": parsed_args.name,
            "default_action": parsed_args.default_action,
        })
        if parsed_args.stateful is not None:
            body["stateful"] = _bool(parsed_args.stateful)
        if parsed_args.enabled is not None:
            body["enabled"] = _bool(parsed_args.enabled)
        return {self.resource: body}


class AriaAclPolicyUpdate(_AriaAclUpdate):
    """Update an Aria ACL policy."""

    shell_command = "aria-acl-policy-update"
    resource = "aria_acl_policy"
    id_path = "/aria-acl-policies/%s"
    resource_path = "/aria-acl-policies/%s"

    def add_known_arguments(self, parser):
        parser.add_argument("--name")
        parser.add_argument("--default-action", choices=["allow"])
        parser.add_argument("--stateful", choices=["true", "false"])
        self._add_enabled(parser)

    def args2body(self, parsed_args):
        body = {}
        for field in ("name", "default_action", "stateful", "enabled"):
            value = getattr(parsed_args, field, None)
            if value is not None:
                body[field] = _bool(value) if field in ("stateful", "enabled") else value
        return {self.resource: body}


class AriaAclPolicyDelete(_AriaAclDelete):
    """Delete an Aria ACL policy."""

    shell_command = "aria-acl-policy-delete"
    resource = "aria_acl_policy"
    id_path = "/aria-acl-policies/%s"
    resource_path = "/aria-acl-policies/%s"


class AriaAclRuleList(_AriaAclList):
    """List Aria ACL rules."""

    shell_command = "aria-acl-rule-list"
    resource = "aria_acl_rule"
    collection = "aria_acl_rules"
    resource_plural = "aria_acl_rules"
    path = "/aria-acl-rules"
    object_path = "/aria-acl-rules"
    list_columns = [
        "id", "policy_id", "direction", "priority", "action", "ethertype",
        "protocol", "enabled",
    ]

    def add_known_arguments(self, parser):
        parser.add_argument("--policy-id", dest="policy_id")
        parser.add_argument("--policy", dest="policy_id")


class AriaAclRuleShow(_AriaAclShow):
    """Show an Aria ACL rule."""

    shell_command = "aria-acl-rule-show"
    resource = "aria_acl_rule"
    path = "/aria-acl-rules"
    id_path = "/aria-acl-rules/%s"
    resource_path = "/aria-acl-rules/%s"


class AriaAclRuleCreate(_AriaAclCreate):
    """Create an Aria ACL rule."""

    shell_command = "aria-acl-rule-create"
    resource = "aria_acl_rule"
    path = "/aria-acl-rules"
    object_path = "/aria-acl-rules"

    def add_known_arguments(self, parser):
        self._add_project_arguments(parser)
        parser.add_argument("--policy-id", "--policy", dest="policy_id", required=True)
        parser.add_argument("--direction", choices=["ingress", "egress"], required=True)
        parser.add_argument("--priority", type=int, required=True)
        parser.add_argument("--action", choices=["allow", "deny", "drop"], required=True)
        parser.add_argument("--protocol", type=_protocol)
        parser.add_argument("--src-cidr")
        parser.add_argument("--dst-cidr")
        parser.add_argument("--src-address-set-id")
        parser.add_argument("--dst-address-set-id")
        parser.add_argument("--dst-port-min", type=int)
        parser.add_argument("--dst-port-max", type=int)
        parser.add_argument("--dst-port", type=int)
        parser.add_argument("--ethertype", choices=["IPv4", "IPv6"])
        self._add_enabled(parser)

    def args2body(self, parsed_args):
        body = self._project_body(parsed_args)
        body.update({
            "policy_id": parsed_args.policy_id,
            "direction": parsed_args.direction,
            "priority": parsed_args.priority,
            "action": parsed_args.action,
        })
        optional_fields = (
            "protocol", "src_cidr", "dst_cidr", "src_address_set_id",
            "dst_address_set_id", "dst_port_min", "dst_port_max", "ethertype",
        )
        for field in optional_fields:
            value = getattr(parsed_args, field, None)
            if value is not None:
                body[field] = value
        if parsed_args.dst_port is not None:
            body["dst_port_min"] = parsed_args.dst_port
            body["dst_port_max"] = parsed_args.dst_port
        if parsed_args.enabled is not None:
            body["enabled"] = _bool(parsed_args.enabled)
        return {self.resource: body}


class AriaAclRuleUpdate(_AriaAclUpdate):
    """Update an Aria ACL rule."""

    shell_command = "aria-acl-rule-update"
    resource = "aria_acl_rule"
    id_path = "/aria-acl-rules/%s"
    resource_path = "/aria-acl-rules/%s"

    def add_known_arguments(self, parser):
        parser.add_argument("--direction", choices=["ingress", "egress"])
        parser.add_argument("--priority", type=int)
        parser.add_argument("--action", choices=["allow", "deny", "drop"])
        parser.add_argument("--protocol", type=_protocol)
        parser.add_argument("--src-cidr")
        parser.add_argument("--dst-cidr")
        parser.add_argument("--src-address-set-id")
        parser.add_argument("--dst-address-set-id")
        parser.add_argument("--dst-port-min", type=int)
        parser.add_argument("--dst-port-max", type=int)
        parser.add_argument("--dst-port", type=int)
        parser.add_argument("--ethertype", choices=["IPv4", "IPv6"])
        self._add_enabled(parser)

    def args2body(self, parsed_args):
        body = {}
        for field in (
            "direction", "priority", "action", "protocol", "src_cidr",
            "dst_cidr", "src_address_set_id", "dst_address_set_id",
            "dst_port_min", "dst_port_max",
            "ethertype",
        ):
            value = getattr(parsed_args, field, None)
            if value is not None:
                body[field] = value
        if parsed_args.dst_port is not None:
            body["dst_port_min"] = parsed_args.dst_port
            body["dst_port_max"] = parsed_args.dst_port
        if parsed_args.enabled is not None:
            body["enabled"] = _bool(parsed_args.enabled)
        return {self.resource: body}


class AriaAclRuleDelete(_AriaAclDelete):
    """Delete an Aria ACL rule."""

    shell_command = "aria-acl-rule-delete"
    resource = "aria_acl_rule"
    id_path = "/aria-acl-rules/%s"
    resource_path = "/aria-acl-rules/%s"


class AriaAclAddressSetList(_AriaAclList):
    """List Aria ACL address sets."""

    shell_command = "aria-acl-address-set-list"
    resource = "aria_acl_address_set"
    collection = "aria_acl_address_sets"
    resource_plural = "aria_acl_address_sets"
    path = "/aria-acl-address-sets"
    object_path = "/aria-acl-address-sets"
    list_columns = [
        "id", "name", "ethertype", "members", "enabled", "revision_number",
    ]


class AriaAclAddressSetShow(_AriaAclShow):
    """Show an Aria ACL address set."""

    shell_command = "aria-acl-address-set-show"
    resource = "aria_acl_address_set"
    path = "/aria-acl-address-sets"
    id_path = "/aria-acl-address-sets/%s"
    resource_path = "/aria-acl-address-sets/%s"


class AriaAclAddressSetCreate(_AriaAclCreate):
    """Create an Aria ACL address set."""

    shell_command = "aria-acl-address-set-create"
    resource = "aria_acl_address_set"
    path = "/aria-acl-address-sets"
    object_path = "/aria-acl-address-sets"

    def add_known_arguments(self, parser):
        self._add_project_arguments(parser)
        parser.add_argument("--name", default="")
        parser.add_argument("--member", dest="members", action="append", default=[])
        self._add_enabled(parser)

    def args2body(self, parsed_args):
        body = self._project_body(parsed_args)
        body.update({
            "name": parsed_args.name,
            "members": parsed_args.members or [],
        })
        if parsed_args.enabled is not None:
            body["enabled"] = _bool(parsed_args.enabled)
        return {self.resource: body}


class AriaAclAddressSetUpdate(_AriaAclUpdate):
    """Update an Aria ACL address set."""

    shell_command = "aria-acl-address-set-update"
    resource = "aria_acl_address_set"
    id_path = "/aria-acl-address-sets/%s"
    resource_path = "/aria-acl-address-sets/%s"

    def add_known_arguments(self, parser):
        parser.add_argument("--name")
        parser.add_argument(
            "--replace-member",
            dest="members",
            action="append",
            help=(
                "Replace the complete address-set membership with the repeated "
                "CIDR values; omit this option to preserve existing members."
            ),
        )
        self._add_enabled(parser)

    def args2body(self, parsed_args):
        body = {}
        if parsed_args.name is not None:
            body["name"] = parsed_args.name
        if parsed_args.members is not None:
            body["members"] = parsed_args.members
        if parsed_args.enabled is not None:
            body["enabled"] = _bool(parsed_args.enabled)
        return {self.resource: body}


class AriaAclAddressSetDelete(_AriaAclDelete):
    """Delete an Aria ACL address set."""

    shell_command = "aria-acl-address-set-delete"
    resource = "aria_acl_address_set"
    id_path = "/aria-acl-address-sets/%s"
    resource_path = "/aria-acl-address-sets/%s"


class AriaAclBindingList(_AriaAclList):
    """List Aria ACL bindings."""

    shell_command = "aria-acl-binding-list"
    resource = "aria_acl_binding"
    collection = "aria_acl_bindings"
    resource_plural = "aria_acl_bindings"
    path = "/aria-acl-bindings"
    object_path = "/aria-acl-bindings"
    list_columns = ["id", "policy_id", "target_type", "target_id", "enabled", "revision_number"]

    def add_known_arguments(self, parser):
        parser.add_argument("--policy-id", "--policy", dest="policy_id")
        parser.add_argument("--target-type", dest="target_type")
        parser.add_argument("--target-id", dest="target_id")
        parser.add_argument("--port", dest="target_id")
        parser.add_argument("--network", dest="target_id")


class AriaAclBindingShow(_AriaAclShow):
    """Show an Aria ACL binding."""

    shell_command = "aria-acl-binding-show"
    resource = "aria_acl_binding"
    path = "/aria-acl-bindings"
    id_path = "/aria-acl-bindings/%s"
    resource_path = "/aria-acl-bindings/%s"


class AriaAclBindingCreate(_AriaAclCreate):
    """Create an Aria ACL binding."""

    shell_command = "aria-acl-binding-create"
    resource = "aria_acl_binding"
    path = "/aria-acl-bindings"
    object_path = "/aria-acl-bindings"

    def add_known_arguments(self, parser):
        self._add_project_arguments(parser)
        parser.add_argument("--policy-id", "--policy", dest="policy_id", required=True)
        target = parser.add_mutually_exclusive_group(required=True)
        target.add_argument("--port")
        target.add_argument("--network")
        self._add_enabled(parser)

    def args2body(self, parsed_args):
        body = self._project_body(parsed_args)
        body["policy_id"] = parsed_args.policy_id
        if parsed_args.port:
            body["target_type"] = "port"
            body["target_id"] = parsed_args.port
        else:
            body["target_type"] = "network"
            body["target_id"] = parsed_args.network
        if parsed_args.enabled is not None:
            body["enabled"] = _bool(parsed_args.enabled)
        return {self.resource: body}


class AriaAclBindingUpdate(_AriaAclUpdate):
    """Update an Aria ACL binding."""

    shell_command = "aria-acl-binding-update"
    resource = "aria_acl_binding"
    id_path = "/aria-acl-bindings/%s"
    resource_path = "/aria-acl-bindings/%s"

    def add_known_arguments(self, parser):
        self._add_enabled(parser)

    def args2body(self, parsed_args):
        body = {}
        if parsed_args.enabled is not None:
            body["enabled"] = _bool(parsed_args.enabled)
        return {self.resource: body}


class AriaAclBindingDelete(_AriaAclDelete):
    """Delete an Aria ACL binding."""

    shell_command = "aria-acl-binding-delete"
    resource = "aria_acl_binding"
    id_path = "/aria-acl-bindings/%s"
    resource_path = "/aria-acl-bindings/%s"


class AriaAclPortStatusList(_AriaAclList):
    """List Aria ACL port runtime status rows."""

    shell_command = "aria-acl-port-status-list"
    resource = "aria_acl_port_status"
    collection = "aria_acl_port_statuses"
    resource_plural = "aria_acl_port_statuses"
    path = "/aria-acl-port-statuses"
    object_path = "/aria-acl-port-statuses"
    list_columns = [
        "id", "port_id", "host", "status", "effective_action",
        "effective_policy_id", "binding_id", "generation", "stale",
    ]

    def add_known_arguments(self, parser):
        parser.add_argument("--port-id", "--port", dest="port_id")
        parser.add_argument("--host")


# Numeric drop-reason names for the port-status --counters view. This is a
# CLI-local mirror of neutron_aria.agent.drop_reasons.DROP_REASON_NAMES;
# keep both in sync when the eBPF ABI reason vocabulary changes.
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


class AriaAclPortStatusShow(_AriaAclShow):
    """Show an Aria ACL port runtime status row."""

    shell_command = "aria-acl-port-status-show"
    resource = "aria_acl_port_status"
    path = "/aria-acl-port-statuses"
    id_path = "/aria-acl-port-statuses/%s"
    resource_path = "/aria-acl-port-statuses/%s"

    def add_known_arguments(self, parser):
        parser.add_argument(
            "--counters",
            action="store_true",
            help=(
                "Show port counter rows: cumulative policy/drop counters per "
                "bucket and per drop reason."
            ),
        )

    def execute(self, parsed_args):
        neutron_client = self._client(parsed_args)
        data = neutron_client.show_ext(self.id_path, parsed_args.id)
        status = dict(data.get(self.resource) or {})
        group_map = status.pop("aria_acl_port_group_map", None) or {}
        counter_rows = status.pop("aria_acl_port_counters", None) or []
        if getattr(parsed_args, "counters", False):
            bucket_index = 0
            reason_index = 0
            for row in counter_rows:
                kind = row.get("kind")
                if kind == "bucket":
                    bucket_index += 1
                    key = "counters.bucket[%d]" % bucket_index
                    value = self._format_bucket(row, group_map)
                elif kind == "reason":
                    reason_index += 1
                    key = "counters.reason[%d]" % reason_index
                    value = self._format_reason(row)
                else:
                    continue
                status[key] = value
        data[self.resource] = status
        self.format_output_data(data)
        return self._show_rows(data)

    @staticmethod
    def _direction_name(direction):
        if direction == 0:
            return "ingress"
        if direction == 1:
            return "egress"
        return str(direction)

    @classmethod
    def _group_label(cls, group_id, group_map):
        if group_id is None:
            return None
        cidrs = (
            group_map.get(group_id)
            or group_map.get(str(group_id))
        )
        if cidrs:
            return ",".join(str(cidr) for cidr in cidrs)
        return str(group_id)

    @classmethod
    def _format_bucket(cls, row, group_map=None):
        group_map = group_map or {}
        return (
            "src=%s dst=%s proto=%s dir=%s pkts=%s bytes=%s "
            "dropped=%s pps=%s bps=%s"
            % (
                cls._group_label(row.get("src_id"), group_map),
                cls._group_label(row.get("dst_id"), group_map),
                row.get("proto"),
                cls._direction_name(row.get("direction")),
                row.get("packets"),
                row.get("bytes"),
                row.get("dropped_packets"),
                row.get("pps"),
                row.get("bps"),
            )
        )

    @classmethod
    def _format_reason(cls, row):
        reason_id = row.get("reason")
        reason_name = DROP_REASON_NAMES.get(reason_id)
        if reason_name is None:
            reason_name = "UNKNOWN(%s)" % reason_id
        return (
            "reason=%s dir=%s pkts=%s bytes=%s pps=%s bps=%s"
            % (
                reason_name,
                cls._direction_name(row.get("direction")),
                row.get("packets"),
                row.get("bytes"),
                row.get("pps"),
                row.get("bps"),
            )
        )


_CONCRETE_COMMANDS = (
    AriaAclPolicyList,
    AriaAclPolicyShow,
    AriaAclPolicyCreate,
    AriaAclPolicyUpdate,
    AriaAclPolicyDelete,
    AriaAclRuleList,
    AriaAclRuleShow,
    AriaAclRuleCreate,
    AriaAclRuleUpdate,
    AriaAclRuleDelete,
    AriaAclAddressSetList,
    AriaAclAddressSetShow,
    AriaAclAddressSetCreate,
    AriaAclAddressSetUpdate,
    AriaAclAddressSetDelete,
    AriaAclBindingList,
    AriaAclBindingShow,
    AriaAclBindingCreate,
    AriaAclBindingUpdate,
    AriaAclBindingDelete,
    AriaAclPortStatusList,
    AriaAclPortStatusShow,
)

for _command in _CONCRETE_COMMANDS:
    _command.versions = ["2.0"]

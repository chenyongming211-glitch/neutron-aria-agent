# 15. ACL Operator UX Backlog

Status: UX-ACL-001 implemented; remaining operator UX items stay planned.

Date: 2026-07-08.

Scope rule:

- Improve read-only CLI/API troubleshooting usability for ACL operators.
- Do not change datapath behavior, ACL match semantics, or authority rules.
- Keep the current normalized policy/rule/binding/status resource model.
- Do not block the current MVP on these UX helpers.

## UX-ACL-001: Policy Show With Rules

Problem:

`neutron aria-acl-policy-show <policy_id>` currently shows policy metadata only.
This is correct for a normalized Neutron API, but it is inconvenient for field
troubleshooting because operators must separately query rules, bindings, port
status, and sometimes datapath state.

Current commands:

```text
neutron aria-acl-policy-show <policy_id>
neutron aria-acl-rule-list --policy-id <policy_id>
neutron aria-acl-binding-list --policy-id <policy_id>
neutron aria-acl-port-status-show <port_id>
```

Implemented read-only UX:

```text
neutron aria-acl-policy-show --with-rules <policy_id>
```

or:

```text
neutron aria-acl-policy-rules <policy_id>
```

Acceptance:

- Show IDs for enabled and disabled rules in the policy, ordered by direction,
  priority, and rule ID.
- Keep policy output compact. Operators use
  `neutron aria-acl-rule-show <rule-id>` for complete rule fields.
- Preserve existing `aria-acl-policy-show` output unless `--with-rules` is
  explicitly requested.
- Stay compatible with the legacy Python2 `python-neutronclient` extension
  style used by the target environment.

Implementation notes:

- The default command still reads only `/aria-acl-policies/{id}` and preserves
  the original policy-only output.
- `--with-rules` additionally reads `/aria-acl-rules?policy_id={id}` and adds
  `rule_count` plus a multi-line `rule_ids` field. It does not inline match or
  action details.
- Rules are ordered deterministically by ingress/egress, priority, and rule ID.
- An explicit request against a policy with no rules reports
  `rule_count=0` and `rule_ids=(none)`.
- This is a Legacy neutronclient presentation feature. It does not denormalize
  the Neutron API or add a `rules` column to `aria_acl_policies`.

## UX-ACL-002: Effective ACL Read For Port

Problem:

When a VM port is blocked or allowed unexpectedly, the operator needs one command
that answers: which binding selected which policy, which rules are effective,
what the agent reported, and whether the runtime is stale.

Desired read-only UX:

```text
neutron aria-acl-effective-show --port <port_id>
```

Optional REST shape, if compatible with the deployed Neutron extension style:

```text
GET /aria-acl-effective?port_id=<port_id>
```

Acceptance:

- Include `port_id`, `binding_id`, `policy_id`, policy name, `effective_action`,
  `status`, `runtime_status`, `stale`, `generation`, and host.
- Include effective rules ordered by direction and priority.
- Include clear reasons for common empty states: no binding, disabled binding,
  missing policy, stale status, or agent not ready.
- Read-only only; no datapath submit or local state mutation.

## Priority

Implement after core ACL correctness, rollback, and smoke coverage are stable.
This backlog improves usability and product troubleshooting, but it is not a new
ACL enforcement feature.

# RISK-BOUNDARY-001 Enforcement-Gap Evidence

Date: 2026-08-10

Status: passed on the two available target hosts. The unavailable target host
was not accessed.

## Scope

This evidence validates the product distinction between normal availability-
first bypass and an ACL enforcement gap. The check is read-only and joins:

- enabled Aria ACL policy and binding state;
- current Neutron port host ownership;
- complete Aria ACL port runtime rows;
- exact policy/binding identity, stale state, runtime status, and effective
  action.

## Results

| Scenario | Result |
| --- | --- |
| No enabled ACL binding on the two available hosts | `pass`, zero expected ports and zero enforcement gaps. |
| Compute-only host with no local Neutron API | `pass` after legacy OpenStack catalog endpoint discovery. |
| Enabled policy and port binding on the existing test VM | One expected port, one enforced port, zero gaps. Runtime was exact `ready/enforce` with matching policy and binding identity. |
| Same binding with policy temporarily disabled | One enforcement gap. Runtime was `degraded/bypass` with `policy_missing_or_disabled`; the check emitted an `ALERT` containing port, host, policy, binding, state, action, and reason. |
| Policy restored | One expected port, one enforced port, zero gaps. |
| Binding and policy deleted | Zero enabled bindings, zero expected ports, zero gaps. |

The check returns `0` for a healthy enforcement set, `2` for one or more
enforcement gaps, and `1` when the check itself cannot obtain or validate its
inputs.

## Forwarding Preservation

VM connectivity remained unchanged throughout the policy-state transitions:

- initial `ready/enforce`: 20/20 replies;
- deliberate `degraded/bypass`: 20/20 replies;
- restored `ready/enforce`: 10/10 replies;
- post-cleanup baseline: 10/10 replies.

No OVS, OVS-agent, Python agent, Rust datapath, or Neutron service was
restarted. The test objects were deleted after validation.

## Acceptance Boundary

- No enabled binding is the normal `not_requested/bypass` case and does not
  page the security operator.
- An unbound port is not an active datapath enforcement target and is counted
  separately rather than alerted.
- A currently bound port selected by an enabled ACL binding must have exact,
  non-stale `ready/enforce` evidence. Missing, stale, degraded, bypass, or
  identity-mismatched evidence is an enforcement gap.
- The monitor reports the gap; it never restarts OVS, OVS-agent, datapath, or
  changes desired ACL state.

# ACL-055 All-Mode TC Authority Acceptance

Date: 2026-08-11

Status: passed on the available target-kernel compute node.

## Scope

This acceptance closes `REVIEW-ACL-055` for the three required runtime forms:

- standalone `MODE=system`;
- standalone `MODE=tap`;
- Neutron-managed VM tap.

It verifies that XDP remains ACL/conntrack-neutral, TC ingress and egress are
the only ACL/conntrack authorities, policy transitions invalidate stale flow
state, incomplete TC recovery does not advertise ready, restart replay restores
the enforced policy, and Aria does not interrupt the independent OVS forwarding
canary.

Selector-isolation fixtures were intentionally not rerun in the focused
managed test. They are reported as `not_requested`, not passed. Their separate
two-compute field acceptance is recorded under `REVIEW-ACL-046`.

## Candidate Identity

| Item | Value |
| --- | --- |
| Runtime source commit | `7ffc5d65d9b30d0a1f9e706ec779cc8213200458` |
| Evidence-scope commit | `5a1070566e65ddc7ab468ddddb43a328af3408fd` |
| Exact runtime Build | [31477810061](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31477810061) |
| Exact runtime push Build | [31477333811](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31477333811) |
| `aria-agent` SHA-256 | `687af9d6a319eb1858004e5cff8bfe061e3693217c401e0a9b033a92e86d3079` |
| `libebpf_firewall.so` SHA-256 | `6488da9614a7ce81d0d2ae6271ffd0108d084a2115c2d37da02f6dcda13ab50f` |
| `stack-budget.json` SHA-256 | `98cdc4de5199cee498c752b49f7a5fad5c2756e86a62e75755772e92c98e0503` |
| Worst ingress/egress stack | `448 / 448` bytes |

The evidence-scope commit only adds `SELECTOR_FIXTURE_SCOPE=none` to the
managed smoke and records that scope in its summary. The runtime binaries are
unchanged from the exact runtime Build.

## Results

| Runtime form | Result | Key evidence |
| --- | --- | --- |
| standalone `system` | pass | Legacy TC ingress/egress ready; XDP neutral; a missing TC direction was rejected; health degraded during the fault; exact residual cleanup, replay, and recovery succeeded; cleanup errors empty. |
| standalone `tap` | pass | Legacy TC ingress/egress ready; XDP neutral; missing-direction rejection, restart replay, recovery, and cleanup all passed. |
| Neutron managed | pass | `XDP_NO_ACL_CT`, `TC_INGRESS_HIT`, `TC_EGRESS_HIT`, `STATELESS_ZERO_CT`, `NO_INGRESS_DOUBLE_COUNT`, `TC_LINK_REQUIRED`, `BANK_REVALIDATED`, and `DENY_ZERO_CT` were all true; cleanup errors empty. |

The managed restart guard enabled the existing test policy and binding, waited
for `ready/enforce`, and sent ICMP continuously while restarting only the
`aria_datapath` container. It observed zero successful replies before, during,
or after restart. The health endpoint returned on poll 2 and port status was
already `ready/enforce` on its first post-restart poll. Restoring the original
disabled policy and binding reached `not_requested/bypass` on poll 2, after
which a three-packet connectivity check passed.

The standalone summaries are preserved on the target at:

```text
/var/tmp/aria-acl055-7ffc5d6/system-run/summary.json
/var/tmp/aria-acl055-7ffc5d6/tap-run/summary.json
```

The focused managed summary is preserved at:

```text
/var/tmp/aria-acl055-7ffc5d6/managed-focused/summary.json
/var/tmp/aria-acl055-7ffc5d6/managed-restart/
```

Its selector section records `requested_scope=none`; all three selector
fixtures are `not_requested`. Cleanup restored the pre-test disabled binding,
reported `not_requested/bypass` for the port, and left zero smoke-named local
groups.

## OVS Independence

An independent ping canary ran against a separate canary VM throughout the field
debugging and final three-form acceptance. It recorded 30,162 replies and zero
failure markers. The `ovs-vswitchd` PID remained `3272273`. The
`neutron_openvswitch_agent` container ID, PID `149412`, and start time
`2026-06-03T03:33:19.614042543Z` were unchanged.

Aria did not restart, reconfigure, or repair OVS or ovs-agent. Only the
`aria_datapath` candidate container was restarted for its own runtime recovery
and managed-mode verification.

## Defects Found During Acceptance

The target 4.18 legacy-TC runtime exposed six implementation gaps before the
final pass:

1. system mode assumed TC links were always convertible to `FdLink`;
2. standalone global bank publication was hard-coded;
3. TC contract counters omitted the valid standalone `tap_id=0` identity;
4. healthy legacy-TC reuse replayed state into a different map set;
5. one surviving TC direction was rejected rather than quiesced and rebuilt;
6. rebuilt TC filters could retain an unpinned execution map set while the API
   exposed newly pinned maps.

Commits `d6aa6fc` through `7ffc5d6` repair those boundaries. Each failure path
was kept fail-open for the underlying OVS forwarding path while preventing a
false ACL-ready result.

## Limitations

The old kernel cannot provide every modern pinned-XDP link-identity operation.
XDP is optional for this ACL acceptance and remained ACL/CT-neutral. Exact XDP
hook identity remains the separate `REVIEW-OPS-036` DDoS/XDP activation gate.

The candidate binaries were copied into the running test container for this
acceptance. They are not yet a persistent Kolla image rollout and will be lost
if that container is rebuilt from its prior image.

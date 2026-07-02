# OpenStack Neutron Aria Design Decisions

Status: design decision ledger for v0.9. This document records the major
decisions before they are expanded into detailed design and implementation
tasks.

Normative order:

1. `openstack-neutron-agent-mode.md` section 1.5 is the top-level contract.
2. `neutron-managed-domains-contract.md` is the short day-to-day contract.
3. `aria-acl-neutron-extension-product-design.md` owns `aria_acl` API/DB details.
4. `openstack-deployment-runbook.md` owns enablement and rollback procedure.

## Fixed Decisions

| Decision | Status | Notes |
| --- | --- | --- |
| No overengineering | fixed | Do not build beyond the v0.9 OpenStack scope. Every new field, feature, abstraction, and workflow must map to a first-stage gate, smoke, production risk, or explicitly approved later-stage plan. |
| OpenStack integration shape | fixed | Use OVS enhancement mode. OVS keeps L2 forwarding; Aria adds node-side ACL/QoS enhancement. |
| Runtime communication | fixed | `neutron-aria-agent` talks to `aria-datapath` through local UDS, not TCP OpenAPI. |
| Deployment shape | fixed | Keep `neutron-aria-agent` and `aria-datapath` as separate runtime responsibilities; do not make OVS agent own datapath lifecycle. |
| ACL production northbound | fixed | Production ACL input is `aria_acl` Neutron service plugin/API/DB. |
| ACL non-production inputs | fixed | `fixture` is CI/smoke only; tag + local mapping is legacy lab/bootstrap/migration helper only. |
| Security Group relationship | fixed | Do not project Neutron Security Group, remote group, port security, or allowed address pairs into Aria ACL in v0.9. |
| Control authority | fixed | `neutron_managed` controls attach/detach authority; `managed_domains` controls per-domain local write authority. |
| Local `ariactl` coexistence | fixed | Local writes are rejected only for domains listed in `managed_domains`; local reads and non-managed domains remain available. |
| Failure behavior | fixed | ACL not ready or apply failed means `effective_action=bypass`; OVS L2 forwarding must not be blocked by Aria degraded state. |
| `integration_mode` ownership | fixed | `integration_mode=coexist` is a snapshot field written by `neutron-aria-agent`, not an ini setting. |
| `effective_action` vocabulary | fixed | Use `enforce` for active ACL enforcement, not `enabled`. |

## Deferred Decisions (Post-Stage-Three)

These are recorded target directions, not v0.9 MVP commitments. Detail lives in
`openstack-neutron-aria-details/09-aria-rpc-incremental-sync.md`.

| Decision | Status | Notes |
| --- | --- | --- |
| Sync model phases | planned | P1 REST periodic full-resync (current MVP); P2 RPC-triggered full-resync; P3 incremental RPC with port-scoped apply. |
| Full-resync retention | planned | Incremental RPC optimizes latency; full-resync remains startup/recovery/capability-drift authority. |
| OVS comparison | planned | Borrow OVS RPC notification semantics, not OVS incremental OVSDB ownership; Aria keeps snapshot/WAL/generation model. |
| Port-scoped snapshot | planned | Required for P3; parent design already references port-scoped apply; UDS planned contract is recorded, while Rust scoped apply and WAL tests remain future work. |
| `aria_acl` object RPC | open | ACL object changes may still require resync until dedicated RPC or revision subscription exists. |

## Design Areas To Optimize Before Detailed Implementation

| Area | Why It Matters | Current Plan |
| --- | --- | --- |
| INI contract convergence | Current documents still contain multiple historical ini examples. | Converge all examples to `[agent]`, `[ovs]`, `[aria]`, `[neutron]`, `[acl]`; remove `integration_mode` from ini examples. |
| Documentation entry points | Product readers may start from different docs and miss the control contract. | Link product design to the short contract and runbook; keep README links current. |
| Rich domain status | Current code status is simpler than target contract. | Later detail `DomainStatus`, `effective_action`, `support_disposition`, and heartbeat projection. |
| UDS contract hardening | Production needs compatibility and security guarantees. | Later detail generated `neutron-uds-contract.json`, schema range, body limit, error hash, peer auth, and audit. |
| `aria_acl` server plugin | ACL production path depends on this. | Later detail Python2-compatible plugin/API/DB/RBAC/legacy client implementation. |
| `NeutronAclSource` | Agent cannot use production ACL path while this is stubbed. | Later detail read model, effective ACL merge, revision handling, cache, and full-resync behavior. |
| Deployment enablement | Operators need exact safe enable/rollback sequence. | Expand runbook after target ini layout is finalized and environment evidence is collected. |
| N0.5 evidence | Design assumptions must become verified facts. | Fill `openstack-target-env-discovery.md` with command, expected result, actual result, and evidence path. |

## Anti-Overengineering Rules

This is a first-stage product integration, not a rewrite of OpenStack networking
or Aria's whole control plane. Keep the implementation deliberately narrow.

Do not do these unless a later phase explicitly approves them:

- Do not replace OVS L2, tunnel, local switching, or Neutron port binding.
- Do not project Neutron Security Group, remote group, port security, or allowed
  address pairs into Aria ACL.
- Do not introduce `aria-controller` or v0.10 controller concepts into this
  branch.
- Do not make Mirror, TCPrt, Trace, Drops, SSL, Diagnose, Service Chain, Route,
  NAT, L4 LB, or Service part of the v0.9 Neutron tenant feature scope.
- Do not build full object-level multi-writer ownership before the domain-level
  `managed_domains` model proves insufficient.
- Do not add a full L4 TCP state machine unless the product requirement and
  tests explicitly demand it; the current lightweight stateful ACL model remains
  acceptable for v0.9.
- Do not add new Python dependencies, new Neutron framework assumptions, or
  Python3-only patterns without checking the target product image.
- Do not turn runbook convenience, lab fixtures, or legacy tag/mapping helpers
  into production control-plane contracts.
- Do not expand schema fields just because they are theoretically useful; each
  field must have an owner, reader, validation path, and test.

Prefer these instead:

- Ship the smallest vertical slice that proves `aria_acl -> neutron-aria-agent
  -> UDS snapshot -> aria-datapath -> status` works.
- Keep first-stage gates observable and reversible.
- Treat unverified target-environment assumptions as `planned` or `unknown`, not
  as implemented product facts.
- Add abstractions only when they remove real duplication or enforce a contract
  already used by code and tests.
- Keep local `ariactl` capabilities by default, and gate only the domains that
  Neutron actually owns.

## Known Documentation Debt

These are known documentation cleanups. They do not define alternate designs.

| File / Area | Current Issue | Target |
| --- | --- | --- |
| `openstack-deployment-runbook.md` safe defaults | Still may contain transitional ini layout or section placement. | Align with target ini layout in `neutron-managed-domains-contract.md`. |
| `openstack-neutron-agent-mode.md` section 10 examples | Older examples use `[DEFAULT] + [aria]` shape. | Replace or mark deprecated; use the target ini layout. |
| `aria-acl-neutron-extension-product-design.md` examples | Some examples predate the short contract and runbook. | Add links and align examples with the target ini layout. |
| `integration_mode` in ini examples | Historical examples may still show it as a config key. | Remove from ini examples; keep only in snapshot JSON examples. |
| deploy/kolla examples | They are implementation evidence and may temporarily lag the target contract. | Document any mismatch as transitional, not normative. |

## Backlog That Does Not Change The Design

The following are implementation or evidence work items. They should not be
treated as reasons to reopen the architecture unless a hard blocker is found.

| Backlog | Type |
| --- | --- |
| Implement `aria_acl` Neutron service plugin/API/DB. | implementation |
| Implement production `NeutronAclSource`. | implementation |
| Add generated UDS contract artifact and drift check. | implementation / CI |
| Add Unix peer credential validation and audit log. | security hardening |
| Extend runtime status DTOs to rich per-domain status. | API evolution |
| Fill N0.5 target environment evidence. | validation |
| Finalize Kolla packaging and smoke runbook. | delivery |
| P2 RPC-triggered full-resync enablement. | post-stage-three |
| P3 incremental RPC and port-scoped apply. | post-stage-three |

## Next Refinement Pass

First-pass implementation design packages are tracked in
`openstack-neutron-aria-details/README.md`:

1. `01-ini-contract.md`
2. `02-aria-acl-plugin.md`
3. `03-neutron-acl-source.md`
4. `04-uds-contract-security.md`
5. `05-domain-status-heartbeat.md`
6. `06-deployment-n05-runbook.md`
7. `07-transaction-wal.md`
8. `08-stage3-acl-production-hardening.md`
9. `09-aria-rpc-incremental-sync.md`

QoS remains in v0.9 scope, but its dedicated detail pass should start after the
INI, UDS/transaction, ACL production path, and target QoS runtime capability
questions are stable.

Incremental RPC (plan 09) starts after stage-three closes P2
(RPC-triggered full-resync) and must not reopen v0.9 architecture boundaries.

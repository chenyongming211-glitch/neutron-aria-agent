# 11. QoS Next Phase Entry Plan

Status: entry assessment only. Do not implement QoS shaping from this document
alone.

## Goal

Reopen the QoS part of the v0.9 first-stage scope after ACL/P3 closure, while
honoring the anti-overengineering rule. The first QoS step is to verify what the
target OpenStack and hosts can actually support, then define degraded behavior.

## Current Target Facts

Current N0.5 evidence records:

- Neutron QoS extension is not visible on the 10.58.159 target environment.
- Target hosts lack the `tc` command, so Linux qdisc/clsact shaping cannot be
  promised.
- QoS shaping is currently `unsupported` for that environment.
- ACL production path and P3 RPC work do not enable QoS or Mirror.

Evidence sources:

- `docs/openstack-target-env-discovery.md`
- `docs/evidence/openstack-n05-lite/2026-06-30-discovery-summary.md`
- per-host `qos-extension.txt` files under `docs/evidence/openstack-n05-lite/`

## Entry Principles

- Do not promise shaping until `tc` or an approved equivalent is present and
  verified on the target host.
- Do not expose a Neutron QoS product path until Neutron QoS extension/API
  availability is verified.
- Do not add a second authority model. Reuse `managed_domains`; local QoS writes
  are blocked only when `qos` is in `managed_domains`.
- Do not let QoS degraded/unsupported state affect OVS baseline forwarding.
- Do not expand Mirror, Trace, Drops, or other local-only capabilities as part of
  QoS.

## Proposed Phases

| Phase | Scope | Exit Criteria |
| --- | --- | --- |
| Q0 evidence refresh | Rerun read-only discovery for Neutron QoS extension, `tc`, kernel/qdisc support, and current datapath QoS primitives. | Evidence table shows `supported`, `unsupported`, or `not_applicable` for each host. |
| Q1 status-only contract | Add or verify QoS domain status shape for `not_requested`, `unsupported`, and `degraded/bypass-or-noop`. | QoS can report unsupported without false ready and without datapath mutation. |
| Q2 authority gate | Reuse `managed_domains=["qos"]` for local write blocking when Neutron owns QoS. | Local QoS writes remain allowed when `qos` is not managed; blocked when managed. |
| Q3 input path decision | If Neutron QoS extension exists, map the minimum policy/rule read path. If absent, defer Neutron QoS product path. | No tenant-facing QoS API is claimed without extension evidence. |
| Q4 datapath action decision | Choose shaping, policing, or unsupported based on runtime capability evidence. | Shaping requires `tc`/qdisc evidence; otherwise report policing or unsupported explicitly. |
| Q5 smoke | Run bounded QoS smoke only for the chosen disposition. | Smoke proves either supported action or clean unsupported/degraded status. |

## Minimum Status Semantics

| Condition | QoS Domain Status | Effective Action |
| --- | --- | --- |
| QoS not requested | `not_requested` | `no_op` |
| Neutron QoS extension absent | `degraded` or `unsupported` disposition | `no_op` |
| `tc` missing and shaping requested | `degraded` or `unsupported` disposition | `no_op` or policing only if separately verified |
| Local QoS write while `qos` managed | blocked local write | `LOCAL_WRITE_BLOCKED_FOR_NEUTRON_MANAGED_DOMAIN` |
| Local QoS write while `qos` unmanaged | allowed local write | local authority |

## Required Discovery Commands

Record outputs under `docs/evidence/openstack-n05-lite/` before implementation:

```bash
neutron ext-list | grep -i qos || true
openstack extension list --network | grep -i qos || true
command -v tc || true
tc -V || true
tc qdisc show dev <tap-ifname> || true
ip -d link show <tap-ifname>
```

If commands must run inside containers, record the container name and user. Do
not use root SSH probes as runtime behavior.

## Implementation Guardrails

- Keep QoS behind explicit feature/domain gates.
- Keep ACL/P3 code paths unchanged unless a shared status helper needs a small
  compatibility fix.
- Prefer unsupported/degraded status over a half-working shaping claim.
- Do not add batch optimization, new Neutron APIs, or local policy migration
  until Q0-Q2 are accepted.
- Do not introduce tenant-visible QoS behavior from local `ariactl` alone.

## Acceptance For Starting QoS Development

QoS implementation may start only after:

- Q0 discovery is refreshed on the target hosts;
- the product decision is recorded as one of: `shaping`, `policing-only`, or
  `unsupported/deferred`;
- `managed_domains` authority behavior for `qos` is documented and tested;
- the smoke plan states whether it proves enforcement or clean degradation.

Until then, QoS remains deferred for the 10.58.159 environment.

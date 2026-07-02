# OpenStack eBPF Platform Roadmap

Status: product direction note aligned with the current v0.9 code and field
evidence. This document records the latest architecture positioning after
reviewing the modular eBPF manager proposal against the actual Aria
OpenStack/OVS implementation.

This is not a new stage gate. The normative integration contracts still live in:

1. `openstack-neutron-agent-mode.md`
2. `neutron-managed-domains-contract.md`
3. `aria-acl-neutron-extension-product-design.md`
4. `openstack-deployment-runbook.md`

## Product Positioning

Aria should not be positioned as an OVS replacement.

The product positioning is:

```text
OpenStack/OVS-aware eBPF datapath enhancement platform
```

The first production vertical slice is:

```text
aria_acl Neutron API/DB
  -> neutron-aria-agent
  -> local UDS snapshot
  -> aria-datapath / aria-agent
  -> eBPF ACL enforcement and runtime status
```

Longer term, the same datapath foundation can grow into:

- ACL enforcement and explainability.
- QoS execution through Aria while keeping Neutron QoS semantics.
- Mirror execution through Aria with span-like and policy-selective modes.
- Drop reason, rule hit count, flow counters, and per-port traffic metrics.
- On-demand trace, TCP, syscall, SSL, and diagnostic modules.

The important product message is:

```text
Aria starts with ACL, but the platform foundation is an OpenStack-aware eBPF
manager plus security and observability domains.
```

## Current Runtime Shape

Current component responsibilities:

| Component | Current Role |
| --- | --- |
| `neutron-server` with `aria_acl` plugin | Owns production ACL northbound API, DB, policy/rule/address-set/binding objects, and port status readback. |
| `neutron-aria-agent` | Reads Neutron state, computes effective local desired state, submits host snapshots, reports heartbeat and per-port status. |
| `aria-datapath` / `aria-agent` | Owns local eBPF lifecycle, UDS snapshot apply, WAL, generation/hash convergence, rollback, local write gates, and peer credential hardening. |
| OVS | Continues to own OpenStack L2 switching, bridge topology, tunnel path, and port binding. |
| `ariactl` | Remains local read/debug/admin tooling; writes are blocked only for domains owned by Neutron through `managed_domains`. |

Current product path deliberately keeps `neutron-aria-agent` as a non-privileged
logic agent. It does not own eBPF, does not own OVS lifecycle, and communicates
with the datapath only through the local UDS endpoint.

## Target Program Architecture

The long-term `aria-datapath` program architecture should be described as a
modular eBPF manager. This is a target structure and responsibility model, not
a claim that the current source tree is already fully split into these exact
directories.

```text
aria-datapath
  manager core
    program_manager
    map_manager
    hook_manager
    pipeline_manager
    rollback/WAL
  network modules
    acl
    qos
    mirror
    observability
  system modules
    trace
    tcp
    syscall
    block_io
  api
    policy api
    observability api
    admin api
```

### Manager Core

`manager core` is the only local owner of eBPF lifecycle and host datapath
state.

| Submodule | Responsibility | Current Status |
| --- | --- | --- |
| `program_manager` | Load, attach, replace, detach, pin, and unpin eBPF programs. | Existing datapath already owns attach/detach through local runtime paths; a cleaner named boundary can be introduced later. |
| `map_manager` | Create, pin, version, migrate, clean up, and resize BPF maps. | Existing ACL paths write datapath groups/policies and rely on runtime state; map schema/version ownership should be made explicit before broader observability. |
| `hook_manager` | Own TC/XDP and future kprobe/tracepoint/uprobe/cgroup/LSM hook decisions. | Current OpenStack path is focused on VM tap attach. Future system modules must not reuse network hot-path hooks casually. |
| `pipeline_manager` | Order network modules and standardize verdict flow. | Planned. Today ACL apply is the only Neutron-managed datapath domain; QoS/Mirror must not be inserted until they have gates. |
| `rollback/WAL` | Provide generation, desired hash, intent/commit WAL, replay, and recovery. | Implemented for Neutron snapshot/delete authority and covered by field evidence. |

Manager core rules:

- eBPF programs should stay small and stable.
- Complex policy compilation and rollback belong in userspace.
- Attach/detach must stay single-writer through the local datapath authority.
- A failed module must report status and preserve OVS forwarding unless a later
  product requirement explicitly chooses fail-close.

### Network Modules

Network modules run on packet-facing paths or directly affect packet-facing
state. They must be controlled by feature domains and must report per-domain
runtime status.

| Module | Target Role | Current Status |
| --- | --- | --- |
| `acl` | Enforce Aria ACL policy and report effective action/status. | Current primary product path. Neutron-managed ACL is implemented and field-tested, with translator limits documented in this file. |
| `qos` | Enforce rate/priority behavior while reusing Neutron QoS semantics. | Planned. UDS/domain vocabulary exists, but Neutron-managed Rust apply is not implemented. |
| `mirror` | Provide span-like global mirror and IP-selective mirror. | Planned. Must be a later product domain with separate API/DB/translator/gates. |
| `observability` | Record counters, rule hits, drops, and flow metadata. | Partial only through status/heartbeat. Per-rule/per-port counters and export are future work. |

Recommended future network pipeline:

```text
TC ingress/egress root
  -> packet parse
  -> port context lookup
  -> observability_pre
  -> anti_spoof, if introduced
  -> acl
  -> qos / mirror / service-chain, when productized
  -> observability_result
  -> verdict
```

The standard verdict vocabulary should converge to:

```text
CONTINUE
PASS
DROP
REDIRECT
SKIP
ERROR
```

Each verdict should be able to carry:

```text
domain
feature_id
rule_id
reason
drop_reason
redirect_ifindex
effective_action
```

This vocabulary is a future observability contract. The current ACL stage should
not grow these fields until a concrete reporter, API surface, and smoke gate are
defined.

### System Modules

System modules are diagnostic modules. They should not be inserted into the
network forwarding hot path by default.

| Module | Target Role | Default Product Behavior |
| --- | --- | --- |
| `trace` | Short-lived diagnostic tracing for selected targets. | Default off; enable by operator action only. |
| `tcp` | TCP retransmit/reset/connect latency diagnostics. | Default off or sampled; scoped by host, VM, tenant, or port. |
| `syscall` | Process/syscall observation for troubleshooting. | Default off; not a tenant networking primitive. |
| `block_io` | Block IO latency and storage-path diagnostics. | Default off; belongs to operations/diagnostics, not ACL enforcement. |

System module rules:

- They must be opt-in, time-bounded, or sampled.
- They must support scoping by process, VM, tenant, port, or host where
  possible.
- They must not change network forwarding behavior.
- They must not become Neutron-managed tenant APIs in the v0.9 line.

### API Layers

The local API surface should be split by purpose.

| API Layer | Consumer | Purpose | Current Status |
| --- | --- | --- | --- |
| Policy API | `neutron-aria-agent` and future control-plane adapters | Submit desired datapath state such as ACL/QoS/Mirror. | Current UDS snapshot/delete is the policy API for Neutron-managed attach/ACL. |
| Observability API | Operators, monitoring collectors, and future UI/backend readers | Read counters, drops, flows, rule hits, and diagnostic events. | Planned. Current status/heartbeat is not a full observability API. |
| Admin API | Operators and support tooling | Inspect capabilities, health, attached programs, map state, WAL, rollback, and authority state. | Partially present through capabilities/status and local tooling. |

API rules:

- Policy API mutates datapath state and must be protected by local Unix socket
  permissions and peer credential policy.
- Observability API should be read-oriented and must not change forwarding.
- Admin API can expose rollback and health controls, but destructive operations
  need explicit guardrails.
- Neutron product integration should continue using local UDS, not a remote TCP
  control API.

### Current Code Mapping

The current code already contains several pieces of this architecture, but not
all of them are named as separate modules yet.

| Target Concept | Current Implementation Anchor |
| --- | --- |
| Policy API | Neutron UDS routes: capabilities, status, snapshot, and port delete. |
| Rollback/WAL | Neutron snapshot/delete generation, desired hash, intent/commit WAL, replay, and recovery paths. |
| Domain authority | `managed_domains`, local write gate, and per-domain status. |
| ACL network module | Neutron ACL translator and datapath group/policy reconcile path. |
| Admin status | UDS status, heartbeat payload, and `aria_acl_port_statuses` readback. |
| Observability | Partial heartbeat/status only; rule hit/drop/flow metrics are future work. |
| QoS/Mirror modules | Domain vocabulary and design intent only; not product-ready in Neutron-managed apply. |

Therefore the near-term architecture work should be evolutionary:

1. Keep ACL stable.
2. Make ACL explainability counters first-class.
3. Introduce clearer manager-core/module boundaries only when a second network
   module such as Mirror or QoS is ready to land.
4. Keep system diagnostics separate from Neutron tenant product scope.

## Capability Maturity Matrix

| Capability | Current Product Status | Notes |
| --- | --- | --- |
| Aria ACL | Production vertical slice accepted for stage two; stage three hardening and lifecycle evidence exists. | This is the only Neutron-managed domain with a real end-to-end product path today. |
| ACL transaction and recovery | Implemented and field-tested. | UDS generation, desired hash, WAL, pending snapshot/delete recovery, rollback, tap recreate, migration, OVS restart, and peercred hardening are covered by evidence. |
| ACL observability | Partial. | Heartbeat, domain counts, degraded reasons, and `aria_acl_port_statuses` exist. Rule hit counters, drop reason, port PPS/BPS, and event export are future enhancements. |
| Aria QoS | Planned, not product-enabled. | The preferred model remains: product entry is `aria-qos`; bottom model reuses Neutron QoS semantics; Aria is the execution backend. Current target environment does not expose Neutron QoS, and Rust Neutron snapshot apply does not implement QoS yet. |
| Aria Mirror | Planned for a later phase. | Existing local datapath concepts and earlier mirror analysis are useful, but Neutron-managed `aria-mirror` is not implemented in the current product path. |
| Trace / Drops / TCPrt / SSL | Local or future diagnostic domains, not Neutron tenant product scope. | They must stay available for local read/debug unless explicitly added to `managed_domains` in a later product phase. |
| OpenTelemetry / Prometheus / flow export | Future observability layer. | Do not claim these as delivered by the current ACL stages. Start with bounded ACL counters and per-port metrics first. |

## Current Implementation Boundaries

These boundaries must be reflected in product and design material.

1. OVS remains the OpenStack networking datapath owner for L2 switching,
   bridges, tunnel forwarding, and Neutron binding.

2. `binding:vif_type` remains `ovs`. It must not be changed to `aria`,
   `ebpf`, or another Aria-specific value.

3. Production ACL input is `aria_acl` Neutron API/DB, not Neutron Security
   Group and not local tags.

4. `managed_domains` is a per-port feature authority list. It controls local
   write blocking for Neutron-owned domains, not whether every advertised UDS
   domain is product-ready.

5. Python `neutron-aria-agent` currently validates `acl`, `qos`, and `mirror`
   as managed domain names. Rust datapath Neutron apply currently implements
   `attach` and `acl`; other managed domains are blocked as unimplemented if
   submitted as Neutron-owned domains.

6. UDS capabilities may include broader domain vocabulary for local control
   plane compatibility. That vocabulary is not a product readiness claim.

7. Current Neutron ACL translation is intentionally minimal:

   | ACL Semantics | Current State |
   | --- | --- |
   | IPv4 CIDR match | Supported. |
   | IPv6 match | Not supported by the current Neutron ACL translator. |
   | Destination TCP/UDP port/range | Supported through current translator constraints. |
   | Source port match | Not supported by the current translator. |
   | `default_action=allow` | Supported. |
   | `default_action=deny` | Not productized in the current minimal translator. |
   | Multiple effective policies per port | Not supported; port binding wins over network binding. |

8. Failure behavior remains fail-open for forwarding safety: ACL degraded or
   not requested means `effective_action=bypass`, and OVS L2 forwarding must not
   be broken by Aria.

## Architecture Principles To Keep

The modular eBPF proposal is valid as a target architecture, but it should be
applied incrementally.

Keep these principles:

- Make `aria-datapath` the single local eBPF lifecycle owner.
- Keep eBPF programs small and stable; put orchestration, rollback, and policy
  compilation in userspace.
- Use feature domains (`acl`, `qos`, `mirror`, `drops`, `trace`, and future
  domains) as authority and status boundaries.
- Keep network datapath modules separate from system observability modules.
- Treat metrics/events/exporters as a separate output layer, not as core packet
  forwarding logic.
- Add new public fields only when they have an owner, validation path, status
  reporter, smoke gate, and rollback behavior.

Avoid these in the v0.9 line:

- Do not redesign Aria into a broad eBPF platform before ACL remains stable in
  production operations.
- Do not add QoS/Mirror/Trace into Neutron product scope just because the UDS
  vocabulary can name those domains.
- Do not make a single large TC program that mixes ACL, QoS, mirror, tracing,
  syscall, and IO diagnostics.
- Do not let observability features change forwarding behavior by default.

## Recommended Roadmap

### Phase A: ACL Production Hardening

Status: current mainline.

Goals:

- Keep ACL production path stable.
- Keep stage-two and stage-three gates reproducible.
- Preserve OVS forwarding during all degraded states.
- Maintain UDS peer credential hardening.
- Finish release governance and CI artifact discipline.

### Phase B: ACL Explainability

This should be the next product enhancement after ACL hardening.

Deliver:

- Per-rule hit count.
- Per-rule drop count.
- Per-port allow/drop counters.
- Drop reason vocabulary.
- Runtime status that separates `DomainStatus`, `effective_action`, and support
  disposition.
- CLI/API view for "why is this VM traffic blocked or bypassed?"

This phase gives immediate product value without expanding into QoS or Mirror.

### Phase C: Aria Mirror

Deliver after ACL explainability.

Target semantics:

- `global` means L2 span-like mirror for the source port/interface.
- `policy` means IP-selective mirror.
- `global + policy` can coexist.
- Non-IP traffic belongs to `global`, not policy-selective mirror.
- Optional routing by IP prefix to different target VM ports belongs to
  `aria-mirror` product design, not the current ACL stage.

### Phase D: Aria QoS

Deliver after the target OpenStack QoS control-plane and host runtime questions
are stable.

Target semantics:

- Product entry: `aria-qos`.
- Bottom model: reuse Neutron QoS policy/rule semantics where possible.
- Execution backend: Aria datapath.
- Do not enable or claim host shaping until the runtime dependency and datapath
  behavior are verified.

### Phase E: Broader Observability And Diagnostics

Deliver as opt-in operational modules.

Possible modules:

- Flow counters.
- TCP retransmit/reset visibility.
- Trace and drop diagnostics.
- Process/syscall/IO diagnostics.
- Prometheus/OpenTelemetry/event exporters.

These must be default-off or bounded, and they must not enter the network
forwarding hot path unless explicitly required.

## Documentation Changes Implied By This Roadmap

The following existing docs should stay aligned with this note:

| Document | Required Alignment |
| --- | --- |
| `openstack-neutron-aria-design-decisions.md` | Link this roadmap and keep v0.9 anti-overengineering rules. |
| `neutron-managed-domains-contract.md` | Distinguish UDS domain vocabulary from product-ready Neutron-managed domains. |
| `aria-acl-neutron-extension-product-design.md` | Add the current ACL translator limits if not already visible near the API semantics. |
| `openstack-deployment-runbook.md` | Keep enablement focused on ACL until QoS/Mirror have their own gates. |

## One-Line Summary

Aria should be recorded as an OpenStack-aware eBPF datapath enhancement platform,
but the current product commitment is ACL first: Neutron `aria_acl` input,
`neutron-aria-agent` snapshot sync, `aria-datapath` UDS/WAL apply, runtime status,
and safe rollback. QoS, Mirror, and broader observability remain staged domain
expansions, not current ACL-stage commitments.

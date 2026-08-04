# XDP Storm And DDoS Product Integration Design

Date: 2026-08-04

Status: approved design; implementation pending

Analyzed target: `v0.9-neutron-agent@38e27e7`

## 1. Decision

Aria will use one `xdp_firewall` entry program with two internally isolated
protection domains:

```text
XDP ingress
  -> read one immutable interface configuration snapshot
  -> bounded Ethernet, VLAN, and QinQ parsing
  -> storm_guard
  -> bounded IPv4, IPv6, and required L4 parsing
  -> ddos_guard when enabled for a physical interface
  -> XDP_PASS
  -> existing TC ACL, conntrack, QoS, mirror, and observability domains
```

The shared XDP foundation owns attachment, exact live identity validation,
parsing primitives, generation publication, rate-policy ABI, and bounded
observability conventions. Storm and DDoS do not share policy maps, runtime
maps, statistics maps, desired state, policy generations, readiness, degraded
reasons, or mitigation state.

The implementation is delivered in stages, but the shared foundation and both
domain contracts are designed together. This avoids a second XDP lifecycle
without creating one monolithic protection feature.

## 2. Relationship To Existing Design

This specification supersedes the product and control-plane portions of
[`2026-07-19-xdp-storm-ddos-guard-design.md`](2026-07-19-xdp-storm-ddos-guard-design.md).
It adds the previously missing Neutron tap resources, Legacy `neutron` CLI,
`neutron port-show` projection, explicit node API contracts, status semantics,
security boundaries, and staged release gates.

The older document remains authoritative for low-level ABI layouts, bounded
parser rules, overflow-safe integer refill, spin-lock constraints, map key byte
order, generation-scoped LPM rules, and verifier/performance test mechanics
unless this specification explicitly says otherwise.

The exact pinned XDP link identity work present at the analyzed target is a
foundation, not evidence that storm or DDoS is implemented. At this target
there are no storm or DDoS policies, maps, APIs, metrics, or enforcement code.

## 3. First Product Milestone

The first milestone provides:

- VM tap ingress storm suppression for VM-originated broadcast and multicast;
- physical-interface ingress storm suppression;
- physical-interface ingress DDoS protection;
- independent disabled, observe, and police behavior for storm and DDoS;
- Neutron desired state and runtime projection for tap storm;
- node-local desired state and status for physical storm and DDoS;
- packet-rate and byte-rate limits with explicit bursts;
- observe-first promotion and field-verifiable readiness.

The first milestone does not provide:

- tap DDoS enforcement;
- physical-interface or tap egress policing;
- shared ingress/egress accounting;
- shared limits across bond members;
- unknown-unicast storm classification;
- adaptive threshold learning or autonomous mitigation;
- AF_XDP scrubbing, BGP FlowSpec, RTBH, or switch integration;
- service CIDR or arbitrary service port-range matching;
- cross-node aggregation or attack coordination.

The supported matrix is:

| Target and direction | Storm | DDoS |
| --- | --- | --- |
| VM tap ingress, VM to host/OVS | yes | no |
| Physical-interface ingress | yes | yes |
| VM tap or physical egress | no | no |

## 4. Control-Plane Ownership

VM tap storm desired state belongs to Neutron. It follows a Neutron port UUID
across tap recreation and migration. The authoritative objects are policy,
class, and binding rows in Neutron DB. Runtime status is reported by the agent
and never becomes desired-state authority.

Physical interfaces are node resources. `NodeGuardManager` owns only interfaces
listed explicitly in node configuration. A physical interface is never
represented as a synthetic Neutron port, and physical storm or DDoS status is
never projected into `neutron port-show`.

The control surfaces are:

```text
Legacy neutron CLI and Neutron REST
  -> VM tap storm desired state and status

ariactl and the protected node management API
  -> physical-interface selection, storm, DDoS, mitigation, and status
```

ACL remains a TC domain. Storm or DDoS state cannot make ACL ready or unready,
and XDP never becomes an ACL or conntrack authority.

## 5. Neutron Storm Resources

The Neutron extension alias is `aria-storm`. Its REST collections are:

```text
/v2.0/aria-storm-policies
/v2.0/aria-storm-classes
/v2.0/aria-storm-bindings
/v2.0/aria-storm-port-statuses
```

The extension follows the existing Aria ACL conventions for project ownership,
pagination, field selection, timestamps, revision numbers, service-plugin
registration, REST error mapping, RPC notification, and Legacy `neutron` CLI
discovery.

### 5.1 Storm policy

`aria_storm_policy` contains:

| Field | Type | Contract |
| --- | --- | --- |
| `id` | UUID | server generated |
| `project_id` | string | owning project |
| `name` | string | operator-readable name |
| `description` | string | optional description |
| `enabled` | bool | default `true`; global policy switch |
| `mode` | enum | `observe` or `police`; default `observe` |
| `revision_number` | integer | monotonically updated Neutron revision |
| `created_at`, `updated_at` | datetime | server timestamps |

`disabled` is not a policy mode. `enabled=false` disables a policy; `mode`
describes the behavior when the selected policy is enabled. This prevents two
conflicting disable mechanisms.

### 5.2 Storm class

`aria_storm_class` contains:

| Field | Type | Contract |
| --- | --- | --- |
| `id` | UUID | server generated |
| `project_id` | string | must match the policy project |
| `policy_id` | UUID | owning storm policy |
| `traffic_class` | enum | one of the five fixed classes |
| `pps_limit` | u64 | packets per second; zero only with zero packet burst |
| `burst_packets` | u64 | packet-token capacity |
| `bytes_per_second` | u64 | bytes per second; zero only with zero byte burst |
| `burst_bytes` | u64 | byte-token capacity |
| `enabled` | bool | default `true` |
| `revision_number` | integer | Neutron revision |

The fixed classes are:

```text
broadcast
ipv4_multicast
ipv6_multicast
other_multicast
link_local_control
```

There is at most one row for a `(policy_id, traffic_class)` pair. Each enabled
class enables at least one of packet rate or byte rate. A limit and its burst
are both zero or both positive. API and CLI names spell out bytes; the ambiguous
term `bps` is not used.

An enabled binding requires enabled `broadcast` and `link_local_control` rows.
Deleting or disabling either required row is rejected while an enabled binding
references the policy. Other multicast classes are optional and classes absent
from the effective class mask intentionally pass.

### 5.3 Storm binding

`aria_storm_binding` contains:

| Field | Type | Contract |
| --- | --- | --- |
| `id` | UUID | server generated |
| `project_id` | string | binding owner |
| `policy_id` | UUID | selected storm policy |
| `target_type` | enum | `port` or `network` |
| `target_id` | UUID | Neutron port or network ID |
| `enabled` | bool | default `true` |
| `revision_number` | integer | Neutron revision |
| `created_at`, `updated_at` | datetime | server timestamps |

The server verifies target existence, project compatibility, policy validity,
and authorization. A target has at most one binding row; updates replace its
policy or enabled state. This stronger invariant avoids multiple disabled rows
becoming ambiguous after later enablement.

An explicit port binding always overrides a network binding, including when the
port binding or its policy is disabled. This makes
`binding-update --enabled false` a real per-port opt-out from a network policy.
Without an explicit port binding, the enabled network binding is considered.

The effective-source values are `port`, `network`, `none`, and `unknown`.
An explicit disabled port override reports source `port`, enabled `false`, and
reason `port_binding_disabled`; it does not silently fall back to the network.

### 5.4 Legacy neutron CLI

The command family is:

```text
neutron aria-storm-policy-create|delete|list|show|update
neutron aria-storm-class-create|delete|list|show|update
neutron aria-storm-binding-create|delete|list|show|update
neutron aria-storm-port-status-list|show
```

Examples:

```bash
neutron aria-storm-policy-create \
  --name vm-storm-default \
  --mode observe

neutron aria-storm-class-create \
  --policy <policy-id> \
  --traffic-class broadcast \
  --pps-limit 2000 \
  --burst-packets 500 \
  --bytes-per-second 10485760 \
  --burst-bytes 1048576

neutron aria-storm-class-create \
  --policy <policy-id> \
  --traffic-class link_local_control \
  --pps-limit 500 \
  --burst-packets 200

neutron aria-storm-binding-create \
  --policy <policy-id> \
  --network <network-id>

neutron aria-storm-binding-create \
  --policy <special-policy-id> \
  --port <port-id>
```

`--port` and `--network` are mutually exclusive and exactly one is required.
Creating or updating a binding is the configuration action; `port-show` remains
read-only.

### 5.5 Police admission

The Neutron service plugin uses an `[aria_storm] allow_police=false` deployment
gate for new `mode=police` requests. It is disabled by default. A compute also
verifies its local attach and kernel capabilities before enforcing police. The
admission gate prevents accidental promotion; runtime capability validation
prevents false readiness on a host that cannot enforce the accepted desired
state.

## 6. Neutron Port Projection And Runtime Status

The `aria-storm` extension adds these visible, read-only port attributes:

```text
aria_storm_enabled
aria_storm_effective_policy_id
aria_storm_effective_policy_name
aria_storm_effective_source
aria_storm_binding_id
aria_storm_effective_revision
aria_storm_requested_mode
aria_storm_runtime_mode
aria_storm_runtime_status
aria_storm_runtime_host
aria_storm_runtime_reason
```

Every field has `allow_post=false`, `allow_put=false`, and `is_visible=true`.
Core `port-show` remains available if storm projection fails. Projection
failure returns a complete unknown state, including `aria_storm_enabled=null`,
instead of falsely reporting that protection is disabled.

`aria_storm_runtime_status` uses the same lifecycle vocabulary as ACL:

```text
not_requested
pending
applied
degraded
unsupported
unknown
```

Storm mode is represented separately:

```text
requested_mode = observe | police | none | unknown
runtime_mode   = disabled | observe | police | unknown
```

Only an exact current identity can project `applied`. The runtime row must match
the current `binding:host_id`, policy ID, binding ID, effective revision or
desired hash, tap ifindex, interface generation, live XDP program/link identity,
and requested mode. A migrated port never reuses a ready row from its old host.

Stable projection reasons include:

```text
no_enabled_binding
port_binding_disabled
port_unbound
status_not_reported
status_stale
status_projection_mismatch
requested_mode_not_applied
xdp_program_not_attached
projection_unavailable
```

The agent reports `aria_storm_port_status` rows containing at least:

```text
port_id, host, interface_name, ifindex, interface_generation
effective_policy_id, binding_id, effective_revision, desired_hash
requested_mode, runtime_mode, runtime_status, storm_ready
xdp_program_id, xdp_link_id, attach_mode, reason, reported_at
```

The read path projects all requested ports from one desired-state snapshot and
one status query filtered to that page. It does not issue per-port policy or
status queries. Pagination, sorting, markers, and final field selection remain
the core plugin's responsibility.

Agent status is reported every 30 seconds and immediately on state transition.
A row older than 90 seconds projects `unknown/status_stale`. Deleted ports,
old-host rows, deleted bindings, and unreachable old-generation rows are cleaned
asynchronously, but cleanup delay never makes an old row applicable.

Status may carry one bounded statistics object for the five fixed classes:

```text
pass_packets, pass_bytes
would_drop_packets, would_drop_bytes
dropped_packets, dropped_bytes
```

No source MAC, port UUID, or arbitrary identifier becomes a Prometheus label.

## 7. Physical-Interface Control Plane

Node configuration defines the allowlist and enforcement gates:

```toml
[xdp_protection]
physical_interfaces = ["eth1", "ens5f0"]
allow_generic_fallback = false
storm_police_enabled = false
ddos_police_enabled = false
```

The agent does not infer OVS uplinks or attach to unlisted interfaces. Generic
fallback is explicit rather than silent.

The node API is:

```text
GET    /api/v1/xdp-protection/status
GET    /api/v1/xdp-protection/interfaces
GET    /api/v1/xdp-protection/interfaces/{iface}
PUT    /api/v1/xdp-protection/interfaces/{iface}
DELETE /api/v1/xdp-protection/interfaces/{iface}
GET    /api/v1/xdp-protection/interfaces/{iface}/storm
PUT    /api/v1/xdp-protection/interfaces/{iface}/storm
GET    /api/v1/xdp-protection/interfaces/{iface}/ddos
PUT    /api/v1/xdp-protection/interfaces/{iface}/ddos
GET    /api/v1/xdp-protection/interfaces/{iface}/stats
```

Clients percent-encode every dynamic interface path segment. Interface
registration includes `enabled`, profile `physical_edge`, requested attach
mode, explicit fallback permission, and expected permanent MAC. The manager
validates current ifindex, MAC, program ID, link ID, attach mode, and generation.
A pin-shaped path alone is never readiness evidence.

`enabled=false` preserves configuration while removing active protection.
`DELETE` records durable removal intent, disables both domains, detaches the
shared hook after verification, and asynchronously cleans unreachable state.

The status response contains common identity plus independent domains:

```text
interface_name, expected_mac, current_mac, ifindex, interface_generation
profile, requested_attach_mode, effective_attach_mode, allow_generic_fallback
xdp_program_id, xdp_link_id, xdp_hook_ready

storm_requested_mode, storm_runtime_mode, storm_policy_generation
storm_ready, storm_reason

ddos_requested_mode, ddos_runtime_mode, ddos_policy_generation
ddos_ready, ddos_reason

revision, desired_hash
last_reconcile_at, last_successful_reconcile_at
```

The corresponding CLI family is:

```text
ariactl xdp-protection interface list|show|enable|disable
ariactl xdp-protection storm show|set
ariactl xdp-protection ddos show|set
ariactl xdp-protection mitigation list|create|delete
ariactl xdp-protection stats show
```

## 8. Storm Datapath

### 8.1 Classification

The parser supports untagged Ethernet, one 802.1Q or 802.1ad tag, and two tags
for QinQ. Truncated frames and deeper unsupported encapsulation pass safely,
increment bounded error evidence, and degrade a requested domain rather than
claim readiness.

Classification order is:

1. explicitly recognized `link_local_control`;
2. Ethernet broadcast;
3. IPv4 multicast MAC;
4. IPv6 multicast MAC;
5. other MACs with the multicast bit set;
6. non-storm traffic.

Link-local control includes bounded recognition of ARP, broadcast DHCP, IPv6
ND, and standard link-control protocols. It receives a distinct allowance, not
an unlimited bypass. Vendor-specific protocols require an explicit future
contract. Unknown unicast is not classified because packet-local XDP state
cannot determine bridge or OVS FDB membership.

### 8.2 Policer

Each `(interface generation, storm policy generation, ifindex, class)` has one
dual-dimension bucket. A packet passes only when every enabled dimension has
sufficient packet and byte credit. Packet cost is one; byte cost is the XDP
visible frame length including Ethernet and VLAN headers and excluding FCS.

Refill uses `bpf_ktime_get_ns()` and retains fractional remainder. Arithmetic is
overflow-safe and uses bounded `u64` decomposition rather than `u128` lowering.
When either dimension is short, neither dimension is debited, while completed
refill state is retained.

The enforcement bucket is not duplicated at full rate per CPU. The first
implementation uses one kernel-synchronized bucket per interface/class after an
exact target-kernel capability probe. Lock scope contains only refill, decision,
and debit; no helper call, parser access, or second lock acquisition occurs
while held. Per-CPU maps are used for statistics only.

Observe performs the same token transition and decision as police, records
`would_drop`, and returns pass. An observe/police-only mode change preserves
generation and token state. Rate, burst, class, or exception changes create a
new policy generation initialized to full burst.

## 9. DDoS Policy And Datapath

DDoS runs only on a physical-interface profile and only for IP traffic that
was not already dropped by storm. The four layers execute in this order:

```text
temporary CIDR mitigation
interface aggregate and protocol limits
exact protected-service limits
bounded per-source limits
```

The first rejecting layer is the final reason. Earlier reached rate buckets keep
their offered-load accounting; a later rejection does not roll back earlier
debits. Observe records the first would-drop decision and passes the packet.

### 9.1 Main DDoS document

`GET` and `PUT /api/v1/xdp-protection/interfaces/{iface}/ddos` operate on one
atomic main document:

```json
{
  "enabled": true,
  "mode": "observe",
  "expected_revision": 11,
  "interface_limits": [],
  "service_limits": [],
  "source_limits": []
}
```

Interface classes are `total`, `tcp`, `tcp_syn`, `udp`, `icmp`, `fragment`, and
`other`. `total` is mandatory whenever DDoS is enabled and cannot be bypassed by
trusted service/source handling. Each class uses the same explicit packet and
byte rate structure as storm. A class occurs at most once. Fragment classification
takes precedence over the TCP-SYN modifier.

Protected service policies support one exact IPv4 or IPv6 destination address,
protocol, and, for TCP/UDP, one exact destination port. ICMP, ICMPv6, and other
protocol selectors do not overload port zero as a wildcard. An absent service
policy skips the service layer without degraded state.

Per-source policy is configured by address family and protocol. Runtime state
uses capacity-limited LRU maps and is a secondary control only. Insert failure
or churn cannot disable interface or service protection. New source-layer
activation is rejected unless the maintained target kernel proves the exact
LRU-value synchronization path. Capacity is an agent startup parameter; changing
it requires a controlled domain-map rebuild. If durable desired state already
requests the source layer after a capability later becomes unavailable, the
source layer reports degraded while valid interface and service layers continue;
the agent does not substitute an unsynchronized implementation.

### 9.2 Temporary mitigation

Mitigation is changed independently from the main document:

```text
GET    /api/v1/xdp-protection/interfaces/{iface}/ddos/mitigations
POST   /api/v1/xdp-protection/interfaces/{iface}/ddos/mitigations
DELETE /api/v1/xdp-protection/interfaces/{iface}/ddos/mitigations/{id}
```

Each rule contains CIDR, action, UTC expiry, stable reason, and source ID. Valid
actions are `drop` and `trust_service_source`. Trust may bypass service and
source layers but never the interface total ceiling. Rules are temporary: they
require a future expiry and have a default maximum TTL of 24 hours.

IPv4 and IPv6 use separate bounded generation-scoped LPM maps. Kernel monotonic
time ends enforcement at the exact effective expiry. Agent cleanup delay affects
occupancy only. Durable state stores UTC expiry and recomputes remaining lifetime
after restart; a boot-relative timestamp is never persisted as authority.

## 10. Shared XDP Publication And Isolation

The XDP interface configuration contains interface generation, independent
storm and DDoS generations, profile, independent modes, and independent class
masks. The program performs one lookup and copies one immutable snapshot before
consulting either domain.

For a domain update the manager:

1. validates the complete request and capacity;
2. persists desired state and a pending transaction;
3. allocates a nonzero new domain generation when policy content changes;
4. writes all required policy and fixed runtime entries under that generation;
5. reads back and validates content, layout, padding, and byte order;
6. commits the new generation with the final interface-config write;
7. validates live program, link, interface, attach mode, and effective mode;
8. publishes status and clears the pending transaction;
9. removes unreachable old-generation state asynchronously.

Packets see the complete old or complete new tuple, never a mixed generation.
Updating storm preserves DDoS generation and runtime; updating DDoS preserves
storm generation and runtime.

Missing requested state fails open for packet availability, increments bounded
configuration evidence, and marks only the affected domain degraded. A shared
hook failure can degrade both requested domains but does not authorize cleanup
of TC ACL/CT state.

## 11. Desired State, Disable, And Recovery

Neutron DB is authoritative for tap storm. Node-local durable state is
authoritative for physical interface selection, physical storm, DDoS, mitigation,
desired hashes, domain generations, and the next interface-generation counter.
Pinned maps and token balances are runtime state rather than desired authority.

Disable and delete use a durable pending-disable record before touching the
datapath. Reconciliation prioritizes that record after a crash, disables the
domain, reads back that it cannot continue dropping, commits disabled desired
state, and then cleans old maps. An old police generation cannot be silently
re-enabled because the agent crashed halfway through a disable request.

If a replacement generation fails before commit, the complete old generation
continues running, while status reports `degraded/desired_runtime_mismatch`.
Neutron desired-state acceptance never implies runtime application.

On a process restart during the same boot, token state is preserved only when
boot identity, interface identity, ifindex, interface generation, policy
generation, desired hash, program ID, link ID, and map schema all match. On host
reboot, the agent rebuilds maps and runtime from authority before publishing
ready. Stale pinned state is not trusted merely because its path exists.

A tap runtime identity is `(port_id, host, ifindex, interface_generation)`.
Migration or recreation allocates a new interface generation. Source-node status,
old ifindices, and same-name taps cannot donate policy, tokens, or readiness to
the new instance.

Reconciliation is triggered at startup, desired-state change, netlink/interface
event, and a bounded periodic interval. It is idempotent and does not reset token
state for an already matching generation.

## 12. API Security And Error Contract

Neutron storm writes are admin-only in the first release. Server-side checks
enforce project compatibility and target ownership. Tenant self-service requires
a later explicit policy review.

Node management defaults to UDS or loopback. Binding a non-loopback address
without configured authentication is a startup error. Write endpoints, police
gates, and mitigation operations cannot be exposed unauthenticated.

Neutron uses `revision_number`; node documents return `revision` and
`desired_hash`, and updates carry `expected_revision`. A stale update returns
`409 Conflict` rather than overwriting a concurrent administrator.

HTTP results mean:

| Result | Meaning |
| --- | --- |
| `200 OK` | persisted and exact datapath read-back succeeded |
| `202 Accepted` | desired state persisted; runtime remains pending |
| `400 Bad Request` | malformed field, unit, or request |
| `403 Forbidden` | authorization or police-gate rejection |
| `404 Not Found` | target, policy, or interface absent |
| `409 Conflict` | revision, binding, or interface identity conflict |
| `422 Unprocessable Entity` | unsupported kernel, attach mode, or policy combination |
| `503 Service Unavailable` | required durable/control service unavailable |

A `202` response includes stable pending reason, revision, and desired hash. An
invalid request is rejected before persistence. Accepted but unapplied desired
state is never returned as generic success.

All collections and strings are bounded before map publication. The five storm
classes and seven interface DDoS classes are fixed. Service, source-policy, and
mitigation counts cannot exceed configured map capacity.

## 13. Observability

Statistics distinguish `pass`, `would_drop`, `drop`, and `error_pass`, and
attribute the first terminal result to storm, DDoS interface, DDoS service,
DDoS source, or DDoS mitigation. XDP drops are not counted as TC ACL, QoS, or
conntrack drops.

Required metric families cover:

- XDP hook readiness, attach failures, parser errors, and reconcile failures;
- storm packets/bytes, effective mode, class, verdict, reason, and generation;
- DDoS packets/bytes, layer, class, verdict, reason, and generation;
- source-map insertion attempts/failures, capacity, occupancy, and high-water;
- mitigation count and expiry cleanup;
- rate-limited operational-event suppression.

Labels are bounded to domain, profile, traffic class, layer, verdict, reason,
and attach mode. A physical interface name may be a node-level label. Source or
destination IP, MAC, Neutron port UUID, and arbitrary service ID are not default
Prometheus labels.

Events are emitted on mode, readiness, link identity, capacity threshold,
mitigation, and repeated reconciliation state transitions. There are no
per-packet logs, and repeated events are rate limited with a suppression counter.

## 14. Code Ownership

Implementation follows existing workspace boundaries:

```text
abi/
  shared XDP constants and explicit key/value ABI contracts

ebpf/
  bounded parser, storm_guard, ddos_guard, and entry orchestration

core/
  attach identity, map adapters, generation publication, runtime/stat reads

agent/
  NodeGuardManager, tap storm coordinator, durability, reconcile, node API

openstack/neutron_aria/
  storm DB, migration, REST resources, binding resolution, status, projection

openstack/neutronclient_aria/
  Legacy neutron aria-storm commands

user/
  ariactl xdp-protection commands
```

Storm and DDoS remain separate modules. Shared helpers are limited to genuinely
common interface, parser, rate, publication, and observability contracts. The
work does not add more unrelated responsibilities to `neutron_api.rs` or the
existing ACL service plugin.

## 15. Delivery Batches

### Batch 1: Contracts and shared XDP foundation

- Neutron storm schema, migration, service extension, and CLI contract;
- node xdp-protection API types and route contract;
- XDP/TC map inventory and readiness isolation;
- exact live program/link/interface validation;
- bounded Ethernet, VLAN, and QinQ parsing;
- interface and independent domain generations;
- disabled and observe infrastructure;
- all police admission gates remain disabled.

### Batch 2: Tap and physical storm observe

- five storm classes and dual packet/byte policer;
- tap and physical policy publication;
- Neutron port runtime status and read-only projection;
- bounded statistics, metrics, and events;
- target environment runs observe only.

### Batch 3: Storm police

- exact target-kernel synchronization/verifier capability proof;
- one-CPU, multi-CPU, and hot-class benchmarks;
- one-tap and one-physical-interface canaries;
- explicit per-environment police-gate promotion;
- network-binding police only after port canaries.

### Batch 4: Physical DDoS base

- mandatory total and fixed protocol/modifier classes;
- exact IPv4/IPv6 protected services;
- independent DDoS generation, readiness, status, and statistics;
- observe evidence before base police promotion.

### Batch 5: DDoS source and mitigation

- bounded source policy and LRU runtime;
- target-kernel capability and memory-budget proof;
- expiring IPv4/IPv6 mitigation and recovery;
- capacity/churn, expiry, restart, and operator CLI validation.

Every batch is independently committed, run through hosted CI, and tested in
the real environment before the next enforcement promotion. Development does
not wait until all batches are complete before the first datapath test.

## 16. Verification And Acceptance

Local Cargo build, check, and test remain prohibited. GitHub Actions is the
Rust/eBPF compilation and test authority. Permitted local static and Python
checks do not substitute for hosted compilation or privileged field evidence.

### 16.1 Hosted and non-privileged checks

- ABI size, offset, padding, enum, and byte-order tests;
- untagged, VLAN, QinQ, truncation, and unsupported-depth parser tests;
- all five storm and seven interface DDoS classes;
- token refill, remainder, burst, saturation, and backwards-time behavior;
- observe/police transitions and generation reset behavior;
- immutable interface snapshot and independent domain generation tests;
- fail-open/degraded behavior for missing requested state;
- node API revision, validation, authorization, and error contracts;
- Neutron DB migration, uniqueness, project, and binding-precedence tests;
- Legacy CLI argument/body/URL encoding tests;
- `port-show` exact-host/identity/status projection tests;
- paginated batch projection proving no per-port N+1 queries;
- pending-disable, restart, old-generation, and mitigation-expiry tests;
- static guard proving XDP does not read ACL/CT maps.

### 16.2 Privileged target-environment checks

- real tap ingress and physical-interface native XDP attachment;
- explicitly approved generic fallback when advertised;
- detached-but-pinned links report not ready;
- tap deletion, recreation, and VM migration;
- agent process restart and host reboot;
- ARP, DHCP, IPv6 ND, broadcast, and multicast below and above limits;
- independent packet and byte threshold activation;
- SYN, UDP, ICMP, fragment, and aggregate floods;
- exact service limits and offered-load accounting;
- source state below, at, and above capacity;
- mitigation match, exact expiry, agent restart, and host-reboot replay;
- negative and positive kernel capability probes;
- XDP load, map, and attach failures while TC ACL/CT/QoS stays healthy;
- one domain failure while the other remains ready;
- ifindex reuse, old generation, and mixed-generation exclusion.

### 16.3 Correctness gates

- normal traffic below limits has no unexplained drop;
- steady-state rate is within plus or minus 5 percent of configuration, or one
  packet per measurement interval, whichever tolerance is larger;
- observe mode produces zero enforced drops;
- police drop counters match the first terminal XDP reason;
- stale or mismatched desired/runtime identity never projects `applied`;
- old host, ifindex, generation, or policy counters never enter current status.

### 16.4 Performance gates

On the same host, NIC, queue count, affinity, frame size, and generator:

| Mode | Minimum retained XDP baseline |
| --- | ---: |
| protection disabled fast path | 95% |
| one domain observe | 90% |
| storm and DDoS both observe | 85% |
| one domain police | 80% |
| storm and DDoS both police | 75% |

Results record kernel build, NIC/driver/firmware, native or generic attach,
CPU/IRQ affinity, RX queues, frame-size/FCS convention, map capacity, locked
memory, actual PPS, packet loss, and CPU utilization. GitHub veth tests are
functional evidence, not physical line-rate evidence.

### 16.5 Field promotion

The promotion sequence is:

1. one tap in observe for at least 24 hours;
2. one physical interface with storm and DDoS observe for at least 24 hours;
3. controlled storm police load;
4. controlled DDoS police load;
5. one-port storm canary;
6. limited network binding;
7. selected physical-interface enablement;
8. at least 72 hours of mixed-traffic soak before production assessment.

An unexecuted field step is `pending/deferred`, never passed. Code merges with
storm and DDoS police gates disabled until the environment-specific evidence is
recorded.

## 17. Required Invariants

Implementation is acceptable only while all invariants hold:

1. One XDP entry may host two domains, but their policy/runtime/status remains isolated.
2. Tap ingress supports storm; tap DDoS remains disabled in the first milestone.
3. Physical ingress supports independently selectable storm and DDoS.
4. XDP never becomes ACL or conntrack authority.
5. `TapConfig` remains eight bytes.
6. A physical interface is never represented as a synthetic Neutron tap.
7. Storm failure cannot make DDoS unready, and DDoS failure cannot make storm unready.
8. Neither XDP domain can make healthy TC ACL/CT unavailable.
9. Readiness requires exact live link, program, interface, mode, and generation identity.
10. Missing requested state is explicit degraded fail-open, never false ready.
11. Token refill is kernel-side and independent of agent scheduling.
12. No per-CPU full-rate bucket multiplies an interface limit.
13. Per-source state is bounded and is never the only volumetric defense.
14. Unknown unicast, egress, shared bond limits, and shared bidirectional limits are not advertised.
15. Policy transitions publish one immutable complete generation.
16. Disabled port binding is an explicit override, not an implicit network fallback.
17. `port-show` distinguishes desired enablement from actual runtime application.
18. Unauthenticated remote write access to protection configuration is forbidden.
19. Unexecuted field verification remains pending/deferred.

## 18. Completion Definition

The product milestone is complete only when all five delivery batches have
hosted CI evidence, the relevant privileged target-environment checks have been
executed, `neutron port-show` and node status expose desired/runtime mismatches,
police mode has passed canary and performance gates, and the 72-hour soak has no
unexplained protection-domain or TC regression.

Before those conditions, source delivery, CI, functional field evidence,
performance evidence, soak evidence, and production readiness are reported as
separate states rather than one headline completion claim.

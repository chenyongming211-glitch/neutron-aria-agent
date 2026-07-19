# XDP Storm Guard And Physical-Ingress DDoS Guard Design

Date: 2026-07-19

Status: recorded design baseline; implementation not yet approved

Analyzed target: `origin/v0.9-neutron-agent@96ee460`

## 1. Executive Decision

Aria will use one `xdp_firewall` entry program with two internally isolated protection domains:

```text
XDP ingress
  -> L2 and VLAN parsing
  -> storm_guard
  -> IPv4/IPv6 and L4 parsing when DDoS is enabled
  -> ddos_guard
  -> XDP_PASS
  -> existing TC ingress ACL/CT/QoS/Mirror/TCP-RT
```

The first product milestone protects:

- OpenStack tap ingress against VM-originated broadcast and multicast storms;
- physical-interface ingress against broadcast and multicast storms;
- physical-interface ingress against basic volumetric L3/L4 DDoS attacks.

Physical-interface egress, bidirectional shared limits, bond-member shared limits, unknown-unicast storm control, automatic adaptive blocking, AF_XDP scrubbing, BGP blackhole, and multi-node attack coordination are outside the first milestone.

Storm and DDoS share the XDP entry, parsing primitives, attachment infrastructure, and low-level observability conventions. They do not share policy maps, runtime maps, verdict reasons, desired state, readiness, or mitigation state.

## 2. Current Product Boundary

The current code already provides a suitable insertion point:

- `xdp_firewall` exists and currently returns `XDP_PASS` after minimal IP parsing;
- XDP is ACL/CT-neutral;
- TC ingress and TC egress are the only ACL/conntrack enforcement hooks;
- pinned programs, maps, links, runtime metadata, restart recovery, and per-interface lifecycle already exist;
- existing QoS provides an integer token-bucket implementation pattern;
- per-CPU statistics and drop-reason patterns already exist.

These foundations reduce implementation cost, but they do not mean physical-interface protection is already operational:

- Neutron-managed lifecycle primarily covers tap devices;
- standalone system mode can target a physical or virtual interface, but no node-level physical-interface protection manager exists;
- current XDP health treats a pinned link path as ready without proving exact live program/interface identity;
- the current parser has no MAC fields, supports only one 802.1Q tag, and returns early for non-IP traffic;
- there are no storm or DDoS maps, policies, APIs, metrics, or mitigation state.

XDP and TC are verdict-independent, but their current artifact and runtime lifecycle is not fully independent. Shared runtime metadata treats `xdp_firewall` as a required program and loads it before optional TC programs. The implementation must preserve TC recovery when an XDP protection domain is unavailable.

## 3. Goals

### 3.1 Storm goals

- Drop excess broadcast and multicast traffic before it reaches TC, OVS, or the host stack.
- Protect tap ingress and physical ingress.
- Support packet-rate and byte-rate limits with configurable bursts.
- Preserve a controlled amount of essential ARP, DHCP, IPv6 ND, and link-control traffic instead of applying long drop-all windows.
- Support disabled, observe, and police modes.
- Provide independent per-interface, per-class policy and statistics.

### 3.2 DDoS goals

- Make physical-interface ingress the first DDoS protection target.
- Provide deterministic, configured guardrails before adaptive detection is attempted.
- Protect total interface capacity and selected local services.
- Provide bounded per-source controls without making source-IP state the only defense.
- Support explicit, expiring CIDR mitigation rules.
- Keep DDoS policy and readiness independent from storm and TC ACL/CT.

### 3.3 Product goals

- Reuse Aria's Rust/Aya runtime rather than embedding another product or daemon.
- Preserve the existing eight-byte `TapConfig` ABI.
- Keep OVS responsible for L2 switching and TC responsible for ACL/CT.
- Avoid false readiness and silent attach-mode degradation.
- Make observe-first deployment the default.

## 4. Non-Goals

The first milestone does not provide:

- physical-interface egress policing;
- tap DDoS enforcement by default;
- unknown-unicast detection based on OVS or bridge FDB state;
- shared rate limits across bond members;
- shared rate limits across ingress and egress;
- XDP SYN cookies or `XDP_TX` challenge responses;
- AF_XDP userspace packet scrubbing;
- BGP FlowSpec, RTBH, or switch-controller integration;
- automatic threshold learning followed by autonomous blocking;
- packet fingerprints for specific attack tools;
- unbounded per-flow or per-source state;
- cross-node aggregation or mitigation coordination.

## 5. Considered Architectures

### 5.1 Separate XDP programs

Run storm and DDoS as separate XDP programs through a dispatcher.

Rejected for the first milestone because the current Aya lifecycle assumes one XDP program per interface. Adding a dispatcher creates a second program ownership and recovery model before the protection behavior itself is proven.

### 5.2 One monolithic protection domain

Put storm and DDoS policy, state, readiness, and statistics into one set of maps.

Rejected because a storm configuration error could degrade DDoS, high-cardinality DDoS state could affect storm enforcement, and a single readiness bit would obscure which protection is operational.

### 5.3 One entry with isolated internal domains

Use one `xdp_firewall` entry and invoke isolated `storm_guard` and `ddos_guard` modules in a fixed order.

Selected because it fits the current loader and attach model while preserving policy, state, failure, and readiness separation.

## 6. Datapath Architecture

```text
external traffic -> physical ingress -> xdp_firewall
VM traffic       -> tap ingress      -> xdp_firewall

xdp_firewall
  -> read XDP_INTERFACE_CONFIG by ingress_ifindex
     -> absent or both domains disabled: XDP_PASS
  -> parse bounded Ethernet/VLAN metadata
  -> storm_guard when requested
     -> over limit: account storm reason and XDP_DROP
  -> if DDoS disabled: XDP_PASS
  -> parse IPv4/IPv6 and bounded L4 metadata
  -> ddos_guard
     -> mitigation hit or over limit: account DDoS reason and XDP_DROP
  -> XDP_PASS
  -> existing TC ingress pipeline
```

Storm runs first because it needs only L2 information and must reject L2 floods before deeper parsing. DDoS parsing and maps are skipped for tap profiles that do not request DDoS.

TC behavior remains unchanged. XDP does not read ACL banks, ACL policies, ACL conntrack entries, TC QoS policies, or TC feature flags.

## 7. Interface Profiles

### 7.1 `tap_storm`

- storm mode: observe or police;
- DDoS mode: disabled by default;
- identity: ingress `ifindex`, with existing tap identity available only for control-plane attribution;
- purpose: stop VM-originated broadcast and multicast storms before OVS;
- attachment mode: explicitly detected and reported; no silent mode claim.

### 7.2 `physical_edge`

- storm mode: observe or police;
- DDoS mode: observe or police;
- identity: ingress `ifindex` plus interface generation;
- attachment mode: native/driver XDP preferred;
- generic fallback: allowed only by explicit policy;
- purpose: protect the compute node, TC, OVS, and host stack from external ingress floods.

### 7.3 Unconfigured interfaces

An interface without `XDP_INTERFACE_CONFIG` is outside the protection domain and passes traffic.

## 8. L2 Parsing And Storm Classification

The existing `PacketInfo` remains the L3/L4 representation. A new bounded L2 representation is added for XDP protection:

```rust
#[repr(C)]
pub struct XdpFrameInfo {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub ether_type: u16,
    pub outer_vlan_id: u16,
    pub inner_vlan_id: u16,
    pub vlan_depth: u8,
    pub traffic_class: u8,
    pub _pad: [u8; 2],
}
```

Parsing is bounded to:

- untagged Ethernet;
- one 802.1Q or 802.1ad tag;
- two tags for QinQ;
- safe pass on truncated or unsupported deeper encapsulation, with an error counter.

Storm classes are:

1. broadcast;
2. IPv4 multicast;
3. IPv6 multicast;
4. other multicast;
5. link-local control.

Unknown unicast is intentionally not classified as storm traffic because packet-local XDP state cannot determine whether a unicast destination is absent from an OVS or bridge FDB.

Link-local control traffic receives its own policy. It is not granted an unlimited bypass. Physical profiles use a higher protected allowance, while tap profiles may use a stricter allowance. Vendor-specific control protocols are added through explicit policy rather than an inaccurate universal hard-coded list.

ARP, DHCP broadcast, and IPv6 ND are not fully exempt. Continuous policing preserves a configured allowance while still limiting an actual protocol storm.

## 9. Interface And Storm Map ABI

`TapConfig` remains exactly eight bytes. Storm and DDoS fields are not added to it.

### 9.1 Interface configuration

```text
XDP_INTERFACE_CONFIG: HashMap<u32, XdpInterfaceConfig>
key: ifindex
value:
  interface_generation: u64
  policy_generation: u64
  profile: u8
  storm_mode: u8
  ddos_mode: u8
  flags: u8
  reserved padding
```

The eBPF program uses `ctx.ingress_ifindex` directly. Physical interfaces are not assigned synthetic tap IDs.

`interface_generation` is a userspace-assigned monotonic value created for each successful interface attachment transaction. A deleted and recreated interface receives a new value even when Linux reuses the same ifindex. Runtime values with a different interface generation are invalidated before the domain becomes ready.

### 9.2 Storm policy

```text
STORM_POLICY: HashMap<StormKey, StormPolicy>
key:
  ifindex: u32
  traffic_class: u8
  aligned padding
value:
  pps_limit: u64
  bytes_per_second: u64
  burst_packets: u64
  burst_bytes: u64
  policy_generation: u64
```

The external API may accept bits per second, but the control plane converts it to bytes per second before writing the map. Kernel ABI names always state their units.

### 9.3 Storm runtime

```text
STORM_RUNTIME: HashMap<StormKey, StormRuntime>
value:
  packet_tokens: u64
  byte_tokens: u64
  packet_remainder: u64
  byte_remainder: u64
  last_refill_ns: u64
  policy_generation: u64
  bpf_spin_lock synchronization field
```

Policy generation mismatch resets the bucket from the new policy. Runtime token state is pinned for process recovery but is not stored in desired-state WAL.

### 9.4 Storm statistics

```text
STORM_STATS: PerCpuHashMap<StormStatsKey, StormStatsValue>
key:
  ifindex
  traffic_class
  verdict or reason
value:
  packets
  bytes
```

Counters are per-CPU. The agent records sampling time when it reads them instead of making every packet contend on a shared `last_seen_ns`. Enforcement buckets are not per-CPU full-rate buckets because that would multiply the allowed rate by CPU count.

## 10. Storm Policer

Storm uses two simultaneous token constraints:

- packet tokens enforce packets per second;
- byte tokens enforce bytes per second;
- a packet passes only when both constraints have sufficient credit;
- a dropped packet does not consume bandwidth credit, but the refilled state is retained.

This is a dual PPS/byte-rate policer, not srTCM. It does not implement committed and excess color buckets.

Refill occurs in XDP using `bpf_ktime_get_ns()`. Userspace never replenishes tokens.

Integer refill preserves fractional remainder so low PPS policies do not starve when packets arrive more frequently than one whole token interval. Arithmetic uses saturating, bounded operations and caps tokens at the configured burst.

The initial implementation uses one shared interface/class bucket with kernel-supported synchronization for correctness. A privileged performance gate must measure lock contention under a single hot broadcast class. If that design misses the required packet-rate target, the approved fallback is conservative RX-queue sharding; per-CPU full-rate buckets are not permitted.

Modes behave as follows:

- `disabled`: skip classification work for the domain when no other domain needs it;
- `observe`: run lookup, refill, decision, and statistics but return pass;
- `police`: apply the computed verdict.

## 11. DDoS Guard Layers

The first milestone provides deterministic physical-ingress protection in four bounded layers.

### 11.1 Interface aggregate protection

Fixed-cardinality policies protect:

- total packets and bytes;
- TCP packets;
- TCP SYN packets;
- UDP packets and bytes;
- ICMP and ICMPv6 packets;
- IPv4 and IPv6 fragments;
- other IP protocols.

These limits protect node capacity even when attackers spoof source addresses.

### 11.2 Protected-service policies

Service keys identify:

```text
ifindex + destination address + protocol + destination port
```

Each configured service has packet, byte, and burst limits. Exact address/service policies are the first implementation. Prefix-oriented service policies require separate bounded LPM maps and are not part of the first milestone.

### 11.3 Bounded source policies

Source state uses a capacity-limited LRU map keyed by:

```text
ifindex + address family + source address + protocol
```

It is a secondary control, not the node's primary defense. Map eviction, insertion failure, and capacity pressure have explicit counters and degraded evidence. A full source map must not disable aggregate or service protection.

### 11.4 Temporary CIDR mitigation

Separate IPv4 and IPv6 LPM maps hold explicit mitigation rules with:

- action;
- expiry timestamp;
- reason code;
- policy generation;
- rule source identifier.

Expired rules stop enforcing based on kernel time. The agent removes expired entries asynchronously, so agent delay cannot extend the effective block beyond its declared expiry.

Trusted exceptions do not bypass the absolute interface safety ceiling. They may bypass selected service or source policies only when the policy explicitly says so.

## 12. DDoS Map Domains

The exact map families are isolated from storm:

```text
DDOS_INTERFACE_POLICY
DDOS_INTERFACE_RUNTIME
DDOS_SERVICE_POLICY
DDOS_SERVICE_RUNTIME
DDOS_SOURCE_RUNTIME_V4
DDOS_SOURCE_RUNTIME_V6
DDOS_BLOCKLIST_V4
DDOS_BLOCKLIST_V6
DDOS_STATS
DDOS_CAPACITY_STATS
```

High-cardinality packet events are not emitted per packet. The agent derives state transitions and alerts from bounded statistics. Source addresses are not Prometheus labels.

## 13. Map Inventory And Pinning

The current monolithic map inventory is split logically:

```text
TC_NETWORK_MAP_NAMES
XDP_BASE_MAP_NAMES
STORM_MAP_NAMES
DDOS_MAP_NAMES
ALL_MAP_NAMES
```

Storm or DDoS map absence changes only the corresponding domain readiness. It does not make TC ACL/CT unavailable.

Policy, runtime, and statistics maps are pinned so a restarted agent can reopen, validate, reset, and inspect them. Pinning runtime state does not make it durable desired state.

Each XDP domain has explicit schema and policy-generation metadata. Schema incompatibility degrades that domain and requires a controlled XDP-domain rebuild; it does not authorize scrubbing TC ACL/CT state.

## 14. Physical-Interface Lifecycle

A new `NodeGuardManager` owns explicitly configured physical interfaces.

Responsibilities:

- resolve configured interface names to current ifindices;
- reject ambiguous, missing, or duplicate targets;
- reject simultaneous configuration of a bond master and its members when this would duplicate ingress processing;
- attach driver/native XDP first;
- allow generic fallback only when configured;
- record actual attach mode;
- initialize interface, storm, and DDoS policies transactionally;
- remove or invalidate stale runtime state on interface generation change;
- validate exact program/link/interface identity;
- publish node-level status independently from Neutron port status.

First-milestone physical interfaces come from an explicit allowlist. The agent does not infer OVS uplinks automatically.

Example configuration shape:

```toml
[xdp_protection]
physical_interfaces = ["eth1"]
allow_generic_fallback = false
```

Bond members remain independently limited and counted. Shared bond capacity is a later design.

Existing `TapRegistry` remains responsible for tap attach/detach. It initializes and removes tap storm configuration but does not gain ownership of physical interfaces.

## 15. Program Loading And Failure Isolation

The loader and runtime metadata must reflect requested domains:

- XDP is required only when storm or DDoS is requested for at least one interface;
- TC program load and recovery continue after an XDP program load failure;
- an XDP attach failure does not quiesce healthy TC ACL/CT;
- a TC failure does not silently report storm or DDoS unavailable when their XDP identity remains valid;
- shared ELF build failure remains a release failure, but runtime program-load failures are isolated by program and domain.

Missing policy has two meanings:

- domain not requested: pass and report `not_requested`;
- domain requested but required map/policy missing: pass for availability, report `degraded`, increment an error counter, and emit a rate-limited operational event.

The first milestone uses availability-first fail-open behavior for internal storm/DDoS state failures. Explicit valid policies still fail traffic according to their configured verdicts.

## 16. Readiness Model

The public model separates:

```text
acl_ready
xdp_hook_ready
storm_ready
ddos_ready
```

`xdp_hook_ready` requires exact evidence for:

- expected interface and ifindex;
- expected program ID;
- live attached link ID;
- actual attach mode;
- pinned link identity matching the live attachment.

A path-only pinned-link check is insufficient. `REVIEW-OPS-036` must be closed before storm or DDoS is advertised as operational.

`storm_ready` additionally requires:

- storm requested;
- required storm map schema valid;
- interface and policy generations matched;
- effective mode equal to requested mode.

`ddos_ready` applies the equivalent independent DDoS requirements.

Node-level storm/DDoS status is not added to Neutron `managed_domains` in the first milestone. A physical-interface problem must not block a Neutron tap ACL transaction.

## 17. Control-Plane API

The proposed API family is:

```text
GET /api/v1/xdp-protection/status
GET /api/v1/xdp-protection/interfaces
PUT /api/v1/xdp-protection/interfaces/{iface}
PUT /api/v1/xdp-protection/interfaces/{iface}/storm
PUT /api/v1/xdp-protection/interfaces/{iface}/ddos
GET /api/v1/xdp-protection/interfaces/{iface}/stats
```

Dynamic path segments are percent-encoded by every client. The server validates interface-name syntax consistently.

Status includes:

- requested and effective profile;
- requested and effective storm/DDoS mode;
- interface name, ifindex, and interface generation;
- program ID and link ID;
- attach mode;
- policy generation and applied generation;
- `xdp_hook_ready`, `storm_ready`, and `ddos_ready`;
- stable degraded reason;
- last successful reconciliation time.

Policy updates use generation and desired-hash identity. A response is successful only after the map write and read-back verification match the requested generation.

## 18. Desired State And Recovery

Durable desired state includes:

- protected interface selection;
- interface profile;
- requested domain modes;
- storm policies;
- DDoS aggregate, service, source, and mitigation policies;
- policy generation and desired hash.

Ephemeral state excludes:

- token balances;
- refill remainders;
- transient source LRU contents;
- current rate samples;
- event-delivery cursor.

On restart:

1. validate exact live link/program/interface identity;
2. open and validate XDP-domain maps;
3. compare stored and desired generations/hashes;
4. reset runtime buckets whose policy generation changed;
5. remove expired mitigation entries;
6. publish readiness only after read-back verification;
7. preserve healthy TC ACL/CT regardless of XDP-domain outcome.

## 19. Observability

Prometheus metrics use bounded labels such as:

```text
interface
profile
domain
traffic_class
verdict
reason
attach_mode
```

Source IP, destination IP, and arbitrary service identifiers are not unbounded metric labels.

Required metric families include:

- passed and dropped packets/bytes;
- current effective modes;
- attach and readiness state;
- policy generation;
- map insertion failures and LRU evictions;
- malformed/truncated parse outcomes;
- mitigation rule count and expiry cleanup;
- reconciliation failures;
- rate-limited event suppression count.

Events are generated for state transitions and sampled operational evidence, not for every dropped packet.

## 20. Delivery Batches

### Batch 1: XDP foundation and observe-only operation

- close exact XDP identity gap `REVIEW-OPS-036`;
- split XDP and TC map inventories and readiness;
- add `NodeGuardManager` and explicit physical-interface allowlist;
- record native/generic attach mode and fallback result;
- add bounded Ethernet, VLAN, and QinQ parser;
- add interface profile and generation maps;
- run all new classifiers in observe mode only.

### Batch 2: Storm enforcement

- implement five L2 classes;
- implement kernel-refilled packet and byte policer;
- add tap and physical storm policies;
- add statistics, API, metrics, and state-transition events;
- promote selected interfaces from observe to police only after baseline review.

### Batch 3: Physical-ingress DDoS enforcement

- implement interface aggregate limits;
- implement TCP SYN, UDP, ICMP, fragment, and other-protocol classes;
- implement exact protected-service policies;
- implement bounded per-source LRU limits;
- implement expiring IPv4/IPv6 CIDR mitigation;
- deploy observe-first, then explicitly promote validated policies to police.

### Later enhancements

- adaptive anomaly detection and mitigation recommendations;
- controlled automatic mitigation with safety gates;
- tap DDoS profiles for malicious VM traffic;
- AF_XDP, BGP, switch, or controller integration;
- cross-node analysis;
- shared bond or bidirectional limits.

## 21. Verification And Acceptance

Local Cargo build, check, and test commands remain prohibited. Rust/eBPF compilation authority is GitHub Actions. Static and non-Cargo checks may run locally where allowed.

### 21.1 Pure and static verification

- ABI layout and alignment tests for every new shared type;
- `TapConfig` remains eight bytes;
- parser tests for untagged, VLAN, QinQ, truncation, and unsupported depth;
- classification tests for all storm and DDoS classes;
- token refill, fractional remainder, burst, saturation, and generation-reset tests;
- disabled/observe/police transition tests;
- desired-hash and read-back tests;
- map inventory mutation tests proving storm/DDoS absence cannot change ACL readiness;
- static guard proving XDP never reads ACL/CT maps.

### 21.2 Privileged datapath verification

- tap ingress and physical-like veth ingress;
- native and generic attach modes;
- broadcast and multicast floods through untagged, VLAN, and QinQ traffic;
- control traffic remains within its configured allowance;
- packet and byte limits independently trigger;
- TCP SYN, UDP, ICMP, fragment, and aggregate interface floods;
- service policy enforcement;
- temporary CIDR mitigation and exact expiry;
- full source-state map and insertion-failure behavior;
- XDP drop counters are not attributed to TC ACL/QoS;
- healthy TC ingress/egress survive XDP load, map, and attach failures;
- detached-but-pinned XDP link reports not ready;
- ifindex reuse cannot inherit stale effective policy;
- agent pause/restart does not stop token refill;
- policy generation change does not reuse stale tokens.

### 21.3 Performance gates

- baseline XDP pass throughput before and after the new disabled fast path;
- storm hot-key throughput and CPU cost;
- DDoS interface and service policy throughput;
- multi-CPU threshold accuracy;
- synchronization contention under sustained flood;
- verifier acceptance on the maintained minimum kernel and the release kernel;
- eBPF stack use no greater than the 512-byte verifier limit.

On the same host, NIC mode, queue configuration, packet size, and benchmark tool:

- the disabled fast path must retain at least 95% of the pre-change XDP pass baseline;
- observe mode must retain at least 90% of that baseline;
- police mode under a single hot storm class must retain at least 80% of that baseline while enforcing the configured aggregate limit;
- benchmark output must record packet loss, CPU use, attach mode, queue count, and achieved PPS.

If the shared synchronized storm bucket misses those gates, the only approved fallback is a separately reviewed conservative sharding design.

## 22. External Implementation Lessons

The design borrows from `storm-control`:

- L2 broadcast and multicast classification;
- per-CPU counters;
- dynamic interface lifecycle;
- observe-first operation;
- Prometheus visibility.

It does not copy:

- one-second userspace threshold decisions;
- whole-class long-duration drop switches;
- generic-XDP-only attachment;
- packet-only thresholds;
- one global threshold set for every interface;
- mismatched trigger and recovery windows.

The design may use FastNetMon as a later detection/control-plane reference and Katran/xdp-tools as datapath lifecycle and performance references. They are not embedded into Aria.

## 23. Required Invariants

The implementation is acceptable only while all of these remain true:

1. XDP never becomes an ACL or conntrack authority.
2. `TapConfig` remains eight bytes.
3. Physical interfaces are not represented as synthetic Neutron taps.
4. Storm and DDoS maps are not TC ACL critical maps.
5. Storm failure cannot make `acl_ready=false`.
6. DDoS failure cannot make `storm_ready=false`.
7. XDP readiness is based on exact live identity, not pin-path existence.
8. Token refill is kernel-side and independent of agent scheduling.
9. Missing requested XDP protection state is explicit degraded fail-open, not false ready.
10. Per-source state is bounded and is never the only volumetric defense.
11. No per-CPU full-rate bucket multiplies an interface limit.
12. First-milestone physical protection is ingress-only.
13. Bond members do not share a limit in the first milestone.
14. Unknown unicast is not advertised as supported.
15. Every enforcement transition is generation-identified and read-back verified.

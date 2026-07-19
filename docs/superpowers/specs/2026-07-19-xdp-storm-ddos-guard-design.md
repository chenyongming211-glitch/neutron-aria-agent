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
- tap DDoS enforcement;
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
- DDoS mode: disabled in the first milestone;
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
pub(crate) struct XdpFrameInfo {
    pub src_mac: [u8; 6],
    pub dst_mac: [u8; 6],
    pub ether_type: u16,
    pub outer_vlan_id: u16,
    pub inner_vlan_id: u16,
    pub vlan_depth: u8,
    pub traffic_class: u8,
}
```

`XdpFrameInfo` is parser-local state, not a map key, map value, event, or userspace ABI. It therefore does not implement `aya::Pod` and has no reserved ABI padding. If a later feature needs to export L2 metadata, it must define a separate versioned shared type with explicit padding rather than turning this parser-local type into an accidental ABI.

Parsing is bounded to:

- untagged Ethernet;
- one 802.1Q or 802.1ad tag;
- two tags for QinQ;
- safe pass on truncated or unsupported deeper encapsulation, with an error counter.

Storm classes are:

1. `STORM_CLASS_BROADCAST = 1`;
2. `STORM_CLASS_IPV4_MULTICAST = 2`;
3. `STORM_CLASS_IPV6_MULTICAST = 3`;
4. `STORM_CLASS_OTHER_MULTICAST = 4`;
5. `STORM_CLASS_LINK_LOCAL_CONTROL = 5`.

Class zero is invalid and is never published as a wildcard.

Unknown unicast is intentionally not classified as storm traffic because packet-local XDP state cannot determine whether a unicast destination is absent from an OVS or bridge FDB.

Link-local control traffic receives its own policy. It is not granted an unlimited bypass. Physical profiles use a higher protected allowance, while tap profiles may use a stricter allowance. Vendor-specific control protocols are added through explicit policy rather than an inaccurate universal hard-coded list.

ARP, DHCP broadcast, and IPv6 ND are not fully exempt. Continuous policing preserves a configured allowance while still limiting an actual protocol storm.

## 9. Interface And Storm Map ABI

`TapConfig` remains exactly eight bytes. Storm and DDoS fields are not added to it.

### 9.1 Interface configuration

```rust
pub const XDP_MODE_DISABLED: u8 = 0;
pub const XDP_MODE_OBSERVE: u8 = 1;
pub const XDP_MODE_POLICE: u8 = 2;

pub const XDP_PROFILE_NONE: u8 = 0;
pub const XDP_PROFILE_TAP_STORM: u8 = 1;
pub const XDP_PROFILE_PHYSICAL_EDGE: u8 = 2;

#[repr(C)]
pub struct XdpInterfaceConfig {
    pub interface_generation: u64,
    pub storm_policy_generation: u64,
    pub ddos_policy_generation: u64,
    pub profile: u8,
    pub storm_mode: u8,
    pub ddos_mode: u8,
    pub storm_class_mask: u8,
    pub ddos_class_mask: u8,
    pub _pad: [u8; 3],
}
```

`XDP_INTERFACE_CONFIG` is a `HashMap<u32, XdpInterfaceConfig>` keyed by ingress ifindex. The value is 32 bytes with no implicit padding. Interface generation zero is invalid. A domain policy generation is zero only while that domain is disabled. Separate storm and DDoS policy generations preserve domain independence: changing one domain does not force runtime replacement in the other.

Class bit `n - 1` corresponds to class constant `n`. Valid storm masks are within `0x1f`; valid DDoS masks are within `0x7f`. An enabled storm domain requires a nonzero mask and one complete policy/runtime pair for every selected class. An enabled DDoS domain requires bit zero for the total class and one complete interface policy/runtime pair for every selected interface class; service and source policies remain optional. A first-milestone `tap_storm` profile requires disabled DDoS mode, zero DDoS generation, and zero DDoS class mask. Reserved mask bits, invalid profile/mode combinations, unknown profiles, and unknown modes fail open for packet availability, increment a bounded configuration-error counter, and make only the affected XDP domain degraded. A selected class with a missing generation-scoped policy is degraded missing state, not an implicit unlimited class.

The eBPF program uses `ctx.ingress_ifindex` directly. Physical interfaces are not assigned synthetic tap IDs.

`interface_generation` is allocated from a durable, node-local, monotonically increasing `u64` counter before each interface attachment transaction. A deleted and recreated interface receives a new value even when Linux reuses the same ifindex. Counter exhaustion is a hard configuration error; the counter never wraps to zero.

Every enforcement policy and runtime key includes both interface and domain policy generation. Publication follows this order:

1. remove or disable the old `XDP_INTERFACE_CONFIG[ifindex]` entry so packets pass while a replacement interface identity is prepared;
2. allocate a nonzero interface generation and nonzero generations for every requested domain;
3. write every requested policy, fixed-cardinality runtime, and mitigation entry under the new generations; high-cardinality source runtime remains lazy;
4. read back and validate the complete generation-scoped map set;
5. write `XDP_INTERFACE_CONFIG[ifindex]` last as the atomic per-interface commit point;
6. publish readiness, then remove old-generation entries asynchronously.

An ordinary policy update on the same live interface follows steps 3 through 6 with a new generation only for the changed domain. Until the final interface-config write, packets continue using the complete old generation. After that write, old policy and runtime entries for the changed domain are unreachable while the other domain keeps its existing generation and state. There is no mixed old/new effective policy window.

### 9.2 Storm policy

```rust
#[repr(C)]
pub struct StormKey {
    pub interface_generation: u64,
    pub policy_generation: u64,
    pub ifindex: u32,
    pub traffic_class: u8,
    pub _pad: [u8; 3],
}

#[repr(C)]
pub struct RatePolicy {
    pub pps_limit: u64,
    pub bytes_per_second: u64,
    pub burst_packets: u64,
    pub burst_bytes: u64,
}
```

`STORM_POLICY` is a `HashMap<StormKey, RatePolicy>`. `StormKey` is 24 bytes and `RatePolicy` is 32 bytes; neither has implicit padding. All constructors zero explicit padding before a map operation.

The external API may accept bits per second, but the control plane converts it to bytes per second before writing the map. Kernel ABI names always state their units.

For each packet-rate or byte-rate dimension:

- `limit == 0 && burst == 0` disables that dimension;
- `limit > 0 && burst > 0` enables it;
- exactly one of limit or burst being zero is invalid and is rejected before map publication;
- at least one dimension must be enabled for every published rate policy.

A class intentionally outside enforcement is removed from the corresponding interface class mask; it is not represented by a missing required policy.

### 9.3 Storm runtime

```rust
#[repr(C)]
pub struct StormRuntime {
    pub lock: aya_ebpf::bindings::bpf_spin_lock,
    pub _pad: [u8; 4],
    pub packet_tokens: u64,
    pub byte_tokens: u64,
    pub packet_remainder: u64,
    pub byte_remainder: u64,
    pub last_refill_ns: u64,
}
```

`STORM_RUNTIME` is a `HashMap<StormKey, StormRuntime>`. The value is 48 bytes: the lock occupies offset 0 through 3, explicit padding occupies 4 through 7, and the five `u64` fields occupy 8 through 47. The lock is the real top-level BTF `struct bpf_spin_lock`, not a layout-compatible plain `u32`. Runtime types containing kernel synchronization objects are eBPF-owned types, not shared `aya::Pod` types. Userspace does not treat the lock bytes as ordinary mutable state.

The implementation may use a spin lock only after a privileged load probe proves that the maintained target kernel accepts it for the XDP program and selected map type. Every execution path unlocks before returning, and no helper call, BPF-to-BPF call, packet load, or second lock acquisition occurs while the lock is held. Packet parsing, policy lookup, time acquisition, and statistics updates happen outside the critical section.

A new generation starts with both enabled token dimensions full, both remainders zero, and `last_refill_ns` set to current kernel monotonic time. Runtime token state is pinned for process recovery but is not stored in desired-state WAL.

### 9.4 Storm statistics

```rust
#[repr(C)]
pub struct StormStatsKey {
    pub interface_generation: u64,
    pub ifindex: u32,
    pub traffic_class: u8,
    pub verdict: u8,
    pub reason: u8,
    pub _pad: u8,
}

#[repr(C)]
pub struct StormStatsValue {
    pub packets: u64,
    pub bytes: u64,
}
```

`STORM_STATS` is a `PerCpuHashMap<StormStatsKey, StormStatsValue>`. Verdict and reason use bounded shared constants, including pass, would-drop in observe mode, enforced drop, missing required policy, invalid configuration, and time anomaly.

Shared rate verdict constants are `XDP_RATE_VERDICT_PASS = 1`, `XDP_RATE_VERDICT_WOULD_DROP = 2`, `XDP_RATE_VERDICT_DROP = 3`, and `XDP_RATE_VERDICT_ERROR_PASS = 4`. Shared rate reasons are none 0, packet limit 1, byte limit 2, both limits 3, missing required state 4, invalid configuration 5, time anomaly 6, and capacity failure 7. Unknown verdict or reason values are never emitted.

Counters are per-CPU. The agent records sampling time when it reads them instead of making every packet contend on a shared `last_seen_ns`. Enforcement buckets are not per-CPU full-rate buckets because that would multiply the allowed rate by CPU count.

## 10. Storm Policer

Storm uses two simultaneous token constraints:

- packet tokens enforce packets per second;
- byte tokens enforce bytes per second;
- a packet passes only when both constraints have sufficient credit;
- a dropped packet does not consume bandwidth credit, but the refilled state is retained.

This is a dual PPS/byte-rate policer, not srTCM. It does not implement committed and excess color buckets.

Refill occurs in XDP using `bpf_ktime_get_ns()`. Userspace never replenishes tokens.

Integer refill preserves fractional remainder so low PPS policies do not starve when packets arrive more frequently than one whole token interval. For one enabled dimension, the mathematical result is:

```text
N                 = 1_000_000_000
elapsed_ns        = now_ns.saturating_sub(last_refill_ns)
credit_numerator  = rate_per_second * elapsed_ns + remainder
whole_tokens      = floor(credit_numerator / N)
next_remainder    = credit_numerator % N
next_tokens       = min(burst, tokens + whole_tokens)
```

This formula defines semantics, not a requirement to multiply two unbounded `u64` values. The eBPF implementation must not rely on `u128` lowering. It computes the same result with bounded `u64` operations:

```text
whole_seconds = elapsed_ns / N
subsecond_ns  = elapsed_ns % N
rate_hi       = rate_per_second / N
rate_lo       = rate_per_second % N

second_credit = saturating_mul(rate_per_second, whole_seconds)
fraction_num  = rate_lo * subsecond_ns + remainder
fraction      = saturating_add(rate_hi * subsecond_ns,
                               fraction_num / N)
next_remainder = fraction_num % N
next_tokens    = min(burst,
                     saturating_add(tokens,
                                    saturating_add(second_credit, fraction)))
```

Every multiplication shown in the fractional path is bounded below `u64::MAX` by the quotient/remainder decomposition. Once tokens saturate at burst, the implementation sets the corresponding remainder to zero; credit accumulated while a bucket is full is not banked for later. A backwards kernel-time observation produces zero elapsed time and an operational counter rather than a token grant.

The packet dimension charges one token. The byte dimension charges `ctx.data_end - ctx.data`, including the Ethernet header and VLAN tags visible to XDP but excluding wire FCS. A disabled dimension is treated as satisfied and is neither refilled nor debited.

Storm makes one atomic decision under the runtime lock: refill both enabled dimensions, test both costs, and debit both only when both pass. If either dimension is over limit, neither dimension is debited; the refilled state and remainders are retained. `observe` performs the same simulated debit and decision as `police`, but converts a would-drop verdict to pass after accounting it separately.

The initial implementation uses one shared interface/class bucket with kernel-supported synchronization for correctness. A privileged performance gate must measure lock contention under a single hot broadcast class. If that design misses the required packet-rate target, the approved fallback is conservative RX-queue sharding; per-CPU full-rate buckets are not permitted.

Modes behave as follows:

- `disabled`: skip classification work for the domain when no other domain needs it;
- `observe`: run lookup, refill, decision, and statistics but return pass;
- `police`: apply the computed verdict.

Mode-only changes on the same interface and policy generation preserve token and remainder state. `observe -> police` therefore begins enforcement from the state measured in observe mode; `police -> observe` continues an accurate simulation. Enabling a previously disabled domain requires a new policy generation and initializes full bursts. Disabling a domain does not need synchronous runtime deletion, but a later re-enable must use another new generation so stale balances cannot become reachable.

Any rate, burst, traffic-class membership, or exception change requires a new policy generation. The new generation receives a full configured burst. This intentionally grants one new burst at policy publication; it never inherits a larger balance from an older, more permissive policy.

## 11. DDoS Guard Layers

The first milestone provides deterministic physical-ingress protection in four bounded layers.

The execution order is temporary CIDR mitigation, interface aggregate protection, protected-service policy, then bounded per-source policy. A mitigation drop returns immediately. Rate buckets account offered load: every reached bucket refills, evaluates, and conditionally debits its own state; a later layer's rejection does not roll back an earlier layer's debit. This conservative rule avoids multi-lock transactions and makes overload accounting deterministic. Statistics distinguish the first rejecting layer from other buckets that were reached.

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

Every IP packet reaches the mandatory total bucket and, when selected by the DDoS class mask, one protocol bucket: TCP, UDP, ICMP/ICMPv6, or other. It may also reach one selected modifier bucket. Fragment takes precedence over TCP SYN as the modifier, so a packet reaches at most three interface buckets: total, protocol, and fragment-or-SYN. A non-initial fragment has no usable L4 ports and cannot match an exact-port service policy.

### 11.2 Protected-service policies

Service keys identify:

```text
ifindex + destination address + protocol + destination port
```

Each configured service has packet, byte, and burst limits. Exact address/service policies are the first implementation. Prefix-oriented service policies require separate bounded LPM maps and are not part of the first milestone.

TCP and UDP service policies use an exact destination port. ICMP, ICMPv6, and other protocols use a protocol-wide selector with no port. Selector kind is explicit in the key, so port zero remains a real port rather than a wildcard sentinel. If no exact service policy matches, this layer is skipped without degraded state.

### 11.3 Bounded source policies

Source state uses a capacity-limited LRU map keyed by:

```text
ifindex + address family + source address + protocol
```

It is a secondary control, not the node's primary defense. Insertion failure and sampled capacity pressure have explicit evidence; internal LRU replacement is not advertised as an exact counter. A full source map must not disable aggregate or service protection.

Per-source policy is configured per interface, address family, and protocol. It creates rate runtime lazily for observed sources. Failure to create source state fails open for this secondary layer, increments capacity evidence, and leaves the interface and service layers active.

### 11.4 Temporary CIDR mitigation

Separate IPv4 and IPv6 LPM maps hold explicit mitigation rules with:

- action;
- expiry timestamp;
- reason code;
- policy generation;
- rule source identifier.

Expired rules stop enforcing based on kernel time. The agent removes expired entries asynchronously, so agent delay cannot extend the effective block beyond its declared expiry.

The durable rule stores `expires_at_unix_ns` and the original creation metadata, never the kernel `expiry_ns`. On publication or restart, the agent computes the remaining wall-clock lifetime and converts it to `bpf_ktime_get_ns()` space using saturating addition. A rule already expired in wall-clock time is not published. The XDP program calls `bpf_ktime_get_ns()` once before mitigation lookup processing and treats a matched entry with `now_ns >= expiry_ns` as no match.

The default userspace cleanup interval is 30 seconds and is configurable from 1 through 300 seconds. Cleanup latency affects map occupancy only, not enforcement duration. A large wall-clock correction triggers reconciliation so persisted deadlines are translated again; already published monotonic deadlines are never extended silently.

Trusted exceptions do not bypass the absolute interface safety ceiling. They may bypass selected service or source policies only when the policy explicitly says so.

## 12. DDoS Map Domains

The DDoS rate-policy value is the shared 32-byte `RatePolicy` from Section 9.2. DDoS runtime values use the same token, remainder, timestamp, padding, and real `bpf_spin_lock` layout and restrictions as `StormRuntime`. Each runtime map has its own Rust type name so storm and DDoS maps cannot be interchanged accidentally. Each individual DDoS bucket makes its packet/byte decision atomically under its own lock, and packet processing holds at most one bucket lock at a time. DDoS mode changes and generation initialization follow the Section 10 transition rules with the independent DDoS policy generation.

Interface aggregate buckets use:

```rust
#[repr(C)]
pub struct DdosBucketKey {
    pub interface_generation: u64,
    pub policy_generation: u64,
    pub ifindex: u32,
    pub traffic_class: u8,
    pub _pad: [u8; 3],
}
```

The fixed class constants are `DDOS_CLASS_TOTAL = 1`, `DDOS_CLASS_TCP = 2`, `DDOS_CLASS_TCP_SYN = 3`, `DDOS_CLASS_UDP = 4`, `DDOS_CLASS_ICMP = 5`, `DDOS_CLASS_FRAGMENT = 6`, and `DDOS_CLASS_OTHER = 7`. Class zero is invalid. Unknown class values are rejected by userspace and treated as degraded no-policy lookups in XDP.

Exact service maps are split by address family rather than storing IPv4 in an invented IPv6 mapping:

```rust
#[repr(C)]
pub struct DdosServiceKey4 {
    pub interface_generation: u64,
    pub policy_generation: u64,
    pub ifindex: u32,
    pub dst_ip: u32,
    pub dst_port: u16,
    pub protocol: u8,
    pub selector_kind: u8,
    pub _pad: [u8; 4],
}

#[repr(C)]
pub struct DdosServiceKey6 {
    pub interface_generation: u64,
    pub policy_generation: u64,
    pub dst_ip: [u8; 16],
    pub ifindex: u32,
    pub dst_port: u16,
    pub protocol: u8,
    pub selector_kind: u8,
}
```

`DDOS_SERVICE_SELECTOR_PROTOCOL = 1` selects destination address plus protocol and requires `dst_port == 0`; `DDOS_SERVICE_SELECTOR_EXACT_PORT = 2` selects destination address, protocol, and the exact port. Selector zero and unknown selectors are invalid. Address-family constants use their IP version numbers: IPv4 is 4 and IPv6 is 6.

IPv4 values use `u32::from_be_bytes(address.octets())`, matching the existing parser representation. IPv6 uses the 16 network-order octets. Ports use the numeric value produced by `u16::from_be_bytes`; userspace performs the same conversion before map operations. Explicit padding is always zero.

Source policy and lazy runtime keys are:

```rust
#[repr(C)]
pub struct DdosSourcePolicyKey {
    pub interface_generation: u64,
    pub policy_generation: u64,
    pub ifindex: u32,
    pub address_family: u8,
    pub protocol: u8,
    pub _pad: [u8; 2],
}

#[repr(C)]
pub struct DdosSourceKey4 {
    pub interface_generation: u64,
    pub policy_generation: u64,
    pub ifindex: u32,
    pub src_ip: u32,
    pub protocol: u8,
    pub _pad: [u8; 7],
}

#[repr(C)]
pub struct DdosSourceKey6 {
    pub interface_generation: u64,
    pub policy_generation: u64,
    pub src_ip: [u8; 16],
    pub ifindex: u32,
    pub protocol: u8,
    pub _pad: [u8; 3],
}
```

Temporary mitigation uses generation-scoped LPM keys. Every field after `prefix_len` is stored in network byte order because LPM matching is byte-oriented:

```rust
#[repr(C)]
pub struct DdosBlockKey4 {
    pub prefix_len: u32,
    pub ifindex_be: u32,
    pub interface_generation_be: u64,
    pub policy_generation_be: u64,
    pub network_addr_be: u32,
    pub _pad: [u8; 4],
}

#[repr(C)]
pub struct DdosBlockKey6 {
    pub prefix_len: u32,
    pub ifindex_be: u32,
    pub interface_generation_be: u64,
    pub policy_generation_be: u64,
    pub network_addr: [u8; 16],
}

#[repr(C)]
pub struct DdosBlockValue {
    pub expiry_ns: u64,
    pub rule_source_id: u64,
    pub reason_code: u32,
    pub action: u8,
    pub flags: u8,
    pub _pad: [u8; 2],
}
```

The LPM prefix length excludes its own four-byte field. A stored rule uses `32 + 64 + 64 + cidr_prefix_len`, covering ifindex, interface generation, policy generation, and the requested address prefix. An XDP lookup uses the full `192` bits for IPv4 or `288` bits for IPv6 after `prefix_len`. Padding is outside the matched prefix and is zero in both stored and lookup keys. First-milestone actions are `DDOS_MITIGATION_DROP = 1` and `DDOS_MITIGATION_TRUST_SERVICE_SOURCE = 2`; action zero and unknown actions are invalid. Neither valid action bypasses the interface aggregate safety ceiling.

Bounded statistics use generation-aware keys and fixed-size values:

```rust
#[repr(C)]
pub struct DdosStatsKey {
    pub interface_generation: u64,
    pub ifindex: u32,
    pub layer: u8,
    pub traffic_class: u8,
    pub verdict: u8,
    pub reason: u8,
}

#[repr(C)]
pub struct DdosStatsValue {
    pub packets: u64,
    pub bytes: u64,
}

#[repr(C)]
pub struct DdosCapacityStats {
    pub source_v4_insert_attempts: u64,
    pub source_v4_insert_failures: u64,
    pub source_v6_insert_attempts: u64,
    pub source_v6_insert_failures: u64,
}
```

Layer constants are `DDOS_LAYER_INTERFACE = 1`, `DDOS_LAYER_SERVICE = 2`, `DDOS_LAYER_SOURCE = 3`, and `DDOS_LAYER_MITIGATION = 4`. Rate verdicts/reasons reuse the shared constants above; `DDOS_REASON_MITIGATION_MATCH = 8` and `DDOS_REASON_EXPIRED_RULE = 9` are DDoS-specific. Source addresses and service identifiers never enter statistics keys.

The exact map families are isolated from storm:

```text
DDOS_INTERFACE_POLICY        HashMap<DdosBucketKey, RatePolicy>
DDOS_INTERFACE_RUNTIME       HashMap<DdosBucketKey, DdosInterfaceRuntime>
DDOS_SERVICE_POLICY_V4       HashMap<DdosServiceKey4, RatePolicy>
DDOS_SERVICE_POLICY_V6       HashMap<DdosServiceKey6, RatePolicy>
DDOS_SERVICE_RUNTIME_V4      HashMap<DdosServiceKey4, DdosServiceRuntime>
DDOS_SERVICE_RUNTIME_V6      HashMap<DdosServiceKey6, DdosServiceRuntime>
DDOS_SOURCE_POLICY           HashMap<DdosSourcePolicyKey, RatePolicy>
DDOS_SOURCE_RUNTIME_V4       LruHashMap<DdosSourceKey4, DdosSourceRuntime>
DDOS_SOURCE_RUNTIME_V6       LruHashMap<DdosSourceKey6, DdosSourceRuntime>
DDOS_BLOCKLIST_V4            LpmTrie<DdosBlockKey4, DdosBlockValue>
DDOS_BLOCKLIST_V6            LpmTrie<DdosBlockKey6, DdosBlockValue>
DDOS_STATS                   PerCpuHashMap<DdosStatsKey, DdosStatsValue>
DDOS_CAPACITY_STATS          PerCpuArray<DdosCapacityStats>
```

`DDOS_SOURCE_RUNTIME_V4` and `V6` are LRU hash maps keyed by `DdosSourceKey4` and `DdosSourceKey6`. Maximum entries are immutable map-creation parameters configured at agent start. A capacity change requires a controlled DDoS-domain map rebuild and observe-mode validation before police mode returns.

Source-layer activation additionally requires a privileged probe proving that the exact maintained kernel accepts a top-level `bpf_spin_lock` in an LRU-hash value for the XDP program. Failure disables and degrades only a requested source layer; it does not replace the design with an unsynchronized cross-CPU bucket and does not disable interface or service protection.

The architecture does not hard-code unmeasured source capacities. Release defaults are selected from an explicit node memory budget after measuring actual locked memory for both key sizes on the maintained target kernel. The release gate records configured maximum entries, observed locked memory, occupancy high-water mark, lookup/insert latency, and aggregate-protection throughput under source churn.

Kernel LRU replacement can make an insertion succeed without reporting which entry was evicted. `DDOS_CAPACITY_STATS` therefore records insertion attempts and failures only. The agent separately reports configured capacity, sampled occupancy, occupancy high-water mark, and cleanup deletions. The product does not claim an exact internal-eviction count. A later kernel-supported observable may add a separately named approximate or kernel-reported metric without changing this contract.

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
mitigation_cleanup_interval_seconds = 30
```

`ddos_source_v4_max_entries` and `ddos_source_v6_max_entries` are startup-only settings required when bounded source protection is enabled. Zero or absence rejects source-layer activation; it does not disable aggregate/service protection. Product packaging may provide values only after the release memory/performance gate has validated them for the supported host profile.

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
- active interface and storm policy generations matched;
- every selected storm class has a complete policy/runtime pair;
- effective mode equal to requested mode.

`ddos_ready` applies the equivalent independent DDoS requirements, including the mandatory total bucket and every interface class selected in the DDoS class mask. Optional service/source policy absence is not degraded unless desired state declares that policy.

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
- requested and applied storm policy generation;
- requested and applied DDoS policy generation;
- `xdp_hook_ready`, `storm_ready`, and `ddos_ready`;
- stable degraded reason;
- last successful reconciliation time.

Policy updates use domain-specific generation and desired-hash identity. A response is successful only after all generation-scoped writes, the final `XDP_INTERFACE_CONFIG` publication, and read-back verification match the requested domain generation. Updating one domain reports no applied-generation change for the other domain.

## 18. Desired State And Recovery

Durable desired state includes:

- protected interface selection;
- interface profile;
- requested domain modes;
- selected storm and DDoS interface class masks;
- storm policies;
- DDoS aggregate, service, source, and mitigation policies;
- mitigation `expires_at_unix_ns`, never a boot-relative kernel timestamp;
- independent storm/DDoS policy generations and desired hashes;
- the next durable node-local interface-generation counter.

Ephemeral state excludes:

- token balances;
- refill remainders;
- transient source LRU contents;
- current rate samples;
- event-delivery cursor.

On restart:

1. validate exact live link/program/interface identity;
2. open and validate XDP-domain maps;
3. compare stored and desired interface/domain generations and hashes;
4. preserve same-generation token state during a process restart on the same boot;
5. initialize full buckets for a new policy generation and republish generation-scoped mitigation entries from durable wall-clock deadlines;
6. remove expired or unreachable old-generation entries asynchronously;
7. publish readiness only after the active generation is read back and complete;
8. preserve healthy TC ACL/CT regardless of XDP-domain outcome.

Pinned maps do not survive a host reboot as valid runtime authority. After reboot, the agent reconstructs maps from desired state, allocates or restores the intended interface identity, translates mitigation deadlines into the new monotonic time domain, and publishes interface config last. A stale boot-relative expiry is never accepted merely because a pinned-path-shaped object exists.

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
- independent storm and DDoS policy generations;
- map insertion attempts/failures, configured capacity, sampled occupancy, and occupancy high-water mark;
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
- implement explicit shared ABI and kernel-recognized synchronized runtime;
- implement overflow-safe kernel-refilled packet and byte policer;
- implement generation-scoped policy publication and mode-transition semantics;
- add tap and physical storm policies;
- add statistics, API, metrics, and state-transition events;
- promote selected interfaces from observe to police only after baseline review.

### Batch 3: Physical-ingress DDoS enforcement

- implement interface aggregate limits;
- implement TCP SYN, UDP, ICMP, fragment, and other-protocol classes;
- implement separate IPv4/IPv6 exact protected-service policies;
- implement bounded per-source LRU limits;
- implement expiring IPv4/IPv6 CIDR mitigation;
- validate source-map memory budgets and selected release capacities;
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
- token tests at `u64` boundaries proving the bounded decomposition matches the mathematical formula without `u128`;
- zero-limit/zero-burst validation and packet-length charging tests;
- disabled/observe/police transition tests;
- tests proving storm and DDoS generations change independently;
- struct size, field-offset, zero-padding, byte-order, and unknown-enum tests for every shared ABI type;
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
- temporary mitigation across agent restart and simulated host-reboot replay;
- full source-state map, source churn, LRU replacement, and insertion-failure behavior;
- offered-load debit behavior when a later DDoS layer rejects;
- XDP drop counters are not attributed to TC ACL/QoS;
- healthy TC ingress/egress survive XDP load, map, and attach failures;
- detached-but-pinned XDP link reports not ready;
- ifindex reuse cannot inherit stale effective policy;
- packets see either the complete old generation or complete new generation during policy publication, never a mixed set;
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

The maintained-minimum gate uses the exact deployed distribution kernel build recorded by the target environment, currently `4.18.0-553.5.1.el8_10.x86_64`, because enterprise BPF backports cannot be inferred from the upstream version number. It must load-probe the selected XDP attach mode, map types, BTF spin-lock value, and every helper used by the critical section. The release-kernel gate runs separately on the kernel shipped or recommended with the release.

The reproducible benchmark matrix is:

- GitHub Actions privileged veth/generic-XDP smoke for functional regression, not a line-rate claim;
- at least one supported physical NIC/driver in native XDP for the release performance gate;
- generic fallback on the same physical host when fallback is an advertised configuration;
- 64-byte wire frames for worst-case PPS and 1500-byte Ethernet frames for byte-rate behavior, explicitly recording whether generator counters include FCS;
- one RX queue and an RSS multi-queue run with queue count, CPU affinity, IRQ affinity, and CPU count recorded;
- Linux `pktgen` for repeatable host-local smoke and an external traffic generator such as TRex for physical line-rate evidence;
- source-cardinality runs below capacity, at configured capacity, and above capacity to measure LRU churn and aggregate-protection stability.

On the same host, NIC mode, queue configuration, packet size, and benchmark tool:

- the disabled fast path must retain at least 95% of the pre-change XDP pass baseline;
- observe mode must retain at least 90% of that baseline;
- police mode under a single hot storm class must retain at least 80% of that baseline while enforcing the configured aggregate limit;
- benchmark output must record packet loss, CPU use, attach mode, queue count, and achieved PPS.
- benchmark output must also record kernel build, NIC and driver/firmware version, CPU model, frame-size convention, map capacities, locked map memory, policy generations, and generator configuration.

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

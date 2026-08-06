# ACL-056 Fragment-Safe ACL And Conntrack Design

Date: 2026-07-19

Status: implementation, hosted CI, and privileged legacy-kernel tap evidence
complete on `v0.9-neutron-agent`; production activation remains disabled pending
a separate change-controlled rollout.

Analyzed implementation target: `v0.9-neutron-agent@43e0e2a`

Tracked finding: `REVIEW-ACL-056`

## 1. Executive Decision

Aria will support legitimate IPv4 and IPv6 fragmentation for ACL policies that
contain destination-port constraints. It will not use the previously considered
steady-state behavior of dropping every real fragment that matches a port-based
ACL.

The selected design is an enhanced Cilium-style fragment tracking model:

1. a first fragment must contain a complete and valid TCP or UDP header;
2. the TC datapath evaluates that first fragment normally;
3. before an allowed first fragment is released, the datapath stores its L4
   ports and publication identity in a bounded fragment-context LRU map;
4. later fragments recover the same ports and therefore use the same ACL and
   conntrack tuple as the first fragment;
5. later fragments received before the first are dropped because TC cannot
   safely queue them while waiting for L4 authority;
6. malformed, stale, expired, cross-tap, cross-direction, cross-VLAN, or
   resource-untracked fragments fail closed;
7. IPv6 atomic fragments (`offset=0`, `M=0`) are ordinary packets and do not
   consume fragment-context capacity.

This is fragment tracking, not full IP payload reassembly. It preserves the
existing TC-only ACL/CT authority in standalone and managed-Neutron modes and
does not make correctness depend on OVS or Netfilter hook ordering.

The steady-state product contract is:

> Once a valid first fragment has established an unexpired fragment context,
> later fragments of that datagram may arrive in any order and inherit the same
> L4 ports, ACL epoch, and CT tuple. A non-first fragment that arrives before
> the first has no authoritative port context and is dropped.

## 2. Confirmed Defect And Impact

The current IPv4 parser ignores the fragment offset and parses the beginning of
a non-first fragment's payload as a TCP or UDP header. Those attacker-controlled
payload bytes become ports, enter ACL lookup, and form an ordinary `CtKey4`.

The current IPv6 parser instead recognizes a nonzero offset and zeroes the L4
fields, but the zero-port tuple can still enter ordinary ACL/CT processing. The
families disagree, and neither provides a correct port-policy contract.

This can cause payload-derived ACL matches, different CT keys for fragments of
one datagram, zero-port collisions between datagrams, and CT creation or refresh
without authoritative L4 context. Dropping every port-dependent fragment would
remove ambiguity but break legitimate fragmented UDP such as a destination-port
53 rule, so that behavior is rejected as the product solution.

## 3. Product Semantics

### 3.1 Classification

The parser classifies packets as:

- `Unfragmented`: IPv4 `offset=0 && MF=0`, or IPv6 without a Fragment header;
- `First`: a real fragment with `offset=0` and more-fragments set;
- `NonInitial`: a real fragment with `offset>0`;
- `Atomic`: IPv6 Fragment header with `offset=0 && M=0`.

`Atomic` normalizes to ordinary processing. IPv4 uses its 16-bit Identification;
IPv6 uses its 32-bit Fragment Identification. Offsets are normalized to bytes.

### 3.2 TCP and UDP

- Unfragmented and atomic packets follow the existing pipeline.
- A valid first fragment is evaluated using its real L4 header.
- An allowed first fragment must establish context before returning pass.
- A non-initial fragment with valid context recovers the first fragment's ports.
- Fragments after the first may arrive out of offset order.
- A non-initial fragment received before the first is dropped.

Protocols without TCP/UDP ports retain address/protocol/direction ACL behavior,
but arbitrary fragment payload must never be interpreted as ports.

### 3.3 Scope of normalization

This design does not buffer a later fragment while waiting for the first. That
requires kernel or userspace reassembly and a different authority boundary.

It also does not claim full L7 normalization or detect every overlap between two
non-initial payload ranges. It does reject a later fragment that overlaps the
authoritative first-fragment L4 range, preventing port-policy substitution.

## 4. Considered Approaches

### 4.1 Reject all port-dependent fragments

Rejected as steady state because it violates the product requirement. It is
only the safe pre-activation fallback while real-tap evidence is pending.

### 4.2 Full reassembly before ACL

Not selected. It supports later-before-first arrival but requires payload
queues, timers, overlap/range tracking, memory-pressure defense, and optional
refragmentation. Implementing it in TC is not a bounded ACL-056 repair, while
delegating it to OVS/Netfilter would split standalone and managed semantics.

### 4.3 Copy Cilium's port-only cache

Directionally correct but incomplete. Aria also has per-tap identity, two TC
directions, VLANs, banked ACL publication, strict CT invalidation, and pinned
runtime recovery. A four-byte port-only value cannot prove those boundaries.

### 4.4 Enhanced fragment context

Selected. It preserves normal fragmented traffic after the first fragment and
makes pressure or stale state cause explicit drops rather than ACL bypass.

## 5. Metadata And Map Contract

### 5.1 Packet metadata

`PacketInfo` is internal scratch, not pinned userspace ABI. It carries the
equivalent of:

```rust
enum FragmentKind {
    Unfragmented,
    First,
    NonInitial,
    Atomic,
}

struct FragmentMetadata {
    kind: FragmentKind,
    identification: u32,
    offset_bytes: u16,
    more_fragments: bool,
    l4_offset: u16,
    first_payload_end: u16,
}
```

Every field is initialized on every successful parse path. The existing padding
byte must not become undocumented fragment state.

### 5.2 Context maps and keys

Two bounded LRU maps avoid address-family ambiguity:

```text
FRAG_CONTEXT_V4: FragmentContextKey4 -> FragmentContextValue
FRAG_CONTEXT_V6: FragmentContextKey6 -> FragmentContextValue
```

Both keys contain `tap_id`, TC direction, VLAN ID, source/destination address,
protocol, and fragment Identification. Padding is explicit and zeroed. Managed
mode reserves `tap_id=0` and cannot create context with it; standalone mode
uses `tap_id=0` as its stable identity and must be allowed to create and resolve
that exact identity. VLAN is included because one TC-managed interface can
observe identical IP fragment tuples in different VLAN domains.

### 5.3 Context value

The shared value contains source and destination port, observed ACL bank,
monotonic fragment publication epoch, first-fragment payload end, absolute
monotonic expiry, and a version/flags field.

It stores no payload and never refreshes expiry on later fragments, preventing
replayed non-initial fragments from retaining an ID indefinitely.

### 5.4 Publication epoch

Bank alone is insufficient because banks alternate 0/1. A bank-0 context could
otherwise appear current after two quick publications.

A per-tap `FRAGMENT_EPOCH` map provides a monotonic 64-bit epoch. Every semantic
ACL change advances it before active-bank switch, including standalone policy
and batch mutations, ACL-referenced groups, managed replacement/purge, and
every ACL runtime disable/enable transition. Attach and recovery also establish
a fresh epoch before readiness.

```text
stage the complete inactive-bank projection
    -> advance fragment epoch
    -> switch active bank
    -> persist and strictly scrub CT
```

Staging remains invisible and therefore runs first. Epoch advance is the final
fence before bank switch. If publication later fails and restores the old bank,
the epoch is not rolled back. In-flight fragment contexts become unavailable,
but stale authority can never revive. Epoch advance failure compensates staging
and aborts before bank switch. Wrap is blocked and requires quiesced map reset;
it never silently returns to zero.

### 5.5 Runtime configuration

A versioned `FRAGMENT_CONFIG` map carries the activation flag, runtime identity
mode, and IPv4/IPv6 timeouts. ABI version 2 preserves the 24-byte total size
and timeout offsets while replacing implicit padding state with explicit
fields:

```text
version: u8
enabled: u8
runtime_mode: u8
_pad: [u8; 5]
ipv4_timeout_ns: u64
ipv6_timeout_ns: u64
```

The stable runtime modes are `managed` and `standalone`; zero or any unknown
mode is invalid. Managed authority rejects `tap_id=0`, while standalone
authority accepts only its stable `tap_id=0` identity. Configuration validity,
including both IPv4 and IPv6 timeouts, is checked before disabled handling
regardless of the current packet family. A valid disabled configuration still
returns the stable tracking-disabled result, without evaluating enabled-only
tap identity. Once guarded activation is implemented, enabled authority applies
the mode-specific identity rule. Managed and standalone disabled defaults are
therefore distinct legal configurations rather than padding conventions.

Generic ABI validation recognizes both `enabled=0` and the future `enabled=1`
state. Task 4 startup, readiness, reuse, and replay are narrower: they require
`enabled=0`, and must treat an otherwise valid enabled config as not ready until
Task 6 owns guarded activation.

The activation flag defaults to disabled until privileged field evidence
passes. The safe disabled behavior is still parser-correct: ambiguous TCP/UDP
fragments drop explicitly instead of entering CT with invented ports.

Map maximum entries are selected by the loader before eBPF load because they
are map properties, not mutable packet-path configuration. Invalid versions,
modes, padding, timeouts, or activation combinations prevent ACL/CT readiness.
Userspace validation always receives the expected runtime mode, so a managed
runtime cannot accept a standalone config or vice versa.

Runtime identity and group projection are independent dimensions but are not
passed as independent raw arguments. Managed registration selects a
`ManagedReplayRoute` from `ManagedAttachMode`; its constructor always carries
managed fragment identity while its projection is either `Managed` or
`StandaloneCompatibility`. `StandaloneReplayRoute` is fixed to
`StandaloneCompatibility` projection plus standalone fragment identity, and
only the explicitly named `replay_standalone_state_to_pinned_maps` wrapper uses
it. The private replay implementation accepts only those typed routes.

Managed compatibility projection continues to reload `state_path` through the
WAL before replay, preserving the previous durable-snapshot authority; managed
projection continues to use the prepared in-memory snapshot.

The hosted behavior lane directly executes the production managed-route
selector for every `ManagedAttachMode` variant and the core route invariants.
It does not use `include_str!` or source-text matching to prescribe helper
spelling.

### 5.6 Capacity and lifetime

The initial maximum is 8192 contexts per family, matching Cilium's established
baseline. It is a bounded safety default, not a throughput claim. The loader
exposes it as a pre-load deployment setting, and field evidence reports pressure
under target traffic.

Lifetime uses `bpf_ktime_get_ns()`, defaults to 30 seconds, and is configurable
from 1 through 60 seconds. Context is not durable firewall state. An expired
lookup is accounted and dropped without packet-path deletion; a later valid
first fragment replaces that slot, while LRU eviction or a userspace scrub
provides eventual cleanup. Eviction, pressure, or update failure may drop a
datagram but must never fall back to zero or payload-derived ports.

The initial maps are global across taps, so sustained unique-fragment traffic
from one tap can evict another tap's context and cause availability loss. Key
isolation prevents cross-tap authorization, but does not claim per-tenant
capacity fairness. Activation evidence must exercise this pressure case; any
future per-tap map-of-maps or quota is a DDoS-capacity enhancement, not a reason
to weaken miss handling.

## 6. Parser Requirements

### 6.1 IPv4

Parse and validate IHL, total length, Identification, MF, fragment offset, byte
offset, and bytes available inside IP total length. Non-initial fragments never
read TCP/UDP ports, flags, sequence, header length, or payload length.

A first TCP fragment must contain the complete base header and the full header
selected by TCP data offset. A first UDP fragment must contain all eight bytes.
The current four-byte port-pair fallback is invalid for tracked first fragments.

### 6.2 IPv6

Bounded extension-header traversal extracts Fragment Identification, offset,
and M. Non-initial payload is never treated as an upper-layer header. Atomic
fragments follow ordinary processing. Reaching the traversal bound without an
upper-layer header is malformed/unsupported, not a zero-port packet.

### 6.3 Tiny and overlapping fragments

The first fragment records its payload end. Every later fragment must start at
or after it. A lower offset is an overlap with the authoritative first range and
is dropped. This intentionally rejects ambiguous fragmentation without adding a
full non-initial range-set reassembler.

## 7. TC Data Flow

Fragment resolution runs after tap and direction are resolved, the authority
snapshot is captured, and feature flags are loaded, but before
`CtKey4`/`CtKey6` construction.

After tap resolution, each TC packet samples the active ACL bank and fragment
epoch exactly once into private pipeline scratch. Fragment resolution, CT
expected-bank validation, banked ACL LPM/policy selection, and first-context
installation reuse that same packet snapshot. This is one-packet authority
consistency, not a cross-map atomicity claim. A missing epoch fails closed only
for participating first or non-initial fragments; ordinary unfragmented and
IPv6 atomic packets continue without fragment authority.

### 7.1 First fragment

1. validate complete L4 authority and retain real ports;
2. reuse the packet's bank and epoch snapshot;
3. run CT lookup plus normal ACL/QoS/Mirror/trace processing, but defer a CT
   miss insertion for a tracked first fragment;
4. do not install an allow context for a final drop;
5. for final pass, insert context before creating a new CT entry;
6. convert insert failure to an explicit resource drop without a CT delete;
7. after successful context installation, create the CT entry with
   `BPF_NOEXIST` and continue the accepted path.

Context insertion deliberately uses `BPF_ANY`: a valid allowed first fragment
may replace a live, expired, or stale entry for the same key so that fragment-ID
reuse can make progress. This is distinct from CT creation, which remains
`BPF_NOEXIST` and occurs only after a tracked first fragment has installed its
context. A same-key ID collision while two datagrams overlap remains a
residual ambiguity: the latest valid first fragment becomes the recovered-port
authority. The implementation does not claim that this theoretical collision
is a proven authorization bypass because every later packet still traverses
current CT/ACL policy with the recovered tuple.

This is an explicit availability-first conflict contract, not an accidental
map-update detail. An accepted first fragment is the freshest trustworthy
authority, so it wins even when the old value has not yet expired. The packet
path must not use permanent `BPF_NOEXIST`, delete-then-insert, or a pre-lookup
followed by a conditional insert: those alternatives either let an expired
entry block legitimate fragment-ID reuse, create an authority gap, or introduce
a lookup/update race. `BPF_ANY` also means that overlapping datagrams which
reuse the complete context key can be classified with the newest accepted
ports; late fragments from the older datagram may therefore be allowed or
dropped according to the newer tuple. We accept that bounded ambiguity to
preserve normal forwarding, while keeping these safety limits:

- only a completely parsed first fragment whose final pipeline action is pass
  may publish or replace context;
- a map update failure drops that first fragment before it creates a CT entry,
  and never deletes a same-key CT entry that another packet may have replaced;
- a non-initial fragment never creates authority, guesses ports, or bypasses a
  missing, expired, stale, overlapping, or otherwise invalid context;
- expiry remains replace-on-next-valid-first-fragment rather than packet-path
  deletion, so legal ID reuse is never dependent on a cleanup race.

For unfragmented, atomic, and resolved non-initial packets, CT-miss creation
remains immediately after policy/QoS acceptance. Only a tracked first fragment
moves CT creation after context installation. A pre-existing legitimate CT hit
is never deleted when context installation fails.

### 7.2 Non-initial fragment

1. parse only L3 and fragment metadata, leaving L4 zero;
2. build the context key from resolved tap/direction/VLAN;
3. reject miss or expiry;
4. require exact bank and epoch;
5. reject overlap with the first authoritative range;
6. copy cached ports into scratch and construct the normal CT key;
7. run the existing ACL/CT path with that recovered tuple.

Current ACL lookup still decides the action; context authorizes only the cached
ports and epoch, keeping policy accounting and bank semantics centralized.

The last fragment does not delete context because it may arrive before a middle
fragment. Absolute expiry or LRU eviction performs eventual removal.

### 7.3 CT and TCPRT

All fragments with recovered context use the same ordinary five-tuple CT key.
They never create or refresh zero-port or payload-derived entries.

Non-initial TCP fragments do not contain authoritative flags, sequence, or TCP
payload boundaries, so they must not create, advance, or refresh TCPRT. A valid
first TCP fragment may continue through TCPRT.

Policy/rule counters, CT lookup/touch/create attempts, QoS token consumption,
and skb EDT updates occur while deciding an attempted packet and are not rolled
back if a later context insert fails. Final PASS trace, mirror, accepted-flow
and group statistics, and TCPRT remain after successful context installation.
Documentation and telemetry must distinguish decision/attempt effects from
final-pass effects.

For a resolved non-initial fragment, protocol-filtered trace selection and
emitted trace events use the private recovered effective protocol together with
the recovered ports; `PacketInfo.proto` remains immutable parser metadata.
Trace selection is re-evaluated after resolution. Tap-only trace filters are
still evaluated before resolution, so they can observe missing-context drops.

At TC only, an Ethernet frame positively identified as IPv4 or IPv6 (including
one 802.1Q tag) must not fail open when full parsing fails. The datapath first
uses the existing safe `pull_data(0)` and reparses with refreshed pointers for a
possibly non-linear skb. A second failure is `TC_ACT_SHOT` with stable
`malformed-ip` drop accounting. Non-IP/unsupported Ethernet remains pass, and
the intentionally neutral XDP parser-failure behavior is unchanged.

## 8. Failure And Recovery Matrix

| Condition | Required result |
| --- | --- |
| non-initial before first | drop: context missing |
| expired context | retain entry, account expiry, and drop; later valid first may replace |
| bank or epoch mismatch | drop: stale context |
| different tap/direction/VLAN | no match and drop |
| incomplete first L4 header | drop: invalid fragment L4 |
| overlap with first range | drop: fragment overlap |
| context update failure for allowed first | drop: update failed |
| LRU eviction | later miss/drop; never zero-port fallback |
| epoch advance failure | abort publication before bank switch |
| recovery context scrub or final-empty verification failure | keep fragment tracking disabled and runtime not ready |
| any missing/wrong fragment runtime map | fail readiness; no partial legacy fallback |

Fragment context is ephemeral and not restored from WAL. During attach, agent
restart, pinned-runtime recovery, or uncertain inventory lineage, lifecycle code
first validates all five exact runtime maps (V4/V6 LRU context, hash epoch/hash
config, and per-CPU-array `u64` metrics), writes and reads back the mode-specific
disabled config, then clears both context maps before readiness. This validates
map type and ABI shape, not program-to-map identity; Task 7 retains that
privileged proof.

LRU eviction may race a userspace sweep. A remove-time `KeyNotFound` is treated
as already clear and the sweep continues; any other iteration/removal error is
strict. Tap-scoped scrub completes V4 and V6, verifies that neither family has
a matching key, and only then deletes that tap's epoch. Global recovery verifies
both maps are empty after the sweep. Because disabled config is established
before clear, a remaining or concurrently appearing entry is a strict recovery
failure and readiness is not published. Map absence or ABI mismatch cannot fall
back to current behavior.

## 9. Observability

Add distinct drop reasons for context missing, expired, stale, update failure,
invalid/incomplete first L4, and overlap. Expose first/non-initial counts,
hits/misses, inserts/failures, expiry/stale counts, and per-family occupancy or
pressure. Existing drop profiling retains tap, direction, and protocol.

Trace carries recovered ports only after a successful hit and identifies that
they came from fragment context. Operators must distinguish ACL deny from
tracking capacity loss.

Stable map structs, configuration, metrics, and drop identifiers are exported
through `abi::userspace`. Resolve/install decisions and helper classifiers are
private datapath/test machinery kept only at crate root; they are not part of
the supported userspace ABI surface.

## 10. Activation And Compatibility

The implementation produces identical TC behavior for standalone and managed
Neutron, `MODE=system`, and `MODE=tap`; it does not depend on OVS `ct`, nftables,
or Security Group processing.

Until guarded real-tap smoke passes, the new compatibility capability remains
production-disabled as required by repository policy. The pre-activation safety
behavior for ambiguous TCP/UDP fragments is explicit drop, not current unsafe
parsing. After field evidence passes, tracking is mandatory whenever ACL or Aria
conntrack is enabled; disabling it while either remains enabled is rejected by
runtime admission.

Pinned-map inventory recognizes the new maps and versions. An old runtime is not
ready until map create/migration and the recovery scrub/epoch barrier complete.

## 11. Test Contract

### 11.1 Raw parser fixtures

Cover IPv4/IPv6 unfragmented, first/middle/last, IPv6 atomic, IPv4 options,
bounded IPv6 extensions, truncation, four-byte-only L4, offset/MF/M handling,
and payload bytes resembling allowed/denied ports. The decisive regression is
that non-first IPv4 payload never populates any L4 field.

### 11.2 Rust behavior tests

Prove:

- ordered fragmented UDP/53 allow passes every fragment;
- fragments after first may reorder and retain one tuple;
- non-initial-before-first drops;
- denied first creates no allow context;
- IPv4/IPv6 parity;
- isolation across tap, direction, VLAN, family, protocol, address, and ID;
- expiry is not refreshed;
- bank/epoch invalidation, including two bank rotations;
- update failure drops first;
- eviction causes miss/drop, never fallback;
- tiny/overlapping fragments reject;
- recovered fragments share first-fragment CT;
- non-initial TCP never advances TCPRT;
- epoch integration covers standalone, managed, and recovery publication;
- restart clears uncertain context before readiness.

Tests bind public behavior/ABI, not private helper names or source layout. No
new Python source parser/checker is allowed.

### 11.3 CI and field smoke

Commit RED before production implementation and prove an intended RED-only CI
failure. GREEN includes focused Rust behavior plus warning-denied userspace and
eBPF builds. No local Cargo command is run.

Privileged evidence must use real pinned maps and raw IPv4/IPv6 fragments in
both TC directions,
including ordered, post-first reordered, later-before-first, tap/VLAN isolation,
publication invalidation, restart recovery, and bounded pressure/eviction in
the temporary standalone capacity-8 fixture. Managed smoke preserves deployed
capacity. `update_failed` remains a hosted Rust/eBPF contract because the LRU
map and public configuration expose no safe deterministic field trigger.

The 2026-08-06 legacy-kernel tap run satisfied this matrix, including bounded
capacity pressure and cleanup. The sanitized result is recorded in
`docs/evidence/openstack-n05-lite/20260806-acl-high-risk-field-acceptance/summary.md`.
Field verification does not activate the shipped production gate by itself.

### 11.4 Hosted implementation evidence

- Parser/context RED: commits `ec5e6ce..bdbbdc0`, Builds
  [29694226731](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29694226731)
  and [29694579684](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29694579684);
  parser/ABI GREEN: `e97ea7c`, Build
  [29696020281](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29696020281).
- Datapath GREEN: `99292d0`, final Build
  [29727166995](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29727166995);
  lifecycle/recovery GREEN: `e3d2543`, Build
  [29735595296](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29735595296).
- Publication-fence RED: Build
  [29741601036](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29741601036);
  GREEN: `e98ce03`, Build
  [29742110581](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29742110581).
- Guarded activation/recovery GREEN: `32bd37f`, Build
  [29822186960](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29822186960);
  observability GREEN: `5af1ac0`, Build
  [29827817509](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29827817509).
- Guarded field wiring head `e4bac0c` passed Build
  [29941244612](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29941244612);
  no privileged packet execution is claimed.
- Final-review RED `dd35fb2` failed only on the missing CT-create ordering and
  per-packet reset contracts in Build
  [29942509813](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29942509813).
  GREEN `43e0e2a` passed `fast-contracts`, `rust-behavior`, and warning-denied
  Rust/eBPF/static builds in Build
  [29943612716](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29943612716).
- Privileged legacy-kernel `MODE=tap` execution on 2026-08-06 passed the complete
  dual-stack, dual-direction, ordering, isolation, epoch, restart, pressure,
  eviction, and cleanup matrix. See the sanitized high-risk field acceptance
  summary linked above.

## 12. Scope Boundaries

Included: parser metadata, ABI/map types, epoch integration, TC resolution,
CT/TCPRT semantics, observability, loader/inventory support, behavior tests,
and deferred smoke wiring.

Excluded: full reassembly, waiting for a missing first fragment, public ACL
source-port/priority changes, OVS/Netfilter delegation, ACL-059, remaining
`DEBT-ACL-001`, L7 normalization, and IPv6 jumbograms.

## 13. Implementation Order After Spec Approval

1. add host raw-parser and ABI/behavior RED tests;
2. prove expected RED in hosted CI;
3. add parser metadata and shared map ABI;
4. add bounded context lookup/insert/expiry;
5. resolve context before CT keys in both TC directions;
6. integrate strict epochs into standalone, managed, and recovery paths;
7. add observability, loader, inventory, and status surfaces;
8. prove hosted GREEN and warning-free builds;
9. preserve the passing field evidence while keeping production activation
   disabled;
10. activate only through a separate change-controlled rollout.

## 14. External Baseline

- <https://docs.cilium.io/en/latest/network/concepts/fragmentation/>
- <https://github.com/cilium/cilium/blob/main/bpf/lib/ipv4.h>
- <https://github.com/cilium/cilium/blob/main/bpf/lib/ipv6.h>
- <https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks>
- <https://www.openvswitch.org/support/dist-docs/ovs-ofctl.8.pdf>
- <https://docs.openvswitch.org/en/latest/ref/ovs-actions.7/>
- <https://www.rfc-editor.org/rfc/rfc5722.html>
- <https://www.rfc-editor.org/rfc/rfc6946.html>

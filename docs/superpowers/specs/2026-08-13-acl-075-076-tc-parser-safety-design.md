# REVIEW-ACL-075/076 Bounded TC Parser Safety Design

**Status:** source implementation and exact-head hosted CI complete; maintained
enterprise 4.18 target-kernel evidence deferred/pending

**Date:** 2026-08-13

**Owning findings:** `REVIEW-ACL-075`, `REVIEW-ACL-076`; the merged consequence
record `REVIEW-ACL-087` is covered here and has no independent implementation.

## 1. Decision

Keep the TC direct-parse fast path, but replace the current ambiguous fallback
with one bounded and explicit contract:

1. positively classify the Ethernet frame as IPv4 or IPv6;
2. parse directly from the current linear head while validating IP wire lengths
   against the complete skb length;
3. if a required header byte is not linear, pull at most the first 256 bytes of
   the skb and parse once more with refreshed packet pointers;
4. if the bounded pull or second parse fails, drop the supported-IP packet with
   an existing stable reason instead of bypassing ACL, CT, QoS and fragment
   tracking.

The parser accepts at most eight supported IPv6 extension headers and at most
256 bytes from the start of the frame through the required transport header.
Packets outside that declared parser envelope are dropped, not passed around
the enforcement pipeline.

Non-IP Ethernet remains pass-through. XDP parser failure remains neutral/pass.
Per-CPU scratch lookup failure remains the separately documented fail-open OVS
availability boundary. This batch changes only packet-derived TC parse failure.

## 2. Verified Current Defects

### 2.1 Parse failure bypasses the complete TC pipeline

Both `tc_ingress` and `tc_egress` currently return `TC_ACT_OK` when
`parse_tc_packet` returns false. Commit `8bab0b8` made this an intentional
fail-open behavior and added a Python source checker that requires the private
function body to keep that spelling.

That behavior combines distinct conditions which require different treatment:

- a valid IPv6 packet with more than four supported extension headers reaches
  the current fixed walk limit and then bypasses ACL, CT, QoS and fragment
  tracking for the whole flow;
- an incomplete first TCP/UDP fragment passes without installing fragment
  context, while its non-initial fragments are later dropped, producing an
  asymmetric first-packet pass and a reassembly denial of service;
- a required transport header located in paged skb data follows the same bypass
  path even though the packet may be valid.

The first is a substantive enforcement bypass. The second is not a complete
flow bypass, but still violates the first-fragment contract and forwards bytes
which the policy pipeline never authorized.

### 2.2 `pull_data(0)` cannot repair paged header access

`parse_tc_packet` calls `TcContext::pull_data(0)` and then reparses. The Linux
helper implementation passes `skb_headlen(skb)` when the requested length is
zero, both in upstream
[`v4.18`](https://github.com/torvalds/linux/blob/v4.18/net/core/filter.c#L1755-L1767)
and
[`v6.11`](https://github.com/torvalds/linux/blob/v6.11/net/core/filter.c#L1862-L1874).
It can make the existing head writable, but does not ask the kernel to extend
that head into paged data.

The Aya wrapper delegates the provided length directly to the kernel helper.
The kernel implementation, not the wrapper prose, is authoritative for the
maintained enterprise 4.18 backport boundary. Target-kernel execution remains
required before field closure.

### 2.3 The raw parser conflates wire length with linear bytes

The IPv4 parser currently requires `ip_total_len <= data_end - ip_offset`; the
IPv6 parser similarly requires the complete advertised payload to fit before
`data_end`. At TC, `data_end` bounds direct access to the current linear head,
not necessarily the complete skb wire length.

Only header bytes that are actually dereferenced must be linear. Requiring the
whole payload to be linear causes valid GRO/non-linear packets to enter the
broken fallback even when all required headers are already available.

## 3. Contract Reconciliation

This design narrows, rather than removes, the repository's fail-open
availability contract.

| Condition | Result after this batch | Reason |
| --- | --- | --- |
| Aria program cannot load or attach | OVS forwarding remains authoritative | Existing deployment availability contract. |
| Required per-CPU packet/pipeline scratch is unavailable | `TC_ACT_OK` | Existing internal-resource fail-open contract; not controlled by packet bytes. |
| Ethernet is not supported IPv4/IPv6 | `TC_ACT_OK` | Outside the current IP policy parser. |
| XDP parser cannot classify/parse | `XDP_PASS` | XDP remains neutral and independent from TC ACL/CT. |
| TC positively identifies IPv4/IPv6 but bounded parsing fails | `TC_ACT_SHOT` | Untrusted packet shape or unavailable required bytes must not bypass enforcement. |

The legacy stack-budget document's scratch-failure rule does not authorize a
packet to manufacture a parse failure and bypass policy. The ACL fragment
design's intended TC fail-closed rule remains correct, but its reference to a
"safe `pull_data(0)`" is technically wrong and will be corrected when GREEN
lands.

## 4. Parser Envelope

### 4.1 Separate wire length from direct-access boundary

Both raw IP parsers receive two independent bounds:

- `data_end`: the last byte currently safe for direct pointer dereference;
- `wire_len`: the complete frame length reported by the hook.

The parsers use `wire_len` only for scalar protocol length validation. They
must never form a packet pointer from an untrusted advertised IP length. Every
Ethernet, VLAN, IP, extension and transport-header dereference remains guarded
against `data_end`.

At XDP, `wire_len = data_end - data`, so behavior is unchanged. At TC,
`wire_len = ctx.len()`, allowing a packet whose payload is paged to parse when
the required header prefix is already linear.

### 4.2 Bounded pull

Define one explicit parser budget:

```text
TC_PARSE_LINEAR_BYTES = 256
pull_len = min(ctx.len(), TC_PARSE_LINEAR_BYTES)
```

The helper is called only after the direct parse fails. The argument is never
zero for a frame already classified as supported IP. All packet pointers are
refreshed after the helper because `bpf_skb_pull_data` invalidates previous
direct-access checks.

The budget is measured from the start of Ethernet, not as an additional byte
count. It covers:

- Ethernet plus one 802.1Q tag;
- the IPv4 maximum 60-byte header or the IPv6 40-byte base header;
- eight minimum-size supported IPv6 extension headers;
- the TCP maximum 60-byte header or UDP 8-byte header;
- more than 70 bytes of verifier/performance margin for the worst supported
  minimum-extension TCP shape.

The implementation must not call `pull_data(ctx.len())`: forcing a complete
large GSO skb linear would introduce unbounded copy cost into the TC path.

### 4.3 IPv6 extension bound

Raise the fixed supported extension-header count from four to eight. Retain a
compile-time bounded loop suitable for the maintained verifier. The currently
recognized header set remains Hop-by-Hop Options, Routing, Destination Options
and Fragment; this batch does not introduce new IPsec or mobility semantics.

The two limits are cumulative:

- up to eight recognized extension headers may be traversed;
- the complete required header prefix must fit within the 256-byte linear
  budget after the fallback pull.

A ninth recognized header or a header chain whose required prefix exceeds the
budget is a stable malformed/unsupported parser-envelope drop. This is an
intentional bounded security policy: unusual traffic may be rejected, but it
cannot skip enforcement.

### 4.4 Remove the suspicious-zero TCP retry

The current second `pull_data(0)` branch guesses that TCP is truncated when
flags and sequence are both zero. Those values are legal packet data and are
not a reliable linearity signal.

After wire length and direct-access length are separated, `parse_transport`
succeeds only when the complete selected TCP header is directly readable. A
failed header bound triggers the single bounded fallback; a successful parse
needs no value-based retry. Remove this branch.

## 5. TC Failure Classification And Accounting

Add one small pure parser result classifier. It consumes the preserved
`PacketInfo` failure marker and returns an existing nonzero drop reason:

```text
0                         = parse succeeded
DROP_FRAGMENT_INVALID_L4  = final parse proved incomplete first-fragment L4
DROP_MALFORMED_IP         = every other supported-IP parse/pull failure
```

`parse_tc_packet` returns that scalar rather than a conditional enum payload.
This matches the legacy-verifier rule against forwarding conditionally
initialized aggregate payloads across BPF calls. A pull-helper error always
returns `DROP_MALFORMED_IP`; it must not reuse an invalid-L4 marker from the
pre-pull attempt because the paged bytes were never inspected.

The mapping is exact:

| Parse failure | Existing reason | Extra metric |
| --- | --- | --- |
| incomplete TCP/UDP header on a first IPv4/IPv6 fragment | `DROP_FRAGMENT_INVALID_L4` | increment existing family-specific invalid-L4 fragment metric |
| every other supported-IP parse/pull failure | `DROP_MALFORMED_IP` | none in this batch |

Ingress and egress use the returned reason and the same drop-recording helper.
For `DROP_FRAGMENT_INVALID_L4`, the existing `invalid_l4_failure` accessor
supplies the proven family/protocol; every other failure uses the already
classified family and protocol zero. The drop record uses the current
interface-to-tap lookup, packet length, direction, zero group IDs, and current
kernel time. Both entry points then return `TC_ACT_SHOT`.

No new reason code, map ABI, trace-result ABI or public API is required.
`REVIEW-ACL-098` remains responsible for additive fragment-specific trace
result attribution; this batch must not claim that work.

## 6. Runtime Sequence

```text
TC ingress/egress
  -> classify Ethernet family
     -> unsupported/non-IP: existing raw-mirror path, TC_ACT_OK
     -> supported IPv4/IPv6:
          -> parse(linear data_end, complete wire_len)
             -> success: existing ACL/CT/QoS/fragment pipeline
             -> failure:
                  -> pull min(wire_len, 256)
                  -> refresh data/data_end
                  -> parse once more
                     -> success: existing pipeline
                     -> failure/pull error:
                          classify stable reason
                          record metrics/drop
                          TC_ACT_SHOT
```

There is no loop around the helper and no full-skb retry.

## 7. Failure Matrix

| Scenario | Required result |
| --- | --- |
| ordinary linear IPv4/IPv6 | direct parse; no helper call |
| non-linear payload with complete linear headers | direct parse using full wire length; no helper call |
| L4 header partly paged but ends within byte 256 | bounded pull, refreshed pointers, successful parse |
| bounded pull returns an error | stable supported-IP drop |
| parse still fails after pull | stable supported-IP drop |
| incomplete first-fragment TCP/UDP header | invalid-fragment-L4 drop and metric |
| valid chain with five through eight minimum extension headers | parse and enforce normally |
| ninth supported extension header | malformed/parser-envelope drop |
| required extension/header prefix exceeds 256 bytes | malformed/parser-envelope drop |
| non-IP Ethernet | unchanged pass-through |
| missing packet scratch | unchanged pass-through |
| XDP parse failure | unchanged `XDP_PASS` |

## 8. RED And GREEN Evidence

The existing host-side raw parser fixture is the executable behavior boundary.
RED commit `cb9deb5` added tests to
`abi/tests/fragment_parser_contract.rs` covering:

1. IPv4 and IPv6 packets whose complete wire length exceeds the simulated
   linear head but whose required headers are linear;
2. a transport header which becomes readable only after the declared bounded
   prefix is available;
3. pull-length selection for short and large frames, proving nonzero and the
   256-byte cap;
4. five and eight recognized IPv6 extension headers parsing successfully;
5. a ninth recognized extension header returning a drop-classified failure;
6. malformed supported IPv4/IPv6 mapping to `DROP_MALFORMED_IP`;
7. incomplete first-fragment TCP/UDP mapping to
   `DROP_FRAGMENT_INVALID_L4` with family and protocol preserved;
8. non-IP remaining an unsupported/pass candidate.

The old Python test which parses private TC function bodies to demand
`TC_ACT_OK` is removed. It is not replaced by an inverse source checker.
Behavior belongs in Rust tests and the compiled eBPF artifact gates.

The exact-head RED Build
[`31695043494`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31695043494)
failed in `rust-behavior` only on the intended missing parser signature,
constants and failure classifier. `fast-contracts` passed; the older production
eBPF artifact and stack-budget gate passed before the remaining RED run was
cancelled after the expected failure was captured.

GREEN commit `29636e6` implemented the separate wire/direct bounds, one bounded
TC pull, eight-header limit, stable drop classification, and identical ingress
and egress behavior. Its exact-head Build
[`31695508165`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31695508165)
passed:

- `fast-contracts`, including the remaining legacy packet-bound structural
  contracts;
- `rust-behavior` with warnings denied;
- `rust-build`, including warning-denied eBPF compilation and the 448-byte
  linked-artifact stack budget;
- the linked-artifact stack gate with `tc_ingress` and `tc_egress` both at 448
  bytes on their maximum call paths.

No local Cargo command is allowed.

## 9. Target-Kernel Evidence

Hosted tests can model the linear/wire split but cannot create a real paged skb
or prove the enterprise 4.18 backport's verifier/helper behavior. Field closure
therefore requires a guarded target-kernel case which demonstrates:

1. ordinary linear IPv4/IPv6 forwarding remains unchanged;
2. a non-linear/GRO packet with L4 bytes outside the initial head is parsed and
   enforced after the bounded pull;
3. a five-header IPv6 packet reaches ACL/CT rather than bypassing it;
4. an over-budget chain and an incomplete first L4 fragment are dropped with
   the expected counters;
5. both ingress and egress programs remain within the accepted legacy verifier
   and attachment contract.

Until that environment exists, this evidence is `deferred/pending`. Hosted CI
must not be relabeled as target-kernel execution.

## 10. Files And Scope

Production and RED/GREEN work is limited to:

- `ebpf/src/parser.rs`: wire/linear bounds, extension limit, pull budget helper
  and pure failure classification;
- `ebpf/src/lib.rs`: XDP/TC call-site lengths, one bounded TC retry and stable
  TC drop wiring;
- `abi/tests/fragment_parser_contract.rs`: executable parser behaviors;
- `ci/test_ebpf_legacy_packet_bounds.py`: remove only the contradictory private
  fail-open source assertion and its unused import;
- the ACL-056 fragment design, this design, the implementation plan and the
  REVIEW register for evidence/status updates.

Explicitly excluded:

- no XDP storm/DDoS behavior;
- no fragment context ABI or timeout change;
- no ACL, CT, QoS or Mirror policy semantic change after parsing succeeds;
- no new trace result ABI (`REVIEW-ACL-098`);
- no fragment group-attribution change (`REVIEW-ACL-099`);
- no generic packet-parser framework, tail-call conversion or full skb
  linearization;
- no private Rust source checker.

## 11. Acceptance

1. No positively identified IPv4/IPv6 TC packet can receive `TC_ACT_OK` solely
   because bounded full parsing failed.
2. Valid common non-linear packets do not require their payload to be copied
   into the linear head.
3. The fallback requests a nonzero `min(packet_len, 256)` and reparses exactly
   once with refreshed pointers.
4. Five through eight supported minimum extension headers reach normal policy
   processing; over-count or over-byte-budget chains are dropped, never
   bypassed.
5. Incomplete first TCP/UDP fragments keep the existing exact reason and
   invalid-L4 metric.
6. XDP, non-IP pass-through and scratch-failure availability contracts remain
   unchanged.
7. The eBPF artifact compiles with warnings denied and remains within the
   448-byte legacy stack budget.
8. Target-kernel evidence remains visibly pending until it actually runs.

# Legacy-Kernel eBPF Stack Budget Design

Date: 2026-08-04

Status: approved architecture baseline; implementation in progress

Analyzed target: `origin/v0.9-neutron-agent@850832b`

## 1. Executive Decision

The TC data path will use a map-backed per-CPU packet context, a bounded BPF
call graph, and an exact maintained-kernel load gate.

The immediate implementation will:

- move primary and TCP-RT-derived `CtKey4` and `CtKey6` construction out of
  BPF function stack frames;
- retain the existing `PKT_SCRATCH` and `PIPE_SCRATCH` model;
- keep the worst analyzed BPF call path at or below 448 bytes;
- require both TC entry programs to load on the maintained Rocky Linux 8
  kernel before an artifact is deployable;
- preserve fail-open behavior so an Aria load or scratch failure cannot block
  the original OVS forwarding path.

The first implementation will not convert the whole TC pipeline to tail calls.
Tail-call stage isolation is the defined second-level architecture and is used
only if the bounded-call implementation cannot maintain the 448-byte budget.

## 2. Problem Statement

The current release artifact compiles successfully but is rejected by the
maintained kernel verifier for both `tc_ingress` and `tc_egress`:

```text
combined stack size of 5 calls is 544. Too large
```

The kernel limit is 512 bytes. The 544-byte value is the worst combined nested
BPF-to-BPF call path, not one 544-byte local variable.

The current pipeline already avoids two large stack allocations:

- `PacketInfo` lives in `PKT_SCRATCH`;
- `PipelineCtx` lives in `PIPE_SCRATCH`.

Later TC unification and fragment recovery added longer-lived `CtKey4` and
`CtKey6` locals plus new resolve, install, conntrack, policy, and post-accept
call paths. Each individual frame remains bounded, but the maintained 4.18
verifier accumulates the worst nested path beyond 512 bytes.

Changing one `#[inline]` annotation is not an architectural fix. An isolated
experiment that forced the CT-miss phases inline increased the verifier result
from 544 to 576 bytes and was reverted.

## 3. Maintained Compatibility Contract

The maintained minimum environment is the exact deployed distribution kernel:

```text
4.18.0-553.5.1.el8_10.x86_64
```

Enterprise BPF backports differ from an upstream version with the same major
and minor number. Therefore:

- a successful Rust build is necessary but not sufficient;
- acceptance on a newer kernel is not evidence of 4.18 acceptance;
- the exact maintained-kernel verifier is the final compatibility authority;
- ingress and egress must be tested independently;
- IPv4, IPv6, fragmented, and non-fragmented paths remain in scope.

### 3.1 TC attachment contract on the maintained kernel

Aya selects legacy netlink TC below kernel 6.6 and TCX on kernel 6.6 or newer.
Only TCX links can be converted to `FdLink` and pinned in bpffs. Therefore TC
readiness has two explicit implementations rather than treating a legacy
netlink link as a failed TCX link:

```text
kernel >= 6.6: TCX attach -> exact program/link identity -> pinned link
kernel <  6.6: detach stale exact-name Aria filter -> netlink attach ->
               kernel-owned filter -> exact-name tc health check
```

The legacy path is constrained as follows:

- cleanup targets only the exact Aria program names `tc_ingress` and
  `tc_egress` on the selected interface and direction;
- a missing prior filter is an idempotent success;
- non-missing netlink or query errors fail the attach transaction;
- the successfully attached legacy link is deliberately handed to the kernel
  instead of being dropped by Aya and detached immediately;
- graceful rollback and detach remove the exact-name legacy filters;
- after an agent crash, the next attach first removes any stale exact-name
  filter, preventing duplicate filters before reattachment;
- readiness requires both directions to be observed in `tc filter show`; an
  in-memory attach flag alone is not sufficient;
- any attach or health uncertainty leaves ACL/CT bypassed and OVS forwarding
  untouched.

Aria does not add, delete, or restart OVS bridges, OVS processes, or the
Neutron OVS agent while managing either TC attachment mode.

## 4. Stack Architecture

### 4.1 Per-CPU scratch ownership

Use two two-entry per-CPU scratch maps:

```text
CT_KEY4_SCRATCH: PerCpuArray<CtKey4>
CT_KEY6_SCRATCH: PerCpuArray<CtKey6>
```

Only the map matching the packet family is accessed. Slot ownership is fixed:

```text
slot 0: primary ACL/conntrack key owned by the TC family wrapper
slot 1: derived TCP-RT forward/reverse key owned by TCP-RT helpers
```

The owner writes key fields directly into the map value and passes that
map-value reference to conntrack, flow statistics, or TCP-RT helpers. TCP-RT
auto-direction handling reuses slot 1 sequentially and calls the TCP-RT core
directly; it must not nest through a reverse-key constructor that reuses the
same slot.

The implementation must not first construct a local `CtKey4` or `CtKey6` and
then copy it into the map because that can preserve the same stack temporary.

The scratch maps are execution-local infrastructure:

- they contain no desired state, accepted state, statistics, or recovery data;
- they are not critical network maps;
- they are not replayed, migrated, exported, or included in WAL semantics;
- they are not added to `NETWORK_MAP_NAMES`, `ALL_MAP_NAMES`, or either critical
  map list;
- their value ABI may change with the eBPF artifact because no persistent data
  depends on them.

The first linked-artifact measurement after moving only the primary keys was
576 verifier-charged bytes. Its worst path included 160 bytes for the TCP-RT
auto frame and 96 bytes for the nested reverse-key frame. This evidence is why
slot 1 and the direct auto-to-core path are part of the baseline rather than a
separate feature expansion.

Existing map-backed packet contexts remain unchanged in the first pass. The
implementation must not enlarge `PipelineCtx` merely to absorb every future
temporary.

### 4.2 Scratch failure behavior

If a required scratch lookup returns no value, the TC program returns
`TC_ACT_OK` for that packet.

This is a deliberate fail-open invariant:

- Aria does not drop the packet;
- Aria does not detach or restart OVS;
- Aria does not restart `neutron-openvswitch-agent`;
- the original OVS forwarding path remains authoritative;
- a per-CPU error counter records the bypass when verifier-compatible
  instrumentation is available without increasing the critical stack path.

Observability must not be allowed to turn scratch failure into a data-plane
failure. If recording the counter is itself unavailable, pass still wins.

### 4.3 BPF function rules

The TC call graph follows three logical phases:

```text
entry and packet authority
  -> conntrack, ACL, and QoS decision
  -> accepted-packet state and observability
```

The following rules apply to all code on these paths:

- packet-lifetime structures larger than 32 bytes use per-CPU scratch or an
  existing map value;
- map values remain borrowed and are not copied into local structures;
- cross-function outcomes use initialized scalars or fields in map-backed
  context, not conditional enum payloads;
- large arrays and keys are never returned by value;
- local lifetimes end before entering unrelated phases where practical;
- `#[inline(always)]` and `#[inline(never)]` are verifier decisions supported
  by measured evidence, not code-style decisions;
- a phase split is not accepted merely because each individual frame is under
  512 bytes; the combined entry path is the budgeted unit.

## 5. Stack Budget

The kernel hard limit remains 512 bytes. The project release budget is lower:

| Measurement | Budget |
|---|---:|
| Worst combined path from either TC entry | 448 bytes maximum |
| Reserved compatibility and compiler margin | 64 bytes minimum |
| Any single unexpectedly growing frame | review required |

The 448-byte budget avoids accepting an artifact that only happens to reach
exactly 512 bytes with one compiler version. Stack use is an artifact property,
so it is measured after the release eBPF object is built.

The combined-path calculation matches the maintained 4.18 verifier: every
function frame is charged as `round_up(max(frame_bytes, 1), 32)` before call
path accumulation. Reports retain both the raw frame and verifier-charged size.

The report must include at least:

- `tc_ingress` worst path and total;
- `tc_egress` worst path and total;
- each function on the worst path;
- each function's analyzed frame size;
- comparison with the previous accepted artifact.

The exact-kernel verifier remains authoritative if static ELF analysis and the
kernel disagree. A static false negative must fail closed at release time: the
artifact is not deployable until the disagreement is understood.

## 6. Build And Release Gates

Rust and eBPF compilation runs in GitHub Actions. The developer workstation may
run source-contract tests and read-only ELF analysis, but it does not produce a
deployable Rust or eBPF binary.

The release sequence is:

```text
source-contract tests
  -> GitHub Actions Rust/eBPF build
  -> ELF stack and call-graph report
  -> isolated maintained-kernel load canary
  -> minimum allow/drop traffic canary
  -> deployable artifact approval
```

The maintained-kernel canary uses a temporary veth pair, network namespace,
private bpffs directory, and temporary agent state. It must not use a live VM
tap, restart OVS, or modify production pin paths.

The canary passes only when:

- `tc_ingress` loads and attaches;
- `tc_egress` loads and attaches;
- the verifier reports no uninitialized stack or packet-bound error;
- the analyzed worst path is at most 448 bytes;
- allow traffic passes;
- a minimum ACL drop case drops;
- cleanup removes every temporary link, namespace, pin, and state directory.

On the maintained 4.18 kernel, the canary expects legacy netlink TC health and
does not require impossible TCX link pins. It still requires both exact Aria
program names to be live and both traffic verdicts to pass.

Legacy TC ownership is derived from the live kernel inventory, not from a
process-local flag. With JSON-capable `tc`, each direction must expose exactly
one matching program name and its program ID must equal the corresponding
program pinned in the private bpffs runtime. On the maintained environment's
older `tc`, which has no `-j` support and omits program IDs from text output,
the fallback requires exactly one matching program name and the same kernel
BPF program tag as the pinned program. A missing match is not ready; a
duplicate name or identity mismatch is an ownership conflict and must not be
detached or claimed. The fallback does not accept name-only ownership.

The canary artifact and the deployable artifact must have identical SHA-256
hashes.

## 7. Tail-Call Capacity Boundary

Tail calls are the defined escalation path, not the first implementation.

Tail-call stage isolation is required when either condition is true:

- scratch-backed bounded calls still exceed 448 bytes on the maintained
  kernel; or
- a planned data-plane capability cannot fit while preserving at least 64
  bytes of stack margin.

The future stage model is:

```text
TC entry: parse, tap authority, fragment resolution
  -> tail call: conntrack, ACL, QoS decision
  -> tail call: CT create, statistics, Mirror, Trace, TCP-RT
```

State crosses stages only through the map-backed packet context. A tail-call
target is populated before any entry program is attached. A missing or failed
tail call returns `TC_ACT_OK`, increments a bounded failure metric when safe,
and is surfaced as datapath degraded/bypass by the agent.

Before this design is activated, the exact maintained kernel must load-probe
the required `PROG_ARRAY`, TC tail-call behavior, and Aya loader lifecycle. No
support is inferred from a newer development kernel.

## 8. Deployment And Rollback

The first deployment remains an isolated canary. After it passes, rollout is
one compute node at a time.

For each node:

1. Preserve the last accepted agent and eBPF artifact hashes.
2. Load the new artifact without changing OVS or Neutron OVS-agent state.
3. Prove both TC directions ready before marking the datapath ready.
4. Run a managed-port allow/drop smoke.
5. Roll back immediately if either direction is absent or verifier loading
   fails.

Rollback restores the last accepted Aria artifact. It never restarts OVS or
`neutron-openvswitch-agent`.

## 9. Acceptance Matrix

| Area | Required evidence |
|---|---|
| Build | GitHub Actions Rust and eBPF build green |
| Stack | Both TC worst paths at most 448 bytes |
| Kernel | Exact maintained 4.18 load canary green |
| Families | IPv4 and IPv6 load and packet smoke |
| Fragments | Initial and non-initial fragment paths load and remain bounded |
| Conntrack | CT hit and CT miss paths exercised |
| ACL | allow and deny paths exercised |
| Directions | ingress and egress independently proven |
| Failure | scratch and attach failure preserve `TC_ACT_OK`/OVS forwarding |
| Cleanup | no canary namespace, veth, bpffs, or state residue |
| Rollback | previous accepted artifact restores readiness |

## 10. Non-Goals

This work does not:

- add QoS, Mirror, Trace, DDoS, or tenant-visible features;
- change Neutron ACL semantics or RPC behavior;
- redesign conntrack state semantics;
- restart or manage OVS lifecycle;
- introduce tail calls unless the recorded trigger is reached;
- refactor unrelated eBPF programs such as SSL uprobes or kernel-drop probes;
- make scratch state persistent or observable through product APIs.

## 11. Implementation Order

The approved implementation order is intentionally narrow:

1. Add source contracts that reject stack-local `CtKey4` and `CtKey6` on the
   four TC family paths.
2. Add the two non-persistent per-CPU key scratch maps.
3. Rewrite the four family wrappers to initialize map values field by field.
4. Build only through GitHub Actions.
5. Generate and review the ELF stack report before any remote load attempt.
6. Run the isolated maintained-kernel canary.
7. Continue measured call-graph reduction only if the artifact exceeds 448.
8. Activate the tail-call design only if the recorded trigger is reached.
9. Roll out to compute nodes only after the canary and rollback evidence pass.

This order fixes the current compatibility blocker while preserving a clear
architectural boundary against both verifier regressions and unnecessary
rewrites.

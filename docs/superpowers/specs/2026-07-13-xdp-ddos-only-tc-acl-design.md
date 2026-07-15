# XDP DDoS-Only And TC-Unified ACL/CT Design

Date: 2026-07-13

Status: implemented; GitHub Build green; privileged runtime evidence pending

Supersedes the standalone/XDP compatibility portions of
`2026-07-12-acl-batch-6-tc-unified-datapath-design.md`.

## Implementation Status

The final all-mode implementation is present at code commit
`89b81e94ac7a6aaaf98295132a9b09d556b99796`. Complete GitHub Build
[29297316622](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/29297316622)
passed Python stages, targeted Rust authority/recovery tests, nightly eBPF,
static userspace/agent builds, and binary verification. Local non-Cargo gates
also passed, including 283 Stage 1 tests, both smoke mutation checkers, the
datapath checker, shell syntax, and `git diff --check`.

Whole-branch reliability review added four final hardening boundaries after
the first green checkpoint:

- CT entries created while ACL was disabled do not receive the
  `ACL_EVALUATED` flag and cannot become ACL fast-path hits merely because
  their stored bank happens to match;
- managed and system restart reuse requires exact live dual-TCX identity, not
  only surviving pin paths;
- partial global runtime updates and reads propagate missing/corrupt map state
  instead of synthesizing enabled defaults;
- the guarded standalone smoke preserves bpffs across healthy and incomplete
  restarts, proves the incomplete gate is quiesced, and then proves recovery.

The normal Build runs syntax and structure/mutation contracts; it does not run
the privileged netns/tap smokes. No privileged environment with the built
artifacts was available during this implementation. `REVIEW-ACL-055` is
therefore `likely-fixed`. It becomes `fixed` only after preserved passing
summaries exist for standalone `MODE=system`, standalone `MODE=tap`, and the
managed-Neutron smoke.

`REVIEW-OPS-036` separately records that XDP hook health is still path-only and
can false-pass for a detached-but-pinned link. This does not affect ACL/CT
readiness because XDP is neutral and TC is authoritative. Exact XDP live-link
identity is required before implementing or advertising the future DDoS
domain.

## Goal

Make TC ingress and TC egress the only ACL/conntrack enforcement hooks in every
runtime mode:

- Neutron-managed taps;
- local tap-managed standalone instances;
- system standalone instances.

XDP remains available as a separate early hook, but it no longer implements,
selects, accelerates, restores, or accounts ACL/CT. The current batch leaves
XDP as an ACL/CT-neutral pass path and reserves it for a future independent
DDoS domain.

## Confirmed Boundaries

1. XDP never falls back to ACL, even when TC attach or readiness fails.
2. XDP currently performs no DDoS enforcement. No DDoS rules, maps, agent
   domain, API, rate limiter, mitigation state, or metrics are added here.
3. ACL and CT are authoritative in TC ingress and TC egress for Neutron and
   standalone modes.
4. An ACL/CT-enabled runtime requires both TC links. A single-direction TC
   runtime must not report ready or continue partial ACL/CT enforcement.
5. XDP attach health is independent of ACL readiness. Until the DDoS domain is
   implemented, XDP failure is explicit and degraded but does not block a
   healthy TC ACL runtime.
6. Existing ACL, CT, policy, bank, and statistics map ABIs remain unchanged.
7. `TapConfig` remains exactly eight bytes.
8. QoS, Mirror, Trace, TCP-RT, and future DDoS product expansion are outside
   this change except where their existing TC ordering must be preserved.
9. GitHub Actions remains the Rust/eBPF build authority. No local Cargo build,
   check, or test is permitted.

## Existing Problems This Design Closes

The current Batch 6 implementation moved Neutron ingress ACL/CT to TC but
retained legacy standalone ingress ACL/CT in XDP. That leaves two ingress
architectures, two recovery modes, and a hook selector capable of reactivating
the old path.

The final branch review also found two implementation blockers:

1. A fresh or rebuilt managed runtime can replay persisted ACL/CT enable flags
   before its links are attached. Because the ingress-hook byte is not
   persisted as desired state, the new map entry can default to XDP and expose
   stale enforcement before a Neutron full resync.
2. Active-bank and generic partial runtime updates swallow every map read error
   through `.ok()`. A real read failure can therefore be treated as an absent
   key and synthesize an enabled default configuration.

Removing XDP ACL is not sufficient by itself. The attach transaction, runtime
gate, old-pin behavior, and map error contract must change with the datapath.

## Considered Approaches

### A. Preserve The ABI And Retire The Selector — Selected

Keep the final `TapConfig` byte and the mirrored constants so old pinned maps
and mixed-version binaries remain layout compatible. Stop using the byte as a
datapath selector:

- XDP is always ACL/CT-neutral;
- TC ingress always runs the ingress ACL/CT pipeline;
- control-plane writers normalize the compatibility byte to `TC=1`;
- old zero and unknown values cannot select XDP ACL or suppress TC ACL.

This removes the unsafe branch without forcing a pinned-map rebuild.

### B. Retain The Selector And Migrate Every Stored Value

Rewrite old zero values to TC before activating links, while keeping the XDP
and TC branches. This was rejected because any missed writer, replay path, or
old pin can restore split enforcement.

### C. Remove The Byte And Break The Map ABI

Replace `TapConfig` with a new layout and require full pinned-runtime rebuild.
This gives a cleaner type but creates unnecessary upgrade and rollback risk.

## Datapath Architecture

### XDP

The XDP program retains only the minimal entry/parsing scaffolding needed to
keep the hook loadable and to provide a clear future DDoS insertion point. In
this batch its verdict is always `XDP_PASS`.

Before returning, XDP must not:

- read `TapConfig` ACL or CT flags;
- read the ingress-hook compatibility byte;
- read an ACL bank, selector, policy, group, or CT entry;
- create, update, expire, or remove an ACL CT entry;
- update ACL rule, flow, group, drop, bank, or CT contract statistics;
- call any legacy XDP ACL/CT phase.

The future DDoS stage belongs before `XDP_PASS` and owns independent maps,
configuration, state, verdict reasons, and metrics. It must not reuse ACL banks
or ACL CT entries.

### TC Ingress

TC ingress is unconditional with respect to `acl_ingress_hook`. Neutron and
standalone runtimes use the same decision sequence:

```text
resolve runtime and direction
  -> build the IPv4 or IPv6 CT key
  -> bank-aware CT lookup when CT is enabled
     -> current-bank hit: restore cached policy metadata and skip ACL
     -> miss/expired/stale/disabled: evaluate the active ACL bank
  -> ACL drop: account and return
  -> existing ingress QoS and post-processing
  -> QoS drop: account and return
  -> create CT on an accepted miss when CT is enabled
  -> return pass
```

The legacy TC-ingress post-processing-only branch is removed. Family-specific
leaf helpers may remain for verifier constraints, but they must implement the
same ordering.

### TC Egress

TC egress keeps the existing unified ACL/CT contract and uses the same hit,
miss, stale-bank, post-processing, and CT-create semantics as TC ingress. Only
direction-specific keys and post-processing parameters differ.

Each direction performs at most one authoritative CT lookup per packet. XDP
never adds a second ingress observation, so CT packet and byte counters retain
their documented per-TC-hook meaning.

## ABI And Mixed-Version Compatibility

`TapConfig` remains eight bytes and keeps the existing field offsets. The last
byte remains named `acl_ingress_hook` for source and pin compatibility, but it
is deprecated as a selector.

The control plane writes `ACL_INGRESS_HOOK_TC` for every new, replayed, or
partially updated per-tap configuration. Datapath code does not branch on the
field. Reads used for inventory may expose the stored value, but no readiness
or verdict depends on it.

This is safe in both mixed-version directions:

- new control plane plus old Batch 6 eBPF writes `TC=1`, which selects the old
  TC path;
- old control plane plus new eBPF may leave `0`, but new XDP still passes and
  new TC ingress still enforces.

A rollback to the current Batch 6 eBPF remains safe after normalization because
the stored value is TC. No upgrade step may first disable the TC path while old
XDP has already stopped enforcing.

System standalone uses `FIREWALL_CONFIG` rather than the per-tap hook selector,
but the same new eBPF artifact makes its XDP path neutral and TC path
authoritative.

## ACL/CT Readiness

ACL/CT readiness is independent of XDP readiness.

For a runtime with either ACL or CT enabled:

- TC ingress must be attached and its pinned/live identity validated;
- TC egress must be attached and its pinned/live identity validated;
- the required runtime maps and schema must be valid;
- the runtime gate may become enabled only after all checks succeed.

If ACL and CT are both disabled, the instance may start without TC ACL
readiness. Existing non-ACL features retain their own contracts and are not
silently promoted into ACL dependencies by this design.

XDP remains default-attached. An XDP attach failure is reported separately as
the future DDoS hook being unavailable. It neither blocks a healthy TC ACL
runtime nor triggers an ACL fallback.

## Startup And Recovery Transactions

### Fresh Or Rebuilt Runtime

The persisted desired state is loaded separately from the live runtime gate.
Rules and maps may be staged, but the live gate is first forced to:

```text
conntrack=false, acl=false, acl_ingress_hook=TC
```

Programs are then attached while the gate is quiesced. Both TC links are
verified before publication.

- Standalone restores its persisted desired ACL/CT flags atomically after both
  TC links are live.
- Neutron remains quiesced until an authoritative full resync stages and
  publishes the desired ACL/CT state.

Any failure before publication leaves ACL/CT disabled, rolls back links created
by the transaction where safe, and returns an explicit error.

### Healthy Pre-Existing Pinned Runtime

Last-known-good ACL/CT may remain active only when the ifindex, map/schema
inventory, runtime identity, TC ingress link, and TC egress link are all
verified as the exact expected live runtime.

Standalone can claim that runtime directly. Neutron may preserve the committed
datapath during restart, but its ACL authority/status remains degraded and
full-resync-required until the controller republishes authoritative state.

### Incomplete Or Stale Pinned Runtime

If either TC link or any required identity/schema check fails, the agent must:

1. prevent ready publication;
2. quiesce ACL/CT on any surviving live path when the map is safely writable;
3. report blocked/degraded with a stable reason;
4. never select XDP ACL;
5. rebuild only through the existing safe dormant-runtime boundary.

### Runtime Link Loss

TC readiness uses both event-driven detection and a low-frequency safety poll:

- netlink, OVS rebuild, attach, and runtime reconcile events validate both
  links immediately;
- a default ten-second poll validates the ifindex, TC ingress link, TC egress
  link, and expected pinned/live identities for ACL/CT-enabled runtimes;
- the poll runs outside the packet path and serializes its transition through
  the existing per-interface/runtime locks;
- a failed observation is revalidated under the lock before state changes,
  preventing a concurrent successful reattach from being treated as loss;
- repeated observations of the same failure are deduplicated instead of
  producing an unbounded warning stream.

Confirmed disappearance of either TC link marks ACL/CT not ready and quiesces
the surviving direction. The agent must not silently run a single-direction
firewall.

The safety poll is a detector, not a second recovery engine. It does not loop
on automatic reattach or restore ready by observation alone. Recovery uses the
normal attach/reconcile transaction; Neutron still requires authoritative full
resync where documented.

This is a control-plane fail-closed contract: Aria refuses to claim enforcement.
Because XDP is no longer an ACL hook, a missing TC hook cannot be converted into
an XDP packet-drop fallback by this change.

## Runtime Update And Error Contracts

Every request that changes ACL or CT from disabled to enabled must verify both
TC links immediately before publishing the gate. Policy maps may be staged
while disabled, but staged state is not reported as enforced.

Pinned-map lookup handling is strict:

- `KeyNotFound` is the only result that may be classified as absent;
- all other map errors propagate with map name and tap identifier;
- `set_acl_active_bank` requires an existing initialized `TapConfig` and never
  synthesizes enabled defaults;
- generic per-tap partial updates require an existing initialized
  `TapConfig`;
- only an explicit full-initialization path may create a missing config;
- partial updates preserve every unrelated field and normalize the compatibility
  byte to TC.

These rules close both the restart reactivation gap and the read-error/default
synthesis bug found by final branch review.

## Status And Observability

ACL status reports TC ingress and TC egress readiness separately in its reason
details while preserving the existing public ready/degraded/blocked model.
Neither `attach=ready` nor an XDP link is sufficient evidence for ACL ready.

XDP status is a separate hook-health signal. Until a DDoS domain exists, it
must not advertise DDoS enforcement merely because the XDP program is attached.

Existing ACL/CT/rule counters are updated only in TC. A static and runtime test
must prove that XDP does not change them. Future DDoS counters will use a
separate namespace.

## Test Strategy

### Pure Rust Contracts

- `TapConfig` size and field offsets remain unchanged.
- Old zero and unknown hook values cannot select XDP ACL or suppress TC ingress.
- Full initialization and partial updates write/preserve TC normalization.
- Non-`KeyNotFound` map errors propagate.
- Active-bank and partial updates fail when per-tap config is absent.
- ACL/CT enable transitions require both TC links.
- Standalone restores only after dual-TC readiness.
- Neutron fresh/rebuilt recovery remains quiesced until full resync.
- Healthy old pins and incomplete old pins take the distinct recovery paths.
- Event-driven checks and the ten-second safety poll detect either TC link
  loss, clear readiness, and prevent continued partial enforcement status.
- Poll detection is revalidated under the runtime lock, deduplicates repeated
  faults, and cannot restore ready outside the normal recovery transaction.

### Source-Structure Contracts

A brace-aware checker verifies:

- XDP contains no ACL/CT/bank/rule-stat calls in any mode;
- TC ingress contains no hook-selector or legacy post-processing-only branch;
- TC ingress and egress both perform family-correct bank-aware CT lookup;
- hit paths skip ACL and miss paths preserve ACL, QoS, post-processing, then CT
  creation ordering;
- all relevant runtime writers normalize the compatibility byte to TC;
- readiness checks cover both TC link pins.
- the health loop uses the documented interval and delegates state changes to
  the shared dual-TC readiness transition.

### GitHub Build Gates

GitHub Actions runs the Rust contracts, nightly eBPF build, binary verification,
static userspace/agent builds, Python stages, shell syntax, and source-structure
checkers. No local Cargo command is used.

### Integration Evidence

- The guarded disposable netns/veth fixture is prepared to validate system
  standalone ingress and egress TC enforcement without changing a host
  production interface.
- The guarded tap-managed standalone fixture is prepared to validate dual-TC
  readiness, restart restore, missing-link rejection, and exact TC-only ACL/CT
  accounting.
- The guarded Neutron managed-tap smoke is prepared to validate ingress/egress
  stateful and stateless ACL, deny behavior, strict bank transition, exact CT
  packet/byte accounting, and full-resync publication.
- Negative mutations prove that removing either expected TC readiness marker
  fails the static/smoke contract.

Code and CI evidence may move the tracked item to likely-fixed. Only preserved
real runtime evidence may move it to fixed.

## Documentation Updates

- Mark the 2026-07-12 design as superseded for standalone XDP ACL, hook-selector
  semantics, XDP-required ACL readiness, and related acceptance tests.
- Update the implementation plan rather than editing completed task history in
  place; the new work receives explicit follow-up tasks.
- Keep `REVIEW-ACL-055` `likely-fixed` after the complete all-mode Build. Its
  previous green builds remain historical/superseded evidence, not closure
  evidence. Promote to `fixed` only after all three privileged runtime
  summaries are preserved and pass.
- Keep `REVIEW-ACL-056` separate. Fragment semantics are not changed here.

## Acceptance Criteria

1. XDP executes no ACL or ACL CT operation in any runtime mode.
2. XDP has no effect on ACL, CT, bank, rule, flow, or group counters.
3. TC ingress and TC egress are the only ACL/CT authority paths for Neutron and
   standalone.
4. No datapath verdict or readiness decision branches on
   `acl_ingress_hook`.
5. `TapConfig` remains eight bytes and old zero-valued pins cannot cause an ACL
   bypass.
6. Every ACL/CT enable transition requires verified TC ingress and egress.
7. Fresh/rebuilt standalone restores desired ACL/CT only after both links are
   live.
8. Fresh/rebuilt Neutron runtime remains quiesced until authoritative full
   resync.
9. Healthy exact pinned runtimes and incomplete pinned runtimes follow the
   documented distinct recovery paths.
10. Losing either TC link prevents ready/enable and does not leave silent
    single-direction ACL enforcement; event detection is backed by a default
    ten-second safety poll.
11. Map read failures cannot synthesize a default enabled configuration.
12. XDP readiness is independent of ACL readiness and does not advertise a
    DDoS feature that is not implemented.
13. No DDoS product surface or unrelated QoS/Mirror feature is added.
14. GitHub CI passes, and backlog closure remains gated on the documented real
    runtime smoke evidence.

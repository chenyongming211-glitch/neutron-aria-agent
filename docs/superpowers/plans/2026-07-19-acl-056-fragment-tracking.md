# ACL-056 Fragment Tracking Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make IPv4 and IPv6 TCP/UDP fragments selected by destination-port ACLs use authoritative first-fragment ports, one ACL publication epoch, and one CT tuple without allowing payload-derived or zero-port bypass.

**Architecture:** Add shared fragment ABI types and host-testable parser metadata, then place two bounded LRU context maps in front of TC CT-key construction. First fragments establish context only before an allowed packet returns; non-initial fragments recover ports only when tap, direction, VLAN, bank, epoch, lifetime, and first-range checks pass. A per-tap epoch is advanced after shadow staging and before every ACL bank switch, while recovery clears ephemeral context before readiness.

**Tech Stack:** Rust workspace, `no_std` ABI crate, Aya/aya-ebpf TC programs, pinned BPF maps, GitHub Actions `rust-behavior` and `rust-build`, Bash privileged smoke.

## Global Constraints

- Work only on local and remote `v0.9-neutron-agent`; do not create branches, worktrees, or PRs.
- Do not run local Cargo commands. Commit and push each RED/GREEN checkpoint; GitHub Actions is the Rust/eBPF execution authority.
- Preserve TC ingress and TC egress as the only ACL/CT authorities; XDP remains ACL/CT-neutral.
- Preserve the public ACL model: no source-port field, no datapath priority arbitration, and controller-side overlap validation.
- Fragment tracking is production-disabled until guarded privileged evidence passes; disabled mode must safely drop ambiguous TCP/UDP fragments.
- No Python source-shape checker may bind private Rust helpers, argument order, variables, or module layout.
- Field evidence remains `deferred/pending` until a real environment exists.
- Map baseline is 8192 entries per family; timeout defaults to 30 seconds and accepts only 1 through 60 seconds.

---

## File Structure

- Create `abi/src/fragment.rs`: stable key/value/config types and pure context-validation contract.
- Create `abi/tests/fragment_parser_contract.rs`: raw IPv4/IPv6 frame fixtures that include the real eBPF parser.
- Create `abi/tests/fragment_context_contract.rs`: public context identity, expiry, epoch, and overlap tests.
- Modify `abi/src/lib.rs`: export fragment ABI, drop reasons, flags, and Aya Pod types.
- Modify `ebpf/src/parser.rs`: complete fragment metadata and safe L4 parsing.
- Create `ebpf/src/fragment.rs`: context lookup, expiry, insert, recovery, and drop mapping.
- Modify `ebpf/src/maps.rs`: V4/V6 context, epoch, configuration, and metrics maps.
- Modify `ebpf/src/lib.rs`: resolve context before CT keys, insert before first-fragment pass, and skip non-initial TCPRT.
- Create `core/src/ebpf_ops/fragment.rs`: pinned map open, configure, epoch advance, scrub, and status operations.
- Modify `core/src/ebpf_ops.rs`, `core/src/ebpf_ops/scrub.rs`, `core/src/ebpf_ops/inventory.rs`, and `core/src/ebpf_ops/replay.rs`: exports, lifecycle cleanup, inventory, and recovery.
- Modify `agent/src/control_plane/standalone_acl.rs` and `agent/src/control_plane.rs`: epoch fence in standalone and managed publications.
- Modify `agent/src/instance.rs`: critical-map pin inventory and load-time capacity.
- Modify `agent/src/main.rs`, `config/aria-agent.toml`, and `deploy/kolla/config/aria-agent-openstack.toml`: disabled activation, timeout, and capacity inputs.
- Modify `agent/src/api_handlers/metrics.rs` and `core/src/monitoring.rs`: fragment counters and pressure/status projection.
- Modify `deploy/smoke/aria_standalone_acl_tc_datapath_smoke.sh` and `deploy/kolla/smoke/neutron_aria_acl_tc_datapath_smoke.sh`: guarded field evidence scenarios.
- Modify `ci/check_neutron_stage1.py`: discover named fragment behavior tests and syntax-check existing smoke entrypoints only.
- Modify `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`: record RED, GREEN, CI, and pending field evidence without claiming runtime execution.

### Task 1: Commit Parser And Context RED Contracts

**Files:**
- Create: `abi/tests/fragment_parser_contract.rs`
- Create: `abi/tests/fragment_context_contract.rs`
- Modify: `ci/check_neutron_stage1.py`

**Interfaces:**
- Consumes: current `ebpf/src/parser.rs` through `#[path = "../../ebpf/src/parser.rs"]`.
- Produces: tests named `fragment_parser_*` and `fragment_context_*`; later tasks implement `FragmentKind`, `FragmentContextKey4`, `FragmentContextValue`, `fragment_context_disposition`, and parser fields used here.

- [ ] **Step 1: Add raw-frame parser RED tests**

Create a root `common` shim so the real parser compiles in a host integration test, then construct Ethernet/IP bytes directly:

```rust
mod common {
    pub use aria_ebpf_abi::{IPPROTO_TCP, IPPROTO_UDP};
}

#[path = "../../ebpf/src/parser.rs"]
mod parser;

use aria_ebpf_abi::{FragmentKind, IPPROTO_UDP};
use core::mem::MaybeUninit;

unsafe fn parse_v4(frame: &[u8]) -> parser::PacketInfo {
    let mut out = MaybeUninit::<parser::PacketInfo>::zeroed();
    assert!(parser::parse_eth_ipv4(
        frame.as_ptr() as usize,
        frame.as_ptr() as usize + frame.len(),
        0,
        out.as_mut_ptr(),
    ));
    out.assume_init()
}

#[test]
fn fragment_parser_ipv4_non_initial_never_reads_payload_as_ports() {
    let frame = ipv4_fragment(IPPROTO_UDP, 0x1234, 1, false, &[0x00, 0x35, 0x13, 0x89]);
    let info = unsafe { parse_v4(&frame) };
    assert_eq!(info.fragment_kind, FragmentKind::NonInitial as u8);
    assert_eq!((info.src_port, info.dst_port), (0, 0));
    assert_eq!((info.tcp_flags, info.tcp_seq, info.payload_len), (0, 0, 0));
}
```

Add equivalent cases for IPv4 first UDP, IPv4 four-byte-only UDP rejection, IPv6 first/non-initial, IPv6 atomic, offset bytes, and an IPv6 extension chain.

- [ ] **Step 2: Add fragment-context RED tests**

```rust
use aria_ebpf_abi::{
    fragment_context_disposition, FragmentContextDisposition, FragmentContextKey4,
    FragmentContextValue,
};

#[test]
fn fragment_context_rejects_two_bank_rotation_epoch_reuse() {
    let value = FragmentContextValue {
        src_port: 40000,
        dst_port: 53,
        first_payload_end: 1480,
        acl_bank: 0,
        flags: 0,
        version: 1,
        _pad: 0,
        _reserved: [0; 6],
        epoch: 7,
        expires_at_ns: 30_000_000_000,
    };
    assert_eq!(
        fragment_context_disposition(&value, 0, 9, 1_000, 1480),
        FragmentContextDisposition::Stale,
    );
}
```

Cover exact identity layout, current hit, expiry boundary, overlap, and bank mismatch.

- [ ] **Step 3: Register the behavior filter**

Add the following command once to `RUST_TESTS`:

```python
["test", "--locked", "-p", "aria-ebpf-abi", "--features", "aya-pod", "fragment_"],
```

Do not add a source parser to the Python checker.

- [ ] **Step 4: Commit and push RED**

```bash
git add abi/tests/fragment_parser_contract.rs abi/tests/fragment_context_contract.rs ci/check_neutron_stage1.py
git -c user.name=netmouser -c user.email=chenyongming211@gmail.com commit -m "test: define fragment-safe ACL semantics"
git push origin v0.9-neutron-agent
```

Expected GitHub result: `fast-contracts` passes; `rust-behavior` fails only because fragment ABI/parser fields are absent; unrelated selected Rust tests remain green. Record the run ID before continuing.

### Task 2: Implement Shared ABI And Safe Parser Metadata

**Files:**
- Create: `abi/src/fragment.rs`
- Modify: `abi/src/lib.rs`
- Modify: `ebpf/src/parser.rs`

**Interfaces:**
- Consumes: Task 1 test names and raw frames.
- Produces: `FragmentKind`, `FragmentContextKey4`, `FragmentContextKey6`, `FragmentContextValue`, `FragmentConfig`, `FragmentEpochValue`, `FragmentContextDisposition`, and `fragment_context_disposition`; complete `PacketInfo` fragment fields.

- [ ] **Step 1: Add stable fragment ABI**

Implement explicit `repr(C)` types in `abi/src/fragment.rs`:

```rust
#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FragmentKind { Unfragmented = 0, First = 1, NonInitial = 2, Atomic = 3 }

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FragmentContextKey4 {
    pub tap_id: u32, pub src_ip: u32, pub dst_ip: u32,
    pub fragment_id: u16, pub vlan_id: u16,
    pub proto: u8, pub direction: u8, pub _pad: [u8; 2],
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct FragmentContextValue {
    pub src_port: u16, pub dst_port: u16, pub first_payload_end: u16,
    pub acl_bank: u8, pub flags: u8, pub version: u8, pub _pad: u8,
    pub _reserved: [u8; 6],
    pub epoch: u64, pub expires_at_ns: u64,
}
```

Define the IPv6 key with `[u8; 16]` addresses and `u32 fragment_id`. Define config version 1, disabled flag, two timeout fields, and epoch value. Implement disposition ordering: version, expiry, bank/epoch, overlap, then hit.

- [ ] **Step 2: Export ABI and add layout assertions**

Add `mod fragment; pub use fragment::*;`, include new map types in the `aya::Pod` implementation list, and assert exact sizes/offsets in `critical_map_layouts_remain_stable` plus new `fragment_map_layouts_are_stable`.

- [ ] **Step 3: Implement IPv4 classification and complete first L4 validation**

Read total length, ID, flags/offset, normalize offset by multiplying the 13-bit value by eight, and never enter TCP/UDP parsing for `NonInitial`. Require the complete eight-byte UDP header and complete TCP data-offset-selected header for `First`.

- [ ] **Step 4: Implement IPv6 classification and atomic normalization**

Read the Fragment header ID/offset/M fields during bounded extension traversal. Preserve `Atomic` metadata for tests but allow ordinary L4 parsing. Do not parse L4 for `NonInitial`.

- [ ] **Step 5: Push parser/ABI GREEN**

```bash
/Users/chen/.cargo/bin/rustfmt --edition 2021 abi/src/lib.rs abi/src/fragment.rs abi/tests/fragment_parser_contract.rs abi/tests/fragment_context_contract.rs ebpf/src/parser.rs
git add abi/src/lib.rs abi/src/fragment.rs abi/tests/fragment_parser_contract.rs abi/tests/fragment_context_contract.rs ebpf/src/parser.rs
git -c user.name=netmouser -c user.email=chenyongming211@gmail.com commit -m "fix: parse IP fragments without L4 ambiguity"
git push origin v0.9-neutron-agent
```

Expected: fragment tests and ABI full suite pass; eBPF warning-denied build passes. `rustfmt` is formatting, not compilation, and is allowed locally.

### Task 3: Add Fragment Context Maps And TC Resolution

**Files:**
- Modify: `abi/src/fragment.rs`
- Modify: `abi/src/lib.rs`
- Create: `ebpf/src/fragment.rs`
- Modify: `ebpf/src/conntrack.rs`
- Modify: `ebpf/src/maps.rs`
- Modify: `ebpf/src/lib.rs`
- Modify: `ebpf/src/parser.rs`
- Modify: `ebpf/src/trace.rs`
- Modify: `abi/tests/fragment_context_contract.rs`
- Create: `abi/tests/fragment_parser_contract.rs`
- Modify: `docs/superpowers/specs/2026-07-19-acl-056-fragment-tracking-design.md`

**Interfaces:**
- Consumes: Task 2 ABI and parser metadata.
- Produces: `resolve_v4`, `resolve_v6`, `install_allowed_v4`, and `install_allowed_v6` behavior; V4/V6 context maps, config, epoch, and counters.

- [ ] **Step 1: Extend RED for datapath decisions**

Add pure behavior cases for disabled mode, missing context, first-range overlap,
exact hit, expired retain-and-drop classification, one-packet bank/epoch scratch,
supported Ethernet family recognition, malformed IP parsing, and
insert-before-pass failure. Keep datapath-only helpers at crate root rather than
expanding the stable `abi::userspace` surface.

- [ ] **Step 2: Define maps**

Add `FRAG_CONTEXT_V4` and `FRAG_CONTEXT_V6` as `LruHashMap` with 8192 entries, `FRAGMENT_EPOCH` and `FRAGMENT_CONFIG` as `HashMap`, and a bounded per-CPU fragment metric map. Do not use per-eviction counters because LRU eviction is not reported to the updating eBPF program.

- [ ] **Step 3: Resolve non-initial context before CT key construction**

In both TC directions, sample active bank and fragment epoch once after tap
resolution and before `CtKey4`/`CtKey6`, then call the family resolver. Reuse
that snapshot for resolve, CT bank validation, banked ACL lookup/policy, and
first-context install. On hit, copy only ports into packet scratch and retain
the recovered effective protocol privately. On miss/expiry/stale/overlap/
disabled, set a dedicated drop reason and return `TC_ACT_SHOT`; expiry does not
delete from the packet path.

- [ ] **Step 4: Install allowed first context before return pass**

After the existing pipeline determines final pass, insert the first-fragment
context with the packet bank/epoch snapshot and absolute expiry. Use `BPF_ANY`
so a valid first fragment can replace live/expired/stale authority for fragment
ID reuse. If insertion fails, remove a CT entry created by this packet and
return the update-failed drop. Do not remove a pre-existing CT hit.

Treat `BPF_ANY` as the required availability contract, not an implementation
option: the newest valid, finally allowed first fragment wins. Do not replace it
with permanent `BPF_NOEXIST`, delete-then-insert, or lookup-then-conditionally-
insert logic. Document the bounded same-key overlap risk, but preserve the hard
boundary that non-initial fragments without trustworthy context never invent
ports or pass solely to improve availability.

For ownership-safe cleanup, change `ct_create_v4` and `ct_create_v6` to use an
atomic no-overwrite insert and return only whether this packet successfully
inserted the entry. A pre-existing/racing entry or any insert failure is not
owned by this packet. Fragment-context failure removes CT only for that proven
owned outcome. This intentionally changes concurrent same-key creation from
last-writer overwrite to first successful insert wins without adding a generic
transaction framework.

- [ ] **Step 5: Exclude non-initial TCP from TCPRT**

Guard every TCPRT call with `fragment_kind != NonInitial`. Do not synthesize flags, sequence, or payload length from context.

Re-evaluate protocol-filtered trace after successful fragment resolution using
the private effective protocol, without mutating parser metadata. Preserve
tap-only visibility for missing-context drops. For TC supported IPv4/IPv6
frames, retry malformed/non-linear parsing with safe pull/reparse, then drop and
account persistent malformed input; leave non-IP Ethernet and XDP neutral.

Keep policy counters, CT attempts/touches, QoS tokens, and skb EDT as attempted-
packet effects before context insertion. Keep PASS trace/mirror, accepted flow
and group stats, and TCPRT after successful insertion.

- [ ] **Step 6: Commit and push datapath GREEN**

```bash
/Users/chen/.cargo/bin/rustfmt --edition 2021 abi/src/fragment.rs abi/src/lib.rs abi/tests/fragment_context_contract.rs ebpf/src/fragment.rs ebpf/src/conntrack.rs ebpf/src/maps.rs ebpf/src/lib.rs
git add abi/src/fragment.rs abi/src/lib.rs abi/tests/fragment_context_contract.rs ebpf/src/fragment.rs ebpf/src/conntrack.rs ebpf/src/maps.rs ebpf/src/lib.rs docs/superpowers/plans/2026-07-19-acl-056-fragment-tracking.md
git -c user.name=netmouser -c user.email=chenyongming211@gmail.com commit -m "fix: recover fragment ports before ACL conntrack"
git push origin v0.9-neutron-agent
```

Expected: fragment behavior passes and warning-denied eBPF build accepts bounded control flow.

### Task 4: Add Strict Userspace Epoch And Recovery Operations

Status: implemented on `v0.9-neutron-agent` with hosted CI evidence. Fragment
tracking remains disabled; Tasks 5-6 and privileged field evidence are pending.

**Files:**
- Create: `core/src/ebpf_ops/fragment.rs`
- Create: `core/src/ebpf_ops/fragment_tests.rs`
- Modify: `core/src/ebpf_ops.rs`
- Modify: `core/src/ebpf_ops/scrub.rs`
- Modify: `core/src/ebpf_ops/inventory.rs`
- Modify: `core/src/ebpf_ops/replay.rs`
- Modify: `agent/src/instance.rs`
- Modify: `agent/src/system_manager.rs`
- Modify: `ci/check_neutron_stage1.py`

**Interfaces:**
- Consumes: pinned map names and ABI from Tasks 2-3.
- Produces: `read_fragment_epoch`, `advance_fragment_epoch_strict`, `configure_fragment_tracking`, `scrub_fragment_contexts_strict`, and inventory/recovery proof.

- [x] **Step 1: Write epoch and recovery RED tests**

Use narrow injectable operations and in-memory fakes (not unprivileged fake
pinned maps) to prove missing epoch map errors, `u64::MAX` wrap rejection,
exact increment, per-tap isolation, V4/V6 LRU `KeyNotFound` continuation,
strict non-missing errors, final-empty verification before epoch deletion,
config-before-clear recovery ordering, and all five map-validator failure paths.
Add ABI authority tests for version-2 managed/standalone runtime modes: managed
enabled authority rejects `tap_id=0`, standalone enabled authority accepts its
`tap_id=0`, unknown modes fail, and their disabled defaults are distinct.

- [x] **Step 2: Implement pinned operations**

Open maps by exact names and exact key/value types. `FragmentConfig` version 2
uses explicit `runtime_mode` plus five zero padding bytes while preserving its
size and timeout offsets. `advance_fragment_epoch_strict` reads the per-tap
entry, rejects max, inserts `current + 1`, and reads back the value to verify
it. Missing/invalid maps return errors.

- [x] **Step 3: Integrate scrub and inventory**

Add both context maps, epoch, config, and metrics to critical pin inventory and
validate all five exact typed pins before readiness. Full tap scrub removes only
matching contexts, tolerates remove-time LRU `KeyNotFound`, verifies V4 and V6
empty, and only then removes the tap epoch. Uncertain shared-runtime recovery
writes the expected-mode disabled config before strictly clearing and verifying
both global context maps.

- [x] **Step 4: Configure load-time capacity and disabled default**

Set both context map capacities through `EbpfLoader` before load, validate 8192
default and positive configured values, then initialize version-2
mode-specific config with activation disabled and 30-second family timeouts.
Managed new/reused recovery requires managed mode; standalone recovery requires
standalone mode. Generic ABI validation recognizes enabled values `0/1`, but
Task 4 strict readiness/reuse/replay requires `enabled=0` and rejects a valid
future enabled config as not ready. Task 4 does not enable tracking or advance
publication epochs. Managed registration can retain standalone-compatible group
projection without changing fragment runtime identity: its production
`ManagedAttachMode` selector returns a typed managed replay route whose identity
is always `managed`. The typed standalone route is fixed to compatibility
projection plus `standalone` identity and is reachable only through the
explicitly named standalone replay wrapper. Filtered behavior tests execute the
production selector and route invariants directly; no source-shape checker is
used. The managed compatibility route retains its prior `load_with_wal`
durable-snapshot input, while managed projection retains the prepared snapshot.

- [x] **Step 5: Commit and push userspace GREEN**

```bash
/Users/chen/.cargo/bin/rustfmt --edition 2021 core/src/ebpf_ops.rs core/src/ebpf_ops/fragment.rs core/src/ebpf_ops/scrub.rs core/src/ebpf_ops/inventory.rs core/src/ebpf_ops/replay.rs agent/src/instance.rs
git add core/src/ebpf_ops.rs core/src/ebpf_ops/fragment.rs core/src/ebpf_ops/scrub.rs core/src/ebpf_ops/inventory.rs core/src/ebpf_ops/replay.rs agent/src/instance.rs
git -c user.name=netmouser -c user.email=chenyongming211@gmail.com commit -m "fix: manage fragment epoch and recovery state"
git push origin v0.9-neutron-agent
```

Expected: core fragment tests, existing replay/inventory tests, and static agent build pass.

### Task 5: Fence Standalone And Managed ACL Publication

**Files:**
- Modify: `agent/src/control_plane/standalone_acl.rs`
- Modify: `agent/src/control_plane.rs`
- Modify: `agent/src/neutron_api.rs`

**Interfaces:**
- Consumes: `advance_fragment_epoch_strict` from Task 4.
- Produces: one `AdvanceFragmentEpoch` plan phase after staging/general changes and before `SwitchBank` for every semantic ACL publication and gate transition.

- [ ] **Step 1: Add publication-order RED tests**

Extend standalone plan tests to assert:

```rust
assert!(position(StandaloneAclPublicationStep::StageShadow)
    < position(StandaloneAclPublicationStep::AdvanceFragmentEpoch));
assert!(position(StandaloneAclPublicationStep::AdvanceFragmentEpoch)
    < position(StandaloneAclPublicationStep::SwitchBank));
```

Add managed replacement, purge, gate disable/enable, and recovery cases under the existing `neutron_acl_` filters. Assert epoch failure leaves active bank and acknowledged state unchanged.

- [ ] **Step 2: Execute the epoch fence in standalone publication**

After shadow/general preparation and before active switch, call the strict operation. Do not roll epoch back during compensation. Add epoch failure as a pre-switch failure phase that scrubs the failed shadow and restores general-map mutations.

- [ ] **Step 3: Execute the same fence in managed publication and purge**

Place the call inside the existing lifecycle/instance lock and transaction boundary. Gate transitions and recovery establish a new epoch before reporting ACL ready.

- [ ] **Step 4: Commit and push publication GREEN**

```bash
/Users/chen/.cargo/bin/rustfmt --edition 2021 agent/src/control_plane/standalone_acl.rs agent/src/control_plane.rs agent/src/neutron_api.rs
git add agent/src/control_plane/standalone_acl.rs agent/src/control_plane.rs agent/src/neutron_api.rs
git -c user.name=netmouser -c user.email=chenyongming211@gmail.com commit -m "fix: fence ACL publication with fragment epochs"
git push origin v0.9-neutron-agent
```

Expected: all standalone/managed publication and rollback tests pass; existing CT strict-flush behavior remains green.

### Task 6: Add Configuration And Observability Contracts

**Files:**
- Modify: `agent/src/main.rs`
- Modify: `agent/src/instance.rs`
- Modify: `agent/src/tap_registry.rs`
- Modify: `agent/src/system_manager.rs`
- Modify: `agent/src/control_plane.rs`
- Modify: `agent/src/control_plane/observability.rs`
- Modify: `agent/src/api_handlers/metrics.rs`
- Modify: `core/src/ebpf_ops.rs`
- Modify: `core/src/ebpf_ops/fragment.rs`
- Modify: `core/src/ebpf_ops/replay.rs`
- Modify: `core/src/monitoring.rs`
- Modify: `abi/src/fragment.rs`
- Modify: `abi/src/lib.rs`
- Modify: `abi/tests/fragment_parser_contract.rs`
- Modify: `ebpf/src/parser.rs`
- Modify: `ebpf/src/fragment.rs`
- Modify: `ebpf/src/lib.rs`
- Modify: `config/aria-agent.toml`
- Modify: `deploy/kolla/config/aria-agent-openstack.toml`
- Modify: `docs/openstack-neutron-agent-mode.md`
- Modify: `docs/openstack-deployment-runbook.md`

**Interfaces:**
- Consumes: Task 3 metrics and Task 4 config operations.
- Produces: validated capacity/timeouts, guarded activation, exact fragment
  counters, and per-runtime/per-family pressure with explicit reason labels.

This expanded file boundary is required by the real loader, recovery,
publication-admission, and parser paths. Implement it as two sequential TDD
delivery segments on `v0.9-neutron-agent`; do not create a parallel branch and
do not change the Task 3 forwarding decision, `BPF_ANY`, expiry, or fragment-ID
reuse contracts.

- [x] **Step 1: Add Task 6A configuration and activation RED tests**

Test default `{enabled:false, max_entries:8192, ipv4_timeout_seconds:30, ipv6_timeout_seconds:30}`, reject zero entries, and reject timeout values outside 1..=60. Test that ACL/CT readiness rejects an explicit disabled setting after the field gate is marked verified.

- [x] **Step 2: Commit, push, and verify Task 6A RED**

Name the agent tests `fragment_loader_config_*` so the existing hosted
`rust-behavior` selector executes them. Do not add or expand a Python
source-shape checker. Verify that CI fails only because the configuration,
capacity propagation, recovery validation, and readiness admission are absent.

- [x] **Step 3: Implement Task 6A configuration and guarded activation**

Add immutable startup settings for `enabled`, `max_entries`, IPv4/IPv6 timeout,
and an independent field-evidence gate. Both shipped configuration bundles use
`enabled=false`, `field_verified=false`, `8192`, and `30/30`. Propagate capacity
to managed and standalone loaders. Recovery writes and reads back the expected
mode-specific config before scrub/readiness, and live reuse validates exact
config plus map capacity. Every ACL/CT enable or re-enable path performs
fragment readiness admission before publishing the gate; once field evidence
is marked verified, explicitly disabling tracking while ACL/CT is requested is
rejected.

- [x] **Step 4: Commit, push, and verify Task 6A GREEN**

Expected: Task 6A RED tests and existing fast contracts, Rust behavior, and
static builds pass; production activation remains disabled.

- [x] **Step 5: Add Task 6B observability RED tests**

Assert exact stable labels for first, non-initial, hit, miss, expired, stale, update-failed, invalid-L4, overlap, and pressure. Do not infer LRU eviction count.

- [x] **Step 6: Commit, push, and verify Task 6B RED**

Name the agent metrics tests `fragment_loader_metrics_*` so hosted
`rust-behavior` executes them. Extend the existing raw parser fixture for an
incomplete TCP/UDP first fragment. Verify that CI fails only because the exact
invalid-L4 signal and userspace projection are absent.

- [x] **Step 7: Implement Task 6B exact metrics and pressure**

Add a distinct shared ABI metric and TC parse-failure signal for incomplete
first-fragment L4. Do not relabel stored-context invalidity or generic malformed
IP as invalid-L4. The parser may retain only a validated first-fragment
family/protocol marker for this failure path and must not leave stale scratch
authority. Share the per-family metric-index calculation between eBPF and
userspace. Aggregate metrics once per unique runtime pin path because managed
taps share a runtime. Derive V4/V6 pressure from actual LRU occupancy divided by
the map's `max_entries`; never infer or label an LRU eviction count. On strict
map-read failure, omit the affected series and warn instead of publishing a
false zero.

- [x] **Step 8: Complete activation and observability documentation**

Wire counters and pressure through the existing control-plane accessor and
metrics handler. Documentation distinguishes implementation availability,
production activation, and field evidence. Real privileged evidence remains
`deferred/pending`; no document may claim field execution.

- [x] **Step 9: Commit, push, and verify Task 6B GREEN**

```bash
/Users/chen/.cargo/bin/rustfmt --edition 2021 agent/src/main.rs agent/src/instance.rs agent/src/tap_registry.rs agent/src/system_manager.rs agent/src/control_plane.rs agent/src/control_plane/observability.rs agent/src/api_handlers/metrics.rs core/src/ebpf_ops.rs core/src/ebpf_ops/fragment.rs core/src/ebpf_ops/replay.rs core/src/monitoring.rs abi/src/fragment.rs abi/src/lib.rs abi/tests/fragment_parser_contract.rs ebpf/src/parser.rs ebpf/src/fragment.rs ebpf/src/lib.rs
git add agent/src/main.rs agent/src/instance.rs agent/src/tap_registry.rs agent/src/system_manager.rs agent/src/control_plane.rs agent/src/control_plane/observability.rs agent/src/api_handlers/metrics.rs core/src/ebpf_ops.rs core/src/ebpf_ops/fragment.rs core/src/ebpf_ops/replay.rs core/src/monitoring.rs abi/src/fragment.rs abi/src/lib.rs abi/tests/fragment_parser_contract.rs ebpf/src/parser.rs ebpf/src/fragment.rs ebpf/src/lib.rs config/aria-agent.toml deploy/kolla/config/aria-agent-openstack.toml docs/openstack-neutron-agent-mode.md docs/openstack-deployment-runbook.md
git -c user.name=netmouser -c user.email=chenyongming211@gmail.com commit -m "feat: expose guarded fragment tracking status"
git push origin v0.9-neutron-agent
```

Expected: fast contracts, Rust behavior, and static builds pass; capability remains disabled.

### Task 7: Wire Guarded Privileged Smoke Without Claiming Execution

**Files:**
- Create: `deploy/smoke/lib/fragment_tracking_field_driver.py`
- Modify: `deploy/smoke/aria_standalone_acl_tc_datapath_smoke.sh`
- Modify: `deploy/kolla/smoke/neutron_aria_acl_tc_datapath_smoke.sh`
- Modify: `ci/check_neutron_stage1.py`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`

**Interfaces:**
- Consumes: public config, drop reasons, pinned maps, and metrics from Tasks 3-6.
- Produces: `FRAGMENT_TRACKING_SMOKE=1` guarded field entrypoints and truthful pending evidence.

- [x] **Step 1: Add managed and standalone scenarios**

Add one shared stdlib-only field driver instead of duplicating inline Python in
both shell scripts. It builds valid IPv4/IPv6 UDP/53 fragments (including
802.1Q), validates allowed delivery with a random-token UDP receiver, and
strictly compares the public fragment Prometheus series. It must not parse
Rust or shell source and must not print a field PASS by itself.

Reuse the existing standalone namespace/tap setup, extend it with dual-stack
addresses plus VLAN fixtures, and guard every new process and network object in
cleanup. `MODE=system` is a deliberately single-interface runtime: it covers
both families, both TC directions, ordering, VLAN isolation, epoch invalidation,
and restart scrub, but it must not fabricate a second attached tap. `MODE=tap`
adds a second auto-attached veth/tap and is the authoritative cross-tap
isolation scenario. Across the standalone mode matrix, cover ordered IPv4/IPv6
UDP/53, post-first reorder, later-before-first drop, cross-tap/VLAN isolation,
epoch invalidation during policy update, and restart scrub.

The managed path remains opt-in and requires an explicit local peer execution
contract: `FRAGMENT_PEER_NETNS`, `FRAGMENT_PEER_IFNAME`, dual-stack
`FRAGMENT_IPV4_HOST/PEER` and `FRAGMENT_IPV6_HOST/PEER`, plus the configured
VLAN pair. Missing or inconsistent inputs fail the enabled subsection; they
must never downgrade to PASS or silently reduce family/direction coverage.
Reuse the existing Neutron policy/full-resync/restart operations and the shared
driver. Do not accept arbitrary shell/eval or add an unreviewed SSH adapter.

- [x] **Step 2: Keep execution opt-in**

If `FRAGMENT_TRACKING_SMOKE` is not `1`, print one stable `SKIP` line and exit the fragment subsection successfully. Never report `PASS` for skipped field work.

Only the opt-in temporary standalone fixture may set fragment tracking
`enabled=true` and `field_verified=true`. Shipped configuration remains
disabled. Enabled execution reports verified only after packet delivery,
counter/pressure deltas, epoch invalidation, restart scrub, and cleanup all
succeed. Current development does not execute privileged packets and records
field evidence as `deferred/pending`.

Field pressure evidence uses bounded occupancy/eviction behavior. Do not freeze,
corrupt, chmod, or otherwise destructively modify a pinned context map to force
an insert failure. The `update_failed` counter remains covered by Rust/eBPF
behavior tests and the hosted metrics contract because the production LRU map
and public configuration expose no safe deterministic field trigger. A future
test-only fault-injection surface, if needed, is a separate reviewed design and
is not part of Task 7.

- [x] **Step 3: Syntax and contract verification**

Run only non-compiling local checks:

```bash
bash -n deploy/smoke/aria_standalone_acl_tc_datapath_smoke.sh
bash -n deploy/kolla/smoke/neutron_aria_acl_tc_datapath_smoke.sh
python3 ci/check_neutron_stage1.py --fast-contracts
git diff --check
```

The fast contract may run a stdlib-only driver `--self-test` for frame checksum,
fragment ordering, receiver fixtures, and metrics parsing. It may also verify
the public disabled-entrypoint behavior, but must not add substring/source-shape
checks for private helper names or order. Expected: all commands pass; no
privileged packet is sent locally.

- [x] **Step 4: Commit and push smoke wiring**

```bash
git add deploy/smoke/lib/fragment_tracking_field_driver.py deploy/smoke/aria_standalone_acl_tc_datapath_smoke.sh deploy/kolla/smoke/neutron_aria_acl_tc_datapath_smoke.sh ci/check_neutron_stage1.py docs/openstack-neutron-aria-details/12-review-bug-backlog.md
git -c user.name=netmouser -c user.email=chenyongming211@gmail.com commit -m "test: wire fragment tracking field evidence"
git push origin v0.9-neutron-agent
```

Expected backlog state: implementation and hosted CI complete; privileged field evidence deferred; production activation disabled.

### Task 8: Final Hosted Verification And Documentation Closure

**Files:**
- Modify: `docs/superpowers/specs/2026-07-19-acl-056-fragment-tracking-design.md`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`
- Modify: this plan checkbox state

**Interfaces:**
- Consumes: exact commit SHAs and GitHub run IDs from Tasks 1-7.
- Produces: reviewable implementation/CI evidence without false field claims.

- [ ] **Step 1: Verify exact-head GitHub checks**

```bash
head_sha="$(git rev-parse HEAD)"
run_id="$(gh run list --branch v0.9-neutron-agent --limit 20 --json databaseId,headSha --jq ".[] | select(.headSha == \"${head_sha}\") | .databaseId" | head -1)"
test -n "${run_id}"
gh run view "${run_id}" --json headSha,status,conclusion,jobs,url
```

Expected: the selected run is for exact HEAD; `fast-contracts`, `rust-behavior`, and `rust-build` are successful. Record both run ID and head SHA in the docs.

- [ ] **Step 2: Perform final static review**

Inspect parser length/offset arithmetic, every fragment-map key initialization, epoch ordering, first-pass insertion error cleanup, non-initial TCPRT guards, pin inventory, recovery, and metrics. Run `git diff --check`; do not run local Cargo.

- [ ] **Step 3: Close hosted evidence only**

Update the design status and backlog with RED and GREEN commits and exact CI URL. Keep `REVIEW-ACL-056` at `implementation and hosted CI complete; privileged field evidence deferred` until real smoke evidence exists.

- [ ] **Step 4: Commit and push documentation closure**

```bash
git add docs/superpowers/specs/2026-07-19-acl-056-fragment-tracking-design.md docs/openstack-neutron-aria-details/12-review-bug-backlog.md docs/superpowers/plans/2026-07-19-acl-056-fragment-tracking.md
git -c user.name=netmouser -c user.email=chenyongming211@gmail.com commit -m "docs: record fragment tracking evidence"
git push origin v0.9-neutron-agent
```

Expected final state: clean worktree, local/remote divergence `0 0`, hosted checks green, activation disabled, field evidence pending.

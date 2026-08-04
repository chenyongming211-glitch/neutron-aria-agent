# Legacy-Kernel eBPF Stack Budget Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the current TC ingress and egress artifact load on the maintained 4.18 kernel while keeping the worst BPF call path at or below 448 bytes and preserving fail-open OVS forwarding.

**Architecture:** Move primary and TCP-RT-derived connection keys from stack-local aggregates into two-slot, non-persistent per-CPU scratch maps, then measure the linked artifact rather than trusting source shape. GitHub Actions remains the only Rust/eBPF compiler, and the exact maintained kernel remains the final release authority through an isolated veth/netns canary.

**Tech Stack:** Rust 2021, Aya eBPF 0.1, Python 3 `unittest`, final-ELF BPF instruction analysis, pyelftools 0.32, GitHub Actions, Rocky Linux 8 kernel `4.18.0-553.5.1.el8_10.x86_64`.

## Global Constraints

- The worst analyzed call path from `tc_ingress` or `tc_egress` must be at most 448 bytes.
- Rust and eBPF compilation occurs only in GitHub Actions.
- Scratch failure returns `TC_ACT_OK`; Aria must not restart OVS or `neutron-openvswitch-agent`.
- Scratch maps are not persistent, critical, replayed, exported, or part of WAL semantics.
- No QoS, Mirror, Trace, RPC, Neutron API, or tenant feature expansion is included.
- Tail calls are not implemented unless the scratch-backed artifact still exceeds 448 bytes.
- Existing unrelated working-tree changes are not staged or modified.

---

## File Structure

- Modify `ci/test_ebpf_legacy_packet_bounds.py`: source-level regression contracts for stack-local CT keys and scratch map lifecycle.
- Modify `ebpf/src/maps.rs`: define `CT_KEY4_SCRATCH` and `CT_KEY6_SCRATCH` as non-persistent per-CPU execution state.
- Modify `ebpf/src/lib.rs`: initialize CT keys directly in scratch map values on all four TC family paths.
- Create `ci/check_ebpf_stack_budget.py`: linked-artifact stack frame and call-path analyzer.
- Create `ci/test_ebpf_stack_budget.py`: deterministic parser and call-graph tests for the analyzer.
- Modify `.github/workflows/build.yml`: generate and enforce the stack report after the eBPF build.
- Create `deploy/kolla/smoke/neutron_aria_legacy_kernel_loader_canary.sh`: isolated maintained-kernel loader and cleanup gate.
- Modify `docs/superpowers/specs/2026-08-04-ebpf-legacy-stack-budget-design.md`: append final evidence references only after acceptance.

### Task 1: Lock The Scratch-Backed CT Key Contract

**Files:**
- Modify: `ci/test_ebpf_legacy_packet_bounds.py`
- Test: `ci/test_ebpf_legacy_packet_bounds.py`

**Interfaces:**
- Consumes: Rust source in `ebpf/src/maps.rs`, `ebpf/src/lib.rs`, and map inventories in `core/src/ebpf_ops/inventory.rs`.
- Produces: failing source contracts that require two scratch maps, reject four stack-local key constructors, and reject persistent scratch inventory entries.

- [ ] **Step 1: Write the failing source contracts**

Add source loading for `lib.rs`, `maps.rs`, and `inventory.rs`, then add assertions equivalent to:

```python
def test_tc_connection_keys_use_per_cpu_scratch(self):
    self.assertIn('map(name = "CT_KEY4_SCRATCH")', self.maps_source)
    self.assertIn('map(name = "CT_KEY6_SCRATCH")', self.maps_source)
    self.assertNotRegex(self.lib_source, re.compile(r"let\s+ct_key\s*=\s*CtKey[46]\s*\{"))
    self.assertEqual(self.lib_source.count("CT_KEY4_SCRATCH.get_ptr_mut(0)"), 2)
    self.assertEqual(self.lib_source.count("CT_KEY6_SCRATCH.get_ptr_mut(0)"), 2)

def test_ct_key_scratch_is_not_persistent_inventory(self):
    for name in ("CT_KEY4_SCRATCH", "CT_KEY6_SCRATCH"):
        self.assertNotIn('"%s"' % name, self.inventory_source)
```

- [ ] **Step 2: Run the test and prove RED**

Run:

```powershell
python -m unittest ci.test_ebpf_legacy_packet_bounds
```

Expected: failure because the two maps and four scratch lookups do not exist.

- [ ] **Step 3: Commit the failing contract separately**

```powershell
git add ci/test_ebpf_legacy_packet_bounds.py
git commit -m "test: require stackless TC connection keys"
```

### Task 2: Move CT Keys Into Per-CPU Scratch

**Files:**
- Modify: `ebpf/src/maps.rs`
- Modify: `ebpf/src/lib.rs`
- Test: `ci/test_ebpf_legacy_packet_bounds.py`

**Interfaces:**
- Consumes: `CtKey4`, `CtKey6`, `PerCpuArray`, `TC_ACT_OK`, and the failing Task 1 contracts.
- Produces: `CT_KEY4_SCRATCH: PerCpuArray<CtKey4>` and `CT_KEY6_SCRATCH: PerCpuArray<CtKey6>` used by ingress/egress IPv4/IPv6 family wrappers.

- [ ] **Step 1: Add the non-persistent scratch maps**

Add beside `PKT_SCRATCH` and `PIPE_SCRATCH`. Slot 0 is the primary TC key and
slot 1 is the derived TCP-RT key:

```rust
#[map(name = "CT_KEY4_SCRATCH")]
pub static CT_KEY4_SCRATCH: PerCpuArray<CtKey4> = PerCpuArray::with_max_entries(2, 0);

#[map(name = "CT_KEY6_SCRATCH")]
pub static CT_KEY6_SCRATCH: PerCpuArray<CtKey6> = PerCpuArray::with_max_entries(2, 0);
```

Do not add either name to any inventory or critical map list.

- [ ] **Step 2: Replace each IPv4 stack-local constructor**

In `try_tc_egress_v4` and `try_tc_ingress_v4`, replace the aggregate constructor with direct map-value initialization:

```rust
let ct_key_ptr = match maps::CT_KEY4_SCRATCH.get_ptr_mut(0) {
    Some(ptr) => ptr,
    None => return TC_ACT_OK,
};
(*ct_key_ptr).tap_id = p.tap_id;
(*ct_key_ptr).src_ip = info.src_ip;
(*ct_key_ptr).dst_ip = info.dst_ip;
(*ct_key_ptr).src_port = info.src_port;
(*ct_key_ptr).dst_port = info.dst_port;
(*ct_key_ptr).proto = p.proto;
(*ct_key_ptr).pad = [0; 3];
let ct_key = &*ct_key_ptr;
```

- [ ] **Step 3: Replace each IPv6 stack-local constructor**

Use `CT_KEY6_SCRATCH` in `try_tc_egress_v6` and `try_tc_ingress_v6`, assigning `src_ip_v6` and `dst_ip_v6` directly into the map value. Scratch lookup failure returns `TC_ACT_OK`.

- [ ] **Step 4: Run local non-Rust contracts and prove GREEN**

```powershell
python -m unittest ci.test_ebpf_legacy_packet_bounds
python ci/check_blocked_terms.py
python ci/check_build_workflow_contract.py
git diff --check
```

Expected: all commands exit zero. Do not run Cargo locally.

- [ ] **Step 5: Commit the minimal implementation**

```powershell
git add ebpf/src/maps.rs ebpf/src/lib.rs
git commit -m "fix: move TC connection keys off the BPF stack"
```

### Task 3: Enforce Artifact Stack Budget In CI

**Files:**
- Create: `ci/check_ebpf_stack_budget.py`
- Create: `ci/test_ebpf_stack_budget.py`
- Modify: `.github/workflows/build.yml`

**Interfaces:**
- Consumes: linked `ebpf-artifacts/libebpf_firewall.so`, TC entry names, and a numeric `--max-path-bytes` argument.
- Produces: a text/JSON report containing each TC entry's worst path, per-function frames, and total; exits nonzero above 448 bytes.

- [ ] **Step 1: Write failing analyzer unit tests**

Use synthetic BPF instructions and a frame/call graph with frames `32`, `96`,
and `80`. Assert that the analyzer follows frame-pointer arithmetic and direct
stack accesses, resolves pseudo-call edges, applies the verifier's 32-byte
frame rounding, detects recursion, rejects unknown targets, and fails a
192-byte budget.

- [ ] **Step 2: Run the analyzer test and prove RED**

```powershell
python -m unittest ci.test_ebpf_stack_budget
```

Expected: import failure because `ci.check_ebpf_stack_budget` does not exist.

- [ ] **Step 3: Implement the analyzer**

The script must use pyelftools 0.32 and:

```text
derive function frames from final BPF instructions and r10-relative accesses
resolve BPF-to-BPF pseudo-calls from ELF instructions and relocations
compute the maximum acyclic call path from tc_ingress and tc_egress
print the path and total
exit 1 when either total exceeds --max-path-bytes
```

Unknown pseudo-call targets, malformed ELF, unbounded frame-pointer analysis,
or a recursive cycle are errors rather than an implicit pass.

- [ ] **Step 4: Prove the analyzer unit tests GREEN**

```powershell
python -m unittest ci.test_ebpf_stack_budget
```

- [ ] **Step 5: Add the GitHub Actions gate**

Immediately after `Find eBPF artifacts`, run:

```yaml
- name: Enforce legacy eBPF stack budget
  run: |
    python3 -m pip install --disable-pip-version-check pyelftools==0.32
    python3 -m unittest ci.test_ebpf_stack_budget
    python3 ci/check_ebpf_stack_budget.py \
      --artifact ebpf-artifacts/libebpf_firewall.so \
      --max-path-bytes 448 \
      --report ebpf-artifacts/stack-budget.json
```

Include `stack-budget.json` in the Rust artifact payload.

The analyzer charges each frame as
`round_up(max(frame_bytes, 1), 32)`, matching the maintained 4.18 verifier.

- [ ] **Step 6: Run local workflow contracts**

```powershell
python -m unittest ci.test_ebpf_stack_budget
python ci/check_build_workflow_contract.py
python ci/check_blocked_terms.py
git diff --check
```

- [ ] **Step 7: Commit the CI gate**

```powershell
git add ci/check_ebpf_stack_budget.py ci/test_ebpf_stack_budget.py .github/workflows/build.yml
git commit -m "ci: enforce eBPF call-path stack budget"
```

### Task 4: Build And Inspect The Artifact

**Files:**
- No source changes unless CI exposes a measured stack regression.

**Interfaces:**
- Consumes: Tasks 1-3 commits pushed to `v0.9-neutron-agent`.
- Produces: GitHub Actions artifact containing `aria-agent`, `libebpf_firewall.so`, and `stack-budget.json` with matching run SHA.

- [ ] **Step 1: Push the reviewed commits**

```powershell
git push origin v0.9-neutron-agent
```

- [ ] **Step 2: Trigger artifact publishing**

```powershell
gh workflow run build.yml --ref v0.9-neutron-agent -f publish_artifacts=true -f run_deep_audit=false
```

- [ ] **Step 3: Wait for every required GitHub job**

Expected: `fast-contracts`, `rust-behavior`, and `rust-build` are green. A
stack-budget failure returns to Task 2 for one measured call-path change; do
not combine multiple speculative annotations.

- [ ] **Step 4: Download and verify the artifact**

Record the workflow run, commit SHA, artifact names, SHA-256 values, and the
two worst-path reports. Reject an artifact without `stack-budget.json`.

### Task 5: Run The Exact-Kernel Isolated Canary

**Files:**
- Create: `deploy/kolla/smoke/neutron_aria_legacy_kernel_loader_canary.sh`

**Interfaces:**
- Consumes: the exact Task 4 `aria-agent` and `libebpf_firewall.so` hashes.
- Produces: isolated ingress/egress load, allow/drop, and cleanup evidence without touching OVS or live VM taps.

- [ ] **Step 1: Write the canary with cleanup first**

The script creates a temporary network namespace, veth pair, private bpffs,
state directory, and HTTP port. A shell `trap` removes every resource on pass,
failure, or interruption. It refuses interfaces matching live tap/qvo/OVS
patterns.

- [ ] **Step 2: Add preflight assertions**

Assert the exact kernel release, artifact hashes, root privileges, free HTTP
port, and absence of the selected namespace/veth names. A mismatch exits before
creating resources.

- [ ] **Step 3: Load both TC programs and run minimum traffic**

Start the artifact against the temporary veth, prove both TC directions are
attached, send one allowed packet, install one temporary drop rule through the
isolated state path, and prove the denied packet is dropped.

- [ ] **Step 4: Prove cleanup and preserve evidence**

After shutdown, assert that the namespace, veth, private bpffs, state directory,
and temporary process are absent. Preserve only the redacted summary, hashes,
verifier result, and traffic verdicts.

- [ ] **Step 5: Commit the canary**

```powershell
git add deploy/kolla/smoke/neutron_aria_legacy_kernel_loader_canary.sh
git commit -m "test: gate eBPF artifacts on the maintained kernel"
```

- [ ] **Step 6: Support the maintained kernel's legacy netlink TC link**

If the exact-kernel canary loads the programs but Aya reports
`FdLink: InvalidLink`, do not weaken dual-direction readiness. Implement the
section 3.1 attachment contract:

1. add failing tests for legacy attachment ownership and exact-name health;
2. detach only stale `tc_ingress`/`tc_egress` netlink filters before attach;
3. retain a successful non-TCX attachment in the kernel;
4. verify both directions through `tc filter show`;
5. remove exact-name legacy filters during rollback/detach;
6. build only in GitHub Actions and rerun this same isolated canary.

This step does not add a third attachment implementation and does not change
OVS lifecycle behavior.

### Task 6: Controlled Three-Node Rollout

**Files:**
- Modify: `docs/superpowers/specs/2026-08-04-ebpf-legacy-stack-budget-design.md`

**Interfaces:**
- Consumes: a Task 5 canary-green artifact and the last accepted live artifact hashes.
- Produces: one-node-at-a-time deployment evidence and an explicit rollback result.

- [ ] **Step 1: Preserve the rollback artifact and active hashes**

Record the current accepted agent and eBPF hashes before any replacement.

- [ ] **Step 2: Roll out to one compute node**

Update only Aria artifacts and Aria containers. Do not restart OVS or
`neutron-openvswitch-agent`. Require both TC directions ready before running a
managed-port ACL smoke.

- [ ] **Step 3: Prove rollback once**

Restore the previous accepted Aria artifact, prove readiness, then redeploy the
new accepted artifact. This is required evidence, not an emergency-only step.

- [ ] **Step 4: Roll out the remaining compute nodes serially**

Each node independently proves hashes, TC ingress/egress readiness, ACL
allow/drop, agent heartbeat, and no new Aria error before the next node starts.

- [ ] **Step 5: Record final evidence and commit**

Append only redacted artifact hashes, CI run, stack totals, canary result,
rollout result, and rollback result to the design document. Run blocked-term
and diff checks before committing.

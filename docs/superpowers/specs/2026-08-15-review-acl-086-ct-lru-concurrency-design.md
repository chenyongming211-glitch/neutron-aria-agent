# REVIEW-ACL-086 CT LRU Concurrency Design

**Status:** source implementation and hosted CI complete; privileged target-kernel stress deferred

**Scope:** IPv4 and IPv6 TC conntrack lookup/update only

## 1. Objective

Prevent a packet running on one CPU from retaining and mutating a
`CT_TABLE_V4` or `CT_TABLE_V6` value pointer after another CPU has removed or
evicted the underlying preallocated LRU element.

The repair must preserve the existing product behavior:

- TC ingress and egress remain the only ACL/conntrack enforcement hooks;
- IPv4 and IPv6, forward and reverse lookup use the same rule;
- stale-bank and expired entries remain cache misses;
- a confirmed current entry retains its cached policy decision and stateful
  behavior;
- the two CT maps remain bounded LRU maps; and
- a concurrent cache race cannot become a cross-flow write or an incorrect
  cached policy hit.

This batch does not redesign conntrack, change timeout values, add a spin lock,
change map capacity, or modify QoS, Mirror, TCP-RT, fragment, or generic
observability behavior.

## 2. Verified Root Cause

The maintained deployment evidence records
`4.18.0-553.5.1.el8_10.x86_64`. The exact Rocky/RHEL-compatible source package
used for this review is:

- package:
  [`kernel-4.18.0-553.5.1.el8_10.src.rpm`](https://download.rockylinux.org/pub/rocky/8/BaseOS/source/tree/Packages/k/kernel-4.18.0-553.5.1.el8_10.src.rpm);
- package SHA-256:
  `6c057076f6902c7c543ccbcc92a823c15f144e08fb49d46b043e708c4044a0fb`;
- embedded source archive SHA-256:
  `39a0e3b9324ec6eb22d7303f02074a9ce3c456b9db9a8f4162b78bd7678114d4`;
- `kernel/bpf/hashtab.c` SHA-256:
  `731c694b23432f99dba8b01851e165d152b7cc46c648202e74ce31333540ba89`;
- `kernel/bpf/bpf_lru_list.c` SHA-256:
  `e7209fe90fd6dc39de883de2f9a58c434a57f6d88d02f1252d11974e8bccf7be`.

The source proves all required steps of the race:

1. `htab_lru_map_lookup_elem()` returns an address inside the selected
   preallocated `htab_elem`.
2. `htab_lru_map_delete_elem()` removes that element from the hash bucket and
   immediately calls `bpf_lru_push_free()` after releasing the bucket lock.
3. `prealloc_lru_pop()` obtains a node from `bpf_lru_pop_free()` and immediately
   overwrites its key; `htab_lru_map_update_elem()` then overwrites the value
   before publishing the node for another key.
4. The target kernel rejects `BPF_MAP_TYPE_LRU_HASH` with
   `BPF_F_NO_PREALLOC`, so delayed RCU freeing cannot be enabled by changing a
   map flag.

The repository uses `LruHashMap<..., CtValue>` with flags `0`. Aya 0.1.1 also
documents that a removed preallocated hash element may become aliased by
another element and that writes through a retained pointer can corrupt that
other element.

The current `ct_lookup_v4()` and `ct_lookup_v6()` retain a mutable pointer,
inspect it, and update `last_seen`, counters, flags, and state in place. A
second CPU may delete the same entry because it sees an expired or stale-bank
value, or the LRU may evict it while making room for an insertion. A later
write through the first pointer can therefore target a newly assigned flow.
The impact is not limited to counters: mixed or aliased reads can also supply
the cached state and matched policy fields used by the current packet.

`REVIEW-ACL-086` is therefore confirmed on the exact maintained kernel. A
privileged stress run remains useful field evidence, but is no longer required
to decide whether the source-level defect exists.

## 3. Rejected Repairs

### 3.1 Re-lookup once and keep writing through the pointer

A new eviction can occur immediately after the re-lookup. This only moves the
race window and is not a repair.

### 3.2 Set `BPF_F_NO_PREALLOC` on the LRU maps

The target kernel returns `-ENOTSUPP` for an LRU hash created without
preallocation. This would prevent the program from loading.

### 3.3 Add `bpf_spin_lock` to `CtValue`

The LRU delete and reuse implementation does not acquire a lock stored in the
map value. It can recycle and overwrite the element while another CPU holds
such a lock. The target verifier also forbids ordinary helper calls while a
BPF spin lock is held, so an external lock cannot enclose lookup, delete, and
update helpers.

### 3.4 Replace LRU with a non-preallocated ordinary hash map

That would solve element lifetime but remove bounded automatic eviction. A
correct replacement would also require a garbage collector, admission and
capacity semantics, restart behavior, and new operational evidence. It is a
conntrack architecture change, not the minimum ACL-086 repair.

### 3.5 Use per-CPU conntrack values

Forward and reverse packets of one flow can run on different CPUs. Per-CPU
state would lose the shared reply/state transition that stateful ACL depends
on.

## 4. Selected Publication Protocol

Add a two-entry `PerCpuArray<CtValue>` scratch map. It is packet-local storage:
it is never persisted, pinned as authority, or included in runtime inventory.

For each IPv4/IPv6 forward or reverse lookup:

1. look up the requested CT key and copy the complete value into scratch slot
   zero;
2. look up the same key again and copy the complete value into scratch slot
   one;
3. compare every `CtValue` field;
4. if the second lookup is absent or the snapshots differ, return an ordinary
   CT miss and do not delete or update either observed pointer;
5. evaluate stale-bank and expiration against the confirmed snapshot;
6. for a confirmed stale/expired entry, delete by key and return the existing
   miss reason;
7. for a confirmed hit, apply the existing timestamp, packet/byte count,
   reply flag, and state transition to scratch slot zero; and
8. publish the complete updated value with `BPF_EXIST`, using the requested CT
   key rather than a retained CT value pointer.

The publication helper may race with a same-key delete or replacement. It can
only update the requested key; it cannot write into the element currently
owned by another key. If publication fails, the already confirmed snapshot is
not written through and the current packet retains the confirmed cached
decision. A later packet will either confirm the current entry or take the
ordinary miss/policy-evaluation path.

At a completely full LRU map, a helper replacement may need one LRU node before
returning the replaced node to the free list. That can increase cache churn at
the existing capacity boundary, but cannot create an incorrect ACL verdict:
an evicted entry becomes an ordinary cache miss and is evaluated by the normal
ACL path. Capacity behavior should be observed in the later target-kernel
stress run; it is not a reason to retain an unsafe cross-flow write.

## 5. Shared Behavior Helpers

The ABI crate owns two layout-neutral helpers used by both host tests and the
eBPF implementation:

- exact `CtValue` snapshot equality; and
- the existing confirmed-hit mutation for forward and reverse packets.

No field is added to or removed from `CtValue`; its size and userspace map ABI
remain unchanged. The helpers use wrapping packet/byte counters to preserve
release-datapath arithmetic at the integer boundary.

## 6. Failure Semantics

| Condition | Result |
| --- | --- |
| first lookup absent | existing `NotFound` miss |
| second lookup absent | concurrent-change miss |
| two snapshots differ | concurrent-change miss |
| confirmed stale bank | delete by key; existing `StaleBank` miss |
| confirmed expired entry | delete by key; existing `Expired` miss |
| confirmed hit, publication succeeds | hit with the updated state |
| confirmed hit, publication loses a race | hit from the confirmed snapshot; no pointer write |

The concurrent-change outcome maps to the existing ordinary CT-miss
observability reason. This batch does not expand the public ABI or create a new
operator-facing reason code.

## 7. Verification

RED host behavior tests must prove:

- identical complete snapshots are accepted;
- a delete/reuse model that changes any enforcement or lifecycle field is
  rejected;
- a missing second snapshot is a miss;
- forward hit mutation preserves reply-driven promotion;
- reverse hit mutation sets `SEEN_REPLY` without prematurely promoting state;
- packet and byte counters retain wrapping behavior; and
- `CtValue` remains 40 bytes.

GREEN verification requires:

- the host behavior tests;
- no `CT_TABLE_V4.get_ptr_mut` or `CT_TABLE_V6.get_ptr_mut` mutation path in
  conntrack lookup;
- warning-denied eBPF compilation;
- the existing 448-byte linked TC stack-budget gate; and
- the full hosted Rust behavior lane.

No local Cargo command is run. The privileged exact-kernel concurrency stress
remains `deferred/pending` until the field environment is available; it will
measure cache churn and confirm the source-derived race closure, not substitute
for the source proof.

## 8. Delivery Evidence

- `c382853` records the exact target-kernel source proof and this selected
  design.
- RED `e44498a` failed the Rust behavior lane because the required complete-
  snapshot and confirmed-hit helpers did not exist; its warning-denied eBPF
  build and 448-byte stack gate still passed.
- GREEN `7dd5b71` removed in-place LRU value writes and added two-snapshot,
  key-scoped publication. Its first hosted build exposed a real 480-byte
  compiler-generated `memmove` call path rather than weakening the stack gate.
- `f77bb15` made the three padding bytes explicit, restoring the existing
  448-byte maximum without changing the protocol. Exact-head Build
  [31882176133](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31882176133)
  passed Rust behavior, warning-denied eBPF compilation, the 448-byte legacy
  stack budget, static userspace/agent builds, fast contracts, DB contracts,
  and clean installation.

The implementation is delivered, but the exact-kernel privileged churn test
remains `deferred/pending`; this document does not record unexecuted field work
as PASS.

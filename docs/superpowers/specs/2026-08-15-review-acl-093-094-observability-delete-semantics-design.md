# REVIEW-ACL-093/094 ACL Observability Delete Semantics Design

**Status:** design complete; RED evidence pending

**Scope:** ACL-facing trace filters/logs, `DROP_REASON_STATS`, and ACL
rule/group statistics cleanup

## 1. Objective

Make ACL observability deletion honest under key absence, iterator faults and
per-key removal faults. A caller must never receive `false`, `Ok(())`, or an
inflated deletion count after an operational map error.

This batch changes error and count semantics only. It does not change packet
processing, map ABI, trace filtering, metric attribution, policy publication,
or the best-effort cleanup position after a successful ACL transaction.

## 2. Confirmed Roots

### 2.1 ACL-093

`delete_trace_filter()` first calls `map.get()` and converts every lookup error
to `Ok(false)`. A permission, syscall, key-size, or other map fault is therefore
reported as an already absent filter, and removal is skipped.

The pre-read also creates an unnecessary check/delete race. The map delete
result already distinguishes successful removal, missing key and real fault.

### 2.2 ACL-094 ACL-facing portion

The following paths collect candidate keys, count candidates, then discard
remove errors:

- `TRACE_LOG` and `TRACE_LOG_V6` flush;
- per-tap `DROP_REASON_STATS` flush;
- both-bank ACL `RULE_STATS` cleanup; and
- both-direction ACL `GROUP_STATS` cleanup.

The trace/drop iterators also discard item errors. A partial failure can thus
return a full requested-key count or successful cleanup even though entries
remain.

## 3. Selected Semantics

Use the existing Aya-aware missing classification:

- successful delete: removed, increment the returned count;
- `MapError::KeyNotFound` or delete syscall `ENOENT`: idempotent absence, do
  not increment the count;
- every other error: retain the exact map/key context and aggregate it.

For a batch:

1. enumerate every candidate strictly; an iterator error aborts before
   deletion and is returned;
2. open and validate every required map before the first mutation;
3. attempt every collected key even after a removal fault;
4. count only successful removals;
5. return the count only when no operational error occurred; otherwise return
   all removal failures as one error.

`TRACE_LOG_V6` retains legacy optional-map compatibility: only a true missing
pin is absence. Permission, open and conversion failures are errors. IPv4 and
IPv6 candidates are collected before either map is mutated.

`delete_trace_filter()` performs no pre-read. It directly classifies the delete
result, returning `true` only for an actual removal, `false` only for a missing
key, and an error for every operational fault.

ACL rule/group statistics cleanup remains post-commit best effort at its
existing callers. The helper now returns real errors so those callers emit the
existing warning instead of a false silent success; this batch does not turn
statistics cleanup into an ACL publication rollback condition.

## 4. Explicit Exclusions

No production or test changes are made to:

- `qos_ops`, QoS statistics, or QoS policy behavior;
- Mirror;
- TCP-RT;
- global `kernel_drop_ops` flush behavior;
- unrelated generic monitoring queries; or
- datapath/eBPF code.

The excluded global kernel-drop removal-accounting defect remains recorded as
non-ACL observability debt. It is not counted as fixed by closing the
ACL-specific portion of `REVIEW-ACL-094`.

## 5. RED/GREEN Evidence

RED Rust fault-model tests must prove:

- trace-filter missing-key deletion is idempotent;
- a non-missing trace-filter delete fault propagates;
- batch deletion attempts every candidate after a fault;
- missing candidates are not counted as removals;
- only actual removals contribute to a successful count;
- multiple real failures are aggregated; and
- iterator faults abort rather than yielding a partial candidate set.

GREEN requires the selected Rust behavior lane and the full hosted build. No
local Cargo command is run. No privileged evidence is required because this
batch changes userspace error reporting only and does not alter packet or map
ABI behavior.

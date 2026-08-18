# RISK-ACL-001/002 Contract Fixes Implementation Plan

**Goal:** Make enabled ACL priorities unique per policy, direction, and IP family, and canonicalize bare host IP inputs to explicit host prefixes.

**Constraints:** Python/Neutron scope only. Do not change Rust/eBPF code, trigger GitHub CI, commit, or push in this session.

## Task 1: Lock the address contract with failing tests

1. Add unit coverage for bare IPv4 and IPv6 host inputs.
2. Verify canonical output is `/32` for IPv4 and `/128` for IPv6.
3. Cover address-set member normalization and canonical deduplication.
4. Run the focused tests and confirm the new cases fail before implementation.
5. Update `normalize_cidr` without weakening existing strict validation.
6. Re-run the focused tests.

## Task 2: Qualify rule priority by IP family

1. Add repository tests proving equal priorities are accepted across IPv4 and IPv6.
2. Add effective ACL tests proving cross-family rules do not degrade a port.
3. Preserve same-family duplicate rejection and disabled-rule behavior.
4. Run the focused tests and confirm the new cases fail before implementation.
5. Add normalized `ethertype` to write-invariant and effective-ACL duplicate keys.
6. Include family in diagnostic context while preserving the stable conflict token.
7. Re-run the focused tests.

## Task 3: Align persistence and schema migration

1. Add migration tests for replacing the old enabled-priority unique index with the family-qualified index.
2. Add downgrade conflict preflight coverage.
3. Add SQLite repository schema/runtime bridge coverage for first-class `ethertype` storage.
4. Run migration/repository tests and confirm the new cases fail before implementation.
5. Add the new Alembic revision after the current ACL migration head.
6. Backfill missing family as `IPv4`, replace the index idempotently, and refuse unsafe downgrade.
7. Update SQLite create, upgrade, write, and conflict paths to use `ethertype`.
8. Re-run migration/repository tests.

## Task 4: Document and verify the resulting contract

1. Update the ACL risk backlog with the implemented semantics and remaining validation boundary.
2. Update the RC product test plan so same-family duplicates fail and cross-family reuse succeeds.
3. Run focused unit suites for contracts, write invariants, effective ACL, migration, plugin, and client behavior.
4. Run the local Python contract checks that do not invoke Rust or hosted CI.
5. Review the final diff for unrelated-file churn and summarize remaining field/CI validation.

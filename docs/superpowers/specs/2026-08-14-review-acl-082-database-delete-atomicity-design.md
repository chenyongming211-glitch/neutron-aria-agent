# REVIEW-ACL-082 Database Delete Atomicity Design

**Status:** approved design; implementation pending

**Scope:** `REVIEW-ACL-082` only

## 1. Objective

Make ACL policy and address-set deletion atomic with respect to concurrent
rule and binding creation. A completed repository operation must never leave a
rule or binding whose referenced policy or address set was deleted by the
competing operation.

This batch preserves the existing repository and HTTP contracts. It does not
change ACL datapath behavior, notification ordering, payload schemas, or the
meaning of an in-use delete rejection.

## 2. Confirmed Root Cause

The current Neutron SQLAlchemy repository has an asymmetric locking protocol:

- `create_rule` locks every referenced address-set row and then the policy
  row before validation and insert;
- `create_binding` locks the policy row before validation and insert;
- `delete_policy` performs its in-use check without an outer write
  transaction or parent-row lock, then deletes the policy in a separate
  helper transaction;
- `delete_address_set` has one outer write transaction, but performs no
  parent-row lock before checking references and deleting members and the
  parent row.

The schema has no foreign keys for these references. In particular,
address-set identifiers remain payload fields rather than dedicated rule
columns. A concurrent creator can therefore commit after the delete-side
reference check but before the parent delete.

The same gap exists in the stdlib SQLite contract repository and the
in-memory repository because their policy and address-set delete methods do
not cover the complete check/delete sequence with their existing write
serialization primitives.

A deterministic current-code SQLite reproduction produced:

```text
errors=[] policies=0 rules=1
```

The orphan is visible to later projection and produces degraded/bypass
behavior. The failure is therefore real, although it is not a fully silent
allow path.

## 3. Considered Approaches

### 3.1 Shared parent-lock protocol — selected

Complete the existing protocol: creators and deleters serialize on the same
policy/address-set parent row, and every delete performs reference validation
and mutation in one outer write transaction.

This requires no schema migration, matches the existing create/update design,
and works for both policy and address-set references.

### 3.2 Database foreign keys with `RESTRICT` — rejected for this batch

Foreign keys would provide a strong final database authority for policy
references. They cannot cover address-set references without first adding
dedicated source/destination address-set columns, backfilling historical
payloads, and changing every write path. That migration is materially larger
than `REVIEW-ACL-082` and would introduce a second representation of existing
payload fields.

### 3.3 Process-local or backend-specific advisory locks — rejected

A process-local lock does not serialize multiple neutron-server workers.
Database advisory locks are backend-specific and duplicate the row-lock
mechanism already used by the repository.

## 4. Required Repository Behavior

### 4.1 Neutron SQLAlchemy repository

`delete_policy(policy_id)` must execute under one `_neutron_write()` outer
transaction:

1. lock the policy parent row with the existing `_lock_write_rows` helper;
2. check for referencing rules and bindings;
3. delete the policy row;
4. commit only when the outer transaction owner commits.

`delete_address_set(address_set_id)` must execute under its existing outer
transaction and:

1. lock the address-set parent row with `_lock_write_rows`;
2. check for referencing rules;
3. delete address-set member rows;
4. delete the address-set parent row;
5. commit only when the outer transaction owner commits.

Nested `_delete` and member-delete helpers must join the outer transaction and
must not create an independent commit boundary.

The lock acquisition order remains compatible with current creators:

```text
rule create:       address sets (sorted) -> policy -> rule insert
binding create:                             policy -> binding insert
policy delete:                              policy -> reference check -> delete
address-set delete: address set          -> reference check -> delete
```

No operation in this batch acquires policy and address-set locks in the
opposite order, so the batch adds no new lock-order cycle.

### 4.2 SQLite repository

Policy and address-set delete methods must use `_sqlite_write()` so one
`BEGIN IMMEDIATE` covers reference validation and deletion. The delete helper
must not commit independently while called from that transaction.

Existing unwrapped delete methods outside this batch retain their current
commit behavior. The implementation may use a transaction-aware delete helper
or a narrowly scoped no-commit primitive, but it must not globally alter
unrelated delete semantics.

With two repositories connected to the same database file, a concurrent
creator must wait for the delete transaction. After the winner commits, the
loser must revalidate against the resulting database state. Exactly one of
these outcomes is allowed:

- create wins, and delete rejects the now-referenced parent; or
- delete wins, and create rejects the now-missing parent.

Neither outcome may contain an orphan.

### 4.3 In-memory repository

Policy and address-set delete methods must use the existing reentrant write
lock across both reference validation and deletion. This is behavioral parity
for the fallback/test repository; it is not presented as cross-process
database protection.

## 5. Error and Notification Contract

This batch preserves current public error mapping:

- deleting an object that is already referenced continues to raise
  `AriaAclValidationError` and maps to HTTP 400;
- a create that loses to a completed parent delete fails the existing missing
  reference validation and maps to HTTP 400;
- named database uniqueness conflicts continue to raise
  `AriaAclConflictError` and map to HTTP 409;
- an absent delete target continues to map to HTTP 404;
- unexpected database faults remain unmapped operational errors.

No delete notifier event is emitted when the repository delete fails. A
successful delete continues emitting exactly the existing event after the
repository operation returns.

## 6. RED and GREEN Evidence

Tests must exercise public repository methods rather than inspect private
source shape.

### 6.1 Deterministic race scenarios

For both policy and address-set parents:

1. pause a delete after its reference check;
2. start a creator that references the same parent;
3. release the operations in a controlled order;
4. assert both threads terminate;
5. assert there is no parent-absent/child-present final state; and
6. assert the losing operation returns the existing typed validation error.

The stdlib SQLite tests use separate repository connections to one temporary
database file. The SQLAlchemy contract lane verifies that delete holds an
outer transaction and uses the same parent-row `FOR UPDATE` protocol as its
creator. In-memory tests use separate threads against one repository.

### 6.2 Regression scenarios

The batch also verifies:

- an unreferenced policy still deletes successfully;
- referenced policy deletion is rejected and preserves policy plus child;
- unreferenced address-set deletion removes members and parent atomically;
- referenced address-set deletion is rejected and preserves the complete
  parent/member/rule preimage;
- injected address-set parent-delete failure still restores members and
  parent; and
- repository error-to-HTTP mapping and notifier suppression remain unchanged.

## 7. Delivery and Verification

The work follows test-driven delivery:

1. commit the approved design;
2. write the implementation plan;
3. add deterministic RED tests without production changes;
4. run allowed Python tests and push the RED checkpoint;
5. capture hosted RED evidence;
6. implement the minimum locking/transaction changes;
7. run allowed Python tests and push GREEN;
8. require the fast-contract, Neutron DB contract, and clean-install lanes to
   pass at the exact implementation head; and
9. update the backlog and remediation-program status without claiming any
   privileged field evidence.

No local Cargo command is required or permitted. Rust/eBPF code is outside
this batch.

## 8. Explicit Exclusions

This batch does not:

- add foreign keys or new database columns;
- change address-set payload representation;
- change HTTP 400/409/404 mappings;
- repair the conditional transaction-ownership item `REVIEW-ACL-084`;
- change general fallback reachability tracked by `REVIEW-ACL-083`;
- change rule, binding, or port-status delete semantics;
- change datapath publication, agent recovery, or status projection; or
- claim target-environment or privileged datapath evidence.

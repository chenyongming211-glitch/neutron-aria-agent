# REVIEW-ACL-058/061 Northbound Write Invariants Design

Date: 2026-07-31

Status: design approved in conversation; written specification awaiting final
user review; no RED test or production implementation has been submitted

Analyzed target:
`v0.9-neutron-agent@b7bdbf61dc7adeb1dfb8c9c561e8cf9410aaab75`

Tracked findings:

- `REVIEW-ACL-058`: northbound CIDR and address-set reference validation
- `REVIEW-ACL-061`: duplicate enabled rule/binding write race

## 1. Executive Decision

All three ACL repositories will use one shared write-invariant layer before
mutating policy-related state. The layer will strictly parse and canonicalize
IPv4 CIDRs, validate every address-set reference against the final referenced
object, and classify duplicate enabled rule priorities and binding targets as
conflicts.

Application-level checks provide deterministic messages, but database
constraints remain the final concurrency authority. The Neutron and SQLite
schemas will use nullable `enabled_guard` columns and named composite unique
indexes. Enabled rows store guard value `1`; disabled rows store `NULL`, so the
database rejects duplicate enabled keys while continuing to allow multiple
disabled rows.

Existing conflicting enabled rows will not be deleted, disabled, or selected
automatically. The additive migration will fail closed and report every
conflicting key and object ID so the operator can resolve desired state before
retrying.

This batch is deliberately limited to northbound write correctness. It does not
change datapath matching, ACL priority semantics, IPv6 support, selector
overlap behavior, pagination, or the Neutron WAL.

## 2. Confirmed Current Defects

### 2.1 CIDR parsing is not the runtime's strict grammar

`acl_contract._validate_ipv4_cidr()` uses `socket.inet_aton()`. That parser
accepts legacy short IPv4 forms such as `10.1/16`, does not return a canonical
network string, and therefore cannot make persisted write state match the
runtime's strict four-octet canonicalizer.

Rule create/update invokes the permissive contract validator. Address-set
create/update does not validate member CIDRs at all. Invalid desired state can
therefore be stored and degrade later during effective ACL compilation.

### 2.2 Address-set references are validated too late

Runtime compilation rejects missing, disabled, empty, oversized, or invalid
address sets. Repository rule create/update currently verifies the policy but
does not resolve `src_address_set_id` or `dst_address_set_id`.

The repositories also permit a referenced address set to be updated into an
invalid final state. A valid cross-project set can be referenced and compiled,
while invalid reference state can degrade to availability-first bypass.

### 2.3 Duplicate checks are read-before-write only

`_reject_duplicate_rule_priority()` and
`_reject_duplicate_binding_target()` enumerate existing rows before a later
write. Two workers can both observe no conflict and then commit.

The initial migration creates non-unique lookup indexes. SQLite additionally
uses `INSERT OR REPLACE`, which is incompatible with conflict preservation
because a unique conflict can replace an existing row instead of returning a
stable error.

### 2.4 Repository errors cannot express HTTP 409

All `AriaAclValidationError` values map to HTTP 400. There is no repository
conflict type or legacy/fallback HTTP 409 type, so friendly duplicate checks
and database race losers cannot share correct HTTP semantics.

## 3. Considered Approaches

### 3.1 Shared invariant layer plus database constraints

This is the selected approach.

- Pure syntax and canonicalization stay in `acl_contract.py`.
- Repository-aware final-state checks live in one small write-invariant module.
- In-memory, SQLite, and Neutron repositories call the same functions.
- Named database constraints provide the final multi-process guarantee.

This expresses each semantic contract once without trusting one API entrypoint
or one process-local lock.

### 3.2 Plugin-only validation

Rejected. Direct repository callers, background tasks, and tests can bypass the
plugin. It also cannot prevent two neutron-server workers from committing the
same enabled key.

### 3.3 Application-wide serialization without database uniqueness

Rejected. A Python lock is not shared across processes or hosts. Distributed
locking would add operational complexity while still duplicating a constraint
the database can enforce directly.

## 4. Strict IPv4 CIDR Contract

The shared parser remains Python 2 compatible and does not add a new runtime
dependency.

### 4.1 Accepted grammar

Input must contain:

- exactly four decimal IPv4 octets;
- each octet in `0..255`;
- no leading zero on a multi-character octet;
- exactly one `/`;
- a decimal prefix in `0..32`; and
- no IPv6 delimiter.

Leading and trailing whitespace around the whole value is removed. Embedded
whitespace is invalid.

Examples:

| Input | Result |
| --- | --- |
| `10.1.2.0/24` | `10.1.2.0/24` |
| ` 10.1.2.3/24 ` | `10.1.2.0/24` |
| `0.0.0.0/0` | `0.0.0.0/0` |
| `10.1/16` | validation error |
| `010.1.2.0/24` | validation error |
| `2001:db8::/64` | validation error |
| `10.1.2.0/33` | validation error |

Full-form addresses with host bits are accepted and normalized to their network
address. This matches the existing effective-ACL canonicalizer while removing
the legacy short-form acceptance.

### 4.2 Rule normalization

Non-empty `src_cidr` and `dst_cidr` values are replaced in the final rule with
their canonical strings before persistence. The existing direct-CIDR versus
address-set mutual exclusion remains unchanged.

### 4.3 Address-set member normalization

Both current input forms remain accepted:

- a CIDR string; or
- an object containing an `address` CIDR.

Every non-empty member must be a valid IPv4 CIDR. The repository canonical form
is a list of objects:

```json
[
  {"address": "10.1.2.0/24"},
  {"address": "10.1.3.4/32"}
]
```

Canonical `(network, prefix)` identity is used for deduplication. Output is
sorted by numeric network and then prefix so all repositories persist and
return the same stable order.

The limit remains exactly 2048 raw members. The limit is checked before
deduplication so repeated input cannot be used to bypass request-size bounds.
An unreferenced address set may be empty or disabled, but every member present
in it must still be syntactically valid.

## 5. Shared Write-Invariant Boundary

The invariant layer consumes a complete final object, never a partial patch.
Each repository first clones the current object, applies allowed patch fields,
pins immutable identity fields, and then calls the shared invariant functions.

### 5.1 Immutable fields

Repository update methods must not allow direct callers to change:

- object `id`;
- `project_id` / `tenant_id`;
- a rule's `policy_id`;
- a binding's `policy_id`, `target_type`, or `target_id`; or
- an address set's owning project.

An attempted mutation is rejected rather than silently discarded. This keeps
direct repository calls aligned with the Neutron extension's `allow_put=False`
contract.

### 5.2 Rule final-state validation

Rule create/update performs these checks in order:

1. require the existing public rule fields;
2. resolve the policy and require the rule project to equal the policy project;
3. normalize direct source and destination CIDRs;
4. resolve source/destination address-set references in stable ID order;
5. require each referenced set to exist;
6. require the set project to equal the policy project;
7. require it to be enabled and non-empty;
8. require at most 2048 raw members;
9. normalize and validate every member; and
10. validate the remaining ACL rule contract.

The final persisted rule contains canonical direct CIDRs. Address-set members
remain owned by the address-set row and are not copied into the rule.

### 5.3 Address-set final-state validation

Address-set create/update always normalizes any supplied members.

When the final address set is referenced by at least one enabled rule, the
write additionally requires:

- `enabled=true`;
- at least one member;
- no more than 2048 raw members;
- every member valid; and
- the set project to match the policy project of every enabled referencing
  rule.

The check uses the complete final address-set state. A failed update leaves the
old metadata, members, revision, and timestamps unchanged.

### 5.4 Binding final-state validation

Binding create/update resolves the policy, validates the same project, retains
the existing `port`/`network` target contract, and derives the enabled
uniqueness guard.

### 5.5 Duplicate classification

These are conflicts rather than malformed requests:

- enabled rule key: `(policy_id, direction, priority)`;
- enabled binding key: `(target_type, target_id)`.

Friendly preflight checks and database unique-constraint failures must raise the
same repository conflict class with the same stable reason prefix.

Disabled rows do not occupy either enabled key. Updating a disabled row to
enabled performs the same conflict checks as create.

## 6. Transaction And Locking Model

Every create/update follows one ordered transaction:

1. load current state where applicable;
2. construct complete final state;
3. lock dependencies;
4. canonicalize and validate;
5. perform friendly duplicate preflight;
6. write the object and dependent rows;
7. let named unique constraints arbitrate any concurrent race;
8. commit; and
9. return the committed object.

The plugin emits an RPC notification only after the repository method returns
successfully. Failed writes do not notify and do not increment revision.

### 6.1 Lock order

To avoid rule-create/address-set-update deadlocks, dependencies are locked in
one global order:

1. referenced address-set IDs, sorted;
2. policy ID; and
3. the object being updated when it is distinct from the dependency rows.

Rule create and address-set update therefore serialize on the same address-set
row. If rule creation wins, a later invalidating address-set update sees the
new reference and fails. If the address-set update wins, the later rule sees
the new final state and either accepts or rejects it.

### 6.2 In-memory repository

A repository-level reentrant lock covers the entire load/validate/write
sequence. This provides deterministic behavior for concurrent callers of the
same in-memory repository instance.

### 6.3 SQLite repository

SQLite uses an explicit write transaction covering preflight and persistence.
Rule and binding create/update use distinct INSERT and UPDATE operations, not
`INSERT OR REPLACE`.

Address-set payload and member replacement commit atomically. Existing SQLite
files receive the same conflict preflight, guard-column backfill, and named
unique indexes as the Neutron schema.

### 6.4 Neutron SQLAlchemy repository

One `session.begin(subtransactions=True)` boundary covers each complete
create/update. Dependency reads use `SELECT ... FOR UPDATE` where supported.
Named database unique indexes remain authoritative across workers and hosts.

Only integrity failures from the two known enabled-key constraints map to the
ACL conflict type. Foreign, storage, connection, and unknown integrity failures
remain internal errors.

## 7. Database Uniqueness Design

Database partial indexes are not selected because the target Neutron
environment must remain portable across its supported SQL backends.

### 7.1 Rule schema

Add a nullable guard column:

```text
enabled_guard SMALLINT NULL
```

Write `1` for an enabled rule and `NULL` for a disabled rule. Add the named
unique index:

```text
uq_aria_acl_rules_enabled_priority
    (policy_id, direction, priority, enabled_guard)
```

### 7.2 Binding schema

Add the same nullable guard column and the named unique index:

```text
uq_aria_acl_bindings_enabled_target
    (target_type, target_id, enabled_guard)
```

The repository derives the guard from the normalized Boolean `enabled` value;
clients cannot provide it.

### 7.3 Additive migration

A new Alembic revision follows `8b9c2d1e4f60`; the published initial migration
is not rewritten.

Upgrade order:

1. query duplicate enabled rule keys and binding keys;
2. if any exist, abort with every conflicting key and sorted object ID list;
3. add nullable guard columns;
4. backfill `1` for enabled rows and `NULL` for disabled rows;
5. create both named unique indexes; and
6. leave the database unchanged from the caller's perspective if preflight
   rejects historical data.

The migration never selects a winner, deletes a row, or disables desired state.
Downgrade drops the indexes and guard columns without changing ACL rows.

Runtime startup against an old Neutron schema must fail with an actionable
migration-required error rather than silently running without the constraints.

## 8. Error And HTTP Contract

Introduce a repository conflict class distinct from validation and not-found
errors.

| Repository result | HTTP result | Examples |
| --- | ---: | --- |
| validation error | 400 | malformed CIDR, invalid member shape, missing/disabled/empty/oversized/cross-project referenced set |
| not found | 404 | GET/UPDATE/DELETE target itself does not exist |
| conflict | 409 | duplicate enabled rule priority or binding target |
| unexpected DB/runtime error | existing 500 path | connection loss, unknown constraint, storage failure |

A missing address-set ID inside a rule body is invalid association input and
therefore returns 400. It is distinct from directly reading an address-set
resource that does not exist, which remains 404.

Stable conflict reason prefixes are:

```text
duplicate_enabled_rule_priority
duplicate_enabled_binding_target
```

The real Neutron exception extends its legacy `Conflict` type. The stdlib test
fallback exposes `status_code = 409`.

## 9. RED Behavior Contract

The RED commit adds behavior and migration tests before production code. It
must not add a static source-shape checker.

### 9.1 Strict CIDR cases

- reject short, leading-zero, IPv6, malformed, and out-of-range input;
- canonicalize whitespace and host bits;
- cover both rule CIDR sides;
- cover string and object address-set member inputs;
- prove canonical deduplication and stable order; and
- accept 2048 raw members but reject 2049.

### 9.2 Address-set reference cases

Rule create and update each reject:

- missing;
- disabled;
- empty;
- invalid-member;
- cross-project; and
- oversized address sets.

A referenced address-set update cannot make the final set disabled, empty,
invalid, oversized, or cross-project. The failed update preserves the complete
old object and revision. An unreferenced set remains allowed to be empty or
disabled.

### 9.3 Uniqueness cases

For rules and bindings:

- duplicate enabled create returns 409;
- conflicting update and disabled-to-enabled transition return 409;
- multiple disabled duplicates remain legal;
- concurrent writers produce exactly one success and conflict outcomes for the
  losers; and
- a failed write does not mutate the old object, increment revision, or emit a
  notifier event.

### 9.4 Repository parity

One behavior fixture is executed against:

- `InMemoryAriaAclRepository`;
- `SqliteAriaAclRepository`; and
- a dependency-free adapter that inherits the real
  `NeutronDbAriaAclRepository` write methods.

The adapter avoids adding SQLAlchemy to the stdlib-only local unit environment.
The additive migration tests independently prove the real database columns and
unique indexes used for cross-worker arbitration.

### 9.5 Migration and HTTP cases

- clean upgrade emits guard-column and named unique-index operations;
- downgrade emits the inverse operations;
- conflicting historical data reports all keys and IDs and blocks upgrade;
- validation maps to 400;
- direct target absence maps to 404;
- both friendly and database duplicate conflicts map to 409; and
- unknown errors remain unmapped.

The expected RED failure must be attributable only to missing canonical write
normalization, reference validation, conflict type/mapping, atomic repository
behavior, and migration constraints. Existing tests unrelated to this batch
must remain green.

## 10. Explicit Exclusions

This batch does not:

- implement production behavior in the RED commit;
- add IPv6 ACL matching;
- add source-port matching;
- make priority a datapath arbiter;
- add cross-project address-set RBAC sharing;
- change selector overlap or general multi-membership semantics;
- implement ACL pagination or remove N+1 queries;
- modify the Neutron WAL or begin `REVIEW-OPS-019`;
- auto-repair historical duplicates;
- add a Python static checker tied to private helper shape;
- claim privileged field evidence; or
- run local Cargo commands.

Existing runtime validation remains defense in depth after northbound
validation is added.

## 11. Delivery Sequence

1. commit this approved design;
2. self-review it for placeholders, contradictions, scope drift, and ambiguous
   semantics;
3. obtain user approval of the written specification;
4. write a detailed implementation/RED plan;
5. add the RED behavior and migration tests without production changes;
6. run allowed local Python/contract checks and verify focused RED;
7. commit and push the RED checkpoint directly to `v0.9-neutron-agent`;
8. use GitHub Actions as the authoritative RED evidence;
9. keep `REVIEW-ACL-058` and `REVIEW-ACL-061` open; and
10. stop before GREEN production implementation until that next step is
    explicitly entered.

No new branch, worktree, PR, local Cargo build, or field-evidence claim is part
of this design/RED batch.


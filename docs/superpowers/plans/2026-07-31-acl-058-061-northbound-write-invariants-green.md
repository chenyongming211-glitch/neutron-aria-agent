# REVIEW-ACL-058/061 Northbound Write Invariants GREEN Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the 87 verified RED failures green with one shared northbound invariant layer, atomic repository adapters, database-authoritative enabled-key uniqueness, and stable HTTP 409 mapping.

**Architecture:** Put pure CIDR normalization in `acl_contract.py` and all repository-aware final-state semantics in one new `write_invariants.py`; the three repositories delegate to it instead of copying validation. Keep storage-specific transaction and constraint handling in each repository, add one additive Alembic migration, and preserve the existing public repository and plugin method shapes.

**Tech Stack:** Python 2-compatible stdlib, `socket`, `threading.RLock`, `sqlite3`, SQLAlchemy Core compatible with the target Neutron runtime, Alembic, `unittest`, GitHub Actions `fast-contracts`.

## Global Constraints

- Work only on local and remote `v0.9-neutron-agent`; create no branch, PR, or worktree.
- Follow `docs/superpowers/specs/2026-07-31-acl-058-061-northbound-write-invariants-design.md`.
- Do not change datapath matching, IPv4-only scope, source-port exclusion, priority semantics, selector overlap, pagination, or the Neutron WAL.
- Do not add a generic transaction framework, repository abstraction hierarchy, new dependency, or private-source checker.
- Preserve the raw address-set request limit at exactly 2048 members before deduplication.
- Preserve public repository method names and payload shapes.
- Do not alter the published initial migration `8b9c2d1e4f60`; add a successor revision.
- Do not run local Cargo commands. This batch changes only Python and migration code.
- Do not claim privileged field evidence.

---

### Task 1: Implement one canonical contract and invariant layer

**Files:**
- Create: `openstack/neutron_aria/neutron_aria/db/aria_acl/errors.py`
- Create: `openstack/neutron_aria/neutron_aria/db/aria_acl/write_invariants.py`
- Modify: `openstack/neutron_aria/neutron_aria/acl_contract.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/effective_acl.py`
- Modify: `openstack/neutron_aria/neutron_aria/db/aria_acl/api.py`

**Interfaces:**
- Produces: `normalize_ipv4_cidr(value) -> str`.
- Produces: `normalize_address_set_members(members) -> list`.
- Produces: `prepare_rule(repository, values, existing=None) -> dict`.
- Produces: `prepare_address_set(repository, values, existing=None) -> dict`.
- Produces: `prepare_binding(repository, values, existing=None) -> dict`.
- Produces: `reject_immutable_changes(existing, patch, fields, object_type)`.
- Produces: `AriaAclConflictError`, re-exported from `api.py`.

- [x] **Step 1: Move repository errors without breaking imports**

Create:

```python
class AriaAclError(Exception):
    pass


class AriaAclNotFound(AriaAclError):
    pass


class AriaAclValidationError(AriaAclError):
    pass


class AriaAclConflictError(AriaAclError):
    pass
```

Import these four classes into `api.py` and remove their inline definitions.
Existing `from neutron_aria.db.aria_acl.api import ...` callers must continue
to work.

- [x] **Step 2: Implement strict canonical IPv4 parsing**

Replace `_validate_ipv4_cidr` with:

```python
def normalize_ipv4_cidr(value):
    text = str(value).strip()
    parts = text.split("/")
    if len(parts) != 2 or ":" in parts[0]:
        raise AclContractError("only IPv4 CIDR is supported")
    octets = parts[0].split(".")
    if len(octets) != 4:
        raise AclContractError("invalid IPv4 CIDR: %s" % value)
    numbers = []
    for octet in octets:
        if (
            not octet or not octet.isdigit() or
            (len(octet) > 1 and octet.startswith("0"))
        ):
            raise AclContractError("invalid IPv4 CIDR: %s" % value)
        number = int(octet)
        if number < 0 or number > 255:
            raise AclContractError("invalid IPv4 CIDR: %s" % value)
        numbers.append(number)
    if not parts[1] or not parts[1].isdigit():
        raise AclContractError("invalid IPv4 prefix: %s" % parts[1])
    prefix = int(parts[1])
    if prefix < 0 or prefix > 32:
        raise AclContractError("invalid IPv4 prefix: %s" % parts[1])
    address = (
        (numbers[0] << 24) | (numbers[1] << 16) |
        (numbers[2] << 8) | numbers[3]
    )
    mask = 0 if prefix == 0 else (0xffffffff << (32 - prefix)) & 0xffffffff
    network = address & mask
    return "%d.%d.%d.%d/%d" % (
        (network >> 24) & 0xff,
        (network >> 16) & 0xff,
        (network >> 8) & 0xff,
        network & 0xff,
        prefix,
    )
```

Make `_validate_ipv4_cidr` delegate to it. Update
`validate_address_set_reference` to accept either a string or
`{"address": value}` and validate the extracted address.

- [x] **Step 3: Implement stable member normalization**

In `write_invariants.py`, enforce the 2048 raw-member limit first. Reject
non-string objects and mappings without `address`; ignore only empty strings.
Canonicalize with `normalize_ipv4_cidr`, deduplicate by canonical string, sort
by numeric network then prefix, and return:

```python
[{"address": canonical_cidr}, ...]
```

Translate `AclContractError` to `AriaAclValidationError`.

- [x] **Step 4: Implement immutable and final-state preparation**

Use these exact immutable sets:

```python
POLICY_IMMUTABLE_FIELDS = ("id", "project_id", "tenant_id")
RULE_IMMUTABLE_FIELDS = ("id", "project_id", "tenant_id", "policy_id")
ADDRESS_SET_IMMUTABLE_FIELDS = ("id", "project_id", "tenant_id")
BINDING_IMMUTABLE_FIELDS = (
    "id", "project_id", "tenant_id", "policy_id", "target_type", "target_id",
)
```

`reject_immutable_changes` rejects a patch only when it supplies a value
different from the existing final value.

`prepare_rule` must:

1. normalize direct CIDRs in place;
2. resolve both address-set IDs in sorted order;
3. translate missing references to validation errors;
4. require referenced sets enabled, non-empty, valid, at most 2048 raw
   members, and owned by the policy project;
5. run `validate_rule`; and
6. raise `AriaAclConflictError` with
   `duplicate_enabled_rule_priority` for an enabled duplicate excluding the
   current ID.

`prepare_address_set` always canonicalizes members. When any enabled rule
references it, require enabled/non-empty/valid/in-limit final state and match
every referencing policy project.

`prepare_binding` validates policy existence/project, target type, and raises
`AriaAclConflictError` with `duplicate_enabled_binding_target` for an enabled
duplicate excluding the current ID.

- [x] **Step 5: Run the pure and in-memory focused suites**

Run:

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest \
  neutron_aria.tests.unit.test_acl_contract \
  neutron_aria.tests.unit.test_aria_acl_write_invariants.InMemoryWriteInvariantTestCase \
  neutron_aria.tests.unit.test_aria_acl_write_invariants.ConcurrentWriteInvariantTestCase -v
```

Expected after Task 1 plus in-memory wiring in Task 2: all selected tests pass.

### Task 2: Route in-memory and Neutron DB writes through final-state transactions

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/db/aria_acl/api.py`

**Interfaces:**
- Consumes: Task 1 prepare functions and error classes.
- Produces: repository-wide atomic load/prepare/write boundaries.
- Produces: named database constraint translation without reclassifying unknown
  storage failures.

- [x] **Step 1: Add in-memory serialization**

Initialize `self._write_lock = threading.RLock()` and remove the duplicate
`self.address_sets = {}` assignment. Wrap every policy/rule/address-set/binding
create/update load-through-write sequence in this same reentrant lock.

For updates:

```python
existing = self.get_rule(rule_id)
reject_immutable_changes(existing, patch, RULE_IMMUTABLE_FIELDS, "aria_acl_rule")
final_values = copy.deepcopy(existing)
final_values.update(copy.deepcopy(patch))
final_values = prepare_rule(self, final_values, existing=existing)
```

Only after preparation succeeds may revision/timestamps advance and the store
be replaced. Apply the equivalent pattern to policies, address sets, and
bindings.

- [x] **Step 2: Replace inline duplicate and project checks**

Delete `_reject_duplicate_rule_priority` and
`_reject_duplicate_binding_target` from `api.py` after all three repositories
delegate to Task 1. Retain `_enabled` only if a storage adapter still needs it;
do not leave a second semantic implementation.

- [x] **Step 3: Add one Neutron transaction context**

Add a Python 2-compatible context manager:

```python
@contextlib.contextmanager
def _write_transaction(self):
    session = getattr(self, "session", None)
    if session is None:
        yield
        return
    with session.begin(subtransactions=True):
        yield
```

Wrap each complete Neutron create/update in it. Existing `_insert`, `_update`,
and `_replace_members` may use nested subtransactions, so address-set metadata
and member replacement commit or roll back with the outer transaction. Acquire
referenced address-set rows in sorted ID order, then policy, then updated object
using Core `select().with_for_update()` when supported.

- [x] **Step 4: Translate only the two named DB constraints**

Add:

```python
def _constraint_name(exc):
    direct = getattr(exc, "constraint_name", None)
    if direct:
        return direct
    original = getattr(exc, "orig", None)
    diagnostic = getattr(original, "diag", None)
    return getattr(diagnostic, "constraint_name", None)
```

Catch errors around rule/binding `_insert` and `_update`. Map only:

```text
uq_aria_acl_rules_enabled_priority -> duplicate_enabled_rule_priority
uq_aria_acl_bindings_enabled_target -> duplicate_enabled_binding_target
```

Re-raise every unknown exception unchanged.

- [x] **Step 5: Add guard columns to SQLAlchemy table definitions**

Add nullable `SmallInteger` `enabled_guard` columns to rules and bindings.
`_db_values` derives `1` for enabled rows and `None` for disabled rows; client
payload cannot override it.

After `ensure_schema` creates missing tables, inspect existing rule/binding
columns. If either guard is absent, raise:

```text
aria_acl_schema_migration_required
```

Do not silently continue against an old Neutron schema.

### Task 3: Make SQLite atomic and database-authoritative

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/db/aria_acl/api.py`

**Interfaces:**
- Consumes: Task 1 prepare functions.
- Produces: `BEGIN IMMEDIATE` final-state writes, guard-column backfill, named
  unique indexes, and safe INSERT/UPDATE behavior.

- [x] **Step 1: Extend new and existing SQLite schemas**

New rule rows contain `direction TEXT`, `priority INTEGER`, and
`enabled_guard INTEGER`; binding rows contain `enabled_guard INTEGER`.

For existing files:

1. inspect `PRAGMA table_info`;
2. add missing columns;
3. read every JSON payload;
4. derive normalized Boolean guard plus rule direction/priority;
5. report every duplicate enabled key and sorted object ID;
6. abort before creating indexes when conflicts exist; and
7. create the two exact named unique indexes when clean.

- [x] **Step 2: Add an explicit write transaction**

Use `BEGIN IMMEDIATE` before load/prepare/preflight and commit only after the
row and any dependent payload update succeed. Roll back on every exception.
Do not nest this wrapper around port-status operations.

- [x] **Step 3: Remove `INSERT OR REPLACE` from desired-state writes**

Make `_upsert` check object-ID existence. Use plain `INSERT` for a new ID and
`UPDATE ... WHERE id=?` for an existing ID. Include rule
direction/priority/guard and binding guard columns beside the JSON payload.
The composite unique indexes must therefore raise instead of deleting or
replacing an existing conflicting row.

- [x] **Step 4: Map only known SQLite uniqueness errors**

When a repository rule/binding write raises `sqlite3.IntegrityError`, inspect
the named indexed column set in the error message and map it to the same stable
`AriaAclConflictError` prefix. Re-raise primary-key, storage, and unknown
integrity failures.

- [x] **Step 5: Run repository parity**

Run:

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest \
  neutron_aria.tests.unit.test_aria_acl_write_invariants -v
```

Expected: all repository parity, concurrency, constraint, and old-schema tests
pass with no warnings or errors.

### Task 4: Add the migration and HTTP 409 contract

**Files:**
- Create: `openstack/neutron_aria/neutron_aria/db/migration/aria_acl_write_invariants.py`
- Create: `openstack/neutron_aria/neutron_aria/db/aria_acl/migration/versions/f61a2c4e7b90_add_acl_write_invariants.py`
- Modify: `openstack/neutron_aria/neutron_aria/services/aria_acl/exceptions.py`

**Interfaces:**
- Produces: Alembic revision `f61a2c4e7b90`, down revision `8b9c2d1e4f60`.
- Produces: fail-closed historical conflict report.
- Produces: `AriaAclConflict` HTTP exception with status 409.

- [x] **Step 1: Implement additive migration preflight**

Query all enabled rules and bindings before any DDL. Group in Python by:

```python
(policy_id, direction, int(priority))
(target_type, target_id)
```

Accept either raw query rows or the grouped `object_ids` rows supplied by the
dependency-free migration test. If conflicts exist, raise one `RuntimeError`
starting with `aria_acl_write_invariant_conflicts` and include every sorted key
and sorted ID list. Emit no add/update/index operation before this check.

- [x] **Step 2: Add guards, backfill, and unique indexes**

On a clean preflight:

```python
op_handle.add_column(
    "aria_acl_rules",
    sa_module.Column("enabled_guard", sa_module.SmallInteger(), nullable=True),
)
op_handle.add_column(
    "aria_acl_bindings",
    sa_module.Column("enabled_guard", sa_module.SmallInteger(), nullable=True),
)
```

Backfill `1` for enabled and `NULL` for disabled, then create the exact two
named unique indexes. Downgrade drops indexes first, then guard columns.

- [x] **Step 3: Add the Neutron migration wrapper**

The versioned module re-exports `revision`, `down_revision`, `branch_labels`,
`depends_on`, `upgrade`, and `downgrade` from the implementation module,
matching the existing initial-migration wrapper style.

- [x] **Step 4: Map conflicts to HTTP 409**

Import `AriaAclConflictError`. When Neutron is installed, define
`AriaAclConflict(neutron_exc.Conflict)`; otherwise define a fallback with
`status_code = 409`. Check conflict before validation in
`map_repository_error`, and make `ErrorMappingRepositoryProxy` catch the
conflict type along with validation/not-found.

- [x] **Step 5: Run migration and plugin behavior**

Run:

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest \
  neutron_aria.tests.unit.test_aria_acl_write_migration \
  neutron_aria.tests.unit.test_aria_acl_plugin -v
```

Expected: all tests pass.

### Task 5: Verify, submit, and close the batch

**Files:**
- Modify: `docs/superpowers/plans/2026-07-31-acl-058-061-northbound-write-invariants-green.md`
- Modify after CI: `docs/superpowers/specs/2026-07-31-acl-058-061-northbound-write-invariants-design.md`
- Modify after CI: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`

**Interfaces:**
- Consumes: Tasks 1-4.
- Produces: exact-head GREEN evidence and the next-step decision for
  `REVIEW-OPS-019`.

- [x] **Step 1: Run all allowed local verification**

Run:

```bash
python3 ci/check_build_workflow_contract.py
python3 -m unittest ci.test_ci_lane_contract
python3 ci/check_neutron_stage1.py --fast-contracts
git diff --check
```

Expected: all commands exit zero. The existing `SafeConfigParser`
deprecation warning is tracked separately and must not be suppressed in this
batch. Do not run Cargo.

- [x] **Step 2: Review implementation size and duplication**

Require:

- one canonical CIDR implementation;
- one repository-aware invariant implementation;
- no repeated address-set reference matrix in `api.py`;
- no static checker;
- no production edits outside the files listed above; and
- a net production increase proportional to the shared invariant, transaction,
  schema, and migration code rather than the 97-case test matrix.

Local GREEN evidence:

- `python3 ci/check_build_workflow_contract.py`: passed;
- `python3 -m unittest ci.test_ci_lane_contract`: 5 passed;
- `python3 ci/check_neutron_stage1.py --fast-contracts`: 504 passed;
- `git diff --check`: passed;
- exactly one `normalize_ipv4_cidr` implementation remains; and
- `effective_acl.py` now delegates to that canonicalizer while preserving the
  existing `invalid_acl_ipv4_cidr` runtime reason contract. This compatibility
  wiring was discovered by the full 504-test run and removes the previous
  duplicate parser without changing forwarding behavior.

- [x] **Step 3: Commit and push GREEN**

```bash
git add \
  openstack/neutron_aria/neutron_aria/acl_contract.py \
  openstack/neutron_aria/neutron_aria/db/aria_acl/api.py \
  openstack/neutron_aria/neutron_aria/db/aria_acl/errors.py \
  openstack/neutron_aria/neutron_aria/db/aria_acl/write_invariants.py \
  openstack/neutron_aria/neutron_aria/db/migration/aria_acl_write_invariants.py \
  openstack/neutron_aria/neutron_aria/db/aria_acl/migration/versions/f61a2c4e7b90_add_acl_write_invariants.py \
  openstack/neutron_aria/neutron_aria/services/aria_acl/exceptions.py \
  docs/superpowers/plans/2026-07-31-acl-058-061-northbound-write-invariants-green.md
git -c user.name=repository-maintainer -c user.email=maintainers@example.invalid \
  commit -m "fix: enforce ACL northbound write invariants"
git push origin v0.9-neutron-agent
```

- [x] **Step 4: Require exact-head hosted GREEN**

The exact production SHA must have:

- `changes`: success;
- `fast-contracts`: success with all 504 tests;
- Rust behavior/build: skipped for Python-only changes; and
- no new warning or unrelated failure.

- [x] **Step 5: Record evidence and advance the backlog**

Record the implementation SHA, hosted run/job links, test count, and no-field
scope in the design and backlog. Mark `REVIEW-ACL-058` and
`REVIEW-ACL-061` fixed only after exact-head GREEN. Commit/push the docs
evidence update and require its exact-head CI green.

Then reassess the next recorded item. Do not implement `REVIEW-OPS-019` in this
batch.

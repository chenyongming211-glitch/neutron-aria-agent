# REVIEW-ACL-082 Database Delete Atomicity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent concurrent ACL rule or binding creation from leaving an orphan after policy or address-set deletion.

**Architecture:** Complete the existing shared-parent locking protocol. Neutron SQLAlchemy creators and deleters serialize on the same parent row inside one outer transaction; SQLAlchemy-on-SQLite uses an equivalent no-op parent update because SQLite ignores `FOR UPDATE`; the stdlib SQLite and in-memory repositories use their existing whole-writer serialization primitives.

**Tech Stack:** Python 2.7-compatible repository code, SQLAlchemy 1.4 contract tests, stdlib SQLite, `unittest`, GitHub Actions.

## Global Constraints

- Work only on `v0.9-neutron-agent`; do not create a branch, worktree, or PR.
- Preserve the existing HTTP mappings: in-use and missing-reference validation is 400, named uniqueness conflict is 409, and absent delete target is 404.
- Do not add foreign keys, database columns, payload fields, or a new transaction framework.
- Do not change rule, binding, port-status, notifier, datapath, recovery, or status-projection semantics.
- Keep all production Python compatible with the supported legacy Python 2.7 Neutron runtime.
- Do not run local Cargo commands. Rust/eBPF is outside this batch.
- Hosted CI is authoritative for SQLAlchemy 1.4 and clean-install verification.

---

### Task 1: Add Deterministic RED Delete/Create Races

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_write_invariants.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_sql_query.py`

**Interfaces:**
- Consumes: public `delete_policy`, `delete_address_set`, `create_rule`, and `create_binding` repository methods.
- Produces: deterministic public-behavior tests proving that a delete/check window cannot create a parent-absent/child-present final state.

- [x] **Step 1: Add reusable race assertions to the repository parity tests**

Add a test helper that pauses the real delete path immediately after the
reference check. Start the competing public create operation, give it a
bounded opportunity to finish, release the delete, and assert the final
invariant rather than asserting private call counts:

```python
def _assert_no_orphan(self, parent_exists, children, errors):
    self.assertFalse(parent_exists is False and bool(children))
    self.assertEqual(1, len(errors))
    self.assertIsInstance(errors[0], AriaAclValidationError)
```

Cover policy/rule and address-set/rule races against one
`InMemoryAriaAclRepository`. The paused repository subclasses remain test
fixtures only; do not add a pause hook to production code.

- [x] **Step 2: Add real stdlib SQLite races**

For each parent type, create two repository instances in separate threads
against one temporary database file. The delete-side fixture pauses after
the real reference check. The writer uses the unmodified public create
method. After both threads terminate, open a third repository and assert:

```python
parent_exists = bool(repository.list_policies())  # or list_address_sets()
children = repository.list_rules()
self.assertFalse(parent_exists is False and bool(children))
self.assertEqual(1, len(errors))
self.assertIsInstance(errors[0], AriaAclValidationError)
```

Use `threading.Event`, bounded waits, `try/finally`, and close every SQLite
connection in its creating thread.

- [x] **Step 3: Add SQLAlchemy-on-SQLite races in the DB contract lane**

Extend `AriaAclSqlQueryTestCase` with a helper that creates a file-backed
SQLite engine using:

```python
engine = sa.create_engine(
    "sqlite:///%s" % path,
    connect_args={"check_same_thread": False, "timeout": 5},
)
session_factory = sessionmaker(bind=engine)
```

Use one session/repository per thread and commit the operation before closing
the session. Cover policy/rule and address-set/rule. Assert only the public
final-state invariant and typed loser error; do not assert helper names or SQL
source strings.

- [x] **Step 4: Add non-race regression cases**

Across the common repository behavior, verify:

```python
def test_referenced_policy_delete_preserves_complete_preimage(self):
    self.create_policy()
    self.repository.create_rule(self.rule_values())
    with self.assertRaises(AriaAclValidationError):
        self.repository.delete_policy("policy-1")
    self.assertEqual("policy-1", self.repository.get_policy("policy-1")["id"])
    self.assertEqual(["rule-1"], [row["id"] for row in self.repository.list_rules()])
```

Use this exact address-set preimage case:

```python
def test_referenced_address_set_delete_preserves_complete_preimage(self):
    self.create_policy()
    self.create_address_set()
    self.repository.create_rule(self.rule_values(
        src_address_set_id="set-1",
    ))
    before = self.repository.get_address_set("set-1")
    with self.assertRaises(AriaAclValidationError):
        self.repository.delete_address_set("set-1")
    self.assertEqual(before, self.repository.get_address_set("set-1"))
    self.assertEqual(["rule-1"], [row["id"] for row in self.repository.list_rules()])
```

For successful deletes, create an unreferenced parent, call its public delete
method, and assert `get_policy` or `get_address_set` raises `AriaAclNotFound`.
Existing SQLAlchemy member rollback coverage must remain unchanged.

- [x] **Step 5: Run focused RED tests**

Run locally without installing new dependencies:

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest \
  neutron_aria.tests.unit.test_aria_acl_write_invariants
```

Expected: the newly added in-memory and stdlib SQLite race tests fail because
the old delete paths leave an orphan; existing regression tests remain green.
The SQLAlchemy class remains skipped locally when SQLAlchemy is unavailable.

- [x] **Step 6: Commit and push RED**

```bash
git add \
  openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_write_invariants.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_sql_query.py
git commit -m "test: expose ACL database delete races"
git push origin v0.9-neutron-agent
```

Capture the exact Build and job IDs. The expected hosted failures must be the
new orphan assertions in fast-contracts and the SQLAlchemy DB lane. Cancel
unrelated long-running Rust jobs after the RED evidence is complete.

---

### Task 2: Make Delete Validation and Mutation Atomic

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/db/aria_acl/api.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_write_invariants.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_sql_query.py`

**Interfaces:**
- Consumes: `_locked_write`, `_neutron_write`, `_sqlite_write`, `_lock_write_rows`, and existing public repository methods.
- Produces: atomic `delete_policy(policy_id)` and `delete_address_set(address_set_id)` implementations with unchanged return and error contracts.

- [x] **Step 1: Serialize in-memory deletes**

Apply the existing decorator to the complete public operations:

```python
@_locked_write
def delete_policy(self, policy_id):
    self._reject_policy_in_use(policy_id)
    self._delete(self.policies, policy_id, "aria_acl_policy")

@_locked_write
def delete_address_set(self, address_set_id):
    self._reject_address_set_in_use(address_set_id)
    self._delete(self.address_sets, address_set_id, "aria_acl_address_set")
```

- [x] **Step 2: Complete the Neutron SQLAlchemy parent-lock protocol**

Make policy delete own one transaction and lock each delete parent before
validation:

```python
@_neutron_write()
def delete_policy(self, policy_id):
    self._lock_write_rows(policy_id=policy_id)
    self._reject_policy_in_use(policy_id)
    self._delete("policies", policy_id, "aria_acl_policy")

@_neutron_write()
def delete_address_set(self, address_set_id):
    self._lock_write_rows(address_set_ids=(address_set_id,))
    self._reject_address_set_in_use(address_set_id)
    self.session.execute(
        self.tables["address_set_members"].delete().where(
            self.tables["address_set_members"].c.address_set_id == address_set_id
        )
    )
    self._delete("address_sets", address_set_id, "aria_acl_address_set")
```

Inside `_lock_write_rows`, keep `SELECT ... FOR UPDATE` for production
dialects. When `session.get_bind().dialect.name == "sqlite"`, execute a
same-row, same-value Core update (`id=row_id`) before validation so the
SQLAlchemy SQLite contract backend obtains its database write lock instead of
silently ignoring `FOR UPDATE`. Implement the dialect branch inside the
existing ordered loop:

```python
bind = self.session.get_bind()
sqlite_write_lock = (
    getattr(getattr(bind, "dialect", None), "name", None) == "sqlite"
)
for table_name, row_id in ordered:
    table = self.tables[table_name]
    if sqlite_write_lock:
        query = table.update().where(table.c.id == row_id).values(id=row_id)
        self.session.execute(query)
        continue
    query = table.select().where(table.c.id == row_id)
    if hasattr(query, "with_for_update"):
        query = query.with_for_update()
    self.session.execute(query).fetchall()
```

Do not add a backend-specific public API.

- [x] **Step 3: Make stdlib SQLite delete helpers transaction-aware**

Decorate only the policy and address-set delete methods with `_sqlite_write()`
and call the existing private delete helper with `commit=False`:

```python
@_sqlite_write()
def delete_policy(self, policy_id):
    self._reject_policy_in_use(policy_id)
    self._delete(
        "aria_acl_policies", policy_id, "aria_acl_policy", commit=False
    )
```

Extend `_delete` as follows so unrelated unwrapped delete paths retain their
current commit behavior:

```python
def _delete(self, table, object_id, object_type, commit=True):
    cursor = self.connection.execute(
        "DELETE FROM %s WHERE id=?" % table,
        (object_id,),
    )
    if commit:
        self.connection.commit()
    if cursor.rowcount == 0:
        raise AriaAclNotFound("%s %s not found" % (object_type, object_id))
```

The `_sqlite_write()` wrapper commits successful atomic deletes and rolls back
typed failures.

- [x] **Step 4: Run focused GREEN tests**

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest \
  neutron_aria.tests.unit.test_aria_acl_write_invariants \
  neutron_aria.tests.unit.test_aria_acl_plugin
```

Expected: all executed tests pass; SQLAlchemy-only tests are skipped locally
when the dependency is unavailable.

- [x] **Step 5: Run allowed static checks**

```bash
python3 -m py_compile \
  openstack/neutron_aria/neutron_aria/db/aria_acl/api.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_write_invariants.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_sql_query.py
git diff --check
```

Expected: exit code 0 with no diagnostics.

- [x] **Step 6: Commit and push GREEN**

```bash
git add \
  openstack/neutron_aria/neutron_aria/db/aria_acl/api.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_write_invariants.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_sql_query.py
git commit -m "fix: make ACL database deletes atomic"
git push origin v0.9-neutron-agent
```

Require exact-head fast-contracts, Neutron DB contracts, and clean-install
success. Rust jobs may skip because this batch changes no Rust-relevant file.

---

### Task 3: Close Documentation and Exact-Head Evidence

**Files:**
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`
- Modify: `docs/superpowers/specs/2026-08-13-bug-hunt-remediation-program-design.md`
- Modify: `docs/superpowers/specs/2026-08-14-review-acl-082-database-delete-atomicity-design.md`
- Modify: `docs/superpowers/plans/2026-08-14-review-acl-082-database-delete-atomicity.md`

**Interfaces:**
- Consumes: exact RED and GREEN commit/Build/job IDs from Tasks 1 and 2.
- Produces: an auditable fixed backlog row and advancement to remediation step 9 without field-evidence overclaim.

- [x] **Step 1: Record implementation evidence**

Mark `REVIEW-ACL-082` fixed only after the exact implementation-head hosted
lanes pass. Record:

- deterministic old-code orphan outcome;
- RED commit and Build/job IDs;
- GREEN implementation commit and exact-head Build/job IDs;
- the parent-lock/outer-transaction/SQLite serialization boundary;
- unchanged HTTP mapping; and
- that no privileged or target datapath evidence applies.

- [x] **Step 2: Advance the remediation program**

Mark step 8 complete and identify step 9 as the next active batch:
`REVIEW-ACL-078` and `REVIEW-OPS-039` as independent commits in one review
window. Do not pull either item into ACL-082.

- [x] **Step 3: Update design and plan status**

Change the design status to implemented and hosted-CI verified. Check every
completed plan step and include exact evidence links. Do not write a field
PASS claim.

- [x] **Step 4: Verify and commit documentation closure**

```bash
rg -n "REVIEW-ACL-082|step 8|step 9" \
  docs/openstack-neutron-aria-details/12-review-bug-backlog.md \
  docs/superpowers/specs/2026-08-13-bug-hunt-remediation-program-design.md \
  docs/superpowers/specs/2026-08-14-review-acl-082-database-delete-atomicity-design.md \
  docs/superpowers/plans/2026-08-14-review-acl-082-database-delete-atomicity.md
git diff --check
git add docs
git commit -m "docs: close ACL database delete atomicity"
git push origin v0.9-neutron-agent
```

- [x] **Step 5: Require final exact-head CI and clean synchronization**

Wait for the documentation-head Build. Require fast-contracts, Neutron DB
contracts, and clean install to pass; if Rust jobs run, require them to pass as
well. Then verify:

```bash
git status --short --branch
git rev-list --left-right --count \
  origin/v0.9-neutron-agent...v0.9-neutron-agent
```

Expected: clean worktree and `0 0` divergence.

## Completion Evidence

- RED commit `4336892`; Build
  [31784518770](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31784518770)
  failed only the six intended orphan race assertions: four in
  [fast-contracts](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31784518770/job/94717352346)
  and two in
  [neutron-db-contracts](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31784518770/job/94717352314).
- GREEN commit `db169c9`; exact-head Build
  [31784634775](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31784634775)
  passed [fast contracts](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31784634775/job/94717707731),
  [Neutron DB contracts](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31784634775/job/94717707617),
  and [clean install](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31784634775/job/94717707597).
- The documentation closure commit is required to pass those same applicable
  lanes before this plan is reported complete. No privileged or datapath field
  PASS is required or claimed.

# REVIEW-ACL-058/061 Northbound Write Invariants RED Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Submit a production-code-free RED checkpoint that proves strict canonical IPv4 writes, valid same-project address-set references, atomic repository behavior, and database-authoritative enabled-key uniqueness are missing.

**Architecture:** Extend the public ACL contract tests and add one repository-parity behavior suite that drives the real `InMemoryAriaAclRepository`, `SqliteAriaAclRepository`, and inherited `NeutronDbAriaAclRepository` write methods. Add migration and HTTP tests through callable interfaces rather than source-shape inspection, run only allowed Python/static checks locally, then use the exact-head `fast-contracts` failure as authoritative RED evidence.

**Tech Stack:** Python 2-compatible stdlib code, `unittest`, `sqlite3`, repository public methods, Alembic operation fakes, GitHub Actions `fast-contracts`.

## Global Constraints

- Work only on local and remote `v0.9-neutron-agent`; create no branch, PR, or worktree.
- Follow `docs/superpowers/specs/2026-07-31-acl-058-061-northbound-write-invariants-design.md`.
- This plan may add or modify tests and planning documentation only; it must not modify production modules or migrations.
- Do not run local Cargo commands. Rust/eBPF jobs are unrelated to this Python-only RED checkpoint.
- Do not add a Python checker that binds to private production function names or source layout.
- Keep the ACL public model IPv4-only; do not add source-port matching or make priority a datapath arbiter.
- Preserve the raw address-set request limit at exactly 2048 members, checked before canonical deduplication.
- Treat field evidence as `deferred/pending`; this batch has no privileged datapath claim.
- The expected hosted result is `fast-contracts=failed` for the named missing behaviors, with Rust jobs skipped.

---

### Task 1: Expose the strict IPv4 canonicalization gap

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_acl_contract.py`

**Interfaces:**
- Consumes: existing `neutron_aria.acl_contract.validate_rule`.
- Declares for GREEN: `neutron_aria.acl_contract.normalize_ipv4_cidr(value) -> str`.
- Produces: RED proof for strict four-octet parsing and canonical network output.

- [x] **Step 1: Import the contract module without importing a missing symbol**

Add this import while retaining the existing symbol imports:

```python
from neutron_aria import acl_contract
```

Using module lookup lets the missing future API fail as an assertion rather
than aborting test discovery with `ImportError`.

- [x] **Step 2: Add strict rejection behavior**

Add:

```python
    def test_rule_rejects_non_strict_ipv4_cidr_spellings(self):
        for field in ("src_cidr", "dst_cidr"):
            for cidr in (
                "10.1/16",
                "010.1.2.0/24",
                "10.1.2.0 /24",
                "10.1.2.0/ 24",
                "10.1.2.0/33",
                "2001:db8::/64",
            ):
                values = {
                    "direction": "ingress",
                    "priority": 1,
                    "action": "allow",
                    field: cidr,
                }
                with self.assertRaises(AclContractError):
                    validate_rule(values)
```

Expected on the old implementation: at least `10.1/16` and the leading-zero
form are accepted, so the test fails.

- [x] **Step 3: Add canonical output behavior**

Add:

```python
    def test_ipv4_cidr_normalization_trims_outer_space_and_networks_host_bits(self):
        self.assertTrue(
            hasattr(acl_contract, "normalize_ipv4_cidr"),
            "strict canonical CIDR API is missing",
        )
        self.assertEqual(
            "10.1.2.0/24",
            acl_contract.normalize_ipv4_cidr(" 10.1.2.3/24 "),
        )
        self.assertEqual(
            "0.0.0.0/0",
            acl_contract.normalize_ipv4_cidr("255.255.255.255/0"),
        )
```

Expected on the old implementation: FAIL with
`strict canonical CIDR API is missing`.

- [x] **Step 4: Run the focused module and verify correct RED**

Run:

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest \
  neutron_aria.tests.unit.test_acl_contract -v
```

Expected: existing contract tests pass; only the strict spelling and missing
canonical output tests fail. A syntax error, discovery error, or unrelated
failure is not acceptable RED.

### Task 2: Add repository-parity final-state behavior

**Files:**
- Create: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_write_invariants.py`

**Interfaces:**
- Consumes: public create/get/update methods of all three repositories.
- Declares for GREEN: `AriaAclConflictError` as a subtype of `AriaAclError`.
- Declares for GREEN: canonical address-set storage as
  `[{"address": "<canonical-cidr>"}]`.
- Produces: the same observable validation, normalization, atomicity, and
  conflict expectations for in-memory, SQLite, and inherited Neutron DB writes.

- [x] **Step 1: Add dependency-free repository factories**

Create the test module with Python 2-compatible imports, a temporary SQLite
factory, and this adapter skeleton:

```python
class NeutronDbMethodAdapter(NeutronDbAriaAclRepository):
    def __init__(self):
        self.rows = dict(
            (name, {}) for name in ("policies", "rules", "address_sets", "bindings")
        )

    def _db_values(self, _table_name, values):
        return copy.deepcopy(values)

    def _insert(self, table_name, values):
        self.rows[table_name][values["id"]] = copy.deepcopy(values)

    def _update(self, table_name, object_id, values):
        if object_id not in self.rows[table_name]:
            raise AriaAclNotFound("%s not found" % object_id)
        self.rows[table_name][object_id] = copy.deepcopy(values)

    def _list(self, table_name, filters=None):
        return [
            copy.deepcopy(value)
            for value in self.rows[table_name].values()
            if all(
                value.get(key) in expected
                if isinstance(expected, (list, tuple, set))
                else value.get(key) == expected
                for key, expected in (filters or {}).items()
            )
        ]

    def _get(self, table_name, object_id, object_type):
        if object_id not in self.rows[table_name]:
            raise AriaAclNotFound("%s %s not found" % (object_type, object_id))
        return copy.deepcopy(self.rows[table_name][object_id])

    def _replace_members(self, address_set_id, members):
        self.rows["address_sets"][address_set_id]["members"] = copy.deepcopy(members)
```

The adapter inherits the real Neutron DB create/update implementations; it does
not copy their write logic and does not require local SQLAlchemy.

Add a `RepositoryCase` context manager that yields:

```python
("memory", InMemoryAriaAclRepository())
("sqlite", SqliteAriaAclRepository(path))
("neutron-methods", NeutronDbMethodAdapter())
```

It must close and unlink SQLite resources in `finally`.

- [x] **Step 2: Add canonical write cases**

For every repository:

```python
rule = repository.create_rule({
    "id": "rule-1",
    "project_id": "project-1",
    "policy_id": "policy-1",
    "direction": "ingress",
    "priority": 10,
    "action": "allow",
    "src_cidr": " 10.1.2.3/24 ",
    "dst_cidr": "192.0.2.19/28",
})
self.assertEqual("10.1.2.0/24", rule["src_cidr"])
self.assertEqual("192.0.2.16/28", rule["dst_cidr"])
```

Also create an address set with mixed string/object members:

```python
"members": [
    "10.0.1.9/24",
    {"address": "10.0.0.2/24"},
    {"address": "10.0.1.1/24"},
]
```

Assert the stored and returned final form is:

```python
[
    {"address": "10.0.0.0/24"},
    {"address": "10.0.1.0/24"},
]
```

Add boundaries proving 2048 raw entries are accepted and 2049 are rejected
before deduplication. Expected on the old implementation: returned CIDRs and
members retain their input spelling/order and 2049 members are accepted.

- [x] **Step 3: Add rule reference validation matrix**

For rule create and update, cover both `src_address_set_id` and
`dst_address_set_id`. Each write must raise `AriaAclValidationError` for:

```python
("missing", no row)
("disabled", {"enabled": False, "members": ["10.0.0.1/32"]})
("empty", {"enabled": True, "members": []})
("invalid-member", {"enabled": True, "members": ["10.1/16"]})
("cross-project", project_id="project-2")
("oversized", 2049 raw members)
```

After every failed update, assert the complete original rule and its
`revision_number` are unchanged.

Expected on the old implementation: the repository accepts these associations.

- [x] **Step 4: Add referenced address-set update and immutable-field cases**

Create a valid referenced set and rule, then assert attempts to make the set
disabled, empty, invalid, oversized, or owned by another project fail while
preserving the full original set and revision.

Also assert direct repository updates reject changes to `id`, project identity,
rule `policy_id`, and binding identity fields. Do not accept the current silent
pinning behavior.

Expected on the old implementation: invalid set updates are persisted and
immutable changes are either accepted or silently discarded.

- [x] **Step 5: Add sequential conflict semantics**

First assert:

```python
self.assertTrue(
    hasattr(aria_acl_api, "AriaAclConflictError"),
    "repository conflict type is missing",
)
```

Then, for rules and bindings, cover duplicate enabled create, conflicting
update, and disabled-to-enabled transition. Assert:

```python
with self.assertRaises(aria_acl_api.AriaAclConflictError):
    operation()
```

Prove multiple disabled duplicate keys remain legal. After each rejected
update, assert the old object and revision are unchanged.

Expected on the old implementation: the named conflict type is missing and
duplicates raise validation/HTTP-400 semantics.

- [x] **Step 6: Add deterministic concurrent-writer cases**

Start eight public in-memory repository writers from one barrier and assert
exactly one `"success"` plus seven `AriaAclConflictError` results. Assert the
repository contains exactly one enabled row for the key.

For SQLite, inspect the real repository schema for the two named unique indexes,
then issue duplicate enabled rule and binding inserts directly through
`sqlite3`. Assert the second write raises `sqlite3.IntegrityError`. This proves
database arbitration deterministically without binding the test to a private
repository preflight hook or relying on thread scheduling.

Expected on the old implementation: both writers succeed because there is no
lock/unique constraint.

- [x] **Step 7: Run the focused repository suite**

Run:

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest \
  neutron_aria.tests.unit.test_aria_acl_write_invariants -v
```

Expected: failures are limited to missing canonicalization, reference
validation, atomicity, conflict typing, and concurrency arbitration. Fix test
errors and nondeterminism; do not modify production code.

### Task 3: Add migration and HTTP RED contracts

**Files:**
- Create: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_write_migration.py`

**Interfaces:**
- Consumes: `map_repository_error`, plugin notifier behavior, and callable
  Alembic migration modules.
- Declares for GREEN migration module:
  `neutron_aria.db.aria_acl.migration.versions.f61a2c4e7b90_add_acl_write_invariants`.
- Declares named indexes:
  `uq_aria_acl_rules_enabled_priority` and
  `uq_aria_acl_bindings_enabled_target`.
- Produces: RED proof of HTTP 409, post-commit notification, additive schema,
  and fail-closed historical duplicate handling.

- [x] **Step 1: Extend the fake Alembic operations**

Add recorded `added_columns`, `dropped_columns`, and an injectable bind to
`FakeAlembicOp`, with:

```python
    def add_column(self, table_name, column):
        self.added_columns.append((table_name, column))

    def drop_column(self, table_name, column_name):
        self.dropped_columns.append((table_name, column_name))

    def get_bind(self):
        return self.bind
```

The fake bind returns configured rule/binding rows to the migration's
preflight queries.

- [x] **Step 2: Add conflict-to-HTTP behavior**

Import the DB module rather than a missing symbol, assert
`AriaAclConflictError` exists, instantiate it with
`duplicate_enabled_rule_priority`, and assert:

```python
mapped = map_repository_error(conflict)
self.assertEqual(409, mapped.status_code)
self.assertIn("duplicate_enabled_rule_priority", str(mapped))
```

Retain existing 400 and 404 cases.

- [x] **Step 3: Prove failed writes do not notify**

Use `AriaAclPlugin(repository=..., notifier=FakeNotifier())`, create valid
baseline state, clear the notifier, then attempt a duplicate enabled rule and
binding. Assert the error is HTTP 409, `notifier.events == []`, and baseline
objects/revisions are unchanged.

- [x] **Step 4: Prove database race errors retain conflict semantics**

Use a fake repository whose `create_rule` and `create_binding` raise the same
named constraint failures that the Neutron repository will receive from the
database. Assert repository translation produces `AriaAclConflictError` with
the matching stable reason prefix, and the plugin maps it to HTTP 409 without
notifying. Also inject an unknown integrity/storage failure and assert it
remains on the existing 500 path rather than being misclassified.

- [x] **Step 5: Add additive migration behavior**

Load the exact migration module through `importlib`. If absent, call
`self.fail("ACL write-invariant migration is missing")` so RED is a normal
failure.

For a clean fake bind, call `upgrade` and assert:

```python
self.assertEqual("8b9c2d1e4f60", migration.down_revision)
self.assertIn(("aria_acl_rules", "enabled_guard"), added_column_names)
self.assertIn(("aria_acl_bindings", "enabled_guard"), added_column_names)
self.assertIn(
    ("uq_aria_acl_rules_enabled_priority", "aria_acl_rules",
     ("policy_id", "direction", "priority", "enabled_guard"), True),
    op.created_indexes,
)
self.assertIn(
    ("uq_aria_acl_bindings_enabled_target", "aria_acl_bindings",
     ("target_type", "target_id", "enabled_guard"), True),
    op.created_indexes,
)
```

Call `downgrade` and assert both indexes and both guard columns are removed.

- [x] **Step 6: Add historical-conflict fail-closed behavior**

Configure the fake bind with multiple duplicate enabled rule and binding keys.
Assert `upgrade` raises a migration exception whose message contains every
conflicting key and every sorted object ID. Assert no column/index operation
was emitted. This proves the migration does not choose a winner, delete, or
disable desired state.

- [x] **Step 7: Add old-schema startup rejection**

Construct the Neutron DB repository against a fake reflected schema without
either `enabled_guard` column. Assert initialization fails with
`AriaAclValidationError` containing the exact actionable prefix:

```text
aria_acl_schema_migration_required
```

Do not accept fallback execution without the database constraints.

- [x] **Step 8: Run focused plugin/migration tests**

Run:

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest \
  neutron_aria.tests.unit.test_aria_acl_plugin -v
```

Expected: existing tests stay green; new tests fail only because conflict
mapping and the additive migration are absent.

### Task 4: Verify, submit, and record exact-head RED

**Files:**
- Modify: `docs/superpowers/plans/2026-07-31-acl-058-061-northbound-write-invariants-red.md`
- Modify after CI: `docs/superpowers/specs/2026-07-31-acl-058-061-northbound-write-invariants-design.md`

**Interfaces:**
- Consumes: focused RED results and exact-head GitHub Actions jobs.
- Produces: durable RED evidence without marking either backlog item fixed.

- [x] **Step 1: Run the complete allowed local test command**

Run:

```bash
python3 ci/check_build_workflow_contract.py
python3 -m unittest ci.test_ci_lane_contract
python3 ci/check_neutron_stage1.py --fast-contracts
git diff --check
```

Expected: workflow/static checks and `git diff --check` pass.
`--fast-contracts` fails only in the new ACL-058/061 tests for the intended
missing behavior. Do not suppress the failure and do not run Cargo.

- [x] **Step 2: Self-review the RED diff**

Verify:

- no production or migration file changed;
- tests call behavior and migration APIs rather than parsing private source;
- no test already passes because it merely restates current behavior;
- every observed failure maps to an approved design requirement;
- thread/barrier tests terminate deterministically; and
- existing unrelated tests remain green when the new failing cases are
  excluded.

- [x] **Step 3: Commit and push the RED checkpoint**

```bash
git add \
  openstack/neutron_aria/neutron_aria/tests/unit/test_acl_contract.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_write_invariants.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_write_migration.py \
  docs/superpowers/plans/2026-07-31-acl-058-061-northbound-write-invariants-red.md
git -c user.name=netmouser -c user.email=chenyongming211@gmail.com \
  commit -m "test: expose ACL northbound write invariant gaps"
git push origin v0.9-neutron-agent
```

- [ ] **Step 4: Require exact-head hosted RED**

Use:

```bash
gh run list --branch v0.9-neutron-agent --limit 10 \
  --json databaseId,headSha,status,conclusion,url
gh run view <exact-head-run-id> --json headSha,status,conclusion,jobs,url
```

Accept RED only when:

- `headSha` equals the RED commit;
- `fast-contracts` fails in the new ACL invariant tests;
- `changes` succeeds;
- Rust behavior/build jobs are skipped for the Python-only change; and
- no unrelated job fails.

- [ ] **Step 5: Record evidence and stop before GREEN**

Update the design status with the RED commit, run/job link, failing behavior
groups, and the statement that no production code was included. Commit and
push that docs-only evidence update, require its exact-head docs CI to pass,
then stop.

Keep `REVIEW-ACL-058` and `REVIEW-ACL-061` open. The next development step is
a separate GREEN production implementation plan; `REVIEW-OPS-019` remains
after this batch.

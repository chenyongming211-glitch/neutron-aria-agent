# ACL-060/004 Native Pagination Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver bounded native Neutron pagination and field projection for all Aria ACL resources, remove SQL address-set N+1 loading, and give per-host port-status rows an exact stable identity.

**Architecture:** A small Python 2-compatible `query.py` owns public query normalization, deterministic in-memory behavior, port-status projection, and the versioned status ID. A separate `sql_query.py` translates the same normalized contract into SQLAlchemy Core expressions. Existing repositories retain CRUD and transaction ownership; the service plugin forwards the complete Neutron contract only after every resource has a valid marker.

**Tech Stack:** Python 2.7-compatible source, stdlib `unittest`/`sqlite3`, SQLAlchemy Core APIs available in `>=1.0.10,<1.1.0`, hosted SQLAlchemy 1.4.54 contract tests, Neutron 9.0 legacy service-plugin API, python-neutronclient 6.0.0, GitHub Actions.

**Approved Design:** `docs/superpowers/specs/2026-07-31-acl-060-pagination-query-design.md`

**Starting Head:** `v0.9-neutron-agent@7e5e2d98c6c3defab40bf91031db03f39e3d14f0`

## Global Constraints

- Work only on local and remote `v0.9-neutron-agent`; do not create a branch, stacked PR, or worktree.
- Before every implementation task, require a clean worktree and zero divergence from `origin/v0.9-neutron-agent`.
- Do not run local `cargo build`, `cargo check`, `cargo test`, or any other Cargo command.
- Production query code must remain importable without SQLAlchemy installed until `NeutronDbAriaAclRepository` is instantiated.
- Production query code must use only Python 2.7 syntax and SQLAlchemy APIs present in 1.0.10.
- Hosted SQL query-count coverage uses exactly `SQLAlchemy==1.4.54`; target SQLAlchemy 1.0 evidence remains field-pending.
- Do not enable plugin-native pagination/sorting before all five resources implement valid identity, filtering, sorting, marker, reverse, limit, and fields behavior.
- Keep `REVIEW-ACL-040`, `REVIEW-ACL-013`, `REVIEW-ACL-038`, datapath behavior, and database status-schema migration outside this batch.
- Preserve the current all-host behavior of legacy status delete; change only exact derived-ID delete and ambiguous legacy show.
- Every RED and GREEN claim must name the exact commit and GitHub Actions run. Missing field environment remains `deferred/pending`.

---

## File Responsibility Map

**Create**

- `openstack/neutron_aria/neutron_aria/db/aria_acl/query.py`: resource specifications, typed query normalization, deterministic memory execution, field projection, request-scoped status view, and status ID codec.
- `openstack/neutron_aria/neutron_aria/db/aria_acl/sql_query.py`: SQLAlchemy Core filter, null-order, keyset-boundary, sort, and limit construction without importing SQLAlchemy globally.
- `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_query.py`: storage-independent query, status-ID, reverse-page, marker, typed-filter, and field-projection behavior.
- `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_sql_query.py`: real SQLAlchemy repository parity and query-count budgets; skips cleanly when SQLAlchemy is absent.
- `ci/requirements-neutron-db-contracts.txt`: exact hosted SQLAlchemy dependency pin.

**Modify**

- `openstack/neutron_aria/neutron_aria/db/aria_acl/api.py`: forward complete list arguments, use shared query execution, perform SQL/SQLite bounded selection, batch-load address-set members, and add exact status-row accessors.
- `openstack/neutron_aria/neutron_aria/services/aria_acl/plugin.py`: forward every list argument, construct one status projection per request, honor show fields, fix status ambiguity, and enable native capabilities last.
- `openstack/neutron_aria/neutron_aria/extensions/aria_acl.py`: mark desired IDs explicitly primary and add visible read-only status `id`.
- `openstack/neutron_aria/neutron_aria/agent/config.py`: add `acl_page_size` with `port_page_size` fallback semantics.
- `openstack/neutron_aria/neutron_aria/agent/acl_source.py`: pass the resolved ACL page size into the REST-client factory.
- `openstack/neutron_aria/neutron_aria/agent/neutron_client.py`: accept the factory page size and preserve link/marker safety.
- `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_plugin.py`: repository/plugin integration, fields, native flags, and ambiguous status tests.
- `openstack/neutron_aria/neutron_aria/tests/unit/test_acl_source.py`: ACL page-size and multi-page status/client tests.
- `openstack/neutron_aria/neutron_aria/tests/unit/test_config.py`: explicit and fallback ACL page-size tests.
- `openstack/neutronclient_aria/neutronclient_aria/v2_0/aria_acl.py`: enable legacy list pagination/sorting and show status `id`.
- `openstack/neutronclient_aria/neutronclient_aria/tests/test_aria_acl_cli.py`: parser/search option and status-ID display/show tests.
- `ci/check_neutron_stage1.py`: execute the stdlib neutronclient extension tests in `fast-contracts`.
- `ci/test_ci_lane_contract.py`: require a separate DB-contract lane and keep it Cargo-free.
- `.github/workflows/build.yml`: add independent `neutron-db-contracts` job.
- `deploy/kolla/config/neutron-aria-agent.ini`: set bounded `acl_page_size = 100` without changing `port_page_size`.
- `docs/superpowers/specs/2026-07-31-acl-060-pagination-query-design.md`: record the implementation-time projection-context clarification and final evidence.
- `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`: update ACL-060/004 only after exact-head GREEN.

---

### Task 1: Submit the Complete RED Query and CI Contract

**Files:**

- Create: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_query.py`
- Create: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_sql_query.py`
- Create: `ci/requirements-neutron-db-contracts.txt`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_plugin.py`
- Modify: `ci/test_ci_lane_contract.py`
- Modify: `.github/workflows/build.yml`

**Interfaces:**

- Consumes: current repository/plugin public methods and the approved design at `docs/superpowers/specs/2026-07-31-acl-060-pagination-query-design.md`.
- Produces: executable RED contracts for `normalize_query`, `apply_memory_query`, `PortStatusProjection`, `encode_port_status_id`, `decode_port_status_id`, full repository list signatures, SQL query budgets, and the `neutron-db-contracts` CI lane.

- [ ] **Step 1: Add storage-independent RED tests**

Create `test_aria_acl_query.py` with imports that name the exact future API and table-driven cases that do not depend on dictionary order:

```python
from __future__ import absolute_import

import unittest

from neutron_aria.db.aria_acl.errors import AriaAclNotFound
from neutron_aria.db.aria_acl.errors import AriaAclValidationError
from neutron_aria.db.aria_acl.query import PortStatusProjection
from neutron_aria.db.aria_acl.query import apply_memory_query
from neutron_aria.db.aria_acl.query import decode_port_status_id
from neutron_aria.db.aria_acl.query import encode_port_status_id
from neutron_aria.db.aria_acl.query import normalize_query


class AriaAclQueryTestCase(unittest.TestCase):
    def setUp(self):
        self.rows = [
            {"id": "p3", "name": "same", "enabled": True, "revision_number": 3},
            {"id": "p1", "name": "same", "enabled": True, "revision_number": 1},
            {"id": "p2", "name": None, "enabled": False, "revision_number": 2},
        ]

    def test_forward_and_reverse_pages_use_identity_tie_breaker(self):
        first_query = normalize_query("policies", sorts=[("name", True)], limit=2)
        first = apply_memory_query(self.rows, first_query)
        self.assertEqual(["p2", "p1"], [row["id"] for row in first])

        second_query = normalize_query(
            "policies", sorts=[("name", True)], limit=2, marker="p1"
        )
        self.assertEqual(
            ["p3"],
            [row["id"] for row in apply_memory_query(self.rows, second_query)],
        )

        reverse_query = normalize_query(
            "policies",
            sorts=[("name", True)],
            limit=2,
            marker="p3",
            page_reverse=True,
        )
        self.assertEqual(
            ["p2", "p1"],
            [row["id"] for row in apply_memory_query(self.rows, reverse_query)],
        )

    def test_typed_filters_aliases_and_fields_are_exact(self):
        query = normalize_query(
            "policies",
            filters={"enabled": ["true"], "revision_number": ["1", "3"]},
            fields=["id", "name"],
        )
        self.assertEqual(
            [{"id": "p1", "name": "same"}, {"id": "p3", "name": "same"}],
            apply_memory_query(self.rows, query),
        )

    def test_invalid_filter_sort_and_missing_marker_fail(self):
        self.assertRaises(
            AriaAclValidationError,
            normalize_query,
            "address_sets",
            filters={"members": ["10.0.0.0/24"]},
        )
        self.assertRaises(
            AriaAclValidationError,
            normalize_query,
            "port_statuses",
            sorts=[("runtime_status", True)],
        )
        query = normalize_query("policies", limit=1, marker="missing")
        self.assertRaises(AriaAclNotFound, apply_memory_query, self.rows, query)

    def test_status_id_and_projected_filters_are_stable(self):
        status_id = encode_port_status_id("port-1", "ostack2.bj159.net")
        self.assertTrue(status_id.startswith("aria-status-v1."))
        self.assertEqual(
            ("port-1", "ostack2.bj159.net"),
            decode_port_status_id(status_id),
        )
        projection = PortStatusProjection(now_epoch=200.0, stale_seconds=90)
        rows = [{
            "port_id": "port-1",
            "host": "ostack2.bj159.net",
            "status": "ready",
            "updated_at": "1970-01-01T00:01:00.000000Z",
        }]
        query = normalize_query(
            "port_statuses",
            filters={"stale": ["true"], "runtime_status": ["stale"]},
        )
        result = apply_memory_query(rows, query, projection=projection)
        self.assertEqual([status_id], [row["id"] for row in result])


if __name__ == "__main__":
    unittest.main()
```

Add this explicit malformed-ID test:

```python
def test_status_id_rejects_every_noncanonical_form(self):
    invalid_payloads = [
        "wrong-prefix.cG9ydC0xAG9zdGFjazI",
        "aria-status-v1.***",
        "aria-status-v1." + _b64(b"port-1\x00host\x00extra"),
        "aria-status-v1." + _b64(b"port-1\x00\xff"),
        "aria-status-v1.cG9ydC0xAG9zdGFjazI=",
    ]
    for value in invalid_payloads:
        with self.subTest(value=value):
            self.assertRaises(AriaAclValidationError, decode_port_status_id, value)
    self.assertRaises(AriaAclValidationError, encode_port_status_id, "p" * 37, "host")
    self.assertRaises(AriaAclValidationError, encode_port_status_id, "port-1", "h" * 256)
```

Define test-local `_b64(payload)` with `base64.urlsafe_b64encode(payload)`,
ASCII decoding, and stripped `=` padding.

- [ ] **Step 2: Add plugin/repository RED integration tests**

In `test_aria_acl_plugin.py`, add a recording repository and tests that prove every argument and one immutable status projection reach the repository:

```python
class RecordingListRepository(object):
    def __init__(self):
        self.calls = []

    def list_policies(self, **kwargs):
        self.calls.append(("policies", kwargs))
        return [{"id": "policy-1"}]

    def list_port_statuses(self, **kwargs):
        self.calls.append(("port_statuses", kwargs))
        return []


def test_plugin_forwards_complete_list_contract(self):
    repository = RecordingListRepository()
    plugin = AriaAclPlugin(repository=repository, now=lambda: 200.0)
    result = plugin.get_aria_acl_policies(
        None,
        filters={"enabled": ["true"]},
        fields=["id"],
        sorts=[("name", False)],
        limit=10,
        marker="policy-2",
        page_reverse=True,
    )
    self.assertEqual([{"id": "policy-1"}], result)
    self.assertEqual({
        "filters": {"enabled": ["true"]},
        "fields": ["id"],
        "sorts": [("name", False)],
        "limit": 10,
        "marker": "policy-2",
        "page_reverse": True,
    }, repository.calls[0][1])
```

Add exact integration tests:

```python
def test_multi_host_legacy_status_show_is_conflict_but_id_is_exact(self):
    plugin = AriaAclPlugin(now=lambda: 200.0)
    for host in ("ostack2", "ostack3"):
        plugin.report_aria_acl_port_status(None, {"aria_acl_port_status": {
            "port_id": "port-1", "host": host, "status": "ready",
        }})
    with self.assertRaises(AriaAclConflict):
        plugin.get_aria_acl_port_status(None, "port-1")
    exact_id = encode_port_status_id("port-1", "ostack3")
    self.assertEqual(
        "ostack3", plugin.get_aria_acl_port_status(None, exact_id)["host"]
    )


def test_all_public_collections_declare_one_primary_id(self):
    for collection in aria_acl.RESOURCE_COLLECTIONS.values():
        attributes = aria_acl.API_RESOURCE_ATTRIBUTE_MAP[collection]
        primary = sorted(
            name for name, descriptor in attributes.items()
            if descriptor.get("primary_key")
        )
        self.assertEqual(["id"], primary, collection)
```

- [ ] **Step 3: Add real SQLAlchemy RED query-count tests**

Create `test_aria_acl_sql_query.py`. Keep module import safe when SQLAlchemy is
absent and run the real cases only in the DB lane:

```python
from __future__ import absolute_import

import unittest

try:
    import sqlalchemy as sa
    from sqlalchemy import event
    from sqlalchemy.orm import sessionmaker
except ImportError:
    sa = None


@unittest.skipIf(sa is None, "SQLAlchemy DB contracts run in their own CI lane")
class AriaAclSqlQueryTestCase(unittest.TestCase):
    def setUp(self):
        from neutron_aria.db.aria_acl.api import NeutronDbAriaAclRepository

        engine = sa.create_engine("sqlite://")
        session = sessionmaker(bind=engine)()
        context = type("Context", (), {"session": session})()
        self.repository = NeutronDbAriaAclRepository(context, auto_create=True)
        self.engine = engine
        self.statements = []
        event.listen(
            engine,
            "before_cursor_execute",
            lambda conn, cursor, statement, parameters, context, executemany:
                self.statements.append(statement),
        )

    def test_address_set_page_uses_constant_member_queries(self):
        for index in range(8):
            self.repository.create_address_set({
                "id": "set-%02d" % index,
                "project_id": "project-1",
                "members": [{"address": "10.0.%d.0/24" % index}],
            })
        self.statements[:] = []
        page = self.repository.list_address_sets(
            fields=["id", "members"], sorts=[("id", True)], limit=5
        )
        self.assertEqual(5, len(page))
        self.assertEqual(2, len(self.statements))

        self.statements[:] = []
        without_members = self.repository.list_address_sets(
            fields=["id"], sorts=[("id", True)], limit=5
        )
        self.assertEqual(5, len(without_members))
        self.assertEqual(1, len(self.statements))
        self.assertNotIn("members", without_members[0])
```

Add `test_repository_query_parity()` that creates policy IDs `p3,p1,p2`, then
asserts the same ID sequences as `AriaAclQueryTestCase` for forward and reverse
`name` pages. Add `test_status_composite_marker()` with two hosts for one port
and one second port; assert every derived ID appears once across `limit=1`
pages. Add `test_custom_marker_cost_is_constant()` that resets
`self.statements`, requests `sorts=[("name", True)]`, `marker="p1"`, and
asserts exactly two statements: marker lookup plus page select. Use the same
typed-filter values `enabled=["true"]` and `revision_number=["1", "3"]` as
the storage-independent test.

- [ ] **Step 4: Add the separate DB-contract CI lane and lane tests**

Create `ci/requirements-neutron-db-contracts.txt` containing exactly:

```text
SQLAlchemy==1.4.54
```

Add this independent job after `fast-contracts` in `build.yml`:

```yaml
  neutron-db-contracts:
    runs-on: ubuntu-22.04
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1

      - name: Install Neutron DB contract dependencies
        run: python3 -m pip install --requirement ci/requirements-neutron-db-contracts.txt

      - name: Run Neutron DB query contracts
        env:
          PYTHONPATH: openstack/neutron_aria
        run: python3 -m unittest neutron_aria.tests.unit.test_aria_acl_sql_query
```

Update `test_ci_lane_contract.py` to require six pinned checkout uses, require
the job and exact requirements file, and forbid Cargo in it:

```python
def test_neutron_db_contracts_are_independent_and_cargo_free(self):
    db_contracts = job_block(self.source, "neutron-db-contracts")
    self.assertIn("ci/requirements-neutron-db-contracts.txt", db_contracts)
    self.assertIn("test_aria_acl_sql_query", db_contracts)
    self.assertNotRegex(db_contracts, r"\bcargo\b")
    self.assertNotIn("needs: rust-build", db_contracts)
```

- [ ] **Step 5: Run only safe local RED checks**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=openstack/neutron_aria \
  python3 -m unittest neutron_aria.tests.unit.test_aria_acl_query \
  neutron_aria.tests.unit.test_aria_acl_plugin
python3 -m unittest ci.test_ci_lane_contract
```

Expected: query tests fail because `neutron_aria.db.aria_acl.query` does not
exist; plugin tests fail on discarded arguments/ambiguous status; CI lane
contract passes. Do not install SQLAlchemy locally and do not run Cargo.

- [ ] **Step 6: Commit, push, and record hosted RED**

```bash
git add .github/workflows/build.yml \
  ci/requirements-neutron-db-contracts.txt ci/test_ci_lane_contract.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_query.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_sql_query.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_plugin.py
git commit -m "test: expose ACL pagination and status identity gaps"
git push origin v0.9-neutron-agent
```

Use `gh run list --workflow Build --branch v0.9-neutron-agent` and
`gh run view <run-id> --log-failed`. Expected hosted result: the new named
query/plugin/DB contracts fail for missing behavior; unrelated existing
contracts do not regress. Record the exact commit and run ID in the plan before
starting Task 2.

---

### Task 2: Implement the Shared Query Contract and In-Memory Reference

**Files:**

- Create: `openstack/neutron_aria/neutron_aria/db/aria_acl/query.py`
- Modify: `openstack/neutron_aria/neutron_aria/db/aria_acl/api.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_query.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_plugin.py`

**Interfaces:**

- Consumes: `AriaAclValidationError`, `AriaAclNotFound`, dictionaries returned by existing repositories.
- Produces: `QuerySpec`, `NormalizedQuery`, `PortStatusProjection`, `normalize_query()`, `apply_memory_query()`, `project_fields()`, field-aware repository get methods, `encode_port_status_id()`, and `decode_port_status_id()`.

- [ ] **Step 1: Define exact resource specifications and normalized types**

Implement Python 2-compatible immutable-by-convention objects:

```python
class QuerySpec(object):
    def __init__(self, name, public_identity_field, identity_fields, aliases,
                 field_types, visible_fields, filterable_fields,
                 sortable_fields):
        self.name = name
        self.public_identity_field = public_identity_field
        self.identity_fields = tuple(identity_fields)
        self.aliases = dict(aliases)
        self.field_types = dict(field_types)
        self.visible_fields = frozenset(visible_fields)
        self.filterable_fields = frozenset(filterable_fields)
        self.sortable_fields = frozenset(sortable_fields)


class NormalizedQuery(object):
    def __init__(self, spec, filters, fields, sorts, limit, marker,
                 page_reverse):
        self.spec = spec
        self.filters = filters
        self.fields = tuple(fields) if fields else None
        self.sorts = tuple(sorts)
        self.limit = limit
        self.marker = marker
        self.page_reverse = bool(page_reverse)
```

Define specs for `policies`, `rules`, `address_sets`, `bindings`, and
`port_statuses`, all with public identity field `id`. Desired identity fields
are `(id,)`; status identity fields are `(port_id, host)`. Expand public status
`id` into missing compound sort components, preserving explicit user sort
direction and avoiding duplicate columns. Reject address-set `members`, status
`tenant_id`, status `stale` sort, and status `runtime_status` sort. Fields may
include every visible attribute even when that attribute is intentionally not
filterable/sortable.

- [ ] **Step 2: Implement strict normalization and the status codec**

Implement these exact call signatures:

```python
def normalize_query(resource, filters=None, fields=None, sorts=None,
                    limit=None, marker=None, page_reverse=False):
    return NormalizedQuery(
        spec=_spec(resource),
        filters=_normalize_filters(_spec(resource), filters or {}),
        fields=_normalize_fields(_spec(resource), fields),
        sorts=_normalize_sorts(_spec(resource), sorts or []),
        limit=_normalize_limit(limit),
        marker=marker,
        page_reverse=page_reverse,
    )


def encode_port_status_id(port_id, host):
    port_bytes = _identity_utf8(port_id, "port_id", 36)
    host_bytes = _identity_utf8(host, "host", 255)
    payload = port_bytes + b"\x00" + host_bytes
    encoded = base64.urlsafe_b64encode(payload).rstrip(b"=")
    return "aria-status-v1." + encoded.decode("ascii")


def decode_port_status_id(value):
    prefix = "aria-status-v1."
    if not isinstance(value, STRING_TYPES) or not value.startswith(prefix):
        raise AriaAclValidationError("invalid aria_acl_port_status id prefix")
    encoded = value[len(prefix):]
    if not encoded or "=" in encoded or re.match(r"^[A-Za-z0-9_-]+$", encoded) is None:
        raise AriaAclValidationError("invalid aria_acl_port_status id encoding")
    try:
        payload = base64.urlsafe_b64decode(
            encoded.encode("ascii") + b"=" * (-len(encoded) % 4)
        )
    except (TypeError, ValueError, binascii.Error):
        raise AriaAclValidationError("invalid aria_acl_port_status id encoding")
    if payload.count(b"\x00") != 1:
        raise AriaAclValidationError("invalid aria_acl_port_status id payload")
    port_bytes, host_bytes = payload.split(b"\x00", 1)
    try:
        port_id = port_bytes.decode("utf-8")
        host = host_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise AriaAclValidationError("invalid aria_acl_port_status id utf8")
    _identity_utf8(port_id, "port_id", 36)
    _identity_utf8(host, "host", 255)
    if encode_port_status_id(port_id, host) != value:
        raise AriaAclValidationError("noncanonical aria_acl_port_status id")
    return port_id, host
```

Define `_identity_utf8(value, field, maximum)` to accept text/bytes, strictly
decode UTF-8, reject empty values and embedded NUL, enforce the byte limit, and
return encoded bytes. Define `STRING_TYPES` with the same Python 2 fallback
already used in `api.py`.

`_normalize_filters()` converts only canonical decimal integers and
case-insensitive `true`/`false`/`1`/`0`. It aliases desired `tenant_id` to
`project_id`, ORs values inside each field, and preserves an empty list as a
match-none sentinel. It raises `AriaAclValidationError` with resource and field
in every invalid message.

- [ ] **Step 3: Implement one request-scoped status projection**

```python
class PortStatusProjection(object):
    def __init__(self, now_epoch, stale_seconds):
        self.now_epoch = float(now_epoch)
        self.stale_seconds = int(stale_seconds)

    def project(self, row):
        value = dict(row)
        value["id"] = encode_port_status_id(value["port_id"], value["host"])
        value.setdefault("last_reported_at", value.get("updated_at"))
        value["stale"] = self._is_stale(value.get("updated_at"))
        value["runtime_status"] = (
            "stale" if value["stale"] else value.get("status") or "unknown"
        )
        return value
```

Reuse the existing accepted timestamp grammar. Missing or malformed
`updated_at` is stale. A negative stale threshold disables staleness. Do not
read the clock inside `project()`.

- [ ] **Step 4: Implement deterministic memory execution**

`apply_memory_query(rows, query, projection=None)` must execute in this exact
order: clone/project, filter, stable comparator sort, marker lookup, directional
slice, logical-order restoration, and field projection.

Use an explicit comparator through `functools.cmp_to_key` on Python 3 and a
small compatibility wrapper on Python 2. Compare NULL rank first, then value,
then the next sort component. A missing marker raises `AriaAclNotFound`; a
malformed status marker is rejected before scanning.

```python
def project_fields(row, fields):
    if not fields:
        return dict(row)
    return dict((field, row[field]) for field in fields if field in row)
```

- [ ] **Step 5: Route the in-memory repository through the shared executor**

Change all five in-memory list signatures to the complete contract. Each
desired method calls `normalize_query()` plus `apply_memory_query()`. Status
adds `projection=None` and requires the plugin/tests to supply a
`PortStatusProjection` when projected fields are queried.

```python
def list_policies(self, filters=None, fields=None, sorts=None, limit=None,
                  marker=None, page_reverse=False):
    query = normalize_query(
        "policies", filters, fields, sorts, limit, marker, page_reverse
    )
    return apply_memory_query(self.policies.values(), query)
```

Remove `_matches_filters()` only after no repository uses it.

Make the four in-memory desired-resource get methods accept `fields=None` and
apply `project_fields()` after their existing not-found check. Internal write
paths continue calling them without fields and therefore receive complete
objects.

- [ ] **Step 6: Verify the common and in-memory GREEN subset**

Run:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=openstack/neutron_aria \
  python3 -m unittest neutron_aria.tests.unit.test_aria_acl_query
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=openstack/neutron_aria \
  python3 -m unittest neutron_aria.tests.unit.test_aria_acl_plugin
```

Expected: storage-independent and in-memory repository cases pass. SQLAlchemy
and plugin forwarding/native cases may remain RED until later tasks.

- [ ] **Step 7: Commit the bounded shared contract**

```bash
git add openstack/neutron_aria/neutron_aria/db/aria_acl/query.py \
  openstack/neutron_aria/neutron_aria/db/aria_acl/api.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_query.py
git commit -m "feat: add deterministic ACL query contract"
```

---

### Task 3: Implement Bounded SQLAlchemy and SQLite Queries

**Files:**

- Create: `openstack/neutron_aria/neutron_aria/db/aria_acl/sql_query.py`
- Modify: `openstack/neutron_aria/neutron_aria/db/aria_acl/api.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_sql_query.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_plugin.py`

**Interfaces:**

- Consumes: `NormalizedQuery`, resource specs, and optional `PortStatusProjection` from Task 2.
- Produces: `build_select(sa, table, query, marker_row=None, projection=None)`, bounded SQL repository list methods, SQLite SQL paging, and `_members_for_sets(address_set_ids)`.

- [ ] **Step 1: Implement SQLAlchemy Core expression building**

Create `sql_query.py` without a module-level SQLAlchemy import. Implement:

```python
def build_select(sa, table, query, marker_row=None, projection=None):
    statement = table.select()
    statement = _apply_filters(sa, statement, table, query, projection)
    if marker_row is not None:
        statement = statement.where(
            _keyset_boundary(sa, table, query.sorts, marker_row,
                             query.page_reverse, projection)
        )
    statement = statement.order_by(
        *_order_clauses(sa, table, query.sorts, query.page_reverse, projection)
    )
    if query.limit is not None:
        statement = statement.limit(query.limit)
    return statement
```

Build lexicographic boundaries as an OR of prefix-equality plus one directional
comparison per sort component. Resolve NULL rank with `CASE` expressions so
SQLite/MySQL dialect defaults cannot differ. Reverse the fetched row list only
when `page_reverse` and `limit` are active.

- [ ] **Step 2: Replace SQLAlchemy full-table `_list()`**

Give every SQL repository list method the full signature. Resolve marker rows
by primary identity before building custom-sort boundaries. Desired marker
lookup uses `table.c.id`; status marker decoding uses `port_id` and `host`.

Convert only selected page rows. Pass `include_members=False` into row
conversion during page selection so address-set conversion never performs a
per-row member query.

- [ ] **Step 3: Batch-load address-set members**

Replace `_members_for_set()` calls from list conversion with:

```python
def _members_for_sets(self, address_set_ids):
    grouped = dict((address_set_id, []) for address_set_id in address_set_ids)
    if not address_set_ids:
        return grouped
    table = self.tables["address_set_members"]
    rows = self.session.execute(
        table.select().where(table.c.address_set_id.in_(address_set_ids)).order_by(
            table.c.address_set_id.asc(), table.c.address.asc(), table.c.id.asc()
        )
    ).fetchall()
    for row in rows:
        grouped[row["address_set_id"]].append({"address": row["address"]})
    return grouped
```

Call it exactly once after page selection only when full fields or explicit
`members` were requested. Keep single-row show at one row query plus one member
query when members are requested.

Make every SQLAlchemy and SQLite desired-resource get method accept
`fields=None`. For address sets, pass
`include_members=(not fields or "members" in fields)` into row conversion so
`fields=["id"]` executes only the row query. Apply `project_fields()` after
conversion. Internal write paths omit fields and retain their existing
complete-object behavior.

- [ ] **Step 4: Implement SQLite SQL paging without a Python full-table fallback**

Register `aria_json_scalar(payload, field)` on the SQLite connection. The
function JSON-decodes one payload and returns only a scalar field. Use indexed
columns for ID/project/policy/target/default sorts and use `json_extract` or
the registered function for supported non-indexed scalar expressions.

Build parameterized WHERE, keyset, ORDER BY, and LIMIT clauses. Never
interpolate field names unless they came from the fixed resource specification.
Decode payloads only from selected rows, then apply exact field projection.

- [ ] **Step 5: Run hosted DB contracts and focused local stdlib tests**

Do not install SQLAlchemy locally. Run the SQLite/common subset:

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=openstack/neutron_aria \
  python3 -m unittest neutron_aria.tests.unit.test_aria_acl_query \
  neutron_aria.tests.unit.test_aria_acl_plugin
```

Commit and push:

```bash
git add openstack/neutron_aria/neutron_aria/db/aria_acl/sql_query.py \
  openstack/neutron_aria/neutron_aria/db/aria_acl/api.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_sql_query.py
git commit -m "fix: bound ACL repository list queries"
git push origin v0.9-neutron-agent
```

Inspect the exact Build. Expected: `neutron-db-contracts` passes query-count and
pagination tests. Remaining plugin/status/client RED tests are allowed; no
unrelated lane may regress.

---

### Task 4: Add Exact Port-Status Identity and ACL-004 Semantics

**Files:**

- Modify: `openstack/neutron_aria/neutron_aria/db/aria_acl/api.py`
- Modify: `openstack/neutron_aria/neutron_aria/services/aria_acl/plugin.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_plugin.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_query.py`

**Interfaces:**

- Consumes: `PortStatusProjection`, `encode_port_status_id()`, and `decode_port_status_id()` from Task 2.
- Produces: `get_port_status_resource(resource_id)`, `delete_port_status_resource(resource_id)`, exact derived-ID show/delete, and legacy multi-host HTTP 409.

- [ ] **Step 1: Add exact status accessors to all repositories**

Add this shared resolver to `query.py` so all repositories classify legacy
ambiguity identically:

```python
def require_one_legacy_port_status(port_id, statuses):
    if not statuses:
        raise AriaAclNotFound("aria_acl_port_status %s not found" % port_id)
    if len(statuses) > 1:
        hosts = sorted(status.get("host") or "" for status in statuses)
        raise AriaAclConflictError(
            "ambiguous_port_status port_id=%s hosts=%s" %
            (port_id, ",".join(hosts))
        )
    return statuses[0]
```

Implement the same public-resource interface in memory, SQLAlchemy, and
SQLite:

```python
def get_port_status_resource(self, resource_id):
    if resource_id.startswith("aria-status-v1."):
        port_id, host = decode_port_status_id(resource_id)
        value = self.get_port_status(port_id, host=host)
        if value is None:
            raise AriaAclNotFound(
                "aria_acl_port_status %s/%s not found" % (port_id, host)
            )
        return value
    return require_one_legacy_port_status(
        resource_id, self.get_port_status(resource_id)
    )


def delete_port_status_resource(self, resource_id):
    if resource_id.startswith("aria-status-v1."):
        port_id, host = decode_port_status_id(resource_id)
        return self.delete_port_status(port_id, host=host)
    return self.delete_port_status(resource_id, host=None)
```

Do not add a database column or migration.

- [ ] **Step 2: Make status show deterministic**

In the plugin, call `get_port_status_resource(resource_id)` through
`ErrorMappingRepositoryProxy`. The repository resolver emits
`AriaAclNotFound` or `AriaAclConflictError`, so the existing proxy maps them to
HTTP 404/409. Do not raise a raw repository exception from plugin code.

The shared resolver enforces:

```python
zero legacy matches -> AriaAclNotFound -> HTTP 404
one legacy match    -> exact row
many legacy matches -> AriaAclConflictError -> HTTP 409
```

Project the selected row with one `PortStatusProjection`, then apply fields.
Map the existing conflict error to HTTP 409 through the existing proxy.

- [ ] **Step 3: Preserve delete compatibility explicitly**

The plugin calls `delete_port_status_resource(resource_id)` through the proxy.
Derived status ID deletes only the decoded row. A legacy port ID continues to
call `delete_port_status(port_id, host=None)` and removes all host rows. Add
tests for both behaviors so a future refactor cannot accidentally reinterpret
legacy delete as arbitrary single-row deletion.

- [ ] **Step 4: Verify status identity GREEN**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=openstack/neutron_aria \
  python3 -m unittest \
  neutron_aria.tests.unit.test_aria_acl_query.AriaAclQueryTestCase \
  neutron_aria.tests.unit.test_aria_acl_plugin.AriaAclPluginTestCase
```

Expected: derived-ID round trips, exact show/delete, unique legacy show, and
ambiguous legacy 409 all pass across memory and SQLite fixtures.

- [ ] **Step 5: Commit**

```bash
git add openstack/neutron_aria/neutron_aria/db/aria_acl/api.py \
  openstack/neutron_aria/neutron_aria/services/aria_acl/plugin.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_query.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_plugin.py
git commit -m "fix: give ACL port status an exact identity"
```

---

### Task 5: Wire the Complete Plugin Contract and Enable Native Paging Last

**Files:**

- Modify: `openstack/neutron_aria/neutron_aria/services/aria_acl/plugin.py`
- Modify: `openstack/neutron_aria/neutron_aria/extensions/aria_acl.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_plugin.py`

**Interfaces:**

- Consumes: full repository signatures and status identity from Tasks 2-4.
- Produces: complete list/show field behavior and Neutron-recognized `__native_sorting_support`/`__native_pagination_support` flags.

- [ ] **Step 1: Forward the standard arguments through every list method**

Use one explicit call shape rather than `**locals()`:

```python
return self._repo(context).list_policies(
    filters=filters,
    fields=fields,
    sorts=sorts,
    limit=limit,
    marker=marker,
    page_reverse=page_reverse,
)
```

Repeat for rules, address sets, and bindings. Status constructs exactly one:

```python
projection = PortStatusProjection(
    now_epoch=self.now(),
    stale_seconds=self._port_status_stale_seconds(),
)
```

and passes it as `projection=projection` with the six standard arguments.

- [ ] **Step 2: Apply show fields without hiding not-found semantics**

For all desired show methods, pass `fields=fields` into the repository get
method. The controller already adds authorization-required fields before
calling the plugin, so the repository returns them and the controller strips
only temporary additions afterward. Do not turn `None` into `{}` and do not
perform a second plugin-side projection.

- [ ] **Step 3: Declare explicit primary keys**

In `extensions/aria_acl.py`, change every desired resource ID descriptor to:

```python
"id": {
    "allow_post": False,
    "allow_put": False,
    "is_visible": True,
    "primary_key": True,
},
```

Add the same descriptor to port statuses. Do not mark `port_id` or `host` as a
second primary key because Neutron 9.0 selects only one scalar marker field.

- [ ] **Step 4: Enable native capabilities only after all tests pass**

Add class-private flags to `AriaAclPlugin`:

```python
class AriaAclPlugin(object):
    __native_sorting_support = True
    __native_pagination_support = True
    supported_extension_aliases = ["aria-acl"]
```

Test both mangled attributes through the legacy helper naming convention and
verify every list method accepts a controller-appended ID sort.

- [ ] **Step 5: Run plugin and complete repository behavior tests**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=openstack/neutron_aria \
  python3 -m unittest neutron_aria.tests.unit.test_aria_acl_query \
  neutron_aria.tests.unit.test_aria_acl_plugin
```

Expected: all named tests pass locally except SQLAlchemy cases skipped due to
the intentionally absent dependency.

- [ ] **Step 6: Commit and push the server GREEN boundary**

```bash
git add openstack/neutron_aria/neutron_aria/services/aria_acl/plugin.py \
  openstack/neutron_aria/neutron_aria/extensions/aria_acl.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_aria_acl_plugin.py
git commit -m "fix: enable native ACL list pagination"
git push origin v0.9-neutron-agent
```

Expected hosted result: common, plugin, and DB repository contracts pass.
Client/config/CLI tests may remain RED until Task 6.

---

### Task 6: Wire Agent Page Size and Legacy CLI Consumption

**Files:**

- Modify: `openstack/neutron_aria/neutron_aria/agent/config.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/acl_source.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/neutron_client.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_config.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_acl_source.py`
- Modify: `openstack/neutronclient_aria/neutronclient_aria/v2_0/aria_acl.py`
- Modify: `openstack/neutronclient_aria/neutronclient_aria/tests/test_aria_acl_cli.py`
- Modify: `ci/check_neutron_stage1.py`
- Modify: `deploy/kolla/config/neutron-aria-agent.ini`

**Interfaces:**

- Consumes: server next links and stable `id` values from Task 5.
- Produces: `AgentConfig.acl_page_size`, `resolved_acl_page_size()`, a page-size-aware ACL client factory, and CLI `--page-size`/`--sort-key`/`--sort-dir` support.

- [ ] **Step 1: Add explicit ACL page-size configuration**

Add `acl_page_size=None` to `AgentConfig`. Validate configured page sizes as
positive integers; zero and negative values raise `ConfigError`.

```python
def resolved_acl_page_size(config):
    if config.acl_page_size is not None:
        return config.acl_page_size
    return config.port_page_size
```

Load `[neutron] acl_page_size`. Set both values in the deployment sample:

```ini
[neutron]
port_page_size = 100
acl_page_size = 100
```

Do not route `acl_page_size` into `NeutronPortSource`.

- [ ] **Step 2: Pass the resolved size only to ACL reads**

Change the factory to:

```python
def build_aria_acl_client_from_env(env=None, page_size=None):
    return AriaAclRestClient(
        build_neutronclient_from_env(env=env),
        page_size=page_size,
    )
```

In `build_acl_source()`, call it with
`page_size=resolved_acl_page_size(config)`. Leave status-reporter construction
without a page size because it writes only. Preserve the current repeated-marker
guard and missing-ID stop/error behavior.

- [ ] **Step 3: Add agent tests for explicit, fallback, and partial failure**

Add tests that assert:

```python
self.assertEqual(25, AgentConfig(acl_page_size=25).acl_page_size)
self.assertEqual(50, resolved_acl_page_size(
    AgentConfig(acl_page_size=None, port_page_size=50)
))
```

Use a fake factory/client to prove `build_acl_source()` passes 25 to the ACL
client while `build_port_source()` still uses `port_page_size`. Extend the
multi-page REST-client test to status rows carrying derived IDs. Add a
three-page desired-state load where page 3 raises and assert no
`EffectiveAclIndex` is returned or published.

- [ ] **Step 4: Enable pagination and sorting in the CLI mixin**

Set:

```python
class _AriaAclCommandMixin(object):
    pagination_support = True
    sorting_support = True
```

The python-neutronclient 6.0.0 `ListCommand.retrieve_list()` appends `limit`,
`sort_key`, and `sort_dir` after the custom `args2search_opts()`, so do not
duplicate those parameters. Add `id` as the first port-status list column.

Add CLI tests that build a real parser and assert `--page-size 25 --sort-key
name --sort-dir desc` reaches `list_ext()` unchanged. Add a status-show test
whose positional ID is
`aria-status-v1.cG9ydC0xAG9zdGFjazI` and assert the same value reaches
`show_ext()`.

- [ ] **Step 5: Put CLI tests in fast-contracts**

Add a separate function to `ci/check_neutron_stage1.py`:

```python
def run_neutronclient_extension_tests():
    env = os.environ.copy()
    root = os.path.join(ROOT, "openstack", "neutronclient_aria")
    env["PYTHONPATH"] = root + (
        os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else ""
    )
    run([
        sys.executable,
        "-m",
        "unittest",
        "neutronclient_aria.tests.test_aria_acl_cli",
    ], env=env)
```

Call it from `run_fast_contracts()` immediately after the Neutron agent Python
tests.

- [ ] **Step 6: Run focused and full fast contracts**

```bash
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=openstack/neutron_aria \
  python3 -m unittest neutron_aria.tests.unit.test_config \
  neutron_aria.tests.unit.test_acl_source
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=openstack/neutronclient_aria \
  python3 -m unittest neutronclient_aria.tests.test_aria_acl_cli
PYTHONDONTWRITEBYTECODE=1 python3 ci/check_neutron_stage1.py --fast-contracts
```

Expected: all commands pass. The known `SafeConfigParser` deprecation warning
may appear; no new warning is accepted.

- [ ] **Step 7: Commit and push the complete GREEN implementation**

```bash
git add openstack/neutron_aria/neutron_aria/agent/config.py \
  openstack/neutron_aria/neutron_aria/agent/acl_source.py \
  openstack/neutron_aria/neutron_aria/agent/neutron_client.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_config.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_acl_source.py \
  openstack/neutronclient_aria/neutronclient_aria/v2_0/aria_acl.py \
  openstack/neutronclient_aria/neutronclient_aria/tests/test_aria_acl_cli.py \
  ci/check_neutron_stage1.py deploy/kolla/config/neutron-aria-agent.ini
git commit -m "feat: consume bounded ACL pages in agent and CLI"
git push origin v0.9-neutron-agent
```

Watch the exact Build. Expected: `fast-contracts`, `neutron-db-contracts`, and
`changes` pass. Rust jobs may run because workflow/CI inputs changed, but they
remain separate jobs and no local Cargo command is used.

---

### Task 7: Exact-Head Review, Regression Gate, and Evidence Closure

**Files:**

- Modify: `docs/superpowers/specs/2026-07-31-acl-060-pagination-query-design.md`
- Modify: `docs/superpowers/plans/2026-07-31-acl-060-004-native-pagination.md`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`

**Interfaces:**

- Consumes: all production commits and exact-head hosted Build evidence.
- Produces: source-fixed ACL-060/004 records with field evidence explicitly pending.

- [ ] **Step 1: Review the complete diff against the design**

Run read-only checks:

```bash
git diff --check 7e5e2d9..HEAD
git diff --stat 7e5e2d9..HEAD
git diff --name-status 7e5e2d9..HEAD
git log --oneline --reverse 7e5e2d9..HEAD
```

Review every changed function call and confirm:

- no repository silently reads a complete production table for supported pages;
- native flags appear only after all five resources are wired;
- status ID is virtual and no migration exists;
- no ACL-040/013/038 behavior was absorbed;
- no static checker binds private helper shape; and
- no Cargo command was added to fast or DB contract jobs.

- [ ] **Step 2: Run the complete safe local verification set**

```bash
git diff --check
python3 ci/check_blocked_terms.py
python3 ci/check_build_workflow_contract.py
python3 -m unittest ci.test_ci_lane_contract
PYTHONDONTWRITEBYTECODE=1 python3 ci/check_neutron_stage1.py --fast-contracts
```

Expected: all pass. SQLAlchemy tests remain hosted in their dedicated lane.

- [ ] **Step 3: Require one exact-head hosted GREEN Build**

Push any review corrections, then identify the run whose head SHA exactly
matches `git rev-parse HEAD`:

```bash
git push origin v0.9-neutron-agent
gh run list --workflow Build --branch v0.9-neutron-agent --limit 10
gh run view <exact-head-run-id>
```

Required jobs:

- `changes`: success;
- `fast-contracts`: success;
- `neutron-db-contracts`: success;
- `rust-behavior`/`rust-build`: success when the detector requires them,
  otherwise GitHub's explicit skipped result is acceptable.

- [ ] **Step 4: Update design, plan, and backlog evidence truthfully**

Update ACL-060 to `fixed` only after exact-head hosted GREEN. Update ACL-004 to
`fixed` only after exact/legacy status tests and CLI tests pass. Record:

```text
source implementation and hosted CI complete;
target Neutron 9.0/Python 2/SQLAlchemy 1.0 field evidence deferred
```

Do not write `field validated`, `production ready`, or `PASS` for the absent
target smoke. Add commit IDs, run URL, job URLs, test counts, and the exact
query budgets.

- [ ] **Step 5: Commit and push documentation closure**

```bash
git add docs/superpowers/specs/2026-07-31-acl-060-pagination-query-design.md \
  docs/superpowers/plans/2026-07-31-acl-060-004-native-pagination.md \
  docs/openstack-neutron-aria-details/12-review-bug-backlog.md
git commit -m "docs: close ACL pagination source findings"
git push origin v0.9-neutron-agent
```

Require a final exact-head Build for the documentation closure commit because
the branch gate applies to every delivered head. Record that run without
changing the field-evidence status.

---

## Deferred Field Evidence

When the target environment becomes available, run one Python 2/Neutron 9.0
service-plugin smoke that proves:

1. forward and reverse pages for all five resources;
2. custom sort plus identity tie-breakers;
3. `fields` projection, including address sets without `members`;
4. multi-host status next links and exact derived-ID show;
5. explicit 409 for ambiguous legacy status show;
6. SQL statement count remains constant for one address-set page; and
7. existing CRUD, notifier, full-resync, and status-report flows remain intact.

Until that evidence exists, no further source change is implied and neither
finding is described as field-validated.

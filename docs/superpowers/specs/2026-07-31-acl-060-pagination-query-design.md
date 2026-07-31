# REVIEW-ACL-060/004 ACL Query and Status Identity Design

Date: 2026-07-31

Status: design approved; production implementation and RED behavior tests have
not started

Analyzed target:
`v0.9-neutron-agent@ebd0b758a2244b294cc6aec38377d868278748d3`

Tracked findings:

- `REVIEW-ACL-060`: ACL list pagination, field projection, and address-set N+1
  queries
- `REVIEW-ACL-004`: ambiguous multi-host port-status show behavior

## 1. Executive Decision

The Aria ACL service plugin will implement one native, deterministic query
contract for policies, rules, address sets, bindings, and per-host port-status
reports. All three repositories will accept the complete Neutron list
contract: filters, fields, sorts, limit, marker, and page direction.

The contract will use keyset pagination. Every requested sort is extended with
the resource identity as a final tie-breaker. The SQLAlchemy repository will
push supported scalar filters, ordering, marker boundaries, and limits into
SQL. Address-set members will be loaded once for the selected page rather than
once per row. SQLite and in-memory repositories will expose identical public
behavior through the same query specification and comparison rules.

Per-host port-status rows will gain a virtual, versioned `id` derived from the
existing `(port_id, host)` database identity. This gives Neutron's legacy
single-marker pagination controller a unique field without adding a database
column or backfill migration. Exact status show/delete operations will accept
the derived ID. A legacy port-ID show remains compatible only while it resolves
to zero or one row; multiple rows return an explicit conflict instead of an
arbitrary first row.

This batch deliberately does not change status upsert concurrency, implement
the Neutron port-extension projection, choose an authoritative host for a
migrating port, or change ACL datapath behavior. Those remain in
`REVIEW-ACL-040`, `REVIEW-ACL-013`, and their existing follow-up order.

## 2. Confirmed Current Defects

### 2.1 The service layer discards the list contract

All five list methods accept the standard Neutron arguments but pass only
`filters` to their repositories. Consequently:

- client sorting is ignored;
- `limit`, `marker`, and `page_reverse` are ignored;
- requested fields are ignored; and
- the repositories fetch complete collections.

The four desired-state show methods also ignore `fields`.

### 2.2 Current controller emulation still reads whole collections

`AriaAclPlugin` does not advertise native sorting or native pagination. The
target Neutron 9.0 controller therefore calls the plugin without sort and page
arguments, sorts the returned Python list, and slices it afterward. This can
produce correct small responses for resources with an `id`, but it cannot
bound database work or memory use.

Native pagination and sorting capability flags are plugin-wide in this
Neutron release. They cannot be enabled safely until every collection exposed
by the plugin has a valid identity and implements the same contract.

### 2.3 Port status has no controller-compatible identity

The persistence identity is `(port_id, host)` in all three repositories. The
API resource has no `id`, while the Neutron controller selects one scalar
primary-key field for marker generation and defaults to `id`.

Marking `port_id` as the primary key would still be invalid because one port
can retain reports from multiple hosts. Such rows would produce the same
marker and make forward/reverse pages ambiguous. The existing show method has
the same identity defect: a request without `host` returns the first matching
row, whose order is not defined.

### 2.4 Filter values and stored values use different types

Legacy Neutron passes query filters as lists, normally containing strings.
Current repository filtering compares values directly. Boolean and numeric
filters can therefore compare values such as `"true"` with `True`, or `"100"`
with `100`, and silently fail. `tenant_id` is also not consistently mapped to
the stored `project_id` field.

### 2.5 SQLAlchemy and SQLite perform unbounded reads

`NeutronDbAriaAclRepository._list()` selects every row, converts it to a
dictionary, and applies filters in Python. `SqliteAriaAclRepository._list()`
selects and JSON-decodes every payload before filtering.

For an address-set list, SQLAlchemy row conversion calls a separate member
query for each row. Listing N address sets therefore performs `1 + N` queries,
including when the caller did not request `members`.

### 2.6 The agent does not enable ACL collection paging

`AriaAclRestClient` can send `limit` and follow collection links, but
`build_aria_acl_client_from_env()` never supplies its `page_size`. The existing
`port_page_size` setting is wired only to core Neutron port listing. Normal
desired-state resync therefore requests the four ACL collections without a
limit.

## 3. Considered Approaches

### 3.1 Desired resources only; leave status emulated

Rejected. Native pagination support is advertised by the plugin, not per
resource, in the target runtime. Leaving status without a unique marker either
blocks native pagination for every ACL resource or leaves one collection with
an invalid contract.

### 3.2 Add and persist a surrogate status UUID

Rejected for this batch. It requires an additive schema migration, existing-row
backfill, an ID-preserving upsert contract, downgrade handling, and privileged
database evidence. The UUID would also hide, rather than model, the existing
compound identity.

### 3.3 Versioned derived status ID plus a shared native query contract

Selected. A deterministic virtual ID represents the existing compound key and
requires no data migration. A small shared query specification prevents the
three repositories from developing different filter, sort, and marker
semantics, while each repository retains a storage-appropriate execution
path.

## 4. Public Query Contract

### 4.1 Repository method shape

Every list method will accept:

```python
def list_policies(
    filters=None,
    fields=None,
    sorts=None,
    limit=None,
    marker=None,
    page_reverse=False,
):
    ...
```

The equivalent signature applies to rules, address sets, bindings, and port
statuses. Plugin list methods forward every argument unchanged after basic
normalization. Desired-state show methods and status show apply `fields` to the
final public response.

Port-status list additionally accepts an internal optional `projection`
keyword containing one immutable request-scoped timestamp and stale threshold.
The plugin constructs it once and the repositories use it to translate
`stale`, `runtime_status`, and `last_reported_at` before marker/limit. It is not
a public Neutron query parameter and does not change the standard six list
arguments.

`fields is None` or an empty list preserves the existing full-object response.
Otherwise the response contains only requested visible fields, after internal
identity, authorization, sort, and pagination fields have served their
purpose.

### 4.2 Resource query specifications

A small Python 2-compatible module will define one immutable specification per
resource. Each specification contains only data required by the public query
contract:

- public resource name;
- storage table/store name;
- public identity field;
- storage identity columns;
- field aliases;
- field value types;
- stable sortable scalar fields;
- filterable fields;
- default sort; and
- fields whose materialization has extra cost.

This is not a general repository framework. Write validation, transaction
handling, row conversion, and CRUD remain in the existing repository classes.

The initial public capability matrix is fixed as follows:

| Resource | Filter and sort contract |
| --- | --- |
| Policy | all visible scalar fields; `tenant_id` aliases `project_id` |
| Rule | all visible scalar fields, including nullable CIDR, port, and reference fields |
| Address set | all visible scalar fields; `members` is neither filterable nor sortable |
| Binding | all visible scalar fields; `tenant_id` aliases `project_id` |
| Port status | stored scalar fields plus projected-field filters described below; `stale` and `runtime_status` are not sortable |

Unsupported fields fail with HTTP 400. They are not silently ignored or sent
through an unbounded fallback. Port-status `tenant_id` is currently advertised
but is not persisted consistently by the production repository. Filtering or
sorting status by `tenant_id` is therefore rejected in this batch rather than
returning repository-dependent results. Supplying that ownership through the
authoritative Neutron port projection remains part of `REVIEW-ACL-013`.

### 4.3 Filter semantics

Filters use Neutron's existing rule: values within one field are ORed, while
different fields are ANDed.

Before comparison or SQL binding, values are normalized according to the
resource specification:

- boolean fields accept booleans and case-insensitive `true`/`false` or
  `1`/`0` strings;
- integer fields accept integers or canonical decimal strings and reject
  invalid input;
- textual and identity fields remain strings;
- for desired resources, `tenant_id` is an API alias for stored
  `project_id`; and
- an explicitly empty value list matches no rows.

Invalid typed filter input raises `AriaAclValidationError` and is exposed as
HTTP 400. Direct repository callers and REST callers receive the same result.

Port-status projected fields are translated rather than evaluated after a
limited page:

- `last_reported_at` aliases stored `updated_at`;
- `stale` is evaluated against one request-scoped `now` and stale cutoff; and
- `runtime_status` is `stale` for stale rows, otherwise stored `status` or
  `unknown`.

This ordering is mandatory: filtering projected status fields after applying
the SQL limit could return short or incorrect pages.

### 4.4 Sort semantics

The repositories support stable scalar sorts only. Collection-valued
`members` is neither filterable nor sortable. Invalid or unsupported filter or
sort keys return HTTP 400 instead of triggering a full in-memory production
scan.

Sort directions use the Neutron representation `(field, ascending_bool)`.
Every query appends its identity if that identity is not already the final
unique sort:

```text
policy/rule/address-set/binding: (...requested sorts..., id ASC)
port status:                    (...requested sorts..., port_id ASC, host ASC)
```

For the public status resource, the compound suffix is represented externally
by the derived `id` but compared internally as `(port_id, host)`.

Nullable values use one cross-repository order matching the legacy Neutron
emulated sorter:

- ascending: NULL before non-NULL;
- descending: non-NULL before NULL.

The SQL builder must express this null rank explicitly rather than relying on
database-dialect defaults.

### 4.5 Marker semantics

The public marker is always the public identity of an existing row. It is not
an OFFSET and is not a serialized copy of mutable sort values.

For a custom sort, the repository resolves the marker row by identity and uses
that row's complete normalized sort tuple to construct the keyset boundary.
The marker lookup is independent of the request filters, matching the legacy
Neutron model. A missing or malformed marker fails the request explicitly; it
must not restart at the first page or return a silently empty collection.

For forward pages, rows compare after the marker tuple. For reverse pages, all
directions and null ranks are inverted for selection, the limit is applied,
and the selected rows are reversed before returning. Public rows are always
presented in the requested logical order.

No single multi-request resync is claimed to be a database snapshot. Stable
immutable identity ordering prevents duplicate boundaries; a concurrent
insert before an already-consumed marker can be observed through the normal
change notification or next full resync. A query/marker failure aborts that
resync and preserves the agent's last-good desired snapshot.

## 5. Versioned Port-Status Identity

### 5.1 Encoding

Every projected per-host status row includes:

```text
id = "aria-status-v1." + base64url(port_id_utf8 + NUL + host_utf8)
```

Base64 padding is omitted. The encoder and decoder use only the Python
standard library and remain compatible with Python 2.7.

The decoder must:

1. require the exact `aria-status-v1.` prefix;
2. restore only valid base64 padding;
3. reject invalid alphabet and decoding errors;
4. require exactly one NUL separator;
5. require non-empty `port_id` and `host`;
6. enforce the existing storage limits of 36 bytes for `port_id` and 255 bytes
   for UTF-8 `host`;
7. reject embedded NUL values; and
8. re-encode and compare with the input to reject non-canonical aliases.

The ID is stable for the lifetime of the `(port_id, host)` row. It is a public
row identity, not a secret and not an authorization token.

### 5.2 Extension metadata

All desired resources will explicitly mark their existing `id` attribute as
`primary_key=True`. Port status gains a visible, read-only `id` attribute with
the same marker role. This removes reliance on the controller's implicit
default and makes the pagination contract auditable in the extension map.

### 5.3 Exact and legacy show behavior

`GET /aria-acl-port-statuses/{aria-status-v1...}` resolves exactly one
`(port_id, host)` row.

The existing port-ID form remains a compatibility path:

- zero rows: return not found;
- one row: return that row; and
- more than one row: return HTTP 409 with reason
  `ambiguous_port_status`, including the port ID and sorted candidate hosts.

Returning the first row is forbidden. The CLI will display status `id` and use
it for exact show. A separate host selector is unnecessary once the exact ID
is available.

If the status delete endpoint is called with a derived ID, it deletes only the
exact per-host row. Its legacy port-ID form retains the current all-host delete
behavior for compatibility and is documented as a bulk cleanup operation.

### 5.4 Future canonical per-port projection

The current rows are raw per-host execution reports. A future authoritative
per-port view must select the report whose host matches the Neutron port's
current `binding:host_id`; it must not pick the newest timestamp globally.

That projection belongs to `REVIEW-ACL-013`. It may expose a canonical row
keyed by `port_id` while preserving the versioned IDs of raw per-host reports.
This batch does not add another table or change which report is authoritative.

## 6. Repository Execution

### 6.1 In-memory repository

The in-memory repository is the reference behavioral implementation. It will:

1. clone candidate rows;
2. add virtual/projected fields needed by the query;
3. normalize and apply filters;
4. sort with the shared comparator;
5. resolve and apply the marker boundary;
6. apply the limit and reverse-page contract; and
7. project requested fields.

Dictionary insertion order must never influence public results.

### 6.2 SQLAlchemy repository

For persisted scalar fields, the SQLAlchemy Core path will:

1. create a table select;
2. translate aliases and projected status expressions;
3. add typed filter predicates;
4. resolve a marker row when required;
5. add lexicographic keyset predicates;
6. add explicit null-rank and value ordering;
7. apply the database limit; and
8. fetch only the selected page.

The implementation must use APIs available in the target
`SQLAlchemy>=1.0.10,<1.1.0` range. It must not depend on modern ORM-only
pagination helpers or neutron-lib.

Unsupported complex production sorts are rejected. There is no unbounded
Python fallback in the SQLAlchemy production path.

### 6.3 Address-set member loading

After selecting one address-set page:

- if `fields` excludes `members`, do not query the member table;
- otherwise issue one member query with `address_set_id IN (...)`;
- order members by address-set ID and stable member identity/address;
- group them in Python and attach them to the selected rows; and
- attach an empty list to sets with no members.

The query budget per address-set page is therefore:

| Request | Maximum steady-state queries |
| --- | ---: |
| Page without `members` | 1 |
| Page with `members` and default ID sort | 2 |
| Page with custom sort and marker lookup | 3 |

The marker lookup is constant cost. Query count must not grow with page size.

Single address-set show performs one row query and, only when requested, one
member query.

### 6.4 SQLite repository

SQLite remains the stdlib-backed persistent contract test bed. Existing
indexed scalar columns are used for default identity paging and supported
filters. JSON payload decoding occurs only for selected rows.

The batch does not duplicate every payload field into a new SQLite column.
For supported non-indexed scalar filters and sorts, SQLite uses `json_extract`
when JSON1 is available and a repository-registered scalar JSON function
otherwise. Both paths keep filtering, ordering, marker comparison, and limit
inside the SQL statement. The production SQLAlchemy path does not depend on
either SQLite mechanism.

Default agent resync uses immutable ID ordering and therefore always takes the
bounded SQL path.

### 6.5 Read consistency and transaction boundaries

Each repository list call observes one database statement sequence, not a
cross-page transaction. Member loading uses the same request/session after the
page rows are selected. A concurrently deleted address set may yield an empty
member group, but it cannot attach members from another set or change the page
identity.

This batch does not add long-running read transactions around a complete agent
resync because they would retain database snapshots and locks across HTTP
requests.

## 7. Service, Agent, and CLI Wiring

### 7.1 Service plugin

After all five resource contracts are implemented, `AriaAclPlugin` advertises
both private legacy capability flags:

```python
__native_sorting_support = True
__native_pagination_support = True
```

Native pagination is not enabled in an intermediate commit where any resource
still lacks correct marker behavior.

Status projection receives one request-scoped timestamp so every row on one
page uses the same stale cutoff. Supported projected-field filtering and
`last_reported_at` sorting use that same timestamp; `stale` and
`runtime_status` sorting remain explicitly unsupported.

### 7.2 Agent page size

Introduce `[neutron] acl_page_size` as the explicit page size for Aria ACL
collection reads. Compatibility rules are:

1. use `acl_page_size` when set;
2. otherwise use existing `port_page_size` as the ACL-client fallback; and
3. when neither is set, preserve the server-default/no-limit behavior.

The deployment examples will set a bounded `acl_page_size` value of 100.
Existing installations that already set `port_page_size` gain ACL paging
without a breaking rename. Core port paging remains controlled only by
`port_page_size`; this batch does not broaden the still-open
`REVIEW-ACL-038` repeated-marker path.

`build_acl_source()` passes the resolved ACL page size into
`build_aria_acl_client_from_env()`. Status reporting may continue to construct
the same client without a page size because it performs writes, not collection
reads.

The REST client follows Neutron-provided `next` links, continues to use the
last returned `id` as the next marker, and retains its repeated-marker guard.
It does not derive custom cursors or attempt to merge partially downloaded
desired state.

### 7.3 CLI

List commands enable the legacy neutronclient sorting and pagination options.
Status list output includes `id`, `port_id`, and `host`. Status show accepts the
derived row ID; a legacy port ID remains subject to the explicit ambiguity
contract.

CLI changes consume the server contract only. They do not reimplement marker
encoding or database ordering.

## 8. Error Contract

| Condition | Repository error | HTTP result |
| --- | --- | ---: |
| Invalid boolean/integer filter | `AriaAclValidationError` | 400 |
| Unsupported filter or sort field | `AriaAclValidationError` | 400 |
| Malformed versioned status ID | `AriaAclValidationError` | 400 |
| Missing marker row | `AriaAclNotFound` | 404 |
| Exact status row not found | `AriaAclNotFound` | 404 |
| Legacy status show matches multiple hosts | `AriaAclConflictError` | 409 |

No query error may silently fall back to the first page, an arbitrary status
row, or a complete production table scan.

## 9. RED Behavior Test Matrix

### 9.1 Shared query semantics

The same table-driven scenarios run against in-memory and SQLite repositories,
and against SQLAlchemy where dependencies are available:

- default ordering is stable regardless of insertion order;
- forward pages cover every row exactly once;
- reverse pages return the correct preceding rows in logical order;
- repeated values in a user sort are resolved by identity tie-breakers;
- `limit=1`, exact-boundary, last-page, and empty-page behavior;
- missing markers return not found;
- malformed markers return validation errors;
- multi-value filters are OR within a key and AND across keys;
- string boolean and integer filters match stored typed values;
- desired-resource `tenant_id` and `project_id` filters are equivalent;
- requested fields are exact for list and show; and
- unsupported collection/dynamic filter or sort fields fail deterministically.

### 9.2 Status identity and ambiguity

Tests require:

- two hosts for one port produce different stable derived IDs;
- encode/decode round trips under Python 2-compatible byte handling;
- invalid prefix, alphabet, separator count, length, UTF-8, and canonical form
  are rejected;
- derived-ID show returns the exact host row;
- a unique legacy port-ID show remains compatible;
- a multi-host legacy port-ID show returns 409 and sorted host evidence;
- status forward and reverse pages contain no duplicate marker; and
- `stale`, `runtime_status`, and `last_reported_at` filters are applied before
  limit using one request timestamp.

### 9.3 SQL query budgets

SQLAlchemy event/query instrumentation verifies:

- page work is bounded independently of total table size;
- address-set list without members executes one steady-state query;
- address-set list with members executes two steady-state queries;
- custom-sort marker lookup adds at most one query;
- selecting more address sets does not add member queries; and
- field projection excluding `members` does not touch the member table.

### 9.4 Agent and CLI

Tests require:

- `acl_page_size` reaches the ACL client without changing the port client;
- `port_page_size` remains an ACL compatibility fallback;
- all four desired-state collections follow multiple pages;
- status collection pagination works with derived IDs;
- repeated or missing markers abort rather than loop;
- a failed multi-page resync does not publish a partial snapshot; and
- CLI pagination/sorting arguments are sent unchanged.

## 10. CI and Verification Strategy

The existing stdlib unit suite remains in `fast-contracts`. SQL query-count
coverage requires a separate Python DB-contract job that installs
`SQLAlchemy==1.4.54`, the maintained hosted compatibility runner for these Core
queries, and runs only focused repository tests. Production code remains
restricted to APIs present in SQLAlchemy 1.0.10. The hosted job must not be
serialized with Rust behavior or Rust/eBPF compilation.

Hosted verification consists of:

1. stdlib query/status/client/CLI behavior tests;
2. SQLAlchemy Core query and query-count tests;
3. existing Stage 1 and Stage 2 Python contracts; and
4. workflow lane-contract tests.

No local Cargo build, check, or test is part of this batch. GitHub Actions
remains the Rust/eBPF compilation authority under the repository rules.

The target Neutron 9.0/Python 2/SQLAlchemy 1.0 service-plugin smoke remains
privileged field evidence. Without that environment it is recorded as
`deferred/pending`, never inferred from hosted CI. Native pagination is not
claimed production-validated until that smoke exercises forward/reverse list,
status marker links, fields, and address-set member loading on the target
container.

## 11. Implementation Boundaries and Sequence

The implementation plan must preserve this internal order:

1. add shared query and status-ID RED behavior tests;
2. prove current code RED in hosted CI;
3. implement the bounded shared query specification and in-memory reference;
4. implement SQLAlchemy and SQLite execution plus batched members;
5. add status derived ID and explicit ambiguity behavior;
6. wire all plugin parameters and only then enable native capability flags;
7. wire agent page-size configuration and CLI options;
8. add the separate DB-contract CI lane;
9. run exact-head hosted CI and update backlog evidence; and
10. leave target-environment smoke pending until the environment exists.

Intermediate commits must not advertise native pagination before every
resource is ready. GREEN implementation may be split by layer, but the public
feature is complete only when all five resource types pass the same query
contract.

## 12. Explicit Exclusions

This batch does not:

- change port-status upsert locking or uniqueness (`REVIEW-ACL-040`);
- populate ACL fields on the core Neutron port resource
  (`REVIEW-ACL-013`);
- choose or persist an authoritative host during migration;
- add a canonical status table or status history retention policy;
- change desired-state write invariants already delivered by
  `REVIEW-ACL-058/061`;
- change notification ordering or agent apply transactions;
- change ACL matching, CT, fragments, maps, or eBPF code;
- solve the separate core port-list repeated-marker defect
  (`REVIEW-ACL-038`); or
- claim privileged field validation without the target environment.

## 13. Acceptance Criteria

`REVIEW-ACL-060` can be marked source-fixed only when:

- all five list APIs honor filters, fields, sorts, limit, marker, and reverse;
- desired and status show APIs honor fields;
- native pagination is enabled only after all resource identities are valid;
- all repositories pass the shared behavior matrix;
- SQLAlchemy performs bounded queries and removes address-set N+1 loading;
- agent configuration actually requests bounded ACL pages;
- CLI pagination and sorting consume the same contract;
- hosted exact-head CI is green; and
- the backlog records target field evidence as pending when unavailable.

`REVIEW-ACL-004` can be marked source-fixed in the same batch when multi-host
legacy show returns an explicit 409 and exact derived-ID show is covered across
repository, plugin, and CLI tests.

Production validation remains separate from source completion. Target
Neutron/Python 2/database smoke evidence is required before the feature is
described as field-validated or production-ready.

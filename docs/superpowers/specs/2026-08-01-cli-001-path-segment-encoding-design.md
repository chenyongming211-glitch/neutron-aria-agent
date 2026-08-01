# REVIEW-CLI-001 Rust Client Path-Segment Encoding Design

Date: 2026-08-01

Status: approved approach; implementation pending

Analyzed target:
`v0.9-neutron-agent@77e97822d170e8bbc4fe93f19109915097f8f1b0`

Tracked finding: `REVIEW-CLI-001`

## 1. Decision

The Rust client will preserve every dynamic instance, group, and service-chain
name as exactly one URL path segment by percent-encoding the UTF-8 bytes before
constructing a request URL.

The change stays inside `ariactl`. It does not reject currently accepted
names, change server routes, introduce identifiers, or migrate persisted
state. Static route text and query parameters remain separate from dynamic
path segments.

## 2. Revalidated Root Cause

`user/src/api_client.rs` currently has 37 request sites whose paths contain a
dynamic name:

- 35 contain an instance name;
- one of those also contains a group name; and
- two contain a service-chain name.

Each site interpolates the name directly into a string passed to `reqwest`.
The server accepts group and chain names containing URI delimiters; group
validation only reserves `any`, and chain creation does not validate the name.

Raw interpolation changes the request target before it reaches Axum:

- `/` creates another path level;
- `?` starts the query;
- `#` starts a client-side fragment and the remainder is not sent; and
- `%` can be interpreted as an already encoded octet.

An object can therefore be created through a JSON body and persisted, while a
later Rust-client get or delete addresses a different route or identity.
Instance-scoped operations have the same construction defect even though most
current instance names originate from interface names.

## 3. Considered Approaches

### 3.1 Chosen: encode dynamic segments in the Rust client

Add a small path-segment encoder and three private URL boundaries:

- instance-scoped resource URL;
- instance-scoped group URL; and
- service-chain URL.

Every current dynamic request site must use one of these boundaries. This
preserves existing names and changes no public request or response schema.

### 3.2 Rejected: reject URI delimiters at every write surface

This would be smaller in the client, but it is an API restriction and would
not restore access to names already persisted. Consistent enforcement would
also have to cover group, chain, and all instance-registration surfaces.

### 3.3 Deferred: replace path names with stable IDs

ID-based routes are a possible future API version, but require server, client,
CLI, persistence, migration, and compatibility work. They are not required to
repair the current transport ambiguity.

## 4. URL Construction Contract

The implementation will use the maintained `percent-encoding` crate already
present in the dependency graph. It becomes a direct `ariactl` dependency so
the client does not rely on a transitive implementation detail.

Only dynamic values are encoded. The helpers keep static suffixes separate:

```text
instance_url(instance, "/groups")
group_url(instance, group)
chain_url(chain)
```

The instance helper accepts only a static suffix. Query-bearing callers build
the path first and attach `top` through `reqwest::RequestBuilder::query`, so a
name can never supply query syntax.

Encoding must be exactly once:

- name `blue/red` sends `blue%2Fred`;
- name `blue?mode#tail` sends `blue%3Fmode%23tail`; and
- literal name `blue%2Fred` sends `blue%252Fred`, allowing the server to
  recover the literal percent text rather than silently treating it as `/`.

Normal alphanumeric names retain their existing request paths. Other
punctuation may be encoded even when RFC 3986 permits it unescaped; Axum path
extraction decodes it back to the original name.

## 5. Affected Client Surface

The migration covers every current instance-scoped method: groups, policies,
QoS, mirror, conntrack, config, statistics, TCP-RT, and trace. It also covers
group deletion plus service-chain get and delete.

Static global endpoints such as health, system start/stop, SSL, chain list and
create, and kernel-drop statistics do not contain dynamic path segments and
remain unchanged.

No new generic URL framework is introduced. The three helpers are concrete
enough to make the supported route shapes obvious and prevent a dynamic name
from being confused with a static suffix.

## 6. Error and Compatibility Semantics

- HTTP methods, response parsing, timeout behavior, and connection errors are
  unchanged.
- Server-side stored names and JSON representations are unchanged.
- Existing ordinary names continue to address the same resource.
- Existing names containing `/`, `?`, `#`, or `%` become addressable through
  the Rust client.
- Server validation is deliberately unchanged; empty-name and dot-segment
  product policy is not expanded in this bug fix.

## 7. RED and GREEN Evidence Plan

Rust tests in `user/src/api_client.rs` will use a real local TCP listener to
capture the HTTP request line produced by public `ApiClient` methods. The
listener returns a bounded error response; it does not mock URL construction.

RED behaviors:

1. group delete encodes both the instance and group names as separate
   segments;
2. an instance-scoped endpoint with `top` keeps the encoded instance in the
   path and the numeric value in the query;
3. service-chain get and delete encode the chain name; and
4. a literal `%2F` in a name is sent as `%252F`.

The existing implementation must fail these assertions because its request
line is truncated or structurally changed. The tests will run in hosted CI
through one `ariactl` behavior filter. No Python source checker will inspect
private Rust helper spelling.

GREEN requires:

- all named `ariactl` URL behaviors pass;
- all existing selected Rust behaviors pass;
- warning-denied userspace, agent, and eBPF builds pass; and
- fast contracts and database contracts remain green.

No local Cargo command will run under the repository rule.

## 8. Scope and Code-Volume Boundary

Expected production files:

- `Cargo.toml`;
- `Cargo.lock`;
- `user/Cargo.toml`; and
- `user/src/api_client.rs`.

Expected CI wiring is one behavior-filter entry in
`ci/check_neutron_stage1.py`. Documentation updates are limited to this design,
its implementation plan, and the two `REVIEW-CLI-001` backlog summaries.

The change must not modify server handlers, route definitions, eBPF code,
Neutron APIs, or unrelated client commands. It must not create a general URL
DSL or a static checker.

## 9. Acceptance Criteria

`REVIEW-CLI-001` can be marked fixed only when:

- every dynamic path site is routed through one of the three encoding
  boundaries;
- request-line tests prove reserved delimiters and literal percent text retain
  identity;
- query parameters are not concatenated with encoded instance names;
- RED is demonstrated against the old implementation;
- exact-head hosted GREEN CI passes with warnings denied; and
- the final diff remains within the declared client, dependency, CI-filter,
  test, and documentation scope.

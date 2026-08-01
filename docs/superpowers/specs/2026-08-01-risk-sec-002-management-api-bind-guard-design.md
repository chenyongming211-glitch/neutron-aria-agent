# RISK-SEC-002 Management API Bind Guard Design

**Status:** implemented by `ca5cb88`. Exact implementation-head Build
[30706732514](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30706732514)
passed all required hosted lanes. The TCP API remains unauthenticated; no
privileged field evidence applies or is claimed.

## Problem

`aria-agent` runs as root and serves the complete standalone management router
over TCP. That router includes policy mutation, system start/stop, map/state
flush, tracing, and runtime configuration endpoints. It has no HTTP
authentication or transport-security layer.

The safe boundary today is operational only:

- `Config::default()`, `install.sh`, the Kolla configuration, and the user
  manual use `127.0.0.1:8080`;
- `Config.listen_addr` remains an arbitrary string;
- `tokio::net::TcpListener::bind(&listen_addr)` accepts wildcard, private, or
  public addresses without a security check.

A configuration mistake can therefore expose a root management surface to the
network. The listener default is safe, but the invariant is not enforced.

## Decision

Keep loopback-only TCP management as the default enforced boundary, while
retaining one deliberately named emergency escape hatch:

```toml
listen_addr = "127.0.0.1:8080"
allow_unauthenticated_non_loopback = false
```

When the escape hatch is `false`, startup accepts only an explicit IP socket
whose IP is loopback. When it is `true`, startup may bind a non-loopback IP but
must emit a high-severity warning that the root management API remains
unauthenticated.

This setting does not assert that an external boundary exists and does not
convert the TCP API into a secured API. Its name describes exactly the unsafe
behavior being enabled.

## Alternatives Considered

### Permanently reject every non-loopback listener

This is the smallest and safest implementation, but it removes the possibility
of a deliberately isolated management network or a locally enforced external
proxy. It is too restrictive as a permanent product contract.

### Default-deny with an explicit unsafe escape hatch

This is the selected approach. It closes accidental exposure without claiming
authentication and preserves an auditable break-glass path. The compatibility
cost is limited to configurations that currently bind a hostname or
non-loopback address.

### Add TLS, tokens, mTLS, or RBAC now

This would provide a stronger remote-management product, but requires secret
distribution, rotation, client compatibility, certificate identity, and
deployment ownership decisions. It is a separate security feature rather than
the minimum closure for this unsafe default boundary.

## Configuration Contract

Add this field to `agent/src/main.rs::Config`:

```rust
#[serde(default)]
allow_unauthenticated_non_loopback: bool,
```

The default is `false`, including when an existing configuration omits the new
field. No configuration migration is required for the packaged loopback
profiles.

The accepted address grammar becomes an explicit `std::net::SocketAddr`:

- accepted by default: `127.0.0.1:8080`, any other `127.0.0.0/8` address, and
  `[::1]:8080`;
- rejected by default: `0.0.0.0:8080`, `[::]:8080`, private addresses, public
  addresses, link-local addresses, multicast addresses, and IPv4-mapped IPv6
  forms;
- rejected in every mode: malformed values and hostname forms such as
  `localhost:8080`;
- accepted only with the explicit escape hatch: a syntactically valid,
  non-loopback IP socket.

Hostname rejection is intentional. Resolving a name for validation and then
resolving it again for bind creates ambiguity and a time-of-check/time-of-use
boundary. Operators can configure the resolved loopback IP directly.

Port `0` is not changed by this risk closure. It remains a valid socket port,
because ephemeral-port policy is operational rather than an authentication or
exposure invariant.

## Validation Boundary

Add a pure configuration method:

```rust
fn management_listen_addr(&self) -> Result<std::net::SocketAddr, String>;
```

It performs exactly these steps:

1. parse `listen_addr` as `SocketAddr` without DNS resolution;
2. return a stable invalid-address error if parsing fails;
3. accept if `socket.ip().is_loopback()`;
4. accept a non-loopback socket only when
   `allow_unauthenticated_non_loopback` is true;
5. otherwise return a stable error that names both `listen_addr` and the
   explicit escape-hatch setting.

`main()` validates this value immediately after loading configuration and
fragment-tracking settings, before resolving/loading eBPF objects, creating
control-plane state, binding sockets, or starting background tasks. Invalid
configuration exits non-zero.

After tracing is initialized, an accepted non-loopback address emits a warning
containing:

- the effective socket address;
- `allow_unauthenticated_non_loopback=true`;
- an explicit statement that the root HTTP management API is unauthenticated.

The validated `SocketAddr`, rather than the original string, is passed to
`TcpListener::bind`. This avoids a second hostname-resolution boundary.

## Runtime and Deployment Behavior

The existing HTTP route inventory and response behavior do not change. The
Neutron UDS router, peer credentials, socket mode, and `RISK-SEC-001` are
outside this transaction.

Packaged configuration remains loopback-only and records the explicit safe
value:

```toml
allow_unauthenticated_non_loopback = false
```

Update these maintained configuration/documentation surfaces:

- `install.sh` generated default configuration;
- `deploy/kolla/config/aria-agent-openstack.toml`;
- `docs/user-manual.md` configuration reference;
- `docs/openstack-neutron-aria-details/12-review-bug-backlog.md` after GREEN.

Existing smoke scripts already use loopback TCP addresses and remain valid.
Historical plan snippets are not rewritten.

## Error and Compatibility Semantics

The validation is fail-closed:

- invalid syntax never falls back to a resolved hostname;
- `allow_unauthenticated_non_loopback=false` never permits a non-loopback
  address;
- setting the escape hatch does not make malformed input valid;
- a rejected listener exits before runtime mutation or interface attachment.

The intentional compatibility changes are:

- `listen_addr = "localhost:8080"` must become an explicit loopback IP;
- existing non-loopback deployments must either return to loopback or set the
  deliberately unsafe escape hatch;
- packaged and documented configurations continue without behavioral change.

No authentication success, protected namespace, reverse proxy, TLS, or field
validation is inferred from the escape hatch.

## Test Strategy

Rust behavior tests in `agent/src/main.rs` use the public configuration
boundary rather than source-layout inspection. The RED contract covers:

1. the default listener is IPv4 loopback and the escape hatch defaults false;
2. explicit IPv4 and IPv6 loopback listeners are accepted;
3. IPv4 wildcard, IPv6 wildcard, private, public, and IPv4-mapped IPv6
   listeners are rejected by default;
4. `localhost:8080` and malformed values are rejected without resolution;
5. the explicit escape hatch accepts a valid non-loopback socket;
6. the explicit escape hatch still rejects malformed input;
7. the returned value is the parsed `SocketAddr` used for binding.

Add one `aria-agent` Cargo behavior filter with a stable public prefix such as
`management_listener_` to `ci/check_neutron_stage1.py::RUST_TESTS`. Hosted CI
must prove that the filter executes at least one test. Do not add a Python Rust
parser or bind CI to a private helper name.

Local verification remains non-Cargo only:

```bash
git diff --check
python3 -m unittest ci.test_ci_lane_contract ci.test_ci001_trusted_gates
python3 ci/check_neutron_stage1.py --fast-contracts
```

GitHub Actions supplies the RED and GREEN Rust behavior evidence and the
warning-denied userspace/eBPF/static builds.

## Execution Evidence

- RED `4316b62` added the five management-listener behavior tests and the
  Cargo-discovered hosted filter. Build
  [30706588907](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30706588907)
  failed on the intentionally absent
  `allow_unauthenticated_non_loopback` field and
  `management_listen_addr()` method; fast, database, and clean-install
  contracts remained green. Remaining expensive work was cancelled after the
  RED evidence was captured.
- GREEN `ca5cb88` added one pure validation method, validated-before-runtime
  startup wiring, direct typed bind, explicit unsafe warning, and maintained
  safe configuration/docs. Exact-head Build
  [30706732514](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30706732514)
  executed all five `management_listener_` tests and passed fast, database,
  clean-install, selected Rust behavior, warning-denied eBPF/userspace/static
  agent, and bundle checks.
- Local non-Cargo verification passed 557 Python tests with 8 skips, 10 CLI
  tests, shell syntax, installer, and public contract checks.
- No HTTP authentication, TLS, or privileged field result is inferred or
  claimed.

## Closure Criteria

`RISK-SEC-002` may be marked fixed when all of the following are true:

- the pure configuration behavior is proven RED against the old code;
- production startup validates and binds only the returned `SocketAddr`;
- loopback defaults and packaged configurations remain unchanged;
- non-loopback exposure requires the exact explicit unsafe setting and logs a
  warning;
- hosted Rust behavior and warning-denied builds pass at the implementation
  head;
- the backlog accurately describes the remaining lack of TCP authentication.

No privileged field environment is required for this configuration-boundary
closure, and none may be claimed.

## Explicit Exclusions

- TLS, mTLS, bearer tokens, API keys, sessions, or RBAC;
- authentication or authorization for the TCP router;
- reverse-proxy or network-namespace deployment automation;
- Neutron UDS peer-credential hardening (`RISK-SEC-001`);
- readiness semantics (`RISK-READY-001`);
- route inventory or handler behavior changes;
- local Cargo compilation or tests.

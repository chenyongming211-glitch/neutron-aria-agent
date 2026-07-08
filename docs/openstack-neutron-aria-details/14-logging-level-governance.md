# Logging Level Governance

Status: design record, not implementation claim.

This plan records the accepted logging-level cleanup for the Rust datapath
agent and the Python `neutron-aria-agent`. The goal is product-grade logs:
operators should see meaningful state changes and actionable faults at
`INFO/WARN/ERROR`, while high-frequency success paths and debug detail stay
behind `DEBUG`.

## Scope

In scope:

- Rust `aria-agent` running as the OpenStack `aria-datapath` container.
- Python `neutron-aria-agent`.
- Kolla launcher log routing for both containers.
- Log level defaults, noisy log demotion, and OpenStack-mode feature noise
  reduction.

Out of scope:

- New product capabilities.
- Centralized log collection, dashboards, or alerting.
- Changing ACL, QoS, Mirror, RPC, or UDS behavior.
- Reworking all legacy local-admin modules.

Anti-overengineering rule:

Only change log level, log routing, and feature-noise gates needed to make ACL
production operation readable. Do not introduce a logging framework migration
or a new telemetry subsystem.

## Current State

### Rust Datapath Agent

Current target files:

- `agent/src/main.rs`
- `agent/src/control_plane.rs`
- `deploy/kolla/config/aria-agent-openstack.toml`
- `deploy/kolla/aria-datapath/start-aria-datapath.sh`

Observed behavior:

- Logs already include levels such as `INFO`, `WARN`, and `ERROR`.
- `log_filter = "info"` filters out `DEBUG` and `TRACE`.
- `accepted Neutron UDS peer` is currently logged at `INFO`, which is too noisy
  during normal heartbeat/full-resync operation.
- SSL observability reconcile runs in OpenStack `neutron_managed` mode even
  though `ssl` is not part of the ACL product path. Missing OpenSSL debuglink
  files can produce repeated `WARN` logs such as `failed to read global SSL
  config during periodic reconcile`.
- The Rust logger writes to stdout and to `log_file_path`, while the Kolla
  launcher also redirects stdout/stderr to the same log file. This can duplicate
  log lines.

### Python Neutron Aria Agent

Current target files:

- `openstack/neutron_aria/neutron_aria/agent/main.py`
- `openstack/neutron_aria/neutron_aria/agent/config.py`
- `openstack/neutron_aria/neutron_aria/agent/service.py`
- `openstack/neutron_aria/neutron_aria/agent/event_loop.py`
- `deploy/kolla/config/neutron-aria-agent.ini`
- `deploy/kolla/neutron-aria-agent/start-neutron-aria-agent.sh`

Observed behavior:

- Logs already include Python logging levels.
- The `neutron_aria` logger is hard-coded to `INFO`.
- `service_result`, `acl_delivery_profile`, and event-batch detail can be noisy
  during polling or RPC operation.
- Operators need `INFO` summaries for mode, generation, readiness, and apply
  outcomes, but not every debug decision by default.

## Logging Level Contract

### ERROR

Use `ERROR` only when the service or a required product path cannot continue
successfully:

- Invalid config that prevents startup.
- UDS bind failure.
- Required eBPF artifact missing.
- Required eBPF runtime cannot load for the datapath product path.
- Neutron client/RPC initialization failure that prevents the configured sync
  mode from operating.
- Unhandled exception about to terminate the process.

### WARN

Use `WARN` for degraded but recoverable product behavior:

- ACL apply failed and runtime enters `degraded` or `bypass`.
- Full-resync failed and will retry.
- Heartbeat/status report failed.
- UDS peer authentication failed.
- Tap/port lifecycle mismatch affecting a managed port.
- OVS/Neutron read failure that blocks current reconciliation.

Repeated WARNs should be rate-limited, logged only on state transition, or
logged only when the error text changes.

### INFO

Use `INFO` for operator-useful lifecycle and state summaries:

- Service startup summary.
- Effective config summary with safe, non-secret values.
- eBPF selected artifact, trace backend, and runtime mode.
- UDS socket ready.
- Full-resync completion summary.
- ACL generation accepted/applied summary.
- Domain status transition, especially `ready <-> degraded`.
- Packaged sync mode, for example heartbeat-only, polling full-resync, RPC
  full-resync, or port-scoped experimental mode.

### DEBUG

Use `DEBUG` for high-frequency success paths and troubleshooting detail:

- Accepted UDS peer.
- Per-port projection decisions.
- RPC event merge detail.
- Port-scoped dry-run decision detail.
- ACL delivery timing profile by phase.
- Normal polling heartbeat-only loop result with no state change.

### TRACE

Reserve `TRACE` for extremely detailed datapath or map-level diagnostics:

- Per-rule or per-map-entry write detail.
- Packet-like or hot-path diagnostic detail.
- Temporary local reproducer instrumentation.

Production defaults must not enable `TRACE`.

## Rust Agent Design

### Config Additions

Add explicit OpenStack-mode feature/log controls:

```toml
log_format = "text"
log_filter = "info"
log_file_path = ""
ssl_observability_enabled = false
```

Semantics:

- `log_filter` remains the primary level filter.
- `log_file_path = ""` means the Rust logger writes stdout only; the Kolla
  launcher remains the single owner that redirects stdout/stderr to
  `/var/log/kolla/aria-datapath/aria-datapath.log`.
- `ssl_observability_enabled = false` disables SSL manager initialization and
  periodic SSL reconcile in OpenStack `neutron_managed` defaults.

Future optional shape, only if needed:

```toml
log_output = "stdout" # stdout | file | both
```

Do not add this unless `log_file_path = ""` is insufficient.

### Level Changes

Required changes:

- Demote `accepted Neutron UDS peer` from `INFO` to `DEBUG`.
- Keep peer authentication rejection as `WARN`.
- Keep UDS bind/config startup failures as `ERROR`.
- Keep full snapshot apply lifecycle summaries at `INFO`.
- Keep apply failure and domain degradation at `WARN`.
- Gate SSL reconcile behind `ssl_observability_enabled`.

Optional, if noisy after the first pass:

- Log repeated same-error SSL/init failures once at `WARN`; subsequent identical
  failures become `DEBUG` until the error changes.
- Demote non-product local-admin module warnings in `neutron_managed` mode when
  the module is disabled.

### Rust Non-Goals

- Do not remove SSL code.
- Do not change ACL apply semantics.
- Do not hide real ACL/eBPF datapath failures.
- Do not make OpenStack ACL depend on SSL observability readiness.

## Python Agent Design

### Config Additions

Add to `[agent]`:

```ini
log_level = INFO
```

Accepted values:

```text
TRACE is not required.
DEBUG, INFO, WARNING, ERROR, CRITICAL are enough for Python.
```

Python 2 compatibility note:

- Use stdlib `logging` only.
- Do not add `oslo.log` as a new dependency for this cleanup.
- Keep the existing legacy Neutron compatibility boundary.

### Logging Setup

Change `configure_logging()` to accept config or a level value:

```text
configure_logging(config)
  -> parse config.log_level
  -> default INFO
  -> set neutron_aria logger level
```

Invalid `log_level` should fail config validation early with a clear error.

### Level Changes

Keep as `INFO`:

- Startup summary.
- `sync_mode`.
- First initialization result.
- Full-resync completion summary.
- State transition summaries.

Move to `DEBUG`:

- `acl_delivery_profile` by default.
- Event-batch details when they do not trigger an apply or state transition.
- Repeated `service_result` lines that only report unchanged heartbeat-only or
  polling state.

Keep as `WARNING`:

- `full_resync_degraded`.
- Local API degraded.
- Heartbeat report failed.
- Event queue overflow.
- RPC event received while full-resync is disabled.
- Source cleanup failure.

Use `LOG.exception`:

- Unexpected exceptions inside service loop and RPC/event handlers where the
  traceback is required for diagnosis.

## Kolla Log Routing

Datapath container:

- Preferred MVP behavior: `aria-agent` writes stdout only.
- `deploy/kolla/aria-datapath/start-aria-datapath.sh` remains responsible for:

```text
exec aria-agent --config "${CONFIG_FILE}" >>"${LOG_FILE}" 2>&1
```

Python agent container:

- Keep launcher-owned stdout/stderr redirection.
- Avoid adding a second Python file handler unless Kolla routing changes.

This avoids duplicate log lines and keeps log rotation responsibility outside
the application process.

## Production Defaults

`aria-agent-openstack.toml`:

```toml
log_format = "text"
log_filter = "info"
log_file_path = ""
ssl_observability_enabled = false
```

`neutron-aria-agent.ini`:

```ini
[agent]
log_level = INFO
```

Debugging override:

```toml
log_filter = "debug"
```

```ini
[agent]
log_level = DEBUG
```

The operator should be able to enable debug temporarily on one node without
changing ACL product behavior.

## Acceptance Tests

Static/unit tests:

- Rust config parsing accepts `ssl_observability_enabled`.
- Rust `neutron_managed` default does not start SSL reconcile when disabled.
- Rust log filtering still accepts `info`, `debug`, and module filters.
- Python config parser accepts valid `log_level` and rejects invalid values.
- Python `configure_logging()` applies the configured level.

Smoke tests:

- Starting `aria-datapath` produces one startup line, not duplicate paired lines.
- With default OpenStack config, no periodic SSL reconcile warning appears in a
  short observation window.
- UDS peer acceptance no longer appears at `INFO` under default config.
- Peer rejection still appears at `WARN`.
- ACL full-resync success still emits a concise `INFO` generation summary.
- ACL degraded apply still emits `WARN`.

Field checks:

```bash
tail -f /var/log/kolla/aria-datapath/aria-datapath.log
tail -f /var/log/kolla/neutron/neutron-aria-agent.log
```

Expected default behavior:

- No repeated SSL reconcile WARNs.
- No repeated accepted-peer INFO lines.
- No duplicate same-timestamp paired lines caused by app-level and launcher-level
  file writes.
- Product-impacting failures remain visible at `WARN` or `ERROR`.

## Rollout Order

1. Add config fields and defaults.
2. Demote high-frequency success logs.
3. Gate SSL manager/reconcile in `neutron_managed` OpenStack defaults.
4. Switch datapath Kolla config to stdout-only app logging.
5. Add Python `[agent] log_level`.
6. Run unit tests and a short three-node log observation smoke.

Do not bundle this with ACL apply semantics changes. This is an observability
hardening patch.

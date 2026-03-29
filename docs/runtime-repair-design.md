# Aria Firewall Runtime Repair Design

Status: Draft
Date: 2026-03-22
Scope: Runtime correctness fixes, SSL observability globalization, compatibility migration

## 1. Background

This document consolidates the confirmed runtime bugs found during source review and provides a formal repair plan.

The current codebase has two classes of issues:

- Runtime correctness issues in attach/detach/recovery paths.
- Structural inconsistency in SSL observability: the code comments and API present SSL as a host-global feature, but the implementation still binds loading, pinning, and lifecycle to per-instance firewall state.

The design goal is to fix the confirmed bugs without introducing another round of lifecycle drift between `system` mode, tap-managed mode, userspace state, and pinned kernel objects.

## 2. Confirmed Problems

### 2.1 Missing `ssl_write_return` eBPF entry and drifted probe lists

Facts:

- `agent/src/instance.rs` tries to attach `ssl_write_return`.
- `ebpf/src/lib.rs` does not export `ssl_write_return`.
- `agent/src/system_manager.rs` does not try to attach `ssl_write_return`.
- SSL link cleanup lists in `instance.rs` and `system_manager.rs` also omit `ssl_write_return_link`.

Impact:

- Tap-managed mode fails partway through SSL probe attachment.
- System mode never captures `SSL_write` error events.
- The two attach paths are already semantically inconsistent.

### 2.2 SSL maps missing from pin inventory

Facts:

- `core/src/ebpf_ops.rs::ALL_MAP_NAMES` omits:
  - `SSL_HTTP_VALUE_BUF`
  - `SSL_GLOBAL_CONFIG`
  - `SSL_ERROR_TABLE`
  - `SSL_ERROR_SEQ`
  - `SSL_WRITE_SCRATCH`
- These maps exist in `ebpf/src/maps.rs`.

Impact:

- `SSL_GLOBAL_CONFIG` and `SSL_ERROR_TABLE` cannot be reliably accessed via pin path.
- SSL map pinning semantics are incomplete.
- Crash recovery behavior is inconsistent across SSL data structures.

### 2.3 Global SSL path and lifecycle mismatch

Facts:

- Comments in the code describe SSL uprobes as process-level global functionality.
- `ControlPlane` reads and writes `SSL_GLOBAL_CONFIG` and `SSL_ERROR_TABLE` via `base_pin_path`.
- Actual SSL attach currently happens inside `FirewallInstance::attach()` and `system_start()`, using per-instance pin paths.

Impact:

- Global SSL API methods point at the wrong path.
- Multi-instance mode can attach duplicate uprobes.
- "Global SSL" behavior depends on whichever instance happened to attach probes.

### 2.4 Wrong detach ordering in `TapRegistry`

Facts:

- `TapRegistry::detach()` unregisters the instance from the control plane before calling `instance.detach()`.

Impact:

- If kernel cleanup fails, userspace has already forgotten the instance.
- The system can be left with pinned programs and links while API state reports the instance as gone.

### 2.5 Recovery path mismatch: `state.json` vs `state.wal`

Facts:

- Control-plane state recovery uses `load_with_wal()`.
- eBPF replay on attach/recovery reads only `state.json`.

Impact:

- After a crash in the window between WAL append and compact, userspace state and kernel map state can diverge.
- Agent restart can recover a newer logical state than the rules actually replayed into the kernel.

### 2.6 TC runtime recovery is incomplete

Facts:

- The recovery branches in `FirewallInstance::attach()` only replay maps and check `fq`.
- They do not verify that `tc_egress` and `tc_ingress` are still attached.
- They do not repair missing `fq` when shaping rules exist.

Impact:

- Agent restart can leave XDP recovered while TC egress/ingress behavior is partially absent.
- QoS shaping and ingress mirror behavior may silently degrade after restart.

### 2.7 SSL metrics and cleanup logic assume per-instance storage

Facts:

- Prometheus SSL metrics are emitted inside a per-instance loop.
- Orphan pin cleanup keeps only `system`; any future global SSL directory would be treated as orphaned.
- Upgraded deployments may still contain per-instance SSL pin leftovers.

Impact:

- Global SSL data would be duplicated across instance labels.
- A future `ssl-global` directory could be deleted by normal cleanup.
- Old instance-local SSL pins would keep accumulating after migration.

### 2.8 SSL configuration is currently dual-tracked

Facts:

- `config set ssl on/off` writes `FIREWALL_CONFIG.ssl_enabled`.
- eBPF SSL probe code checks `SSL_GLOBAL_CONFIG`.
- CLI also exposes dedicated `ariactl ssl enable/disable/status`.

Impact:

- There are two SSL switches with overlapping names and different runtime effects.
- API, CLI, and eBPF do not share a single source of truth.

## 3. Design Goals

- Fix all confirmed correctness bugs without introducing new lifecycle drift.
- Make SSL observability a real host-global subsystem.
- Keep tap-managed firewall behavior independent from SSL probe lifecycle.
- Preserve backward compatibility for existing CLI and REST consumers during a migration window.
- Make restart recovery deterministic for state, TC programs, and SSL runtime state.

## 4. Non-Goals

- No redesign of ACL/QoS/mirror semantics.
- No change to external firewall policy format.
- No attempt in this workstream to redesign build tooling.
- No immediate removal of legacy per-instance SSL routes in the first compatibility release.

## 5. High-Level Repair Strategy

The repair is split into two tracks:

- Track A: runtime correctness fixes
- Track B: SSL globalization and compatibility migration

Track A must land first because it fixes correctness bugs that exist regardless of SSL globalization.

Track B then removes the structural cause of the SSL-related path, lifecycle, and metrics bugs.

## 6. Detailed Design

### 6.1 Unify SSL probe inventory

Introduce one shared inventory of SSL uprobes and link names.

Recommended new module:

- `agent/src/ssl_support.rs`

Recommended contents:

- `SSL_UPROBE_SPECS: &[(&str, &str, ProbeKind)]`
- `SSL_LINK_NAMES: &[&str]`

Required probe set:

- `ssl_handshake_entry` -> `SSL_do_handshake`
- `ssl_handshake_return` -> `SSL_do_handshake`
- `ssl_set_sni` -> `SSL_ctrl`
- `ssl_write_entry` -> `SSL_write`
- `ssl_write_return` -> `SSL_write`
- `ssl_read_entry` -> `SSL_read`
- `ssl_read_return` -> `SSL_read`

Implementation changes:

- Export `ssl_write_return` from `ebpf/src/lib.rs`.
- Replace the duplicated per-file probe arrays in `instance.rs` and `system_manager.rs` with the shared inventory.
- Replace duplicated SSL link cleanup arrays with the shared link inventory.

Result:

- System mode and tap-managed mode no longer drift.
- `SSL_write` error tracking is enabled in both paths.

### 6.2 Introduce a global `SslManager`

SSL must become a dedicated manager, not an accidental side-effect of interface attachment.

Recommended new module:

- `agent/src/ssl_manager.rs`

Recommended struct:

- `SslManager`

Recommended fields:

- `ebpf_path: String`
- `base_pin_path: String`
- `pin_path: String`
- `state: tokio::sync::Mutex<SslManagerState>`

Recommended internal state:

- `loaded: bool`
- `libssl_path: Option<String>`
- `last_error: Option<String>`

Recommended pin path:

- `"{base_pin_path}/ssl-global"`
- Example: `/sys/fs/bpf/aria/ssl-global`

Lifecycle rules:

- Agent startup creates the directory.
- Agent startup creates the manager.
- Agent startup calls `ensure_loaded()` once.
- `ensure_loaded()` remains idempotent and lock-protected so later calls are safe.

Why not pure lazy-loading:

- Startup creation is simpler operationally.
- The global config and error maps exist before the first SSL command.
- It avoids "first caller wins" races and reduces API-path complexity.

Behavior on failure:

- Agent startup should not abort if SSL manager fails to load.
- The manager stores the error and SSL APIs return a clear runtime error or disabled status as appropriate.

### 6.3 Split pin inventories into network and SSL groups

`ALL_MAP_NAMES` should no longer be a single undifferentiated list.

Recommended constants:

- `NETWORK_MAP_NAMES`
- `SSL_GLOBAL_MAP_NAMES`
- `ALL_PINNED_MAP_NAMES` if a combined list is still useful

`SSL_GLOBAL_MAP_NAMES` must include at least:

- `SSL_HANDSHAKE_SCRATCH`
- `SSL_CONN_TABLE`
- `SSL_SNI_TABLE`
- `SSL_SEQ`
- `SSL_HTTP_PARSE_BUF`
- `SSL_HTTP_SCRATCH`
- `SSL_HTTP_SCRATCH_BUF`
- `SSL_READ_SCRATCH`
- `SSL_HTTP_TABLE`
- `SSL_HTTP_SEQ`
- `SSL_HTTP_VALUE_BUF`
- `SSL_GLOBAL_CONFIG`
- `SSL_ERROR_TABLE`
- `SSL_ERROR_SEQ`
- `SSL_WRITE_SCRATCH`

Usage rules:

- `FirewallInstance` pins only network-interface-related maps.
- `SslManager` pins only SSL-global maps and SSL probe programs.

Result:

- Pin paths match lifecycle ownership.
- Global APIs no longer depend on per-instance directories.

### 6.4 Make SSL global path usage explicit

Refactor global SSL operations to accept the actual SSL pin directory, not a generic base path.

Changes:

- `core/src/ssl_ops.rs`
  - Rename function parameters from `base_pin_path` to `ssl_pin_path` where appropriate.
- `ControlPlane`
  - Store either:
    - `ssl_pin_path: String`, or
    - `ssl_manager: Arc<SslManager>`

Recommended `ControlPlane` API behavior:

- `get_ssl_global_config()` reads from `ssl_manager.pin_path()`
- `set_ssl_global_config()` writes to `ssl_manager.pin_path()`
- `get_ssl_errors()` reads from `ssl_manager.pin_path()`
- `flush_ssl_errors()` writes to `ssl_manager.pin_path()`

Result:

- The code no longer pretends a process-global map lives at `base_pin_path`.

### 6.5 Remove SSL attach from `FirewallInstance` and `system_start`

After `SslManager` exists, SSL attach must be removed from per-instance flows.

Changes:

- Remove `self.attach_ssl_uprobes()` from `FirewallInstance::attach()`.
- Remove direct `attach_ssl_uprobes()` from `system_start()`.
- Keep only `SslManager::ensure_loaded()`.

Result:

- Multi-instance mode no longer duplicates uprobes.
- System mode and tap mode share the same SSL subsystem.

### 6.6 Repair SSL configuration semantics

SSL must have one authoritative runtime switch.

Target state:

- The only real runtime switch is `SSL_GLOBAL_CONFIG`.
- Per-instance `FIREWALL_CONFIG.ssl_enabled` becomes compatibility-only during migration and is later removed.

Compatibility behavior for the first migration release:

- `update_config(instance, ssl=Some(v))` also updates global `SSL_GLOBAL_CONFIG`.
- `get_config(instance)` should report the global SSL state for the `ssl` field, not a stale per-instance value.
- CLI `config set ssl on/off` should internally dispatch to the same path used by `ariactl ssl enable/disable`.

Deprecation plan:

- Keep the `ssl` field in `UpdateConfigRequest` and `ConfigResponse` for one compatibility window.
- Mark it as deprecated in docs and help text.
- Remove it after the dedicated global SSL endpoints and CLI paths have been the default for at least one release cycle.

### 6.7 Add global SSL routes while preserving per-instance compatibility

Current routes already treat config and errors as global. SSL list and HTTP list should join them.

Add new routes:

- `GET /api/v1/ssl`
- `DELETE /api/v1/ssl`
- `GET /api/v1/ssl/http`
- `DELETE /api/v1/ssl/http`

Compatibility routes to keep temporarily:

- `GET /api/v1/{instance}/ssl`
- `DELETE /api/v1/{instance}/ssl`
- `GET /api/v1/{instance}/ssl/http`
- `DELETE /api/v1/{instance}/ssl/http`

Compatibility behavior:

- Per-instance routes proxy to the global SSL store.
- The `instance` path segment is ignored for actual data selection.

CLI behavior:

- `ariactl ssl list/http/flush/errors` should work without `--tap`.
- If `--tap` is provided for SSL commands, keep accepting it but print a short compatibility note that SSL data is global.

Result:

- Existing automation keeps working.
- New APIs and CLI match actual runtime ownership.

### 6.8 Repair `TapRegistry::detach` ordering

New detach sequence:

1. Acquire per-interface lock.
2. Read and remove the instance from the registry only after kernel detach succeeds, or keep it in place until success is certain.
3. Call `instance.detach()`.
4. If detach succeeds:
   - remove from registry
   - unregister from control plane
   - clean lock entry
5. If detach fails:
   - preserve registry and control-plane state
   - return error for retry

Recommended implementation detail:

- Fetch the instance first without unregistering.
- Only commit userspace removal after the kernel cleanup path returns success.

Result:

- Userspace and kernel state stay aligned in failure scenarios.

### 6.9 Unify runtime recovery on `snapshot + WAL`

Add one canonical runtime state loader.

Recommended shape:

- `core::wal::load_with_wal(state_path) -> FirewallState`
- `core::ebpf_ops::replay_loaded_state(bpf, &FirewallState)`

Then:

- `FirewallInstance` recovery uses `load_with_wal()` and replays that result.
- Initial attach also uses the same runtime state source.

Do not leave `replay_state()` reading `state.json` directly.

Result:

- Recovery input matches control-plane state.
- Crash windows between append and compact no longer create divergent userspace and kernel state.

### 6.10 Add TC runtime verification and repair

Recovery should not assume TC state survived just because XDP did.

Recommended new helpers in `FirewallInstance`:

- `ensure_tc_runtime(&mut self, bpf: &mut aya::Ebpf, pin_path: &str) -> Result<(), String>`
- `ensure_fq_runtime(&mut self, requires_shaping: bool) -> Result<(), String>`

`ensure_tc_runtime()` should:

- Check for `tc_egress_link` and `tc_ingress_link`.
- If link pins exist, treat them as valid on kernels with `bpf_link`.
- If link pins do not exist, inspect actual `tc filter` state.
- Reattach `tc_egress` or `tc_ingress` only if missing.

`ensure_fq_runtime()` should:

- Detect whether any configured QoS rules require shaping.
- If shaping is required and `fq` is absent, try `setup_fq_qdisc()`.
- Update `edt_available` based on the final result.

Rationale:

- Recovery must be idempotent.
- Do not blindly duplicate TC attachments.

### 6.11 Preserve `ssl-global` during cleanup and migrate legacy SSL pins

Two cleanup paths are needed.

Normal orphan cleanup:

- Extend the reserved directory allowlist to keep:
  - `system`
  - `ssl-global`

Legacy migration cleanup:

- Add a startup-only cleanup function such as `cleanup_legacy_instance_ssl_pins(base_pin_path)`.
- For each instance directory, remove only old SSL-related map and link pins.
- Do not remove non-SSL pinned network objects.

Order:

1. Initialize `ssl-global`
2. Load `SslManager`
3. Run legacy SSL pin cleanup
4. Continue normal interface scan

Result:

- The new global directory is safe from orphan cleanup.
- Old per-instance SSL pins do not accumulate indefinitely after upgrade.

### 6.12 Fix SSL metrics ownership

After SSL globalization, SSL metrics must be collected once, not once per instance.

Changes to Prometheus output:

- Export SSL handshake metrics from the global SSL store one time.
- Export SSL HTTP metrics from the global SSL store one time.

Compatibility recommendation:

- During the migration release, label global SSL metrics with `instance="ssl-global"` instead of duplicating them for every tap.

Reason:

- Repeating one global dataset for each interface label is incorrect and misleading.

## 7. Implementation Order

### Phase 1: Correctness hotfixes

- Add `ssl_write_return` eBPF entry
- Unify SSL probe/link inventory
- Fix SSL link cleanup list
- Split pin inventories and add missing SSL maps
- Fix `TapRegistry::detach` ordering
- Unify replay input to `snapshot + WAL`
- Add TC/FQ runtime verification and repair

### Phase 2: SSL globalization

- Introduce `SslManager`
- Move all SSL pinning to `ssl-global`
- Remove SSL attach from `FirewallInstance` and `system_start`
- Fix global SSL path usage in `ControlPlane` and `ssl_ops`
- Add legacy instance SSL pin cleanup
- Protect `ssl-global` from orphan cleanup

### Phase 3: API and compatibility cleanup

- Add global SSL list/flush/http routes
- Keep per-instance SSL routes as proxy compatibility layer
- Make CLI SSL commands independent from `--tap`
- Route `config set ssl` through the global SSL switch
- Mark per-instance SSL config as deprecated
- Fix Prometheus SSL metrics to be global-only

## 8. Validation Plan

### 8.1 Unit tests

- Test that shared SSL probe inventory contains all expected probes, including `ssl_write_return`.
- Test that SSL link cleanup inventory includes `ssl_write_return_link`.
- Test that pin inventory includes all SSL-global maps.
- Test that runtime replay built from `state.json + WAL` matches control-plane recovery input.

### 8.2 Integration tests

- System mode:
  - start firewall
  - enable SSL
  - confirm `ssl status`, `ssl list`, `ssl http`, `ssl errors`
- Tap-managed mode:
  - attach one tap
  - confirm SSL load succeeds without missing-program failure
- Multi-instance mode:
  - attach multiple taps
  - confirm SSL events are not duplicated
- Recovery:
  - create WAL-only pending changes
  - restart agent
  - confirm kernel maps and API state are identical
- TC recovery:
  - restart agent with pinned XDP and missing TC runtime
  - confirm `tc_egress` and `tc_ingress` are repaired as needed
- Cleanup:
  - confirm `ssl-global` survives orphan cleanup
  - confirm legacy per-instance SSL pins are removed

Current repository helper:

- `tools/runtime_lifecycle_regression.py`
  - validates `system stop + vanished iface`
  - validates `system preexisting fq`
  - validates `managed crash recovery -> DelLink`
  - should be used as the baseline `6.8` runtime lifecycle smoke before any future repair changes are merged

### 8.3 Compatibility tests

- Existing CLI with `--tap` still works for SSL commands.
- Per-instance SSL routes return the same data as new global routes.
- `config set ssl on` and `ssl enable` lead to the same effective runtime state.
- SSL metrics are exported only once and no longer duplicated by interface.

## 9. Risks and Mitigations

Risk:

- Introducing `SslManager` changes lifecycle ownership.

Mitigation:

- Keep first release compatible by proxying old routes and CLI behavior.

Risk:

- Legacy cleanup may remove files still assumed by old code paths.

Mitigation:

- Run cleanup only after `ssl-global` is initialized and only remove SSL-specific pins.

Risk:

- TC recovery may attach duplicate filters if detection is wrong.

Mitigation:

- Use "check before attach" logic, not blind reattachment.

Risk:

- Temporary dual-support period may still confuse users.

Mitigation:

- Emit explicit deprecation notes in CLI output and docs.

## 10. Expected End State

After all phases are complete:

- SSL is a real host-global subsystem.
- Firewall interface instances no longer own SSL probe lifecycle.
- Control-plane state, WAL recovery, and kernel map replay use the same logical state source.
- Restart recovery restores XDP, TC, and required runtime prerequisites consistently.
- SSL APIs, CLI, pin paths, cleanup logic, and metrics all describe the same ownership model.

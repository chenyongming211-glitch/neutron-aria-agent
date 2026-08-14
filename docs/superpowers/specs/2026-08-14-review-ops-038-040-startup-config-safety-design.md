# REVIEW-OPS-038/040 Startup Configuration Safety Design

**Status:** source implementation and exact-head hosted CI complete

**Date:** 2026-08-14

**Owning findings:** `REVIEW-OPS-038`, `REVIEW-OPS-040`

## 1. Decision

Make configuration loading and interface-pattern compilation one mandatory,
side-effect-free startup gate:

```text
parse CLI arguments
  -> read configuration
     -> NotFound: use documented standalone defaults
     -> every other read error: fatal
     -> TOML decode error: fatal
  -> compile configured iface_pattern exactly once
     -> invalid regex: fatal
  -> continue with tracing, eBPF resolution, runtime managers and registry
```

The compiled `Regex` is passed into `TapRegistry`. The registry no longer
accepts an unchecked string and no longer substitutes `^tap` for invalid
operator input.

This preserves the documented absent-file quick-start behavior without
allowing an existing damaged configuration to silently change authority mode
or interface scope.

## 2. Verified Root Causes

### 2.1 Existing invalid configuration becomes standalone authority

`load_config` currently checks `Path::exists`, tries to read and parse the
file, prints warnings on failure, and returns `Config::default()` in every
failure case. The default is `mode=standalone`; absent an explicit override,
`requested_auto_attach` and `effective_auto_attach` are both true. A damaged
Neutron-managed configuration can therefore restart as standalone and begin
discovering interfaces matching the default `^tap` scope.

The `exists` check also adds a time-of-check/time-of-use race. A file that
disappears between `exists` and `read_to_string` is treated like every other
read failure and currently falls back silently.

### 2.2 Invalid interface scope becomes `^tap`

`TapRegistry::new` currently compiles the configured `iface_pattern` and uses
`unwrap_or_else` to replace any invalid expression with `^tap`. This changes an
operator typo into a valid, broader discovery scope instead of rejecting the
configuration. The substitution is silent and happens inside a runtime object,
after other startup work has already begun.

## 3. Startup Boundary

Add one concrete loader in `agent/src/main.rs`:

```rust
struct StartupConfig {
    config: Config,
    iface_pattern: Regex,
}

fn load_startup_config(path: &Path) -> Result<StartupConfig, String>;
```

The helper performs only filesystem read, TOML deserialization and regex
compilation. It does not initialize tracing, create directories, resolve or
load eBPF, bind sockets, construct managers, scan links or attach programs.

`main` must obtain `StartupConfig` immediately after argument parsing. Any
error is printed to stderr and exits nonzero before all runtime construction.
Once the gate succeeds, the existing fragment, management-listener, peer-auth,
trace-backend and other validation paths retain their current order and
semantics.

This is deliberately a small concrete boundary, not a generic validation
framework or closure/future transaction abstraction.

## 4. File Loading Contract

`load_startup_config` calls `read_to_string` directly and classifies the
result by `io::ErrorKind`:

- `NotFound`: log that the path is absent and use `Config::default()`;
- any other error, including permission denial, a directory in place of the
  file, invalid encoding or other read failure: return an error containing the
  requested path and underlying cause;
- readable but invalid TOML: return an error containing the path and TOML
  decode cause;
- readable valid TOML: preserve the decoded configuration exactly.

There is no separate `exists` pre-check. If the path disappears before the
single read, the operating system reports `NotFound`, which follows the
documented absent-file contract. No existing unreadable or malformed input is
converted into defaults.

This batch does not change the product decision that a genuinely absent
configuration, including an explicitly supplied absent path, uses standalone
defaults. Tightening that compatibility boundary would require a separate
CLI/product decision.

## 5. Interface Pattern Contract

The selected configuration's `iface_pattern` is compiled exactly once inside
the startup gate:

- valid expressions are preserved byte-for-byte in the configuration and as
  the compiled matcher supplied to the registry;
- invalid expressions return an error naming `iface_pattern` and the rejected
  value;
- no fallback pattern exists;
- `TapRegistry::new` accepts an already compiled `Regex`, making it impossible
  for the registry to reinterpret or silently replace startup input.

The default remains `^tap` only when Serde/default configuration legitimately
selects the default. This batch does not reject valid empty, broad or otherwise
operator-chosen regular expressions; policy restrictions on valid expressions
are outside the confirmed finding.

## 6. Alternatives Rejected

### 6.1 Return `Result` from `TapRegistry::new`

This removes the fallback but validates too late, after eBPF resolution,
directory creation and global manager initialization. It does not provide the
required pre-side-effect startup gate.

### 6.2 Validate in `main`, then compile again in the registry

This is a smaller signature change but creates two parsers for one contract.
Future option or library drift could make validation and runtime matching
disagree.

### 6.3 Keep defaults for malformed input but disable auto-attach

This treats only the most visible symptom. It still discards the configured
authority mode, socket, paths and security settings and lets the service run
under configuration the operator did not supply.

## 7. RED/GREEN Behavior Matrix

The hosted Rust behavior lane adds a `startup_config_` filter and requires
nonzero execution for:

1. absent path returns the documented standalone/default matcher;
2. valid standalone configuration preserves its mode, auto-attach setting and
   custom matcher;
3. valid Neutron-managed configuration preserves its mode and cannot become
   standalone;
4. malformed TOML returns an error rather than defaults;
5. an existing non-readable configuration path returns an error rather than
   defaults;
6. invalid `iface_pattern` returns an error before a registry can be built;
7. a valid custom pattern is the exact matcher used by `TapRegistry` and is
   never replaced by `^tap`.

The existing `startup_mode` behaviors remain in the lane. Tests use public
startup/registry behavior and filesystem inputs; no Python source parser or
private function-shape checker is added.

RED commit `fb0f948` failed in Build
[31762886875](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31762886875)
with `E0425` for the absent startup gate and `E0308` because the old registry
still required an unchecked string; the remaining long build was cancelled
after that exact evidence was captured. GREEN commit `9010f7e` passed eight
nonzero `startup_config_` behaviors plus warning-denied eBPF, userspace and
agent builds in exact-head Build
[31763073075](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31763073075).
No privileged attach execution is claimed or required for this pre-runtime
failure boundary.

## 8. Failure And Compatibility Semantics

- Configuration load/parse/pattern errors terminate startup with nonzero exit.
- No registry, netlink monitor, discovery scan or attach attempt occurs after
  such an error.
- No eBPF manager or socket is initialized before the new gate succeeds.
- Error messages identify the configured path or pattern without echoing
  unrelated configuration contents.
- Valid existing standalone and Neutron-managed configurations are unchanged.
- Missing-file default behavior and the default `^tap` value are unchanged.

## 9. Scope

Production changes are limited to:

- `agent/src/main.rs`: fallible startup loader, early regex compilation and
  startup error handling;
- `agent/src/tap_registry.rs`: accept the compiled matcher and remove fallback;
- the three existing `TapRegistry::new` call sites;
- Rust behavior tests and the existing hosted behavior inventory;
- startup contract, implementation plan, program index and REVIEW register.

Explicit exclusions:

- no change to valid regex semantics or interface naming policy;
- no change to CLI defaults or the absent-file quick-start contract;
- no validation framework for unrelated configuration fields;
- no eBPF, datapath, UDS, API, WAL or state schema change;
- no privileged attach test substituted for the pre-runtime startup contract;
- no implementation of later `REVIEW-ACL-077` or `REVIEW-TXN-033` work.

## 10. Acceptance

1. Only `NotFound` can select `Config::default()` during file loading.
2. Existing unreadable and malformed configuration is fatal.
3. Invalid `iface_pattern` is fatal before tracing/runtime construction.
4. `TapRegistry` has no invalid-regex fallback and receives one compiled
   matcher from the startup gate.
5. Valid standalone, Neutron-managed and custom-pattern behavior is preserved.
6. The required hosted filter executes every new behavior test and reports a
   nonzero count.
7. Exact-head fast contracts, Rust behavior and warning-denied eBPF,
   userspace and agent builds pass before either finding is closed.

# REVIEW-OPS-038/040 Startup Configuration Safety Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> superpowers:executing-plans to implement this plan task-by-task. Steps use
> checkbox (`- [ ]`) syntax for tracking. Execute inline on the sole
> `v0.9-neutron-agent` branch; do not create a branch, worktree, PR, or
> subagent task.

**Goal:** reject existing unreadable/malformed configuration and invalid
`iface_pattern` before any runtime construction, while preserving the
documented missing-file standalone defaults.

**Architecture:** introduce one concrete `load_startup_config` gate in
`agent/src/main.rs` that reads/decodes the configuration and compiles its regex
exactly once. Pass the compiled `Regex` into `TapRegistry`, deleting its
fallback and leaving all later runtime behavior unchanged.

**Tech Stack:** Rust 2021, Serde/TOML, `regex`, existing `aria-agent` unit
tests, GitHub Actions warning-denied Rust/eBPF builds.

## Global Constraints

- Follow the approved
  [design](../specs/2026-08-14-review-ops-038-040-startup-config-safety-design.md).
- Work directly on `v0.9-neutron-agent`; do not create another branch,
  worktree, PR, or subagent task.
- Do not run local Cargo build, check, test, clippy, or rustfmt commands.
- Push RED and GREEN separately; hosted CI is the Rust authority.
- Only `io::ErrorKind::NotFound` may select `Config::default()`.
- Compile `iface_pattern` once before tracing/eBPF/runtime construction and
  pass the compiled matcher into `TapRegistry`.
- Do not change valid regex semantics, CLI defaults, absent-file behavior,
  public APIs, state/WAL formats or datapath behavior.
- Keep `REVIEW-ACL-077`, `REVIEW-TXN-033` and unrelated configuration cleanup
  outside this batch.

---

### Task 1: RED Startup Configuration Behaviors

**Files:**

- Modify: `agent/src/main.rs` test module
- Modify: `agent/src/tap_registry.rs` test helper and test module
- Modify: `ci/check_neutron_stage1.py`

**Interfaces:**

- Requires future interface:

```rust
struct StartupConfig {
    config: Config,
    iface_pattern: regex::Regex,
}

fn load_startup_config(path: &Path) -> Result<StartupConfig, String>;
```

- Requires future `TapRegistry::new` parameter:

```rust
pub fn new(
    ebpf_path: &str,
    base_pin_path: &str,
    base_state_path: &str,
    iface_pattern: Regex,
    max_port_policies: u32,
    control_plane: Arc<ControlPlane>,
) -> Self;
```

- [ ] **Step 1: Add deterministic temporary configuration fixtures**

Add a `startup_config_path` helper in the `main.rs` test module. It must use
process ID plus `SystemTime::now().duration_since(UNIX_EPOCH).as_nanos()` and
remove any stale path before returning it:

```rust
fn startup_config_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "aria-startup-config-{}-{}-{}",
        name,
        std::process::id(),
        nanos
    ));
    let _ = std::fs::remove_file(&path);
    let _ = std::fs::remove_dir_all(&path);
    path
}
```

- [ ] **Step 2: Add missing, valid and invalid file behaviors**

Add tests named with the `startup_config_` prefix. The assertions must cover
the exact contract:

```rust
#[test]
fn startup_config_missing_path_uses_documented_defaults() {
    let path = startup_config_path("missing");
    let startup = load_startup_config(&path).unwrap();

    assert_eq!(startup.config.mode, AgentMode::Standalone);
    assert!(startup.config.effective_auto_attach());
    assert!(startup.iface_pattern.is_match("tap123"));
    assert!(!startup.iface_pattern.is_match("qvo123"));
}

#[test]
fn startup_config_valid_neutron_mode_and_custom_pattern_are_preserved() {
    let path = startup_config_path("valid-neutron");
    std::fs::write(
        &path,
        "mode = \"neutron_managed\"\niface_pattern = \"^qvo[0-9]+$\"\n",
    )
    .unwrap();

    let startup = load_startup_config(&path).unwrap();
    assert_eq!(startup.config.mode, AgentMode::NeutronManaged);
    assert!(!startup.config.effective_auto_attach());
    assert!(startup.iface_pattern.is_match("qvo12"));
    assert!(!startup.iface_pattern.is_match("tap12"));

    std::fs::remove_file(path).unwrap();
}
```

Add standalone `auto_attach=false` coverage using a valid custom pattern.
Add malformed TOML and invalid regex tests which extract the `Err` through a
`match`, assert that it contains the path plus `parse configuration` or
`iface_pattern`, and assert it does not return defaults.

- [ ] **Step 3: Add deterministic existing-read-failure behavior**

Create a directory at the requested configuration path so `read_to_string`
must fail independently of runner UID. Assert that `load_startup_config`
returns an error containing both the path and `read configuration`, then remove
the directory:

```rust
#[test]
fn startup_config_existing_unreadable_path_is_fatal() {
    let path = startup_config_path("unreadable");
    std::fs::create_dir(&path).unwrap();

    let error = match load_startup_config(&path) {
        Ok(_) => panic!("existing unreadable config path must not use defaults"),
        Err(error) => error,
    };
    assert!(error.contains(&path.display().to_string()));
    assert!(error.contains("read configuration"));

    std::fs::remove_dir(path).unwrap();
}
```

- [ ] **Step 4: Make the registry test contract require a compiled matcher**

Change the test helper to pass `Regex::new("^(lo|tap)").unwrap()` and add:

```rust
#[test]
fn startup_config_registry_uses_prevalidated_pattern_without_default_fallback() {
    let root = temp_root("prevalidated-pattern");
    let registry = test_registry_with_pattern(
        &root,
        Regex::new("^qvo[0-9]+$").unwrap(),
    );

    assert!(registry.matches_pattern("qvo12"));
    assert!(!registry.matches_pattern("tap12"));
    std::fs::remove_dir_all(root).unwrap();
}
```

The helper `test_registry_with_pattern(root, Regex)` must construct the real
registry; `test_registry(root)` delegates to it with `^(lo|tap)`.

- [ ] **Step 5: Add the required hosted behavior filter**

Add this independent entry to `RUST_BEHAVIOR_TESTS` in
`ci/check_neutron_stage1.py`:

```python
["test", "--locked", "-p", "aria-agent", "startup_config_"],
```

Keep the existing `startup_mode` filter. The lane's existing nonzero-count
contract must reject a filter that discovers no tests.

- [ ] **Step 6: Run allowed RED preflight checks**

Run:

```bash
python3 -m unittest ci.test_ci_lane_contract -v
python3 ci/check_blocked_terms.py
git diff --check
```

Expected: all Python/static checks pass. Do not run Cargo locally.

- [ ] **Step 7: Commit and push RED**

```bash
git add agent/src/main.rs agent/src/tap_registry.rs ci/check_neutron_stage1.py
git commit -m "test: expose unsafe startup config fallback"
git push origin v0.9-neutron-agent
```

Expected hosted failure: `rust-behavior` fails because
`load_startup_config`/`StartupConfig` and the compiled-regex constructor do not
exist in production yet. Cancel remaining long build work only after the exact
RED evidence is captured.

### Task 2: GREEN Early Validation And Compiled Registry Pattern

**Files:**

- Modify: `agent/src/main.rs`
- Modify: `agent/src/tap_registry.rs`
- Modify: `agent/src/neutron_api.rs` test helper

**Interfaces:**

- Produces `fn load_startup_config(&Path) -> Result<StartupConfig, String>`.
- Produces `TapRegistry::new(..., Regex, ...) -> Self` with no fallback.
- Consumes the tests and hosted filter from Task 1.

- [ ] **Step 1: Add the concrete startup configuration type and loader**

Import `regex::Regex` and implement this boundary in `agent/src/main.rs`:

```rust
struct StartupConfig {
    config: Config,
    iface_pattern: Regex,
}

fn load_startup_config(path: &Path) -> Result<StartupConfig, String> {
    let config = match std::fs::read_to_string(path) {
        Ok(contents) => {
            let config = toml::from_str(&contents).map_err(|error| {
                format!(
                    "failed to parse configuration {}: {}",
                    path.display(),
                    error
                )
            })?;
            println!("Loaded config from {:?}", path);
            config
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            println!("Config file {:?} not found, using defaults", path);
            Config::default()
        }
        Err(error) => {
            return Err(format!(
                "failed to read configuration {}: {}",
                path.display(),
                error
            ));
        }
    };

    let iface_pattern = Regex::new(&config.iface_pattern).map_err(|error| {
        format!(
            "invalid iface_pattern {:?}: {}",
            config.iface_pattern,
            error
        )
    })?;

    Ok(StartupConfig {
        config,
        iface_pattern,
    })
}
```

Delete the old `load_config` function and its `PathBuf`-specific signature.

- [ ] **Step 2: Move the gate to the start of `main`**

Immediately after `Args::parse`, replace the infallible load with:

```rust
let StartupConfig {
    config,
    iface_pattern,
} = match load_startup_config(&args.config) {
    Ok(startup) => startup,
    Err(error) => {
        eprintln!("Error: invalid startup configuration: {}", error);
        std::process::exit(1);
    }
};
```

This must remain before fragment settings, listener validation, tracing,
eBPF resolution, directory creation, manager construction and socket binding.

- [ ] **Step 3: Remove registry fallback by construction**

Change `TapRegistry::new` to accept `iface_pattern: Regex` and assign it
directly:

```rust
pub fn new(
    ebpf_path: &str,
    base_pin_path: &str,
    base_state_path: &str,
    iface_pattern: Regex,
    max_port_policies: u32,
    control_plane: Arc<ControlPlane>,
) -> Self {
    Self {
        instances: RwLock::new(HashMap::new()),
        iface_locks: RwLock::new(HashMap::new()),
        ebpf_path: PathBuf::from(ebpf_path),
        base_pin_path: PathBuf::from(base_pin_path),
        base_state_path: PathBuf::from(base_state_path),
        iface_pattern,
        max_port_policies,
        control_plane,
    }
}
```

Pass the owned `iface_pattern` from `main`. Update only the two Rust test
helpers in `tap_registry.rs` and `neutron_api.rs` to construct explicit valid
`Regex` values. No unchecked string-to-regex conversion remains in the
registry.

- [ ] **Step 4: Run allowed GREEN preflight checks**

Run:

```bash
python3 -m unittest ci.test_ci_lane_contract -v
python3 ci/check_blocked_terms.py
git diff --check
```

Expected: all pass. Do not run Cargo locally.

- [ ] **Step 5: Commit and push GREEN**

```bash
git add agent/src/main.rs agent/src/tap_registry.rs agent/src/neutron_api.rs
git commit -m "fix: fail closed on invalid startup config"
git push origin v0.9-neutron-agent
```

Require the exact implementation HEAD to pass `fast-contracts`, the nonzero
`startup_config_` behavior filter, the maintained Rust behavior lane, and
warning-denied eBPF/userspace/agent builds.

### Task 3: Contract And REVIEW Closure

**Files:**

- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`
- Modify:
  `docs/superpowers/specs/2026-08-13-bug-hunt-remediation-program-design.md`
- Modify this plan and its design

**Interfaces:**

- Consumes exact RED/GREEN commit IDs and Build URLs from Tasks 1 and 2.
- Advances the fixed sequence to `REVIEW-ACL-077` only after GREEN.

- [ ] **Step 1: Record the final startup contract**

Update the design status and this plan with exact evidence. State explicitly:

```text
NotFound -> documented defaults
existing unreadable/malformed input -> fatal before runtime construction
invalid iface_pattern -> fatal before runtime construction
valid compiled matcher -> passed unchanged to TapRegistry
```

Do not claim privileged attach execution; this batch proves the pre-runtime
failure boundary through Rust behavior and hosted build evidence.

- [ ] **Step 2: Close only the verified findings**

Mark `REVIEW-OPS-038` and `REVIEW-OPS-040` fixed with exact commits and Builds.
Update the ordinary-open-P1 count by removing OPS-038. Preserve all conditional
and target-kernel-pending statuses.

- [ ] **Step 3: Advance the fixed-order program**

Change the active next batch to `REVIEW-ACL-077` Python 2.7 status
compatibility. Do not pull `REVIEW-TXN-033` forward.

- [ ] **Step 4: Run documentation verification**

```bash
python3 ci/check_blocked_terms.py
python3 -m unittest ci.test_public_release_hygiene ci.test_ci_lane_contract -v
git diff --check
```

Expected: all checks pass.

- [ ] **Step 5: Commit, push and verify the documentation HEAD**

```bash
git add docs/openstack-neutron-aria-details/12-review-bug-backlog.md \
  docs/superpowers/plans/2026-08-14-review-ops-038-040-startup-config-safety.md \
  docs/superpowers/specs/2026-08-13-bug-hunt-remediation-program-design.md \
  docs/superpowers/specs/2026-08-14-review-ops-038-040-startup-config-safety-design.md
git commit -m "docs: close startup config safety"
git push origin v0.9-neutron-agent
```

Require the selected exact-head fast/static Build to pass, then verify the
worktree is clean and local/remote divergence is `0 0`.

## Plan Self-Review

- Coverage: missing, valid, unreadable, malformed and invalid-regex inputs;
  compiled matcher ownership; startup ordering; hosted discovery; warning-
  denied build; and register closure each have an owning step.
- Scope: two production Rust modules, one Rust test helper, the existing CI
  behavior inventory and named documentation only. No generic config framework
  or datapath change is introduced.
- Type consistency: `load_startup_config` returns one `StartupConfig`; the
  `Regex` it owns is moved directly into the revised `TapRegistry::new`.
- Evidence: RED and GREEN are separate hosted commits; no local Cargo command
  appears in the execution steps.

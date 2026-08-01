# RISK-SEC-002 Management API Bind Guard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent accidental network exposure of the unauthenticated root HTTP management API while preserving an explicit, auditable unsafe override.

**Architecture:** Parse and validate `listen_addr` once as a literal `SocketAddr` before eBPF or runtime initialization, then bind that validated value directly. Loopback is accepted by default; every non-loopback IP requires `allow_unauthenticated_non_loopback=true` and emits an explicit warning.

**Tech Stack:** Rust, Serde/TOML, Tokio TCP listener, tracing, Python-hosted CI lane definitions, shell/Kolla TOML configuration, Markdown.

## Global Constraints

- Work only on local and remote `v0.9-neutron-agent`; do not create a branch, PR, or worktree.
- Do not run Cargo locally. GitHub Actions supplies all Rust RED/GREEN and warning-denied build evidence.
- Do not add TLS, tokens, RBAC, proxy automation, UDS changes, or readiness behavior.
- Do not add a Python parser for Rust source or bind CI to private helper spelling.
- Do not claim privileged field evidence; this configuration boundary requires none.
- Preserve the packaged `127.0.0.1:8080` listener and make the unsafe override default to `false`.

## Execution Evidence

- RED `4316b62`: Build
  [30706588907](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30706588907)
  failed on the intentionally missing field and validation method after all
  non-Rust contracts passed.
- GREEN `ca5cb88`: exact-head Build
  [30706732514](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30706732514)
  passed all required lanes and executed all five `management_listener_`
  tests.
- Documentation closure `dbed756`: Build
  [30706991370](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30706991370)
  passed fast, database, and clean-install contracts; Rust jobs correctly
  skipped for the docs-only change.
- Local non-Cargo verification passed 557 Python tests with 8 skips, 10 CLI
  tests, shell syntax, installer, and public contract checks.
- The TCP API remains unauthenticated. No privileged field evidence applies or
  is claimed.

---

### Task 1: Establish the RED management-listener contract

**Files:**
- Modify: `agent/src/main.rs:1091` test module
- Modify: `ci/check_neutron_stage1.py:25` Rust behavior inventory

**Interfaces:**
- Consumes: existing private `Config` TOML boundary.
- Produces: `Config::management_listen_addr() -> Result<SocketAddr, String>`, `Config.allow_unauthenticated_non_loopback`, and hosted filter `management_listener_` as intentionally missing RED contracts.

- [x] **Step 1: Add the configuration behavior tests**

Add these tests to `agent/src/main.rs`:

```rust
fn management_listener_config(listen_addr: &str, allow_non_loopback: bool) -> Config {
    toml::from_str(&format!(
        "listen_addr = {:?}\nallow_unauthenticated_non_loopback = {}\n",
        listen_addr, allow_non_loopback
    ))
    .unwrap()
}

#[test]
fn management_listener_default_is_loopback_and_unsafe_override_is_off() {
    let config = Config::default();

    assert!(!config.allow_unauthenticated_non_loopback);
    assert_eq!(
        config.management_listen_addr().unwrap(),
        "127.0.0.1:8080".parse::<std::net::SocketAddr>().unwrap()
    );
}

#[test]
fn management_listener_accepts_explicit_ipv4_and_ipv6_loopback() {
    for value in ["127.4.3.2:8080", "[::1]:8080"] {
        let config = management_listener_config(value, false);
        assert_eq!(
            config.management_listen_addr().unwrap(),
            value.parse::<std::net::SocketAddr>().unwrap()
        );
    }
}

#[test]
fn management_listener_rejects_non_loopback_without_explicit_override() {
    for value in [
        "0.0.0.0:8080",
        "[::]:8080",
        "10.0.0.8:8080",
        "198.51.100.8:8080",
        "[fe80::1]:8080",
        "[ff02::1]:8080",
        "[::ffff:127.0.0.1]:8080",
    ] {
        let error = management_listener_config(value, false)
            .management_listen_addr()
            .unwrap_err();
        assert!(error.contains(value));
        assert!(error.contains("allow_unauthenticated_non_loopback = true"));
    }
}

#[test]
fn management_listener_rejects_hostname_and_malformed_values_without_resolution() {
    for value in ["localhost:8080", "127.0.0.1", "not-an-address"] {
        let error = management_listener_config(value, false)
            .management_listen_addr()
            .unwrap_err();
        assert!(error.contains(value));
        assert!(error.contains("explicit IP socket"));
    }
}

#[test]
fn management_listener_explicit_override_allows_only_valid_non_loopback_socket() {
    let config = management_listener_config("192.0.2.20:8080", true);
    assert!(config.allow_unauthenticated_non_loopback);
    assert_eq!(
        config.management_listen_addr().unwrap(),
        "192.0.2.20:8080"
            .parse::<std::net::SocketAddr>()
            .unwrap()
    );

    let error = management_listener_config("external.example:8080", true)
        .management_listen_addr()
        .unwrap_err();
    assert!(error.contains("explicit IP socket"));
}
```

- [x] **Step 2: Add the hosted Cargo behavior filter**

Add exactly one entry to `ci/check_neutron_stage1.py::RUST_TESTS`:

```python
["test", "--locked", "-p", "aria-agent", "management_listener_"],
```

The existing zero-test guard must remain authoritative.

- [x] **Step 3: Run local non-Cargo verification**

Run:

```bash
git diff --check
python3 -m unittest ci.test_ci_lane_contract ci.test_ci001_trusted_gates
python3 ci/check_neutron_stage1.py --fast-contracts
```

Expected: all Python/CLI/shell contracts pass. No Cargo command runs locally.

- [x] **Step 4: Commit and push RED**

```bash
git add agent/src/main.rs ci/check_neutron_stage1.py
git commit -m "test: expose unsafe management API binding"
git push origin v0.9-neutron-agent
```

- [x] **Step 5: Capture exact hosted RED**

Wait for the exact-head Build. Expected: `rust-behavior` fails because
`allow_unauthenticated_non_loopback` and `management_listen_addr()` do not yet
exist. Confirm fast contracts still pass, record the run URL, and cancel only
remaining expensive jobs after the intended RED is captured.

---

### Task 2: Enforce the startup bind invariant

**Files:**
- Modify: `agent/src/main.rs:4-13,46-91,272-347,799-877,950-958`

**Interfaces:**
- Consumes: Task 1 tests and `std::net::SocketAddr`.
- Produces: `Config::management_listen_addr() -> Result<SocketAddr, String>` and a validated `SocketAddr` passed directly to Tokio bind.

- [x] **Step 1: Add the configuration field and default**

Import `SocketAddr` and add the field/default:

```rust
use std::net::SocketAddr;

#[serde(default)]
allow_unauthenticated_non_loopback: bool,
```

```rust
allow_unauthenticated_non_loopback: false,
```

- [x] **Step 2: Implement the pure address validation**

Add this method inside `impl Config`:

```rust
fn management_listen_addr(&self) -> Result<SocketAddr, String> {
    let listen_addr = self.listen_addr.parse::<SocketAddr>().map_err(|_| {
        format!(
            "invalid listen_addr '{}': expected an explicit IP socket such as 127.0.0.1:8080 or [::1]:8080",
            self.listen_addr
        )
    })?;

    if listen_addr.ip().is_loopback() || self.allow_unauthenticated_non_loopback {
        return Ok(listen_addr);
    }

    Err(format!(
        "listen_addr '{}' is not loopback; set allow_unauthenticated_non_loopback = true only when an external security boundary protects the unauthenticated root management API",
        self.listen_addr
    ))
}
```

- [x] **Step 3: Validate before runtime initialization**

Immediately after fragment-tracking validation and before `init_tracing`, add:

```rust
let management_listen_addr = match config.management_listen_addr() {
    Ok(listen_addr) => listen_addr,
    Err(e) => {
        eprintln!("Error: invalid management API listener configuration: {}", e);
        std::process::exit(1);
    }
};
```

After tracing initialization, warn on the explicit unsafe state:

```rust
if !management_listen_addr.ip().is_loopback() {
    warn!(
        listen_addr = %management_listen_addr,
        allow_unauthenticated_non_loopback = config.allow_unauthenticated_non_loopback,
        "unauthenticated root HTTP management API exposed on non-loopback address"
    );
}
```

Include the boolean and validated address in the existing startup `info!` event.

- [x] **Step 4: Bind only the validated socket**

Replace the string-based bind boundary with:

```rust
let listen_addr = management_listen_addr;
let listener = match tokio::net::TcpListener::bind(listen_addr).await {
    Ok(listener) => listener,
    Err(e) => {
        error!(listen_addr = %listen_addr, error = %e, "failed to bind HTTP server");
        std::process::exit(1);
    }
};
```

Do not resolve or bind the original string again.

- [x] **Step 5: Re-run local non-Cargo verification**

Run the same commands from Task 1 Step 3. Expected: all non-Cargo contracts
pass; no local Rust compilation is attempted.

---

### Task 3: Maintain safe packaged and operator-visible configuration

**Files:**
- Modify: `install.sh:274-287`
- Modify: `deploy/kolla/config/aria-agent-openstack.toml:16`
- Modify: `docs/user-manual.md:70-110`

**Interfaces:**
- Consumes: Task 2 configuration field.
- Produces: explicit safe defaults and operator documentation for the unsafe override.

- [x] **Step 1: Add explicit safe packaged defaults**

Immediately after every maintained `listen_addr = "127.0.0.1:8080"`, add:

```toml
allow_unauthenticated_non_loopback = false
```

Do this in `install.sh`, the Kolla configuration, and the current user-manual
configuration example. Do not rewrite historical plan snippets.

- [x] **Step 2: Document the exact operator contract**

Extend the `listen_addr` section in `docs/user-manual.md` to state:

```markdown
  - 必须是明确的 IP 和端口；默认只允许 IPv4/IPv6 loopback，不解析 hostname
- `allow_unauthenticated_non_loopback`
  - 默认 `false`
  - 仅在外部安全边界已经保护 root HTTP 管理面时才可显式设为 `true`
  - 该开关不会为 HTTP API 增加认证或加密
```

- [x] **Step 3: Verify shell/config contracts locally**

Run:

```bash
git diff --check
bash -n install.sh
python3 ci/check_neutron_stage1.py --fast-contracts
```

Expected: installer and maintained configuration contracts pass.

- [x] **Step 4: Commit and push GREEN**

```bash
git add agent/src/main.rs ci/check_neutron_stage1.py install.sh \
  deploy/kolla/config/aria-agent-openstack.toml docs/user-manual.md
git commit -m "fix: guard unauthenticated management listener"
git push origin v0.9-neutron-agent
```

- [x] **Step 5: Capture exact implementation-head GREEN**

Wait for `fast-contracts`, `neutron-db-contracts`, `neutron-agent-clean-install`,
`rust-behavior`, and `rust-build`. Confirm the `management_listener_` filter
executes the new tests and all warning-denied userspace/eBPF/static builds pass.

---

### Task 4: Close the risk with exact evidence

**Files:**
- Modify: `docs/superpowers/specs/2026-08-01-risk-sec-002-management-api-bind-guard-design.md`
- Modify: `docs/superpowers/plans/2026-08-01-risk-sec-002-management-api-bind-guard.md`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md:423`

**Interfaces:**
- Consumes: exact RED/GREEN commit IDs and Build URLs.
- Produces: an authoritative `RISK-SEC-002` closure without an authentication or field-evidence claim.

- [x] **Step 1: Record exact execution evidence**

Update the design status and this plan with:

- exact RED commit and expected failure;
- exact GREEN implementation commit and successful required jobs;
- explicit statement that TCP authentication remains absent;
- explicit statement that no privileged field evidence applies or is claimed.

- [x] **Step 2: Update the risk register**

Mark `RISK-SEC-002` fixed only if the exact implementation-head Build is green.
Describe the loopback default, literal-IP requirement, explicit unsafe override,
startup warning, direct typed bind, and remaining lack of HTTP authentication.

- [x] **Step 3: Verify and commit documentation closure**

Run:

```bash
git diff --check
python3 -m unittest ci.test_ci_lane_contract ci.test_ci001_trusted_gates
python3 ci/check_neutron_stage1.py --fast-contracts
git add docs/superpowers/specs/2026-08-01-risk-sec-002-management-api-bind-guard-design.md \
  docs/superpowers/plans/2026-08-01-risk-sec-002-management-api-bind-guard.md \
  docs/openstack-neutron-aria-details/12-review-bug-backlog.md
git commit -m "docs: close RISK-SEC-002"
git push origin v0.9-neutron-agent
```

- [x] **Step 4: Verify exact docs head and repository state**

Wait for docs-only required CI, then verify:

```bash
git status --short --branch
git rev-list --left-right --count \
  v0.9-neutron-agent...origin/v0.9-neutron-agent
```

Expected: clean worktree and divergence `0 0`.

- [x] **Step 5: Reassess next work**

Proceed to `RISK-READY-001`. Do not mix readiness behavior into this fix.

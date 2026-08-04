# REVIEW-OPS-036 Exact XDP Link Identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace path-only XDP health and startup claiming with exact pinned-link, program, and interface identity while preserving independent TC ACL/CT operation.

**Architecture:** A focused `xdp_link_health` module owns one pure identity classifier, one startup disposition function, and the smallest possible Linux BPF syscall adapter for reading the exact pinned link. Existing instance, shared-runtime, and standalone startup paths consume the same conservative result; non-verified existing pins are preserved and block replacement.

**Tech Stack:** Rust 2021, Aya 0.13.1, aya-obj 0.2.1 Linux UAPI bindings, libc `SYS_bpf`, GitHub Actions `rust-behavior` and warning-denied `rust-build`, Bash privileged smoke.

## Global Constraints

- Work directly on local and remote `v0.9-neutron-agent`; do not create another branch, worktree, or PR.
- Do not run local `cargo build`, `cargo check`, `cargo test`, clippy, or rustfmt. Rust RED/GREEN and warning evidence comes from GitHub Actions.
- Do not add an external `bpftool` or `ip` dependency to production health polling.
- Treat missing, unreadable, unsupported, detached, or mismatched evidence as not-ready; never fall back to path existence.
- Preserve unverified pre-existing pins and do not attach a replacement over their expected path.
- Keep TC ACL/CT health, activation, and forwarding independent from XDP health.
- Do not add storm/DDoS policy, map, API, attach-mode, or activation behavior.
- Keep privileged evidence `deferred/pending` until the guarded field smoke actually runs on a target kernel.
- Do not add Python source parsing or checks for private Rust implementation shape.
- Every semantic implementation commit must have exact-head hosted CI evidence before its result is recorded as complete.

---

## File structure and responsibilities

- Create `agent/src/xdp_link_health.rs`: identity types, pure classification, startup disposition, exact pinned-link syscall adapter, and focused Rust tests.
- Modify `agent/src/main.rs`: declare the focused module.
- Modify `agent/src/instance.rs`: replace path-only health and prevent shared-runtime path-only claiming.
- Modify `agent/src/system_manager.rs`: prevent standalone startup from claiming or replacing an unverified existing XDP pin.
- Modify `ci/check_neutron_stage1.py`: add one maintained Cargo behavior filter; do not add a source checker or duplicate the suite.
- Modify `deploy/smoke/aria_standalone_acl_tc_datapath_smoke.sh`: add an explicit opt-in detached-but-pinned XDP field case with stable skipped/passed state.
- Modify `docs/superpowers/specs/2026-08-04-review-ops-036-xdp-link-identity-design.md`: record implementation and hosted CI status after GREEN.
- Modify `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`: record source/hosted completion separately from deferred field evidence.

---

### Task 1: RED exact-identity and startup contracts

**Files:**
- Create: `agent/src/xdp_link_health.rs`
- Modify: `agent/src/main.rs`
- Modify: `ci/check_neutron_stage1.py`

**Interfaces:**
- Consumes: no production identity API; the RED tests express the required API.
- Produces: required types `XdpPinnedLinkIdentity`, `XdpLinkHealth`, `XdpLinkHealthReason`, `ExistingXdpPinDisposition`; required functions `classify_xdp_link_identity(...)` and `existing_xdp_pin_disposition(...)`.

- [ ] **Step 1: Declare the focused module**

Add next to the existing agent modules in `agent/src/main.rs`:

```rust
mod xdp_link_health;
```

- [ ] **Step 2: Add test-only RED contracts**

Create `agent/src/xdp_link_health.rs` with only this test module so normal source exists but the Rust test build fails on the deliberately missing production API:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn identity(link_type: u32, link_id: u32, program_id: u32, ifindex: u32) -> XdpPinnedLinkIdentity {
        XdpPinnedLinkIdentity { link_type, link_id, program_id, ifindex }
    }

    #[test]
    fn xdp_link_identity_requires_exact_live_program_and_interface() {
        let health = classify_xdp_link_identity(41, 9, identity(6, 77, 41, 9));
        assert_eq!(health, XdpLinkHealth::VerifiedLive { link_id: 77, program_id: 41, ifindex: 9 });
        assert!(health.is_ready());
    }

    #[test]
    fn xdp_link_identity_rejects_detached_but_pinned_link() {
        assert_eq!(
            classify_xdp_link_identity(41, 9, identity(6, 77, 41, 0)),
            XdpLinkHealth::NotReady(XdpLinkHealthReason::Detached),
        );
    }

    #[test]
    fn xdp_link_identity_rejects_wrong_interface_program_type_and_zero_id() {
        assert_eq!(
            classify_xdp_link_identity(41, 9, identity(6, 77, 41, 10)),
            XdpLinkHealth::NotReady(XdpLinkHealthReason::WrongInterface),
        );
        assert_eq!(
            classify_xdp_link_identity(41, 9, identity(6, 77, 42, 9)),
            XdpLinkHealth::NotReady(XdpLinkHealthReason::WrongProgram),
        );
        assert_eq!(
            classify_xdp_link_identity(41, 9, identity(11, 77, 41, 9)),
            XdpLinkHealth::NotReady(XdpLinkHealthReason::WrongLinkType),
        );
        assert_eq!(
            classify_xdp_link_identity(41, 9, identity(6, 0, 41, 9)),
            XdpLinkHealth::NotReady(XdpLinkHealthReason::InvalidLinkId),
        );
    }

    #[test]
    fn xdp_link_identity_unavailable_evidence_is_never_ready() {
        for reason in [
            XdpLinkHealthReason::MissingProgramPin,
            XdpLinkHealthReason::ProgramUnverifiable,
            XdpLinkHealthReason::MissingLinkPin,
            XdpLinkHealthReason::LinkUnverifiable,
            XdpLinkHealthReason::InterfaceUnverifiable,
        ] {
            assert!(!XdpLinkHealth::NotReady(reason).is_ready());
        }
    }

    #[test]
    fn xdp_link_identity_existing_unverified_pin_is_preserved_not_replaced() {
        assert_eq!(
            existing_xdp_pin_disposition(true, true),
            ExistingXdpPinDisposition::Claim,
        );
        assert_eq!(
            existing_xdp_pin_disposition(false, false),
            ExistingXdpPinDisposition::Attach,
        );
        assert_eq!(
            existing_xdp_pin_disposition(true, false),
            ExistingXdpPinDisposition::PreserveDegraded,
        );
    }
}
```

- [ ] **Step 3: Put the contract in the maintained hosted lane**

Add this entry to `RUST_TESTS` in `ci/check_neutron_stage1.py` next to the existing TC health filters:

```python
    ["test", "--locked", "-p", "aria-agent", "xdp_link_identity_"],
```

- [ ] **Step 4: Verify non-Cargo structure locally**

Run:

```bash
python3 -m unittest ci.test_ci_lane_contract
python3 ci/check_blocked_terms.py
git diff --check
```

Expected: every command exits 0. Do not run Cargo locally.

- [ ] **Step 5: Commit, push, and prove RED in hosted CI**

```bash
git add agent/src/main.rs agent/src/xdp_link_health.rs ci/check_neutron_stage1.py
git commit -m "test: expose path-only XDP link health"
git push origin v0.9-neutron-agent
```

Expected: the exact-head Build reaches `rust-behavior` and fails because the required identity types/functions do not exist. Confirm the failure is limited to the new missing API before continuing; cancel remaining expensive work after RED is captured if needed.

---

### Task 2: GREEN exact pinned-link identity and lifecycle integration

**Files:**
- Modify: `agent/src/xdp_link_health.rs`
- Modify: `agent/src/instance.rs`
- Modify: `agent/src/system_manager.rs`

**Interfaces:**
- Consumes: the Task 1 types/functions and the existing `xdp_firewall`, `xdp_link`, and `<iface>_xdp_link` pin conventions.
- Produces: `exact_xdp_link_health(iface: &str, program_pin: &Path, link_pin: &Path) -> XdpLinkHealth` and conservative startup disposition shared by standalone and managed paths.

- [ ] **Step 1: Implement the pure identity model before the RED tests**

Add above the tests in `agent/src/xdp_link_health.rs`:

```rust
use aya_obj::generated::{bpf_attr, bpf_cmd, bpf_link_info, bpf_link_type};
use std::ffi::CString;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct XdpPinnedLinkIdentity {
    pub(crate) link_type: u32,
    pub(crate) link_id: u32,
    pub(crate) program_id: u32,
    pub(crate) ifindex: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum XdpLinkHealthReason {
    MissingProgramPin,
    ProgramUnverifiable,
    MissingLinkPin,
    LinkUnverifiable,
    WrongLinkType,
    InvalidLinkId,
    Detached,
    InterfaceUnverifiable,
    WrongInterface,
    WrongProgram,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum XdpLinkHealth {
    VerifiedLive { link_id: u32, program_id: u32, ifindex: u32 },
    NotReady(XdpLinkHealthReason),
}

impl XdpLinkHealth {
    pub(crate) fn is_ready(self) -> bool {
        matches!(self, Self::VerifiedLive { .. })
    }

    pub(crate) fn reason(self) -> Option<XdpLinkHealthReason> {
        match self {
            Self::VerifiedLive { .. } => None,
            Self::NotReady(reason) => Some(reason),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ExistingXdpPinDisposition { Attach, Claim, PreserveDegraded }

pub(crate) fn existing_xdp_pin_disposition(pin_exists: bool, verified_live: bool) -> ExistingXdpPinDisposition {
    match (pin_exists, verified_live) {
        (false, _) => ExistingXdpPinDisposition::Attach,
        (true, true) => ExistingXdpPinDisposition::Claim,
        (true, false) => ExistingXdpPinDisposition::PreserveDegraded,
    }
}

pub(crate) fn classify_xdp_link_identity(
    expected_program_id: u32,
    expected_ifindex: u32,
    observed: XdpPinnedLinkIdentity,
) -> XdpLinkHealth {
    if observed.link_type != bpf_link_type::BPF_LINK_TYPE_XDP as u32 {
        return XdpLinkHealth::NotReady(XdpLinkHealthReason::WrongLinkType);
    }
    if observed.link_id == 0 {
        return XdpLinkHealth::NotReady(XdpLinkHealthReason::InvalidLinkId);
    }
    if observed.ifindex == 0 {
        return XdpLinkHealth::NotReady(XdpLinkHealthReason::Detached);
    }
    if observed.ifindex != expected_ifindex {
        return XdpLinkHealth::NotReady(XdpLinkHealthReason::WrongInterface);
    }
    if observed.program_id != expected_program_id {
        return XdpLinkHealth::NotReady(XdpLinkHealthReason::WrongProgram);
    }
    XdpLinkHealth::VerifiedLive {
        link_id: observed.link_id,
        program_id: observed.program_id,
        ifindex: observed.ifindex,
    }
}
```

- [ ] **Step 2: Implement the bounded Linux observation adapter**

In the same module, implement:

```rust
fn sys_bpf(cmd: bpf_cmd, attr: &mut bpf_attr) -> io::Result<i64> {
    let result = unsafe { libc::syscall(libc::SYS_bpf, cmd, attr, size_of::<bpf_attr>()) };
    if result < 0 { Err(io::Error::last_os_error()) } else { Ok(result) }
}

fn open_pinned_bpf_object(path: &Path) -> io::Result<OwnedFd> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "pin path contains NUL"))?;
    let mut attr = unsafe { zeroed::<bpf_attr>() };
    attr.__bindgen_anon_4.pathname = path.as_ptr() as u64;
    let fd = sys_bpf(bpf_cmd::BPF_OBJ_GET, &mut attr)?;
    let raw_fd = i32::try_from(fd)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "BPF_OBJ_GET returned invalid fd"))?;
    Ok(unsafe { OwnedFd::from_raw_fd(raw_fd) })
}

fn read_pinned_link_identity(path: &Path) -> io::Result<XdpPinnedLinkIdentity> {
    let fd = open_pinned_bpf_object(path)?;
    let mut info = unsafe { zeroed::<bpf_link_info>() };
    let mut attr = unsafe { zeroed::<bpf_attr>() };
    attr.info.bpf_fd = fd.as_raw_fd() as u32;
    attr.info.info_len = size_of::<bpf_link_info>() as u32;
    attr.info.info = (&mut info as *mut bpf_link_info) as u64;
    sys_bpf(bpf_cmd::BPF_OBJ_GET_INFO_BY_FD, &mut attr)?;
    let ifindex = if info.type_ == bpf_link_type::BPF_LINK_TYPE_XDP as u32 {
        unsafe { info.__bindgen_anon_1.xdp.ifindex }
    } else {
        0
    };
    Ok(XdpPinnedLinkIdentity {
        link_type: info.type_,
        link_id: info.id,
        program_id: info.prog_id,
        ifindex,
    })
}

fn read_ifindex(iface: &str) -> Result<u32, XdpLinkHealthReason> {
    std::fs::read_to_string(PathBuf::from("/sys/class/net").join(iface).join("ifindex"))
        .ok()
        .and_then(|raw| raw.trim().parse::<u32>().ok())
        .filter(|ifindex| *ifindex != 0)
        .ok_or(XdpLinkHealthReason::InterfaceUnverifiable)
}

pub(crate) fn exact_xdp_link_health(iface: &str, program_pin: &Path, link_pin: &Path) -> XdpLinkHealth {
    if !program_pin.exists() {
        return XdpLinkHealth::NotReady(XdpLinkHealthReason::MissingProgramPin);
    }
    let program = match aya::programs::Xdp::from_pin(
        program_pin,
        aya_obj::programs::XdpAttachType::Interface,
    ) {
        Ok(program) => program,
        Err(_) => return XdpLinkHealth::NotReady(XdpLinkHealthReason::ProgramUnverifiable),
    };
    let expected_program_id = match program.info() {
        Ok(info) => info.id(),
        Err(_) => return XdpLinkHealth::NotReady(XdpLinkHealthReason::ProgramUnverifiable),
    };
    if !link_pin.exists() {
        return XdpLinkHealth::NotReady(XdpLinkHealthReason::MissingLinkPin);
    }
    let observed = match read_pinned_link_identity(link_pin) {
        Ok(observed) => observed,
        Err(_) => return XdpLinkHealth::NotReady(XdpLinkHealthReason::LinkUnverifiable),
    };
    let expected_ifindex = match read_ifindex(iface) {
        Ok(ifindex) => ifindex,
        Err(reason) => return XdpLinkHealth::NotReady(reason),
    };
    classify_xdp_link_identity(expected_program_id, expected_ifindex, observed)
}
```

During implementation, keep the code equivalent to this contract while adapting only compiler-required Aya generated-field syntax. Do not broaden the behavior.

- [ ] **Step 3: Replace `FirewallInstance` path-only health**

Import `exact_xdp_link_health`, `existing_xdp_pin_disposition`, and
`ExistingXdpPinDisposition` in `agent/src/instance.rs`. Add a private detailed
method and retain the existing boolean API:

```rust
fn xdp_link_health_detail(&self) -> XdpLinkHealth {
    exact_xdp_link_health(
        &self.iface,
        Path::new(&self.tc_prog_pin_path("xdp_firewall")),
        Path::new(&self.xdp_link_pin_path()),
    )
}

pub fn xdp_link_health(&self) -> bool {
    self.xdp_link_health_detail().is_ready()
}
```

In `attach_links_from_pinned_runtime()`, replace the path-only claim branch with
the disposition decision. `Claim` sets `ClaimedExisting`; `Attach` calls the
existing attach transaction; `PreserveDegraded` logs the stable health reason
and performs neither claim nor attachment.

- [ ] **Step 4: Apply the same disposition to standalone startup**

In `agent/src/system_manager.rs`, use
`existing_xdp_pin_disposition(xdp_link_preexisting,
preexisting_health.xdp_ready())`:

- `Claim`: keep the current ownership claim;
- `Attach`: execute the existing `attach_xdp_program()` branch;
- `PreserveDegraded`: leave ownership false, preserve the link pin, emit one
  bounded warning, and continue to TC setup.

Do not modify the TCX reuse decision or `system_acl_activation()`.

- [ ] **Step 5: Verify GREEN in hosted CI**

Run only non-Cargo local checks:

```bash
python3 -m unittest ci.test_ci_lane_contract
python3 ci/check_blocked_terms.py
git diff --check
```

Then commit and push:

```bash
git add agent/src/xdp_link_health.rs agent/src/instance.rs agent/src/system_manager.rs
git commit -m "fix: verify exact pinned XDP link identity"
git push origin v0.9-neutron-agent
```

Expected exact-head Build: `fast-contracts`, `rust-behavior`, and warning-denied
`rust-build` succeed. Inspect the test count/output to prove the
`xdp_link_identity_` filter executed nonzero tests.

---

### Task 3: Guarded detached-but-pinned field scenario

**Files:**
- Modify: `deploy/smoke/aria_standalone_acl_tc_datapath_smoke.sh`
- Test: `ci/check_smoke_python_blocks.py`

**Interfaces:**
- Consumes: existing root/bpffs fixture, HTTP instance status, mode-specific XDP link paths, and `bpftool link detach pinned`.
- Produces: opt-in `XDP_IDENTITY_SMOKE=1` evidence plus summary fields `xdp_link_identity.status`, `detached_pin_retained`, `reported_not_ready`, and `tc_acl_independent`.

- [ ] **Step 1: Add explicit field state and input validation**

Default `XDP_IDENTITY_SMOKE=0`. Validate it is exactly `0` or `1`. Initialize
three evidence booleans to false. Disabled execution prints
`SKIP: XDP link identity field smoke disabled` and records `status=skipped`.

- [ ] **Step 2: Add the field action**

When enabled, derive the exact link pin from `MODE`, require initial
`xdp_ready=true` and `acl_ready=true`, detach it with:

```bash
bpftool link detach pinned "${xdp_link}"
test -e "${xdp_link}"
bpftool -j link show pinned "${xdp_link}" >"${WORK_DIR}/xdp-detached-but-pinned.json"
```

After the configured health-poll interval, query the same instance and require:

```python
assert item["xdp_ready"] is False, item
assert item["acl_ready"] is True, item
```

Record each evidence boolean only after its assertion succeeds. Do not label a
disabled or incomplete case passed.

- [ ] **Step 3: Add stable summary output**

Emit:

```json
"xdp_link_identity": {
  "status": "passed|skipped",
  "enabled": true,
  "detached_pin_retained": true,
  "reported_not_ready": true,
  "tc_acl_independent": true
}
```

The summary may use `passed` only when enabled and all three booleans are true.

- [ ] **Step 4: Verify smoke structure without executing privileges**

Run:

```bash
bash -n deploy/smoke/aria_standalone_acl_tc_datapath_smoke.sh
python3 ci/check_smoke_python_blocks.py
python3 ci/check_blocked_terms.py
git diff --check
```

Expected: every command exits 0. No privileged packet or BPF command runs.

- [ ] **Step 5: Commit and push field wiring**

```bash
git add deploy/smoke/aria_standalone_acl_tc_datapath_smoke.sh
git commit -m "test: wire XDP detached-pin field evidence"
git push origin v0.9-neutron-agent
```

Expected exact-head Build: hosted lanes succeed, but the backlog continues to
say the privileged scenario was not executed.

---

### Task 4: Documentation and authoritative register closure

**Files:**
- Modify: `docs/superpowers/specs/2026-08-04-review-ops-036-xdp-link-identity-design.md`
- Modify: `docs/superpowers/plans/2026-08-04-review-ops-036-xdp-link-identity.md`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`

**Interfaces:**
- Consumes: exact RED commit/build, GREEN commit/build, field-wiring commit/build, and current git state.
- Produces: authoritative status `implementation and hosted CI complete; privileged field evidence deferred`.

- [ ] **Step 1: Record exact evidence without overstating field readiness**

Update the design status and OPS-036 register row with:

- RED commit and expected failing Build;
- GREEN implementation commit and exact-head successful Build;
- field-wiring commit and exact-head successful Build;
- identity dimensions proved in hosted behavior;
- explicit statement that no target-kernel detached-pin execution occurred;
- explicit statement that full DDoS readiness still requires attach-mode and
  domain-generation/map validation.

- [ ] **Step 2: Mark every completed plan step accurately**

Change only steps actually evidenced by commits/CI to `[x]`. Leave privileged
field execution outside the hosted completion claim.

- [ ] **Step 3: Run final non-Cargo checks**

```bash
python3 ci/check_blocked_terms.py
python3 -m unittest ci.test_ci_lane_contract
bash -n deploy/smoke/aria_standalone_acl_tc_datapath_smoke.sh
python3 ci/check_smoke_python_blocks.py
git diff --check
```

Expected: every command exits 0.

- [ ] **Step 4: Commit, push, and verify the documentation head**

```bash
git add docs/superpowers/specs/2026-08-04-review-ops-036-xdp-link-identity-design.md \
  docs/superpowers/plans/2026-08-04-review-ops-036-xdp-link-identity.md \
  docs/openstack-neutron-aria-details/12-review-bug-backlog.md
git commit -m "docs: record exact XDP identity delivery"
git push origin v0.9-neutron-agent
```

Expected: exact-head Build succeeds; local and remote `v0.9-neutron-agent`
match; worktree is clean. OPS-036 is no longer an ordinary open source defect,
but privileged field evidence remains deferred and storm/DDoS is not declared
operational.

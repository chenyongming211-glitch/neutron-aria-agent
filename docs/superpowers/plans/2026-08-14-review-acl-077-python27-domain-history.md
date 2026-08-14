# REVIEW-ACL-077 Python 2.7 Domain History Implementation Plan

> Execute inline on the sole `v0.9-neutron-agent` branch. Do not create a
> branch, worktree, PR, or subagent task.

**Goal:** preserve JSON-decoded Unicode domain keys when restoring durable
feature-ready generation history under Python 2.7.

**Architecture:** use the repository-standard `basestring`-compatible text
predicate at the existing `AgentRuntimeStatus` normalization boundary. Prove
the behavior both in the normal unit suite and with real Python 2.7 inside the
existing clean-install container lane.

## Global Constraints

- Follow the approved
  [design](../specs/2026-08-14-review-acl-077-python27-domain-history-design.md).
- Work directly on `v0.9-neutron-agent`; do not create another delivery line.
- Do not run local Cargo commands; this batch contains no Rust change.
- Push RED and GREEN separately and use hosted CI for exact Python 2.7 evidence.
- Do not change state schema, status authority, supported domains, heartbeat
  schema, or feature-ready ownership.
- Do not add source-shape/static parser checks.

---

### Task 1: Add RED Restoration Behaviors

**Files:**

- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_status_reporter.py`
- Modify: `ci/test_neutron_agent_clean_install.sh`

- [x] Add a unit behavior that decodes a durable history through `json.loads`,
  hydrates `AgentRuntimeStatus`, and verifies the exact domain-generation map.
- [x] Include invalid empty/non-text keys through a direct helper input so the
  tolerant filtering contract remains explicit.
- [x] Extend the installed-egg Python 2.7 smoke to assert that `json.loads`
  returns a `unicode` `acl` key and that hydration preserves `{"acl": 42}`.
- [x] Run the focused Python 3 unit test locally.
- [ ] Commit and push RED. Record the expected Python 2.7 clean-install failure.

### Task 2: Implement The Compatibility Boundary

**File:**

- Modify: `openstack/neutron_aria/neutron_aria/agent/status.py`

- [ ] Define `_STRING_TYPES` using `basestring` with a Python 3 `str` fallback.
- [ ] Replace the bare `str` predicate in `_generation_by_domain` with
  `_STRING_TYPES` without changing any other normalization behavior.
- [ ] Run the focused unit test and the relevant fast Python contracts locally.
- [ ] Commit and push GREEN.

### Task 3: Hosted Verification And Closure

**Files:**

- Modify: `docs/superpowers/specs/2026-08-14-review-acl-077-python27-domain-history-design.md`
- Modify: `docs/superpowers/plans/2026-08-14-review-acl-077-python27-domain-history.md`
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`
- Modify: `docs/superpowers/specs/2026-08-13-bug-hunt-remediation-program-design.md`

- [ ] Verify exact-head `fast-contracts` and `neutron-agent-clean-install` pass.
- [ ] Confirm the clean-install log executed the real Python 2.7 Unicode JSON
  assertion rather than skipping it.
- [ ] Record RED and GREEN commit/Build evidence in the design and register.
- [ ] Mark `REVIEW-ACL-077` fixed only after exact-head GREEN.
- [ ] Advance the fixed remediation order to `REVIEW-TXN-033`.

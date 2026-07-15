# ACL Batch 5 Selector Interning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to execute this plan as one bounded task with independent review.

**Goal:** Remove the remaining ACL validation memory/CPU amplification by storing each canonical selector once and proving cross-selector overlap with a global interval sweep, while preserving all approved Batch 5 behavior and failure semantics.

**Architecture:** Python and Rust independently intern source and destination selectors. Selector ID `0` means `any`; deterministic positive IDs refer to unique non-empty canonical selector vectors. Validation rules carry selector IDs rather than owned CIDR vectors. A per-side interval sweep rejects overlap between distinct non-zero selector IDs in `O(T log T)` CIDR work, permits overlap within one selector, and leaves the bounded rule-pair pass with ID/behavior comparisons only. Rust validated templates retain the selector tables so port-specific group rendering remains deterministic and snapshot-cacheable.

**Tech Stack:** Python 2/3-compatible OpenStack adapter code, Rust standard collections, GitHub Actions.

## Constraints

- Preserve the runtime-only ACL validation boundary and priority-independent datapath semantics.
- Preserve strict IPv4 CIDR parsing, the `1000/2048` limits, Python policy compile caching, Rust snapshot validation caching, force-bypass behavior, outcome reporting, and failure phases.
- Preserve stable overlap reasons by mapping a conflicting selector-ID pair back to the first priority/ID-ordered rule pair.
- Keep source and destination selector ID spaces independent.
- Do not add Neutron API quota validation, numeric priority scanning, IPv6, QoS, Mirror, source-port, default-deny, or new datapath features.
- Do not change `PolicyKey`, `PolicyValue`, conntrack, WAL, or eBPF layouts.
- Do not run local `cargo build`, `cargo check`, or `cargo test`; GitHub Actions is the Rust authority.
- Work only on `codex/acl-batch-5-selector-interning` in `/private/tmp/aria-firewall-acl-batch5-rust-red`; do not modify or push the main checkout's external commit or dirty `README.md`.
- One implementation agent owns this complete task and creates separate RED, GREEN, and closure commits.

## File Map

| File | Responsibility |
| --- | --- |
| `openstack/neutron_aria/neutron_aria/agent/effective_acl.py` | Python selector interning, interval sweep, and ID-only pair validation. |
| `openstack/neutron_aria/neutron_aria/tests/unit/test_effective_acl.py` | Python storage, sweep, stable-reason, and boundary regressions. |
| `agent/src/neutron_api.rs` | Rust selector tables, ID-only normalized rules, interval sweep, cached rendering, and Rust tests. |
| `docs/superpowers/specs/2026-07-12-acl-batch-5-final-review-hardening-design.md` | Final implementation and CI evidence. |

---

### Task 1: Replace Pair-Owned Selectors with Interned Selector Tables

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/agent/effective_acl.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_effective_acl.py`
- Modify: `agent/src/neutron_api.rs`
- Modify: `docs/superpowers/specs/2026-07-12-acl-batch-5-final-review-hardening-design.md`

**Required interfaces and invariants:**

- Python compilation maintains independent `src_selectors` and `dst_selectors` tables and stores `src_selector_id` / `dst_selector_id` in its validation view.
- Rust `AclValidatedTemplate::Ready` retains ID-only normalized rules plus independent source/destination selector tables.
- Selector ID `0` is `any`; the first non-empty selector is ID `1`, while rendered group ordinals remain zero-based so existing names such as `neutron:<port>:src:selector:0` do not change.
- Selector interning keys are canonical immutable vectors; no pair cache owns copied CIDR vectors.
- The interval sweep flattens `(start, end, selector_id)`, sorts deterministically, expires intervals where `end < start`, tracks active selector counts, and returns a deterministic pair when another active selector ID exists.
- Internal nesting or overlap between members of the same selector is accepted.
- After both side sweeps pass, ID equality means identical, ID `0` means any/intersecting, and distinct non-zero IDs mean disjoint.

- [ ] **Step 1: Add Python RED tests**

Add focused tests that require:

1. One 2048-member selector shared by 1000 rules is interned once and all rules reference the same ID.
2. 1000 mutually disjoint selectors are accepted without a selector-pair relation cache.
3. Nested CIDRs in two different selectors are rejected with the existing stable rule-ID/priority reason.
4. Nested CIDRs inside one shared selector remain valid.
5. Identical source and destination selector text receives IDs from independent registries.
6. Public `effective_for_port` DTOs remain unchanged and defensive-copy behavior still holds.

Expose only the smallest private helper/result seam needed for structural assertions; do not weaken the public boundary.

- [ ] **Step 2: Record Python RED evidence**

Run:

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest \
  neutron_aria.tests.unit.test_effective_acl
```

Expected: new tests fail only because selector tables, IDs, and the sweep are absent. Commit tests only:

```bash
git add openstack/neutron_aria/neutron_aria/tests/unit/test_effective_acl.py
git commit -m "test: require interned ACL selector validation"
```

- [ ] **Step 3: Implement Python selector interning and sweep**

Add deterministic interning with ID `0` reserved for `any`. Build an ID-only validation view plus independent selector tables during policy compilation. Replace `_selector_relation` and its owned tuple-pair cache with a per-side heap sweep using `heapq` and active counts. Map a detected selector pair back to the first conflicting pair from the existing priority/ID-ordered rules so user-visible reasons remain stable. Preserve the compiled DTO, compile cache, limits, and defensive copies.

- [ ] **Step 4: Verify and commit Python GREEN**

Run the focused module, the full Python suite, Stage 1, and Stage 2:

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest \
  neutron_aria.tests.unit.test_effective_acl
PYTHONPATH=openstack/neutron_aria python3 -m unittest discover \
  -s openstack/neutron_aria/neutron_aria/tests -p 'test_*.py'
python3 ci/check_neutron_stage1.py
python3 ci/check_neutron_stage2_acl.py
git diff --check
```

Commit production code separately:

```bash
git add openstack/neutron_aria/neutron_aria/agent/effective_acl.py
git commit -m "fix: intern Python ACL selectors"
```

- [ ] **Step 5: Add Rust RED tests**

Add Rust unit tests that require:

1. `NormalizedAclRule` contains selector IDs rather than owned source/destination vectors.
2. A large selector shared by 1000 normalized rules is stored once in the validated template.
3. A large set of disjoint selectors passes the sweep.
4. Cross-selector nesting is rejected with the stable overlap reason.
5. Same-selector internal nesting is accepted.
6. Source/destination ID spaces are independent.
7. Cached validated templates still render port-specific groups and rules with unchanged group names.

Keep scale assertions structural where possible; do not construct pair-owned 1000-by-2048 fixtures.

- [ ] **Step 6: Record Rust RED in GitHub Actions**

Commit and push the isolated branch, then dispatch the existing Build workflow. Do not run Cargo locally.

```bash
git add agent/src/neutron_api.rs
git commit -m "test: require interned Rust ACL selectors"
git push -u origin codex/acl-batch-5-selector-interning
gh workflow run build.yml --ref codex/acl-batch-5-selector-interning
```

Expected: the `neutron_acl_` Rust filter fails for missing selector-table/ID/sweep behavior while unrelated jobs remain healthy. Record the run URL and exact expected failure.

- [ ] **Step 7: Implement Rust selector tables and interval sweep**

Introduce a small selector ID type and independent deterministic interning tables. Change normalized validation rules to store only source/destination IDs. Change `AclValidatedTemplate::Ready` to retain rules plus both selector tables. Implement a deterministic per-side sweep using sorted intervals, a min-end heap (for example `BinaryHeap<Reverse<...>>`), and active counts. Remove the owning selector-relation memo. Keep the final rule-pair scan ID/behavior-only, preserve stable reasons, and render port-specific groups by resolving IDs through the retained selector tables.

- [ ] **Step 8: Verify and commit Rust GREEN**

Run only allowed local static checks:

```bash
python3 ci/check_neutron_stage1.py
python3 ci/check_neutron_stage2_acl.py
git diff --check
```

Commit and push:

```bash
git add agent/src/neutron_api.rs
git commit -m "fix: intern Rust ACL selectors"
git push origin codex/acl-batch-5-selector-interning
gh workflow run build.yml --ref codex/acl-batch-5-selector-interning
```

Require the full Build workflow, including `neutron_acl_` and eBPF/static jobs, to pass.

- [ ] **Step 9: Refresh bounded closure evidence**

Update only the final-review hardening design with implementation commits, Python counts, RED/GREEN Build run URLs, complexity/storage guarantees, and the explicit runtime-only boundary. Do not edit the backlog, original priority design, or product design while the main checkout carries the conflicting external semantic-unification commit.

Run:

```bash
python3 ci/check_neutron_stage1.py
python3 ci/check_neutron_stage2_acl.py
git diff --check
```

Commit and push:

```bash
git add docs/superpowers/specs/2026-07-12-acl-batch-5-final-review-hardening-design.md
git commit -m "docs: close ACL selector interning hardening"
git push origin codex/acl-batch-5-selector-interning
```

- [ ] **Step 10: Independent review and final verification**

Review both the implementation delta and the complete isolated branch range from `f5d59b1` to `HEAD`. Confirm:

- no selector vectors are copied into pair-cache keys or per-rule normalized state;
- CIDR sweep cost is `O(T log T)` and memory is proportional to rules plus unique selector members;
- the remaining maximum 499,500 rule pairs perform ID/behavior comparisons only;
- public DTOs, reasons, group names, limits, cache scopes, force-bypass, and failure classification are unchanged;
- no forbidden Cargo command or out-of-scope file change occurred;
- final GitHub Actions Build is green.

If review finds an issue, add a focused regression test first, fix it, rerun the relevant verification, and obtain a clean re-review before declaring completion.

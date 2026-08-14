# REVIEW-ACL-085/090/091 Neutron Event And Client Correctness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ensure every drained Neutron ACL event converges through an immediate authoritative resync after delete failure, reject truncated port pagination, and issue every ACL status POST/DELETE at most once.

**Architecture:** Keep the three repairs inside their existing public boundaries. `AgentService` reuses `safe_full_resync()` as the sole authority recovery path; `NeutronPortSource` matches the strict pagination contract already used by `AriaAclRestClient`; and `AriaAclPortStatusReporter` uses an explicit construction-time adapter style instead of exception-driven side-effect probing.

**Tech Stack:** Python 2.7-compatible agent code, `unittest`, GitHub Actions fast contracts and clean-install lane.

## Global Constraints

- Work only on `v0.9-neutron-agent`; do not create a branch, worktree, or PR.
- Do not modify QoS, Mirror, TCP-RT, generic trace/drop monitoring, or Rust/eBPF code.
- Preserve current Neutron snapshot, heartbeat, pagination, and port-status payload schemas.
- Do not re-enqueue a drained event batch; use the existing authoritative full-resync path.
- Do not catch `TypeError` around any POST or DELETE and then retry that side effect.
- Keep production Python compatible with the target Python 2.7 Neutron runtime.
- Do not run local Cargo commands. Hosted CI remains authoritative for clean install.

---

### Task 1: Add RED Behavior Tests

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_service.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_neutron_client.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_acl_source.py`
- Modify: `openstack/neutron_aria/neutron_aria/tests/unit/test_status_reporter.py`

**Interfaces:**
- Consumes: `AgentService.run_once`, `NeutronPortSource.list_ports_for_host`, `AriaAclRestClient.report_aria_acl_port_status`, and `AriaAclPortStatusReporter` public behavior.
- Produces: deterministic RED evidence for both delete-failure positions, both unusable pagination-marker forms, and every exception-driven status-write retry.

- [x] **Step 1: Add delete-failure convergence tests**

Extend the service fake with a configured set of failing delete IDs. Its
`delete_port` must record the attempted ID before raising so tests can prove the
real side effect was attempted once.

Add one test whose drained batch contains a failing `deleted_ports` item, a
port update, and a dirty network. Assert:

```python
self.assertEqual(2, sync.resync_calls)  # initialize plus immediate recovery
self.assertTrue(result["resync_attempted"])
self.assertEqual(["update-1"], result["events"]["port_updates"])
self.assertEqual(["network-1"], result["events"]["dirty_networks"])
self.assertIn("delete-1", result["events"]["delete_errors"][0])
```

Add a second test for a foreign-host port update whose decision is
`delete_local` and whose delete fails while another update/dirty network is in
the same batch. Assert the same immediate full-resync and retained event
observability behavior.

- [x] **Step 2: Add strict host-port pagination tests**

In `test_neutron_client.py`, add:

```python
def test_port_source_rejects_empty_page_with_next_link(self):
    client = FakeNeutronClient([{
        "ports": [],
        "ports_links": [{"rel": "next", "href": "?marker=missing"}],
    }])
    with self.assertRaises(PortSourceUnavailable):
        NeutronPortSource(client, "compute-1", page_size=1).list_ports_for_host()
```

Add the equivalent non-empty page whose last port lacks `id`. A terminal empty
page without a next link must remain valid.

- [x] **Step 3: Add exactly-once POST and DELETE tests**

Add a fake neutronclient `post()` that increments a counter and raises
`TypeError("response decode failed")` from inside the method. Calling
`AriaAclRestClient.report_aria_acl_port_status()` must raise that exact error
with counter `1`.

Add context-style status API fakes whose report and delete methods accept
`*args`, increment a counter, then raise the same `TypeError`. The reporter must
call each method once. Add one payload-style fake with the explicit adapter
style marker and assert report/delete receive no context argument.

- [x] **Step 4: Run focused RED tests**

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest \
  neutron_aria.tests.unit.test_service \
  neutron_aria.tests.unit.test_neutron_client \
  neutron_aria.tests.unit.test_acl_source \
  neutron_aria.tests.unit.test_status_reporter
```

Expected: only the new tests fail. Old code does not resync after either delete
failure, accepts both incomplete host-port pages, and invokes the TypeError
fakes twice.

- [x] **Step 5: Commit and push RED**

```bash
git add \
  openstack/neutron_aria/neutron_aria/tests/unit/test_service.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_neutron_client.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_acl_source.py \
  openstack/neutron_aria/neutron_aria/tests/unit/test_status_reporter.py
git commit -m "test: expose Neutron ACL event and client loss"
git push origin v0.9-neutron-agent
```

Capture exact failing test names from fast-contracts. Cancel unrelated Rust
jobs only after the required RED evidence is complete.

---

### Task 2: Converge Drained Events After Delete Failure

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/agent/service.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_service.py`

**Interfaces:**
- Consumes: existing `safe_full_resync`, runtime degraded status, event-decision observability, and resync backoff handling.
- Produces: `_resync_after_delete_failure(batch_dict, delete_errors)` returning the normal resync result with `events` and `resync_attempted=True`.

- [x] **Step 1: Add one concrete failure-convergence helper**

Add a private helper on `AgentService`:

```python
def _resync_after_delete_failure(self, batch_dict, delete_errors):
    errors = [str(error) for error in delete_errors]
    batch_dict["delete_errors"] = errors
    self._record_event_observability(batch_dict["decisions"])
    self.synchronizer.runtime_status.mark_degraded(
        DELETE_PORT_DEGRADED_REASON,
        "; ".join(errors),
    )
    result = self.synchronizer.safe_full_resync()
    result["events"] = batch_dict
    result["resync_attempted"] = True
    return result
```

The helper does not synthesize snapshot/status fields. `safe_full_resync()`
remains their owner.

- [x] **Step 2: Route both delete-failure positions through the helper**

Replace the early heartbeat-only return after `_delete_known_ports()` errors
with the helper. In the `ACTION_DELETE_LOCAL` exception branch, attach the
exact error to the decision and invoke the same helper:

```python
decision["delete_error"] = str(exc)
return self._resync_after_delete_failure(
    batch_dict,
    ["%s:%s" % (port_id, exc)],
)
```

- [x] **Step 3: Run service tests**

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest \
  neutron_aria.tests.unit.test_service
```

Expected: all service tests pass, including both new delete-failure cases.

---

### Task 3: Reject Incomplete Host-Port Pagination

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/agent/neutron_client.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_neutron_client.py`

**Interfaces:**
- Consumes: `_extract_ports_and_next` and existing `PortSourceUnavailable`.
- Produces: complete-or-error host-port inventory semantics matching the ACL resource client.

- [x] **Step 1: Separate terminal completion from invalid continuation**

Replace the combined `not has_next or not batch` break:

```python
if not has_next:
    break
if not batch:
    raise PortSourceUnavailable(
        "neutron port response has a next page but no pagination marker"
    )
next_marker = batch[-1].get("id")
if not next_marker:
    raise PortSourceUnavailable(
        "neutron port response has a next page but no pagination marker"
    )
```

Keep repeated-marker and maximum-page checks after this validation.

- [x] **Step 2: Run client tests**

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest \
  neutron_aria.tests.unit.test_neutron_client
```

Expected: all host-port pagination tests pass.

---

### Task 4: Make ACL Status Writes Exactly Once

**Files:**
- Modify: `openstack/neutron_aria/neutron_aria/agent/neutron_client.py`
- Modify: `openstack/neutron_aria/neutron_aria/agent/status_reporter.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_acl_source.py`
- Test: `openstack/neutron_aria/neutron_aria/tests/unit/test_status_reporter.py`

**Interfaces:**
- Consumes: repository-owned `AriaAclRestClient`, direct context-style plugin APIs, and the existing reporter payload builders.
- Produces: class marker `ARIA_ACL_STATUS_CALL_STYLE = "payload"` and one stored reporter call style selected before any side effect.

- [x] **Step 1: Declare the repository-owned adapter contract**

Add this class attribute to `AriaAclRestClient`:

```python
ARIA_ACL_STATUS_CALL_STYLE = "payload"
```

Call the underlying production neutronclient POST once with `body=body` and
remove its `except TypeError` retry. DELETE already has one canonical call and
remains unchanged.

- [x] **Step 2: Resolve reporter style during construction**

Add constants in `status_reporter.py`:

```python
ARIA_ACL_STATUS_CALL_CONTEXT = "context"
ARIA_ACL_STATUS_CALL_PAYLOAD = "payload"
```

In `AriaAclPortStatusReporter.__init__`, read
`ARIA_ACL_STATUS_CALL_STYLE` from the API. Repository-owned adapters explicitly
select payload style; direct plugin APIs default to context style. Reject any
other marker with `StatusReportError` before a report or delete can occur.

- [x] **Step 3: Remove exception-driven status retries**

Dispatch once from `_report_one` and `_delete_one`:

```python
if self.api_call_style == ARIA_ACL_STATUS_CALL_PAYLOAD:
    return method(payload)
return method(self.context, body)
```

Use `(port_id, host)` for payload-style delete and
`(context, port_id, host=host)` for context-style delete. Do not catch
`TypeError` around either call.

- [x] **Step 4: Run status/client tests**

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest \
  neutron_aria.tests.unit.test_acl_source \
  neutron_aria.tests.unit.test_status_reporter
```

Expected: all tests pass; response-processing `TypeError` fakes show one call.

---

### Task 5: Verify GREEN, Commit, And Close Documentation

**Files:**
- Modify: `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`
- Modify: `docs/superpowers/specs/2026-08-14-acl-only-remaining-remediation-design.md`
- Modify: this plan

**Interfaces:**
- Consumes: exact RED and GREEN commit/Build/job IDs.
- Produces: fixed Register rows for `REVIEW-ACL-085/090/091` without changing excluded-item status.

- [x] **Step 1: Run full allowed Python verification**

```bash
PYTHONPATH=openstack/neutron_aria python3 -m unittest \
  neutron_aria.tests.unit.test_service \
  neutron_aria.tests.unit.test_neutron_client \
  neutron_aria.tests.unit.test_acl_source \
  neutron_aria.tests.unit.test_status_reporter
python3 -m py_compile \
  openstack/neutron_aria/neutron_aria/agent/service.py \
  openstack/neutron_aria/neutron_aria/agent/neutron_client.py \
  openstack/neutron_aria/neutron_aria/agent/status_reporter.py
git diff --check
```

Expected: every executed test passes and both static commands exit zero.

- [x] **Step 2: Commit and push GREEN**

```bash
git add \
  openstack/neutron_aria/neutron_aria/agent/service.py \
  openstack/neutron_aria/neutron_aria/agent/neutron_client.py \
  openstack/neutron_aria/neutron_aria/agent/status_reporter.py
git commit -m "fix: preserve Neutron ACL event and write authority"
git push origin v0.9-neutron-agent
```

Require exact-head fast-contracts and clean install. Database contracts may run
and must pass. Rust jobs should skip because no Rust-relevant file changed.

- [x] **Step 3: Record exact evidence and advance to fragment attribution**

Mark only `REVIEW-ACL-085/090/091` fixed. Record RED/GREEN commit and job links,
the immediate-resync contract, pagination failure semantics, and exactly-once
write behavior. Keep every excluded non-ACL item at its prior status. Change
the ACL-only design active batch to `REVIEW-ACL-098/099`.

- [ ] **Step 4: Commit, push, and require final documentation-head CI**

```bash
git add docs
git commit -m "docs: close Neutron ACL event and client correctness"
git push origin v0.9-neutron-agent
```

Wait for exact documentation-head CI, then require a clean worktree and `0 0`
local/remote divergence.

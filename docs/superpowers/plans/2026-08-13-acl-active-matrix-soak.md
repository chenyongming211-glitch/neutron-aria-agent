# ACL Active Matrix Soak Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and run a three-compute, bidirectional ACL acceptance soak that repeatedly proves ICMP, TCP, and UDP enforcement, mutation, rollback, status identity, and cleanup on dedicated Neutron ports.

**Architecture:** A Python 2/3 nonce echo utility provides trustworthy TCP and UDP verdicts. A node-local shell runner owns one VM port and one ACL case atomically; a cluster scheduler provisions one CirrOS VM per compute and runs cases serially across nodes so cleanup and evidence remain attributable.

**Tech Stack:** Bash, Python 2.7/3 standard library, legacy `neutron`/`nova` CLI, Neutron `aria_acl` API, Docker/Kolla, existing CirrOS Go listener.

## Global Constraints

- Use one dedicated CirrOS test VM on each target compute; never reuse fixed-soak ports.
- Do not restart or modify OVS, the Neutron OVS agent, or the Rust datapath.
- Do not compile Rust or eBPF locally; this plan requires no Rust/eBPF build.
- Keep `incremental_rpc_enabled` unchanged and exercise the currently deployed RPC/full-resync mode.
- Run active cases serially; a one-minute scheduler tick must skip while a prior case is active.
- The overnight run is controlled entirely from the designated controller compute; it must not depend on the workstation or an interactive SSH session remaining connected.
- Launch through a named `systemd-run` transient service with no automatic restart on assertion failure.
- Use `default_action=allow`; unsupported defaults and fields are negative API/CLI tests only.
- Treat the current stateful implementation as lightweight five-tuple, reply-seen, timeout-based tracking, not a strict TCP state machine.
- Never write credentials, tokens, passwords, raw environment files, or internal endpoint URLs into tracked evidence.
- Failure stops only the active-matrix gate, preserves evidence, and performs best-effort owned-resource cleanup; existing runtime, fixed-policy, and disabled-binding churn soaks continue.
- Delete all dedicated VMs, listeners, policies, rules, bindings, status rows, and runtime target files after the gate.

## File Structure

| File | Responsibility |
| --- | --- |
| `deploy/kolla/smoke/neutron_aria_acl_nonce_echo.py` | TCP/UDP nonce echo server and probe oracle, Python 2/3 compatible. |
| `deploy/kolla/smoke/neutron_aria_cirros_guest_exec.py` | Password-file based CirrOS command execution without logging credentials. |
| `ci/test_neutron_aria_acl_nonce_echo.py` | Local deterministic unit/integration tests for both protocols and timeout behavior. |
| `deploy/kolla/smoke/neutron_aria_acl_active_matrix_case.sh` | Own one port, one policy, one case, status waits, traffic assertions, mutation, and cleanup. |
| `ci/test_neutron_aria_acl_active_matrix_case.sh` | Stubbed contract tests for validation, ordering, status identity, no-overlap, and cleanup. |
| `deploy/kolla/smoke/neutron_aria_acl_active_matrix_soak.sh` | Provision three VMs, prepare listeners, schedule node/case work, collect evidence, and remove resources. |
| `ci/test_neutron_aria_acl_active_matrix_soak.sh` | Stubbed provisioning/scheduling/failure tests and sensitive-output checks. |
| `ci/check_neutron_stage2_acl.py` | Makes the new scripts and contract tests part of the maintained ACL gate. |
| `docs/openstack-neutron-aria-details/06-deployment-n05-runbook.md` | Operator entry, required inputs, execution, failure, and cleanup semantics. |

---

### Task 1: Deterministic TCP And UDP Nonce Oracle

**Files:**
- Create: `deploy/kolla/smoke/neutron_aria_acl_nonce_echo.py`
- Create: `ci/test_neutron_aria_acl_nonce_echo.py`

**Interfaces:**
- Consumes: `serve <tcp|udp> <bind-ip> <port> <ready-file>` and `probe <tcp|udp> <host> <port> <nonce> <timeout-seconds>` CLI arguments.
- Produces: exit `0` only when the exact nonce is echoed; exit `2` for timeout/mismatch; a ready file created only after bind succeeds.

- [ ] **Step 1: Write failing protocol tests**

Create tests that start an ephemeral TCP or UDP server, probe with a unique nonce, verify exact echo, verify a closed port fails, and verify invalid protocol/port input fails without creating a ready file:

```python
class NonceEchoTests(unittest.TestCase):
    def test_tcp_exact_nonce(self):
        self.assertEqual(0, self.run_round_trip("tcp", "tcp-%s" % uuid.uuid4()))

    def test_udp_exact_nonce(self):
        self.assertEqual(0, self.run_round_trip("udp", "udp-%s" % uuid.uuid4()))

    def test_closed_port_is_not_reachable(self):
        result = self.run_probe("udp", self.unused_port(), "must-not-return", 0.2)
        self.assertEqual(2, result.returncode)

    def test_invalid_port_fails_before_ready(self):
        result = self.run_server("tcp", 0, self.ready_file)
        self.assertNotEqual(0, result.returncode)
        self.assertFalse(os.path.exists(self.ready_file))
```

- [ ] **Step 2: Run the tests and verify the missing helper failure**

Run:

```bash
python ci/test_neutron_aria_acl_nonce_echo.py -v
```

Expected: FAIL because `deploy/kolla/smoke/neutron_aria_acl_nonce_echo.py` does not exist.

- [ ] **Step 3: Implement the minimal Python 2/3 oracle**

Implement strict argument parsing, bounded socket timeouts, `SO_REUSEADDR`, atomic ready-file creation, signal-aware shutdown, and exact payload comparison. Keep the wire payload below 256 bytes:

```python
def probe(protocol, host, port, nonce, timeout):
    payload = nonce.encode("utf-8")
    sock_type = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    sock = socket.socket(socket.AF_INET, sock_type)
    sock.settimeout(timeout)
    try:
        if protocol == "tcp":
            sock.connect((host, port))
            sock.sendall(payload)
            received = recv_exact(sock, len(payload))
        else:
            sock.sendto(payload, (host, port))
            received, peer = sock.recvfrom(512)
            if peer[0] != socket.gethostbyname(host):
                return False
        return received == payload
    except (IOError, OSError, socket.timeout):
        return False
    finally:
        sock.close()
```

The server must echo only the received bytes and must never interpret them as commands.

- [ ] **Step 4: Run local oracle tests**

Run:

```bash
python ci/test_neutron_aria_acl_nonce_echo.py -v
python -m py_compile deploy/kolla/smoke/neutron_aria_acl_nonce_echo.py
```

Expected: all tests PASS and `py_compile` exits `0`.

- [ ] **Step 5: Commit the oracle**

```bash
git add deploy/kolla/smoke/neutron_aria_acl_nonce_echo.py ci/test_neutron_aria_acl_nonce_echo.py
git commit -m "test(acl): add deterministic TCP UDP nonce oracle"
```

### Task 2: Atomic Node-Local Active ACL Case Runner

**Files:**
- Create: `deploy/kolla/smoke/neutron_aria_acl_active_matrix_case.sh`
- Create: `ci/test_neutron_aria_acl_active_matrix_case.sh`

**Interfaces:**
- Consumes required environment: `CASE_ID`, `VM_IP`, `PORT_ID`, `IFNAME`, `EXPECTED_HOST`, `DIRECTION`, `PROTOCOL`, `STATEFUL`, `SELECTOR_KIND`, `MATCH_PORT_MIN`, `MATCH_PORT_MAX`, `NONMATCH_PORT`, `EGRESS_TARGET_IP`, `GUEST_EXEC_FILE`, `WORK_DIR`.
- Consumes optional environment: `CONVERGENCE_TIMEOUT=30`, `QUIET_SECONDS=5`, `ADMIN_RC_FILE=/etc/kolla/.adminrc`, `LOCAL_NEUTRON_URL=http://127.0.0.1:9696/v2.0`, `NONCE_ECHO=./neutron_aria_acl_nonce_echo.py`.
- `GUEST_EXEC_FILE` is an executable runtime-only wrapper accepting one guest command on stdin; it obtains credentials externally and never prints them.
- Produces: `result.json`, `events.tsv`, API responses, traffic verdicts, status snapshots, heartbeat snapshots, cleanup inventory, and exit `0` only after complete rollback.

- [ ] **Step 1: Write failing shell contract tests**

Build temporary `docker`, `curl`, `ping`, and guest-exec stubs. Assert the runner:

```bash
assert_fails env -u PORT_ID bash "${CASE_SCRIPT}"
assert_fails env DIRECTION=sideways "${complete_env[@]}" bash "${CASE_SCRIPT}"
assert_fails env PROTOCOL=gre "${complete_env[@]}" bash "${CASE_SCRIPT}"
assert_order "binding-delete" "rule-delete" "policy-delete" "${CALL_LOG}"
assert_contains '"effective_policy_id":"policy-1"' "${WORK_DIR}/status-ready.json"
assert_contains '"binding_id":"binding-1"' "${WORK_DIR}/status-ready.json"
assert_contains 'cleanup_complete' "${WORK_DIR}/events.tsv"
```

Include a forced traffic mismatch and a forced status-host mismatch; both must fail and still delete owned objects in dependency order.

- [ ] **Step 2: Run the contract test and verify the missing runner failure**

Run:

```bash
bash ci/test_neutron_aria_acl_active_matrix_case.sh
```

Expected: FAIL because the case runner does not exist.

- [ ] **Step 3: Implement strict input and ownership handling**

Add enum/numeric validation before authentication or mutation. Keep owned IDs in an append-only file and trap `EXIT INT TERM`:

```bash
record_owned() { printf '%s\t%s\n' "$1" "$2" >>"${WORK_DIR}/owned.tsv"; }

cleanup_owned() {
    set +e
    reverse_ids binding | while read -r id; do api_delete "aria-acl-bindings/${id}"; done
    reverse_ids rule | while read -r id; do api_delete "aria-acl-rules/${id}"; done
    reverse_ids policy | while read -r id; do api_delete "aria-acl-policies/${id}"; done
    assert_no_owned_objects && event cleanup_complete pass
}

trap 'rc=$?; cleanup_owned; exit $rc' EXIT INT TERM
```

Never delete by name prefix alone; delete only IDs recorded by this process.

- [ ] **Step 4: Implement status, heartbeat, and traffic oracles**

Wait for a row matching all identities, not merely the first ready row:

```python
matching = [row for row in rows
            if row.get("port_id") == port_id
            and row.get("host") == expected_host
            and row.get("effective_policy_id") == policy_id
            and row.get("binding_id") == binding_id
            and row.get("status") == "ready"
            and row.get("runtime_status") == "ready"
            and row.get("effective_action") == "enforce"
            and not row.get("stale")]
if len(matching) != 1:
    raise SystemExit("expected exactly one current ready/enforce status row")
```

For allow verdicts require exact nonce echo or successful bounded ICMP. For drop verdicts require at least three consecutive nonce timeouts or ICMP failures while a separately selected non-matching flow succeeds. Capture `ready`, `degraded`, `generation_lag`, accepted/applied generation, and sync mode from heartbeat before and after mutation.

- [ ] **Step 5: Implement the policy and mutation sequence**

Create one `default_action=allow` policy with the requested `stateful` value, one drop rule, and one enabled port binding. Use destination-port selectors only for TCP/UDP. Execute this exact sequence:

```text
baseline matching allow
baseline non-matching allow
create policy/rule/binding
wait exact ready/enforce identity
matching drop x3
non-matching allow
update selector; old allow; new drop
rule disable; matching allow
rule enable; matching drop
binding disable; all allow; status bypass/not_requested
binding enable; matching drop; exact identity restored
policy disable; all allow
policy enable; matching drop
delete binding/rule/policy
all baseline flows allow
no owned object or active projection remains
```

For stateful TCP, establish a connection before the selector update and record whether the publication epoch invalidates the old flow according to the current contract. For stateless cases, open a fresh connection for every verdict and verify no prior reply state changes the result.

- [ ] **Step 6: Run contract and syntax tests**

Run:

```bash
bash -n deploy/kolla/smoke/neutron_aria_acl_active_matrix_case.sh
bash ci/test_neutron_aria_acl_active_matrix_case.sh
python ci/test_neutron_aria_acl_nonce_echo.py -v
```

Expected: all commands PASS.

- [ ] **Step 7: Commit the atomic runner**

```bash
git add deploy/kolla/smoke/neutron_aria_acl_active_matrix_case.sh ci/test_neutron_aria_acl_active_matrix_case.sh
git commit -m "test(acl): add atomic active matrix case runner"
```

### Task 3: Three-Compute Provisioning And Serialized Scheduler

**Files:**
- Create: `deploy/kolla/smoke/neutron_aria_acl_active_matrix_soak.sh`
- Create: `ci/test_neutron_aria_acl_active_matrix_soak.sh`

**Interfaces:**
- Consumes required runtime-only files: `TARGETS_FILE` and `GUEST_PASSWORD_FILE`.
- `TARGETS_FILE` rows are tab-separated: `<alias> <nova-az-host> <ssh-host> <egress-ip>`; aliases must be public-safe and unique.
- Consumes required environment: `IMAGE_ID`, `NETWORK_ID`, `FLAVOR_ID`, `DEADLINE_EPOCH`, `TARGETS_FILE`, `GUEST_PASSWORD_FILE`.
- Consumes optional environment: `SCHEDULER_INTERVAL=60`, `CASE_TIMEOUT=420`, `REMOTE_ROOT=/var/tmp/aria-acl-active-matrix`, `WORK_DIR=/var/tmp/aria-acl-active-matrix-<run-id>`.
- Produces: one manifest, one node/case result directory, `metrics.tsv`, `summary.json`, `exit-code`, and `complete` marker.
- Produces an atomic `checkpoint.json` after every scheduler decision and case transition, including `updated_at`, `phase`, `node_alias`, `case_id`, `cycle`, and `last_result`.

- [ ] **Step 1: Write failing scheduler contract tests**

Stub `docker exec openstack_client`, `ssh`, `scp`, `date`, and `sleep`. Cover:

```bash
assert_fails env TARGETS_FILE=missing bash "${SOAK_SCRIPT}"
assert_eq 3 "$(count_calls nova-boot "${CALL_LOG}")"
assert_no_parallel_cases "${CALL_LOG}"
assert_recorded skipped_active_tick "${EVENTS}"
assert_order binding-delete nova-delete "${CALL_LOG}"
assert_eq 3 "$(count_calls nova-delete "${CALL_LOG}")"
assert_no_secret "${PASSWORD_VALUE}" "${WORK_DIR}"
```

Also force the second node's first case to fail. The scheduler must stop new cases, clean all three VMs, preserve the first node result and failed-node result, and leave no `complete` marker.

- [ ] **Step 2: Run the scheduler test and verify the missing script failure**

Run:

```bash
bash ci/test_neutron_aria_acl_active_matrix_soak.sh
```

Expected: FAIL because the scheduler does not exist.

- [ ] **Step 3: Implement preflight and dedicated VM provisioning**

Preflight before creating a VM:

```text
exactly three unique target rows
deadline is in the future
password file mode has no group/other bits
image, network, and flavor exist
all target computes are enabled/up
all three Aria heartbeats are alive, ready, non-degraded, generation_lag=0
node-local case runner, nonce helper, and CirrOS listener tool exist
host target ports 1 and 18080-18082 are free; the harness never kills a
  listener it did not start
fixed-soak ports are not present in the generated VM manifest
```

Boot `aria-acl-matrix-<run-id>-<alias>` with `--availability-zone nova:<nova-az-host>`. Wait for `ACTIVE`, exact scheduled host, one normal OVS port, IP address, tap existence, and no pre-existing Aria binding. Persist only VM ID, port ID, IP, alias, host, and ifname.

Run one negative contract group before active policy work. Both legacy CLI and
direct API must reject `default_action=deny`, IPv6 ethertype, `protocol=gre`,
source-port selectors, reversed destination-port ranges, port `0`, and port
`65536`. Record the HTTP/CLI disposition and verify no rejected object exists.

- [ ] **Step 4: Implement listener preparation and control canary**

For each node, copy the nonce helper and case runner to `${REMOTE_ROOT}/${RUN_ID}`, start TCP/UDP host targets, and use the installed CirrOS listener tool to start guest TCP `8080`, UDP `1080`, TCP `8081`, TCP `8082`, and TCP `65535` listeners. Verify every listener by nonce before ACL creation.

Start an independent ICMP canary to a non-matrix VM or gateway selected by `OVS_CANARY_IP`. Record every sample; it must remain outside all ACL CIDRs and selectors.

- [ ] **Step 5: Implement the exact rotating matrix**

Use this fixed matrix and run each row on all three nodes serially before advancing:

```text
ingress icmp stateful  none
egress  icmp stateful  none
ingress tcp  stateful  single:8080
egress  tcp  stateful  single:18081
ingress udp  stateful  single:1080
egress  udp  stateful  single:18082
ingress tcp  stateless range:8080-8082
egress  udp  stateless range:18080-18082
ingress tcp  stateless single:65535
egress  tcp  stateless single:1
```

The host-side root nonce server owns port `1`, `18080`, `18081`, and `18082`. Each case uses a distinct non-matching port with a confirmed listener. The scheduler tick is one minute; if a case is active, append `skipped_active_tick` and do not fork another case.

- [ ] **Step 6: Implement final cleanup and summary**

On success or signal: stop scheduling, terminate owned listeners, delete any recorded ACL binding/rule/policy, delete all three VMs, wait for their ports to disappear, verify no active projection/status remains, and stop the OVS canary. The summary must keep these gates separate:

```json
{
  "runtime_soak": "external",
  "fixed_policy_soak": "external",
  "control_plane_churn": "external",
  "active_matrix": "pass",
  "ovs_canary_loss": 0,
  "owned_resources_remaining": 0
}
```

Create `complete` only after cleanup succeeds; always write `exit-code`.

- [ ] **Step 7: Implement a detached systemd launcher**

Add `launch`, `status`, and `collect` subcommands to the scheduler. `launch`
must write a mode-0600 runtime environment file, take a non-blocking `flock`,
and start a deterministic unit name without automatic restart. A controller-
local `run-detached.sh` performs log redirection so the command remains
compatible with the target's older systemd:

```bash
systemd-run \
  --unit="aria-acl-active-matrix-${RUN_ID}" \
  --property=Type=simple \
  --property=WorkingDirectory="${REMOTE_ROOT}/${RUN_ID}" \
  /usr/bin/flock -n "${WORK_DIR}/scheduler.lock" \
  /bin/bash "${REMOTE_ROOT}/${RUN_ID}/run-detached.sh" \
  "${WORK_DIR}/runtime.env" "${WORK_DIR}/service.log"
```

`run-detached.sh` validates both paths, sets a fixed system `PATH`, then uses
`exec ... >>"${log}" 2>&1` to run the scheduler. The preflight first verifies
that `systemd-run` and `flock` exist and that a trivial transient unit works on
the target systemd version.

Do not set `Restart=`. A product assertion failure must remain failed instead
of being silently retried. The `status` command prints systemd state plus the
current checkpoint; `collect` copies evidence only and never changes test or
OpenStack state.

- [ ] **Step 8: Test SSH-disconnect independence and launch gating**

Extend the scheduler contract stubs to assert that `launch` returns after the
unit becomes active, no child remains attached to the invoking shell, and the
unit command references only controller-local paths. Simulate advancing two
checkpoint timestamps and require launch success; simulate a stale checkpoint
and require launch failure plus unit stop and owned-resource cleanup.

- [ ] **Step 9: Run scheduler tests and syntax checks**

Run:

```bash
bash -n deploy/kolla/smoke/neutron_aria_acl_active_matrix_soak.sh
bash ci/test_neutron_aria_acl_active_matrix_soak.sh
bash ci/test_neutron_aria_acl_active_matrix_case.sh
```

Expected: all commands PASS, including detached launch, stale-checkpoint, and
single-instance cases.

- [ ] **Step 10: Commit the cluster scheduler**

```bash
git add deploy/kolla/smoke/neutron_aria_acl_active_matrix_soak.sh ci/test_neutron_aria_acl_active_matrix_soak.sh
git commit -m "test(acl): add three-compute active matrix soak"
```

### Task 4: CI Contract And Operator Runbook

**Files:**
- Modify: `ci/check_neutron_stage2_acl.py`
- Modify: `docs/openstack-neutron-aria-details/06-deployment-n05-runbook.md`
- Test: `ci/test_neutron_aria_acl_nonce_echo.py`
- Test: `ci/test_neutron_aria_acl_active_matrix_case.sh`
- Test: `ci/test_neutron_aria_acl_active_matrix_soak.sh`

**Interfaces:**
- Consumes: the three maintained test entry points from Tasks 1-3.
- Produces: CI rejection when a script, guardrail, matrix row, cleanup boundary, or documentation entry drifts.

- [ ] **Step 1: Add failing Stage2 contract assertions**

Require all new files and key markers:

```python
ACTIVE_MATRIX_REQUIRED = {
    "neutron_aria_acl_nonce_echo.py": ["probe", "serve", "ready-file"],
    "neutron_aria_acl_active_matrix_case.sh": [
        "effective_policy_id", "binding_id", "generation_lag", "cleanup_complete"
    ],
    "neutron_aria_acl_active_matrix_soak.sh": [
        "skipped_active_tick", "65535", "single:1", "owned_resources_remaining"
    ],
}
```

Run the three contract tests from the Stage2 checker using the repository's selected Python/Bash interpreters.

- [ ] **Step 2: Run Stage2 check and verify documentation marker failure**

Run:

```bash
python ci/check_neutron_stage2_acl.py
```

Expected: FAIL until the runbook contains the active-matrix operator entry.

- [ ] **Step 3: Document execution and rollback**

Add an `active bidirectional matrix soak` row after the existing active-traffic row. Document exact required inputs, three dedicated VMs, one-minute non-overlapping scheduling, direction/protocol/state matrix, nonce verdict rule, external soak separation, evidence location, and cleanup commands. Explicitly state:

```text
This gate never restarts OVS, ovs-agent, or aria-datapath.
UDP reachability is proven only by exact nonce response, never by nc -uvz.
The four soak layers retain separate pass/fail results.
```

- [ ] **Step 4: Run all non-Rust checks**

Run:

```bash
python ci/test_neutron_aria_acl_nonce_echo.py -v
bash ci/test_neutron_aria_acl_active_matrix_case.sh
bash ci/test_neutron_aria_acl_active_matrix_soak.sh
python ci/check_neutron_stage2_acl.py
python ci/check_blocked_terms.py
git diff --check
```

Expected: all commands PASS. Do not run Cargo locally.

- [ ] **Step 5: Commit and push the maintained gate**

```bash
git add ci/check_neutron_stage2_acl.py docs/openstack-neutron-aria-details/06-deployment-n05-runbook.md
git commit -m "docs(test): register active ACL matrix release gate"
git push origin v0.9-neutron-agent
```

Require the exact pushed SHA's GitHub Actions fast-contract, sensitive-term, Python 2 clean-container, and release-governance jobs to pass. Rust jobs may skip because this change does not touch Rust/eBPF inputs.

### Task 5: Three-Node Field Run And Evidence Closure

**Files:**
- Create after successful field run: `docs/evidence/openstack-n05-lite/20260814-acl-active-matrix/summary.md`
- Modify after successful field run: `docs/openstack-neutron-aria-details/06-deployment-n05-runbook.md`

**Interfaces:**
- Consumes: exact CI-passed commit, current immutable agent image digest, runtime-only target/password files, existing CirrOS image/network/flavor, and three ready compute nodes.
- Produces: public-safe summary bound to commit/image, raw evidence retained outside Git, and zero owned resources after cleanup.

- [ ] **Step 1: Capture the immutable preflight baseline**

Record commit SHA, image digest, container IDs, process identities, agent heartbeat fields, `/readyz`, OVS/ovs-agent process identities, existing fixed-soak bindings, and current runtime/control-plane soak directories. Confirm all three target computes use the same candidate.

- [ ] **Step 2: Stage scripts without restarting services**

Copy only the three smoke helpers to `/var/tmp/aria-acl-active-matrix-<sha>/` on each node, mark them executable, and verify their SHA-256 values match the local commit. Do not copy configuration, agent packages, Rust binaries, or eBPF objects.

- [ ] **Step 3: Run a one-cycle canary**

Set `DEADLINE_EPOCH` far enough for exactly the first ingress ICMP stateful row on all three nodes. Require exact status identity, matching drops, non-matching allows, complete cleanup, heartbeat health, and zero OVS-canary loss before the long run.

- [ ] **Step 4: Run the full matrix until the agreed deadline**

Start the scheduler through its named `systemd-run` service on the designated
controller compute with
the absolute 09:00 deadline. The workstation SSH process must not be an
ancestor or owner of the scheduler process.

Before releasing external SSH access, complete the detached launch gate:

```text
the controller can reach all three dedicated test VMs over the management network
OpenStack token renewal succeeds from the controller
staged SHA-256 values match the CI-passed files
systemd unit is active and the flock is held
checkpoint advances across two one-minute ticks
all three VMs are ACTIVE on their requested hosts
the first active case has started
service.log contains no immediate error
```

If any item fails, stop the unit, run cleanup, and report that the overnight
gate did not start. Do not describe the gate as passed while it is running.

- [ ] **Step 5: Collect and validate evidence**

After completion, require:

```text
exit-code = 0
complete marker present
all 10 matrix rows passed on all 3 nodes
all expected allow/drop verdicts matched
status identity mismatches = 0
heartbeat degraded samples = 0
generation lag violations = 0
OVS canary packet loss = 0
owned ACL objects remaining = 0
dedicated VMs/ports/listeners remaining = 0
```

Correlate, but do not merge, the external runtime, fixed-policy, and control-plane churn results.

- [ ] **Step 6: Write public-safe evidence and commit it**

Summarize topology aliases, matrix counts, convergence percentiles, cleanup, resource trends, commit/image digest, and separate external-soak dispositions. Exclude credentials, tokens, internal endpoint URLs, full configuration, and raw logs.

```bash
git add docs/evidence/openstack-n05-lite/20260814-acl-active-matrix/summary.md \
  docs/openstack-neutron-aria-details/06-deployment-n05-runbook.md
git commit -m "test(acl): record three-node active matrix acceptance"
git push origin v0.9-neutron-agent
```

- [ ] **Step 7: Update the morning collection automation**

Add the systemd unit state, active-matrix work directory, `checkpoint.json`,
`exit-code`, `complete`, `summary.json`, `metrics.tsv`, service log, cleanup
inventory, and OVS-canary result to the existing soak collection instructions.
If SSH is unavailable, report collection deferred rather than test failure.

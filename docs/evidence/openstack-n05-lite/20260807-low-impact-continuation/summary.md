# Low-Impact ACL Field Continuation

Date: 2026-08-07

## Scope And Safety Boundary

- Used compute nodes 2 and 4 only. Node 3 remained untouched while it was under
  operator recovery.
- Did not reboot a host or restart OVS, ovs-agent, neutron-aria-agent, or
  aria-datapath.
- Used synthetic policies, bindings, status rows, and ports unless a read-only
  VM connectivity canary was explicitly required.
- The active local neutron-server ended with zero continuation objects. The
  clustered endpoint intermittently returned one already-cleaned synthetic row
  while node 3 was under recovery; this remains `RISK-ENV-001` rather than a
  global zero-residue claim. Pre-existing historical test objects were not
  deleted.

## Results

| Area | Result | Field evidence |
| --- | --- | --- |
| Baseline health | pass | Aria containers remained running on nodes 2 and 4; the independent VM canary returned 5/5 replies from both nodes; no recent `ERROR`, `CRITICAL`, or panic entries were observed in either Aria container. |
| Collection and item RBAC | pass | A temporary non-admin project received 403 for all five collections and policy create. Cross-project policy GET, PUT, and DELETE hid existence with 404. Admin access remained functional and temporary identities were removed. |
| Port-status aging | pass | A fresh synthetic status projected `stale=false` and `runtime_status=ready`; a 300-second DB backdate projected `stale=true` and `runtime_status=stale` without changing stored `status=ready`; a new report restored fresh state and advanced generation. |
| Rule validation | pass | Unsupported IPv6, source ports, named GRE, reversed ranges, ICMP ports, negative priority, invalid address-set references, and conflicting selectors all returned 400. No rejected rule or temporary object remained. |
| Write concurrency | pass | Concurrent duplicate enabled rule priority produced one 201 and one 409 with one committed row. Concurrent duplicate enabled binding produced the same one-success/one-conflict result. |
| RPC fanout and coalescing | pass | Nodes 2 and 4 received the same fanout. Four create events became one event batch, four delete events became one event batch, and ten concurrent-test events became one event batch. No resync storm was observed. |
| Periodic fallback | pass | A repository-only policy transition with no RPC event was recovered by periodic full resync. Enforce converged in 5 seconds in one window; rollback that missed the boundary converged in 59 seconds, consistent with the configured 60-second interval. |
| UDS authorization | pass | Socket mode was 0660. A normal unprivileged user was blocked by filesystem permissions, root was rejected by peer credentials, and the authorized runtime identity received 200 from status and capabilities. Unknown routes returned 404. |
| UDS malformed snapshot | pass | Invalid JSON returned 400; applied generation was unchanged before and after; the independent VM canary remained 5/5. |
| HTTP malformed input | mixed, inherited risk | Malformed JSON and unknown fields returned 400. A resource value with the wrong container type returned framework 500 for both Aria and the built-in network API before plugin dispatch; see `REVIEW-ACL-073`. |
| HTTP pagination | activation gap | The target has global `allow_pagination=False`. Twelve `limit=2` requests each returned all five rows with no next link, and malformed markers were ignored for Aria and built-in resources. Internal pagination code remains implemented, but `REVIEW-ACL-060` is not field-closed until the global deployment gate is reviewed and enabled. |

## New Or Reopened Findings

- `REVIEW-SEC-003` (P1, closed in the working tree on 2026-08-10): inherited
  OVS debug configuration enabled third-party HTTP DEBUG logs containing
  authentication headers. See the dedicated SEC-003 field summary.
- `REVIEW-ACL-071` (P2, closed on 2026-08-10): new status IDs use a route-safe
  separator while old dotted IDs remain input-compatible. Exact two-host HTTP
  show/delete passed on the active controller.
- `REVIEW-ACL-060` (P2): repository pagination is implemented, but the target
  production HTTP route has global pagination disabled.
- `REVIEW-ACL-073` (P3): wrong-shaped resource bodies inherit a Neutron 9
  controller 500 before Aria validation.
- `RISK-ENV-001` (high): clustered collection reads were intermittently stale
  during node recovery; the active local neutron-server was consistently clean.

## Remaining Deferred Work

- Rerun the node-3 portions only after the operator confirms node 3 is restored.
- Verify every Neutron API/DB backend directly and through the clustered entry
  before closing `RISK-ENV-001` or claiming global cleanup.
- `REVIEW-SEC-003` was fixed and deployed on the two available test nodes on
  2026-08-10. Fresh logs were token-free; pre-fix logs were rotated into
  restricted audit archives without restarting OVS or ovs-agent.
- Review the blast radius of global Neutron pagination before changing the
  production Kolla configuration; validate built-in APIs and Aria pagination
  together.

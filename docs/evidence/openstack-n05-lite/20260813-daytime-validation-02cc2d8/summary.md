# Daytime Validation At `02cc2d8`

## Scope

This evidence binds the daytime validation pass to commit `02cc2d8` and the
same Heartbeat V2 candidate image on three compute nodes. It covers control
plane convergence, UDS failure boundaries, VM lifecycle, baseline networking,
small sustained updates, mixed-version rollback, and final cluster cleanup.
It does not claim the separate 12-hour stability gate.

## Candidate Identity

- Commit: `02cc2d8`
- Agent image ID:
  `sha256:1f47ba02e1e6cbe87d9077ef0368e1f3c45128d4559360cc32fae0e9eb6ef613`
- Image archive SHA-256:
  `f0d37a0c1fe3fd4af0419994519f710632d8a5794822a2e4ad6a26cd4e01e092`
- All three nodes reported Heartbeat schema 2, `summary_only`, ready UDS
  status, full resync enabled, RPC events enabled, and incremental RPC apply
  disabled.
- OVS, the OVS agent, and the Rust datapath were not restarted by these tests.

## Results

| Area | Result | Evidence boundary |
|---|---|---|
| Duplicate and out-of-order RPC | pass | Eight revisions collapsed to one local resync; foreign-host events were filtered. |
| Lost RPC recovery | pass | With RPC temporarily disabled, periodic full resync enforced the policy in 61 seconds and removed it in 59 seconds after cleanup. |
| UDS negative paths | pass | Malformed JSON returned 400, oversized body returned 413, disconnect and idle timeout did not advance generation or disturb forwarding. |
| Soft reboot | pass | Guest traffic recovered in 3 seconds; the independent canary had 98 replies and zero failures. |
| Rebuild | pass | Guest traffic recovered 4 seconds after rebuild completion; the canary had 500 replies and zero failures. |
| Shelve and unshelve | pass | Guest traffic recovered in 5 seconds; the canary had 754 replies and zero failures. |
| Cold migration | pass after `REVIEW-ACL-074` | Reverse migration recovered traffic in 2 seconds and kept exactly one current-host status row through the next full-resync interval. |
| DHCP renew | pass | All three guests retained their expected addresses. |
| East-west and provider-network traffic | pass | All directional guest pairs and all provider paths passed. |
| DNS | environment blocked | The DHCP-provided resolvers refused or timed out; this is not attributed to ACL enforcement. |
| Metadata | environment blocked | The metadata endpoint returned HTTP 500 on all guests. |
| Router and floating IP | not applicable | The test cloud currently has no router or floating-IP topology; provider-network reachability passed. |
| Multi-port updates | pass | Three ports and three policies completed five create/delete cycles, 30 mutations total, with one generation advance per burst and no resync amplification. |
| Mixed Heartbeat V2 image rollback | pass | One node rolled back to the prior V2 image and returned to the candidate while all three guest paths remained reachable. |
| Kolla rebuild and three-node baseline | pass | The same candidate image was loaded on all nodes; installer and runtime gates passed and cleanup left no test policy or binding. |

## `REVIEW-ACL-074`

The initial cold migration exposed two port-status rows: the destination host
reported the active projection while the source-host row remained in the
Neutron database. The source datapath was already clean, so this was an
execution-status lifecycle defect rather than an ACL forwarding defect.

The fix adds:

- exact route-safe status deletion for `(port_id, host)`;
- pending-delete retry in the status reporter;
- status removal on explicit port deletion;
- prior/current projected-port difference cleanup during full resync; and
- focused client, reporter, and event-loop regression tests.

The corrected field run showed one destination-host row immediately and after
the next periodic full resync. No forwarding interruption was observed.

## Verification Boundary

- Focused Python 2 tests for the new delete path passed on all three target
  nodes.
- The related local Python 3 unit set passed 187 tests.
- Direct Python 2 compilation of the installed production modules passed.
- Running the entire source-style unit suite from an installed legacy egg is
  not a valid target gate: that harness lacks modern `unittest.subTest` and
  does not package source test fixtures. This limitation does not replace the
  focused target-runtime checks above.
- The separate three-node 12-hour runtime and live-ACL soak remains the next
  gate.

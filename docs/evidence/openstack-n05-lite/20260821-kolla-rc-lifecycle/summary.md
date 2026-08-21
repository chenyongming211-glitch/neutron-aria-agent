# Three-Compute Kolla RC And Lifecycle Acceptance

Date: 2026-08-21

## Candidate Identity

| Component | Source | Runtime identity |
| --- | --- | --- |
| Neutron adapter | `ba9e7c90` | `neutron-aria-agent:rc-ba9e7c90`, image `sha256:9a6bb9ed29d0ab64ba1f8124478f3a5979cd7702bfbd27dad27ec75bb6ce58ca` |
| Neutron adapter image archive | `ba9e7c90` | SHA-256 `2810ecac4d90ea8d6e260a406b42fa66ef7f0221591311a8ad3303191dbc4de6` |
| Datapath | `bc1b3bc8` | `aria-datapath:rc-bc1b3bc8`, image `sha256:4e258d975689664461f7ed34b1a8e73802de69dc1a65a286cb89964e92ce35bf` |

The Python image was built from a clean Git archive. The focused status-contract
tests passed under the target Python 2.7 image before deployment. Rust and eBPF
were not rebuilt locally; the retained datapath came from the previously locked
hosted build and target-kernel canary.

## Deployment Result

- The same Python and Rust image IDs are active on all three computes.
- The release installer and post-install check passed on all three computes.
- The Python runtime state is host-mounted and survived container replacement.
- All three adapter and datapath containers are healthy.
- All three Neutron heartbeats report `alive=true`, `ready=true`,
  `degraded=false`, `generation_lag=0`, and no last error.
- All three Python state files have `pending_generation=null`.
- Datapath and OVS-agent container identities and start times did not change
  during the Python rollout.

## Lifecycle Matrix

| Scenario | Result | Evidence |
| --- | --- | --- |
| Cold migration | pass | Port ownership moved to the destination compute, the source tap disappeared, source cleanup completed, and ACL enforcement remained active on the destination. |
| Rebuild | pass | The VM returned `ACTIVE` on the same port and host. The port returned to `ready/enforce`; the independent OVS canary remained uninterrupted. |
| Shelve/offload before the fix | fail, root cause found | The old host binding remained in legacy Neutron while the tap disappeared. Rust committed an exact detached tombstone, but Python rejected it as missing managed-port evidence and eventually retained an unresolved local pending generation. |
| Shelve/offload after `ba9e7c90` | pass | The source compute accepted only the exact current-generation/current-hash detached tombstone for a `pending_local_validation` candidate. Heartbeat remained ready with lag zero and no pending transaction. |
| Unshelve | pass | The VM returned `ACTIVE`; the port returned to `ready/enforce`, and the deny probe remained blocked. |
| ACL cleanup/rollback | pass | Binding, rule, and policy were removed. The port converged to `not_requested/bypass`, normal connectivity returned, and no cross-host status row remained. |

## Root-Cause Repair

`ba9e7c90` keeps the strict terminal-evidence contract. A missing managed-port
row is accepted only when all of the following are true:

- the requested candidate is `pending_local_validation`;
- it has no Python-supplied local interface identity;
- Rust reports a detached tombstone for the same port;
- the tombstone carries the exact requested generation and desired hash; and
- the tombstone passes the existing detached-domain validation.

Historical tombstones, a tombstone for another port, a mismatched generation or
hash, and ordinary missing managed evidence remain rejected.

The already-stranded field state was repaired once, before the new image was
installed. The repair first proved that the datapath had terminally committed
the same pending generation and hash, had no remote pending generation, and
reported `classified/ready/none`. The original state file was backed up, only
the proven local pending metadata was cleared, and the next full resync advanced
normally. This is recovery evidence, not part of the steady-state fix.

## Traffic Safety

- First lifecycle canary: `3817/3817`, zero loss.
- Post-fix shelve/unshelve canary: `734/734`, zero loss.
- Total independent OVS canary replies: `4551/4551`, zero loss.
- No test action restarted or modified OVS or the Neutron OVS agent.

## Verification

- RED reproduced `projected ports are not managed` for the exact shelve case.
- GREEN passed the new exact-detached test and the existing diagnostic-only
  tombstone rejection test.
- `154` Python transaction/event-loop and release-installer tests passed.
- The two focused tests passed again in the target Python 2.7 container.
- `git diff --check` passed for the implementation change.

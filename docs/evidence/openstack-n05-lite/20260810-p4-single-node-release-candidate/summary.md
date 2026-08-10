# P4 Single-Node Release Candidate Evidence

Date: 2026-08-10

Status: passed. One compute completed the release-candidate rollout, managed
ACL enforcement and cleanup, transaction recovery, hardened UDS checks, an
actual old-version rollback, and restoration to the release candidate. Aria
did not restart or modify OVS, `neutron-openvswitch-agent`, Nova, or
`neutron-server`.

## Candidate Identity

The P4 candidate is component-scoped because the final source change affects
only the Python Neutron adapter:

| Component | Source / build | SHA-256 or image identity |
| --- | --- | --- |
| Rust `aria-agent` | commit `1051b677063ebe337e977c52a253b907027e6fad`, run `31373688900` | `ba9cdb3f5b01390533c1f7868027b1a8dd994df930e584598e9145e067202c15` |
| eBPF object | commit `1051b677063ebe337e977c52a253b907027e6fad`, run `31373688900` | `140ec66ae9d8f40db2804b3f17538a1ee967e54b9ce70839faf0aa116d2ea1cd` |
| Python source | commit `bb973a202e560cce9158e8c6fd0da904fbdf81e7`, run `31378721542` | `main.py` `30b2957f3370d8ec956d1d2093187fffb27efab51fb885f9ceb8b0df157770b2` |
| Python 2.7 egg | commit `bb973a202e560cce9158e8c6fd0da904fbdf81e7`, run `31378721542` | `07d22cd62bb490e5f0fa4222b07043fd019c1a32b92842f589eebdb6e331fa3f` |
| Kolla bundle | commit `bb973a202e560cce9158e8c6fd0da904fbdf81e7`, run `31378721542` | `c9448a0768ba52b11d39d06976634b60a2bd16273f9c3c095b5adc62e110d952` |
| Python RC image | built on the target from the CI bundle and the onsite Kolla base | `sha256:0baf60183ed482f0772551e2678dc58aedaff7782dbfc95e10547697a6bc02df` |

No Rust or eBPF source changed between the two commits. Rebuilding the Rust
binary in run `31378721542` changed 92 bytes: the 20-byte GNU build ID and 72
bytes of repeated compiler metadata in `.data.rel.ro`; `.text`, file length,
and the eBPF object were unchanged. P4 therefore retained the exact Rust/eBPF
hashes that passed P3. Reproducible Rust linking remains a P6 release-governance
item, not a reason to replace a canary-proven datapath in P4.

## Deployment Boundary

- Only `aria_datapath` and `neutron_aria_agent` participated in the P4
  rollout and rollback exercises.
- The final Python security update replaced only `neutron_aria_agent`.
- The agent remained unprivileged and ran as the `neutron` user.
- The datapath container, datapath process, Rust binary, and eBPF object were
  unchanged during the final Python update.
- OVS, OVSDB, `neutron-openvswitch-agent`, Nova, and `neutron-server` retained
  their process/container identities.
- Both the pre-P4 container and the pre-Python-fix RC container remain stopped
  as local rollback points. No old container was deleted.

## Acceptance Results

| Check | Result |
| --- | --- |
| Composite readiness | passed; heartbeat alive, UDS status `200`, `/readyz` `200`, bodies equal |
| Generation convergence | passed; accepted and applied generations were equal |
| UDS permissions | passed; socket `0660`, root-owned, authorized Neutron group |
| UDS peercred enforcement | passed |
| Managed ACL active traffic | passed; deny took effect and cleanup restored traffic |
| Effective TC identity | passed; live tap links matched pinned program identities |
| WAL pending snapshot replay | passed |
| WAL pending delete replay | passed |
| Migration-source cleanup | passed |
| Datapath restart recovery | passed |
| Actual old-version rollback | passed |
| Restore to release candidate | passed |
| One-shot full resync | passed after temporarily stopping the long-running agent to avoid dual writers |
| One-shot authentication-header leakage | passed; sensitive-header lines `0`, third-party DEBUG lines `0` |
| Active Kolla log scan | passed; files containing authentication headers `0` |
| Final OVS traffic canary | passed; 30 replies, zero loss |

The one-shot probe first demonstrated both safety boundaries independently:
direct access as `neutron` could not read the unprocessed host configuration,
while a root probe could read it but was rejected by UDS peer credentials. The
accepted probe copied the configuration inside a disposable container, changed
the copy to `neutron` ownership, dropped to `neutron`, and then ran the exact
`--once` path. Host configuration permissions were not weakened.

## Rollback Evidence

P4 performed a real rollback rather than a configuration-only rehearsal:

1. The release-candidate containers were stopped.
2. The preserved pre-P4 containers were restored.
3. Readiness and traffic recovery were verified.
4. The release-candidate containers were restored again.
5. Final hashes, readiness, peercred, and traffic were rechecked.

The old and restored runs both left OVS forwarding intact. Aria did not use an
OVS or OVS-agent restart as a recovery action.

## P4 Exit Decision

P4 is complete for the component identities above. P5 may start with this
manifest when the required compute capacity is available. A Rust/eBPF source
change, a different eBPF hash, or a different linked Rust binary selected for
deployment requires renewed candidate identity review and, where applicable,
an isolated maintained-kernel canary before rollout.

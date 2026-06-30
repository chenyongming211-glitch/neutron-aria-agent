# CirrOS VM-Originated Egress ACL Evidence

Host: `ostack2.bj159.net`

Result: accepted for VM -> external/host active ACL direction.

## Probe

| Item | Value |
| --- | --- |
| Temporary VM | `aria-stage2-n05-cirros-egress-20260630-1452` |
| VM IP | `10.58.159.35` |
| Neutron port / tap | `74edc260-dccd-4953-9915-9b0149729ffe` / `tap74edc260-dc` |
| ACL rule | egress ICMP drop, `src=10.58.159.35/32`, `dst=10.58.159.2/32` |
| Generation | `85` |

## Evidence

- `ssh-precheck-2.txt`: guest execution channel worked through key-injected
  CirrOS.
- `precheck-guest-icmp.txt`: tcpdump captured guest-originated ICMP before ACL.
- `status-after-timeout.json`: generation `85` converged to UDS `ready` after
  the CLI wait timed out.
- `post-timeout-guest-icmp.txt`: tcpdump captured 0 packets while the egress ACL
  was active.
- `rollback-and-recovery.txt`: UDS rollback deleted all managed ports.
- `post-rollback-guest-icmp.txt`: tcpdump captured guest-originated ICMP again
  after rollback.
- `cleanup-verify.txt`: no active temporary server, keypair, image, or temp file
  remains; UDS `managed_ports=[]`.

## Caveat

The one-shot `neutron-aria-agent` command timed out while waiting for generation
`85`, but post-timeout UDS status and packet evidence prove that the datapath did
apply the egress ACL and that rollback restored traffic.

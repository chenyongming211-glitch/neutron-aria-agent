# REVIEW-ACL-124 Tap-Recreate Recovery Evidence

## Candidate

- Source commit: `d4dadb32f9b83c606acf6402faa4caa56549c42e`
- GitHub Actions run: `32374731339`
- `aria-agent` SHA-256:
  `1f40bea410f8238746b6eb385225ede5bc24094517de68c60331db5a4ea219e9`
- eBPF SHA-256, unchanged from the preceding candidate:
  `b70f5f1e57f005c17aa262d3cde757764577df9a0c187aac0f5f682f7bee3e63`
- Target: one EL 4.18 compute node, one Neutron-managed VM port, soft reboot.

The candidate userspace binary was overlaid only in the Aria datapath container.
Neither OVS nor the Neutron OVS agent was restarted or modified.

## Hosted Evidence

The RED commit `60378f58` made the logical Neutron-port cache fixture fail with
`530 passed; 1 failed`. The GREEN candidate passed the full hosted Rust workspace
with `531 passed; 0 failed`; selected Rust behavior tests, eBPF stack-budget
enforcement, static builds, Python contracts, and packaging also passed. The
quality job still reports the repository's pre-existing strict Clippy debt; the
new replay-cache line is not one of those findings.

## Field Gate

The authoritative run was the detached systemd unit
`aria-review-acl-124-d4dadb32-v5.service`. It completed with exit status zero.

| Cycle | ifindex | Port replay | Stable false-ready samples | ACL replies | TC ingress/egress | OVS canary |
|---|---|---:|---:|---:|---|---:|
| 1 | `566 -> 567` | 4.382 s | 0 | 0 | present/present | 359/359 |
| 2 | `567 -> 568` | 4.627 s | 0 | 0 | present/present | 677/677 |
| 3 | `568 -> 569` | 5.122 s | 0 | 0 | present/present | 676/676 |

Every cycle observed `DELLINK`, `NEWLINK`, and an internal `scope="port"`
transaction at the already accepted generation and desired hash. The target
port reported `degraded/bypass` while its attachment identity was invalid and
returned to `ready/enforce` only on the replacement ifindex after both TC
directions were present. The active ACL admitted no probe replies.

The sampler separately recorded 1, 0, and 2 non-atomic identity observations.
These are samples where the ifindex changed while the UDS request itself was in
flight; they are not classified as false readiness. The earlier calibration run
proved the distinction: its UDS read started before the kernel delivered
`DELLINK`, while its trailing sysfs read occurred after the tap disappeared.

The independent OVS canary passed `1712/1712`. The OVS process identity and the
Neutron OVS-agent container identity were identical before and after the run.

## Final State

- Aria datapath, Neutron Aria agent, and Neutron OVS agent: `healthy`.
- Accepted/applied generation: `6118/6118`; pending generation: none.
- Port: `ready/enforce` on ifindex `569`.
- WAL: `commit_written`; replay failures: zero.
- Target ACL probe: blocked.
- Independent OVS probe: reachable with zero loss.

## Raw Evidence

- Remote archive:
  `/var/tmp/review-acl-124-d4dadb32-field-v5.tgz`
- SHA-256:
  `7e2da45dee54563ed0c85b32999d3c257dca2558391e32776914cdfc9cb3c97c`

The earlier `field-v2` and `field-v3` runs are harness compatibility failures
and are not product evidence. `field-v4` exercised all three product cycles but
failed its original non-atomic sampler rule; only `field-v5` is authoritative.

## Verdict

`REVIEW-ACL-124` is field verified as fixed for the tested soft-reboot/tap-
recreate path. The fix removes the long false-ready window and recovers from
the process-local last-good Neutron snapshot without waiting for periodic full
resync, while preserving the independent OVS forwarding path.

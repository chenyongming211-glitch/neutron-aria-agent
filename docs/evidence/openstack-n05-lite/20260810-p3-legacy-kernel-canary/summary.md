# P3 Maintained-Kernel Isolated Canary Evidence

Date: 2026-08-10

Status: passed. The exact P2 `aria-agent` and eBPF object loaded on the
maintained 4.18 target kernel in both TC directions and completed the isolated
ACL smoke without fixture residue. This is a loader and isolated-datapath gate;
it is not a production service rollout.

## Candidate Identity

- Commit: `1051b677063ebe337e977c52a253b907027e6fad`
- GitHub Actions run: `31373688900`
- Kernel: `4.18.0-553.5.1.el8_10.x86_64`
- `aria-agent` SHA-256:
  `ba9cdb3f5b01390533c1f7868027b1a8dd994df930e584598e9145e067202c15`
- `libebpf_firewall.so` SHA-256:
  `140ec66ae9d8f40db2804b3f17538a1ee967e54b9ce70839faf0aa116d2ea1cd`

The hashes were checked after upload and again after the canary. They match the
P2 evidence exactly. No local Rust or eBPF compilation was performed.

## Isolation Boundary

The canary ran in a disposable privileged container using a temporary network
namespace, two temporary veth pairs, private bpffs, and a temporary state
directory. Candidate artifacts were mounted read-only. The evidence directory
was the only writable host bind mount.

The run did not attach to a VM tap, change a Neutron port, restart OVS, restart
`neutron-openvswitch-agent`, or replace the running `aria-datapath`. The OVS
processes and both running containers retained the same process identity and
start time before and after the canary.

## Results

| Check | Result |
| --- | --- |
| Exact kernel | passed |
| Exact candidate hashes | passed |
| TC ingress verifier/load | passed |
| TC egress verifier/load | passed |
| Attach mode | legacy TC |
| Isolated allow/drop behavior | passed |
| XDP ACL/CT neutrality | passed |
| WAL and pinned-runtime restart recovery | passed |
| Missing TC health detection | passed; the runtime quiesced and rejected an unsafe enable request |
| Cleanup reported by smoke | passed; `cleanup_errors=[]` |
| Verifier stack, packet-bound, or uninitialized-stack failure signature | none found |

The smoke summary reported:

```text
result=pass
dual_tc_ready=true
recovery_verified=true
healthy_pinned_restart=true
missing_tc_rejected=true
health_poll_degraded=true
xdp_neutral=true
tc_attach_mode=legacy
```

`health_poll_degraded=true` is expected: the smoke deliberately removed one TC
direction to verify that health polling detects the loss and quiesces the
runtime. It is test evidence, not the final canary state.

## Expected Warnings

- The isolated tap-mode run could not preserve an XDP link pin on this legacy
  kernel. XDP identity testing was outside this gate and XDP remained ACL/CT
  neutral; TC ingress and egress stayed authoritative and passed.
- The optional kernel-drop-manager map was absent because this isolated smoke
  did not start that separate domain. This did not affect TC ACL attachment or
  enforcement.
- Initial local HTTP connection refusals were startup polling before the
  temporary agent became ready. The smoke subsequently completed all checks.

Fragment-transition and XDP-link-identity subtests were explicitly disabled by
the P3 canary contract. They remain part of later release-candidate regression
scope and are not claimed here.

## Residue Check

After the disposable container exited:

- the canary container was absent;
- the temporary network namespace was absent;
- all four temporary veth names were absent;
- the private bpffs mount was absent;
- the temporary work directory was absent from the running datapath container;
- OVS, the OVS agent, and the running datapath had not restarted.

## Raw Evidence Integrity

Raw field output remains in the ignored local artifact directory. Its hashes
are:

| File | SHA-256 |
| --- | --- |
| `canary-summary.json` | `dc008b8d863b5e3dd884bc48575066c2bc89916287a331be857e06997a55554e` |
| `standalone-summary.json` | `9c7df3436519344e7e60463557ea7ce6c94073105eaee4c7cef69c0fee482145` |
| `canary-console.log` | `8036159d9657ba51b15da63aaab1084795487108438ca56b5e2286dbfe1557cd` |
| `agent.log` | `13c5db8a26b6354c112271913efa2d7ce5852d5dfddf7c82ff7c4ae9ede0043b` |
| `agent.stdout` | `a47438b7c70536b159dd491a65e5bd38fa53eab80cb0aa6284e8735d10adcc63` |

## P3 Exit Decision

P3 is complete for candidate `1051b677063ebe337e977c52a253b907027e6fad`.
P4 may deploy only these exact candidate hashes to one compute release
candidate. Any Rust/eBPF source change invalidates this evidence and requires a
new P2 build and P3 canary.

# Kolla eBPF Runtime Safe Upgrade Acceptance

Date: 2026-08-17

## Scope

This acceptance validates the Kolla lifecycle path introduced by `1cf1712` on
one test compute. The candidate intentionally reused the already accepted
`rc-0e0da31` image and set `FORCE_RUNTIME_MIGRATION=true`. This isolates the
upgrade mechanism from a new datapath binary while executing the same
quiesce, detach, state/pin split, full-resync, verification, and rollback path
used when the eBPF hash changes.

The automatic hash decision and incompatible-state crash windows remain
covered by the installer unit tests. This field run does not claim that an
arbitrary future incompatible eBPF object has passed the target kernel.

Aria did not restart or modify OVS or the Neutron OVS agent during this run.

## Candidate

- Source commit: `1cf1712`.
- GitHub Actions run: `32034592920`, result `success`.
- Datapath image: `aria-datapath:rc-0e0da31`.
- Image ID:
  `sha256:dd8469c69ea581d82fdb2b7a896142a7b9ce78f81af9668dee89bff9b35f51ff`.
- `aria-agent` SHA-256:
  `9e446efaab37b733852d978f2e5a45d409c7682eb8a5ff316a239c5b86966e4b`.
- eBPF SHA-256:
  `b70f5f1e57f005c17aa262d3cde757764577df9a0c187aac0f5f682f7bee3e63`.
- Installer SHA-256:
  `0a3f9e5dd7d5d339a64dcdbf34acb9d68d227721e079536207a4614edf741136`.

## Upgrade Result

The versioned installer used an isolated root-only release ledger so the
existing formal RC rollback point remained intact.

The forced runtime migration passed:

1. the Python writer was stopped before runtime mutation;
2. all UDS-reported managed ports were detached;
3. the old state directory and shared pin namespace were preserved;
4. the candidate received a copied state directory and fresh shared pins;
5. the datapath and Python agent restarted without touching OVS;
6. authoritative full-resync restored 27 managed ports;
7. both Aria containers returned to Docker `healthy`;
8. the installer `check` command passed exact image and file identities.

## Rollback Result

The reverse runtime-boundary rollback passed:

1. candidate-managed ports were detached before switching back;
2. the original state directory and shared pins were restored;
3. the original datapath container was restored under its service name;
4. full-resync restored all 27 managed ports;
5. both Aria containers returned to Docker `healthy`;
6. no candidate state directory, failed-candidate directory, pin backup, or
   pin quarantine remained;
7. the pre-existing formal RC ledger still passed `check`.

The test ledger retained only a root-owned lifecycle lock and the renamed
rolled-back audit record. No pending transaction remained.

## OVS Safety

The installer recorded and rechecked both OVS identities. Before and after the
upgrade and rollback:

- the `ovs-vswitchd` PID was unchanged;
- the Neutron OVS agent container ID was unchanged;
- the Neutron OVS agent start timestamp was unchanged.

## Verification

- Local fast contracts: 729 passed, 19 skipped.
- Kolla/runtime/release targeted tests: 32 passed.
- Build workflow contract: passed.
- Blocked-term scan: passed.
- Release bundle reproducibility: passed.
- GitHub Actions: fast contracts, clean install, DB contracts, Rust behavior,
  eBPF stack budget, Rust build, and release artifact preparation passed.

## Result

Result: **PASS** for the Kolla hash-aware runtime migration mechanism and its
reverse rollback path on one test compute.

Before a release claims compatibility with a new eBPF schema, that exact
candidate still requires its normal target-kernel canary and ACL regression.

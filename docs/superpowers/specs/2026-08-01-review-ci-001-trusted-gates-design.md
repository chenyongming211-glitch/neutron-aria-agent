# REVIEW-CI-001 Trusted Automated Gates Design

**Status:** implemented in `5d7fcfc`; exact implementation-head Build
[30704906357](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30704906357)
passed all required hosted lanes.  No target runtime evidence is claimed.

## Problem

The required Build workflow already executes the complete Neutron Python unit
discovery, but the Stage 2 and Stage 3 audit scripts still mix five different
kinds of evidence under broad “accepted” or “readiness” wording:

1. executable non-privileged behavior tests;
2. build, package, workflow, and documentation structure contracts;
3. committed historical field-evidence validation;
4. real target-environment smoke;
5. source and test-name substring checks.

That mixture can make a static marker or an old evidence summary look like
current-HEAD runtime readiness.  It also duplicates six Python modules that the
required full discovery already runs, and it validates configured domains in
separate places without one explicit cross-boundary invariant.

## Required outcome

Every automated result must state which evidence class it proves:

- `behavior`: executable tests against public behavior;
- `static_artifact`: workflow, packaging, entrypoint, schema, link, or document
  structure;
- `historical_field_evidence`: validation of committed evidence produced by an
  earlier privileged run, explicitly `head_bound=false`;
- `target_runtime`: evidence produced by a real target-environment smoke.

Only `target_runtime` may claim current runtime execution.  Missing target
execution remains `SKIP/deferred`; it never becomes PASS because a static or
historical checker succeeded.

## Design

### Required Python behavior inventory

`check_neutron_stage1.py --fast-contracts` continues to run the complete
`test_*.py` discovery exactly once.  Before executing it, the checker asks
`unittest.TestLoader` for the discovered test IDs and verifies a small,
reviewable inventory of Neutron-critical behaviors.  This prevents deletion or
renaming of a high-value test from silently weakening the required lane without
running a second selected suite.

The inventory covers:

- eligible OVS tap selection;
- rejection of unimplemented managed domains;
- capability negotiation and missing-domain rejection;
- durable pending state;
- full snapshot submission and fail-closed runtime-status validation;
- ACL RPC convergence;
- degraded heartbeat and bypass projection;
- legacy Neutron port projection, field selection, and fail-soft behavior.

It does not attempt to inventory every Python unit test.

### Domain contract

The contract is proved at two executable boundaries:

1. Rust behavior asserts that the runtime implementation inventory equals
   `NEUTRON_SUPPORTED_DOMAINS`, which is what capabilities advertise.
2. Python fast contracts assert
   `requested_managed_domains ⊆ python_supported_managed_domains ⊆ advertised_supported_domains`.

The current expected sets remain:

- advertised and Rust runtime implemented: `attach`, `acl`;
- Python configurable/requested: `acl`.

QoS and Mirror remain rejected as Neutron-managed domains.

### Rust behavior discovery

The source-regex Rust test finder is removed.  Each configured Cargo behavior
command executes once; its own test-harness output must report at least one
executed test.  A filter that matches zero tests fails even when Cargo exits
successfully.  This uses Cargo’s discovery/execution result and does not bind CI
to Rust source layout or private helper spelling.

### Stage 2 and Stage 3 classification

- The Stage 2 structural audit stops rerunning its six selected Python modules.
- Source/test-name marker guards that are already covered by required behavior
  tests are removed from the active Stage 2 orchestration.
- Legitimate entrypoint, migration, package, workflow, and smoke-command wiring
  checks remain, but report `static_artifact` rather than runtime readiness.
- Stage 2 acceptance, N0.5 discovery, UDS hardening, and N3 summary validation
  report `historical_field_evidence` and `head_bound=false`.
- The Stage 3 readiness-plan checker reports `static_artifact` and
  `runtime_evidence=not_evaluated`.

### Required workflow lane

A focused CI-001 contract test runs in `fast-contracts` on every Build.  The
expensive Rust behavior and Rust/eBPF compilation remain in their independent
jobs.  The scheduled/manual deep audit remains available, but its step labels
must not imply that historical or static checks are a current runtime smoke.

## Explicit exclusions

- No full-workspace Cargo test, clippy, rustfmt, or shellcheck expansion; those
  remain `DEBT-CI-001`.
- No privileged smoke execution in hosted CI.
- No duplicated Stage 2 Python suite.
- No custom Rust parser and no checks for helper names, local variables, or
  parameter order.
- No production fixes for `REVIEW-ACL-063`, `RISK-SEC-002`,
  `RISK-READY-001`, `REVIEW-ACL-011`, or `REVIEW-OPS-036` in this batch.

## Acceptance

1. Removing any required Python behavior test makes `fast-contracts` fail.
2. A Cargo behavior filter that executes zero tests fails `rust-behavior`.
3. Advertised, runtime-implemented, Python-supported, and requested domain sets
   cannot drift across their stated relationships.
4. Static checks and committed field-evidence checks identify their scope in
   machine-readable output.
5. Stage 2 no longer reruns Python modules already covered by full discovery.
6. Hosted CI remains split: fast contracts do not invoke Cargo.
7. No target-environment evidence is claimed.

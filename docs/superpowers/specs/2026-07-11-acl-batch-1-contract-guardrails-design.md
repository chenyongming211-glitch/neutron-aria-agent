# ACL Batch 1 Contract Guardrails Design

Date: 2026-07-11

Status: proposed for implementation

## Goal

Close the first ACL repair batch by making the northbound API, effective ACL
compiler, Python agent configuration, UDS capability contract, and status
projection agree on the ACL behavior that the current Rust datapath actually
implements.

Invalid or unimplemented desired state must be rejected before submission, or
classified as degraded with `effective_action=bypass`. A concrete runtime
`bypass`, error, or degraded result must never be promoted to `enforce` or
`ready` by Python metadata projection.

## Scope

This batch closes or narrows these 12 active findings:

- `REVIEW-ACL-001`: unsupported policy `default_action` accepted northbound.
- `REVIEW-ACL-002`: conflicting bindings and duplicate rule priorities accepted.
- `REVIEW-ACL-006`: repository validation/not-found errors can escape as HTTP 500.
- `REVIEW-ACL-009`: northbound accepts rule fields outside the current translator.
- `REVIEW-ACL-029`: an empty address set compiles as ready.
- `REVIEW-ACL-030`: a disabled address set is still expanded.
- `REVIEW-ACL-031`: effective-for-port hard-codes eligibility.
- `REVIEW-ACL-039`: `qos` can be configured without a production QoS payload.
- `REVIEW-ACL-043`: numeric priority `0` is rejected as missing.
- `REVIEW-ACL-048`: status metadata can overwrite runtime bypass with enforce.
- `REVIEW-ACL-049`: an unimplemented managed domain can block the ACL domain.
- `REVIEW-DOC-021`: capabilities advertise domains without runtime executors.

## Non-Goals

- Do not implement QoS or Mirror indexes, snapshot payloads, recovery executors,
  control-plane operations, or datapath behavior.
- Do not implement `default_action=deny` policy semantics.
- Do not add IPv6 ACL translation or source-port matching.
- Do not change ACL rule-priority execution in the Rust datapath; that remains
  `REVIEW-ACL-047` in Batch 3.
- Do not change `stateful=false` execution; that remains `REVIEW-ACL-054` in
  Batch 3.
- Do not change snapshot/WAL ordering; Batch 2 owns those transaction fixes.
- Do not turn Aria ACL into Neutron Security Group enforcement. The product
  remains in OVS enhancement mode.

## Safety Boundaries

- OVS connectivity readiness remains independent from Aria readiness.
- Invalid or unavailable ACL enhancement produces `DomainStatus=degraded` and
  `effective_action=bypass`; it does not stop the existing OVS forwarding path.
- WAL/capability consistency failures may be `blocked`, but validation failures
  in this batch must not advance a false ACL-ready view.
- The Python agent accepts only `managed_domains=acl` for the current shipped
  configuration. Rust UDS capabilities advertise only runtime-implemented
  domains: `attach` and `acl`.
- A legacy snapshot containing an unsupported domain is rejected or classified
  as unsupported; it is never reported as successfully applied. Recovery of
  historical unsupported WAL intents remains part of Batch 2 under
  `REVIEW-ACL-051`.

## Current ACL Input Contract

The server, legacy CLI, effective compiler, and Rust translator must converge
on this current implementation subset:

| Field | Accepted values and constraints |
| --- | --- |
| Policy `default_action` | `allow` only |
| Rule `direction` | `ingress` or `egress` |
| Rule `action` | `allow`, `deny`, or `drop`; normalize `deny` to drop semantics |
| Rule `ethertype` | absent or `IPv4` |
| Rule `protocol` | absent/`any`, `tcp`, `udp`, `icmp`, or an integer in `0..255` |
| Source CIDR | valid IPv4 CIDR; mutually exclusive with source address set |
| Destination CIDR | valid IPv4 CIDR; mutually exclusive with destination address set |
| Source ports | unsupported; reject when either bound is present |
| Destination ports | `0..65535`, minimum not greater than maximum, TCP/UDP only |
| Rule priority | integer `0` or greater; unique among enabled rules for the same policy and direction |
| Address set | must exist, be enabled, contain at least one non-empty valid IPv4 member, and belong to the policy project |
| Binding | at most one enabled binding for each `(target_type, target_id)` |

Validation is applied on both create and update after merging update fields with
the stored object. Existing invalid records remain readable and are classified
as degraded by the effective compiler; they are not silently repaired.

## Architecture

### 1. Shared Python ACL Contract Validation

Create a small, stdlib-compatible module at
`openstack/neutron_aria/neutron_aria/acl_contract.py`. It owns pure validation
and normalization helpers for policy fields, rule fields, CIDRs, port ranges,
priority keys, address-set usability, and Neutron port eligibility.

The module must remain compatible with the legacy Python runtime used by the
OpenStack package. It must not import SQLAlchemy, oslo, or neutron-server.

Repository create/update paths call the shared validators before writing. The
effective compiler uses the same predicates defensively for existing records.
The CLI keeps local `argparse` choices for immediate feedback, while the server
remains authoritative.

### 2. Repository Conflict Enforcement

Both `InMemoryAriaAclRepository` and `NeutronDbAriaAclRepository` enforce:

- unique enabled binding per target;
- unique enabled priority per `(policy_id, direction)`;
- valid current-MVP policy and rule fields;
- explicit `None`/missing checks so priority `0` is accepted.

Conflict writes return a validation/conflict error before mutation. Batch 1
does not redesign multi-table DB transaction boundaries; address-set atomicity
remains Batch 5 work under `REVIEW-ACL-003` and `REVIEW-ACL-042`.

### 3. Legacy Neutron Error Mapping

Keep repository exceptions transport-neutral. Add a service-plugin boundary
adapter at
`openstack/neutron_aria/neutron_aria/services/aria_acl/exceptions.py` that maps:

- `AriaAclValidationError` to a legacy-Neutron-safe HTTP 400 exception;
- binding/priority conflicts to HTTP 409 when the installed Neutron exception
  surface supports conflict semantics, otherwise HTTP 400;
- `AriaAclNotFound` to HTTP 404;
- unexpected exceptions unchanged so real server faults are not mislabeled.

Every plugin CRUD method calls one private wrapper that performs this mapping.
The fallback repository remains usable without an installed Neutron package.

### 4. Effective ACL Defensive Compilation

`EffectiveAclIndex` performs no writes. It must return degraded/bypass when an
existing desired-state object violates the current contract.

In particular:

- missing, disabled, or empty address sets produce a stable reason code;
- invalid IPv4 members produce a stable reason code;
- unsupported default action or rule fields do not produce `ACL_READY`;
- duplicate bindings and priorities remain degraded even if invalid records
  predate server-side validation;
- actual port eligibility is used instead of a hard-coded true value.

Eligibility is derived from Neutron port fields available at the plugin
boundary: compute device owner, OVS vif type, and normal vNIC type. Missing
runtime-only information must produce a desired-state eligibility disposition,
not fabricate interface attachment readiness.

### 5. Managed-Domain Admission And Capabilities

`AgentConfig.validate_config` accepts only `acl` in `managed_domains` for the
current packaged agent. Values containing `qos`, `mirror`, or another domain
fail fast with `ConfigError` before the service starts submitting snapshots.

The Rust capability constant and `docs/neutron-uds-contract.json` advertise
only `attach` and `acl` as implemented runtime domains. Stage checks assert that
the advertised set equals the implemented set; they must not require planned
QoS/Mirror domains.

Rust still rejects a direct UDS snapshot containing another managed domain.
It returns a per-domain unsupported/error classification without applying or
reporting ACL ready. No QoS/Mirror executor is added.

### 6. Runtime Status Is Authoritative

`SnapshotSynchronizer._port_statuses_from_status` may add identifiers or fill
fields that are genuinely absent, but it must not replace a concrete Rust UDS
value.

The precedence order is:

1. concrete UDS per-domain status and `effective_action`;
2. concrete UDS port-level status and `effective_action`;
3. snapshot metadata only when the corresponding runtime field is absent;
4. conservative degraded/bypass when the sources contradict each other.

Specifically, `bypass`, `degraded`, `blocked`, and `error` are concrete runtime
truth and cannot be overwritten by desired-state `ready/enforce` metadata.

## Data Flow After The Change

1. A caller submits a policy, rule, address set, or binding.
2. The plugin unwraps the request and calls a repository method through the
   exception-mapping wrapper.
3. The repository validates the complete post-update object and target
   uniqueness before writing.
4. The ACL source reads validated records; the effective compiler defensively
   revalidates records already present in an older database.
5. Ineligible ports or invalid ACLs become degraded/bypass and do not submit an
   enforce-ready ACL block.
6. The Python config prevents unimplemented managed domains from entering new
   snapshots.
7. Rust capabilities expose `attach` and `acl`; direct unsupported snapshots
   are rejected without falsely readying ACL.
8. Status projection preserves the concrete Rust result and only enriches
   missing identity metadata.

## Files Expected To Change

Python contract and northbound:

- Create `openstack/neutron_aria/neutron_aria/acl_contract.py`.
- Modify `openstack/neutron_aria/neutron_aria/db/aria_acl/api.py`.
- Create `openstack/neutron_aria/neutron_aria/services/aria_acl/exceptions.py`.
- Modify `openstack/neutron_aria/neutron_aria/services/aria_acl/plugin.py`.
- Modify `openstack/neutron_aria/neutron_aria/extensions/aria_acl.py` where the
  installed legacy Neutron attribute framework supports value validation.
- Modify `openstack/neutronclient_aria/neutronclient_aria/v2_0/aria_acl.py`.

Python agent:

- Modify `openstack/neutron_aria/neutron_aria/agent/config.py`.
- Modify `openstack/neutron_aria/neutron_aria/agent/effective_acl.py`.
- Modify `openstack/neutron_aria/neutron_aria/agent/event_loop.py`.
- Reuse or extract the pure eligibility rules currently represented in
  `openstack/neutron_aria/neutron_aria/agent/inventory.py`.

Rust and contracts:

- Modify `api/src/lib.rs` capability-domain declarations and tests.
- Modify `agent/src/neutron_api.rs` unsupported-domain admission tests only as
  required to make direct UDS rejection explicit.
- Modify `docs/neutron-uds-contract.json`.
- Modify stage contract checks that currently require planned domains.

Tests and documentation:

- Extend repository/plugin/effective ACL/config/event-loop unit tests under
  `openstack/neutron_aria/neutron_aria/tests/unit/`.
- Extend legacy CLI body/choice tests under
  `openstack/neutronclient_aria/neutronclient_aria/tests/` using a stub path so
  the core assertions do not disappear when `python-neutronclient` is absent.
- Update `docs/openstack-neutron-aria-details/12-review-bug-backlog.md` with
  per-ID evidence and final status.
- Update authoritative capability wording in
  `docs/openstack-neutron-agent-mode.md` and ACL detail documents only where
  this batch changes the implemented/current boundary.

## Test Strategy

All behavior changes follow red-green-refactor. Each finding receives at least
one test that fails on baseline `ebaf9dd` for the stated reason before the
implementation change is applied.

Local allowed checks:

- focused Python unit tests for contract, repository, plugin, effective ACL,
  config, inventory, event loop, and CLI body construction;
- full `openstack/neutron_aria` Python unit suite;
- `python3 -m compileall` for both OpenStack Python packages;
- Neutron stage 1/2/3 static and Python checks;
- shell syntax checks where a stage script changes;
- `git diff --check`.

Rust validation:

- add focused Rust unit/contract tests for capability and unsupported-domain
  behavior;
- do not run local `cargo build`, `cargo check`, or `cargo test`;
- push the batch and use GitHub Actions for Rust compilation and tests;
- if CI fails, diagnose from the workflow log, add or correct the smallest
  failing test, and push a follow-up fix.

## Acceptance Criteria

- A policy with `default_action=deny` is rejected by server and CLI before it
  can become desired state.
- Unsupported IPv6/source-port/invalid protocol or action inputs are rejected
  consistently; existing invalid records compile degraded/bypass.
- Priority `0` succeeds; duplicate enabled priority and binding writes fail.
- Missing, disabled, empty, or invalid address sets never compile ready.
- Effective-for-port does not label an ineligible Neutron port ready/enforce.
- Packaged config containing `qos` or `mirror` fails fast; ACL-only config works.
- Capabilities and contract documents expose only implemented runtime domains.
- A direct unsupported-domain snapshot cannot make ACL ready.
- UDS `bypass` or error status survives Python metadata projection unchanged.
- Existing OVS forwarding behavior remains outside the ACL readiness decision.
- All allowed local checks pass and GitHub Actions passes before the batch is
  considered delivered.

## Delivery

Implementation occurs in an isolated `codex/` worktree so the existing dirty
`README.md` and backlog edits remain untouched. The batch is committed in
reviewable TDD slices, then pushed to GitHub. Only Batch 1 files and the already
approved backlog classification are included; later-batch fixes are not folded
into the same change.

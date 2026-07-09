# OpenStack Neutron Aria Detail Plans

Status: first refinement pass. These files break the large v0.9 design into
smaller plans. They are design records, not implementation claims.

Current refinement depth:

- All detail plans are refined to implementation design package level: target
  files, data structures, flows, error semantics, tests, and guardrails.
- Function-call-level design should be written only when opening the specific
  implementation PR.

Normative parent documents:

- `../openstack-neutron-aria-design-decisions.md`
- `../neutron-managed-domains-contract.md`
- `../openstack-neutron-agent-mode.md`

Anti-overengineering rule:

Only detail what is required for v0.9 gates, smoke, production risk reduction,
or an explicitly approved later phase.

## Detail Plan Index

| Plan | Purpose |
| --- | --- |
| `01-ini-contract.md` | Freeze the target `neutron-aria-agent.ini` and local datapath config ownership. |
| `02-aria-acl-plugin.md` | Detail the minimum `aria_acl` Neutron service plugin/API/DB plan. |
| `03-neutron-acl-source.md` | Detail how `neutron-aria-agent` reads `aria_acl` and builds effective ACL input. |
| `04-uds-contract-security.md` | Detail UDS contract, body limits, error hash, peer auth, and audit. |
| `05-domain-status-heartbeat.md` | Detail rich domain status and Neutron heartbeat/status projection. |
| `06-deployment-n05-runbook.md` | Detail deployment enablement, N0.5 evidence, smoke, and rollback. |
| `07-transaction-wal.md` | Detail snapshot apply transaction, WAL intent/commit, replay, timeout, and idempotency. |
| `08-stage3-acl-production-hardening.md` | Detail Stage-Three ACL Production Hardening, release/CI, persistent UDS rollout, and N3 fault/lifecycle gates. |
| `09-aria-rpc-incremental-sync.md` | Record post-stage-three RPC evolution: P2 RPC-triggered full-resync and P3 incremental RPC with port-scoped apply. |
| `10-rust-scoped-apply.md` | Detail the P3-3 Rust single-port scoped apply minimum design and test boundary before touching datapath logic. |
| `11-qos-next-phase.md` | Record the QoS next-phase entry assessment after ACL/P3 closure; starts with capability discovery and degraded/unsupported semantics. |
| `12-review-bug-backlog.md` | Track code-review bugs and risks that must be fixed without expanding the product scope. |
| `13-acl-delivery-performance-optimization.md` | Detail ACL strategy delivery performance optimization after the 2026-07-07 200-rule convergence probe. |
| `14-logging-level-governance.md` | Record Rust/Python agent logging-level governance, noisy-log demotion, SSL reconcile gating, and Kolla log routing cleanup. |
| `15-acl-operator-ux-backlog.md` | Track read-only ACL operator UX improvements such as policy-with-rules and effective-port inspection commands. |

## Refinement Order

1. INI contract, because examples and runbooks depend on it.
2. Transaction/WAL semantics, because snapshot apply safety is the current pause
   checkpoint and every production path depends on it.
3. UDS contract/security, because Python and Rust must agree before production.
4. `aria_acl` plugin and `NeutronAclSource`, because they complete the ACL product path.
5. Domain status/heartbeat, because product observability depends on it.
6. Deployment/N0.5 runbook, because it turns design into safe field enablement.
7. Stage-three ACL production hardening, because stage two is accepted and the
   next risk is release/CI plus N3 operational behavior.
8. Aria RPC incremental sync, recording P2 and the accepted config-gated P3
   follow-up after stage three.
9. Rust scoped apply, recording the accepted P3 scoped route/apply boundary and
   test contract.
10. QoS next-phase entry assessment, only after ACL/P3 closure and target
    capability evidence are clear.
11. ACL delivery performance optimization, starting with logging and duplicate
    submit suppression before changing UDS semantics or eBPF map layout.
12. Logging-level governance, to keep ACL product operation readable before
    adding more feature surface or telemetry.
13. ACL operator UX backlog, after core ACL correctness and smoke coverage are
    stable, to improve read-only troubleshooting without changing datapath
    behavior.

## Dependency Map

```text
01 INI contract
  -> 06 config smoke and deployment gates

07 transaction/WAL
  -> 04 timeout semantics
  -> 06 recovery smoke
  -> 05 generation projection

04 UDS contract/security
  -> 06 UDS smoke and peer-auth deployment gates

02 aria_acl plugin
  -> 03 NeutronAclSource
  -> 06 G5/G6 production ACL enablement

05 domain status/heartbeat
  -> 02 aria_acl_port_statuses
  -> 06 heartbeat and production status validation

08 Stage-Three ACL Production Hardening
  -> release/CI gate
  -> persistent UDS rollout
  -> ACL N3 fault and lifecycle gates

09 Aria RPC incremental sync
  -> 03 revision cache and effective read
  -> 05 incremental failure reporting
  -> 07 port-scoped WAL/generation semantics
  -> 08 P2 RPC-triggered resync entry criteria
  -> 10 Rust scoped apply test boundary

10 Rust scoped apply
  -> 04 advertised, config-gated port-scoped UDS route
  -> 07 scoped WAL/generation semantics
  -> 09 P3-3 implementation package

11 QoS next phase
  -> N0.5 capability refresh for Neutron QoS and tc/qdisc
  -> managed_domains qos authority gate
  -> degraded/unsupported QoS status before any shaping claim

13 ACL delivery performance optimization
  -> 07 pending generation and WAL idempotency
  -> 09 RPC and port-scoped update path
  -> 10 Rust scoped apply route
  -> 04 async accepted UDS contract
  -> ACL quota and capacity gates

14 Logging level governance
  -> 06 deployment log checks
  -> 08 production hardening evidence
  -> 09 RPC event log breadcrumbs
  -> 13 ACL delivery performance logs

15 ACL operator UX backlog
  -> 02 aria_acl plugin/client read-side commands
  -> 05 status/heartbeat effective port inspection
```

## Gate Mapping

| Gate | Primary Plans | Meaning |
| --- | --- | --- |
| G0 image/config packaged | 01, 06 | Container and target ini safe defaults are packaged. |
| G1 datapath inert | 04, 06 | UDS status/capabilities work while OVS forwarding remains baseline. |
| G2 authority gate | 01, 04, 07 | `managed_domains` local write authority is enforced safely. |
| G3 fixture ACL | 03, 07 | ACL datapath path works before production Neutron ACL source exists. |
| G4 environment discovery | 06 | N0.5 facts are verified and recorded. |
| G5 production ACL source | 02, 03, 07 | `aria_acl` and `NeutronAclSource` can build and submit snapshots. |
| G6 full resync | 01, 03, 05, 07 | Neutron port source, resync, heartbeat, and generation status are stable. |
| G7 rollback | 06, 07 | Disabling integration preserves OVS forwarding and safe recovery semantics. |
| S3 production hardening | 08 | CI/release, persistent UDS rollout, ACL N3 fault, and lifecycle gates are ready. |
| P2/P3 RPC sync evolution | 09, 10 | RPC-triggered resync and incremental port-scoped apply are accepted behind config gates; packaged defaults keep incremental runtime disabled. |
| QoS next-phase entry | 11 | Q0 evidence is refreshed; QoS remains deferred until Q1/Q2 status and authority gates are accepted and Q4 decides shaping, policing-only, or unsupported/degraded behavior. |
| ACL delivery performance | 07, 09, 10, 13 | 100/200-rule ACL changes must avoid duplicate generation churn, expose per-phase timing, prefer port-scoped/diff apply, and keep full-resync rollback. |
| Logging governance | 06, 08, 09, 13, 14 | Production logs keep state transitions and failures visible while demoting high-frequency success paths, disabling non-product SSL noise in OpenStack mode, and avoiding duplicate Kolla log writes. |

## Stage-One Verification

Status: closed. Closure evidence is recorded in:

```text
docs/evidence/openstack-n05-lite/20260701-stage1-closure-summary.md
```

Use this focused check while implementing 01, 04, and 07:

```text
python ci/check_neutron_stage1.py
```

In an environment with Rust installed, require the Rust-side UDS/WAL checks:

```text
python ci/check_neutron_stage1.py --require-rust --rust-toolchain stable
```

The first command is allowed to skip Rust when `cargo` is unavailable; the
second command must fail if Rust cannot run.

Stage-one implementation status:

| Area | Current Evidence |
| --- | --- |
| 01 INI contract | `config.py` validates target layout constraints; `test_config.py` covers invalid domains, `integration_mode`, ACL source, full-resync gate, and stage-one request timeout. |
| 04 UDS contract | `docs/neutron-uds-contract.json`, Rust capabilities fields, Python client validation, UDS body/timeout limits, socket mode validation, config-gated `SO_PEERCRED` peer enforcement/audit hooks, exact smoke capability checks, and contract phase-status checks. |
| 07 Transaction/WAL | Python state/event-loop tests cover generation, pending snapshot/delete, timeout recovery; Rust WAL and `domain_authority` tests cover intent/commit/replay/hash plus managed-domain local write gating and are wired into the locked stage-one Rust check. The local stage-one script also statically verifies required Rust WAL/OpenAPI/recovery/gate source terms exist when `cargo` is unavailable. |
| 02/03 ACL production path | `aria_acl` has a stdlib-only repository/plugin contract, API extension descriptor, minimal persistent DB repository with minimum CRUD, minimal Alembic table creation, and `NeutronAclSource` can consume the effective payload/list contract through either injected methods or the aria_acl REST adapter. `ci/check_neutron_stage2_acl.py` guards the no-Security-Group/no-tag-mapping boundary plus the Neutron ACL source -> datapath snapshot path. |
| Local verification | `python ci/check_neutron_stage1.py` currently runs 161 Python tests and `bash -n` over smoke shell scripts, then skips Rust only when `cargo` is unavailable. |
| Rust verification | Closed by GitHub Actions run `28442974505` on commit `e476b2d1463988a84dc525f58bf01e46d0121146`; it ran `check_neutron_stage1.py --require-rust --rust-toolchain stable`, Rust tests, eBPF build, static userspace build, static agent build, and binary verification. No Rust/binary-trigger paths changed after that commit. |

## Stage-Two ACL MVP Field Evidence

The 2026-06-29 stage-two ACL MVP gate passed on `ostack2.bj159.net` and
`ostack3.bj159.net` with the packaged Kolla bundle. Evidence is recorded in:

```text
docs/evidence/openstack-n05-lite/2026-06-29-stage2-acl/summary.md
```

The final stage-two acceptance audit is recorded in:

```text
docs/evidence/openstack-n05-lite/2026-06-30-stage2-acceptance-summary.md
```

This evidence covers `aria_acl` plugin/API/DB, REST CRUD, `NeutronAclSource`,
full-resync, `aria_acl_port_statuses` reportback, and heartbeat summary fields.
It does not close full N0.5 or enable QoS/Mirror/RPC event consumption.

The 2026-06-30 read-only G4 discovery evidence is accepted by:

```text
python ci/check_n05_discovery_evidence.py
```

That acceptance covers target OS/kernel, OVS/tap facts, BTF/bpffs, UDS
readability, Neutron extension disposition, trunk/port-class disposition, and
the requirement that at least one target host has compute tap plus OVS
`iface-id` evidence. Repository/config gating now covers UDS peer
credential/audit hooks. Field evidence for UID/GID candidates is recorded in:

```text
docs/evidence/openstack-n05-lite/2026-06-30-uds-hardening-summary.md
```

That evidence shows `neutron_aria_agent` runs as UID/GID `42435`. A later
three-host reversible hardening proof accepted socket `root:42435 0660`,
peercred allow-list matching, audit output, and clean restore through
`REQUIRE_HARDENED=true` smoke. Persistent hardened rollout is still a
release/operations gate; it is not required to expand QoS/Mirror scope.
DHCP/metadata/IPv6 disposition now has bounded guest evidence: DHCP initial
lease passed, explicit renew is `not_applicable` for the current CirrOS image,
metadata reached the namespace proxy but the target metadata backend returned
HTTP 500/`ENOENT`, and IPv6 ND is `not_applicable` because the target Neutron
subnets are IPv4-only.

The first G7 rollback connectivity evidence is recorded in:

```text
docs/evidence/openstack-n05-lite/2026-06-30-g7-rollback-summary.md
```

It proves external/host -> VM ACL block and UDS rollback recovery on
`ostack2.bj159.net`, plus `neutron_aria_agent` and `aria_datapath`
stop/restart without OVS connectivity loss. Active direction evidence is
recorded in:

```text
docs/evidence/openstack-n05-lite/2026-06-30-active-direction-summary.md
```

Do not count host-initiated ping echo-reply as VM -> external evidence; it is
reverse traffic for a stateful inbound flow. The accepted VM -> external proof
uses a temporary CirrOS guest-originated ICMP loop: packets are visible before
the ACL, absent after generation `85` reaches UDS `ready`, and visible again
after UDS rollback. DHCP/metadata/IPv6 guest disposition is recorded in
`docs/evidence/openstack-n05-lite/20260630155334-ostack2.bj159.net-guest-bypass-probe/`;
metadata content HTTP 200 remains dependent on fixing the target metadata
backend socket, not on adding Aria product features. IPv6 ND remains not
applicable until an IPv6 network exists.

## QoS Detail Timing

QoS remains in the v0.9 first-stage scope. ACL and P3 are now closed enough to
open a QoS entry assessment, but not enough to implement shaping blindly.

The next QoS document is:

```text
docs/openstack-neutron-aria-details/11-qos-next-phase.md
```

It is an entry plan only. The 2026-07-02 Q0 refresh shows no visible Neutron QoS
extension and no host-shell `tc`, but Kolla containers do include `tc` and can
read qdisc from the shared network namespace. Implementation must still choose
one disposition before datapath work: `shaping`, `policing-only`, or
`unsupported/deferred`.

## Stage-Three ACL Production Hardening

Stage two is accepted. The next active plan is:

```text
docs/openstack-neutron-aria-details/08-stage3-acl-production-hardening.md
```

Use this check as the local stage-three guard:

```text
python ci/check_stage3_readiness.py
```

## Post-Stage-Three: Aria RPC And Incremental Sync

RPC-triggered full-resync (P2) and config-gated incremental port-scoped apply
(P3) have controlled acceptance evidence. The RPC design and scoped apply work
are recorded in:

```text
docs/openstack-neutron-aria-details/09-aria-rpc-incremental-sync.md
docs/openstack-neutron-aria-details/10-rust-scoped-apply.md
```

Do not enable P3 runtime behavior in packaged defaults. The Rust port-scoped
UDS route and Python single-port submitter are available for controlled testing
behind `incremental_rpc_enabled=true`; plan 09 records the accepted P3-4/P3-5/P3-6
failure, smoke, and rollback/runbook gates. Production rollout still requires a
separate revision-aware rollout decision.
Old Neutron environments without trustworthy `revision_number` stay on P2
full-resync fallback by default; `revisionless_incremental_mode=experimental`
is test-host only.
The current RPC hardening pass adds strict boolean parsing for production
enablement flags and exposes a `sync_mode` summary in logs/heartbeat:
`heartbeat_only`, `polling_full_resync`, `rpc_full_resync`,
`rpc_port_scoped`, or `rpc_port_scoped_revisionless_experimental`.

The 2026-07-09 P2.5 design adds Aria domain object RPC for `aria_acl`
policy/rule/binding/address-set changes. These events trigger merged
full-resync first, retain periodic full-resync recovery, and keep port-scoped
apply behind the existing P3 gates.

The 2026-07-02 P3-5 smoke evidence is recorded in:

```text
docs/evidence/openstack-n05-lite/20260702-p3-5-incremental-smoke/summary.md
```

It accepts package RPC event smoke, P2 full-resync A/B, controlled
revisionless experimental port-scoped apply, default revisionless fallback, and
rollback to zero managed ports on the old Neutron test host. The P3 acceptance
summary is recorded in:

```text
docs/evidence/openstack-n05-lite/20260702-p3-acceptance-summary/summary.md
```

P3-6 records the default-off production contract and rollback levels in plan 09
plus the operator runbook.

## QoS Next Phase

QoS is the next reasonable planning target, but not an immediate shaping
implementation. The target environment currently lacks visible Neutron QoS
extension support. Q0 refreshed the `tc` detail: host shells lack `tc`, while
Kolla containers have read-only qdisc visibility. QoS remains deferred until
Q1/Q2 status/authority gates and a Q4 datapath decision choose between shaping,
policing-only, or unsupported/degraded behavior.

Start here:

```text
docs/openstack-neutron-aria-details/11-qos-next-phase.md
```

## Out Of Scope For This Pass

- No unapproved tenant features beyond ACL and the QoS entry assessment.
- No QoS shaping implementation before target capability evidence exists.
- No Security Group projection.
- No OVS L2 replacement.
- No full object-level multi-writer authority model unless the domain-level
  `managed_domains` model is proven insufficient.

# 2026-06-30 Stage-Three N3 Evidence Summary

Status: active N3 validation started; schema gate is enabled.

Scope:

- Close ACL production hardening without expanding QoS or Mirror.
- Keep full-resync as the only production update model in this stage.
- Record fault and lifecycle outcomes as `pass`, `degraded`, `unsupported`,
  `not_applicable`, or `pending`.
- Treat `pending` as acceptable only while stage three is active. Final stage
  closure must pass `python ci/check_stage3_n3_evidence.py --require-complete`.

## N3 Evidence Matrix

| Gate | Category | Disposition | Evidence | Notes | Next Action |
| --- | --- | --- | --- | --- | --- |
| S3-1 release-ci | release | pass | GitHub Actions workflow dispatch `28438231005` on commit `082f002`; artifacts `firewall-binaries-x86_64` and `neutron-aria-stage2-acl-kolla-bundle-082f002a953c6bd74978732ec668fb8c0985ee37` were uploaded after payload policy passed. | Rust/eBPF, `ariactl`, and `aria-agent` compiled in CI; release creation stayed tag-only. | none |
| S3-2 uds-rollout | operations | pending | `docs/evidence/openstack-n05-lite/2026-06-30-uds-hardening-summary.md` covers reversible three-host proof. | Persistent hardened rollout has not been left enabled on target hosts. | Run `deploy/kolla/smoke/neutron_aria_uds_hardened_rollout_smoke.sh` as a controlled rollout or mark audit-only with explicit release approval. |
| S3-3 no-binding | fault | pass | `docs/evidence/openstack-n05-lite/20260630-stage3-no-binding-probe/summary.md` | Rerun on `ostack2.bj159.net` with the CI datapath artifact and Python timeout/reportback fix returned `agent_rc=0`, submitted snapshot generation 107, reported all five managed ACL domains as `not_requested` with `effective_action=bypass`, refreshed Neutron `aria_acl_port_statuses`, and rolled back to zero managed ports. | none |
| S3-3 missing-policy | fault | pass | `docs/evidence/openstack-n05-lite/20260630-stage3-missing-policy-probe/summary.md` | Direct fault injection inserted five temporary `aria_acl_bindings` rows that referenced a non-existent policy. Full-resync submitted generation 109, each managed ACL domain reported `degraded` with `effective_action=bypass` and `reason=policy_missing_or_disabled`, Neutron `aria_acl_port_statuses` refreshed to generation 109, a VM ping succeeded while degraded, and cleanup removed all temporary bindings and managed ports. | none |
| S3-3 apply-failure | fault | pass | `docs/evidence/openstack-n05-lite/20260630-stage3-apply-failure-probe/summary.md` | Representative one-shot ACL apply failure at `neutron.acl.after_policy_write` returned target port `error` without `effective_action=enforce`, preserved forwarding while partial, did not increase `wal_replay_failures`, recovered on the second full-resync, blocked ICMP while ACL was ready, rolled back to zero managed ports, and restored the hardened UDS config. | none |
| S3-3 uds-timeout-crash | fault | pending | `deploy/kolla/smoke/neutron_aria_crash_injection_smoke.sh` and `deploy/kolla/smoke/neutron_aria_transaction_state_smoke.sh` are available. | Need timeout/crash evidence that Python reports pending/degraded and recovery reconciles through full-resync/status. | Run crash/transaction smoke and capture WAL replay/idempotency output. |
| S3-3 rollback-connectivity | fault | pending | Stage-two G7 rollback passed in `docs/evidence/openstack-n05-lite/2026-06-30-g7-rollback-summary.md`. | Need N3 rollback record tied to the fault/lifecycle run set. | Re-run rollback connectivity after N3 fault probes and link the resulting evidence directory. |
| S3-4 ovs-restart | lifecycle | pending | No dedicated N3 evidence yet. | Need OVS restart behavior without stale-ready reporting. | Run controlled OVS restart or mark unsupported if target maintenance window is unavailable. |
| S3-4 tap-recreate | lifecycle | pending | `deploy/kolla/smoke/neutron_aria_tap_recreate_smoke.sh` is available. | Requires permission to reboot/recreate the test VM tap. | Run with `ALLOW_VM_REBOOT=true` on the test VM and capture before/after ifindex and status. |
| S3-4 vm-migration | lifecycle | pending | `deploy/kolla/smoke/neutron_aria_vm_migration_smoke.sh` is available. | Requires two compute hosts that can live/cold migrate the same test VM. | Run migration smoke if Nova supports it; otherwise record `unsupported` with Nova capability evidence. |
| S3-4 same-host-vm | lifecycle | pending | No dedicated N3 evidence yet. | Current accepted stage-two traffic evidence covers VM-to-external, not two same-host VMs. | Create or identify two same-host test VMs, or record `not_applicable` if scheduling cannot place them safely. |

## Verification Commands

```bash
python ci/check_stage3_n3_evidence.py
python ci/check_stage3_n3_evidence.py --require-complete
```

Current expected result:

- Plain schema gate: pass.
- `--require-complete`: fail until the pending N3 fault/lifecycle rows are
  replaced with `pass`, `degraded`, `unsupported`, or `not_applicable`.

## Guardrails

- Do not add QoS/Mirror scope to close these gates.
- Do not treat target metadata HTTP 500 as an Aria bug unless a new probe proves
  Aria changed the path.
- Do not leave temporary ACL bindings, test VMs, or managed datapath ports after
  each smoke run.
- Do not use host SSH probes as product runtime behavior; they are evidence
  collection only.

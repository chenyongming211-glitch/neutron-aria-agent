# 2026-06-30 Stage-Two Acceptance Summary

Status: stage-two ACL MVP acceptance passed.

Scope:

- Complete the production ACL input loop through `aria_acl`.
- Do not expand QoS or Mirror.
- Accept G4/N0.5 evidence needed by stage two.
- Accept G5/G6 production ACL source and full-resync evidence.
- Accept G7 rollback, active traffic, and UDS hardening evidence.

## Acceptance Matrix

| Requirement | Disposition | Evidence |
| --- | --- | --- |
| G0 package gate | pass for MVP | `dist/kolla/neutron-aria-stage2-acl-kolla-bundle.tgz` rebuild succeeded; image registry release remains later governance, not a stage-two MVP blocker. |
| G4/N0.5 discovery | pass | `docs/evidence/openstack-n05-lite/2026-06-30-discovery-summary.md`; `python ci/check_n05_discovery_evidence.py` accepts three hosts with zero `fail`. |
| DHCP/metadata/IPv6 disposition | pass with target metadata caveat | `docs/evidence/openstack-n05-lite/20260630155334-ostack2.bj159.net-guest-bypass-probe/`: DHCP initial lease passed; metadata reached Neutron proxy but target backend returned HTTP 500/`ENOENT`; IPv6 ND is `not_applicable`. |
| G5 production ACL source | pass | `docs/evidence/openstack-n05-lite/2026-06-29-stage2-acl/summary.md`: `aria_acl` extension/API/DB, CRUD, and `NeutronAclSource` passed on `ostack2` and `ostack3`. |
| G6 full resync | pass | `ostack2` applied five ACL-managed ports and rolled them back; `ostack3` handled zero local compute ports cleanly. |
| Port status and heartbeat | pass | `aria_acl_port_statuses` reportback, `last_reported_at`, `stale`, `runtime_status`, generation lag, and degraded reason summary are recorded in the stage-two ACL evidence. |
| G7 rollback/connectivity | pass | `docs/evidence/openstack-n05-lite/2026-06-30-g7-rollback-summary.md`: baseline ping, ACL block, UDS rollback, post-rollback recovery, and agent/datapath stop-restart connectivity passed. |
| Active traffic direction | pass | `docs/evidence/openstack-n05-lite/2026-06-30-active-direction-summary.md`: external/host -> VM and VM -> external/host are accepted; the rejected host-initiated egress proof is explicitly excluded. |
| UDS hardening gate | pass for reversible field proof | `docs/evidence/openstack-n05-lite/2026-06-30-uds-hardening-summary.md`; `ci/check_uds_hardening_evidence.py --require-hardened` accepts all three hosts. Persistent rollout remains a release/operations item. |
| QoS/Mirror boundary | pass | Stage-two evidence and runbook keep QoS/Mirror out of scope; no gate opened for QoS/Mirror. |
| Cleanup | pass | Final remote scan showed no `aria-n05` server/image/keypair/tmp residue and UDS status had `managed_ports=[]`, `active_instances=[]`. |

## Verification Commands

```bash
python ci/check_stage2_acceptance_evidence.py
python ci/check_n05_discovery_evidence.py
python ci/check_uds_hardening_evidence.py \
  --evidence-dir docs/evidence/openstack-n05-lite/20260630131254-ostack2.bj159.net \
  --evidence-dir docs/evidence/openstack-n05-lite/20260630133213-ostack3.bj159.net \
  --evidence-dir docs/evidence/openstack-n05-lite/20260630133213-ostack4.bj159.net \
  --min-hosts 3 \
  --require-hardened
python ci/check_neutron_stage2_acl.py
python ci/check_neutron_stage1.py
bash deploy/kolla/package/build_stage2_acl_bundle.sh
git diff --check
```

Latest local results:

- `check_stage2_acceptance_evidence.py`: accepted, `checked_files=10`.
- `check_n05_discovery_evidence.py`: accepted, `hosts=3`, zero `fail`.
- `check_uds_hardening_evidence.py --require-hardened`: accepted, `hosts=3`.
- `check_neutron_stage2_acl.py`: 82 tests passed.
- `check_neutron_stage1.py`: 159 tests passed; Rust tests were skipped locally because `cargo` was unavailable.
- `build_stage2_acl_bundle.sh`: rebuilt `dist/kolla/neutron-aria-stage2-acl-kolla-bundle.tgz`.
- `git diff --check`: no whitespace errors; only line-ending conversion warnings.

## Non-Blocking Caveats

- Target metadata content still returns HTTP 500 because the Neutron metadata
  namespace proxy cannot connect to its backend Unix socket. This is target
  environment degraded state, not an Aria ACL block.
- Persistent UDS hardening rollout is not left enabled on the three hosts. The
  reversible proof passed and restored the baseline; persistent rollout belongs
  to release/operations.
- Local `check_neutron_stage1.py` skipped Rust execution because `cargo` was not
  installed. CI or a Rust-enabled environment should still run the locked Rust
  command before a formal tag release.
- Full product N0.5/N3 items outside the stage-two ACL MVP, such as legacy path
  audits, persistent hardening, and future incremental event gates, remain
  tracked separately and do not expand this stage-two goal.

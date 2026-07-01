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
| S3-2 uds-rollout | operations | pass | `docs/evidence/openstack-n05-lite/20260701-stage3-uds-persistent-rollout/summary.md` | Persistent UDS hardening is enabled on all three target hosts. `REQUIRE_HARDENED=true` smoke passed for `ostack2.bj159.net`, `ostack3.bj159.net`, and `ostack4.bj159.net`; active sockets are non-world-writable with peercred enforcement and allowed audit records. The rollout did not restart OVS, OVS agent, or `neutron_aria_agent`. | none |
| S3-3 no-binding | fault | pass | `docs/evidence/openstack-n05-lite/20260630-stage3-no-binding-probe/summary.md` | Rerun on `ostack2.bj159.net` with the CI datapath artifact and Python timeout/reportback fix returned `agent_rc=0`, submitted snapshot generation 107, reported all five managed ACL domains as `not_requested` with `effective_action=bypass`, refreshed Neutron `aria_acl_port_statuses`, and rolled back to zero managed ports. | none |
| S3-3 missing-policy | fault | pass | `docs/evidence/openstack-n05-lite/20260630-stage3-missing-policy-probe/summary.md` | Direct fault injection inserted five temporary `aria_acl_bindings` rows that referenced a non-existent policy. Full-resync submitted generation 109, each managed ACL domain reported `degraded` with `effective_action=bypass` and `reason=policy_missing_or_disabled`, Neutron `aria_acl_port_statuses` refreshed to generation 109, a VM ping succeeded while degraded, and cleanup removed all temporary bindings and managed ports. | none |
| S3-3 apply-failure | fault | pass | `docs/evidence/openstack-n05-lite/20260630-stage3-apply-failure-probe/summary.md` | Representative one-shot ACL apply failure at `neutron.acl.after_policy_write` returned target port `error` without `effective_action=enforce`, preserved forwarding while partial, did not increase `wal_replay_failures`, recovered on the second full-resync, blocked ICMP while ACL was ready, rolled back to zero managed ports, and restored the hardened UDS config. | none |
| S3-3 uds-timeout-crash | fault | pass | `docs/evidence/openstack-n05-lite/20260701-stage3-uds-timeout-crash-probe/summary.md` | Crash smoke recovered pending snapshot and pending delete after agent restart, restarted datapath to verify replay/status recovery, then rolled back to zero managed ports. Transaction smoke separately recovered pending snapshot, pending delete, and migration-source cleanup state. Final status was `ready`, `pending_generation=null`, `managed_ports=[]`, and `wal_replay_failures` did not increase from the historical baseline. | none |
| S3-3 rollback-connectivity | fault | pass | `docs/evidence/openstack-n05-lite/20260701-stage3-rollback-connectivity-probe/summary.md` | Rollback connectivity smoke passed on `ostack2.bj159.net`: baseline ping, ACL full-resync generation 136, rollback to zero managed ports, post-rollback ping, agent stop/restart connectivity, and datapath stop/restart connectivity all passed. WAL replay failures stayed at the historical baseline `219`; the datapath restart subcheck reported `replayed_with_errors` from that existing baseline, with no counter increase. | none |
| S3-4 ovs-restart | lifecycle | pass | `docs/evidence/openstack-n05-lite/20260701-stage3-ovs-restart-acl-focused-probe/summary.md` | ACL-focused OVS restart smoke passed on `ostack2.bj159.net`: test harness explicitly restarted `ovs-vswitchd.service`, target tap stayed present with ifindex 71 and XDP attached, ACL status stayed `ready/effective_action=enforce` at generation 148, ACL maps remained visible, rollback left zero managed ports, WAL replay failures stayed at the historical baseline `219`, and VM forwarding recovered after 8 seconds. Production Aria runtime must not trigger OVS restart; this was a test-only harness action. | none |
| S3-4 tap-recreate | lifecycle | pass | `docs/evidence/openstack-n05-lite/20260701-stage3-tap-recreate-probe/summary.md` | Controlled hard reboot recreated the test VM tap on `ostack2.bj159.net`; ifindex changed from `48` to `69`. Full-resync generation 139 re-associated the target port with the new ifindex, rollback left zero managed ports, final ping passed, and WAL replay failures stayed at the historical baseline `219`. | none |
| S3-4 vm-migration | lifecycle | pass | `docs/evidence/openstack-n05-lite/20260701-stage3-vm-migration-probe/summary.md` | Bidirectional live migration passed for the controlled test VM: `ostack2.bj159.net -> ostack3.bj159.net -> ostack2.bj159.net`. Source hosts cleaned managed state after binding moved away, destination hosts applied after full-resync saw the new binding, rollback left zero managed ports, and WAL replay failure counters did not increase. | none |
| S3-4 same-host-vm | lifecycle | pass | `docs/evidence/openstack-n05-lite/20260701-stage3-same-host-vm-probe/summary.md` | Temporary same-host guest `10.58.159.43` proved guest-originated ICMP to target guest `10.58.159.28`: baseline ping passed, ACL full-resync generation 144 reported the temporary port `ready` with `effective_action=enforce`, the ICMP probe was blocked while ACL was active, rollback left zero managed ports, and post-rollback ping passed. | none |

## Verification Commands

```bash
python ci/check_stage3_n3_evidence.py
python ci/check_stage3_n3_evidence.py --require-complete
```

Current expected result:

- Plain schema gate: pass.
- `--require-complete`: pass when this matrix remains free of `pending` rows.

## Guardrails

- Do not add QoS/Mirror scope to close these gates.
- Do not treat target metadata HTTP 500 as an Aria bug unless a new probe proves
  Aria changed the path.
- Do not leave temporary ACL bindings, test VMs, or managed datapath ports after
  each smoke run.
- Do not use host SSH probes as product runtime behavior; they are evidence
  collection only.

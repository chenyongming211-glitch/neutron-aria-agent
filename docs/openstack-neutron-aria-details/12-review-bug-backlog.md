# Review Bug Backlog

Status: open review backlog.

Date: 2026-07-03; refreshed 2026-07-08.

Scope rule:

- Fix bugs and contract gaps discovered during review.
- Do not use this backlog to add new ACL/QoS/Mirror product features.
- Prefer API/config validation and narrowly scoped tests over new behavior.

## 2026-07-08 Full Review Refresh

The 2026-07-08 full-code review confirmed that the highest-risk findings are
already represented by existing backlog IDs. No new ACL/RPC feature work should
be added while closing this list.

Confirmed still open:

- `REVIEW-ACL-001`: `default_action=deny` is accepted by Neutron API/legacy CLI
  but rejected by the Rust datapath translator.
- `REVIEW-ACL-009`: ACL rule API/CLI still accept fields outside the current MVP
  translator contract, including source-port matching and IPv6 inputs.
- `REVIEW-ACL-012`: the Kolla agent egg installer still copies the egg into
  `site-packages` without a clean setuptools/easy-install path update.
- `REVIEW-ACL-003`: Neutron DB address-set row/member updates are still split
  across transactions.
- `REVIEW-ACL-006`: aria_acl repository errors still lack a legacy-Neutron-safe
  HTTP error mapping layer.
- `REVIEW-ACL-018`: root `install.sh` still fails `bash -n` because of CRLF
  line endings.
- `REVIEW-ACL-010`: DB CRUD smoke still uses `ADMIN_RC_FILE` without defining a
  default value.
- `REVIEW-ACL-014`: GitHub workflow still grants `contents: write` globally.

Review note:

- P3 port-scoped apply was reviewed for false-success commits. Current Python
  and Rust paths check per-port errors plus generation/hash convergence, so no
  new bug ID is recorded for that path in this pass.

## Open Bugs

| ID | Severity | Area | Status | Finding | Required fix |
| --- | --- | --- | --- | --- | --- |
| REVIEW-ACL-001 | P1 | ACL API/CLI/datapath contract | open | Neutron API and legacy CLI allow `default_action=deny`, but the Rust Neutron ACL translator rejects non-allow defaults. A user can create a policy that looks valid and later gets degraded/bypassed during apply. | For MVP, reject `default_action=deny` in server-side validation and CLI help/choices, or mark it explicitly unsupported until datapath default-deny support is implemented. Add API, CLI, and translator contract tests. |
| REVIEW-ACL-002 | P2 | ACL desired-state validation | open | Server-side create/update accepts multiple enabled bindings for the same `(target_type, target_id)` and duplicate rule priorities inside a policy/direction. Effective ACL later degrades to bypass. | Reject conflicting enabled binding writes with 409/validation error. Reject duplicate enabled rule priority per `(policy_id, direction)`. Add repository/plugin tests for create and update paths. |
| REVIEW-ACL-003 | P2 | ACL DB transactionality | open | Neutron DB address-set writes update the main address-set row and members in separate transactions. A mid-operation failure can leave the main row updated while members remain stale. | Wrap address-set create/update/delete plus member replacement/removal in one transaction. Add a failure-injection/unit test that proves no partial member state is committed. |
| REVIEW-ACL-004 | P3 | Port runtime status API/CLI | open | `aria_acl_port_statuses` is keyed by `(port_id, host)`, but `get_aria_acl_port_status(port_id, host=None)` returns the first row, and legacy CLI show has no `--host` selector. Multi-host or detached retained rows can be misleading. | Require host for single-row show when multiple rows exist, or return a clear ambiguity error/list. Add CLI/API tests for multi-host status rows. |
| REVIEW-ACL-005 | P3 | Legacy neutron CLI test coverage | open | Local `neutronclient_aria` unit tests skip when legacy `python-neutronclient` is absent, so CI can miss CLI command regressions outside onsite smoke. | Add a small fake/stub test path that exercises command body construction without a real neutronclient install, or add a legacy container CI job. Keep onsite smoke as integration evidence. |
| REVIEW-ACL-006 | P2 | Neutron REST error semantics | open | Repository failures such as `AriaAclValidationError` and `AriaAclNotFound` are plain Python exceptions. The service plugin passes them through directly, so old Neutron controllers can expose invalid requests or missing resources as HTTP 500 instead of 400/404. | Add a legacy-Neutron-compatible exception mapping layer in the plugin or exception classes. Cover missing policy, invalid binding target type, duplicate/unsupported writes, and missing object show/delete with API-level tests. |
| REVIEW-ACL-007 | P2 | Kolla package rollback | open | `install_neutron_aria_agent_egg.sh` only records a rollback backup when an old egg exists. First-time installs leave no "none" marker, so rollback fails instead of removing the newly installed agent egg. The CLI package installer already handles this correctly. | Mirror the CLI installer behavior: write a `.none` marker when no previous agent egg exists, and on rollback remove the agent egg and `easy-install.pth` entry. Add shell/unit smoke coverage for first-install rollback. |
| REVIEW-ACL-008 | P3 | Port status consistency | open | If a host was previously ready and a later full resync becomes globally degraded, `mark_degraded()` keeps old `last_port_statuses`. The port-status reporter can continue writing old per-port rows as `ready/enforce` while the agent heartbeat is degraded. | On global degraded, either mark existing ACL port statuses as degraded with the global reason or suppress per-port status writes until the next successful apply. Add a regression test with ready status followed by local API/ACL-source degraded. |
| REVIEW-ACL-009 | P1 | ACL rule API/datapath contract | open | The API/CLI accept rule fields that the Rust translator does not support yet, including source-port matching, IPv6 ethertype/CIDRs, and unvalidated protocol/action values. `EffectiveAclIndex` can mark such rules `ready/enforce`, but datapath apply later fails and the port falls back to degraded/bypass. | Add server-side and CLI validation for the current MVP-supported rule subset, and make `EffectiveAclIndex` return degraded/unsupported before submit for unsupported fields. Cover source-port, IPv6, unknown protocol, unknown action, and bad port range cases. |
| REVIEW-ACL-010 | P3 | Stage-two smoke reliability | open | `neutron_aria_acl_db_crud_smoke.sh` sources an adminrc file but never defines `ADMIN_RC_FILE`; later it runs `docker exec --env-file "${ADMIN_RC_FILE}"` under `set -u`. On a clean host without that variable already exported, the CRUD smoke can fail before testing ACL. | Add the same `ADMIN_RC_FILE="${ADMIN_RC_FILE:-/etc/kolla/.adminrc}"` default used by the CLI/live smokes, or derive it from the sourced adminrc path. Add shellcheck or a smoke syntax check for unset variables. |
| REVIEW-ACL-011 | P3 | Public release hygiene | open | A repository-wide sensitive-term scan did not find the previously blocked product acronym or environment password, but public-facing docs/metadata still contain personal repository/email and environment hostname identifiers. | Scrub or generalize public docs/metadata before public release. Keep the blocked-term CI gate, and extend it to cover agreed public-release identifiers without recording the sensitive strings in this backlog. |
| REVIEW-ACL-012 | P1 | Kolla agent package install | open | `install_neutron_aria_agent_egg.sh` copies the zipped `neutron_aria` egg into `site-packages` but does not install it with setuptools or add it to `easy-install.pth`. A fresh container without an existing path entry may fail to import `neutron_aria` or find the `neutron-aria-agent` console entry point; the current test environment can mask this because previous installs already left import-path state. | Install the agent package the same way as the legacy CLI package, or explicitly update `easy-install.pth`/console script entries when copying the egg. Add a clean-container package smoke that starts with no previous egg and no path entry. |
| REVIEW-ACL-013 | P3 | Neutron port extension projection | open | The extension declares read-only `ports` fields such as `aria_acl_enabled`, `aria_acl_effective_policy_id`, and `aria_acl_runtime_status`, and product docs show them in `port-show`; review found only attribute declaration, not a Neutron port-dict extension hook that fills those values from effective ACL and `aria_acl_port_statuses`. | Either implement the legacy Neutron port extension hook/populator and smoke `neutron port-show`, or narrow the MVP contract to the explicit `aria-acl-port-status*`/effective APIs until port projection is implemented. |
| REVIEW-ACL-014 | P3 | GitHub release permissions | open | `.github/workflows/build.yml` grants `contents: write` at workflow scope, so normal push/PR validation jobs run with broader repository token permissions than they need. Artifact upload does not require repository content write; only tag release creation needs it. | Set default workflow permissions to read-only and grant `contents: write` only to the release job/step that creates GitHub Releases. Keep artifact upload unchanged. |
| REVIEW-ACL-015 | P3 | Plugin loader rollback | open | `neutron_aria_acl_plugin_load_smoke.sh` backs up `policy.json` only when it already exists. If the install creates a new policy file and rollback is requested, rollback restores `neutron.conf` and package state but leaves the newly created policy file in place. | Mirror the package rollback marker pattern: record a "no previous policy file" marker and remove the smoke-created policy file during rollback. Add first-install rollback coverage for the plugin loader. |
| REVIEW-ACL-016 | P2 | Agent config safety | fixed | Boolean config parsing accepted only known true values and treated every other non-empty string as `false`. A typo such as `full_resync_enabled = ture` silently disabled ACL submit and left the agent in heartbeat-only/degraded mode instead of failing fast with a config error. | Fixed in `agent/config.py`: `full_resync_enabled`, `rpc_events_enabled`, and `incremental_rpc_enabled` now use strict boolean parsing and raise `ConfigError` with section/option/value on invalid values. Unit tests cover typo cases. |
| REVIEW-ACL-017 | P3 | Legacy CLI package smoke | open | `install_neutronclient_aria_cli.sh` hard-codes `/etc/kolla/.adminrc` during command-discovery smoke, while other ACL smokes allow `ADMIN_RC_FILE` override. Sites with a different Kolla/adminrc location can install the CLI package but fail the built-in smoke for an avoidable path assumption. | Add `ADMIN_RC_FILE="${ADMIN_RC_FILE:-/etc/kolla/.adminrc}"` to the installer and use it in smoke, with a clear error if the file is missing. Add a shell smoke/syntax check that exercises a custom adminrc path. |
| REVIEW-ACL-018 | P2 | Root install script | open | The repository README recommends `install.sh` as the one-click install/update entry, but the tracked script still has CRLF line endings. `bash -n install.sh` fails on Linux at the first function definition before any install logic can run. | Normalize `install.sh` to LF and valid UTF-8, preserve executable semantics, and add it to CI/script syntax checks so release artifacts cannot ship an unusable install entry again. |

## Verification At Time Of Recording

- `python -m unittest discover -s openstack/neutron_aria/neutron_aria/tests/unit -v`: 214 tests passed.
- `python -m unittest discover -s openstack/neutronclient_aria/neutronclient_aria/tests -v`: 4 tests skipped because legacy neutronclient is not installed locally.
- `python ci/check_neutron_stage1.py`: passed; 214 Python tests passed, Rust checks skipped locally because cargo is unavailable.
- `python ci/check_neutron_stage2_acl.py`: passed; after RPC sync-mode hardening, 98 tests passed.
- `python ci/check_stage2_acceptance_evidence.py`: passed.
- `python ci/check_stage3_readiness.py`: passed.
- `python ci/check_stage3_n3_evidence.py`: passed.
- `python ci/check_payload_terms.py dist/kolla/neutron-aria-stage2-acl-kolla-bundle.tgz`: passed.
- `python ci/check_blocked_terms.py`: passed.
- `git diff --check`: passed for this backlog patch; one unrelated pre-existing HTML line-ending warning remains outside this review change.
- `bash -n` over deploy/ci shell scripts using POSIX-style paths: 37 scripts passed.
- Continued targeted review of agent config, RPC event routing, incremental fallback, and CLI package smoke found `REVIEW-ACL-016` and `REVIEW-ACL-017`; `REVIEW-ACL-016` is now fixed by strict boolean parsing and config unit tests.
- `python -m unittest neutron_aria.tests.unit.test_config -v`: 27 tests passed after the strict RPC boolean parsing and sync-mode helper fix.
- `python -m unittest neutron_aria.tests.unit.test_config neutron_aria.tests.unit.test_status_reporter neutron_aria.tests.unit.test_service neutron_aria.tests.unit.test_rpc -v`: 64 tests passed for RPC/config/status/service coverage.
- `python -m compileall -q openstack/neutron_aria/neutron_aria openstack/neutronclient_aria/neutronclient_aria`: passed.
- `python ci/check_smoke_python_blocks.py`: passed, 89 embedded smoke Python blocks accepted.
- `bash -n` over tracked `deploy/` and `ci/` shell scripts: 37 scripts passed.
- `bash -n install.sh`: failed on CRLF line endings, recorded as `REVIEW-ACL-018`.

## Verification Refresh 2026-07-08

- `python ci\check_neutron_stage1.py`: passed; Rust checks skipped locally
  because `cargo` is unavailable.
- `python ci\check_neutron_stage2_acl.py`: passed.
- `python ci\check_blocked_terms.py`: passed.
- `git diff --check`: passed; only line-ending warnings were reported.
- `bash -n install.sh`: failed with CRLF syntax error, confirming
  `REVIEW-ACL-018`.

## Fix Order

1. `REVIEW-ACL-001`: close the user-visible default-action contract mismatch first.
2. `REVIEW-ACL-009`: reject or pre-degrade unsupported rule fields before datapath submit.
3. `REVIEW-ACL-012`: make fresh package install independent of prior container state.
4. `REVIEW-ACL-002`: prevent operator mistakes from silently degrading ACL.
5. `REVIEW-ACL-006`: return correct old-Neutron API errors before field use grows.
6. `REVIEW-ACL-003`: tighten DB transaction safety.
7. `REVIEW-ACL-018`: make the README-recommended root installer runnable on Linux.
8. `REVIEW-ACL-007`: make rollback reliable for first-time package rollout.
9. `REVIEW-ACL-004`: improve status/operator correctness.
10. `REVIEW-ACL-008`: keep per-port status aligned with global degraded state.
11. `REVIEW-ACL-010`: make stage-two CRUD smoke self-contained.
12. `REVIEW-ACL-013`: close or explicitly defer `port-show` projection.
13. `REVIEW-ACL-015`: make plugin loader rollback clean on first install.
14. `REVIEW-ACL-017`: make legacy CLI package smoke work with non-default adminrc paths.
15. `REVIEW-ACL-011`: scrub public-release identifiers before the next public artifact.
16. `REVIEW-ACL-014`: reduce GitHub token permissions before the next public release.
17. `REVIEW-ACL-005`: improve test coverage after behavior fixes.

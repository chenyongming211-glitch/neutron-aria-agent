# API / CLI Consistency Probe

Date: 2026-07-03

Scope: validate whether the deployed `aria_acl` Neutron REST API and the
legacy `neutron` CLI expose the same ACL management surface.

## Result

| Check | Result | Notes |
| --- | --- | --- |
| Neutron client version | observed | `2016.9.9` |
| `aria-acl` REST extension | pass | `/v2.0/extensions` reports alias `aria-acl`. |
| Initial legacy `neutron aria-acl-*` commands | fail | Before the client package was installed, `neutron help` did not list `aria-acl-*`; direct `neutron aria-acl-policy-list` returned `Unknown command`. |
| Legacy CLI package install | pass | Installed `neutronclient-aria==0.1.0` into the `openstack_client` container. |
| Legacy `neutron aria-acl-*` command discovery | pass | `neutron help` listed 22 `aria-acl-*` commands. |
| API creates, CLI reads | pass | policy, rule, address-set, and disabled binding were created through REST API and read through `neutron aria-acl-*`. |
| CLI creates, API reads | pass | policy, rule, address-set, and disabled binding were created through `neutron aria-acl-*` and read through REST API. |
| Status CLI | pass | `neutron aria-acl-port-status-list` returned successfully. |
| Cleanup | pass | Temporary policy/rule/address-set/binding objects were deleted; no policy with the test run prefix remained. |

## Conclusion

The deployed Neutron server API and the legacy `neutron` CLI are now consistent
for the first-stage `aria_acl` management surface after installing the
`neutronclient-aria` command extension into the `openstack_client` container.

The original failure was not an ACL service plugin failure. It was a client
packaging gap:

- API/manual curl path worked before the CLI package existed.
- `neutron aria-acl-policy-*`, `aria-acl-rule-*`, `aria-acl-address-set-*`,
  `aria-acl-binding-*`, and `aria-acl-port-status-*` commands are available
  after installing the legacy neutronclient extension.

## Delivered Assets

- `openstack/neutronclient_aria/`
- `deploy/kolla/package/install_neutronclient_aria_cli.sh`
- `deploy/kolla/smoke/neutron_aria_acl_cli_consistency_smoke.sh`

The stage-two ACL gate now installs the CLI package and runs the API/CLI
consistency smoke.

# Changelog

## 0.9.0-rc.1

- Added the production `aria_acl` Neutron API, DB, legacy CLI, agent source,
  RPC-triggered reconciliation, status, and rollback delivery path.
- Made TC ingress and egress the managed ACL/conntrack authority while keeping
  XDP ACL/conntrack-neutral.
- Added WAL recovery, UDS peer credential enforcement, readiness contracts,
  legacy-kernel stack-budget enforcement, and Kolla packaging gates.
- Added a deterministic release manifest, checksums, support matrix, and
  reversible `aria-datapath` RC image lifecycle entrypoint.

This is a release candidate. Three-compute P5 acceptance and formal release
promotion remain open until the unavailable compute completes the same gates.

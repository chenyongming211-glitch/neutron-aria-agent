# N0.5 DHCP / Metadata / IPv6 Read-Only Service Path Evidence

Host: `ostack2.bj159.net`
Run: `20260630153231`

This record is read-only service-path evidence. The bounded guest-side follow-up
is recorded in
`docs/evidence/openstack-n05-lite/20260630155334-ostack2.bj159.net-guest-bypass-probe/`.

## Results

- DHCP agent: observed in Neutron agent list on `ostack2.bj159.net` and
  `ostack3.bj159.net`.
- Metadata agent: observed in Neutron agent list on `ostack2.bj159.net` and
  `ostack3.bj159.net`.
- DHCP service ports: none shown by the legacy `neutron port-list` table output
  for the current sample; DHCP agents are alive and should remain outside Aria
  ACL enforcement.
- IPv6 ND: `not_applicable` for the current target networks because
  `neutron subnet-list` shows only IPv4 CIDRs and no IPv6 subnet/global route
  evidence.
- Guest-side follow-up disposition: DHCP initial lease passed; explicit renew is
  `not_applicable` for the CirrOS image because it has no executable `udhcpc`;
  metadata requests reached the namespace proxy but returned HTTP 500 due to
  backend Unix socket `ENOENT`, recorded as target metadata service degraded.

## Evidence Files

- `neutron-agents.txt`
- `neutron-subnets.txt`
- `neutron-service-ports.txt`
- `uds-status.txt`
- `cleanup-scan.txt`

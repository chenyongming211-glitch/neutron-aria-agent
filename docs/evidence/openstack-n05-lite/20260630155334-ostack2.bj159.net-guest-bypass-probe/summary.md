# Bounded DHCP / Metadata / IPv6 ND Guest Probe Summary

Host: `ostack2.bj159.net`
Run: `20260630155334`
Temporary VM: `aria-n05-guestprobe-20260630155334` / `10.58.159.40`
Neutron port: `504835d3-2df3-4901-a8fe-ebb2213bf0ec`
Network: `23eb9d08-ec8b-4610-a1ff-61492134b6d2`

## Results

- DHCP initial request/lease: pass. Guest `eth0` received dynamic IPv4
  `10.58.159.40/25`, and `service-logs.txt` shows `DHCPOFFER`,
  `DHCPREQUEST`, and `DHCPACK` from Neutron dnsmasq.
- DHCP renew command: not_applicable for this CirrOS image. The image has a
  DHCP lease but does not include an executable `udhcpc` client, so the explicit
  renew sub-command exits before sending a renew packet.
- Metadata network path: pass/degraded. The guest has a route to
  `169.254.169.254` via `10.58.159.24`, and the Neutron metadata namespace proxy
  accepted the guest HTTP request. The endpoint returned HTTP 500 because the
  metadata proxy could not connect to its backend Unix socket (`ENOENT`), which
  is a target-environment metadata service issue, not an Aria ACL block.
- IPv6 ND: not_applicable for this network; no IPv6 subnet/global route found.

## Exit Codes

- baseline: 0
- dhcp: 1
- metadata: 1
- ipv6: 0

## Evidence Files

- `ssh-precheck.txt`
- `guest-baseline.txt`
- `dhcp-renew.txt`
- `metadata-probe.txt`
- `ipv6-nd-probe.txt`
- `service-logs.txt`
- `neutron-subnet-list.txt`
- `uds-status-before.json` / `uds-status-after.json`
- `cleanup-final.txt`

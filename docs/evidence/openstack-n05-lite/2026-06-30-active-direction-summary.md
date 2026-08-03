# 2026-06-30 Active Direction Evidence Summary

Status: external/host-to-VM and VM-to-external active ACL directions are
accepted for the stage-two N0.5 gate.

## Accepted Evidence

| Direction | Evidence Path | Result |
| --- | --- | --- |
| external/host -> VM | `docs/evidence/openstack-n05-lite/20260630115838-compute-1.example.test/` | pass |
| VM -> external/host | `docs/evidence/openstack-n05-lite/20260630145200-compute-1.example.test-cirros-vm-egress-final/` | pass, with manual post-timeout verification |

The accepted rollback smoke applied an ACL full-resync to
`86b83885-671f-474c-9556-8af98cf1cdc8` / `tap86b83885-67`, blocked ICMP from
`192.0.2.2/32` to VM `192.0.2.26`, deleted all managed ports through UDS,
and confirmed post-rollback connectivity.

The accepted VM-originated egress evidence used a temporary CirrOS raw image and
a short-lived VM `192.0.2.35` on `compute-1.example.test`. SSH key injection was
verified, a guest-side ping loop generated ICMP from `192.0.2.35` to
`192.0.2.2`, and host-side tcpdump proved:

- before ACL: ICMP echo request captured;
- after egress ACL generation `85` reached UDS `ready`: no matching ICMP packet
  captured during the check window;
- after UDS rollback: ICMP echo request captured again and `managed_ports=[]`.

The `neutron-aria-agent --once` command timed out while waiting for generation
`85`, but the post-timeout UDS status showed `accepted_generation=85`,
`applied_generation=85`, domain status `ready`, and the packet checks proved the
datapath behavior. The temporary VM, keypair, image, and host/container temp
files were removed after the evidence run; Nova keeps deleted audit records.

## Rejected Probe

| Probe | Evidence Path | Result |
| --- | --- | --- |
| host ping VM with `ACL_DIRECTION=egress` | `docs/evidence/openstack-n05-lite/20260630121023-compute-1.example.test/` | fail, not accepted as VM-to-external evidence |

This probe successfully submitted generation `84` and installed a datapath ACL
policy with `direction=ingress`, `dst_group=192.0.2.2/32`, then rolled back to
`managed_ports=[]`. The ping was not blocked.

The result is not counted as VM-to-external failure of the product ACL feature.
It is an invalid proof shape for VM-originated traffic because a host-initiated
ping creates an inbound request and a VM echo-reply. Under the current stateful
ACL model, that echo-reply is reverse traffic for the host-initiated flow, not a
new VM-initiated flow. VM-to-external acceptance needs traffic generated from
inside the VM or from a dedicated test VM with an explicit guest execution path.

## Guest Access Check

Detailed read-only audit:
`docs/evidence/openstack-n05-lite/20260630134000-compute-1.example.test-guest-access-audit/`

| Check | Result |
| --- | --- |
| `wp-test` / `192.0.2.26` | `waf-20250613-8.1.6.86485`, `key_name=null`, SSH timed out, QEMU guest agent not configured |
| `test1111` / `192.0.2.27` | `icg-20230728-10.1.0`, `key_name=null`, SSH refused, console is `SecOS login:`, QEMU guest agent not configured |
| `cym_vfw1` / `192.0.2.28` | `vfw-20250925-6.1.13.174515`, `key_name=null`, SSH reachable but existing root/admin/centos key auth denied, console is `NSG-VM Username:`, QEMU guest agent not configured |
| `cym_hlas_test` / `192.0.2.29` | `hlas-20251025-v6.332p2`, `key_name=null`, SSH refused, console is Rocky Linux `LAS login:`, cloud-init fallback datasource, QEMU guest agent not configured |
| Legacy image/keypair path | Legacy `nova`/`glance` clients can list product images and create an RSA keypair; the newer `openstack image list` path still returns HTTP 404 in this client context |

No passwords were guessed and no guest disk or console injection was attempted.

## Short-Lived Test VM Probes

Detailed evidence:
`docs/evidence/openstack-n05-lite/20260630140500-compute-1.example.test-temporary-test-vm/`

| Probe | Result |
| --- | --- |
| `qcsp-20241205-v1.2.0.9` / `192.0.2.30` | Booted with config-drive and RSA keypair; Neutron port `5e1f1973-3df0-4cd3-9644-f11ef089cd64` was ACTIVE; `tap5e1f1973-3d` was `LOWER_UP` on `br-int`; host ping passed; SSH port stayed closed; QEMU guest agent not configured; VM deleted |
| `hlas-20251025-v6.332p2` / `192.0.2.31` | Booted with config-drive, RSA keypair, and bounded user-data; Neutron port `8dcf87ae-c8ad-4052-b541-ddec55832c56` was ACTIVE; `tap8dcf87ae-c8` was `LOWER_UP` on `br-int`; host ping passed; console showed cloud-init fallback datasource and OpenSSH service start, but SSH port stayed closed from the cloud side; QEMU guest agent not configured; VM deleted |
| Cleanup | Temporary servers, keypair, remote key files, and user-data file were removed after the probes |

These probes strengthen the G4/N0.5 environment conclusion: Neutron port
binding, OVS tap attachment, and host-to-guest reachability are observable and
healthy, but the current product images do not provide a safe guest command
channel for VM-originated traffic smoke.

## DHCP / Metadata / IPv6 Disposition

Bounded guest evidence for DHCP, metadata, and IPv6 disposition is in
`docs/evidence/openstack-n05-lite/20260630155334-compute-1.example.test-guest-bypass-probe/`.
It confirms DHCP initial lease through Neutron dnsmasq and keeps Aria UDS at
`managed_ports=[]`. Explicit DHCP renew is `not_applicable` for this CirrOS
image because it has no executable `udhcpc`. Metadata traffic reached the
Neutron metadata namespace proxy, but the endpoint returned HTTP 500 because
the proxy backend Unix socket was missing (`ENOENT`); treat that as target
metadata service degraded, not an Aria ACL block. IPv6 ND is `not_applicable`
until an IPv6 network exists.

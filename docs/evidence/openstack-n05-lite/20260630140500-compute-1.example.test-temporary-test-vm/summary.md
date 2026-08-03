# Temporary Test VM Evidence

Host: `compute-1.example.test`

Purpose: close or explicitly bound the G4/N0.5 guest-execution prerequisite for
VM-originated traffic smoke.

## Result

Not accepted for VM -> external traffic yet. The site can boot temporary product
VMs and expose healthy Neutron/OVS tap state, but the tested images do not expose
a usable guest command channel.

## Probes

| Image | IP | Port / Tap | Result |
| --- | --- | --- | --- |
| `qcsp-20241205-v1.2.0.9` | `192.0.2.30` | `5e1f1973-3df0-4cd3-9644-f11ef089cd64` / `tap5e1f1973-3d` | ACTIVE Neutron port, `LOWER_UP` tap, host ping pass, SSH closed, QGA absent |
| `hlas-20251025-v6.332p2` | `192.0.2.31` | `8dcf87ae-c8ad-4052-b541-ddec55832c56` / `tap8dcf87ae-c8` | ACTIVE Neutron port, `LOWER_UP` tap, host ping pass, cloud-init fallback datasource, SSH closed from cloud side, QGA absent |

## Cleanup

Both temporary servers were deleted. The temporary Nova keypair, remote key
files, and user-data file were removed.

## Follow-Up Gate

Full VM -> external N0.5 evidence requires one approved guest execution path:
an existing VM SSH command, a standard cloud image with working key/cloud-init
SSH, or QEMU guest agent on a test VM.

# Guest Access Audit

Host: `ostack2.bj159.net`

Scope: N0.5 active-direction evidence precheck for VM-originated traffic,
DHCP, metadata, and IPv6 ND smoke. This audit is read-only and does not create
or mutate OpenStack resources.

## Result

No usable guest execution channel is currently proven for the existing test
VMs.

| VM | IP | Evidence | Result |
| --- | --- | --- | --- |
| `wp-test` | `10.58.159.26` | `server-wp-test.txt`, `ssh-10.58.159.26.txt`, `qga-check.txt` | `key_name=null`; SSH rc=1; QEMU guest agent not configured |
| `test1111` | `10.58.159.27` | `server-test1111.txt`, `ssh-10.58.159.27.txt`, `qga-check.txt` | `key_name=null`; SSH rc=1; console class is `SecOS`; QEMU guest agent not configured |
| `cym_vfw1` | `10.58.159.28` | `server-cym-vfw1.txt`, `ssh-10.58.159.28.txt`, `qga-check.txt` | `key_name=null`; SSH rc=0 but prior root/admin/centos key auth was denied; QEMU guest agent not configured |
| `cym_hlas_test` | `10.58.159.29` | `server-cym-hlas-test.txt`, `ssh-10.58.159.29.txt`, `qga-check.txt` | `key_name=null`; SSH rc=1; console is Rocky Linux `LAS login:` with cloud-init fallback datasource; QEMU guest agent not configured |

`image-list.txt` shows the current client context cannot list candidate images
through `openstack image list` (`HTTP 404`). `keypair-list.txt` returned no
keypairs. Therefore a keypair-based temporary VM path is not proven available
from the current CLI context.

## Disposition

Do not count host-initiated traffic as VM-to-external evidence. Closing this
N0.5 item still needs one controlled guest execution path:

- a temporary SSH command for an existing VM;
- a short-lived test VM with known login or cloud-init;
- QEMU guest agent enabled on a test VM.

No passwords were guessed and no disk, console, or guest injection was
attempted.

# Isolated Delete Transaction Acceptance Summary

Date: 2026-08-20

This acceptance ran on one target legacy 4.18 compute in an isolated veth and
temporary OVS bridge. Environment-specific host names, addresses, interface
indexes, credentials, and production resource identifiers are intentionally
omitted.

The tested Rust userspace candidate was built from
`6144bf36ba985a0f6333ff07248e2c63241d00eb`. Its `aria-agent` SHA-256 was
`a6e069fcaa06c6fc80d0cdf8e03ce86780f53d5d5473801121784923e8d4347f`.
The eBPF object SHA-256 was
`b70f5f1e57f005c17aa262d3cde757764577df9a0c187aac0f5f682f7bee3e63`.
The final smoke contract came from `e6976edb`.

## Results

| Fixture | Result | Evidence boundary |
| --- | --- | --- |
| Delete after ACL purge | pass | The first delete failed truthfully, retained the exact managed port, quiesced the ACL gate, and published a visible `blocked/bypass` port row. |
| Durable blocked checkpoint | pass | WAL retained the delete intent and appended a blocked snapshot checkpoint with the last applied port hash. No stale `ready/enforce` evidence remained. |
| ACL policy-map purge failure | pass | Renaming the target policy map caused a classified failure without partial publication; the original owned projection remained intact until recovery. |
| Strict conntrack flush failure | pass | Renaming the IPv4 CT map caused a classified failure while preserving the pre-failure publication boundary. |
| Startup forward recovery | pass | A clean isolated datapath restart replayed each pending delete, removed the managed runtime, TC links, owned ACL projection, map rows and persisted tap state, and closed the delete transaction. |
| Idempotent retry | pass | DELETE after startup recovery returned `not_found`; it did not reopen or mutate the completed transaction. |
| Cleanup and OVS isolation | pass | The temporary container, bridge, veth, socket and bpffs tree were absent after exit. The production datapath and OVS-agent container identities and the `br-int` port inventory hash were unchanged. |

All four summary fixtures reported `pass`: `detach_ordering`,
`purge_failure_atomicity`, `strict_flush_rollback`, and `retry_detach`.
`cleanup_errors` was empty.

## Evidence Identity

The raw evidence archive is retained outside the public repository as
`aria-rc-6144bf36-transaction-8-evidence.tgz`, SHA-256
`3ff9e04c460f820832809a35d78663552501fa770396e552b87e6793d9e90061`.
The hosted build for the binary candidate is GitHub Actions run
`32334693695`.

## Boundary

This result closes the isolated target-kernel delete/WAL transaction gate for
the candidate binary. It does not claim that the candidate has already
replaced the production Aria containers, and it does not replace the pending
IPv4/IPv6 real-VM, control-plane, lifecycle, scale, or soak gates.

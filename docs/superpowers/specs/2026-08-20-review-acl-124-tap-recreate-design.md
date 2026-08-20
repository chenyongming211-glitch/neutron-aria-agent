# REVIEW-ACL-124 Tap Recreate Recovery Design

## Problem

When a VM recreates a tap with the same interface name and a new ifindex,
the netlink path removes the Rust runtime instance but does not immediately
invalidate the committed Neutron port status. The port can therefore remain
`ready/enforce` while the replacement tap has no verified TC ingress/egress
ACL attachment. The replacement `RTM_NEWLINK` also follows the generic
standalone attach path, so recovery can wait for the next periodic Python
full resync.

## Required Behavior

- `RTM_DELLINK`, a missing tap, or an ifindex mismatch immediately invalidates
  the attachment identity for the affected Neutron-managed port.
- During the gap, status is `degraded/bypass`; it must never remain
  `ready/enforce`.
- OVS forwarding remains availability-first. Aria must not restart, stop, or
  modify OVS or `neutron-openvswitch-agent`.
- A replacement tap is attached in Neutron-managed quiesced mode, never as a
  standalone ACL authority.
- The replacement tap becomes `ready/enforce` only after both TC directions
  and the last applied port generation/hash are verified by a successful
  internal scoped apply.
- If deterministic replay is unsafe, keep `degraded/bypass` and use the
  existing Python full-resync path.

## Design

### Lifecycle Events

`TapRegistry` owns a bounded Tokio broadcast channel for link lifecycle
events. The netlink monitor delegates matched `DELLINK` and `NEWLINK` events
to registry methods rather than calling generic detach/attach directly.

On link deletion the registry publishes the old ifindex before cleanup and
unregisters the runtime while preserving Neutron authority. Explicit Neutron
detach continues to clear authority. On link creation, generic attach checks
the preserved authority and uses `ManagedAttachMode::NeutronResyncRequired`
when appropriate. The new-link event is published only after the replacement
runtime is attached and quiesced.

### Truthful Status

The Neutron lifecycle task consumes registry events. A matching delete event
is serialized by the existing snapshot apply lock and:

- retains the committed old ifindex so a new ifindex cannot compare equal;
- removes the affected ACL domain desired hash so same-hash shortcuts fail;
- publishes `tap_attachment_identity_lost` as `degraded/bypass`;
- moves authority to `runtime_reconcile_requires_full_resync`; and
- appends the invalidated state to the Neutron WAL.

If the WAL append fails, the invalidated RAM state is still published. A
durability failure may block recovery, but it must not preserve false ready.
Unrelated ports and stronger pending/recovery states are not overwritten.

### Bounded In-Process Replay

`NeutronApiState` keeps one in-memory cache entry per successfully applied
port snapshot. The cache is not persisted and is not a new authority. A full
host commit replaces the cache; a successful scoped commit updates only its
target; delete removes its target.

After `NEWLINK`, internal replay is allowed only when:

- there is no pending generation or recovery barrier;
- the cached generation and desired hash exactly match the currently applied
  runtime identity;
- the committed port still matches the event ifname; and
- the new nonzero ifindex differs from the committed old ifindex.

The cached port snapshot is cloned, updated with the new ifindex, and passed
through the existing `ApplyScope::SinglePort` admission, WAL, apply, status,
and commit pipeline. No public route or production incremental RPC switch is
opened. Process restart starts with an empty cache and therefore retains the
existing mandatory Python full-resync behavior.

### Fallback

Missing cache, pending transactions, stale/out-of-order events, hash or
generation mismatch, attach failure, and replay failure all retain
`degraded/bypass`. The Python agent's existing `required_action=full_resync`
contract remains the recovery fallback.

## Verification

- Pure projection tests cover deletion invalidation, unrelated-port
  isolation, stale event rejection, pending-state preservation, and WAL
  failure publication.
- Registry tests cover authority-preserving link loss and Neutron-managed
  replacement classification.
- Replay tests cover exact identity success, cache miss, pending generation,
  hash mismatch, stale `NEWLINK`, and same-generation drift bypassing no-op.
- GitHub Actions builds and tests Rust/eBPF from one exact commit.
- The field smoke recreates the tap at least three times and records old/new
  ifindex, status, blocked probe, attach identities, generation/hash, and an
  independent OVS canary. No sample may show admitted blocked traffic while
  status is `ready/enforce`; OVS canary loss must be zero.

## Non-Goals

- No persisted second desired-state store.
- No cross-WAL distributed transaction.
- No new UDS route or schema.
- No production enablement of `incremental_rpc_enabled`.
- No QoS, Mirror, Nova, OVS, or Neutron-server behavior change.

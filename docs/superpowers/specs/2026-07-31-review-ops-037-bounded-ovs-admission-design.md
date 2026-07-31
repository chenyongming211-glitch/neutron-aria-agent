# REVIEW-OPS-037 Bounded OVS Admission Design

## Status

Design confirmed against current source; RED tests and production implementation
pending.

## Scope

This design fixes `REVIEW-OPS-037`: Neutron snapshot admission holds the global
apply mutex while synchronous, unbounded `ovs-vsctl` discovery runs.

It covers only Rust Neutron snapshot admission and OVS interface inventory. It
does not change:

- snapshot publication, WAL ordering, or background apply semantics;
- OVS inventory eligibility rules;
- Python pending-state behavior;
- startup runtime reconciliation;
- the public UDS request or response contract.

## Confirmed Current Failure

`accept_neutron_snapshot_submit` currently acquires `apply_lock` and then calls
`LocalInterfaceInventory::load`. That function executes both
`ovs-vsctl list-ports` and `ovs-vsctl list Interface` with
`std::process::Command::output`.

Consequences:

1. a slow command blocks a Tokio executor worker;
2. a hung command has no deadline or child-kill path;
3. the global apply mutex remains held for the whole delay;
4. every full-host and port-scoped snapshot admission queues behind it.

## Bounded Discovery Contract

OVS discovery uses `tokio::process::Command` with:

- a single explicit inventory deadline shared by both commands;
- `kill_on_drop(true)`;
- a timeout error that identifies the command and deadline;
- captured stdout/stderr and the existing parse/error semantics;
- no detached or lingering child after timeout.

The default deadline is a small internal constant appropriate for local
`ovs-vsctl`. This batch does not add a new user-facing configuration option.

A timeout produces the existing non-authoritative inventory result. The
snapshot transaction continues through the established
`inventory_unavailable` recovery contract; it does not silently use partial
command output.

## Lock Boundary And Revalidation

Admission uses a retryable two-lock boundary:

1. acquire `apply_lock`;
2. capture the current runtime admission identity;
3. release `apply_lock`;
4. load the complete OVS inventory asynchronously with the bounded deadline;
5. reacquire `apply_lock`;
6. reread pending/runtime state and compare it with the captured identity;
7. if another apply changed the identity, release the lock and retry discovery;
8. if unchanged, perform early-response checks, build the transaction, append
   the WAL intent, publish pending state, and return the prepared apply while
   retaining the final guard.

Retries are bounded. Exhaustion returns a retryable busy/conflict response and
does not append a WAL intent or mutate runtime.

The admission identity includes the fields that can alter early response or
planning: accepted/applied/pending generations, desired hashes, authority/WAL
state, and committed ports.

This keeps subprocess execution outside the mutation critical section while
preventing a plan built from inventory collected across an intervening apply
from being committed.

## Failure Contract

- spawn, exit-status, UTF-8/JSON parse, and deadline failures produce one
  non-authoritative inventory; partial results are discarded;
- a timed-out child is killed;
- no OVS failure writes a snapshot WAL intent before final lock revalidation;
- a runtime-identity race retries from discovery and never commits a stale
  transaction;
- the existing generation/hash deduplication responses remain unchanged.

## RED/GREEN Coverage

Unprivileged Rust behavior tests must prove:

1. a slow child is bounded and reported as inventory unavailable;
2. timeout drops/kills the child rather than leaving it running;
3. discovery runs while the apply mutex is not held;
4. an intervening runtime mutation forces revalidation/retry;
5. retry exhaustion leaves WAL and runtime unchanged;
6. unchanged runtime reaches the existing prepared-apply path;
7. ordinary OVS output retains the existing inventory parsing behavior.

Tests may use a narrow inventory-command seam. They must not add a Python
source-shape checker or a generic transaction framework.

## Acceptance

- RED fails only on the absent bounded async discovery/revalidation boundary;
- production uses the real async command path;
- exact-head `rust-behavior` and warning-denied Rust/eBPF builds pass in CI;
- no local Cargo command is run;
- `REVIEW-OPS-037` is marked fixed only after exact-head hosted GREEN evidence.


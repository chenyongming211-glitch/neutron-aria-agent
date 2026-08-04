# REVIEW-OPS-036 Exact XDP Link Identity Design

**Status:** source implementation and hosted CI complete; privileged
target-kernel evidence deferred. RED commit `c82e18e` exposed the missing exact
identity boundary in Build
[`30872857520`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30872857520).
Production commit `31dcf49` passed the focused behavior tests and all
warning-denied Rust/eBPF/static builds in exact-head Build
[`30873163705`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30873163705).
Field-wiring commit `6548272` passed hosted Build
[`30873611591`](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/30873611591),
but the opt-in privileged scenario has not run and is not claimed as passing.

## Problem

`FirewallInstance::xdp_link_health()` currently returns true when the expected
bpffs link path exists. A pinned `bpf_link` object can remain present after its
XDP attachment has been detached, so path existence does not prove that packets
on the expected interface still traverse the expected program.

The path-only result is consumed by more than status presentation:

- standalone startup may claim a pre-existing XDP hook;
- shared-runtime recovery may mark a pinned hook as owned;
- periodic runtime health may publish `xdp_ready=true`;
- the combined TC/XDP health value is propagated to instance status.

Consequently a detached-but-still-pinned link can be claimed and reported as
ready. This is `REVIEW-OPS-036`. It does not affect current ACL/CT enforcement,
which uses independently verified ingress and egress TCX links, and storm/DDoS
is not currently advertised as operational.

## Required Outcome

An XDP hook is healthy only when one bounded in-process observation proves all
of the following:

1. the expected pinned XDP program is readable and has a kernel program ID;
2. the exact expected pinned link is readable as a BPF link;
3. the pinned object is an XDP link with a nonzero kernel link ID;
4. the link has a nonzero XDP ifindex, proving that it is currently attached;
5. that ifindex equals the current ifindex of the expected interface;
6. the link's program ID equals the expected pinned program's ID.

Missing, unreadable, unsupported, detached, or mismatched evidence is
not-ready. No error or unavailable inspection path is allowed to fall back to
path existence.

## Kernel Evidence Boundary

The Linux XDP BPF-link implementation clears the link's device reference when
the link is released and reports `xdp.ifindex = 0` through
`BPF_OBJ_GET_INFO_BY_FD` when that reference is absent. Therefore the exact
pinned link FD supplies the live/detached distinction needed by this fix.

This behavior is visible in the upstream Linux
[`bpf_xdp_link_release()` and `bpf_xdp_link_fill_link_info()`
implementation](https://github.com/torvalds/linux/blob/v6.10/net/core/dev.c)
and the public
[`bpf_link_info` UAPI](https://github.com/torvalds/linux/blob/v6.10/include/uapi/linux/bpf.h).
The target enterprise kernel contains backports rather than matching its
upstream version number, so the hosted contract does not substitute for the
later target-kernel field case.

The implementation must not infer liveness from a directory entry, program pin
alone, or a separately enumerated link that cannot be tied back to the expected
pin.

## Decision

Use an in-process exact-pinned-object inspection boundary. Keep the unsafe Linux
syscall adapter isolated in a small module and keep identity comparison as a
pure, unit-testable decision function.

The observation is:

```text
expected interface name
        |
        +--> current interface ifindex
        |
expected program pin --> pinned program ID
        |
expected link pin ----> link type + link ID + link program ID + XDP ifindex
                                  |
                                  +--> exact identity decision
                                           |
                              verified live / not-ready(reason)
```

Only `verified live` maps to the existing public `xdp_ready=true` boolean.

### Alternatives considered

#### External `bpftool` and `ip` JSON

These commands can expose the required data, but production health polling
would then depend on command availability, process scheduling, timeouts, and
JSON compatibility. It would also execute child processes from call sites that
currently expect a short synchronous observation. This is rejected for the
production path; the commands remain useful in privileged smoke tests.

#### Program/interface lookup without opening the exact pin

Enumerating an interface attachment and comparing only its program ID cannot
prove that the expected pin owns that attachment. A stale or wrong pin could
still be claimed. This is rejected.

#### Persistent identity manifest

A manifest would duplicate kernel-owned link identity and itself require
transactional update and recovery. It adds state without improving the
authoritative observation. This is rejected for OPS-036.

## Architecture

### Isolated identity module

Add one focused agent module for XDP link identity. It contains:

- an observation value holding link type, link ID, link program ID, and XDP
  ifindex;
- a small stable not-ready reason enum for internal diagnostics;
- a pure decision function that compares an observation with the expected
  program ID and ifindex;
- a Linux adapter that opens the exact pinned link and reads
  `bpf_link_info`.

The module must not become a general BPF parser or duplicate Aya's loader. It
uses the already pinned program through Aya's public `Xdp::from_pin(...).info()`
API and uses the repository's existing `aya-obj` and `libc` dependencies only
for the missing pinned-link information boundary.

### BPF syscall boundary

The adapter performs two bounded syscalls:

1. `BPF_OBJ_GET` for the exact link pin path;
2. `BPF_OBJ_GET_INFO_BY_FD` into a zero-initialized `bpf_link_info`.

The returned FD is owned and closed on every path. The `unsafe` code is confined
to constructing the two UAPI attributes, invoking `libc::syscall`, and reading
the XDP union member only after the link type is verified as
`BPF_LINK_TYPE_XDP`.

Path conversion failure, an embedded NUL, `ENOENT`, `EPERM`, `EINVAL`,
`EOPNOTSUPP`, short/invalid information, or any other syscall error produces a
not-ready result. Health checks do not retry internally and do not block on an
external process.

### Internal result

The internal result distinguishes at least:

- `verified_live`;
- `missing`;
- `unverifiable`;
- `wrong_link_type`;
- `detached`;
- `wrong_interface`;
- `wrong_program`.

The reason is for stable diagnostics and behavior tests. It is not a new public
API enum and must not expose raw kernel errors or pin-path contents through the
status contract. Existing API fields remain boolean.

## Call-Site Contract

### Health and polling

`FirewallInstance::xdp_link_health()` delegates to the exact identity module.
Every existing status and poll path continues to consume a boolean, but only a
verified identity returns true. TC ACL health remains independently calculated
from the exact ingress and egress TCX program identities.

### Standalone startup

Startup claims a pre-existing XDP link only after exact verification. If an XDP
pin exists but is detached, mismatched, or unverifiable:

- do not claim ownership;
- do not report XDP ready;
- preserve the pin rather than deleting an object whose ownership is not proven;
- do not attempt a second attachment over the occupied expected pin path;
- continue healthy TC ACL/CT startup and emit a bounded diagnostic.

This deliberately prefers an explicit XDP-degraded state over deleting or
replacing a possibly foreign live attachment. Automatic stale-pin repair can be
added only with a separate ownership and rollback contract.

### Shared-runtime recovery

Path existence and verified readiness remain separate facts. A
`RuntimePinState` must never use a path-only `preexisting_xdp_link` flag as
permission to claim the hook. Recovery applies the same rules as standalone
startup: verified hooks may be claimed; invalid or unverifiable pins are
preserved and XDP remains degraded; TC runtime recovery proceeds independently.

This closes the current shared-runtime bypass in
`attach_links_from_pinned_runtime()`, where a path-only flag is currently
claimed without rechecking liveness.

## Attach Mode Boundary

`bpf_link_info` proves the exact pinned link, live interface, and program, but
does not expose the native/generic attach mode required by the later full
storm/DDoS readiness design. OPS-036 closes the path-only false-pass and makes
the current boolean conservative. It does not declare the storm/DDoS domain
operational.

Before storm/DDoS is advertised, its separate readiness implementation must
also record and validate actual attach mode, requested policy/runtime
generations, and required map schema as specified by the XDP storm/DDoS design.

## RED Behavior Coverage

Hosted, non-privileged Rust behavior tests first exercise the pure identity
decision without requiring BPF privileges:

1. exact XDP type, nonzero matching ifindex, and matching program ID is ready;
2. `ifindex=0` is detached and not ready even when the pin exists;
3. a different ifindex is not ready;
4. a different program ID is not ready;
5. a non-XDP link type is not ready;
6. missing or unreadable program, link, or interface evidence is not ready;
7. startup/recovery never claims an existing XDP pin unless the result is
   `verified_live`;
8. a non-verified existing pin blocks replacement and remains preserved;
9. XDP degradation does not lower independently healthy TC ACL readiness;
10. periodic status uses the same strict result and cannot restore path-only
    readiness.

Tests target the public behavior or pure contract. They must not parse source,
require private helper names, or duplicate the Rust suite in Python.

The selected tests are added to the maintained `rust-behavior` inventory. No
local Cargo command is run; RED and GREEN compilation evidence comes from
GitHub Actions with warnings denied.

## Privileged Field Evidence

The existing guarded standalone datapath smoke already demonstrates how to
detach a pinned link while leaving its bpffs path present. The OPS-036 field
case will use the same mechanism for the XDP link:

1. prove the XDP link is initially attached and exactly identified;
2. detach the pinned link while retaining the pin;
3. prove the pin remains readable;
4. wait for the health poll and require `xdp_ready=false`;
5. restart or invoke recovery and require that the stale pin is not claimed;
6. prove ingress and egress TC ACL readiness and forwarding behavior remain
   independent.

Without a privileged target environment this evidence remains
`deferred/pending`. Hosted tests and compilation cannot be relabeled as field
execution.

## Failure And Security Behavior

- Exact identity is fail-closed for readiness: unprovable means not-ready.
- Packet forwarding semantics do not change in this batch; XDP absence remains
  isolated from TC ACL/CT.
- No arbitrary pin is removed on mismatch or inspection failure.
- Diagnostics use stable reasons and do not publish raw paths or syscall detail
  through the API.
- Health polling performs a constant number of local reads/syscalls and spawns
  no subprocess.

## Explicit Exclusions

- No storm-control or DDoS policy, maps, counters, API, or activation.
- No attach-mode fallback or native/generic mode selection change.
- No change to TCX identity validation or ACL/CT readiness semantics.
- No automatic deletion or replacement of unverified XDP pins.
- No `bpftool` or `ip` dependency in production health polling.
- No static Python checker for Rust implementation shape.
- No claim that privileged field evidence passed.

## Delivery Sequence

1. Commit this reviewed design.
2. Add the precise RED Rust behavior tests and wire them into the maintained
   hosted behavior inventory.
3. Push RED and retain the expected exact-head failure evidence.
4. Implement the isolated identity module and route every health/claim call
   site through it.
5. Push GREEN and require exact-head `fast-contracts`, `rust-behavior`, and
   warning-denied Rust/eBPF build success.
6. Update the authoritative REVIEW register with source/hosted evidence while
   keeping privileged field evidence deferred.
7. Run and record the guarded XDP detached-but-pinned field case when a target
   environment becomes available.

## Acceptance

1. A detached-but-still-pinned XDP link always reports not-ready.
2. A link for the wrong interface, wrong program, or wrong BPF link type always
   reports not-ready.
3. Missing or unavailable exact evidence never falls back to path existence.
4. Standalone and shared-runtime startup claim only a verified exact link.
5. Invalid or unverified pre-existing pins are preserved and block replacement
   rather than being silently deleted or overwritten.
6. TC ACL/CT readiness and behavior remain independent of XDP health.
7. Hosted behavior tests and warning-denied builds pass at the implementation
   head without a private-structure checker.
8. The backlog distinguishes source/hosted completion from pending privileged
   field evidence.

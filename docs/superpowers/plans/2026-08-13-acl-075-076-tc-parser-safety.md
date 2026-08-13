# REVIEW-ACL-075/076 Bounded TC Parser Safety Implementation Plan

**Current status:** Tasks 1-4 complete. RED `cb9deb5` reproduced the intended
contract failure in Build `31695043494`; GREEN `29636e6` passed exact-head Build
`31695508165`. Task 5 target-kernel evidence remains deferred/pending.

> **For agentic workers:** use the repository's normal TDD workflow. Work every
> task directly on `v0.9-neutron-agent`; do not create a branch, worktree or PR.

**Goal:** prevent supported IPv4/IPv6 parse uncertainty from bypassing the TC
policy pipeline while correctly handling non-linear skb headers with one
bounded pull.

**Architecture:** raw parsers receive complete wire length separately from the
current direct-access boundary. TC performs a direct fast-path parse, pulls at
most 256 bytes only on failure, refreshes pointers and reparses once. Remaining
supported-IP failures map through one pure classifier to existing stable drop
reasons and return `TC_ACT_SHOT`; XDP, non-IP and scratch-failure behavior does
not change.

**Tech stack:** Rust 2021, Aya eBPF 0.1.1, host-side `aria-ebpf-abi` behavior
tests, Python `unittest` structural contracts, GitHub Actions warning-denied
Rust/eBPF builds, linked eBPF stack-budget analysis.

## Global Constraints

- Follow the approved
  [batch design](../specs/2026-08-13-acl-075-076-tc-parser-safety-design.md)
  without widening semantics.
- Do not run local Cargo build, check, test, clippy or rustfmt commands.
- Push RED and GREEN separately; hosted GitHub Actions is the Rust/eBPF
  compiler and test authority.
- Do not add or invert a Python checker for private Rust helper names, local
  variables, call order or source layout.
- Do not linearize the complete skb. The only fallback request is
  `min(packet_len, 256)`.
- Do not alter XDP parser-failure, non-IP pass-through or scratch-lookup
  fail-open behavior.
- Reuse `DROP_MALFORMED_IP`, `DROP_FRAGMENT_INVALID_L4` and the current invalid
  L4 fragment metric; do not add an ABI value.
- Preserve the 448-byte combined eBPF stack budget and warning-denied builds.
- Keep target-kernel/non-linear field evidence `deferred/pending` until it is
  executed.

## File Structure

- Modify `abi/tests/fragment_parser_contract.rs`: RED public parser/failure
  behavior fixtures and assertions.
- Modify `ebpf/src/parser.rs`: independent wire/direct bounds, bounded-pull
  constants, eight-header traversal and pure parse-failure classification.
- Modify `ebpf/src/lib.rs`: pass hook wire length, perform one bounded TC pull,
  remove value-based TCP retry, record and return stable drops.
- Modify `ci/test_ebpf_legacy_packet_bounds.py`: delete the private fail-open
  implementation-shape assertion and now-unused `_block_after` import only.
- Modify
  `docs/superpowers/specs/2026-07-19-acl-056-fragment-tracking-design.md`:
  correct the obsolete `pull_data(0)` statement after GREEN.
- Modify
  `docs/superpowers/specs/2026-08-13-acl-075-076-tc-parser-safety-design.md`:
  record RED/GREEN and field-evidence status.
- Modify
  `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`: record exact
  implementation/CI evidence without claiming field completion.

---

## Task 1: RED Parser Envelope And Failure Classification

**Files:**

- Modify: `abi/tests/fragment_parser_contract.rs`
- Test: `abi/tests/fragment_parser_contract.rs`

**Interfaces:**

- Requires the future raw-parser argument `wire_len: usize` in addition to
  `data_end`.
- Requires `TC_PARSE_LINEAR_BYTES`, `MAX_IPV6_EXTENSION_HEADERS`,
  `bounded_tc_pull_len(packet_len)` and `tc_parse_failure_reason(info)` from
  the imported parser module.
- Uses existing ABI reasons `DROP_MALFORMED_IP` and
  `DROP_FRAGMENT_INVALID_L4`.

- [x] **Step 1: Add fixtures for an arbitrary IPv6 extension chain**

Add a helper which starts from a valid Ethernet/IPv6/UDP frame and inserts
`count` eight-byte Destination Options headers. Each header points to the next
extension and the final header points to UDP. Update the IPv6 payload length
with checked fixture arithmetic.

Add a helper which invokes the future parser signature with an explicit
`linear_len` and complete `frame.len()` wire length:

```rust
unsafe fn parse_v6_with_linear_len(
    frame: &[u8],
    linear_len: usize,
    out: *mut parser::PacketInfo,
) -> bool {
    parser::parse_eth_ipv6(
        frame.as_ptr() as usize,
        frame.as_ptr() as usize + linear_len,
        frame.len(),
        0,
        out,
    )
}
```

Create the analogous IPv4 helper. The test allocation still contains the
complete frame; only `data_end` simulates the directly readable prefix.

- [x] **Step 2: Add wire-length versus linear-head RED behaviors**

Add tests whose names begin with `fragment_tc_parser_`:

```rust
#[test]
fn fragment_tc_parser_accepts_ipv4_when_payload_is_not_linear() {
    // Ethernet + IPv4 + complete UDP header are linear; payload is not.
    // wire_len remains frame.len(). Parsing must succeed and keep ports.
}

#[test]
fn fragment_tc_parser_accepts_ipv6_when_payload_is_not_linear() {
    // Ethernet + IPv6 + complete UDP header are linear; payload is not.
}

#[test]
fn fragment_tc_parser_requires_the_complete_selected_tcp_header_to_be_linear() {
    // A 60-byte TCP header with only its first 20 bytes linear must fail;
    // exposing the bounded prefix through data_end must then succeed.
}
```

Expected old behavior: the first two assertions fail because `data_end` is
incorrectly used as full wire length. The future parser signature is also
missing.

- [x] **Step 3: Add bounded pull and extension-chain RED behaviors**

Assert exactly:

```rust
assert_eq!(parser::TC_PARSE_LINEAR_BYTES, 256);
assert_eq!(parser::bounded_tc_pull_len(128), 128);
assert_eq!(parser::bounded_tc_pull_len(1500), 256);
assert_eq!(parser::MAX_IPV6_EXTENSION_HEADERS, 8);
```

Add successful five-header and eight-header fixtures. Add a nine-header
fixture which returns false and is classified as `DROP_MALFORMED_IP` rather
than becoming a pass candidate.

- [x] **Step 4: Add stable failure-reason RED behaviors**

For malformed supported IPv4/IPv6, assert that
`tc_parse_failure_reason(&info)` returns `DROP_MALFORMED_IP`.

For incomplete first-fragment UDP/TCP fixtures, assert
`tc_parse_failure_reason(&info) == DROP_FRAGMENT_INVALID_L4` and use the
existing `invalid_l4_failure` accessor to assert the preserved family and
protocol. Retain the existing assertions that stale port and fragment fields
are cleared.

- [x] **Step 5: Update every fixture call to the required signature**

Pass `frame.len()` as `wire_len` for ordinary fully linear host fixtures. Do
not change their expected fragment, port, TCP or VLAN semantics.

- [x] **Step 6: Verify only non-Cargo repository structure locally**

Run:

```bash
python3 ci/check_blocked_terms.py
git diff --check
```

Expected: exit 0. Do not run Cargo locally.

- [x] **Step 7: Commit, push and capture hosted RED**

```bash
git add abi/tests/fragment_parser_contract.rs
git commit -m "test: expose TC parser fail-open boundary"
git push origin v0.9-neutron-agent
```

Expected exact-head result: `rust-behavior` fails because the new parser
signature/constants/failure classifier do not exist or because the current
four-header parser rejects the new success fixtures. Confirm the failure is
limited to the intended ACL-075/076 contracts before production editing.

---

## Task 2: GREEN Raw Parser Bounds

**Files:**

- Modify: `ebpf/src/parser.rs`
- Modify: `ebpf/src/lib.rs` (XDP and raw TC parser call arguments only in this
  task)
- Test: `abi/tests/fragment_parser_contract.rs`

**Interfaces:**

- `parse_eth_ipv4(data, data_end, wire_len, offset, out) -> bool`
- `parse_eth_ipv6(data, data_end, wire_len, offset, out) -> bool`
- `pub const TC_PARSE_LINEAR_BYTES: u32 = 256`
- `pub const MAX_IPV6_EXTENSION_HEADERS: u8 = 8`
- `pub fn bounded_tc_pull_len(packet_len: u32) -> u32`
- `pub fn tc_parse_failure_reason(info: &PacketInfo) -> u8`

- [x] **Step 1: Add exact compile-time bounds and failure value**

In `ebpf/src/parser.rs`, import the existing drop constants and add scalar-only
constants/functions. `bounded_tc_pull_len` must be branch-based and
`#[inline(always)]`; it must not depend on `std`.

`tc_parse_failure_reason` calls the existing `invalid_l4_failure`. When present,
it returns `DROP_FRAGMENT_INVALID_L4`; otherwise it returns
`DROP_MALFORMED_IP`. Family/protocol remain available through
`invalid_l4_failure` and are not copied into a new aggregate.

- [x] **Step 2: Separate IPv4 wire validation from pointer validation**

Add `wire_len` between `data_end` and `offset`. Keep all existing fixed/direct
pointer checks. Replace the full-payload `data_end` comparison with scalar
arithmetic equivalent to:

```rust
let ip_wire_offset = ip_offset - data;
if wire_len < ip_wire_offset {
    return false;
}
let available_wire_ip_len = wire_len - ip_wire_offset;
if ip_total_len < ihl || ip_total_len > available_wire_ip_len {
    return false;
}
```

Do not construct `ip_offset + ip_total_len`. `parse_transport` continues to
check every actual TCP/UDP read against `data_end`.

- [x] **Step 3: Separate IPv6 wire validation and raise the count bound**

Use scalar `wire_len` arithmetic to validate the advertised IPv6 payload, but
retain `data_end` checks for the base header, each extension-header field, each
complete extension header and the selected transport header.

Replace the literal four-iteration bound with
`MAX_IPV6_EXTENSION_HEADERS`. If another recognized extension header remains
after eight iterations, return false. Do not add unbounded loops or support
new extension types in this batch.

- [x] **Step 4: Update full-linear XDP and host call sites**

In `xdp_firewall`, pass `(data_end - data)` as wire length to both parsers.
This preserves neutral XDP behavior. Ordinary host fixtures pass `frame.len()`.

In `parse_tc_family`, accept a scalar `wire_len` argument and forward it; Task
3 will supply `ctx.len()` from the TC wrapper.

- [x] **Step 5: Review verifier-sensitive arithmetic**

Before proceeding, inspect the diff and require:

- advertised IP lengths are never added to packet pointers;
- every dereference still has a fixed/bounded `data_end` proof;
- the extension loop remains compile-time bounded;
- no new aggregate return value is introduced on the TC call path;
- XDP passes the exact linear frame length.

Do not commit or push yet; Task 3 completes the same atomic GREEN behavior.

---

## Task 3: GREEN Bounded TC Retry And Fail-Closed Result

**Files:**

- Modify: `ebpf/src/lib.rs`
- Modify: `ci/test_ebpf_legacy_packet_bounds.py`
- Test: `abi/tests/fragment_parser_contract.rs`
- Test: `ci/test_ebpf_legacy_packet_bounds.py`

**Interfaces:**

- Consumes `bounded_tc_pull_len`, `tc_parse_failure_reason`, existing drop
  constants, `fragment::record_invalid_l4`, `drops::record_drop` and current
  tap lookup.
- Produces one direct parse plus at most one bounded pull/reparse, a scalar
  zero-or-drop-reason result, and a common stable drop path for ingress and
  egress.

- [x] **Step 1: Replace both zero-length pulls with one bounded retry**

Change `parse_tc_packet` from `bool` to a scalar `u8` result where zero means
success and a nonzero value is the exact existing drop reason. Then:

1. capture `wire_len = ctx.len()`;
2. direct-parse with current pointers and complete wire length;
3. on failure compute `pull_len = bounded_tc_pull_len(wire_len)`;
4. reject a zero length defensively as `DROP_MALFORMED_IP`;
5. call `ctx.pull_data(pull_len)` exactly once;
6. return `DROP_MALFORMED_IP` immediately if the helper fails, without trusting
   an invalid-L4 marker from the pre-pull attempt;
7. refresh `data` and `data_end`;
8. parse exactly once more;
9. return zero on success or `tc_parse_failure_reason(out)` after the final
   failed parse.

Delete the TCP `flags == 0 && seq == 0` retry block. There must be no
`pull_data(0)` and no `pull_data(ctx.len())` in the TC parser path.

- [x] **Step 2: Restore one common parse-drop recorder**

Add a small inlined helper which receives context, direction, packet length,
drop reason and protocol, resolves the tap from the current ifindex and records
the existing `DropArgs`. Do not allocate `PipelineCtx` solely for an early
parse drop and do not add a map.

If the reason is `DROP_FRAGMENT_INVALID_L4`, increment the existing invalid-L4
metric for the preserved family before recording the drop.

- [x] **Step 3: Wire identical ingress and egress behavior**

Both entry functions consume the scalar result identically:

```text
reason = parse_tc_packet(...)
if reason != 0:
    if reason is invalid-L4, read its proven family/protocol from packet scratch
    record_tc_parse_drop(context, direction, packet_len, reason, protocol)
    return TC_ACT_SHOT
```

Do not change the `PKT_SCRATCH`/`PIPE_SCRATCH` `None => TC_ACT_OK` paths,
unsupported-family raw mirror path, or later pipeline error results.

- [x] **Step 4: Remove the contradictory implementation-shape checker**

Delete only `test_tc_parse_uncertainty_is_fail_open` from
`ci/test_ebpf_legacy_packet_bounds.py`. Remove `_block_after` from its imports
when it becomes unused. Do not add a test that searches for
`TC_ACT_SHOT`, the new helper name or source order.

- [x] **Step 5: Run allowed local checks**

Run:

```bash
python3 -m unittest ci.test_ebpf_legacy_packet_bounds
python3 -m unittest ci.test_ci_lane_contract
python3 ci/check_blocked_terms.py
git diff --check
```

Expected: all exit 0. Do not run Cargo locally.

- [x] **Step 6: Commit and push the complete GREEN implementation**

```bash
git add ebpf/src/parser.rs ebpf/src/lib.rs \
  abi/tests/fragment_parser_contract.rs ci/test_ebpf_legacy_packet_bounds.py
git commit -m "fix: bound TC parser recovery"
git push origin v0.9-neutron-agent
```

- [x] **Step 7: Require exact-head hosted GREEN**

Require the implementation commit's GitHub Actions Build to show:

- `fast-contracts`: green;
- `rust-behavior`: all `aria-ebpf-abi` parser behaviors green with
  `RUSTFLAGS=-D warnings`;
- `rust-build`: eBPF and userspace builds green with warnings denied;
- linked `tc_ingress` and `tc_egress` maximum call paths at or below 448 bytes.

If the eBPF compiler/verifier or stack gate fails, fix the implementation
within this design. Do not remove tests, suppress warnings or weaken the pull
and drop contract.

---

## Task 4: Architecture And Register Closure For Hosted Evidence

**Files:**

- Modify:
  `docs/superpowers/specs/2026-07-19-acl-056-fragment-tracking-design.md`
- Modify:
  `docs/superpowers/specs/2026-08-13-acl-075-076-tc-parser-safety-design.md`
- Modify:
  `docs/superpowers/plans/2026-08-13-acl-075-076-tc-parser-safety.md`
- Modify:
  `docs/openstack-neutron-aria-details/12-review-bug-backlog.md`

- [x] **Step 1: Correct the older fragment design**

Replace the `pull_data(0)` statement with the implemented separate-wire-length
and bounded-prefix behavior. Link to this design and retain the explicit XDP,
non-IP and scratch-failure exclusions.

- [x] **Step 2: Record exact evidence without over-closing**

Record:

- RED commit and exact failing Build;
- GREEN production commit and exact successful Build;
- warning-denied eBPF build and measured stack-budget result;
- target-kernel/non-linear field evidence as `deferred/pending`.

Set `REVIEW-ACL-075/076` to the repository's established
`implementation + hosted CI complete; field evidence pending` form unless the
target-kernel case has actually run. Keep `REVIEW-ACL-087` merged, not fixed as
an independent item.

- [x] **Step 3: Validate and publish documentation closure**

Run:

```bash
python3 ci/check_blocked_terms.py
git diff --check
```

Then commit and push:

```bash
git add docs/superpowers/specs/2026-07-19-acl-056-fragment-tracking-design.md \
  docs/superpowers/specs/2026-08-13-acl-075-076-tc-parser-safety-design.md \
  docs/superpowers/plans/2026-08-13-acl-075-076-tc-parser-safety.md \
  docs/openstack-neutron-aria-details/12-review-bug-backlog.md
git commit -m "docs: record bounded TC parser evidence"
git push origin v0.9-neutron-agent
```

Require exact-head hosted documentation/static lanes to remain green.

---

## Task 5: Deferred Target-Kernel Evidence

**Files:**

- Modify an existing guarded privileged datapath smoke only if the target
  environment can create or preserve a real non-linear skb deterministically.
- Modify the design and REVIEW register only after actual execution.

- [ ] **Step 1: Prove real helper and verifier behavior**

On the maintained enterprise 4.18 kernel, load both TC directions and send a
controlled packet whose transport header begins outside the initial linear
head but ends inside the 256-byte requested prefix. Require normal ACL/CT
enforcement and no parse-drop increment.

- [ ] **Step 2: Prove bounded fail-closed cases**

Send a five-header supported IPv6 fixture and require normal enforcement. Send
a nine-header or over-256-byte required-prefix fixture and an incomplete first
TCP/UDP fragment; require the exact existing drop counters and no uninspected
forwarding.

- [ ] **Step 3: Record field evidence**

Record the exact artifact commit, kernel release, attach mode, commands,
packet fixtures and counters. Only then may the two REVIEW rows become fully
fixed/field-verified. An unavailable environment remains `deferred/pending` and
does not block starting the next code batch if the capability stays within its
existing production gate.

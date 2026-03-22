# Aria Firewall SSL HTTP Verifier Repair Design

Status: Draft
Date: 2026-03-22
Scope: SSL HTTP observability repair for fragmented `SSL_write*` traffic

## 1. Background

SSL HTTP observability originally assumed that a full HTTP request line would be visible in a single `SSL_write` or `SSL_write_ex` call.

That assumption is false for some runtimes, notably Python's `ssl` stack, where a request header may be split across multiple `SSL_write*` calls. The first repair attempt introduced request-fragment accumulation in eBPF so the method prefix could be recognized across multiple writes.

The functional direction was correct, but the first implementation made the `ssl_write_entry` uprobe unloadable on the target kernel.

## 2. Confirmed Root Cause

The current failure is not caused by:

- `aya 0.13.1`
- SSL map pin paths
- `SslHttpScratch` layout mismatch
- missing `SSL_HTTP_SCRATCH` map pinning

The actual failure is in the compiled eBPF for `ssl_write_entry`.

Facts:

- The agent log reports `ssl_write_entry load: LoadError ... verifier_log ... R6 invalid mem access 'scalar'`.
- The verifier log shows `SSL_HTTP_SCRATCH` with value size `272`, which matches the current `SslHttpScratch` layout.
- `ssl_write_entry` and `ssl_write_ex_entry` both call the same Rust implementation.
- The first failure began after introducing `append_http_fragment()` with a dynamic Rust sub-slice:
  - `&mut scratch.req_data[start..start + copy_len]`
- Replacing that sub-slice with a raw helper write to `scratch.req_data.as_mut_ptr().add(start)` still failed on the target kernel.

Why verifier rejects it:

- Failure mode 1:
  - Even though the source logic constrains `copy_len <= 256 - start`, the Rust compiler still emits bounds-check code for the dynamic slice expression.
  - On BPF targets that bounds path becomes part of the verifier-visible control flow.
  - The verifier loses the relationship between `start`, `copy_len`, and `end = start + copy_len`.
  - It therefore treats the generated slice end as an unconstrained scalar and rejects the panic/bounds-check path.

- Failure mode 2:
  - A raw `bpf_probe_read_user()` call also fails when the destination pointer is a map value at a dynamic offset.
  - On the deployed build the verifier reports:
    - `invalid access to map value, value_size=272 off=271 size=256`
    - `R1 max value is outside of the allowed memory range`
  - This shows that moving from a dynamic Rust slice to a helper call is not sufficient if the helper still writes into `req_data + start`.

This is a verifier-compatibility issue in the eBPF program shape, not in the Aya loader itself.

## 3. Repair Goals

- Keep fragmented `SSL_write` / `SSL_write_ex` accumulation so Python HTTP traffic can be recognized.
- Make `ssl_write_entry` verifier-safe on the current kernel baseline.
- Avoid changing userspace parsing, map names, pin paths, or API schema.
- Preserve the current timeout-based cleanup behavior for incomplete requests.

## 4. Constraints

- The request buffer must remain fixed-size and bounded.
- The implementation must avoid dynamic Rust slice construction on map-backed buffers.
- The verifier must be able to prove every pointer offset and write boundary.
- The fix should be minimal and local to the SSL write accumulation path.

## 5. Detailed Repair

### 5.1 Keep the current scratch layout

No map schema change is required.

`SslHttpScratch` remains:

- `first_write_ts: u64`
- `data_len: u16`
- `flags: u8`
- `_pad: [u8; 5]`
- `req_data: [u8; 256]`

Total size remains `272` bytes.

### 5.2 Use a fixed-base temporary read buffer

`append_http_fragment()` must stop doing either of the following:

- building a dynamic Rust sub-slice
- calling a helper that writes directly into a map value at a dynamic offset

Instead, it should:

1. Read `start = scratch.data_len as usize`
2. Explicitly reject `start >= 256`
3. Compute `remaining = 256 - start`
4. Compute `copy_len = min(num, remaining)`
5. Explicitly reject `copy_len == 0`
6. Compute `end = start + copy_len`
7. Explicitly reject `end > 256`
8. Read the user fragment into `SSL_HTTP_PARSE_BUF.data` at offset `0`
9. Copy bytes from that temporary buffer into `scratch.req_data[start + i]`

Why this works better:

- The helper destination is now a fixed-base per-CPU map value, not a dynamic-offset map pointer.
- The append copy into `scratch.req_data` can be expressed as direct byte stores with explicit per-byte bounds guards, which the verifier can reason about more easily than a helper write.

### 5.3 Keep explicit post-copy bounds checks

After a successful copy:

- update `scratch.data_len = end as u16`
- null-terminate only when `end < 256`

This keeps the userspace parser behavior unchanged while still allowing a full 256-byte capture when the request header fills the buffer.

### 5.4 Use direct byte stores for the append step

The copy from `SSL_HTTP_PARSE_BUF.data` into `scratch.req_data` should be:

- unrolled
- expressed as direct pointer stores
- guarded by explicit per-index constant bounds:
  - for byte `i`, require `start <= 255 - i`

This avoids both:

- Rust bounds-check/panic generation
- helper calls that target a dynamic map-value destination address

### 5.5 Do not broaden the fix beyond write accumulation

This repair should not change:

- `ssl_read_entry_impl`
- `ssl_read_return_impl`
- global SSL manager lifecycle
- API or CLI behavior

Those were investigated separately and are not the current load blocker.

## 6. Validation Plan

### 6.1 Load-time validation

After rebuilding and deploying:

- confirm `aria-agent` no longer logs `ssl_write_entry load` verifier failures
- confirm `/api/v1/ssl/config` succeeds
- confirm SSL uprobe link pins exist under `ssl-global`

### 6.2 Runtime validation

Exercise all of the following:

- `openssl s_client` request
- `curl --http1.1`
- Python `urllib.request.urlopen("https://example.com")`
- Python raw `ssl` socket request

Expected result:

- `/api/v1/ssl/http` emits HTTP events for all of them
- no regression in `/api/v1/ssl` handshake events
- no regression in `/api/v1/ssl/errors`

## 7. Rejected Alternatives

### 7.1 Revert to single-write detection

Rejected because it would restore loadability but reintroduce the original Python visibility gap.

### 7.2 Increase scratch size or change map layout again

Rejected because the verifier failure is not caused by the current map size.

### 7.3 Keep using raw helper writes into `req_data + start`

Rejected because deployment confirmed that the verifier still rejects helper writes into map values when the destination offset is dynamic.

### 7.4 Blame Aya version and downgrade first

Rejected because the failure is explained by verifier-visible code generation in the Rust program itself. The current evidence does not justify a version rollback as the primary repair.

# Aria Firewall SSL Handshake Coverage Repair

Status: In Progress
Date: 2026-03-22
Scope: missing handshake events for `openssl s_client` and duplicate handshake events for some explicit-handshake clients

## 1. Problem

After fixing SSL HTTP observability, `openssl s_client` could produce `/api/v1/ssl/http` events but sometimes produced no `/api/v1/ssl` handshake event.

At the same time, Python HTTPS traffic could produce duplicate handshake events for a single connection.

## 2. Confirmed Root Cause

The current handshake implementation only records completion on `SSL_do_handshake` return.

That is insufficient for two reasons:

- Some clients complete the handshake implicitly during the first successful `SSL_read*` or `SSL_write*` call instead of calling a public handshake API that we currently probe.
- `SSL_do_handshake` may return multiple times during negotiation; recording every return as a completed handshake creates duplicates.

## 3. Evidence

Server-side evidence collected on `root@118.195.135.53`:

- `libssl.so.3` exports all of the relevant public symbols:
  - `SSL_do_handshake`
  - `SSL_connect`
  - `SSL_accept`
  - `SSL_set_connect_state`
  - `SSL_set_accept_state`
- `openssl s_client` is dynamically linked against `libssl.so.3`.
- Short `bpftrace` sessions showed:
  - `openssl s_client` hits `SSL_set_connect_state` once.
  - `openssl s_client` hits `SSL_write` and `SSL_read`.
  - `openssl s_client` does not hit `SSL_do_handshake` or `SSL_connect`.
  - Python `urllib` hits `SSL_do_handshake`.

This means the `openssl` CLI handshake is being completed implicitly in the I/O path, while the current agent only emits handshake events for the explicit `SSL_do_handshake` path.

## 4. Repair

The repaired handshake flow should be:

1. Record handshake start when any of these entry points are hit:
   - `SSL_do_handshake`
   - `SSL_connect`
   - `SSL_accept`
   - `SSL_set_connect_state`
   - `SSL_set_accept_state`
2. Emit a handshake event only when:
   - an explicit handshake API returns success (`ret > 0`), or
   - the first successful `SSL_read*` / `SSL_write*` completes while a handshake is still pending
3. Keep the existing SNI capture path unchanged.

## 5. Expected Outcome

- `openssl s_client` produces both handshake events and HTTP events.
- Python no longer emits duplicate handshake events caused by intermediate `SSL_do_handshake` returns.
- Existing SSL HTTP and SSL error APIs remain unchanged.

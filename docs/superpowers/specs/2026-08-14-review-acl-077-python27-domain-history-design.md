# REVIEW-ACL-077 Python 2.7 Domain History Compatibility Design

**Status:** source implementation and exact-head hosted CI complete

**Date:** 2026-08-14

**Owning finding:** `REVIEW-ACL-077`

## 1. Decision

Restore durable per-domain feature-ready generations with the same
Python-2/3 text predicate already used by the rest of the Neutron adapter:

```python
try:
    _STRING_TYPES = (basestring,)
except NameError:
    _STRING_TYPES = (str,)
```

`AgentRuntimeStatus._generation_by_domain` accepts non-empty values in
`_STRING_TYPES`, continues normalizing generation values through the existing
integer conversion, and continues rejecting non-text or empty domain keys.

The fix does not change the durable schema, feature-ready ownership,
generation arbitration, heartbeat fields, or status authority. It repairs the
Python 2.7 decoding boundary only.

## 2. Verified Root Cause

`AgentRuntimeStatus.hydrate_durable_history` reads
`last_feature_ready_generation_by_domain` from the persisted JSON history and
passes it to `_generation_by_domain`. That helper currently uses:

```python
if not isinstance(domain, str) or not domain:
    continue
```

Under Python 2.7, `json.loads` decodes JSON object keys as `unicode`.
`unicode` is not an instance of `str`, so every valid domain entry is silently
discarded. After restart, the agent can therefore report an empty durable
per-domain feature-ready history even though the state file contains valid
entries.

Sibling adapter modules already define `_STRING_TYPES` using `basestring` on
Python 2 and `str` on Python 3. `status.py` is the inconsistent boundary.

## 3. Restoration Contract

For both `mark_ready` input and durable-history hydration:

- non-empty byte-string keys remain accepted;
- non-empty Unicode keys are accepted on Python 2.7 and Python 3;
- integer-like generation values continue to normalize through
  `_int_or_default`;
- empty text keys and non-text keys remain ignored;
- the original text key value is preserved; no encoding, lowercasing, aliasing,
  or domain allow-list is introduced;
- malformed generation values retain the existing fallback value `0`.

The compatibility fix is deliberately local. Domain support validation remains
at its existing configuration and UDS contract boundaries; durable status
history is not reinterpreted during restoration.

## 4. RED/GREEN Evidence

Two behavior layers cover the contract:

1. the normal Python unit suite hydrates a JSON-decoded durable history and
   verifies exact preservation, numeric normalization, and rejection of empty
   and non-text keys;
2. the existing `neutron-agent-clean-install` lane executes the installed egg
   inside `python:2.7.18-slim-buster`, decodes the durable payload with the real
   Python 2.7 `json` module, hydrates `AgentRuntimeStatus`, and verifies the
   Unicode `acl` key and generation survive the round trip.

The second test must fail against the current implementation. It is real
runtime evidence, not a source-text checker or a Python 3 approximation of
Python 2 string types.

RED `929b42a` failed the installed-egg Python 2.7 assertion in Build
[31764850375](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31764850375).
The Python 3 fast and database contracts passed; the remaining unrelated Rust
jobs were cancelled after the intended failure was captured. GREEN `a483737`
passed exact-head Build
[31764984847](https://github.com/chenyongming211-glitch/aria-firewall/actions/runs/31764984847).
Its clean-install log explicitly emitted
`clean_python27_unicode_domain_history=ok`, proving that the real Python 2.7
JSON key survived restoration. Rust jobs were correctly skipped because the
GREEN production change was Python-only.

## 5. Failure And Compatibility Semantics

- No valid durable entry may disappear solely because Python 2.7 decoded its
  key as `unicode`.
- Invalid keys remain ignored rather than causing startup failure, preserving
  the established tolerant status-history behavior.
- The state file is not rewritten by hydration.
- A failed or absent history does not gain new readiness authority.
- The clean-install lane remains independent from Rust/eBPF compilation.

## 6. Scope

Production code is limited to `neutron_aria/agent/status.py`.

Tests are limited to:

- the existing status reporter/runtime-status unit module;
- the existing Python 2.7 clean-container install smoke.

Documentation updates are limited to this design, its implementation plan,
the remediation-program progress pointer, and the REVIEW register.

Explicit exclusions:

- no persistent-state schema or migration;
- no domain allow-list or capability change;
- no feature-ready generation ownership change;
- no heartbeat schema or Neutron API change;
- no Rust, eBPF, WAL, datapath, packaging, or privileged network change;
- no implementation of `REVIEW-TXN-033` or later findings.

## 7. Acceptance

1. Real Python 2.7 `json.loads` produces a Unicode domain key that survives
   `hydrate_durable_history` with its generation intact.
2. Python 3 behavior remains unchanged for normal string keys.
3. Empty and non-text keys remain excluded.
4. Generation normalization remains unchanged.
5. The focused Python tests and the Python 2.7 clean-install lane pass.
6. Exact-head hosted Build passes before `REVIEW-ACL-077` is marked fixed.

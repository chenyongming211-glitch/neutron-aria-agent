# Neutron Agent Authentication-Header Log Redaction

Date: 2026-08-10

Status: source fix and two-node field verification complete.

## Scope And Safety

- Changed only the Python `neutron-aria-agent` logging boundary.
- Used the two available test nodes. The unavailable node was not accessed.
- Restarted only `neutron_aria_agent` after a reversible egg installation.
- Did not restart or modify OVS, the OVS agent, or the Rust datapath.
- No local Rust or eBPF compilation was performed.

## Root Cause

The dedicated agent loads the shared Neutron and OVS configuration before it
configures its own logger. The final OVS configuration enables global debug
logging. The previous `configure_logging()` implementation constrained only
the `neutron_aria` namespace, so `neutronclient.client` continued to emit DEBUG
request records through the root handlers. Those records included
authentication-header values.

## Repair

- The agent now owns the effective level of the known Neutron, Keystone,
  Requests, and urllib3 client logger namespaces and fixes them at WARNING.
- A handler filter redacts `Authorization`, `X-Auth-Token`, and
  `X-Subject-Token` values if a warning or error record still carries headers.
- Filter installation is idempotent and applies to both existing root handlers
  installed by Neutron and the dedicated agent stream handler.

## Verification

| Check | Result |
| --- | --- |
| TDD RED | Both new tests failed before production code changed: third-party DEBUG exposed the test token and a WARNING retained both authentication values. |
| Focused GREEN | Both logging regressions passed. |
| `test_main` | 7 tests passed. |
| Fast contracts | 581 tests passed, 8 environment-dependent tests skipped; config, UDS, package, CLI, and smoke-entrypoint contracts passed. |
| Payload policy | The generated Python 2.7 egg passed the payload scan. |
| Reversible install | Both available nodes backed up the prior egg and entrypoint, installed the new egg, and passed Python 2.7 import and console-entrypoint smoke. |
| Runtime logger level | Both nodes reported `neutronclient.client` effective level WARNING after deliberately setting it to DEBUG before `configure_logging()`. |
| Python 2.7 redaction | Both nodes removed two fake authentication values from a forced WARNING and emitted the `[REDACTED]` marker. |
| Fresh process logs | Both newly rotated active log files contained ready startup evidence, zero authentication-header lines, zero `neutronclient.client` DEBUG lines, and zero ERROR/CRITICAL/Traceback lines. |
| Service state | Both Python agents returned to ready and non-degraded state; Rust datapath and OVS-agent uptime remained unchanged. |

## Log Retention

The pre-fix active file on each node was moved to a timestamped `pre-sec003`
archive with mode `0640`, then the Python agent was restarted to create a clean
active file. Historical archives were not deleted. Their final retention or
secure disposal remains an operator audit-policy decision.

## Rollback

Each node has a timestamped package and entrypoint backup under the dedicated
SEC-003 installer state directory. The standard agent egg installer rollback
restores those preimages and restarts only `neutron_aria_agent` when requested.

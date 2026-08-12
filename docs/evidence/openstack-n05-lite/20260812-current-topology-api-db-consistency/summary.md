# Current-Topology Neutron API/DB Consistency

Date: 2026-08-12

Scope: replace the obsolete wait-for-recovery condition in `RISK-ENV-001` with
evidence for the currently declared topology. One former compute is unavailable
and is not an admitted Neutron API/DB backend.

## Observed Topology

- The active controller exposes Neutron on the local endpoint and the service
  virtual endpoint.
- The second active compute reaches the same virtual endpoint and has no local
  `neutron-server` container.
- The unavailable former compute was not accessed and is not counted as an
  active backend.

## Bidirectional Consistency Test

Five independent iterations were run in each direction:

1. create an `aria_acl` policy through the local endpoint;
2. read it through the virtual endpoint;
3. delete it through the virtual endpoint;
4. require HTTP 404 through both endpoints;
5. repeat with virtual create, local read/delete, and dual 404 verification.

All ten transactions passed. Each object used a unique correlation name and
identity. Cleanup found and removed one object left by an initial test-harness
dependency error, then confirmed no `risk-env-*` or `acl013-*` policy remained.
VM connectivity to both active computes passed after cleanup.

## Conclusion

The stale collection result recorded under `RISK-ENV-001` did not reproduce on
the active topology. The risk is closed for that declared topology. A recovered
or replacement controller/backend must be treated as a new admission and must
pass direct-versus-virtual create/read/delete consistency before entering
rotation.

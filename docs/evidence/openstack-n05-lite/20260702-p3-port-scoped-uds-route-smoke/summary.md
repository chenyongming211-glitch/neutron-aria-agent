# P3 Port-Scoped UDS Route Smoke

Date: 2026-07-02

Host: `ostack2.bj159.net`

Commit: `70075b0a9b9e635856720fe5f32daf145b80ca90`

Scope: validate the Rust `PUT /api/v1/neutron/ports/{port_id}/snapshot`
route as an internal, capability-disabled P3 building block.

## Deployment

CI run `28568463541` produced the test artifacts:

- `aria-agent`
- `libebpf_firewall.so`
- `libebpf_firewall_perf.so`
- `neutron-aria-stage2-acl-kolla-bundle.tgz`

Only the `aria_datapath` container was updated and restarted. OVS,
the OVS agent, neutron-server, and `neutron_aria_agent` were not restarted.
`incremental_rpc_enabled` remained disabled and no Python port-scoped submitter
was enabled.

Backup path on the target host:

```text
/var/tmp/aria-p3-port-scoped-route-20260702141823
```

Installed artifact hashes:

```text
2bc1b5001a070d852ae9b0ec018420795139ff348b3c0c2c05ef52d5d35f572a  /usr/local/bin/aria-agent
ecc9f929697a16669287c68a22dd1ce28f760991188dbd5d9f0612c7a6efa8d1  /usr/local/lib/libebpf_firewall.so
ecc9f929697a16669287c68a22dd1ce28f760991188dbd5d9f0612c7a6efa8d1  /usr/local/lib/libebpf_firewall_perf.so
```

## Baseline

Before replacing the binary, the same port-scoped route returned `404 Not
Found`, which confirmed the old runtime did not already expose the route.

## Results

Capability stayed closed:

```text
supports_port_scoped_snapshot_present=False
supports_full_snapshot=True
supports_port_delete=True
```

Path/body mismatch returned the scoped contract error:

```text
mismatch_http=400
{"details":"single-port snapshot path/body mismatch: expected target-port, got other-port","error":"PORT_SCOPE_MISMATCH"}
```

Stale scoped generation returned the existing stale semantics:

```text
stale_http=200
{"generation":1,"desired_hash":"route-probe-stale","accepted_generation":164,"applied_generation":164,"status":"stale","results":[{"port_id":"snapshot","ifname":"","action":"ignore","status":"ignored","reason":"stale_generation"}],"active_instances":[]}
```

Same generation with a different hash returned the existing conflict semantics:

```text
conflict_http=409
{"details":"generation 164 already applied with a different desired_hash","error":"generation_hash_conflict"}
```

Runtime state did not change during the non-mutating probes:

```text
generation_before=164 generation_after=164
accepted_before=164 accepted_after=164
managed_ports_before=0 managed_ports_after=0
authority_before=ready authority_after=ready
```

The same route was also probed from the `neutron_aria_agent` container as the
`neutron` user, matching the intended UDS client identity:

```text
agent_container_capabilities_status=HTTP/1.1 200 OK
agent_container_mismatch_status=HTTP/1.1 400 Bad Request
{"details":"single-port snapshot path/body mismatch: expected target-port, got other-port","error":"PORT_SCOPE_MISMATCH"}
```

## Disposition

Pass for P3-3 route-level validation:

- the Rust port-scoped UDS route is live on the target runtime;
- the route reuses existing generation/hash error semantics;
- the scope mismatch guard works before mutation;
- capability advertisement remains closed;
- Python service-loop submission remains disabled.

This does not enable P3 production incremental apply. The next step is a
controlled port-scoped apply test against a real projected local port only after
the explicit Python capability/config gate is implemented.

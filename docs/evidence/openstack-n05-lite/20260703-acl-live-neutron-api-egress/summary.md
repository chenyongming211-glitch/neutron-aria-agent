# ACL Live Neutron API Guest Egress Smoke

Date: 2026-07-03

Host: `ostack2.bj159.net`

Temporary VM: `aria-n05-egress-20260703114351`

Temporary VM IP: `10.58.159.54`

Temporary port: `5c9a69a5-ea32-4fee-83f2-ff8dd8f5669e`

Temporary tap: `tap5c9a69a5-ea`

Remote evidence directory:

```text
/var/tmp/neutron-aria-acl-live-egress-20260703114351-ostack2.bj159.net
```

## Scope

Validate guest-originated egress ACL delivery through the real Neutron `aria_acl`
REST API:

```text
CirrOS guest ping
  -> tap5c9a69a5-ea
  -> aria-datapath eBPF ACL
  <- neutron-aria-agent full resync
  <- Neutron aria_acl API
```

No OVS, OVS agent, or neutron-server restart was performed.

## Temporary ACL

The smoke created a temporary port binding with:

```text
policy default_action = allow
rule direction        = egress
rule action           = drop
rule protocol         = icmp
rule src_cidr         = 10.58.159.54/32
rule dst_cidr         = 10.58.159.2/32
binding target_type   = port
binding target_id     = 5c9a69a5-ea32-4fee-83f2-ff8dd8f5669e
```

All temporary `aria_acl` policy/rule/binding objects were deleted during
rollback.

## Results

Baseline guest-originated traffic:

```text
guest ping 10.58.159.2: 3 transmitted, 3 received, 0% packet loss
target status before first apply: missing from UDS because the VM was newly booted
```

After ACL apply:

```text
snapshot generation 202 submitted
target status: ready / enforce
datapath policy: icmp drop present on tap5c9a69a5-ea
guest ping 10.58.159.2: 3 transmitted, 0 received, 100% packet loss
```

After rollback:

```text
target status: not_requested / bypass
guest ping 10.58.159.2: recovered to 0% packet loss
```

Final cleanup:

```text
aria_acl_policies  = []
aria_acl_rules     = []
aria_acl_bindings  = []
temporary image    = deleted
temporary keypair  = deleted
temporary VM       = not active; only Nova DELETED audit row remains
datapath managed ports = 13, excluding the temporary port
temporary port runtime status = detached
```

Conclusion: guest-originated egress ACL delivery from Neutron `aria_acl` API to
the eBPF datapath is effective, and rollback restores guest connectivity.

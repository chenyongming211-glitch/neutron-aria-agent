# ACL Live Neutron API Downlink Smoke

Date: 2026-07-03

Host: `ostack2.bj159.net`

Target VM: `wp-test`

Target port: `86b83885-671f-474c-9556-8af98cf1cdc8`

Target tap: `tap86b83885-67`

Target IP: `10.58.159.26`

Remote evidence directory:

```text
/var/tmp/neutron-aria-acl-live-20260703100417-ostack2.bj159.net
```

## Scope

Validate production ACL delivery through the real Neutron `aria_acl` REST API:

```text
Neutron aria_acl API
  -> neutron-aria-agent NeutronAclSource
  -> full resync snapshot
  -> aria-datapath UDS
  -> eBPF ACL policy on tap86b83885-67
```

No OVS, OVS agent, or neutron-server restart was performed.

## Temporary ACL

The smoke created a temporary port binding with:

```text
policy default_action = allow
rule direction        = ingress
rule action           = drop
rule protocol         = icmp
rule src_cidr         = 10.58.159.2/32
binding target_type   = port
binding target_id     = 86b83885-671f-474c-9556-8af98cf1cdc8
```

All temporary `aria_acl` policy/rule/binding objects were deleted during rollback.

## Results

Baseline:

```text
ping 10.58.159.26: 3 transmitted, 3 received, 0% packet loss
target status: not_requested / bypass
generation: 189
```

After ACL apply:

```text
snapshot generation 190 submitted
target status: ready / enforce
datapath policy: icmp drop present on tap86b83885-67
ping 10.58.159.26: 3 transmitted, 0 received, 100% packet loss
```

After rollback:

```text
target status: not_requested / bypass
datapath policies: []
ping 10.58.159.26: recovered to 0% packet loss
final API status generation: 192
```

## Final State

Post-smoke checks showed:

```text
aria_acl_policies  = []
aria_acl_rules     = []
aria_acl_bindings  = []
target port status = not_requested / bypass
datapath policies  = []
```

Conclusion: ACL delivery from Neutron `aria_acl` API to eBPF datapath is effective for the tested VM port, and rollback restores connectivity.

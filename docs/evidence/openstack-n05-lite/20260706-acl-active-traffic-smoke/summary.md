# ACL Active Traffic Smoke

Date: 2026-07-06

Host: `compute-a.example.test`

Script: `deploy/kolla/smoke/neutron_aria_acl_active_traffic_smoke.sh`

Remote evidence directory:

```text
/var/tmp/neutron-aria-acl-active-traffic-20260706173237-compute-a.example.test
```

## Scope

Validate that ACL is not only configurable, but can interrupt an already
running test traffic stream and then restore it after rollback:

```text
continuous host -> VM ping stream
  -> temporary Neutron aria_acl policy/rule/binding
  -> neutron-aria-agent full resync
  -> aria-datapath policy on tap
  -> traffic blocked
  -> temporary ACL deleted
  -> full resync rollback
  -> traffic recovered
```

No OVS, OVS agent, Neutron server, or aria-datapath restart was performed.

## Target

```text
target VM IP  = 192.0.2.26
target port   = 86b83885-671f-474c-9556-8af98cf1cdc8
target tap    = tap86b83885-67
source CIDR   = 192.0.2.2/32
target CIDR   = 192.0.2.26/32
protocol      = icmp
```

## Temporary ACL

The smoke created one temporary policy, one rule, and one binding:

```text
policy default_action = allow
rule direction        = ingress
rule action           = drop
rule protocol         = icmp
rule src_cidr         = 192.0.2.2/32
rule dst_cidr         = 192.0.2.26/32
binding target_type   = port
binding target_id     = 86b83885-671f-474c-9556-8af98cf1cdc8
```

## Results

Baseline:

```text
one-shot ping before ACL: pass
continuous ping baseline_success_delta=1 failures=0
```

After ACL apply:

```text
snapshot generation 246 submitted
datapath policy contains action=drop on tap86b83885-67
aria_acl_port_status:
  status=ready
  runtime_status=ready
  effective_action=enforce
  stale=false
one-shot ping after ACL: blocked
continuous blocked window:
  success_delta=0
  failure_delta=4
```

After rollback:

```text
temporary aria_acl binding/rule/policy deleted
full resync rollback completed
datapath policies=[]
one-shot ping recovered
continuous recovery_success_delta=1
```

Final state:

```text
target port status:
  status=not_requested
  runtime_status=not_requested
  effective_action=bypass
  reason=no_enabled_binding
  generation=248
  stale=false

datapath policies:
  []
```

The post-check saw two older `cli-consistency-*` empty policies from previous
CLI consistency smoke runs, but no `aria_acl_rules` and no `aria_acl_bindings`;
the active traffic smoke's temporary objects were removed.

## Conclusion

ACL active traffic gate passed on `compute-a.example.test`: a real test VM traffic
stream was already running, Neutron `aria_acl` policy application blocked it,
port-status reported ready/enforce while active, and rollback restored bypass
state and connectivity.

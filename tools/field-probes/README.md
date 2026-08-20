# IPv6 Field Probes

These small Go programs support privileged IPv6 ACL validation in the target
Linux environment. They do not contain environment-specific addresses or
credentials.

Build each probe explicitly for Linux:

```bash
GOOS=linux GOARCH=amd64 go build -o ipv6-guest-listener ./tools/field-probes/ipv6-guest-listener/main.go
GOOS=linux GOARCH=amd64 go build -o ipv6-udp-probe ./tools/field-probes/ipv6-udp-probe/main.go
GOOS=linux GOARCH=amd64 go build -o ipv6-ext-probe ./tools/field-probes/ipv6-ext-probe/main.go
GOOS=linux GOARCH=amd64 go build -o ipv6-ra-sender ./tools/field-probes/ipv6-ra-sender/main.go
```

`ipv6-ext-probe` and `ipv6-ra-sender` use Linux packet sockets and require the
corresponding network capability or root privileges at runtime.

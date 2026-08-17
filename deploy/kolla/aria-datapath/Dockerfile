ARG BASE_IMAGE
FROM ${BASE_IMAGE}

USER root

COPY deploy/kolla/aria-datapath/start-aria-datapath.sh /usr/local/bin/start-aria-datapath
COPY deploy/kolla/aria-datapath/healthcheck-aria-datapath.sh /usr/local/bin/healthcheck-aria-datapath

RUN chmod 0755 /usr/local/bin/start-aria-datapath /usr/local/bin/healthcheck-aria-datapath

# Product builds must layer the compiled aria-agent binary and eBPF artifacts
# into this image. The smoke/runtime contract expects:
#   /usr/local/bin/aria-agent
#   /usr/local/lib/libebpf_firewall.so
#   /usr/local/lib/libebpf_firewall_perf.so
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["/usr/local/bin/healthcheck-aria-datapath"]

USER root

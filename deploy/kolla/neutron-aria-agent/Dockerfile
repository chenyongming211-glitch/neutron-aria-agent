ARG BASE_IMAGE
FROM ${BASE_IMAGE}

USER root

COPY dist/kolla/neutron_aria-0.1.0-py2.7.egg /tmp/neutron_aria-0.1.0-py2.7.egg
COPY dist/kolla/python2-wheels/netaddr-0.7.19-py2.py3-none-any.whl /tmp/netaddr-0.7.19-py2.py3-none-any.whl
COPY deploy/kolla/neutron-aria-agent/install-neutron-aria-egg-image.sh /usr/local/sbin/install-neutron-aria-egg-image
COPY deploy/kolla/neutron-aria-agent/neutron-aria-agent-entrypoint.py /usr/local/bin/neutron-aria-agent
COPY deploy/kolla/neutron-aria-agent/start-neutron-aria-agent.sh /usr/local/bin/start-neutron-aria-agent
COPY deploy/kolla/neutron-aria-agent/healthcheck-neutron-aria-agent.sh /usr/local/bin/healthcheck-neutron-aria-agent

RUN python -c "import zipfile; assert zipfile.ZipFile('/tmp/neutron_aria-0.1.0-py2.7.egg').testzip() is None" && \
    python3 -m pip install --disable-pip-version-check --no-deps --upgrade \
        --target /usr/lib/python2.7/site-packages \
        /tmp/netaddr-0.7.19-py2.py3-none-any.whl && \
    rm -f /tmp/netaddr-0.7.19-py2.py3-none-any.whl && \
    /usr/local/sbin/install-neutron-aria-egg-image \
        /tmp/neutron_aria-0.1.0-py2.7.egg \
        /usr/lib/python2.7/site-packages && \
    rm -f /tmp/neutron_aria-0.1.0-py2.7.egg && \
    chmod 0755 \
        /usr/local/bin/neutron-aria-agent \
        /usr/local/bin/start-neutron-aria-agent \
        /usr/local/bin/healthcheck-neutron-aria-agent && \
    mkdir -p /var/lib/neutron-aria-agent/state && \
    chown -R neutron:neutron /var/lib/neutron-aria-agent && \
    python -c "import netaddr; assert netaddr.__version__ == '0.7.19'" && \
    neutron-aria-agent --help >/dev/null

# Product shape: this container is a Neutron control-plane adapter, not the
# datapath owner. It should stay non-privileged and talk to aria-datapath only
# through /run/aria/aria-agent.sock.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["/usr/local/bin/healthcheck-neutron-aria-agent"]

USER neutron

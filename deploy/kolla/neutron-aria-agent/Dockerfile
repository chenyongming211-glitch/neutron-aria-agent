ARG BASE_IMAGE
FROM ${BASE_IMAGE}

USER root

COPY openstack/neutron_aria /opt/neutron_aria
COPY dist/kolla/python2-wheels/netaddr-0.7.19-py2.py3-none-any.whl /tmp/netaddr-0.7.19-py2.py3-none-any.whl
COPY deploy/kolla/neutron-aria-agent/start-neutron-aria-agent.sh /usr/local/bin/start-neutron-aria-agent

RUN python3 -m pip install --disable-pip-version-check --no-deps --upgrade \
        --target /usr/lib/python2.7/site-packages \
        /tmp/netaddr-0.7.19-py2.py3-none-any.whl && \
    rm -f /tmp/netaddr-0.7.19-py2.py3-none-any.whl && \
    cd /opt/neutron_aria && \
    rm -rf build dist neutron_aria.egg-info && \
    python setup.py install && \
    chmod 0755 /usr/local/bin/start-neutron-aria-agent && \
    mkdir -p /var/lib/neutron-aria-agent/state && \
    chown -R neutron:neutron /var/lib/neutron-aria-agent && \
    python -c "import netaddr; assert netaddr.__version__ == '0.7.19'" && \
    neutron-aria-agent --help >/dev/null

# Product shape: this container is a Neutron control-plane adapter, not the
# datapath owner. It should stay non-privileged and talk to aria-datapath only
# through /run/aria/aria-agent.sock.
USER neutron

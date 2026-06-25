ARG BASE_IMAGE
FROM ${BASE_IMAGE}

USER root

COPY openstack/neutron_aria /opt/neutron_aria
COPY deploy/kolla/neutron-aria-agent/start-neutron-aria-agent.sh /usr/local/bin/start-neutron-aria-agent

RUN cd /opt/neutron_aria && python setup.py install && \
    chmod 0755 /usr/local/bin/start-neutron-aria-agent && \
    mkdir -p /var/lib/neutron-aria-agent/state && \
    chown -R neutron:neutron /var/lib/neutron-aria-agent

# Product shape: this container is a Neutron control-plane adapter, not the
# datapath owner. It should stay non-privileged and talk to aria-datapath only
# through /run/aria/aria-agent.sock.
USER neutron

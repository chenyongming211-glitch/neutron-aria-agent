ARG BASE_IMAGE
FROM ${BASE_IMAGE}

USER root

COPY openstack/neutron_aria /opt/neutron_aria
COPY deploy/kolla/neutron-aria-agent/start-neutron-aria-agent.sh /usr/local/bin/start-neutron-aria-agent

RUN cd /opt/neutron_aria && python setup.py install && \
    chmod 0755 /usr/local/bin/start-neutron-aria-agent

# The target Kolla OVSDB socket is root-owned and not readable by the neutron
# user. Run as root until the product deployment provides a least-privilege
# OVSDB access group.
USER root

ARG BASE_IMAGE
FROM ${BASE_IMAGE}

USER root

COPY openstack/neutron_aria /opt/neutron_aria
COPY deploy/kolla/neutron-aria-agent/start-neutron-aria-agent.sh /usr/local/bin/start-neutron-aria-agent

RUN cd /opt/neutron_aria && python setup.py install && \
    chmod 0755 /usr/local/bin/start-neutron-aria-agent

USER neutron

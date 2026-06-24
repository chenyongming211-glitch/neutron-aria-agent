ARG BASE_IMAGE
FROM ${BASE_IMAGE}

USER root

COPY openstack/neutron_aria /opt/neutron_aria

RUN cd /opt/neutron_aria && python setup.py install

USER neutron

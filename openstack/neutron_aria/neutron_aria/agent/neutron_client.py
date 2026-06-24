from __future__ import absolute_import


class NeutronPortSource(object):
    """Thin adapter around legacy python-neutronclient.

    The real service will inject an authenticated neutronclient instance from
    the OpenStack runtime. Keeping this wrapper tiny makes unit tests and
    smoke scripts independent from the Neutron libraries.
    """

    def __init__(self, neutron_client, host):
        self.neutron_client = neutron_client
        self.host = host

    def list_ports_for_host(self):
        result = self.neutron_client.list_ports(**{"binding:host_id": self.host})
        if isinstance(result, dict):
            return result.get("ports", [])
        return result


class StaticPortSource(object):
    def __init__(self, ports):
        self.ports = list(ports)

    def list_ports_for_host(self):
        return list(self.ports)

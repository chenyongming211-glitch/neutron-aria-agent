from __future__ import absolute_import


class NeutronPortSource(object):
    """Thin adapter around legacy python-neutronclient.

    The real service will inject an authenticated neutronclient instance from
    the OpenStack runtime. Keeping this wrapper tiny makes unit tests and
    smoke scripts independent from the Neutron libraries.
    """

    def __init__(self, neutron_client, host, page_size=None):
        self.neutron_client = neutron_client
        self.host = host
        self.page_size = page_size

    def list_ports_for_host(self):
        ports = []
        marker = None

        while True:
            kwargs = {"binding:host_id": self.host}
            if self.page_size:
                kwargs["limit"] = self.page_size
            if marker:
                kwargs["marker"] = marker

            result = self.neutron_client.list_ports(**kwargs)
            batch, has_next = self._extract_ports_and_next(result)
            ports.extend(batch)

            if not has_next or not batch:
                break
            marker = batch[-1].get("id")
            if not marker:
                break

        return ports

    def _extract_ports_and_next(self, result):
        if isinstance(result, dict):
            return result.get("ports", []), self._has_next_link(result.get("ports_links", []))
        return result, False

    def _has_next_link(self, links):
        for link in links or []:
            if link.get("rel") == "next":
                return True
        return False


class NeutronFullResyncClient(object):
    def __init__(self, port_source):
        self.port_source = port_source

    def get_ports(self):
        return self.port_source.list_ports_for_host()


class StaticPortSource(object):
    def __init__(self, ports):
        self.ports = list(ports)

    def list_ports_for_host(self):
        return list(self.ports)

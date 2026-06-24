from __future__ import absolute_import

from neutron_aria.agent.inventory import PortInventoryBuilder


class GenerationStore(object):
    def __init__(self, initial=0):
        self.value = int(initial)

    def next(self):
        self.value += 1
        return self.value


class SnapshotSynchronizer(object):
    def __init__(
        self,
        host,
        port_source,
        ovs_reader,
        local_client,
        managed_domains=None,
        generation_store=None,
    ):
        self.host = host
        self.port_source = port_source
        self.ovs_reader = ovs_reader
        self.local_client = local_client
        self.managed_domains = list(managed_domains or ["acl"])
        self.generation_store = generation_store or GenerationStore()

    def check_capabilities(self):
        return self.local_client.capabilities(required_domains=self.managed_domains)

    def full_resync(self):
        self.check_capabilities()
        ports = self.port_source.list_ports_for_host()
        interfaces = self.ovs_reader.list_interfaces()
        builder = PortInventoryBuilder(
            self.host,
            managed_domains=self.managed_domains,
        )
        snapshot = builder.build_snapshot(
            ports,
            interfaces,
            generation=self.generation_store.next(),
        )
        response = self.local_client.put_snapshot(snapshot)
        return {
            "snapshot": snapshot,
            "response": response,
        }

    def delete_port(self, port_id):
        return self.local_client.delete_port(port_id)

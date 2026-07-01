from __future__ import absolute_import


def _rpc_target():
    try:
        import oslo_messaging
    except Exception:
        return None
    return oslo_messaging.Target(version="1.4")


def _port_value(port, key, default=None):
    if not port:
        return default
    if key in port:
        return port.get(key)
    return port.get(key.replace(":", "_"), default)


def rpc_topic_details(topics):
    return [
        [topics.PORT, topics.UPDATE],
        [topics.PORT, topics.DELETE],
        [topics.NETWORK, topics.UPDATE],
    ]


class AriaAgentRpcCallback(object):
    """Neutron agent RPC callbacks that feed the event merger only."""

    target = _rpc_target()

    def __init__(self, event_merger, local_host=None):
        self.event_merger = event_merger
        self.local_host = local_host

    def port_update(self, context, **kwargs):
        port = kwargs.get("port") or {}
        port_id = port.get("id") or kwargs.get("port_id")
        self.event_merger.record_port_update(
            port_id,
            binding_host=_port_value(port, "binding:host_id"),
            revision_number=port.get("revision_number"),
        )

    def port_delete(self, context, **kwargs):
        port = kwargs.get("port") or {}
        port_id = kwargs.get("port_id") or port.get("id")
        self.event_merger.record_port_delete(port_id)

    def network_update(self, context, **kwargs):
        network = kwargs.get("network") or {}
        self.event_merger.record_network_update(
            network.get("id") or kwargs.get("network_id")
        )


def build_rpc_connection(callback, start_listening=False):
    from neutron.agent import rpc as agent_rpc
    from neutron.common import topics

    return agent_rpc.create_consumers(
        [callback],
        topics.AGENT,
        rpc_topic_details(topics),
        start_listening=start_listening,
    )


def start_rpc_consumers(connection):
    if connection is not None and hasattr(connection, "consume_in_threads"):
        return connection.consume_in_threads()
    return None

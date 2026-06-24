from __future__ import absolute_import

try:
    import ConfigParser as configparser
except ImportError:
    import configparser


DEFAULT_SOCKET_PATH = "/run/aria/aria-agent.sock"
DEFAULT_OVS_BRIDGE = "br-int"
DEFAULT_MANAGED_DOMAINS = ("acl",)
DEFAULT_REPORT_INTERVAL = 30
DEFAULT_PORT_SOURCE = "disabled"
DEFAULT_EVENT_MERGE_INTERVAL = 0.2
DEFAULT_EVENT_QUEUE_MAX_PORTS = 10000
DEFAULT_EVENT_QUEUE_MAX_NETWORKS = 1000


class AgentConfig(object):
    def __init__(
        self,
        host=None,
        ovs_bridge=DEFAULT_OVS_BRIDGE,
        socket_path=DEFAULT_SOCKET_PATH,
        managed_domains=None,
        request_timeout=3.0,
        resync_interval=60,
        report_interval=DEFAULT_REPORT_INTERVAL,
        full_resync_enabled=False,
        port_source=DEFAULT_PORT_SOURCE,
        port_page_size=None,
        resync_backoff_initial=5,
        resync_backoff_max=300,
        rpc_events_enabled=False,
        event_merge_interval=DEFAULT_EVENT_MERGE_INTERVAL,
        event_queue_max_ports=DEFAULT_EVENT_QUEUE_MAX_PORTS,
        event_queue_max_networks=DEFAULT_EVENT_QUEUE_MAX_NETWORKS,
    ):
        self.host = host
        self.ovs_bridge = ovs_bridge
        self.socket_path = socket_path
        self.managed_domains = list(managed_domains or DEFAULT_MANAGED_DOMAINS)
        self.request_timeout = float(request_timeout)
        self.resync_interval = int(resync_interval)
        self.report_interval = int(report_interval)
        self.full_resync_enabled = bool(full_resync_enabled)
        self.port_source = port_source or DEFAULT_PORT_SOURCE
        self.port_page_size = int(port_page_size) if port_page_size else None
        self.resync_backoff_initial = int(resync_backoff_initial)
        self.resync_backoff_max = int(resync_backoff_max)
        self.rpc_events_enabled = bool(rpc_events_enabled)
        self.event_merge_interval = float(event_merge_interval)
        self.event_queue_max_ports = int(event_queue_max_ports)
        self.event_queue_max_networks = int(event_queue_max_networks)


def _get(parser, section, option, default=None):
    if parser.has_section(section) and parser.has_option(section, option):
        return parser.get(section, option)
    return default


def _split_domains(value):
    if not value:
        return list(DEFAULT_MANAGED_DOMAINS)
    return [part.strip() for part in value.split(",") if part.strip()]


def _parse_bool(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def load_config(path):
    parser_class = getattr(configparser, "SafeConfigParser", configparser.ConfigParser)
    parser = parser_class()
    parser.read(path)
    return AgentConfig(
        host=_get(parser, "agent", "host"),
        ovs_bridge=_get(parser, "ovs", "bridge", DEFAULT_OVS_BRIDGE),
        socket_path=_get(parser, "aria", "socket_path", DEFAULT_SOCKET_PATH),
        managed_domains=_split_domains(_get(parser, "agent", "managed_domains", "acl")),
        request_timeout=_get(parser, "aria", "request_timeout", "3.0"),
        resync_interval=_get(parser, "agent", "resync_interval", "60"),
        report_interval=_get(parser, "agent", "report_interval", str(DEFAULT_REPORT_INTERVAL)),
        full_resync_enabled=_parse_bool(
            _get(parser, "agent", "full_resync_enabled", "false"),
            default=False,
        ),
        port_source=_get(parser, "neutron", "port_source", DEFAULT_PORT_SOURCE),
        port_page_size=_get(parser, "neutron", "port_page_size"),
        resync_backoff_initial=_get(parser, "agent", "resync_backoff_initial", "5"),
        resync_backoff_max=_get(parser, "agent", "resync_backoff_max", "300"),
        rpc_events_enabled=_parse_bool(
            _get(parser, "neutron", "rpc_events_enabled", "false"),
            default=False,
        ),
        event_merge_interval=_get(
            parser,
            "neutron",
            "event_merge_interval",
            str(DEFAULT_EVENT_MERGE_INTERVAL),
        ),
        event_queue_max_ports=_get(
            parser,
            "neutron",
            "event_queue_max_ports",
            str(DEFAULT_EVENT_QUEUE_MAX_PORTS),
        ),
        event_queue_max_networks=_get(
            parser,
            "neutron",
            "event_queue_max_networks",
            str(DEFAULT_EVENT_QUEUE_MAX_NETWORKS),
        ),
    )

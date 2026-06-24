from __future__ import absolute_import

try:
    import ConfigParser as configparser
except ImportError:
    import configparser


DEFAULT_SOCKET_PATH = "/run/aria/aria-agent.sock"
DEFAULT_OVS_BRIDGE = "br-int"
DEFAULT_MANAGED_DOMAINS = ("acl",)


class AgentConfig(object):
    def __init__(
        self,
        host=None,
        ovs_bridge=DEFAULT_OVS_BRIDGE,
        socket_path=DEFAULT_SOCKET_PATH,
        managed_domains=None,
        request_timeout=3.0,
        resync_interval=60,
    ):
        self.host = host
        self.ovs_bridge = ovs_bridge
        self.socket_path = socket_path
        self.managed_domains = list(managed_domains or DEFAULT_MANAGED_DOMAINS)
        self.request_timeout = float(request_timeout)
        self.resync_interval = int(resync_interval)


def _get(parser, section, option, default=None):
    if parser.has_section(section) and parser.has_option(section, option):
        return parser.get(section, option)
    return default


def _split_domains(value):
    if not value:
        return list(DEFAULT_MANAGED_DOMAINS)
    return [part.strip() for part in value.split(",") if part.strip()]


def load_config(path):
    parser = configparser.SafeConfigParser()
    parser.read(path)
    return AgentConfig(
        host=_get(parser, "agent", "host"),
        ovs_bridge=_get(parser, "ovs", "bridge", DEFAULT_OVS_BRIDGE),
        socket_path=_get(parser, "aria", "socket_path", DEFAULT_SOCKET_PATH),
        managed_domains=_split_domains(_get(parser, "agent", "managed_domains", "acl")),
        request_timeout=_get(parser, "aria", "request_timeout", "3.0"),
        resync_interval=_get(parser, "agent", "resync_interval", "60"),
    )

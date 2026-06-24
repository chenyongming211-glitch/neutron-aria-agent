from __future__ import absolute_import

try:
    import ConfigParser as configparser
except ImportError:
    import configparser


DEFAULT_SOCKET_PATH = "/run/aria/aria-agent.sock"
DEFAULT_OVS_BRIDGE = "br-int"
DEFAULT_MANAGED_DOMAINS = ("acl",)
DEFAULT_REPORT_INTERVAL = 30


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
    ):
        self.host = host
        self.ovs_bridge = ovs_bridge
        self.socket_path = socket_path
        self.managed_domains = list(managed_domains or DEFAULT_MANAGED_DOMAINS)
        self.request_timeout = float(request_timeout)
        self.resync_interval = int(resync_interval)
        self.report_interval = int(report_interval)
        self.full_resync_enabled = bool(full_resync_enabled)


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
    )

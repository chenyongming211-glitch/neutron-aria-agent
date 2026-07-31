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
DEFAULT_REVISIONLESS_INCREMENTAL_MODE = "disabled"
DEFAULT_ACL_SOURCE = ""
DEFAULT_ACL_FIXTURE_PATH = ""
DEFAULT_REQUEST_TIMEOUT = 3.0
DEFAULT_TIMEOUT_CONVERGENCE_ATTEMPTS = 15
DEFAULT_TIMEOUT_CONVERGENCE_INTERVAL = 1.0
DEFAULT_STATE_DIR = "/var/lib/neutron-aria-agent/state"
SUPPORTED_MANAGED_DOMAINS = ("acl",)
SUPPORTED_ACL_SOURCES = ("disabled", "fixture", "neutron")
SUPPORTED_PORT_SOURCES = ("disabled", "neutronclient")
SUPPORTED_REVISIONLESS_INCREMENTAL_MODES = ("disabled", "experimental")
SYNC_MODE_HEARTBEAT_ONLY = "heartbeat_only"
SYNC_MODE_POLLING_FULL_RESYNC = "polling_full_resync"
SYNC_MODE_RPC_FULL_RESYNC = "rpc_full_resync"
SYNC_MODE_RPC_PORT_SCOPED = "rpc_port_scoped"
SYNC_MODE_RPC_PORT_SCOPED_REVISIONLESS_EXPERIMENTAL = (
    "rpc_port_scoped_revisionless_experimental"
)


class ConfigError(Exception):
    pass


def _optional_positive_int(value, option):
    if value is None or str(value).strip() == "":
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        raise ConfigError("%s must be a positive integer" % option)
    if parsed <= 0:
        raise ConfigError("%s must be a positive integer" % option)
    return parsed


class AgentConfig(object):
    def __init__(
        self,
        host=None,
        ovs_bridge=DEFAULT_OVS_BRIDGE,
        socket_path=DEFAULT_SOCKET_PATH,
        managed_domains=None,
        request_timeout=DEFAULT_REQUEST_TIMEOUT,
        timeout_convergence_attempts=DEFAULT_TIMEOUT_CONVERGENCE_ATTEMPTS,
        timeout_convergence_interval=DEFAULT_TIMEOUT_CONVERGENCE_INTERVAL,
        resync_interval=60,
        report_interval=DEFAULT_REPORT_INTERVAL,
        full_resync_enabled=False,
        port_source=DEFAULT_PORT_SOURCE,
        port_page_size=None,
        acl_page_size=None,
        resync_backoff_initial=5,
        resync_backoff_max=300,
        rpc_events_enabled=False,
        incremental_rpc_enabled=False,
        revisionless_incremental_mode=DEFAULT_REVISIONLESS_INCREMENTAL_MODE,
        event_merge_interval=DEFAULT_EVENT_MERGE_INTERVAL,
        event_queue_max_ports=DEFAULT_EVENT_QUEUE_MAX_PORTS,
        event_queue_max_networks=DEFAULT_EVENT_QUEUE_MAX_NETWORKS,
        acl_source=DEFAULT_ACL_SOURCE,
        acl_fixture_path=DEFAULT_ACL_FIXTURE_PATH,
        state_dir=DEFAULT_STATE_DIR,
    ):
        self.host = host
        self.ovs_bridge = ovs_bridge
        self.socket_path = socket_path
        self.managed_domains = list(managed_domains or DEFAULT_MANAGED_DOMAINS)
        self.request_timeout = float(request_timeout)
        self.timeout_convergence_attempts = int(timeout_convergence_attempts)
        self.timeout_convergence_interval = float(timeout_convergence_interval)
        self.resync_interval = int(resync_interval)
        self.report_interval = int(report_interval)
        self.full_resync_enabled = bool(full_resync_enabled)
        self.port_source = port_source or DEFAULT_PORT_SOURCE
        self.port_page_size = _optional_positive_int(
            port_page_size, "neutron.port_page_size"
        )
        self.acl_page_size = _optional_positive_int(
            acl_page_size, "neutron.acl_page_size"
        )
        self.resync_backoff_initial = int(resync_backoff_initial)
        self.resync_backoff_max = int(resync_backoff_max)
        self.rpc_events_enabled = bool(rpc_events_enabled)
        self.incremental_rpc_enabled = bool(incremental_rpc_enabled)
        self.revisionless_incremental_mode = (
            revisionless_incremental_mode or DEFAULT_REVISIONLESS_INCREMENTAL_MODE
        ).strip().lower()
        self.event_merge_interval = float(event_merge_interval)
        self.event_queue_max_ports = int(event_queue_max_ports)
        self.event_queue_max_networks = int(event_queue_max_networks)
        self.acl_source = self._normalize_acl_source(acl_source, acl_fixture_path)
        self.acl_fixture_path = acl_fixture_path or DEFAULT_ACL_FIXTURE_PATH
        self.state_dir = state_dir or DEFAULT_STATE_DIR

    def _normalize_acl_source(self, acl_source, acl_fixture_path):
        source = (acl_source or "").strip()
        if source:
            return source
        if acl_fixture_path:
            return "fixture"
        return "disabled"


def _get(parser, section, option, default=None):
    if parser.has_section(section) and parser.has_option(section, option):
        return parser.get(section, option)
    return default


def _get_first(parser, section, options, default=None):
    for option in options:
        value = _get(parser, section, option)
        if value is not None:
            return value
    return default


def _split_domains(value):
    if not value:
        return list(DEFAULT_MANAGED_DOMAINS)
    domains = []
    seen = set()
    for part in value.split(","):
        domain = part.strip().lower()
        if not domain or domain in seen:
            continue
        domains.append(domain)
        seen.add(domain)
    return domains


def _parse_bool(value, default=False, section=None, option=None):
    if value is None:
        return default
    normalized = str(value).strip().lower()
    if normalized in ("1", "true", "yes", "on"):
        return True
    if normalized in ("0", "false", "no", "off"):
        return False
    name = option or "boolean"
    if section:
        name = "%s.%s" % (section, name)
    raise ConfigError(
        "invalid boolean value for %s: %s" % (name, value)
    )


def _has_option_anywhere(parser, option):
    if option in parser.defaults():
        return True
    for section in parser.sections():
        if parser.has_option(section, option):
            return True
    return False


def validate_config(config):
    if not config.managed_domains:
        raise ConfigError("managed_domains must not be empty")
    unknown_domains = [
        domain for domain in config.managed_domains if domain not in SUPPORTED_MANAGED_DOMAINS
    ]
    if unknown_domains:
        raise ConfigError("unsupported managed_domains: %s" % ",".join(unknown_domains))

    if config.acl_source not in SUPPORTED_ACL_SOURCES:
        raise ConfigError("unsupported acl.source: %s" % config.acl_source)
    if config.acl_source == "fixture" and not config.acl_fixture_path:
        raise ConfigError("acl.source=fixture requires [acl] fixture_path")

    if config.port_source not in SUPPORTED_PORT_SOURCES:
        raise ConfigError("unsupported neutron.port_source: %s" % config.port_source)
    if config.revisionless_incremental_mode not in SUPPORTED_REVISIONLESS_INCREMENTAL_MODES:
        raise ConfigError(
            "unsupported neutron.revisionless_incremental_mode: %s"
            % config.revisionless_incremental_mode
        )
    if config.full_resync_enabled and config.port_source == "disabled":
        raise ConfigError(
            "full_resync_enabled=true requires [neutron] port_source=neutronclient"
        )
    if config.rpc_events_enabled:
        if not config.full_resync_enabled:
            raise ConfigError(
                "rpc_events_enabled=true requires [agent] full_resync_enabled=true"
            )
        if config.port_source != "neutronclient":
            raise ConfigError(
                "rpc_events_enabled=true requires [neutron] port_source=neutronclient"
            )
    if config.incremental_rpc_enabled:
        if not config.rpc_events_enabled:
            raise ConfigError(
                "incremental_rpc_enabled=true requires [neutron] rpc_events_enabled=true"
            )
        if not config.full_resync_enabled:
            raise ConfigError(
                "incremental_rpc_enabled=true requires [agent] full_resync_enabled=true"
            )
        if config.port_source != "neutronclient":
            raise ConfigError(
                "incremental_rpc_enabled=true requires [neutron] port_source=neutronclient"
            )
    if (
        config.revisionless_incremental_mode != DEFAULT_REVISIONLESS_INCREMENTAL_MODE and
        not config.incremental_rpc_enabled
    ):
        raise ConfigError(
            "revisionless_incremental_mode requires [neutron] incremental_rpc_enabled=true"
        )
    if config.request_timeout <= 0:
        raise ConfigError("aria.request_timeout must be positive")
    if config.request_timeout > DEFAULT_REQUEST_TIMEOUT:
        raise ConfigError(
            "aria.request_timeout must not exceed stage-one UDS timeout %.1fs"
            % DEFAULT_REQUEST_TIMEOUT
        )


def sync_mode(config):
    if not config.full_resync_enabled:
        return SYNC_MODE_HEARTBEAT_ONLY
    if not config.rpc_events_enabled:
        return SYNC_MODE_POLLING_FULL_RESYNC
    if not config.incremental_rpc_enabled:
        return SYNC_MODE_RPC_FULL_RESYNC
    if config.revisionless_incremental_mode == "experimental":
        return SYNC_MODE_RPC_PORT_SCOPED_REVISIONLESS_EXPERIMENTAL
    return SYNC_MODE_RPC_PORT_SCOPED


def resolved_acl_page_size(config):
    if config.acl_page_size is not None:
        return config.acl_page_size
    return config.port_page_size


def _validate_loaded_config(parser, config):
    if _has_option_anywhere(parser, "integration_mode"):
        raise ConfigError(
            "integration_mode belongs in Neutron snapshot bodies, not neutron-aria-agent.ini"
        )
    validate_config(config)


def load_config(path):
    parser = configparser.ConfigParser()
    parser.read(path)
    config = AgentConfig(
        host=_get(parser, "agent", "host"),
        ovs_bridge=_get_first(
            parser,
            "ovs",
            ("integration_bridge", "bridge"),
            DEFAULT_OVS_BRIDGE,
        ),
        socket_path=_get(parser, "aria", "socket_path", DEFAULT_SOCKET_PATH),
        managed_domains=_split_domains(_get(parser, "agent", "managed_domains", "acl")),
        request_timeout=_get(parser, "aria", "request_timeout", str(DEFAULT_REQUEST_TIMEOUT)),
        timeout_convergence_attempts=_get(
            parser,
            "aria",
            "timeout_convergence_attempts",
            str(DEFAULT_TIMEOUT_CONVERGENCE_ATTEMPTS),
        ),
        timeout_convergence_interval=_get(
            parser,
            "aria",
            "timeout_convergence_interval",
            str(DEFAULT_TIMEOUT_CONVERGENCE_INTERVAL),
        ),
        resync_interval=_get(parser, "agent", "resync_interval", "60"),
        report_interval=_get(parser, "agent", "report_interval", str(DEFAULT_REPORT_INTERVAL)),
        full_resync_enabled=_parse_bool(
            _get(parser, "agent", "full_resync_enabled", "false"),
            default=False,
            section="agent",
            option="full_resync_enabled",
        ),
        port_source=_get(parser, "neutron", "port_source", DEFAULT_PORT_SOURCE),
        port_page_size=_get(parser, "neutron", "port_page_size"),
        acl_page_size=_get(parser, "neutron", "acl_page_size"),
        resync_backoff_initial=_get(parser, "agent", "resync_backoff_initial", "5"),
        resync_backoff_max=_get(parser, "agent", "resync_backoff_max", "300"),
        rpc_events_enabled=_parse_bool(
            _get(parser, "neutron", "rpc_events_enabled", "false"),
            default=False,
            section="neutron",
            option="rpc_events_enabled",
        ),
        incremental_rpc_enabled=_parse_bool(
            _get(parser, "neutron", "incremental_rpc_enabled", "false"),
            default=False,
            section="neutron",
            option="incremental_rpc_enabled",
        ),
        revisionless_incremental_mode=_get(
            parser,
            "neutron",
            "revisionless_incremental_mode",
            DEFAULT_REVISIONLESS_INCREMENTAL_MODE,
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
        acl_source=_get(parser, "acl", "source", DEFAULT_ACL_SOURCE),
        acl_fixture_path=_get(parser, "acl", "fixture_path", DEFAULT_ACL_FIXTURE_PATH),
        state_dir=_get(parser, "agent", "state_dir", DEFAULT_STATE_DIR),
    )
    _validate_loaded_config(parser, config)
    return config

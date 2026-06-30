from __future__ import absolute_import

import logging
import optparse
import socket
import sys

from neutron_aria.agent.acl_source import build_acl_source
from neutron_aria.agent.config import load_config
from neutron_aria.agent.event_merge import EventMerger
from neutron_aria.agent.event_loop import SnapshotSynchronizer
from neutron_aria.agent.neutron_client import NeutronClientFactoryError
from neutron_aria.agent.neutron_client import StaticPortSource
from neutron_aria.agent.neutron_client import UnavailablePortSource
from neutron_aria.agent.neutron_client import build_port_source
from neutron_aria.agent.rpc import AriaAgentRpcCallback
from neutron_aria.agent.rpc import build_rpc_connection
from neutron_aria.agent.rpc import start_rpc_consumers
from neutron_aria.agent.service import AgentService
from neutron_aria.agent.state import SnapshotStateStore
from neutron_aria.agent.status_reporter import build_neutron_status_reporter
from neutron_aria.agent.uds_client import LocalClient


LOG = logging.getLogger(__name__)


def _default_host(config):
    return config.host or socket.getfqdn() or socket.gethostname()


def configure_logging():
    agent_logger = logging.getLogger("neutron_aria")
    has_stream_handler = False
    for handler in agent_logger.handlers:
        if getattr(handler, "_neutron_aria_stream", False):
            has_stream_handler = True
            break
    if not has_stream_handler:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)s %(name)s %(message)s",
        ))
        handler._neutron_aria_stream = True
        agent_logger.addHandler(handler)
    agent_logger.setLevel(logging.INFO)
    agent_logger.propagate = False


def build_synchronizer(
    config,
    neutron_port_source=None,
    status_reporter=None,
    neutron_acl_client=None,
    local_client=None,
):
    host = _default_host(config)
    port_source = neutron_port_source
    if port_source is None:
        if config.full_resync_enabled:
            try:
                port_source = build_port_source(config, host)
            except NeutronClientFactoryError as exc:
                port_source = UnavailablePortSource(str(exc))
        else:
            port_source = StaticPortSource([])
    return SnapshotSynchronizer(
        host=host,
        port_source=port_source,
        ovs_reader=None,
        local_client=local_client or LocalClient(
            config.socket_path,
            timeout=config.request_timeout,
        ),
        managed_domains=config.managed_domains,
        ovs_bridge=config.ovs_bridge,
        status_reporter=status_reporter,
        acl_source=build_acl_source(config, neutron_client=neutron_acl_client),
        state_store=SnapshotStateStore(config.state_dir),
        timeout_convergence_attempts=config.timeout_convergence_attempts,
        timeout_convergence_interval=config.timeout_convergence_interval,
    )


def initialize_neutron_runtime(config_files=None):
    try:
        from neutron.common import config as common_config
    except Exception:
        return False

    args = []
    for path in config_files or []:
        args.extend(["--config-file", path])
    common_config.init(args)
    try:
        common_config.setup_logging()
    except Exception:
        pass
    return True


def build_once_status_reporter(config, neutron_config_files=None):
    if config.acl_source != "neutron":
        return None
    initialize_neutron_runtime(neutron_config_files)
    return build_neutron_status_reporter(_default_host(config), config)


def main(argv=None):
    if argv is None:
        argv = sys.argv[1:]
    argv = list(argv)
    parser = optparse.OptionParser()
    parser.add_option(
        "-c",
        "--config-file",
        dest="config_file",
        default="/etc/neutron-aria-agent/neutron-aria-agent.ini",
    )
    parser.add_option(
        "--once",
        action="store_true",
        dest="once",
        default=False,
        help="run one empty-port resync smoke and exit",
    )
    parser.add_option(
        "--report-once",
        action="store_true",
        dest="report_once",
        default=False,
        help="send one Neutron heartbeat and exit",
    )
    parser.add_option(
        "--enable-full-resync",
        action="store_true",
        dest="enable_full_resync",
        default=False,
        help="allow the daemon to submit full snapshots",
    )
    parser.add_option(
        "--heartbeat-only",
        action="store_true",
        dest="heartbeat_only",
        default=False,
        help="keep full resync disabled and only publish Neutron heartbeat",
    )
    parser.add_option(
        "--enable-rpc-events",
        action="store_true",
        dest="enable_rpc_events",
        default=False,
        help="consume Neutron port/network RPC events",
    )
    parser.add_option(
        "--disable-rpc-events",
        action="store_true",
        dest="disable_rpc_events",
        default=False,
        help="disable Neutron port/network RPC event consumption",
    )
    parser.add_option(
        "--neutron-config-file",
        action="append",
        dest="neutron_config_files",
        default=[],
        help="Neutron config file used to initialize oslo.messaging",
    )
    options, _args = parser.parse_args(argv)
    config = load_config(options.config_file)
    if options.enable_full_resync:
        config.full_resync_enabled = True
    if options.heartbeat_only:
        config.full_resync_enabled = False
    if options.enable_rpc_events:
        config.rpc_events_enabled = True
    if options.disable_rpc_events:
        config.rpc_events_enabled = False

    if options.once:
        result = build_synchronizer(
            config,
            status_reporter=build_once_status_reporter(
                config,
                options.neutron_config_files,
            ),
        ).full_resync()
        print("snapshot generation %s submitted" % result["snapshot"]["generation"])
        return 0

    initialize_neutron_runtime(options.neutron_config_files)
    configure_logging()
    host = _default_host(config)
    LOG.info(
        "agent_start host=%s managed_domains=%s full_resync_enabled=%s "
        "rpc_events_enabled=%s port_source=%s ovs_bridge=%s socket_path=%s "
        "acl_source=%s acl_fixture_enabled=%s state_dir=%s",
        host,
        ",".join(config.managed_domains),
        config.full_resync_enabled,
        config.rpc_events_enabled,
        config.port_source,
        config.ovs_bridge,
        config.socket_path,
        config.acl_source,
        bool(config.acl_fixture_path),
        config.state_dir,
    )
    status_reporter = build_neutron_status_reporter(host, config)
    event_merger = None
    rpc_connection = None
    if config.rpc_events_enabled:
        event_merger = EventMerger(
            max_pending_ports=config.event_queue_max_ports,
            max_pending_networks=config.event_queue_max_networks,
        )
        rpc_callback = AriaAgentRpcCallback(event_merger, local_host=host)
        rpc_connection = build_rpc_connection(rpc_callback, start_listening=False)
        start_rpc_consumers(rpc_connection)

    service = AgentService(
        build_synchronizer(config, status_reporter=status_reporter),
        full_resync_enabled=config.full_resync_enabled,
        report_interval=config.report_interval,
        resync_interval=config.resync_interval,
        resync_backoff_initial=config.resync_backoff_initial,
        resync_backoff_max=config.resync_backoff_max,
        event_merger=event_merger,
        event_merge_interval=config.event_merge_interval,
    )
    if options.report_once:
        result = service.initialize()
        print("heartbeat %s reason=%s host=%s" % (
            result["heartbeat"],
            result["status"]["reason"],
            host,
        ))
        return 0

    try:
        service.run_forever()
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

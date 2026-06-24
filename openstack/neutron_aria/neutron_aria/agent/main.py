from __future__ import absolute_import

import optparse
import socket
import sys

from neutron_aria.agent.config import load_config
from neutron_aria.agent.event_loop import SnapshotSynchronizer
from neutron_aria.agent.neutron_client import StaticPortSource
from neutron_aria.agent.ovsdb import OvsdbInterfaceReader
from neutron_aria.agent.service import AgentService
from neutron_aria.agent.status_reporter import build_neutron_status_reporter
from neutron_aria.agent.uds_client import LocalClient


def _default_host(config):
    return config.host or socket.getfqdn() or socket.gethostname()


def build_synchronizer(config, neutron_port_source=None, status_reporter=None):
    host = _default_host(config)
    port_source = neutron_port_source or StaticPortSource([])
    return SnapshotSynchronizer(
        host=host,
        port_source=port_source,
        ovs_reader=OvsdbInterfaceReader(bridge_name=config.ovs_bridge),
        local_client=LocalClient(config.socket_path, timeout=config.request_timeout),
        managed_domains=config.managed_domains,
        ovs_bridge=config.ovs_bridge,
        status_reporter=status_reporter,
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

    if options.once:
        result = build_synchronizer(config).full_resync()
        print("snapshot generation %s submitted" % result["snapshot"]["generation"])
        return 0

    initialize_neutron_runtime(options.neutron_config_files)
    host = _default_host(config)
    status_reporter = build_neutron_status_reporter(host, config)
    service = AgentService(
        build_synchronizer(config, status_reporter=status_reporter),
        full_resync_enabled=config.full_resync_enabled,
        report_interval=config.report_interval,
        resync_interval=config.resync_interval,
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

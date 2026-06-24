from __future__ import absolute_import

import optparse
import socket

from neutron_aria.agent.config import load_config
from neutron_aria.agent.event_loop import SnapshotSynchronizer
from neutron_aria.agent.neutron_client import StaticPortSource
from neutron_aria.agent.ovsdb import OvsdbInterfaceReader
from neutron_aria.agent.uds_client import LocalClient


def _default_host(config):
    return config.host or socket.gethostname()


def build_synchronizer(config, neutron_port_source=None):
    host = _default_host(config)
    port_source = neutron_port_source or StaticPortSource([])
    return SnapshotSynchronizer(
        host=host,
        port_source=port_source,
        ovs_reader=OvsdbInterfaceReader(),
        local_client=LocalClient(config.socket_path, timeout=config.request_timeout),
        managed_domains=config.managed_domains,
    )


def main(argv=None):
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
    options, _args = parser.parse_args(argv)
    config = load_config(options.config_file)

    if options.once:
        result = build_synchronizer(config).full_resync()
        print("snapshot generation %s submitted" % result["snapshot"]["generation"])
        return 0

    parser.error("long-running service mode is not wired yet")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

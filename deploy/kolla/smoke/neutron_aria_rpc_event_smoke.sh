#!/usr/bin/env bash
set -euo pipefail

SERVICE_NAME="${SERVICE_NAME:-neutron_aria_agent}"
EXEC_USER="${EXEC_USER:-neutron}"

die() {
    echo "ERROR: $*" >&2
    exit 1
}

command -v docker >/dev/null 2>&1 || die "missing command: docker"

if ! docker ps --format '{{.Names}}' | grep -qx "${SERVICE_NAME}"; then
    die "${SERVICE_NAME} is not running"
fi

echo "Checking neutron-aria-agent RPC event package path in ${SERVICE_NAME}"
docker exec -i -u "${EXEC_USER}" "${SERVICE_NAME}" python - <<'PY'
from __future__ import print_function

from neutron_aria.agent.config import AgentConfig
from neutron_aria.agent.config import ConfigError
from neutron_aria.agent.config import validate_config
from neutron_aria.agent.event_merge import EventMerger
from neutron_aria.agent.service import AgentService
from neutron_aria.agent.status import AgentRuntimeStatus


def fail(message):
    raise SystemExit(message)


def assert_equal(expected, actual, message):
    if expected != actual:
        fail("%s: expected=%r actual=%r" % (message, expected, actual))


def expect_config_error(config, message):
    try:
        validate_config(config)
    except ConfigError:
        return
    fail(message)


class FakeClock(object):
    def __init__(self, value=0):
        self.value = value

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class FakeSynchronizer(object):
    def __init__(self):
        self.host = "local-host"
        self.runtime_status = AgentRuntimeStatus(self.host)
        self.resync_calls = 0
        self.heartbeat_calls = 0
        self.projected_port_ids = set()
        self.delete_calls = []
        self.delete_reasons = []

    def safe_full_resync(self):
        self.resync_calls += 1
        self.runtime_status.mark_ready(
            generation=self.resync_calls,
            snapshot_ports=1,
            managed_ports=1,
        )
        heartbeat = self.report_status()
        return {
            "snapshot": {"generation": self.resync_calls},
            "response": {},
            "status": self.runtime_status.to_dict(),
            "heartbeat": heartbeat,
        }

    def report_status(self):
        self.heartbeat_calls += 1
        return {
            "ok": True,
            "status": self.runtime_status.to_dict(),
        }

    def has_projected_port(self, port_id):
        return port_id in self.projected_port_ids

    def delete_port(self, port_id, reason=None):
        self.delete_calls.append(port_id)
        self.delete_reasons.append(reason)
        self.projected_port_ids.discard(port_id)
        return {"deleted": port_id}


def new_service():
    clock = FakeClock()
    sync = FakeSynchronizer()
    merger = EventMerger(clock=clock)
    service = AgentService(
        sync,
        full_resync_enabled=True,
        report_interval=5,
        resync_interval=60,
        event_merger=merger,
        event_merge_interval=0.2,
        clock=clock,
    )
    service.initialize()
    return clock, sync, merger, service


validate_config(AgentConfig(
    full_resync_enabled=True,
    port_source="neutronclient",
    rpc_events_enabled=True,
))
expect_config_error(
    AgentConfig(
        full_resync_enabled=False,
        port_source="neutronclient",
        rpc_events_enabled=True,
    ),
    "rpc_events_enabled must require full_resync_enabled",
)
expect_config_error(
    AgentConfig(
        full_resync_enabled=True,
        port_source="disabled",
        rpc_events_enabled=True,
    ),
    "rpc_events_enabled must require neutronclient port source",
)
expect_config_error(
    AgentConfig(
        full_resync_enabled=True,
        port_source="neutronclient",
        rpc_events_enabled=True,
        incremental_rpc_enabled=True,
    ),
    "incremental_rpc_enabled must remain disabled until P3 gate",
)

clock, sync, merger, service = new_service()
merger.record_port_update("p-local", binding_host="local-host")
clock.advance(0.2)
result = service.run_once()
assert_equal(2, sync.resync_calls, "local port update must trigger full resync")
assert_equal(["p-local"], result["events"]["port_updates"], "local port update recorded")
assert_equal("full_resync", result["events"]["decisions"][0]["action"], "local decision")

clock, sync, merger, service = new_service()
merger.record_network_update("net-local")
clock.advance(0.2)
result = service.run_once()
assert_equal(2, sync.resync_calls, "network update must trigger full resync")
assert_equal(["net-local"], result["events"]["dirty_networks"], "network update recorded")

clock, sync, merger, service = new_service()
merger.record_port_update("p-remote", binding_host="remote-host")
clock.advance(0.2)
result = service.run_once()
assert_equal(1, sync.resync_calls, "foreign unknown port update must not resync")
assert_equal([], sync.delete_calls, "foreign unknown port update must not delete")
assert_equal(None, result["snapshot"], "foreign unknown port update must be heartbeat only")
assert_equal("ignore", result["events"]["decisions"][0]["action"], "foreign decision")

clock, sync, merger, service = new_service()
sync.projected_port_ids.add("p-moved")
merger.record_port_update("p-moved", binding_host="remote-host")
clock.advance(0.2)
result = service.run_once()
assert_equal(1, sync.resync_calls, "foreign moved port must not full resync locally")
assert_equal(["p-moved"], sync.delete_calls, "foreign moved known port must cleanup")
assert_equal(["migration_source_cleanup"], sync.delete_reasons, "migration cleanup reason")
assert_equal(None, result["snapshot"], "foreign moved known port cleanup must not submit snapshot")

clock, sync, merger, service = new_service()
sync.projected_port_ids.add("p-delete")
merger.record_port_delete("p-delete")
clock.advance(0.2)
result = service.run_once()
assert_equal(1, sync.resync_calls, "known delete must use UDS delete instead of full resync")
assert_equal(["p-delete"], sync.delete_calls, "known delete must cleanup")
assert_equal(["port_delete_event"], sync.delete_reasons, "delete reason")
assert_equal(None, result["snapshot"], "known delete cleanup must not submit snapshot")

print("rpc_event_package_smoke=pass")
PY

echo "neutron-aria-agent RPC event package smoke passed"

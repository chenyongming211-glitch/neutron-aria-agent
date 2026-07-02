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
        self.scoped_calls = []
        self.forced_revision_status = None

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

    def decide_port_update(self, port_id, binding_host=None, revision_number=None):
        if binding_host and binding_host != self.host:
            if self.has_projected_port(port_id):
                return {
                    "action": "delete_local",
                    "reason": "foreign_host_update_for_projected_port",
                    "port_id": port_id,
                    "delete_reason": "migration_source_cleanup",
                }
            return {
                "action": "ignore",
                "reason": "foreign_host_update_for_unknown_port",
                "port_id": port_id,
            }
        revision_status = self.forced_revision_status
        if revision_status is None:
            revision_status = "newer" if revision_number is not None else "unknown"
        return {
            "action": "full_resync",
            "reason": "local_port_update",
            "port_id": port_id,
            "revision_status": revision_status,
        }

    def delete_port(self, port_id, reason=None):
        self.delete_calls.append(port_id)
        self.delete_reasons.append(reason)
        self.projected_port_ids.discard(port_id)
        return {"deleted": port_id}

    def apply_port_scoped_snapshot(
        self,
        port_id,
        binding_host=None,
        revision_number=None,
        allow_revisionless=False,
    ):
        self.scoped_calls.append({
            "port_id": port_id,
            "binding_host": binding_host,
            "revision_number": revision_number,
            "allow_revisionless": allow_revisionless,
        })
        generation = self.resync_calls + len(self.scoped_calls)
        self.runtime_status.mark_ready(
            generation=generation,
            snapshot_ports=1,
            managed_ports=1,
        )
        heartbeat = self.report_status()
        return {
            "submitted": True,
            "snapshot": {"generation": generation, "ports": [{"port_id": port_id}]},
            "response": {},
            "status": self.runtime_status.to_dict(),
            "heartbeat": heartbeat,
        }


def new_service(incremental_rpc_enabled=False, revisionless_incremental_mode="disabled"):
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
        incremental_rpc_enabled=incremental_rpc_enabled,
        revisionless_incremental_mode=revisionless_incremental_mode,
        clock=clock,
    )
    service.initialize()
    return clock, sync, merger, service


validate_config(AgentConfig(
    full_resync_enabled=True,
    port_source="neutronclient",
    rpc_events_enabled=True,
    incremental_rpc_enabled=True,
))
validate_config(AgentConfig(
    full_resync_enabled=True,
    port_source="neutronclient",
    rpc_events_enabled=True,
    incremental_rpc_enabled=True,
    revisionless_incremental_mode="experimental",
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
        rpc_events_enabled=False,
        incremental_rpc_enabled=True,
    ),
    "incremental_rpc_enabled must require rpc_events_enabled",
)
expect_config_error(
    AgentConfig(
        full_resync_enabled=True,
        port_source="neutronclient",
        rpc_events_enabled=True,
        incremental_rpc_enabled=False,
        revisionless_incremental_mode="experimental",
    ),
    "revisionless_incremental_mode must require incremental_rpc_enabled",
)

clock, sync, merger, service = new_service()
merger.record_port_update("p-local", binding_host="local-host")
clock.advance(0.2)
result = service.run_once()
assert_equal(2, sync.resync_calls, "local port update must trigger full resync")
assert_equal(["p-local"], result["events"]["port_updates"], "local port update recorded")
assert_equal("full_resync", result["events"]["decisions"][0]["action"], "local decision")
assert_equal(
    [{"action": "full_resync", "reason": "local_port_update", "count": 1}],
    result["status"]["last_event_decision_counts"],
    "local decision summary",
)

clock, sync, merger, service = new_service(incremental_rpc_enabled=True)
merger.record_port_update("p-scoped", binding_host="local-host", revision_number=9)
clock.advance(0.2)
result = service.run_once()
assert_equal(1, sync.resync_calls, "incremental local port update must not full resync")
assert_equal(1, len(sync.scoped_calls), "incremental local port update must use scoped apply")
assert_equal("p-scoped", sync.scoped_calls[0]["port_id"], "scoped port id")
assert_equal(False, sync.scoped_calls[0]["allow_revisionless"], "scoped revision guard")
assert_equal("port_scoped_apply", result["events"]["decisions"][0]["action"], "scoped decision")
assert_equal(True, result["events"]["incremental_submitted"], "scoped submit marker")
assert_equal(
    [{"action": "port_scoped_apply", "reason": "local_port_update", "count": 1}],
    result["status"]["last_event_decision_counts"],
    "scoped decision summary",
)

clock, sync, merger, service = new_service(incremental_rpc_enabled=True)
merger.record_port_update("p-revisionless", binding_host="local-host")
clock.advance(0.2)
result = service.run_once()
assert_equal([], sync.scoped_calls, "unknown revision must fall back by default")
assert_equal(2, sync.resync_calls, "unknown revision default must full resync")
assert_equal(
    "revision_unknown",
    result["events"]["decisions"][0]["incremental_reason"],
    "unknown revision default reason",
)

clock, sync, merger, service = new_service(
    incremental_rpc_enabled=True,
    revisionless_incremental_mode="experimental",
)
merger.record_port_update("p-revisionless", binding_host="local-host")
clock.advance(0.2)
result = service.run_once()
assert_equal(
    1,
    len(sync.scoped_calls),
    "unknown revision experimental mode must use scoped apply",
)
assert_equal(
    True,
    sync.scoped_calls[0]["allow_revisionless"],
    "revisionless experimental allow marker",
)
assert_equal(
    "experimental",
    result["events"]["decisions"][0]["incremental_revisionless_mode"],
    "revisionless experimental marker",
)

clock, sync, merger, service = new_service(incremental_rpc_enabled=True)
merger.record_port_update("p-local-1", binding_host="local-host")
merger.record_port_update("p-local-2", binding_host="local-host")
clock.advance(0.2)
result = service.run_once()
assert_equal([], sync.scoped_calls, "multi-port incremental batch must not use scoped apply")
assert_equal(2, sync.resync_calls, "multi-port incremental batch must fall back full resync")

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
assert_equal("ignore", result["status"]["last_event_decisions"][0]["action"], "foreign summary")

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

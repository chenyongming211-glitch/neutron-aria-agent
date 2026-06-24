from __future__ import absolute_import

import time


HEARTBEAT_ONLY_REASON = "full_resync_disabled"
HEARTBEAT_ONLY_ERROR = "full resync is disabled; heartbeat-only service mode"


class AgentService(object):
    """Long-running neutron-aria-agent service loop."""

    def __init__(
        self,
        synchronizer,
        full_resync_enabled=False,
        report_interval=30,
        resync_interval=60,
        resync_backoff_initial=5,
        resync_backoff_max=300,
        clock=None,
        sleeper=None,
    ):
        self.synchronizer = synchronizer
        self.full_resync_enabled = bool(full_resync_enabled)
        self.report_interval = max(1, int(report_interval))
        self.resync_interval = max(1, int(resync_interval))
        self.resync_backoff_initial = max(1, int(resync_backoff_initial))
        self.resync_backoff_max = max(
            self.resync_backoff_initial,
            int(resync_backoff_max),
        )
        self.current_resync_backoff = 0
        self.clock = clock or time.time
        self.sleeper = sleeper or time.sleep
        self.initialized = False
        self.next_report_at = 0
        self.next_resync_at = 0

    def initialize(self):
        now = self.clock()
        self.initialized = True
        if self.full_resync_enabled:
            result = self.synchronizer.safe_full_resync()
            self.next_resync_at = now + self._next_resync_delay(result)
            self.next_report_at = now + self.report_interval
            return result

        self.synchronizer.runtime_status.mark_degraded(
            HEARTBEAT_ONLY_REASON,
            HEARTBEAT_ONLY_ERROR,
        )
        heartbeat = self.synchronizer.report_status()
        self.next_report_at = now + self.report_interval
        return {
            "snapshot": None,
            "response": None,
            "status": self.synchronizer.runtime_status.to_dict(),
            "heartbeat": heartbeat,
        }

    def run_once(self):
        if not self.initialized:
            return self.initialize()

        now = self.clock()
        if self.full_resync_enabled and now >= self.next_resync_at:
            result = self.synchronizer.safe_full_resync()
            self.next_resync_at = now + self._next_resync_delay(result)
            self.next_report_at = now + self.report_interval
            return result

        if now >= self.next_report_at:
            heartbeat = self.synchronizer.report_status()
            self.next_report_at = now + self.report_interval
            return {
                "snapshot": None,
                "response": None,
                "status": self.synchronizer.runtime_status.to_dict(),
                "heartbeat": heartbeat,
            }

        return None

    def sleep_interval(self):
        now = self.clock()
        deadlines = [self.next_report_at]
        if self.full_resync_enabled:
            deadlines.append(self.next_resync_at)
        next_deadline = min([deadline for deadline in deadlines if deadline > 0])
        return max(1, int(next_deadline - now))

    def run_forever(self):
        self.initialize()
        while True:
            self.run_once()
            self.sleeper(self.sleep_interval())

    def _next_resync_delay(self, result):
        status = result.get("status") or {}
        heartbeat = result.get("heartbeat")
        heartbeat_failed = heartbeat is not None and not heartbeat.get("ok", False)
        if status.get("degraded") or heartbeat_failed:
            if self.current_resync_backoff:
                self.current_resync_backoff = min(
                    self.current_resync_backoff * 2,
                    self.resync_backoff_max,
                )
            else:
                self.current_resync_backoff = self.resync_backoff_initial
            return self.current_resync_backoff

        self.current_resync_backoff = 0
        return self.resync_interval

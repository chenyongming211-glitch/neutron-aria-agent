from __future__ import absolute_import

import unittest

from neutron_aria.agent.event_merge import EVENT_QUEUE_OVERFLOW
from neutron_aria.agent.event_merge import EventMerger


class FakeClock(object):
    def __init__(self, value=0):
        self.value = value

    def __call__(self):
        return self.value

    def advance(self, seconds):
        self.value += seconds


class EventMergerTestCase(unittest.TestCase):
    def test_port_update_keeps_latest_revision(self):
        merger = EventMerger()

        merger.record_port_update("p1", binding_host="compute-1", revision_number=4)
        merger.record_port_update("p1", binding_host="compute-2", revision_number=3)
        merger.record_port_update("p1", binding_host="compute-3", revision_number=5)

        batch = merger.drain()

        self.assertEqual(["p1"], sorted(batch.port_updates.keys()))
        self.assertEqual("compute-3", batch.port_updates["p1"]["binding_host"])
        self.assertEqual(5, batch.port_updates["p1"]["revision_number"])

    def test_delete_wins_over_previous_update(self):
        merger = EventMerger()

        merger.record_port_update("p1", binding_host="compute-1")
        merger.record_port_delete("p1")

        batch = merger.drain()

        self.assertEqual({}, batch.port_updates)
        self.assertEqual(["p1"], batch.deleted_ports)

    def test_update_after_delete_wins(self):
        merger = EventMerger()

        merger.record_port_delete("p1")
        merger.record_port_update("p1", binding_host="compute-1")

        batch = merger.drain()

        self.assertEqual(["p1"], sorted(batch.port_updates.keys()))
        self.assertEqual([], batch.deleted_ports)

    def test_merge_window_readiness(self):
        clock = FakeClock()
        merger = EventMerger(clock=clock)

        merger.record_port_update("p1")

        self.assertFalse(merger.ready(0.2))
        clock.advance(0.2)
        self.assertTrue(merger.ready(0.2))

    def test_merge_window_is_measured_from_latest_event(self):
        clock = FakeClock()
        merger = EventMerger(clock=clock)

        merger.record_port_update("p1")
        clock.advance(0.15)
        merger.record_port_update("p2")
        clock.advance(0.05)

        self.assertFalse(merger.ready(0.2))
        self.assertEqual(0.15, merger.last_pending_at())
        clock.advance(0.15)
        self.assertTrue(merger.ready(0.2))

    def test_queue_overflow_collapses_to_full_resync(self):
        merger = EventMerger(max_pending_ports=1)

        merger.record_port_update("p1")
        merger.record_port_update("p2")

        batch = merger.drain()

        self.assertTrue(batch.full_resync)
        self.assertTrue(batch.overflowed)
        self.assertIn(EVENT_QUEUE_OVERFLOW, batch.reasons)
        self.assertEqual({}, batch.port_updates)

    def test_sustained_events_drain_after_max_merge_delay(self):
        clock = FakeClock()
        merger = EventMerger(clock=clock)

        for index in range(50):
            merger.record_port_update("p%s" % index)
            self.assertFalse(merger.ready(0.2, max_merge_delay=5.0))
            clock.advance(0.1)

        # The silence window never opened; the absolute deadline fires.
        clock.advance(0.01)
        self.assertTrue(merger.ready(0.2, max_merge_delay=5.0))

    def test_max_merge_delay_is_measured_from_first_pending_event(self):
        clock = FakeClock()
        merger = EventMerger(clock=clock)

        merger.record_port_update("p1")
        clock.advance(4.9)
        merger.record_port_update("p2")

        self.assertFalse(merger.ready(0.2, max_merge_delay=5.0))
        clock.advance(0.1)
        self.assertTrue(merger.ready(0.2, max_merge_delay=5.0))

    def test_queue_overflow_preserves_deleted_ports(self):
        merger = EventMerger(max_pending_ports=1)

        merger.record_port_delete("p1")
        merger.record_port_update("p2")

        batch = merger.drain()

        self.assertTrue(batch.full_resync)
        self.assertTrue(batch.overflowed)
        self.assertEqual(["p1"], batch.deleted_ports)
        self.assertEqual({}, batch.port_updates)

    def test_aria_acl_domain_update_requests_full_resync(self):
        merger = EventMerger()

        merger.record_domain_update(
            domain="acl",
            resource="binding",
            operation="update",
            resource_id="binding-1",
            target_type="port",
            target_id="port-1",
            revision_number=7,
        )

        batch = merger.drain()

        self.assertTrue(batch.full_resync)
        self.assertEqual([], batch.deleted_ports)
        self.assertEqual({}, batch.port_updates)
        self.assertIn(
            "aria_domain_update:acl:binding:update:binding-1",
            batch.reasons,
        )


if __name__ == "__main__":
    unittest.main()

from __future__ import absolute_import

import unittest

from neutron_aria.agent.counter_sampler import MAX_BUCKET_ROWS
from neutron_aria.agent.counter_sampler import diff_port_counters


class CounterSamplerTestCase(unittest.TestCase):
    def _port(self, packets, dropped, sampled):
        return {
            "policy_packets": packets,
            "policy_bytes": packets * 10,
            "policy_allow_packets": packets - dropped,
            "policy_dropped_packets": dropped,
            "policy_dropped_bytes": dropped * 10,
            "drop_packets": dropped,
            "drop_bytes": dropped * 10,
            "buckets": [
                {"src_id": 1, "dst_id": 2, "proto": 6, "direction": 0,
                 "packets": packets, "bytes": packets * 10,
                 "dropped_packets": dropped, "dropped_bytes": dropped * 10}
            ],
            "reasons": [
                {"reason": 1, "direction": 0, "proto": 6,
                 "packets": dropped, "bytes": dropped * 10}
            ],
            "truncated": False,
            "sampled_at_ms": sampled,
        }

    def test_first_snapshot_has_no_rates(self):
        rows, reset = diff_port_counters(
            None, self._port(100, 10, 1000)
        )
        self.assertFalse(reset)
        for row in rows:
            self.assertIsNone(row["pps"])
            self.assertIsNone(row["bps"])

    def test_rates_are_differenced_over_elapsed_ms(self):
        rows, reset = diff_port_counters(
            self._port(100, 10, 1000),
            self._port(200, 20, 2000)
        )
        self.assertFalse(reset)
        policy = [r for r in rows if r["kind"] == "port"][0]
        self.assertAlmostEqual(policy["pps"], 100.0, places=3)
        self.assertAlmostEqual(policy["bps"], 1000.0, places=3)
        bucket = [r for r in rows if r["kind"] == "bucket"][0]
        self.assertAlmostEqual(bucket["pps"], 100.0, places=3)
        reason = [r for r in rows if r["kind"] == "reason"][0]
        self.assertAlmostEqual(reason["pps"], 10.0, places=3)

    def test_negative_delta_is_reset_and_rates_are_none(self):
        rows, reset = diff_port_counters(
            self._port(100, 10, 1000),
            self._port(50, 5, 2000)
        )
        self.assertTrue(reset)
        for row in rows:
            self.assertIsNone(row["pps"])
            self.assertIsNone(row["bps"])

    def test_negative_bucket_delta_resets_even_when_port_total_grows(self):
        previous = self._port(100, 10, 1000)
        previous["buckets"] = [
            {"src_id": 1, "dst_id": 2, "proto": 6, "direction": 0,
             "packets": 80, "bytes": 800,
             "dropped_packets": 10, "dropped_bytes": 100},
        ]
        current = self._port(120, 10, 2000)
        current["buckets"] = [
            {"src_id": 1, "dst_id": 2, "proto": 6, "direction": 0,
             "packets": 30, "bytes": 300,
             "dropped_packets": 5, "dropped_bytes": 50},
        ]
        rows, reset = diff_port_counters(previous, current)
        self.assertTrue(reset)
        for row in rows:
            self.assertIsNone(row["pps"])
            self.assertIsNone(row["bps"])

    def test_negative_reason_delta_resets_even_when_port_total_grows(self):
        previous = self._port(100, 10, 1000)
        previous["reasons"] = [
            {"reason": 1, "direction": 0, "proto": 6,
             "packets": 10, "bytes": 100},
        ]
        current = self._port(120, 15, 2000)
        current["reasons"] = [
            {"reason": 1, "direction": 0, "proto": 6,
             "packets": 4, "bytes": 40},
        ]
        rows, reset = diff_port_counters(previous, current)
        self.assertTrue(reset)
        for row in rows:
            self.assertIsNone(row["pps"])

    def test_bucket_rows_are_capped_at_512(self):
        current = self._port(100, 10, 1000)
        current["buckets"] = [
            {"src_id": i, "dst_id": 1, "proto": 6, "direction": 0,
             "packets": 1, "bytes": 1, "dropped_packets": 0,
             "dropped_bytes": 0}
            for i in range(600)
        ]
        rows, _ = diff_port_counters(None, current, )
        self.assertEqual(
            len([r for r in rows if r["kind"] == "bucket"]), MAX_BUCKET_ROWS
        )

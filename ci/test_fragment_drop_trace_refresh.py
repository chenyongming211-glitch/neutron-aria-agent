#!/usr/bin/env python3
"""Fragment resolve-stage drops must refresh the trace flag before recording.

Port-filtered tracing computes FLAG_TRACING once before fragment resolve,
when non-first fragments still carry zeroed L4 ports. The four resolve Drop
branches must therefore refresh the flag (with recovered ports where the
context allows) before phase_fragment_resolve_drop records the drop and the
optional trace event.
"""

from __future__ import print_function

import os
import re
import unittest

from ci.check_tc_acl_datapath import function_body


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
LIB = os.path.join(ROOT, "ebpf", "src", "lib.rs")

FUNCTIONS = (
    "try_tc_egress_v4",
    "try_tc_egress_v6",
    "try_tc_ingress_v4",
    "try_tc_ingress_v6",
)

DROP_ARM = re.compile(
    r"ResolveOutcome::Drop => \{\n(?P<body>.*?)\n        \}",
    re.DOTALL,
)


class FragmentDropTraceRefreshTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(LIB, "r", encoding="utf-8") as handle:
            cls.source = handle.read()

    def test_resolve_drop_arms_refresh_trace_flag_before_recording(self):
        for name in FUNCTIONS:
            body = function_body(self.source, name)
            arms = DROP_ARM.findall(body)
            self.assertTrue(arms, "%s has no resolve Drop arm" % name)
            for arm in arms:
                self.assertIn(
                    "refresh_trace_flag_tc(p, info);",
                    arm,
                    "%s Drop arm must refresh the trace flag" % name,
                )
                self.assertLess(
                    arm.index("refresh_trace_flag_tc(p, info);"),
                    arm.index("phase_fragment_resolve_drop_"),
                    "%s Drop arm must refresh before recording the drop" % name,
                )


if __name__ == "__main__":
    unittest.main()

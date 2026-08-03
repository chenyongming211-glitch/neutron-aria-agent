from __future__ import absolute_import

import base64
import unittest

from neutron_aria.db.aria_acl.errors import AriaAclNotFound
from neutron_aria.db.aria_acl.errors import AriaAclValidationError

try:
    from neutron_aria.db.aria_acl import query as query_contract
except ImportError:
    query_contract = None


def _b64(payload):
    encoded = base64.urlsafe_b64encode(payload)
    if not isinstance(encoded, str):
        encoded = encoded.decode("ascii")
    return encoded.rstrip("=")


class AriaAclQueryTestCase(unittest.TestCase):
    def setUp(self):
        self.rows = [
            {"id": "p3", "name": "same", "enabled": True, "revision_number": 3},
            {"id": "p1", "name": "same", "enabled": True, "revision_number": 1},
            {"id": "p2", "name": None, "enabled": False, "revision_number": 2},
        ]

    def _query_contract(self):
        self.assertIsNotNone(
            query_contract,
            "the shared aria_acl query contract module must exist",
        )
        return query_contract

    def test_forward_and_reverse_pages_use_identity_tie_breaker(self):
        contract = self._query_contract()
        first_query = contract.normalize_query(
            "policies", sorts=[("name", True)], limit=2
        )
        first = contract.apply_memory_query(self.rows, first_query)
        self.assertEqual(["p2", "p1"], [row["id"] for row in first])

        second_query = contract.normalize_query(
            "policies", sorts=[("name", True)], limit=2, marker="p1"
        )
        self.assertEqual(
            ["p3"],
            [
                row["id"]
                for row in contract.apply_memory_query(self.rows, second_query)
            ],
        )

        reverse_query = contract.normalize_query(
            "policies",
            sorts=[("name", True)],
            limit=2,
            marker="p3",
            page_reverse=True,
        )
        self.assertEqual(
            ["p2", "p1"],
            [
                row["id"]
                for row in contract.apply_memory_query(self.rows, reverse_query)
            ],
        )

    def test_typed_filters_aliases_and_fields_are_exact(self):
        contract = self._query_contract()
        query = contract.normalize_query(
            "policies",
            filters={"enabled": ["true"], "revision_number": ["1", "3"]},
            fields=["id", "name"],
        )
        self.assertEqual(
            [{"id": "p1", "name": "same"}, {"id": "p3", "name": "same"}],
            contract.apply_memory_query(self.rows, query),
        )

    def test_invalid_filter_sort_and_missing_marker_fail(self):
        contract = self._query_contract()
        self.assertRaises(
            AriaAclValidationError,
            contract.normalize_query,
            "address_sets",
            filters={"members": ["10.0.0.0/24"]},
        )
        self.assertRaises(
            AriaAclValidationError,
            contract.normalize_query,
            "port_statuses",
            sorts=[("runtime_status", True)],
        )
        query = contract.normalize_query("policies", limit=1, marker="missing")
        self.assertRaises(
            AriaAclNotFound,
            contract.apply_memory_query,
            self.rows,
            query,
        )

    def test_status_id_and_projected_filters_are_stable(self):
        contract = self._query_contract()
        status_id = contract.encode_port_status_id(
            "port-1", "compute-1.example.test"
        )
        self.assertTrue(status_id.startswith("aria-status-v1."))
        self.assertEqual(
            ("port-1", "compute-1.example.test"),
            contract.decode_port_status_id(status_id),
        )
        projection = contract.PortStatusProjection(
            now_epoch=200.0,
            stale_seconds=90,
        )
        rows = [{
            "port_id": "port-1",
            "host": "compute-1.example.test",
            "status": "ready",
            "updated_at": "1970-01-01T00:01:00.000000Z",
        }]
        query = contract.normalize_query(
            "port_statuses",
            filters={"stale": ["true"], "runtime_status": ["stale"]},
        )
        result = contract.apply_memory_query(rows, query, projection=projection)
        self.assertEqual([status_id], [row["id"] for row in result])

    def test_status_id_rejects_every_noncanonical_form(self):
        contract = self._query_contract()
        invalid_payloads = [
            "wrong-prefix.cG9ydC0xAG9zdGFjazI",
            "aria-status-v1.***",
            "aria-status-v1." + _b64(b"port-1\x00host\x00extra"),
            "aria-status-v1." + _b64(b"port-1\x00\xff"),
            "aria-status-v1.cG9ydC0xAG9zdGFjazI=",
        ]
        for value in invalid_payloads:
            self.assertRaises(
                AriaAclValidationError,
                contract.decode_port_status_id,
                value,
            )
        self.assertRaises(
            AriaAclValidationError,
            contract.encode_port_status_id,
            "p" * 37,
            "host",
        )
        self.assertRaises(
            AriaAclValidationError,
            contract.encode_port_status_id,
            "port-1",
            "h" * 256,
        )
        self.assertRaises(
            AriaAclValidationError,
            contract.normalize_query,
            "port_statuses",
            filters={"updated_at": ["not-a-timestamp"]},
        )

    def test_in_memory_repository_uses_the_shared_query_contract(self):
        contract = self._query_contract()
        from neutron_aria.db.aria_acl.api import InMemoryAriaAclRepository

        repository = InMemoryAriaAclRepository()
        for policy_id, name, revision in (
            ("p3", "same", 3),
            ("p1", "same", 1),
            ("p2", "", 2),
        ):
            repository.create_policy({
                "id": policy_id,
                "project_id": "project-1",
                "name": name,
                "revision_number": revision,
            })

        page = repository.list_policies(
            filters={"enabled": ["true"]},
            fields=["id", "name"],
            sorts=[("name", True)],
            limit=2,
        )
        self.assertEqual(
            [{"id": "p2", "name": ""}, {"id": "p1", "name": "same"}],
            page,
        )
        self.assertEqual(
            {"id": "p1"},
            repository.get_policy("p1", fields=["id"]),
        )
        self.assertEqual(
            {"tenant_id": "project-1"},
            repository.get_policy("p1", fields=["tenant_id"]),
        )

        repository.upsert_port_status({
            "port_id": "port-1",
            "host": "compute-1",
            "status": "ready",
            "updated_at": "1970-01-01T00:01:00.000000Z",
        })
        statuses = repository.list_port_statuses(
            filters={"stale": ["true"]},
            fields=["id", "runtime_status"],
            projection=contract.PortStatusProjection(9999999999.0, 90),
        )
        self.assertEqual(
            [{
                "id": contract.encode_port_status_id("port-1", "compute-1"),
                "runtime_status": "stale",
            }],
            statuses,
        )


if __name__ == "__main__":
    unittest.main()

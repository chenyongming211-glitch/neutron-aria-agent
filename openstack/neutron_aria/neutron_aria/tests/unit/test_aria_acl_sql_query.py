from __future__ import absolute_import

import inspect
import unittest

try:
    import sqlalchemy as sa
    from sqlalchemy import event
    from sqlalchemy.orm import sessionmaker
except ImportError:
    sa = None


@unittest.skipIf(sa is None, "SQLAlchemy DB contracts run in their own CI lane")
class AriaAclSqlQueryTestCase(unittest.TestCase):
    def setUp(self):
        from neutron_aria.db.aria_acl.api import NeutronDbAriaAclRepository

        self.engine = sa.create_engine("sqlite://")
        self.session = sessionmaker(bind=self.engine)()
        context = type("Context", (object,), {"session": self.session})()
        self.repository = NeutronDbAriaAclRepository(context, auto_create=True)
        self.statements = []
        event.listen(
            self.engine,
            "before_cursor_execute",
            self._record_statement,
        )

    def tearDown(self):
        self.session.close()
        self.engine.dispose()

    def _record_statement(
        self,
        connection,
        cursor,
        statement,
        parameters,
        context,
        executemany,
    ):
        del connection, cursor, parameters, context, executemany
        self.statements.append(statement)

    def _require_list_contract(self, method):
        if hasattr(inspect, "signature"):
            parameters = inspect.signature(method).parameters
        else:
            parameters = inspect.getargspec(method).args
        for name in (
            "filters",
            "fields",
            "sorts",
            "limit",
            "marker",
            "page_reverse",
        ):
            self.assertIn(
                name,
                parameters,
                "%s must accept %s" % (method.__name__, name),
            )

    def _create_policy(self, policy_id, name, revision_number):
        return self.repository.create_policy({
            "id": policy_id,
            "project_id": "project-1",
            "name": name,
            "revision_number": revision_number,
        })

    def test_address_set_page_uses_constant_member_queries(self):
        self._require_list_contract(self.repository.list_address_sets)
        for index in range(8):
            self.repository.create_address_set({
                "id": "set-%02d" % index,
                "project_id": "project-1",
                "members": [{"address": "10.0.%d.0/24" % index}],
            })

        self.statements[:] = []
        page = self.repository.list_address_sets(
            fields=["id", "members"],
            sorts=[("id", True)],
            limit=5,
        )
        self.assertEqual(5, len(page))
        self.assertEqual(2, len(self.statements))

        self.statements[:] = []
        without_members = self.repository.list_address_sets(
            fields=["id"],
            sorts=[("id", True)],
            limit=5,
        )
        self.assertEqual(5, len(without_members))
        self.assertEqual(1, len(self.statements))
        self.assertNotIn("members", without_members[0])

    def test_repository_query_parity(self):
        self._require_list_contract(self.repository.list_policies)
        self._create_policy("p3", "same", 3)
        self._create_policy("p1", "same", 1)
        self._create_policy("p2", "", 2)

        first = self.repository.list_policies(
            sorts=[("name", True)],
            limit=2,
        )
        self.assertEqual(["p2", "p1"], [row["id"] for row in first])
        second = self.repository.list_policies(
            sorts=[("name", True)],
            limit=2,
            marker="p1",
        )
        self.assertEqual(["p3"], [row["id"] for row in second])
        reverse = self.repository.list_policies(
            sorts=[("name", True)],
            limit=2,
            marker="p3",
            page_reverse=True,
        )
        self.assertEqual(["p2", "p1"], [row["id"] for row in reverse])
        filtered = self.repository.list_policies(
            filters={"enabled": ["true"], "revision_number": ["1", "3"]},
            fields=["id", "name"],
        )
        self.assertEqual(
            [{"id": "p1", "name": "same"}, {"id": "p3", "name": "same"}],
            filtered,
        )

    def test_custom_marker_cost_is_constant(self):
        self._require_list_contract(self.repository.list_policies)
        self._create_policy("p3", "same", 3)
        self._create_policy("p1", "same", 1)
        self._create_policy("p2", "", 2)

        self.statements[:] = []
        page = self.repository.list_policies(
            sorts=[("name", True)],
            marker="p1",
            limit=1,
        )
        self.assertEqual(["p3"], [row["id"] for row in page])
        self.assertEqual(2, len(self.statements))

    def test_status_composite_marker_visits_each_row_once(self):
        self._require_list_contract(self.repository.list_port_statuses)
        from neutron_aria.db.aria_acl.query import PortStatusProjection

        expected_hosts = (
            ("port-1", "ostack2"),
            ("port-1", "ostack3"),
            ("port-2", "ostack2"),
        )
        for port_id, host in expected_hosts:
            self.repository.upsert_port_status({
                "port_id": port_id,
                "host": host,
                "status": "ready",
            })

        marker = None
        seen = []
        while True:
            page = self.repository.list_port_statuses(
                sorts=[("port_id", True), ("host", True)],
                limit=1,
                marker=marker,
                projection=PortStatusProjection(
                    now_epoch=200.0,
                    stale_seconds=90,
                ),
            )
            if not page:
                break
            self.assertEqual(1, len(page))
            marker = page[0]["id"]
            self.assertNotIn(marker, seen)
            seen.append(marker)

        self.assertEqual(3, len(seen))


if __name__ == "__main__":
    unittest.main()

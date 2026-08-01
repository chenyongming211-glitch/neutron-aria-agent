from __future__ import absolute_import

import inspect
import os
import tempfile
import threading
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

        exact_timestamp = self.repository.get_port_status(
            "port-1", host="ostack2"
        )["updated_at"]
        exact = self.repository.list_port_statuses(
            filters={"last_reported_at": [exact_timestamp]},
            projection=PortStatusProjection(
                now_epoch=200.0,
                stale_seconds=-1,
            ),
        )
        self.assertEqual(
            [("port-1", "ostack2")],
            [(row["port_id"], row["host"]) for row in exact],
        )
        null_policy = self.repository.list_port_statuses(
            filters={"effective_policy_id": [None]},
            projection=PortStatusProjection(
                now_epoch=200.0,
                stale_seconds=-1,
            ),
        )
        self.assertEqual(3, len(null_policy))

    def test_concurrent_port_status_upserts_converge_without_conflict(self):
        from neutron_aria.db.aria_acl.api import NeutronDbAriaAclRepository

        barrier = threading.Barrier(2)

        class CoordinatedRepository(NeutronDbAriaAclRepository):
            def get_port_status(self, port_id, host=None):
                current = super(CoordinatedRepository, self).get_port_status(
                    port_id,
                    host=host,
                )
                if host is not None and current is None:
                    barrier.wait(timeout=5)
                return current

        fd, path = tempfile.mkstemp()
        os.close(fd)
        engine = sa.create_engine(
            "sqlite:///%s" % path,
            connect_args={"check_same_thread": False, "timeout": 5},
        )
        session_factory = sessionmaker(bind=engine)
        bootstrap_session = session_factory()
        context = type("Context", (object,), {"session": bootstrap_session})()
        NeutronDbAriaAclRepository(context, auto_create=True)
        bootstrap_session.close()
        errors = []

        def write_status(generation):
            session = session_factory()
            context = type("Context", (object,), {"session": session})()
            repository = CoordinatedRepository(context, auto_create=False)
            try:
                repository.upsert_port_status({
                    "port_id": "port-1",
                    "host": "ostack2",
                    "status": "ready",
                    "generation": generation,
                })
            except Exception as exc:
                errors.append(exc)
            finally:
                session.close()

        threads = [
            threading.Thread(target=write_status, args=(generation,))
            for generation in (1, 2)
        ]
        try:
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(10)
            self.assertFalse(any(thread.is_alive() for thread in threads))
            self.assertEqual([], errors)

            verify_session = session_factory()
            verify_context = type(
                "Context",
                (object,),
                {"session": verify_session},
            )()
            repository = NeutronDbAriaAclRepository(
                verify_context,
                auto_create=False,
            )
            status = repository.get_port_status("port-1", host="ostack2")
            self.assertIsNotNone(status)
            self.assertIn(status["generation"], (1, 2))
            verify_session.close()
        finally:
            engine.dispose()
            os.unlink(path)

    def test_address_set_delete_failure_restores_members_and_parent(self):
        self.repository.create_address_set({
            "id": "set-rollback",
            "project_id": "project-1",
            "members": [{"address": "10.0.0.0/24"}],
        })
        self.session.commit()
        original_delete = self.repository._delete

        def fail_parent_delete(*_args, **_kwargs):
            raise RuntimeError("injected parent delete failure")

        self.repository._delete = fail_parent_delete
        try:
            with self.assertRaises(RuntimeError):
                self.repository.delete_address_set("set-rollback")
        finally:
            self.repository._delete = original_delete

        restored = self.repository.get_address_set("set-rollback")
        self.assertEqual(
            [{"address": "10.0.0.0/24"}],
            restored["members"],
        )

    def test_address_set_create_member_failure_rolls_back_parent_and_members(self):
        from neutron_aria.db.aria_acl.api import AriaAclNotFound

        member_inserts = [0]

        def fail_second_member_insert(
            _connection,
            _cursor,
            statement,
            _parameters,
            _context,
            _executemany,
        ):
            if statement.startswith("INSERT INTO aria_acl_address_set_members"):
                member_inserts[0] += 1
                if member_inserts[0] == 2:
                    raise RuntimeError("injected member insert failure")

        event.listen(self.engine, "before_cursor_execute", fail_second_member_insert)
        try:
            with self.assertRaises(RuntimeError):
                self.repository.create_address_set({
                    "id": "set-create-rollback",
                    "project_id": "project-1",
                    "members": [
                        {"address": "10.0.0.0/24"},
                        {"address": "10.0.1.0/24"},
                    ],
                })
        finally:
            event.remove(
                self.engine,
                "before_cursor_execute",
                fail_second_member_insert,
            )

        with self.assertRaises(AriaAclNotFound):
            self.repository.get_address_set("set-create-rollback")

    def test_address_set_update_member_failure_restores_complete_preimage(self):
        self.repository.create_address_set({
            "id": "set-update-rollback",
            "project_id": "project-1",
            "name": "before",
            "members": [{"address": "10.0.0.0/24"}],
        })
        member_inserts = [0]

        def fail_second_member_insert(
            _connection,
            _cursor,
            statement,
            _parameters,
            _context,
            _executemany,
        ):
            if statement.startswith("INSERT INTO aria_acl_address_set_members"):
                member_inserts[0] += 1
                if member_inserts[0] == 2:
                    raise RuntimeError("injected member insert failure")

        event.listen(self.engine, "before_cursor_execute", fail_second_member_insert)
        try:
            with self.assertRaises(RuntimeError):
                self.repository.update_address_set(
                    "set-update-rollback",
                    {
                        "name": "after",
                        "members": [
                            {"address": "10.0.1.0/24"},
                            {"address": "10.0.2.0/24"},
                        ],
                    },
                )
        finally:
            event.remove(
                self.engine,
                "before_cursor_execute",
                fail_second_member_insert,
            )

        restored = self.repository.get_address_set("set-update-rollback")
        self.assertEqual("before", restored["name"])
        self.assertEqual(1, restored["revision_number"])
        self.assertEqual(
            [{"address": "10.0.0.0/24"}],
            restored["members"],
        )


if __name__ == "__main__":
    unittest.main()

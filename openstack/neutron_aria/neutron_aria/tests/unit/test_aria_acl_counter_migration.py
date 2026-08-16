from __future__ import absolute_import

import importlib
import unittest

try:
    import sqlalchemy as sa
except ImportError:
    sa = None


@unittest.skipIf(sa is None, "SQLAlchemy DB contracts run in their own CI lane")
class AriaAclCounterMigrationTestCase(unittest.TestCase):
    MIGRATION_MODULE = (
        "neutron_aria.db.aria_acl.migration.versions."
        "a4e7c2d9b610_add_acl_counter_schema"
    )
    FAMILY_MIGRATION_MODULE = (
        "neutron_aria.db.aria_acl.migration.versions."
        "c7d4e9a1b260_add_acl_counter_family"
    )

    def setUp(self):
        self.engine = sa.create_engine("sqlite://")
        metadata = sa.MetaData()
        self.legacy_statuses = sa.Table(
            "aria_acl_port_statuses",
            metadata,
            sa.Column("port_id", sa.String(36), primary_key=True),
            sa.Column("host", sa.String(255), primary_key=True),
            sa.Column("status", sa.String(64), nullable=False),
            sa.Column("updated_at", sa.DateTime()),
        )
        metadata.create_all(self.engine)
        with self.engine.begin() as connection:
            connection.execute(self.legacy_statuses.insert().values(
                port_id="port-before-counters",
                host="compute-1",
                status="applied",
            ))

    def tearDown(self):
        self.engine.dispose()

    def _migration(self):
        return importlib.import_module(self.MIGRATION_MODULE)

    def test_upgrade_from_write_invariant_schema_preserves_status_rows(self):
        migration = self._migration()

        changed = migration.upgrade_existing_schema(
            self.engine,
            sa_module=sa,
        )

        self.assertTrue(changed)
        self.assertEqual("f61a2c4e7b90", migration.down_revision)
        inspector = sa.inspect(self.engine)
        status_columns = set(
            column["name"]
            for column in inspector.get_columns("aria_acl_port_statuses")
        )
        self.assertIn("counters_policy_packets", status_columns)
        self.assertIn("counters_group_map", status_columns)
        self.assertIn("aria_acl_port_counters", inspector.get_table_names())

        counters_indexes = dict(
            (index["name"], index)
            for index in inspector.get_indexes("aria_acl_port_counters")
        )
        self.assertIn(
            "uq_aria_acl_port_counters_natural",
            counters_indexes,
        )
        self.assertTrue(
            counters_indexes["uq_aria_acl_port_counters_natural"].get("unique")
        )

        with self.engine.connect() as connection:
            row = connection.execute(sa.text(
                "SELECT port_id, host, status FROM aria_acl_port_statuses"
            )).fetchone()
        self.assertEqual(
            ("port-before-counters", "compute-1", "applied"),
            tuple(row),
        )

    def test_runtime_upgrade_is_idempotent(self):
        migration = self._migration()

        self.assertTrue(migration.upgrade_existing_schema(
            self.engine,
            sa_module=sa,
        ))
        self.assertFalse(migration.upgrade_existing_schema(
            self.engine,
            sa_module=sa,
        ))

    def test_counter_migration_adds_nullable_family_and_rebuilds_unique_index(self):
        base = self._migration()
        self.assertTrue(base.upgrade_existing_schema(self.engine, sa_module=sa))
        counters = sa.Table(
            "aria_acl_port_counters", sa.MetaData(), autoload_with=self.engine,
        )
        with self.engine.begin() as connection:
            connection.execute(counters.insert().values(
                id="counter-before-v2", port_id="p1", host="h1",
                kind="bucket", src_id=1, dst_id=2, proto=6,
                direction="ingress", packets=1, bytes=10,
            ))

        migration = importlib.import_module(self.FAMILY_MIGRATION_MODULE)
        self.assertTrue(migration.upgrade_existing_schema(self.engine, sa_module=sa))

        inspector = sa.inspect(self.engine)
        columns = dict(
            (column["name"], column)
            for column in inspector.get_columns("aria_acl_port_counters")
        )
        self.assertIn("ip_family", columns)
        self.assertTrue(columns["ip_family"]["nullable"])
        indexes = dict(
            (index["name"], index)
            for index in inspector.get_indexes("aria_acl_port_counters")
        )
        self.assertEqual(
            indexes["uq_aria_acl_port_counters_natural"]["column_names"],
            ["port_id", "host", "kind", "ip_family", "src_id", "dst_id",
             "proto", "direction", "reason"],
        )
        with self.engine.connect() as connection:
            row = connection.execute(sa.text(
                "SELECT id, ip_family FROM aria_acl_port_counters"
            )).fetchone()
        self.assertEqual(("counter-before-v2", None), tuple(row))
        self.assertFalse(migration.upgrade_existing_schema(self.engine, sa_module=sa))


if __name__ == "__main__":
    unittest.main()

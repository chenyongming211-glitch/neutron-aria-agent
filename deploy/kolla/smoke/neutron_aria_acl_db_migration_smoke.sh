#!/usr/bin/env bash
set -euo pipefail

CONTAINER="${CONTAINER:-neutron_server}"
ACTION="${1:-${ACTION:-upgrade}}"

log() {
    printf '[neutron-aria-acl-db-migration-smoke] %s\n' "$*"
}

if [ "$(id -u)" != "0" ]; then
    echo "This smoke must run as root on the OpenStack/Kolla host." >&2
    exit 1
fi

case "${ACTION}" in
    upgrade|check|downgrade)
        ;;
    *)
        echo "Usage: $0 [upgrade|check|downgrade]" >&2
        exit 1
        ;;
esac

log "Running aria_acl DB migration action=${ACTION} in ${CONTAINER}"
docker exec -i "${CONTAINER}" python - "${ACTION}" <<'PY'
from __future__ import print_function

import sys

from oslo_config import cfg

cfg.CONF(args=[
    '--config-file', '/etc/neutron/neutron.conf',
    '--config-file', '/etc/neutron/plugins/ml2/ml2_conf.ini',
    '--config-file', '/etc/neutron/plugins/ml2/ml2_conf_sriov.ini',
], project='neutron')

from neutron import context
from neutron_aria.db.aria_acl.api import NeutronDbAriaAclRepository
from neutron_aria.db.migration.aria_acl_write_invariants import (
    upgrade_existing_schema as upgrade_write_invariants,
)
from neutron_aria.db.migration.aria_acl_counters import (
    upgrade_existing_schema as upgrade_acl_counters,
    upgrade_counter_family_existing_schema,
)
from neutron_aria.db.migration.aria_acl_priority_family import (
    RULE_INDEX_COLUMNS_V2,
    RULE_INDEX,
    upgrade_existing_schema as upgrade_acl_priority_family,
)


ACTION = sys.argv[1]


def existing_tables(repo):
    bind = repo.session.get_bind()
    existing = []
    for name, table in repo.tables.items():
        if table.exists(bind=bind):
            existing.append(table.name)
    return sorted(existing)


def drop_tables(repo):
    bind = repo.session.get_bind()
    dropped = []
    for name in sorted(repo.tables.keys(), reverse=True):
        table = repo.tables[name]
        if table.exists(bind=bind):
            table.drop(bind=bind, checkfirst=True)
            dropped.append(table.name)
    return sorted(dropped)


ctx = context.get_admin_context()
repo = NeutronDbAriaAclRepository(ctx, auto_create=False)

if ACTION == "upgrade":
    write_invariants_changed = upgrade_write_invariants(
        repo.session.get_bind(),
        sa_module=repo.sa,
    )
    counters_changed = upgrade_acl_counters(
        repo.session.get_bind(),
        sa_module=repo.sa,
    )
    counter_family_changed = upgrade_counter_family_existing_schema(
        repo.session.get_bind(),
        sa_module=repo.sa,
    )
    priority_family_changed = upgrade_acl_priority_family(
        repo.session.get_bind(),
        sa_module=repo.sa,
    )
    repo.ensure_schema()
    print("write_invariants_upgraded=%s" % write_invariants_changed)
    print("acl_counters_upgraded=%s" % counters_changed)
    print("acl_counter_family_upgraded=%s" % counter_family_changed)
    print("acl_priority_family_upgraded=%s" % priority_family_changed)
    print("upgraded=%s" % ",".join(existing_tables(repo)))
elif ACTION == "check":
    expected = sorted(table.name for table in repo.tables.values())
    found = existing_tables(repo)
    missing = [name for name in expected if name not in found]
    print("found=%s" % ",".join(found))
    if missing:
        raise SystemExit("missing aria_acl tables: %s" % ",".join(missing))
    inspector = repo.sa.inspect(repo.session.get_bind())
    required_columns = {
        "aria_acl_port_statuses": (
            "counters_sampled_at",
            "counters_policy_packets",
            "counters_group_map",
        ),
        "aria_acl_port_counters": ("ip_family",),
    }
    missing_columns = []
    for table_name, column_names in sorted(required_columns.items()):
        present = set(
            column["name"] for column in inspector.get_columns(table_name)
        )
        missing_columns.extend(
            "%s.%s" % (table_name, column_name)
            for column_name in column_names
            if column_name not in present
        )
    if missing_columns:
        raise SystemExit(
            "missing aria_acl columns: %s" % ",".join(missing_columns)
        )
    print("schema_columns=pass")
    rule_indexes = dict(
        (index["name"], tuple(index.get("column_names") or ()))
        for index in inspector.get_indexes("aria_acl_rules")
    )
    if rule_indexes.get(RULE_INDEX) != RULE_INDEX_COLUMNS_V2:
        raise SystemExit(
            "invalid aria_acl priority index: %s" % (
                rule_indexes.get(RULE_INDEX),
            )
        )
    print("priority_family_index=pass")
elif ACTION == "downgrade":
    print("dropped=%s" % ",".join(drop_tables(repo)))
PY

if [ "${ACTION}" = "upgrade" ]; then
    log "Verifying aria_acl DB schema"
    bash "$0" check
fi

log "aria_acl DB migration action=${ACTION} ok"

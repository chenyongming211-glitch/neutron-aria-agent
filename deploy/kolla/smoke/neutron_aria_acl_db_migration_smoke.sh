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
    upgrade_existing_schema,
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
    changed = upgrade_existing_schema(
        repo.session.get_bind(),
        sa_module=repo.sa,
    )
    repo.ensure_schema()
    print("write_invariants_upgraded=%s" % changed)
    print("upgraded=%s" % ",".join(existing_tables(repo)))
elif ACTION == "check":
    expected = sorted(table.name for table in repo.tables.values())
    found = existing_tables(repo)
    missing = [name for name in expected if name not in found]
    print("found=%s" % ",".join(found))
    if missing:
        raise SystemExit("missing aria_acl tables: %s" % ",".join(missing))
elif ACTION == "downgrade":
    print("dropped=%s" % ",".join(drop_tables(repo)))
PY

if [ "${ACTION}" = "upgrade" ]; then
    log "Verifying aria_acl DB schema"
    bash "$0" check
fi

log "aria_acl DB migration action=${ACTION} ok"

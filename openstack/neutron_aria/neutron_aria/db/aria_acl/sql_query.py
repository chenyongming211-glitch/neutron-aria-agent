from __future__ import absolute_import

import datetime

from neutron_aria.db.aria_acl.errors import AriaAclValidationError
from neutron_aria.db.aria_acl.query import decode_port_status_id


def build_select(sa, table, query, marker_row=None, projection=None):
    statement = table.select()
    statement = _apply_filters(sa, statement, table, query, projection)
    if marker_row is not None:
        statement = statement.where(
            _keyset_boundary(
                sa,
                table,
                query.sorts,
                marker_row,
                query.page_reverse,
                projection,
            )
        )
    statement = statement.order_by(
        *_order_clauses(
            sa,
            table,
            query.sorts,
            query.page_reverse,
            projection,
        )
    )
    if query.limit is not None:
        statement = statement.limit(query.limit)
    return statement


def _apply_filters(sa, statement, table, query, projection):
    clauses = []
    for field, values in query.filters.items():
        if not values:
            clauses.append(sa.false())
            continue
        if query.spec.name == "port_statuses" and field == "id":
            identities = [decode_port_status_id(value) for value in values]
            clauses.append(sa.or_(*[
                sa.and_(table.c.port_id == port_id, table.c.host == host)
                for port_id, host in identities
            ]))
            continue
        expression = _expression(sa, table, field, projection)
        bound_values = _sql_filter_values(query, field, values)
        choices = []
        non_null = tuple(value for value in bound_values if value is not None)
        if non_null:
            choices.append(expression.in_(non_null))
        if None in bound_values:
            choices.append(expression.is_(None))
        clauses.append(sa.or_(*choices))
    if clauses:
        statement = statement.where(sa.and_(*clauses))
    return statement


def _keyset_boundary(
    sa,
    table,
    sorts,
    marker_row,
    page_reverse,
    projection,
):
    components = _sort_components(sa, table, sorts, marker_row, projection)
    prefixes = []
    terms = []
    for expression, ascending, marker_value in components:
        forward_ascending = ascending if not page_reverse else not ascending
        if marker_value is not None:
            comparison = (
                expression > marker_value
                if forward_ascending
                else expression < marker_value
            )
            terms.append(sa.and_(*(prefixes + [comparison])))
        prefixes.append(_equals(expression, marker_value))
    if not terms:
        return sa.false()
    return sa.or_(*terms)


def _order_clauses(sa, table, sorts, page_reverse, projection):
    clauses = []
    for field, ascending in sorts:
        expression = _expression(sa, table, field, projection)
        null_rank = _null_rank(sa, expression, ascending)
        components = ((null_rank, True), (expression, ascending))
        for component, component_ascending in components:
            effective = (
                component_ascending
                if not page_reverse
                else not component_ascending
            )
            clauses.append(component.asc() if effective else component.desc())
    return clauses


def _sort_components(sa, table, sorts, marker_row, projection):
    components = []
    for field, ascending in sorts:
        expression = _expression(sa, table, field, projection)
        marker_value = marker_row.get(field)
        components.append(
            (_null_rank(sa, expression, ascending), True,
             _null_rank_value(marker_value, ascending))
        )
        components.append((expression, ascending, marker_value))
    return components


def _expression(sa, table, field, projection):
    if field == "stale":
        return _stale_expression(sa, table, projection)
    if field == "runtime_status":
        stale = _stale_expression(sa, table, projection)
        return _case(
            sa,
            ((stale, "stale"),),
            else_=sa.func.coalesce(table.c.status, "unknown"),
        )
    try:
        return table.c[field]
    except KeyError:
        raise AriaAclValidationError("field %s has no SQL expression" % field)


def _sql_filter_values(query, field, values):
    if query.spec.name != "port_statuses" or field != "updated_at":
        return values
    return tuple(
        datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
        if value is not None else None
        for value in values
    )


def _stale_expression(sa, table, projection):
    if projection is None:
        raise AriaAclValidationError(
            "port_statuses projected query requires a status projection"
        )
    if projection.stale_seconds < 0:
        return sa.false()
    cutoff = datetime.datetime.utcfromtimestamp(
        projection.now_epoch - projection.stale_seconds
    )
    return sa.or_(table.c.updated_at.is_(None), table.c.updated_at < cutoff)


def _null_rank(sa, expression, ascending):
    return _case(
        sa,
        ((expression.is_(None), 0 if ascending else 1),),
        else_=1 if ascending else 0,
    )


def _case(sa, whens, else_):
    version = getattr(sa, "__version__", "1.0").split(".")
    try:
        modern_call = tuple(int(part) for part in version[:2]) >= (1, 4)
    except ValueError:
        modern_call = False
    if modern_call:
        return sa.case(*whens, else_=else_)
    return sa.case(list(whens), else_=else_)


def _null_rank_value(value, ascending):
    if value is None:
        return 0 if ascending else 1
    return 1 if ascending else 0


def _equals(expression, value):
    return expression.is_(None) if value is None else expression == value


_SQLITE_COLUMNS = {
    "policies": frozenset(("id", "project_id")),
    "rules": frozenset(("id", "project_id", "policy_id", "direction", "priority")),
    "address_sets": frozenset(("id", "project_id")),
    "bindings": frozenset(
        ("id", "project_id", "policy_id", "target_type", "target_id")
    ),
    "port_statuses": frozenset(("port_id", "host")),
}


def build_sqlite_select(table_name, query, marker_row=None, projection=None):
    where = []
    parameters = []
    for field, values in query.filters.items():
        if not values:
            where.append("0")
            continue
        if query.spec.name == "port_statuses" and field == "id":
            identities = [decode_port_status_id(value) for value in values]
            where.append("(" + " OR ".join(
                "(port_id=? AND host=?)" for _value in identities
            ) + ")")
            for port_id, host in identities:
                parameters.extend((port_id, host))
            continue
        expression = _sqlite_expression(query.spec.name, field, projection)
        non_null = [value for value in values if value is not None]
        choices = []
        if non_null:
            choices.append(
                "%s IN (%s)" % (
                    expression,
                    ",".join("?" for _value in non_null),
                )
            )
            parameters.extend(non_null)
        if None in values:
            choices.append("%s IS NULL" % expression)
        where.append("(" + " OR ".join(choices) + ")")

    if marker_row is not None:
        boundary, boundary_parameters = _sqlite_boundary(
            query,
            marker_row,
            projection,
        )
        where.append(boundary)
        parameters.extend(boundary_parameters)

    order = _sqlite_order(query, projection)
    sql = "SELECT payload FROM %s" % table_name
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY " + ", ".join(order)
    if query.limit is not None:
        sql += " LIMIT ?"
        parameters.append(query.limit)
    return sql, parameters


def _sqlite_boundary(query, marker_row, projection):
    components = []
    for field, ascending in query.sorts:
        expression = _sqlite_expression(query.spec.name, field, projection)
        value = marker_row.get(field)
        rank = _null_rank_value(value, ascending)
        rank_expression = "CASE WHEN %s IS NULL THEN %d ELSE %d END" % (
            expression,
            0 if ascending else 1,
            1 if ascending else 0,
        )
        components.extend(((rank_expression, True, rank), (expression, ascending, value)))

    prefixes = []
    terms = []
    parameters = []
    for expression, ascending, value in components:
        effective = ascending if not query.page_reverse else not ascending
        if value is not None:
            term_parts = []
            term_parameters = []
            for prefix_expression, prefix_value in prefixes:
                if prefix_value is None:
                    term_parts.append("%s IS NULL" % prefix_expression)
                else:
                    term_parts.append("%s = ?" % prefix_expression)
                    term_parameters.append(prefix_value)
            term_parts.append("%s %s ?" % (expression, ">" if effective else "<"))
            term_parameters.append(value)
            terms.append("(" + " AND ".join(term_parts) + ")")
            parameters.extend(term_parameters)
        prefixes.append((expression, value))
    return "(" + " OR ".join(terms or ("0",)) + ")", parameters


def _sqlite_order(query, projection):
    clauses = []
    for field, ascending in query.sorts:
        expression = _sqlite_expression(query.spec.name, field, projection)
        rank_expression = "CASE WHEN %s IS NULL THEN %d ELSE %d END" % (
            expression,
            0 if ascending else 1,
            1 if ascending else 0,
        )
        components = ((rank_expression, True), (expression, ascending))
        for component, component_ascending in components:
            effective = (
                component_ascending
                if not query.page_reverse
                else not component_ascending
            )
            clauses.append("%s %s" % (component, "ASC" if effective else "DESC"))
    return clauses


def _sqlite_expression(resource, field, projection):
    if field == "stale":
        return _sqlite_stale_expression(projection)
    if field == "runtime_status":
        return "CASE WHEN %s=1 THEN 'stale' ELSE COALESCE(%s, 'unknown') END" % (
            _sqlite_stale_expression(projection),
            _sqlite_json_expression("status"),
        )
    if field in _SQLITE_COLUMNS[resource]:
        return field
    return _sqlite_json_expression(field)


def _sqlite_stale_expression(projection):
    if projection is None:
        raise AriaAclValidationError(
            "port_statuses projected query requires a status projection"
        )
    if projection.stale_seconds < 0:
        return "0"
    cutoff_julian = (
        (projection.now_epoch - projection.stale_seconds) / 86400.0
    ) + 2440587.5
    updated = _sqlite_json_expression("updated_at")
    return (
        "CASE WHEN {updated} IS NULL OR julianday({updated}) IS NULL "
        "OR julianday({updated}) < {cutoff:.12f} THEN 1 ELSE 0 END"
    ).format(updated=updated, cutoff=cutoff_julian)


def _sqlite_json_expression(field):
    if re_safe_field(field):
        return "aria_json_scalar(payload, '%s')" % field
    raise AriaAclValidationError("invalid SQLite query field %s" % field)


def re_safe_field(field):
    return bool(field) and all(
        character.isalnum() or character == "_" for character in field
    )

"""SQL analysis via sqlglot: projections, SELECT *, JOIN/WHERE column usage.

This module is an *enhancer* for the engine, never a hard requirement: when a
node has no SQL or its SQL fails to parse, :func:`analyze_sql` returns ``None``
and the engine degrades to presence-based classification for that node.
"""

from __future__ import annotations

from dataclasses import dataclass

import sqlglot
from sqlglot import exp


@dataclass(frozen=True)
class SqlAnalysis:
    """What the engine needs to know about one node's transformation SQL."""

    select_star: bool
    #: output column name -> source column name (alias-aware, lowercased)
    projected: dict[str, str]
    #: column names used in a JOIN condition or WHERE clause (lowercased)
    join_or_where: set[str]


def analyze_sql(sql: str, dialect: str = "bigquery") -> SqlAnalysis | None:
    """Parse ``sql`` and extract projection/JOIN/WHERE facts.

    Returns ``None`` when the SQL cannot be parsed or contains no SELECT —
    callers must treat that as "no SQL available" and fall back gracefully.
    """
    try:
        statement = sqlglot.parse_one(sql, read=dialect)
    except Exception:  # sqlglot raises several error types; any of them = no info
        return None

    select = statement if isinstance(statement, exp.Select) else statement.find(exp.Select)
    if select is None:
        return None

    select_star = False
    projected: dict[str, str] = {}
    for projection in select.expressions:
        if isinstance(projection, exp.Star) or (
            isinstance(projection, exp.Column) and isinstance(projection.this, exp.Star)
        ):
            # `SELECT *` or a qualified `SELECT t.*`
            select_star = True
        elif isinstance(projection, exp.Column):
            projected[projection.name.lower()] = projection.name.lower()
        elif isinstance(projection, exp.Alias) and isinstance(projection.this, exp.Column):
            # `x AS y`: propagates under the output name y
            projected[projection.alias.lower()] = projection.this.name.lower()
        # Any other expression (aggregate, literal, function) does not carry a
        # raw column through: the column is read but dropped.

    join_or_where: set[str] = set()
    for join in select.find_all(exp.Join):
        on_condition = join.args.get("on")
        if on_condition is not None:
            join_or_where.update(c.name.lower() for c in on_condition.find_all(exp.Column))
    where_clause = select.args.get("where")
    if where_clause is not None:
        join_or_where.update(c.name.lower() for c in where_clause.find_all(exp.Column))

    return SqlAnalysis(select_star=select_star, projected=projected, join_or_where=join_or_where)

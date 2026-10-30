"""In-memory synthetic lineage source for tests, demos, and offline smoke runs.

The graph exercises every risk level (see ADR-0001):

    raw_customers (ORIGIN: email, phone, full_name)
        -> stg_customers (projects PII -> MEDIUM)
            -> dim_customers (drops phone -> MEDIUM)
                -> mart_orders_enriched (JOINs on email -> HIGH, PII not in output)
                    -> mart_daily_revenue (aggregates only -> NONE)
                -> mart_customer_dump (SELECT * -> LOW)
    raw_orders (no PII -> NONE)

All names are synthetic; there is no real company behind them.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from sensiflow.model import LineageGraph, Node, PiiTag
from sensiflow.root_selectors import GraphSelection
from sensiflow.sources.base import ExistingTag
from sensiflow.writeback import ApplyResult, TagChange

#: Physical output schema of each fixture node: what a catalog would list as
#: its columns. ``mart_orders_enriched`` does not output ``email`` (it only
#: joins on it), so a JOIN-only HIGH finding there has no column to tag.
_COLUMNS: dict[str, tuple[str, ...]] = {
    "raw_customers": ("customer_id", "email", "phone", "full_name", "segment"),
    "raw_orders": ("order_id", "customer_email", "order_date", "amount"),
    "stg_customers": ("customer_id", "email", "phone", "full_name"),
    "dim_customers": ("customer_id", "email", "full_name", "segment"),
    "mart_orders_enriched": ("order_id", "order_date", "amount", "segment"),
    "mart_customer_dump": ("customer_id", "email", "full_name", "segment"),
    "mart_daily_revenue": ("order_date", "revenue"),
}

_Key = tuple[str, str]


class MockSource:
    """A LineageSource and WritebackTarget over a small fixed synthetic graph.

    The graph is a fixture: the selection is accepted (to satisfy the
    LineageSource protocol) but ignored. Markup lives in memory: ``write_changes``
    mutates it and a subsequent ``read_markup`` / ``build_graph`` sees the
    result, giving offline tests the full plan -> diff -> apply -> re-diff
    cycle. Human markup (``managed=False``) seeds the graph like a real
    catalog's tags would; managed markup never does (ADR-0006 §4).

    ``fail_on`` makes ``write_changes`` fail for the given ``(node_id, column)``
    pairs — a hook for exercising partial-failure paths.
    """

    def __init__(
        self,
        markup: dict[_Key, ExistingTag] | None = None,
        *,
        fail_on: Iterable[_Key] = (),
    ) -> None:
        self._markup: dict[_Key, ExistingTag] = dict(markup or {})
        self._fail_on = frozenset(fail_on)

    # -- WritebackTarget -------------------------------------------------------

    def set_markup(self, node_id: str, column: str, existing: ExistingTag) -> None:
        """Place markup directly (test hook: simulate a human or a prior run)."""
        self._markup[(node_id, column.lower())] = existing

    def read_markup(self, node_ids: Sequence[str]) -> dict[_Key, ExistingTag]:
        wanted = set(node_ids)
        return {key: tag for key, tag in self._markup.items() if key[0] in wanted}

    def find_unmatched(self, changes: Sequence[TagChange]) -> dict[_Key, str]:
        unmatched: dict[_Key, str] = {}
        for change in changes:
            columns = _COLUMNS.get(change.node_id)
            if columns is None:
                unmatched[(change.node_id, change.column.lower())] = "node not found in target"
            elif change.column.lower() not in columns:
                unmatched[(change.node_id, change.column.lower())] = (
                    "column is not in the node's output schema"
                )
        return unmatched

    def write_changes(self, changes: Sequence[TagChange]) -> ApplyResult:
        result = ApplyResult(applied=[], failed=[])
        for change in changes:
            key = (change.node_id, change.column.lower())
            if key in self._fail_on:
                result.failed.append((change, "simulated write failure"))
                continue
            self._markup[key] = ExistingTag(
                tag=change.tag,
                managed=True,
                risk=change.risk,
                confidence=change.confidence,
                origin=change.origin_node,
            )
            result.applied.append(change)
        return result

    # -- LineageSource ---------------------------------------------------------

    def build_graph(self, selection: GraphSelection | None = None) -> LineageGraph:
        nodes = [
            Node(
                id="raw_customers",
                name="raw_customers",
                owners=["core-data@example.com"],
                declared_pii={
                    "email": PiiTag(category="email"),
                    "phone": PiiTag(category="phone"),
                    "full_name": PiiTag(category="name"),
                },
            ),
            Node(
                id="raw_orders",
                name="raw_orders",
                owners=["core-data@example.com"],
            ),
            Node(
                id="stg_customers",
                name="stg_customers",
                owners=["core-data@example.com"],
                upstream=["raw_customers"],
                sql=(
                    "SELECT customer_id, email, phone, full_name "
                    "FROM raw_customers"
                ),
            ),
            Node(
                id="dim_customers",
                name="dim_customers",
                owners=["analytics@example.com"],
                upstream=["stg_customers"],
                sql=(
                    "SELECT customer_id, email, full_name, segment "
                    "FROM stg_customers"
                ),
            ),
            Node(
                id="mart_orders_enriched",
                name="mart_orders_enriched",
                owners=["analytics@example.com"],
                upstream=["raw_orders", "dim_customers"],
                sql=(
                    "SELECT o.order_id, o.order_date, o.amount, c.segment "
                    "FROM raw_orders AS o "
                    "JOIN dim_customers AS c ON o.customer_email = c.email"
                ),
            ),
            Node(
                id="mart_customer_dump",
                name="mart_customer_dump",
                owners=["marketing@example.com"],
                upstream=["dim_customers"],
                sql="SELECT * FROM dim_customers",
            ),
            Node(
                id="mart_daily_revenue",
                name="mart_daily_revenue",
                owners=["finance@example.com"],
                upstream=["mart_orders_enriched"],
                sql=(
                    "SELECT order_date, SUM(amount) AS revenue "
                    "FROM mart_orders_enriched GROUP BY order_date"
                ),
            ),
        ]
        graph_nodes = {node.id: node for node in nodes}
        for (node_id, column), existing in self._markup.items():
            if not existing.managed and node_id in graph_nodes:
                graph_nodes[node_id].declared_pii[column] = existing.tag
        return LineageGraph(nodes=graph_nodes)

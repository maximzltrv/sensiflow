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

from sensiflow.model import LineageGraph, Node, PiiTag


class MockSource:
    """A LineageSource returning a small fixed synthetic graph."""

    def build_graph(self, root: str | None = None) -> LineageGraph:
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
        return LineageGraph(nodes={node.id: node for node in nodes})

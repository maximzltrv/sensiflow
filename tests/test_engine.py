"""Engine tests: risk levels and propagation invariants from ADR-0001."""

from __future__ import annotations

import pytest

from sensiflow import LineageGraph, Node, NodeResult, PiiTag, trace
from sensiflow.sources.mock import MockSource


@pytest.fixture(scope="module")
def mock_result() -> dict[str, NodeResult]:
    result = trace(MockSource().build_graph())
    return dict(result.nodes)


# --- the four risk levels on the mock graph -------------------------------


def test_declared_source_is_origin(mock_result: dict[str, NodeResult]) -> None:
    node = mock_result["raw_customers"]
    assert node.is_source
    assert node.max_risk == "ORIGIN"
    assert set(node.findings) == {"email", "phone", "full_name"}
    assert all(f.confidence == 1.0 for f in node.findings.values())


def test_explicit_projection_is_medium(mock_result: dict[str, NodeResult]) -> None:
    node = mock_result["stg_customers"]
    assert node.max_risk == "MEDIUM"
    assert set(node.findings) == {"email", "phone", "full_name"}
    assert all(f.risk == "MEDIUM" for f in node.findings.values())


def test_join_on_pii_is_high(mock_result: dict[str, NodeResult]) -> None:
    node = mock_result["mart_orders_enriched"]
    assert node.max_risk == "HIGH"
    assert node.findings["email"].risk == "HIGH"
    assert node.findings["email"].reason == "used in JOIN/WHERE"
    assert node.findings["email"].origin_node == "raw_customers"


def test_select_star_is_low_names_preserved(mock_result: dict[str, NodeResult]) -> None:
    node = mock_result["mart_customer_dump"]
    assert node.max_risk == "LOW"
    assert set(node.findings) == {"email", "full_name"}
    assert all(f.risk == "LOW" for f in node.findings.values())


def test_no_pii_is_none(mock_result: dict[str, NodeResult]) -> None:
    assert mock_result["raw_orders"].max_risk == "NONE"
    assert mock_result["mart_daily_revenue"].max_risk == "NONE"
    assert mock_result["mart_daily_revenue"].findings == {}


# --- propagation invariants ------------------------------------------------


def test_join_only_column_does_not_leak_downstream(mock_result: dict[str, NodeResult]) -> None:
    """email is HIGH on mart_orders_enriched but is not in its output."""
    downstream = mock_result["mart_daily_revenue"]
    assert "email" not in downstream.findings


def test_dropped_column_does_not_propagate(mock_result: dict[str, NodeResult]) -> None:
    """dim_customers projects email/full_name but drops phone."""
    node = mock_result["dim_customers"]
    assert "phone" not in node.findings
    assert set(node.findings) == {"email", "full_name"}


def test_confidence_decays_down_the_graph(mock_result: dict[str, NodeResult]) -> None:
    origin = mock_result["raw_customers"].findings["email"].confidence
    staged = mock_result["stg_customers"].findings["email"].confidence
    dumped = mock_result["mart_customer_dump"].findings["email"].confidence
    assert origin > staged > dumped


# --- degradation and denylist ----------------------------------------------


def test_unparseable_sql_degrades_to_presence_based() -> None:
    graph = LineageGraph(
        nodes={
            "src": Node(id="src", name="src", declared_pii={"email": PiiTag("email")}),
            "broken": Node(
                id="broken", name="broken", upstream=["src"], sql="%%% not sql at all %%%"
            ),
        }
    )
    result = trace(graph)
    node = result.nodes["broken"]
    assert node.max_risk == "LOW"
    assert node.findings["email"].reason == "present via lineage (no SQL available)"


def test_missing_sql_degrades_to_presence_based() -> None:
    graph = LineageGraph(
        nodes={
            "src": Node(id="src", name="src", declared_pii={"email": PiiTag("email")}),
            "no_sql": Node(id="no_sql", name="no_sql", upstream=["src"]),
        }
    )
    result = trace(graph)
    assert result.nodes["no_sql"].max_risk == "LOW"


def test_generic_name_denylist_suppresses_match() -> None:
    graph = LineageGraph(
        nodes={
            "src": Node(id="src", name="src", declared_pii={"value": PiiTag("misc")}),
            "down": Node(id="down", name="down", upstream=["src"], sql="SELECT value FROM src"),
        }
    )
    result = trace(graph)
    # The declared source keeps its ORIGIN finding: declarations are explicit.
    assert result.nodes["src"].max_risk == "ORIGIN"
    # But a downstream name-match on a generic column name is not trusted.
    assert result.nodes["down"].findings == {}


def test_cycle_raises() -> None:
    graph = LineageGraph(
        nodes={
            "a": Node(id="a", name="a", upstream=["b"]),
            "b": Node(id="b", name="b", upstream=["a"]),
        }
    )
    with pytest.raises(ValueError, match="cycle"):
        trace(graph)


def test_no_seeds_anywhere_produces_warning() -> None:
    graph = LineageGraph(
        nodes={
            "a": Node(id="a", name="a"),
            "b": Node(id="b", name="b", upstream=["a"], sql="SELECT x FROM a"),
        }
    )
    result = trace(graph)
    assert all(node.max_risk == "NONE" for node in result.nodes.values())
    assert any("no PII seeds" in warning for warning in result.warnings)


def test_graph_warnings_pass_through_to_result() -> None:
    graph = LineageGraph(
        nodes={"src": Node(id="src", name="src", declared_pii={"email": PiiTag("email")})},
        warnings=["downstream truncated at depth 1; consumers below this horizon "
                  "were not analyzed"],
    )
    result = trace(graph)
    assert result.warnings == graph.warnings


# --- result API --------------------------------------------------------------


def test_summary_counts_every_level() -> None:
    result = trace(MockSource().build_graph())
    summary = result.summary()
    assert summary == {"HIGH": 1, "MEDIUM": 2, "LOW": 1, "ORIGIN": 1, "NONE": 2}


def test_by_risk_filters_and_orders() -> None:
    result = trace(MockSource().build_graph())
    names = [n.name for n in result.by_risk(minimum="LOW")]
    assert names[0] == "mart_orders_enriched"  # HIGH first
    assert set(names) == {
        "mart_orders_enriched",
        "stg_customers",
        "dim_customers",
        "mart_customer_dump",
    }

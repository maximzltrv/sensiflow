"""Unit tests for evaluate_gate (ADR-0004 §2 / §5).

The gate is pure policy over a TraceResult, so most tests build results by
hand to pin the exact boundary semantics: both comparisons inclusive,
ORIGIN never trips, per-finding filtering, suppressed ordering.
"""

from __future__ import annotations

import dataclasses
from typing import cast

import pytest

from sensiflow.engine import trace
from sensiflow.exceptions import SensiflowInputError
from sensiflow.gate import GateRisk, evaluate_gate
from sensiflow.model import Finding, NodeResult, PiiTag, Risk, TraceResult
from sensiflow.sources.mock import MockSource


def _finding(
    column: str,
    risk: Risk,
    confidence: float = 0.9,
    origin: str = "raw_customers",
) -> Finding:
    return Finding(
        column=column,
        tag=PiiTag(category="email"),
        risk=risk,
        reason="selected in projection",
        confidence=confidence,
        origin_node=origin,
    )


def _node(node_id: str, *findings: Finding, name: str | None = None) -> NodeResult:
    return NodeResult(
        node_id=node_id,
        name=name or node_id,
        owners=[],
        is_source=False,
        findings={f.column: f for f in findings},
    )


def _result(*nodes: NodeResult) -> TraceResult:
    return TraceResult(nodes={n.node_id: n for n in nodes})


# --- risk threshold -------------------------------------------------------


def test_trips_at_and_above_threshold_most_exposed_first() -> None:
    result = _result(
        _node("low_node", _finding("a", "LOW")),
        _node("high_node", _finding("b", "HIGH")),
        _node("medium_node", _finding("c", "MEDIUM")),
    )
    outcome = evaluate_gate(result, fail_on="MEDIUM")
    assert outcome.tripped
    assert [n.node_id for n in outcome.violations] == ["high_node", "medium_node"]
    assert outcome.suppressed == ()


def test_threshold_is_inclusive() -> None:
    result = _result(_node("n", _finding("email", "MEDIUM")))
    assert evaluate_gate(result, fail_on="MEDIUM").tripped
    assert not evaluate_gate(result, fail_on="HIGH").tripped


def test_below_threshold_passes_cleanly() -> None:
    result = _result(_node("n", _finding("email", "LOW")))
    outcome = evaluate_gate(result, fail_on="MEDIUM")
    assert not outcome.tripped
    assert outcome.violations == ()
    assert outcome.suppressed == ()


def test_origin_never_trips() -> None:
    # A declared seed is the precondition of the analysis, not an exposure.
    result = _result(_node("seed", _finding("email", "ORIGIN", confidence=1.0)))
    outcome = evaluate_gate(result, fail_on="LOW")
    assert not outcome.tripped
    assert outcome.violations == ()


def test_violations_ordered_by_risk_then_name() -> None:
    result = _result(
        _node("z_high", _finding("a", "HIGH")),
        _node("a_high", _finding("b", "HIGH")),
        _node("m_medium", _finding("c", "MEDIUM")),
    )
    outcome = evaluate_gate(result, fail_on="LOW")
    assert [n.node_id for n in outcome.violations] == ["a_high", "z_high", "m_medium"]


# --- policy validation ----------------------------------------------------


@pytest.mark.parametrize("bad", ["ORIGIN", "NONE", "high", "CRITICAL", ""])
def test_invalid_fail_on_is_rejected(bad: str) -> None:
    result = _result(_node("n", _finding("email", "HIGH")))
    with pytest.raises(SensiflowInputError, match="fail-on"):
        evaluate_gate(result, fail_on=cast(GateRisk, bad))


@pytest.mark.parametrize("bad", [-0.01, 1.01, float("nan")])
def test_out_of_range_min_confidence_is_rejected(bad: float) -> None:
    result = _result(_node("n", _finding("email", "HIGH")))
    with pytest.raises(SensiflowInputError, match="min-confidence"):
        evaluate_gate(result, fail_on="HIGH", min_confidence=bad)


@pytest.mark.parametrize("boundary", [0.0, 1.0])
def test_min_confidence_range_boundaries_are_valid(boundary: float) -> None:
    result = _result(_node("n", _finding("email", "HIGH", confidence=1.0)))
    assert evaluate_gate(result, fail_on="HIGH", min_confidence=boundary).tripped


# --- confidence filtering (§5) --------------------------------------------


def test_confidence_boundary_is_inclusive() -> None:
    result = _result(_node("n", _finding("email", "HIGH", confidence=0.75)))
    outcome = evaluate_gate(result, fail_on="HIGH", min_confidence=0.75)
    assert outcome.tripped
    assert outcome.suppressed == ()


def test_low_confidence_finding_is_suppressed_not_dropped() -> None:
    finding = _finding("email", "HIGH", confidence=0.5)
    result = _result(_node("n", finding))
    outcome = evaluate_gate(result, fail_on="HIGH", min_confidence=0.75)
    assert not outcome.tripped
    assert outcome.violations == ()
    assert outcome.suppressed == (("n", finding),)


def test_node_violates_via_another_gating_finding() -> None:
    # Per-finding filtering: the suppressed HIGH does not shield the node
    # when a second finding still gates.
    weak = _finding("email", "HIGH", confidence=0.5)
    strong = _finding("phone", "HIGH", confidence=0.9)
    result = _result(_node("n", weak, strong))
    outcome = evaluate_gate(result, fail_on="HIGH", min_confidence=0.75)
    assert outcome.tripped
    assert [n.node_id for n in outcome.violations] == ["n"]
    assert outcome.suppressed == (("n", weak),)


def test_below_risk_threshold_findings_are_not_suppressed() -> None:
    # Suppression only collects findings at/above fail_on: a LOW finding
    # under a HIGH gate is simply out of scope, not "suppressed".
    result = _result(
        _node("n", _finding("email", "LOW", confidence=0.1), _finding("phone", "HIGH"))
    )
    outcome = evaluate_gate(result, fail_on="HIGH", min_confidence=0.75)
    assert outcome.tripped
    assert outcome.suppressed == ()


def test_default_min_confidence_suppresses_nothing() -> None:
    # 0.0 is opt-out: every finding gates, even at the engine's lowest beliefs.
    result = _result(_node("n", _finding("email", "HIGH", confidence=0.05)))
    outcome = evaluate_gate(result, fail_on="HIGH")
    assert outcome.min_confidence == 0.0
    assert outcome.tripped
    assert outcome.suppressed == ()


def test_suppressed_ordered_by_risk_then_node_name_then_column() -> None:
    # node ids deliberately disagree with names: ordering is by *name*.
    alpha = _node(
        "id_2",
        _finding("zz", "HIGH", confidence=0.1),
        _finding("mm", "MEDIUM", confidence=0.1),
        name="alpha",
    )
    beta = _node(
        "id_1",
        _finding("bb", "HIGH", confidence=0.1),
        _finding("aa", "HIGH", confidence=0.1),
        name="beta",
    )
    outcome = evaluate_gate(_result(alpha, beta), fail_on="MEDIUM", min_confidence=0.9)
    assert not outcome.tripped
    assert [(node_id, f.column) for node_id, f in outcome.suppressed] == [
        ("id_2", "zz"),  # HIGH, alpha
        ("id_1", "aa"),  # HIGH, beta
        ("id_1", "bb"),  # HIGH, beta
        ("id_2", "mm"),  # MEDIUM, alpha
    ]


# --- outcome shape ---------------------------------------------------------


def test_outcome_echoes_policy_and_is_frozen() -> None:
    result = _result(_node("n", _finding("email", "HIGH")))
    outcome = evaluate_gate(result, fail_on="HIGH", min_confidence=0.25)
    assert outcome.fail_on == "HIGH"
    assert outcome.min_confidence == 0.25
    with pytest.raises(dataclasses.FrozenInstanceError):
        outcome.tripped = False  # type: ignore[misc]  # frozen dataclass: assignment must raise


def test_gate_does_not_mutate_engine_output() -> None:
    result = trace(MockSource().build_graph())
    before = {node_id: node.max_risk for node_id, node in result.nodes.items()}
    evaluate_gate(result, fail_on="LOW", min_confidence=0.9)
    assert {node_id: node.max_risk for node_id, node in result.nodes.items()} == before


# --- against real engine output -------------------------------------------


def test_gate_over_mock_graph_trips_on_the_join_node() -> None:
    result = trace(MockSource().build_graph())
    outcome = evaluate_gate(result, fail_on="HIGH")
    assert outcome.tripped
    assert [n.node_id for n in outcome.violations] == ["mart_orders_enriched"]


def test_gate_over_mock_graph_excludes_pure_origins_at_low() -> None:
    result = trace(MockSource().build_graph())
    outcome = evaluate_gate(result, fail_on="LOW")
    violating = {n.node_id for n in outcome.violations}
    assert "raw_customers" not in violating  # ORIGIN ranks below LOW
    assert {"mart_orders_enriched", "stg_customers", "dim_customers"} <= violating


def test_confidence_compared_at_published_precision() -> None:
    # 0.8 * 0.7 == 0.5599999999999999 in floats but is published as 0.56 (A4).
    result = _result(_node("n", _finding("email", "LOW", 0.8 * 0.7)))
    assert evaluate_gate(result, fail_on="LOW", min_confidence=0.56).tripped
    assert not evaluate_gate(result, fail_on="LOW", min_confidence=0.5601).tripped

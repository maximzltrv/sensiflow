"""Renderer tests for the check command (ADR-0004 §4/§5).

Verify both formats against real engine output on the mock graph, with
special attention to the suppression rules: suppressed findings are always
surfaced, and a pass that depended on suppression is visibly different from
a clean pass on the verdict line.
"""

from __future__ import annotations

import json

from sensiflow.engine import trace
from sensiflow.gate import evaluate_gate
from sensiflow.model import Finding, NodeResult, PiiTag, TraceResult
from sensiflow.report import render_check_json, render_check_text, render_json
from sensiflow.sources.mock import MockSource


def _mock_result() -> TraceResult:
    return trace(MockSource().build_graph())


# --- text format ------------------------------------------------------------


def test_text_fail_shows_violations_only_and_verdict() -> None:
    result = _mock_result()
    out = render_check_text(result, evaluate_gate(result, fail_on="HIGH"))

    assert out.startswith("sensiflow check — fail-on=HIGH — 7 nodes analyzed\n")
    assert "summary: ORIGIN=1  LOW=1  MEDIUM=2  HIGH=1  NONE=2" in out
    assert "[HIGH] mart_orders_enriched  (owners: analytics@example.com)" in out
    assert "email" in out and "used in JOIN/WHERE" in out
    # check never dumps the whole graph — that is report's job.
    assert "stg_customers" not in out
    assert "suppressed" not in out
    assert out.rstrip().endswith("result: FAIL — 1 node at or above HIGH")


def test_text_clean_pass_verdict_without_confidence_clause() -> None:
    result = _mock_result()
    # Nothing above HIGH exists in the model, so gate on HIGH minus the one
    # HIGH node: build a result without it.
    nodes = {k: v for k, v in result.nodes.items() if k != "mart_orders_enriched"}
    trimmed = TraceResult(nodes=nodes, warnings=list(result.warnings))
    out = render_check_text(trimmed, evaluate_gate(trimmed, fail_on="HIGH"))

    assert out.rstrip().endswith("result: PASS — no findings at or above HIGH")
    assert "suppressed" not in out


def test_text_suppression_dependent_pass_is_visible() -> None:
    result = _mock_result()
    # The mock HIGH finding carries conf 1.0*0.9*0.9*0.9 ~= 0.73 < 0.9.
    outcome = evaluate_gate(result, fail_on="HIGH", min_confidence=0.9)
    assert not outcome.tripped and len(outcome.suppressed) == 1
    out = render_check_text(result, outcome)

    assert "suppressed by --min-confidence 0.9 (not gating): 1 finding" in out
    assert "[HIGH] mart_orders_enriched.email" in out
    assert "origin=raw_customers" in out
    assert out.rstrip().endswith(
        "result: PASS — no findings at or above HIGH with confidence >= 0.9 "
        "(1 suppressed below confidence)"
    )


def test_text_fail_verdict_states_suppressed_count() -> None:
    weak = Finding(
        column="email",
        tag=PiiTag(category="email"),
        risk="HIGH",
        reason="used in JOIN/WHERE",
        confidence=0.3,
        origin_node="raw_customers",
    )
    strong = Finding(
        column="phone",
        tag=PiiTag(category="phone"),
        risk="HIGH",
        reason="selected in projection",
        confidence=0.9,
        origin_node="raw_customers",
    )
    node = NodeResult(
        node_id="mart_contact_dump",
        name="mart_contact_dump",
        owners=["marketing@example.com"],
        is_source=False,
        findings={f.column: f for f in (weak, strong)},
    )
    result = TraceResult(nodes={node.node_id: node})
    out = render_check_text(result, evaluate_gate(result, fail_on="HIGH", min_confidence=0.5))

    assert out.rstrip().endswith(
        "result: FAIL — 1 node at or above HIGH (1 suppressed below confidence)"
    )
    # The suppressed finding appears only in its own section, not as gating.
    violations_block = out.split("suppressed by")[0]
    assert "phone" in violations_block
    assert "    email" not in violations_block
    assert "[HIGH] mart_contact_dump.email" in out


def test_text_plural_nodes_in_fail_verdict() -> None:
    result = _mock_result()
    out = render_check_text(result, evaluate_gate(result, fail_on="MEDIUM"))
    assert "result: FAIL — 3 nodes at or above MEDIUM" in out


def test_text_warnings_are_rendered() -> None:
    result = _mock_result()
    result.warnings.append("upstream walk truncated at depth 1")
    out = render_check_text(result, evaluate_gate(result, fail_on="HIGH"))
    assert "warning: upstream walk truncated at depth 1" in out


# --- json format ------------------------------------------------------------


def test_json_document_shape_and_trip() -> None:
    result = _mock_result()
    doc = render_check_json(result, evaluate_gate(result, fail_on="HIGH"))

    assert doc["fail_on"] == "HIGH"
    assert doc["min_confidence"] == 0.0
    assert doc["tripped"] is True
    assert doc["summary"] == {"HIGH": 1, "MEDIUM": 2, "LOW": 1, "ORIGIN": 1, "NONE": 2}
    assert doc["warnings"] == []
    assert [n["node_id"] for n in doc["violations"]] == ["mart_orders_enriched"]
    assert doc["suppressed"] == []
    json.dumps(doc)  # must be serializable as-is


def test_json_violation_nodes_match_report_serialization_exactly() -> None:
    # One serializer, one shape: a check violation entry must be identical to
    # the same node in `report --format json` (ADR-0004 §4).
    result = _mock_result()
    doc = render_check_json(result, evaluate_gate(result, fail_on="HIGH"))
    report_nodes = {n["node_id"]: n for n in render_json(result)["nodes"]}
    assert doc["violations"][0] == report_nodes["mart_orders_enriched"]


def test_json_suppressed_entries_carry_node_identity() -> None:
    result = _mock_result()
    doc = render_check_json(result, evaluate_gate(result, fail_on="HIGH", min_confidence=0.9))

    assert doc["tripped"] is False
    assert doc["violations"] == []
    (entry,) = doc["suppressed"]
    assert entry["node_id"] == "mart_orders_enriched"
    assert entry["name"] == "mart_orders_enriched"
    assert entry["column"] == "email"
    assert entry["risk"] == "HIGH"
    assert entry["confidence"] < 0.9
    # finding shape is report's finding shape, extended with node identity
    assert set(entry) == {
        "column",
        "category",
        "sensitive",
        "risk",
        "reason",
        "confidence",
        "origin_node",
        "node_id",
        "name",
    }
    json.dumps(doc)

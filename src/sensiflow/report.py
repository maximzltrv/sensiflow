"""Renderers for TraceResult and GateOutcome. The library never prints; these return values."""

from __future__ import annotations

from typing import Any

from sensiflow.gate import GateOutcome
from sensiflow.model import RISK_RANK, Finding, NodeResult, TraceResult


def _summary_line(result: TraceResult) -> str:
    summary = result.summary()
    return (
        "summary: "
        + "  ".join(f"{risk}={summary[risk]}" for risk in RISK_RANK if risk != "NONE")
        + f"  NONE={summary['NONE']}"
    )


def _finding_line(finding: Finding) -> str:
    return (
        f"    {finding.column:<12} {finding.risk:<7} {finding.reason:<36}"
        f" conf={finding.confidence:.2f}  origin={finding.origin_node}"
    )


def render_text(result: TraceResult) -> str:
    """A compact human-readable report, most exposed nodes first."""
    lines = [
        f"sensiflow report — {len(result.nodes)} nodes analyzed",
        _summary_line(result),
    ]
    lines.extend(f"warning: {warning}" for warning in result.warnings)
    lines.append("")
    ordered = sorted(
        result.nodes.values(), key=lambda n: (-RISK_RANK[n.max_risk], n.name)
    )
    for node in ordered:
        owners = ", ".join(node.owners) if node.owners else "-"
        lines.append(f"[{node.max_risk}] {node.name}  (owners: {owners})")
        for column in sorted(node.findings, key=lambda c: -RISK_RANK[node.findings[c].risk]):
            lines.append(_finding_line(node.findings[column]))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def _finding_json(finding: Finding) -> dict[str, Any]:
    return {
        "column": finding.column,
        "category": finding.tag.category,
        "sensitive": finding.tag.sensitive,
        "risk": finding.risk,
        "reason": finding.reason,
        "confidence": round(finding.confidence, 4),
        "origin_node": finding.origin_node,
    }


def _node_json(node: NodeResult) -> dict[str, Any]:
    return {
        "node_id": node.node_id,
        "name": node.name,
        "owners": node.owners,
        "is_source": node.is_source,
        "max_risk": node.max_risk,
        "findings": [_finding_json(f) for f in node.findings.values()],
    }


def render_json(result: TraceResult) -> dict[str, Any]:
    """A JSON-serializable dict mirroring the full TraceResult."""
    ordered = sorted(
        result.nodes.values(), key=lambda n: (-RISK_RANK[n.max_risk], n.name)
    )
    return {
        "summary": result.summary(),
        "warnings": list(result.warnings),
        "nodes": [_node_json(node) for node in ordered],
    }


def render_check_text(result: TraceResult, outcome: GateOutcome) -> str:
    """A compact gate summary (ADR-0004 §4): violations only, PASS/FAIL verdict.

    Suppressed findings (at/above threshold, below ``min_confidence``) get a
    dedicated section and are counted on the verdict line — a pass that
    depended on suppression must look different from a clean pass.
    """
    threshold = RISK_RANK[outcome.fail_on]
    suppressed_set = set(outcome.suppressed)
    lines = [
        f"sensiflow check — fail-on={outcome.fail_on} — {len(result.nodes)} nodes analyzed",
        _summary_line(result),
    ]
    lines.extend(f"warning: {warning}" for warning in result.warnings)
    lines.append("")
    for node in outcome.violations:
        owners = ", ".join(node.owners) if node.owners else "-"
        lines.append(f"[{node.max_risk}] {node.name}  (owners: {owners})")
        gating = [
            finding
            for finding in node.findings.values()
            if RISK_RANK[finding.risk] >= threshold
            and (node.node_id, finding) not in suppressed_set
        ]
        for finding in sorted(gating, key=lambda f: (-RISK_RANK[f.risk], f.column)):
            lines.append(_finding_line(finding))
        lines.append("")
    if outcome.suppressed:
        count = len(outcome.suppressed)
        plural = "s" if count != 1 else ""
        lines.append(
            f"suppressed by --min-confidence {outcome.min_confidence:g} (not gating): "
            f"{count} finding{plural}"
        )
        for node_id, finding in outcome.suppressed:
            lines.append(
                f"[{finding.risk}] {result.nodes[node_id].name}.{finding.column}   "
                f"conf={finding.confidence:.2f}  origin={finding.origin_node}"
            )
        lines.append("")
    lines.append(_verdict_line(outcome))
    return "\n".join(lines).rstrip() + "\n"


def _verdict_line(outcome: GateOutcome) -> str:
    suffix = ""
    if outcome.suppressed:
        suffix = f" ({len(outcome.suppressed)} suppressed below confidence)"
    if outcome.tripped:
        count = len(outcome.violations)
        plural = "s" if count != 1 else ""
        return f"result: FAIL — {count} node{plural} at or above {outcome.fail_on}{suffix}"
    verdict = f"result: PASS — no findings at or above {outcome.fail_on}"
    if outcome.min_confidence > 0.0:
        verdict += f" with confidence >= {outcome.min_confidence:g}"
    return verdict + suffix


def render_check_json(result: TraceResult, outcome: GateOutcome) -> dict[str, Any]:
    """A machine-stable gate document (ADR-0004 §4); evolution is additive-only.

    Violation entries reuse the exact node serialization of ``render_json`` —
    one serializer, one shape, no drift between ``report`` and ``check``.
    """
    return {
        "fail_on": outcome.fail_on,
        "min_confidence": outcome.min_confidence,
        "tripped": outcome.tripped,
        "summary": result.summary(),
        "warnings": list(result.warnings),
        "violations": [_node_json(node) for node in outcome.violations],
        "suppressed": [
            {
                **_finding_json(finding),
                "node_id": node_id,
                "name": result.nodes[node_id].name,
            }
            for node_id, finding in outcome.suppressed
        ],
    }

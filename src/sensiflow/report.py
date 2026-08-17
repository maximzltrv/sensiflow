"""Renderers for TraceResult. The library never prints; these return values."""

from __future__ import annotations

from typing import Any

from sensiflow.model import RISK_RANK, TraceResult


def render_text(result: TraceResult) -> str:
    """A compact human-readable report, most exposed nodes first."""
    summary = result.summary()
    lines = [
        f"sensiflow report — {len(result.nodes)} nodes analyzed",
        "summary: " + "  ".join(f"{risk}={summary[risk]}" for risk in RISK_RANK if risk != "NONE")
        + f"  NONE={summary['NONE']}",
        "",
    ]
    ordered = sorted(
        result.nodes.values(), key=lambda n: (-RISK_RANK[n.max_risk], n.name)
    )
    for node in ordered:
        owners = ", ".join(node.owners) if node.owners else "-"
        lines.append(f"[{node.max_risk}] {node.name}  (owners: {owners})")
        for column in sorted(node.findings, key=lambda c: -RISK_RANK[node.findings[c].risk]):
            finding = node.findings[column]
            lines.append(
                f"    {finding.column:<12} {finding.risk:<7} {finding.reason:<36}"
                f" conf={finding.confidence:.2f}  origin={finding.origin_node}"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_json(result: TraceResult) -> dict[str, Any]:
    """A JSON-serializable dict mirroring the full TraceResult."""
    ordered = sorted(
        result.nodes.values(), key=lambda n: (-RISK_RANK[n.max_risk], n.name)
    )
    return {
        "summary": result.summary(),
        "nodes": [
            {
                "node_id": node.node_id,
                "name": node.name,
                "owners": node.owners,
                "is_source": node.is_source,
                "max_risk": node.max_risk,
                "findings": [
                    {
                        "column": f.column,
                        "category": f.tag.category,
                        "sensitive": f.tag.sensitive,
                        "risk": f.risk,
                        "reason": f.reason,
                        "confidence": round(f.confidence, 4),
                        "origin_node": f.origin_node,
                    }
                    for f in node.findings.values()
                ],
            }
            for node in ordered
        ],
    }

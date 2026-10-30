"""Renderers for TraceResult and GateOutcome. The library never prints; these return values."""

from __future__ import annotations

from typing import Any

from sensiflow.gate import GateOutcome
from sensiflow.model import RISK_RANK, Finding, NodeResult, TraceResult
from sensiflow.writeback import ApplyResult, TagChange, WritebackAction, WritebackDiff


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


#: Display order of the write-back sections: conflicts first (they need a human).
_ACTION_ORDER: tuple[WritebackAction, ...] = (
    "conflict",
    "add",
    "update",
    "unchanged",
    "manual",
    "unmatched",
    "stale",
)

_SECTION_TITLES: dict[WritebackAction, str] = {
    "conflict": "CONFLICTS — human-placed markup contradicts the derivation (left untouched)",
    "add": "ADD — markup to be written",
    "update": "UPDATE — sensiflow-managed markup to be rewritten",
    "unchanged": "UNCHANGED — managed markup already matches",
    "manual": "MANUAL — compatible human-placed markup (left alone)",
    "unmatched": "UNMATCHED — the target cannot place these columns (nothing written)",
    "stale": "STALE — managed markup no current finding supports "
    "(would be removed by a future --prune)",
}


def _action_counts(diff: WritebackDiff) -> dict[WritebackAction, int]:
    counts: dict[WritebackAction, int] = {action: 0 for action in _ACTION_ORDER}
    for change in diff.changes:
        counts[change.action] += 1
    return counts


def _change_line(change: TagChange) -> str:
    kind = "sensitive" if change.tag.sensitive else "non-sensitive"
    line = (
        f"  [{change.risk}] {change.node_name}.{change.column}  "
        f"tag={change.tag.category} ({kind})  "
        f"conf={change.confidence:.2f}  origin={change.origin_node or '-'}"
    )
    if change.detail:
        detail = change.detail.replace("\n", "\n      ")
        line += f"\n      {detail}"
    return line


def _plan_header(diff: WritebackDiff, mode: str, target: str) -> list[str]:
    plan = diff.plan
    counts = _action_counts(diff)
    lines = [
        f"sensiflow propagate — min-risk={plan.min_risk} "
        f"min-confidence={plan.min_confidence:g} — target={target} — mode={mode}",
        "summary: " + "  ".join(f"{action}={counts[action]}" for action in _ACTION_ORDER),
    ]
    lines.extend(f"warning: {warning}" for warning in plan.warnings)
    lines.append("")
    return lines


def _plan_sections(diff: WritebackDiff) -> list[str]:
    lines: list[str] = []
    for action in _ACTION_ORDER:
        section = [c for c in diff.changes if c.action == action]
        if not section:
            continue
        lines.append(f"{_SECTION_TITLES[action]}: {len(section)}")
        lines.extend(_change_line(change) for change in section)
        lines.append("")
    suppressed = diff.plan.suppressed
    if suppressed:
        plural = "s" if len(suppressed) != 1 else ""
        lines.append(
            f"suppressed by --min-confidence {diff.plan.min_confidence:g} (not written): "
            f"{len(suppressed)} finding{plural}"
        )
        for change in suppressed:
            lines.append(
                f"[{change.risk}] {change.node_name}.{change.column}   "
                f"conf={change.confidence:.2f}  origin={change.origin_node}"
            )
        lines.append("")
    return lines


def render_apply_text(apply_result: ApplyResult) -> str:
    """The outcome of an apply: exactly what succeeded and what failed."""
    lines = [f"applied: {len(apply_result.applied)}"]
    lines.extend(_change_line(change) for change in apply_result.applied)
    lines.append(f"failed: {len(apply_result.failed)}")
    for change, error in apply_result.failed:
        lines.append(_change_line(change))
        lines.append(f"      error: {error}")
    lines.append(
        f"result: APPLIED — {len(apply_result.applied)} applied, "
        f"{len(apply_result.failed)} failed"
    )
    return "\n".join(lines) + "\n"


def render_plan_text(
    diff: WritebackDiff,
    apply_result: ApplyResult | None = None,
    *,
    target: str = "unknown",
    applying: bool = False,
) -> str:
    """The reviewable write-back document: per-action sections plus a mode-aware summary.

    With ``apply_result`` the outcome is appended (``--apply`` mode). With
    ``applying=True`` and no result, the document is the resolved diff printed
    *before* the apply starts, so the reviewed plan is on record even if the
    apply is interrupted.
    """
    mode = "apply" if apply_result is not None or applying else "dry-run"
    lines = _plan_header(diff, mode, target) + _plan_sections(diff)
    pending = len(diff.pending)
    plural = "s" if pending != 1 else ""
    if apply_result is not None:
        return "\n".join(lines) + "\n" + render_apply_text(apply_result)
    if applying:
        lines.append(f"applying {pending} pending change{plural}...")
    else:
        lines.append(
            f"result: DRY-RUN — {pending} change{plural} pending; "
            "re-run with --apply --yes to write"
        )
    return "\n".join(lines).rstrip() + "\n"


def _change_json(change: TagChange) -> dict[str, Any]:
    return {
        "node_id": change.node_id,
        "name": change.node_name,
        "column": change.column,
        "tag": {"category": change.tag.category, "sensitive": change.tag.sensitive},
        "risk": change.risk,
        "confidence": round(change.confidence, 4),
        "origin": change.origin_node,
        "action": change.action,
        "detail": change.detail,
    }


def render_plan_json(
    diff: WritebackDiff,
    apply_result: ApplyResult | None = None,
    *,
    target: str = "unknown",
) -> dict[str, Any]:
    """A machine-stable write-back document; evolution is additive-only (ADR-0006 §9)."""
    plan = diff.plan
    return {
        "mode": "dry-run" if apply_result is None else "apply",
        "target": target,
        "min_risk": plan.min_risk,
        "min_confidence": plan.min_confidence,
        "summary": _action_counts(diff),
        "changes": [_change_json(change) for change in diff.changes],
        # Suppressed findings were never classified against the target: no action.
        "suppressed": [
            {k: v for k, v in _change_json(change).items() if k not in ("action", "detail")}
            for change in plan.suppressed
        ],
        "warnings": list(plan.warnings),
        "applied": (
            None
            if apply_result is None
            else {
                "applied": [_change_json(change) for change in apply_result.applied],
                "failed": [
                    {**_change_json(change), "error": error}
                    for change, error in apply_result.failed
                ],
            }
        ),
    }

"""Plan / diff / apply: explicit write-back of derived PII markup (ADR-0006).

Three stages with strictly increasing authority:

* :func:`plan_writeback` is pure: the desired markup, computed from a
  ``TraceResult`` only.
* :func:`diff_writeback` is read-only I/O: reconciles the plan against the
  target's current markup. All conflict policy lives here, once; connectors
  only translate their catalog into :class:`~sensiflow.sources.base.ExistingTag`.
* :func:`apply_writeback` mutates, and only with ``confirm=True``.

Authority hierarchy: human > tool. Markup without the sensiflow marker is
never overwritten (``manual`` / ``conflict``); only marker-bearing markup may
be updated. Nothing here prints, exits, or knows a catalog client.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal

from sensiflow.exceptions import SensiflowInputError
from sensiflow.model import RISK_RANK, Finding, NodeResult, PiiTag, Risk, TraceResult

if TYPE_CHECKING:
    from sensiflow.sources.base import ExistingTag, WritebackTarget

WritebackAction = Literal[
    "add",  # column has no markup; tag will be written
    "update",  # sensiflow-managed markup exists but its payload differs
    "unchanged",  # sensiflow-managed markup already matches
    "manual",  # compatible human markup exists; left alone
    "conflict",  # human markup contradicts the derivation; left alone, flagged
    "unmatched",  # the target cannot place this column; nothing to write
    "stale",  # managed markup with no supporting finding; reported, never removed
]

#: Thresholds a plan may use. ORIGIN is a declared seed and NONE would select
#: nothing meaningful — neither is a valid write-back threshold.
_PLAN_THRESHOLDS: frozenset[str] = frozenset({"LOW", "MEDIUM", "HIGH"})

_PENDING_ACTIONS: frozenset[str] = frozenset({"add", "update"})


@dataclass(frozen=True)
class TagChange:
    """One column-level markup change (or its reconciled non-change)."""

    node_id: str
    node_name: str
    column: str
    tag: PiiTag
    risk: Risk
    confidence: float
    origin_node: str
    action: WritebackAction = "add"
    detail: str = ""  # human-readable qualifier (conflicting tag, unmatched reason, ...)


@dataclass
class TagPlan:
    """Desired derived markup, target-agnostic (output of :func:`plan_writeback`).

    ``traced_nodes`` (node id -> name, every node of the trace) bounds stale
    detection to the traced subgraph; ``warnings`` carries the trace's caveats
    through to the renderers.
    """

    min_risk: Risk
    min_confidence: float
    changes: list[TagChange]  # all action="add" at this stage
    suppressed: list[TagChange]  # at/above min_risk but below min_confidence
    traced_nodes: dict[str, str] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


@dataclass
class WritebackDiff:
    """The plan reconciled against the target (output of :func:`diff_writeback`)."""

    plan: TagPlan
    changes: list[TagChange]  # every entry carries its final action

    @property
    def pending(self) -> list[TagChange]:
        """Changes :func:`apply_writeback` would execute (``add`` / ``update``)."""
        return [c for c in self.changes if c.action in _PENDING_ACTIONS]


@dataclass
class ApplyResult:
    """What an apply did: executed changes and per-change failures."""

    applied: list[TagChange]
    failed: list[tuple[TagChange, str]]  # change + error message


def _change_from(node: NodeResult, finding: Finding) -> TagChange:
    return TagChange(
        node_id=node.node_id,
        node_name=node.name,
        column=finding.column,
        tag=finding.tag,
        risk=finding.risk,
        confidence=finding.confidence,
        origin_node=finding.origin_node,
    )


def plan_writeback(result: TraceResult, *, min_risk: Risk, min_confidence: float = 0.0) -> TagPlan:
    """Select the findings to materialize; pure, no I/O.

    A finding is planned when its risk ranks at or above ``min_risk`` and its
    confidence is ``>= min_confidence`` — the ADR-0004 A4 rule verbatim: both
    sides rounded to the published 4 decimals, range validation on the raw
    value. ORIGIN findings rank below LOW and are never written onto
    themselves. Findings at/above the risk threshold but below the confidence
    threshold land in ``suppressed`` — surfaced, never silently dropped.
    """
    if min_risk not in _PLAN_THRESHOLDS:
        raise SensiflowInputError(
            f"min-risk threshold must be one of LOW, MEDIUM, HIGH — got {min_risk!r}"
        )
    # NaN fails every comparison, so the chained check also rejects it.
    if not 0.0 <= min_confidence <= 1.0:
        raise SensiflowInputError(
            f"min-confidence must be between 0.0 and 1.0 inclusive — got {min_confidence}"
        )

    threshold = RISK_RANK[min_risk]
    floor = round(min_confidence, 4)
    changes: list[TagChange] = []
    suppressed: list[TagChange] = []
    for node in result.nodes.values():
        for finding in node.findings.values():
            if finding.risk == "ORIGIN" or RISK_RANK[finding.risk] < threshold:
                continue
            change = _change_from(node, finding)
            (changes if round(finding.confidence, 4) >= floor else suppressed).append(change)

    def order(change: TagChange) -> tuple[int, str, str, str]:
        return (-RISK_RANK[change.risk], change.node_name, change.node_id, change.column)

    changes.sort(key=order)
    suppressed.sort(key=order)
    return TagPlan(
        min_risk=min_risk,
        min_confidence=min_confidence,
        changes=changes,
        suppressed=suppressed,
        traced_nodes={node_id: node.name for node_id, node in result.nodes.items()},
        warnings=list(result.warnings),
    )


def _managed_drift(change: TagChange, existing: ExistingTag) -> str:
    """Describe how managed markup differs from the plan; '' when it matches.

    Sensitivity is always compared. Risk / confidence / origin are compared
    only when the target can carry them (dbt); OpenMetadata labels cannot.
    """
    drift: list[str] = []
    if existing.tag.sensitive != change.tag.sensitive:
        drift.append(f"sensitive {existing.tag.sensitive} -> {change.tag.sensitive}")
    if existing.risk is not None and existing.risk != change.risk:
        drift.append(f"risk {existing.risk} -> {change.risk}")
    if existing.confidence is not None and round(existing.confidence, 4) != round(
        change.confidence, 4
    ):
        drift.append(f"confidence {existing.confidence:.4f} -> {change.confidence:.4f}")
    if existing.origin is not None and existing.origin != change.origin_node:
        drift.append(f"origin {existing.origin} -> {change.origin_node}")
    return "; ".join(drift)


def _reclassify(change: TagChange, existing: ExistingTag | None) -> TagChange:
    if existing is None:
        return change
    if existing.managed:
        drift = _managed_drift(change, existing)
        if drift:
            return _with_action(change, "update", drift)
        return _with_action(change, "unchanged")
    if existing.tag.sensitive == change.tag.sensitive:
        return _with_action(change, "manual", f"human-placed {_describe(existing.tag)}")
    return _with_action(
        change,
        "conflict",
        f"human-placed {_describe(existing.tag)} contradicts derived "
        f"{_describe(change.tag)}; left untouched",
    )


def _describe(tag: PiiTag) -> str:
    kind = "sensitive" if tag.sensitive else "non-sensitive"
    return f"{tag.category} tag ({kind})"


def _with_action(change: TagChange, action: WritebackAction, detail: str = "") -> TagChange:
    return TagChange(
        node_id=change.node_id,
        node_name=change.node_name,
        column=change.column,
        tag=change.tag,
        risk=change.risk,
        confidence=change.confidence,
        origin_node=change.origin_node,
        action=action,
        detail=detail,
    )


def diff_writeback(plan: TagPlan, target: WritebackTarget) -> WritebackDiff:
    """Reconcile the plan against the target's current markup (read-only).

    Every planned change is re-classified (``add`` / ``unchanged`` / ``update``
    / ``manual`` / ``conflict`` / ``unmatched``); managed markup on a traced
    node with no planned change is reported as ``stale`` and never removed.
    """
    node_ids = list(dict.fromkeys([*plan.traced_nodes, *(c.node_id for c in plan.changes)]))
    existing = {
        (node_id, column.lower()): tag
        for (node_id, column), tag in target.read_markup(node_ids).items()
    }
    unmatched = {
        (node_id, column.lower()): reason
        for (node_id, column), reason in target.find_unmatched(plan.changes).items()
    }

    changes: list[TagChange] = []
    planned: set[tuple[str, str]] = set()
    for change in plan.changes:
        key = (change.node_id, change.column.lower())
        planned.add(key)
        if key in unmatched:
            changes.append(_with_action(change, "unmatched", unmatched[key]))
        else:
            changes.append(_reclassify(change, existing.get(key)))

    traced = set(node_ids)
    for (node_id, column), tag in sorted(existing.items()):
        if not tag.managed or (node_id, column) in planned or node_id not in traced:
            continue
        changes.append(
            TagChange(
                node_id=node_id,
                node_name=plan.traced_nodes.get(node_id, node_id),
                column=column,
                tag=tag.tag,
                risk=tag.risk or "NONE",
                confidence=tag.confidence if tag.confidence is not None else 0.0,
                origin_node=tag.origin or "",
                action="stale",
                detail="no current finding supports this tag; would be removed by a future --prune",
            )
        )
    return WritebackDiff(plan=plan, changes=changes)


def apply_writeback(diff: WritebackDiff, target: WritebackTarget, *, confirm: bool) -> ApplyResult:
    """Execute ``diff.pending`` against the target; refuses without ``confirm=True``.

    This is the single library-level enforcement point of the confirm gate.
    Per-change failures are collected in the result and never abort the rest;
    a re-run converges because applied changes diff to ``unchanged``.
    """
    if confirm is not True:
        raise SensiflowInputError("apply_writeback mutates the target and requires confirm=True")
    pending = diff.pending
    if not pending:
        return ApplyResult(applied=[], failed=[])
    return target.write_changes(pending)

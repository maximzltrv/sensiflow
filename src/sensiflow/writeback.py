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

from dataclasses import dataclass, field, replace
from typing import TYPE_CHECKING, Literal

from sensiflow.exceptions import SensiflowInputError
from sensiflow.gate import meets_confidence, validate_min_confidence, validate_risk_threshold
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
    in_output: bool = True  # False: the column is only used on the node, never output (A6)


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
    #: Traced findings this run did *not* plan (below the risk or confidence
    #: threshold), keyed ``(node_id, column.lower())`` -> ``(risk, confidence)``.
    #: Lets the diff tell "no finding at all" from "finding below thresholds" (A4).
    unplanned: dict[tuple[str, str], tuple[Risk, float]] = field(default_factory=dict)


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
    """What an apply did (A3).

    ``skipped``: the pre-write re-check reclassified the change — nothing was
    attempted and nothing is broken; a re-run diffs it under its proper action.
    ``failed``: an attempted write failed (I/O, HTTP, parse) — the partial-state
    case the exit code must not hide.
    """

    applied: list[TagChange]
    failed: list[tuple[TagChange, str]]  # change + error message
    skipped: list[tuple[TagChange, str]] = field(default_factory=list)  # change + reason


def _change_from(node: NodeResult, finding: Finding) -> TagChange:
    return TagChange(
        node_id=node.node_id,
        node_name=node.name,
        column=finding.column,
        tag=finding.tag,
        risk=finding.risk,
        confidence=finding.confidence,
        origin_node=finding.origin_node,
        in_output=finding.in_output,
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
    validate_risk_threshold(min_risk, "min-risk")
    validate_min_confidence(min_confidence)

    threshold = RISK_RANK[min_risk]
    changes: list[TagChange] = []
    suppressed: list[TagChange] = []
    unplanned: dict[tuple[str, str], tuple[Risk, float]] = {}
    for node in result.nodes.values():
        for finding in node.findings.values():
            if finding.risk == "ORIGIN":
                continue
            if RISK_RANK[finding.risk] < threshold:
                unplanned[(node.node_id, finding.column.lower())] = (
                    finding.risk,
                    finding.confidence,
                )
            elif meets_confidence(finding.confidence, min_confidence):
                changes.append(_change_from(node, finding))
            else:
                suppressed.append(_change_from(node, finding))
                unplanned[(node.node_id, finding.column.lower())] = (
                    finding.risk,
                    finding.confidence,
                )

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
        unplanned=unplanned,
    )


def _managed_drift(change: TagChange, existing: ExistingTag) -> str:
    """Describe how managed markup differs from the plan; '' when it matches.

    Every field the target stores is compared (A5): sensitivity always, and
    category / risk / confidence / origin wherever the target can carry them.
    A field the target cannot store is ``None`` and never participates.
    """
    drift: list[str] = []
    if existing.sensitive != change.tag.sensitive:
        drift.append(f"sensitive {existing.sensitive} -> {change.tag.sensitive}")
    if existing.category is not None and existing.category != change.tag.category:
        drift.append(f"category {existing.category} -> {change.tag.category}")
    if existing.risk is not None and existing.risk != change.risk:
        drift.append(f"risk {existing.risk} -> {change.risk}")
    if existing.confidence is not None and round(existing.confidence, 4) != round(
        change.confidence, 4
    ):
        drift.append(f"confidence {existing.confidence:.4f} -> {change.confidence:.4f}")
    if existing.origin is not None and existing.origin != change.origin_node:
        drift.append(f"origin {existing.origin} -> {change.origin_node}")
    return "; ".join(drift)


def _describe(sensitive: bool, category: str | None) -> str:
    kind = "sensitive" if sensitive else "non-sensitive"
    return f"{category or 'pii'} tag ({kind})"


def reclassify_change(change: TagChange, existing: ExistingTag | None) -> TagChange:
    """Classify one planned change against the markup currently on its column.

    The single home of the conflict policy (ADR-0006 §7, A1-A5): the diff uses
    it for every change, and connectors use it to re-check live state right
    before writing, so the pre-write verdict can never drift from the reviewed
    one. Returns the change carrying its action and detail.
    """
    if existing is None:
        return change
    derived = _describe(change.tag.sensitive, change.tag.category)
    if existing.not_pii:
        return replace(
            change,
            action="conflict",
            detail=f"human declared this column not PII, which contradicts derived {derived}; "
            "left untouched",
        )
    if existing.managed:
        if existing.sensitive and not change.tag.sensitive:
            # v1 never reduces protection automatically (A2).
            return replace(
                change,
                action="conflict",
                detail="sensitivity downgrade withheld (existing tag sensitive, derived "
                "non-sensitive); needs a human",
            )
        drift = _managed_drift(change, existing)
        if drift:
            return replace(change, action="update", detail=drift)
        return replace(change, action="unchanged")
    human = _describe(existing.sensitive, existing.category)
    if existing.sensitive == change.tag.sensitive:
        return replace(change, action="manual", detail=f"human-placed {human}")
    return replace(
        change,
        action="conflict",
        detail=f"human-placed {human} contradicts derived {derived}; left untouched",
    )


def recheck_reason(verdict: TagChange) -> str:
    """Why a pre-write re-check withheld a change (for ``ApplyResult.skipped`` entries)."""
    suffix = f": {verdict.detail}" if verdict.detail else ""
    return f"re-check found {verdict.action}{suffix}"


_NOT_IN_OUTPUT = (
    "column is not part of the node's output (used only in JOIN/WHERE), so there is no "
    "column to tag; the exposure remains visible in report/check"
)


def _stale_detail(plan: TagPlan, key: tuple[str, str]) -> str:
    below = plan.unplanned.get(key)
    if below is None:
        return (
            "no current finding supports this tag (reported only; removal needs a future --prune)"
        )
    risk, confidence = below
    return (
        f"supported only by a finding below this run's thresholds ({risk}, conf "
        f"{confidence:.2f}); not a removal signal (reported only; removal needs a future --prune)"
    )


def diff_writeback(plan: TagPlan, target: WritebackTarget) -> WritebackDiff:
    """Reconcile the plan against the target's current markup (read-only).

    Every planned change is re-classified (``add`` / ``unchanged`` / ``update``
    / ``manual`` / ``conflict`` / ``unmatched``); managed markup on a traced
    node with no planned change in this run is reported as ``stale`` and never
    removed. Findings whose column is not part of the node's output are
    ``unmatched`` here in core, before any target is consulted (A6).
    """
    node_ids = list(dict.fromkeys([*plan.traced_nodes, *(c.node_id for c in plan.changes)]))
    existing = {
        (node_id, column.lower()): tag
        for (node_id, column), tag in target.read_markup(node_ids).items()
    }
    placeable = [c for c in plan.changes if c.in_output]
    unmatched = {
        (node_id, column.lower()): reason
        for (node_id, column), reason in target.find_unmatched(placeable).items()
    }

    changes: list[TagChange] = []
    planned: set[tuple[str, str]] = set()
    for change in plan.changes:
        key = (change.node_id, change.column.lower())
        planned.add(key)
        if not change.in_output:
            changes.append(replace(change, action="unmatched", detail=_NOT_IN_OUTPUT))
        elif key in unmatched:
            changes.append(replace(change, action="unmatched", detail=unmatched[key]))
        else:
            changes.append(reclassify_change(change, existing.get(key)))

    traced = set(node_ids)
    for key, tag in sorted(existing.items()):
        node_id, column = key
        if not tag.managed or key in planned or node_id not in traced:
            continue
        changes.append(
            TagChange(
                node_id=node_id,
                node_name=plan.traced_nodes.get(node_id, node_id),
                column=column,
                tag=PiiTag(tag.category or "pii", tag.sensitive),
                risk=tag.risk or "NONE",
                confidence=tag.confidence if tag.confidence is not None else 0.0,
                origin_node=tag.origin or "",
                action="stale",
                detail=_stale_detail(plan, key),
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

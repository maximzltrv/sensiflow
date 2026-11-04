"""Pure gate evaluation over a TraceResult (ADR-0004).

The gate decision — "do these results violate this policy?" — is library
logic: no printing, no exit codes, no I/O. The CLI maps a
:class:`GateOutcome` to the process exit contract; library callers get the
identical semantics via ``evaluate_gate(trace(graph), fail_on="HIGH")``.

Confidence is compared at the published 4-decimal precision (ADR-0004 A4).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from sensiflow.exceptions import SensiflowInputError
from sensiflow.model import RISK_RANK, Finding, NodeResult, TraceResult

#: Risks a gate may fail on. ORIGIN is a declared seed, not an exposure, and
#: NONE would trip on every graph — neither is a valid threshold.
GateRisk = Literal["LOW", "MEDIUM", "HIGH"]

_GATE_THRESHOLDS: frozenset[str] = frozenset({"LOW", "MEDIUM", "HIGH"})


def validate_risk_threshold(value: str, label: str) -> None:
    """Reject anything but LOW/MEDIUM/HIGH; ``label`` names the flag in the message.

    Shared by the gate (``fail-on``) and write-back (``min-risk``): ORIGIN is a
    declared seed and NONE would select everything — neither is a threshold.
    """
    if value not in _GATE_THRESHOLDS:
        raise SensiflowInputError(
            f"{label} threshold must be one of LOW, MEDIUM, HIGH — got {value!r}"
        )


def validate_min_confidence(value: float) -> None:
    """Range-check the raw confidence threshold (NaN fails the chained comparison too)."""
    if not 0.0 <= value <= 1.0:
        raise SensiflowInputError(
            f"min-confidence must be between 0.0 and 1.0 inclusive — got {value}"
        )


def meets_confidence(confidence: float, min_confidence: float) -> bool:
    """The ADR-0004 A4 comparison: inclusive, both sides at the published 4 decimals."""
    return round(confidence, 4) >= round(min_confidence, 4)


@dataclass(frozen=True)
class GateOutcome:
    """The result of evaluating a gate policy against a trace."""

    fail_on: GateRisk
    min_confidence: float  # 0.0 = every finding gates (default)
    tripped: bool
    violations: tuple[NodeResult, ...]  # nodes with >=1 gating finding, most exposed first
    suppressed: tuple[tuple[str, Finding], ...]
    # (node_id, finding) pairs at/above fail_on risk but below min_confidence —
    # excluded from gating, surfaced for audit; empty at the default threshold


def evaluate_gate(
    result: TraceResult, *, fail_on: GateRisk, min_confidence: float = 0.0
) -> GateOutcome:
    """Evaluate the gate policy per finding; never recomputes engine output.

    A finding *gates* when its risk ranks at or above ``fail_on`` and its
    confidence is ``>= min_confidence`` (both inclusive). The comparison runs at
    the published precision (ADR-0004 A4): both values are rounded to 4 decimal
    places, the precision of the JSON output, so a confidence copied from the
    output into ``min_confidence`` always gates. Range validation of
    ``min_confidence`` applies to the raw value. A node is a
    violation when it has at least one gating finding. Findings at or above
    the risk threshold whose confidence falls below ``min_confidence`` are
    *suppressed*: collected (risk descending, then node name, then column),
    never silently dropped.
    """
    validate_risk_threshold(fail_on, "fail-on")
    validate_min_confidence(min_confidence)

    threshold = RISK_RANK[fail_on]
    violations: list[NodeResult] = []
    # Carry the node name alongside for ordering; it is dropped afterwards.
    suppressed: list[tuple[str, str, Finding]] = []

    # by_risk already orders nodes most exposed first, then by name, and its
    # max_risk cut cannot lose candidates: any finding at/above the threshold
    # lifts its node's max_risk at least that far.
    for node in result.by_risk(fail_on):
        gating = False
        for finding in node.findings.values():
            if RISK_RANK[finding.risk] < threshold:
                continue
            if meets_confidence(finding.confidence, min_confidence):
                gating = True
            else:
                suppressed.append((node.name, node.node_id, finding))
        if gating:
            violations.append(node)

    suppressed.sort(key=lambda entry: (-RISK_RANK[entry[2].risk], entry[0], entry[2].column))
    return GateOutcome(
        fail_on=fail_on,
        min_confidence=min_confidence,
        tripped=bool(violations),
        violations=tuple(violations),
        suppressed=tuple((node_id, finding) for _, node_id, finding in suppressed),
    )

"""Pure gate evaluation over a TraceResult (ADR-0004).

The gate decision — "do these results violate this policy?" — is library
logic: no printing, no exit codes, no I/O. The CLI maps a
:class:`GateOutcome` to the process exit contract; library callers get the
identical semantics via ``evaluate_gate(trace(graph), fail_on="HIGH")``.
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
    confidence is ``>= min_confidence`` (both inclusive). A node is a
    violation when it has at least one gating finding. Findings at or above
    the risk threshold whose confidence falls below ``min_confidence`` are
    *suppressed*: collected (risk descending, then node name, then column),
    never silently dropped.
    """
    if fail_on not in _GATE_THRESHOLDS:
        raise SensiflowInputError(
            f"fail-on threshold must be one of LOW, MEDIUM, HIGH — got {fail_on!r}"
        )
    # NaN fails every comparison, so the chained check also rejects it.
    if not 0.0 <= min_confidence <= 1.0:
        raise SensiflowInputError(
            f"min-confidence must be between 0.0 and 1.0 inclusive — got {min_confidence}"
        )

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
            if finding.confidence >= min_confidence:
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

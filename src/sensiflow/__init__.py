"""sensiflow — propagate PII tags along data lineage and classify exposure risk."""

from sensiflow.engine import DEFAULT_GENERIC_COLUMNS, trace
from sensiflow.exceptions import (
    SensiflowConnectionError,
    SensiflowDependencyError,
    SensiflowError,
    SensiflowInputError,
)
from sensiflow.gate import GateOutcome, GateRisk, evaluate_gate
from sensiflow.model import (
    Finding,
    LineageGraph,
    Node,
    NodeResult,
    PiiTag,
    Risk,
    TraceResult,
)
from sensiflow.root_selectors import GraphSelection

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_GENERIC_COLUMNS",
    "Finding",
    "GateOutcome",
    "GateRisk",
    "GraphSelection",
    "LineageGraph",
    "Node",
    "NodeResult",
    "PiiTag",
    "Risk",
    "SensiflowConnectionError",
    "SensiflowDependencyError",
    "SensiflowError",
    "SensiflowInputError",
    "TraceResult",
    "__version__",
    "evaluate_gate",
    "trace",
]

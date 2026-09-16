"""sensiflow — propagate PII tags along data lineage and classify exposure risk."""

from sensiflow.engine import DEFAULT_GENERIC_COLUMNS, trace
from sensiflow.exceptions import (
    SensiflowConnectionError,
    SensiflowDependencyError,
    SensiflowError,
)
from sensiflow.model import (
    Finding,
    LineageGraph,
    Node,
    NodeResult,
    PiiTag,
    Risk,
    TraceResult,
)

__version__ = "0.1.0"

__all__ = [
    "DEFAULT_GENERIC_COLUMNS",
    "Finding",
    "LineageGraph",
    "Node",
    "NodeResult",
    "PiiTag",
    "Risk",
    "SensiflowConnectionError",
    "SensiflowDependencyError",
    "SensiflowError",
    "TraceResult",
    "__version__",
    "trace",
]

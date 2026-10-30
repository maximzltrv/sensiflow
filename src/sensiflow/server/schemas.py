"""Request bodies for the HTTP API (ADR-0005 §3).

Pydantic models exist for requests only and check shape and types. Semantic
validation stays in ``GraphSelection`` and ``evaluate_gate``, so every caller
gets the same rules from one implementation. ``extra="forbid"`` makes a stray
``omd_host`` / ``omd_token`` / path field a 422 rather than silently ignored:
the request carries no credentials and no server-side paths, by design.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from sensiflow.root_selectors import GraphSelection


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SelectionSpec(_StrictModel):
    """Mirror of ``GraphSelection``, field for field."""

    roots: list[str] = Field(default_factory=list)
    patterns: list[str] = Field(default_factory=list)
    from_seeds: bool = False
    upstream_depth: int | None = None
    downstream_depth: int | None = None

    def to_selection(self) -> GraphSelection:
        """Build the library object; its constructor does the semantic validation."""
        return GraphSelection(
            roots=tuple(self.roots),
            patterns=tuple(self.patterns),
            from_seeds=self.from_seeds,
            upstream_depth=self.upstream_depth,
            downstream_depth=self.downstream_depth,
        )


class ReportRequest(_StrictModel):
    """Body of ``POST /v1/report``."""

    source: Literal["openmetadata", "mock"]
    selection: SelectionSpec = Field(default_factory=SelectionSpec)
    dialect: str = "bigquery"


class CheckRequest(ReportRequest):
    """Body of ``POST /v1/check``: the report request plus the gate policy."""

    fail_on: str
    min_confidence: float = 0.0

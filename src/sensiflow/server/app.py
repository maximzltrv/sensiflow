"""The FastAPI application factory (ADR-0005).

A peer of the CLI: it consumes only the public library API and owns what the
library deliberately does not: HTTP status mapping, logging, and authentication.
Catalog credentials come from the server's environment, never from a request.
"""

from __future__ import annotations

import hmac
import logging
import os
import time
from collections.abc import Callable
from typing import Any, cast

from fastapi import Depends, FastAPI, Request
from fastapi.responses import JSONResponse

from sensiflow import (
    GateRisk,
    GraphSelection,
    SensiflowConnectionError,
    SensiflowDependencyError,
    SensiflowInputError,
    TraceResult,
    __version__,
    evaluate_gate,
    trace,
)
from sensiflow.report import render_check_json, render_json
from sensiflow.server.schemas import CheckRequest, ReportRequest
from sensiflow.sources.base import LineageSource
from sensiflow.sources.mock import MockSource

logger = logging.getLogger("sensiflow.server")

_GENERIC_INTERNAL_MESSAGE = "internal server error"
_BEARER_PREFIX = "Bearer "


class _Unauthorized(Exception):
    """Missing or wrong API token; handled into a structured 401."""


def _error_response(
    status: int, kind: str, message: str, headers: dict[str, str] | None = None
) -> JSONResponse:
    return JSONResponse(
        status_code=status, content={"error": {"kind": kind, "message": message}}, headers=headers
    )


def _error_kind(exc: Exception) -> str:
    if isinstance(exc, SensiflowInputError):
        return "input"
    if isinstance(exc, SensiflowConnectionError):
        return "connection"
    if isinstance(exc, SensiflowDependencyError):
        return "dependency"
    return "internal"


def _make_source(name: str) -> LineageSource:
    if name == "mock":
        return MockSource()
    host = os.environ.get("OMD_HOST")
    token = os.environ.get("OMD_TOKEN")
    if not host or not token:
        raise SensiflowInputError(
            "the openmetadata source is not configured on this server "
            "(OMD_HOST and OMD_TOKEN must be set in the server environment)"
        )
    # Imported only on demand: the openmetadata extra may be absent.
    from sensiflow.sources.openmetadata import OpenMetadataSource

    return OpenMetadataSource(host, token)


def _selection_counts(selection: GraphSelection) -> str:
    return (
        f"roots={len(selection.roots)} patterns={len(selection.patterns)} "
        f"from_seeds={selection.from_seeds}"
    )


_Work = Callable[[GraphSelection], tuple[Any, TraceResult, str]]


def _logged(endpoint: str, request: ReportRequest, work: _Work) -> Any:
    """Run an analysis request, emitting exactly one log line for it.

    ``work`` returns the response document, the trace, and the verdict label.
    Failures are logged here by kind and re-raised for the exception handlers.
    """
    start = time.perf_counter()
    counts = "roots=? patterns=? from_seeds=?"
    try:
        selection = request.selection.to_selection()
        counts = _selection_counts(selection)
        document, result, verdict = work(selection)
    except Exception as exc:
        logger.warning(
            "%s source=%s %s error=%s duration=%.3fs",
            endpoint,
            request.source,
            counts,
            _error_kind(exc),
            time.perf_counter() - start,
        )
        raise
    logger.info(
        "%s source=%s %s nodes=%d verdict=%s duration=%.3fs",
        endpoint,
        request.source,
        counts,
        len(result.nodes),
        verdict,
        time.perf_counter() - start,
    )
    return document


def _ensure_log_output() -> None:
    """Give the server logger a stderr handler once; uvicorn only wires its own loggers."""
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)


def create_app() -> FastAPI:
    """Build the application. Environment is read here, once, for the API token."""
    _ensure_log_output()
    api_token = os.environ.get("SENSIFLOW_API_TOKEN") or None
    if api_token is None:
        logger.warning(
            "SENSIFLOW_API_TOKEN is not set: /v1/report and /v1/check are OPEN to anyone "
            "who can reach this server. Set it, or restrict access at the network level."
        )

    def require_token(request: Request) -> None:
        if api_token is None:
            return
        header = request.headers.get("authorization", "")
        presented = header[len(_BEARER_PREFIX) :] if header.startswith(_BEARER_PREFIX) else ""
        if not hmac.compare_digest(presented.encode(), api_token.encode()):
            raise _Unauthorized

    app = FastAPI(title="sensiflow", version=__version__)

    @app.exception_handler(_Unauthorized)
    def _unauthorized(_: Request, __: Exception) -> JSONResponse:
        return _error_response(
            401, "auth", "missing or invalid API token", {"WWW-Authenticate": "Bearer"}
        )

    @app.exception_handler(SensiflowInputError)
    def _input_error(_: Request, exc: Exception) -> JSONResponse:
        return _error_response(400, "input", str(exc))

    @app.exception_handler(SensiflowConnectionError)
    def _connection_error(_: Request, exc: Exception) -> JSONResponse:
        return _error_response(502, "connection", str(exc))

    @app.exception_handler(SensiflowDependencyError)
    def _dependency_error(_: Request, exc: Exception) -> JSONResponse:
        return _error_response(500, "dependency", str(exc))

    @app.exception_handler(Exception)
    def _internal_error(_: Request, exc: Exception) -> JSONResponse:
        # The traceback goes to the server log only, never to the client.
        logger.error("unhandled error", exc_info=exc)
        return _error_response(500, "internal", _GENERIC_INTERNAL_MESSAGE)

    @app.get("/v1/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.post("/v1/report", dependencies=[Depends(require_token)])
    def report(body: ReportRequest) -> Any:
        def work(selection: GraphSelection) -> tuple[Any, TraceResult, str]:
            graph = _make_source(body.source).build_graph(selection)
            result = trace(graph, dialect=body.dialect)
            return render_json(result), result, "report"

        return _logged("report", body, work)

    @app.post("/v1/check", dependencies=[Depends(require_token)])
    def check(body: CheckRequest) -> Any:
        def work(selection: GraphSelection) -> tuple[Any, TraceResult, str]:
            graph = _make_source(body.source).build_graph(selection)
            result = trace(graph, dialect=body.dialect)
            # evaluate_gate validates the threshold at runtime; the schema only checks "str".
            outcome = evaluate_gate(
                result,
                fail_on=cast(GateRisk, body.fail_on),
                min_confidence=body.min_confidence,
            )
            return (
                render_check_json(result, outcome),
                result,
                "tripped" if outcome.tripped else "clean",
            )

        return _logged("check", body, work)

    return app

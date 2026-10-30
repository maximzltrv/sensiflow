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
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from sensiflow import (
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

_LOG_HANDLER_NAME = "sensiflow.server.stderr"
_HEALTH_PATH = "/v1/health"
_MAX_BODY_BYTES = 1024 * 1024  # ADR-0005 §3


class _CatalogNotConfigured(Exception):
    """The requested source needs server-side configuration this deployment lacks."""


@dataclass(frozen=True)
class _ErrorSpec:
    status: int
    kind: str
    message: str | None  # None: the exception text is client-safe and is passed through


#: The outcome-to-HTTP table (ADR-0005 §4), most specific class first. Only
#: ``input`` errors expose library text; every other kind returns a fixed
#: message, because the details describe the deployment (catalog host, packages).
_ERROR_TABLE: dict[type[Exception], _ErrorSpec] = {
    SensiflowInputError: _ErrorSpec(400, "input", None),
    _CatalogNotConfigured: _ErrorSpec(
        503, "config", "the requested source is not configured on this server"
    ),
    SensiflowConnectionError: _ErrorSpec(502, "connection", "the catalog could not be reached"),
    SensiflowDependencyError: _ErrorSpec(
        500, "dependency", "the server is missing a required component"
    ),
}
_INTERNAL = _ErrorSpec(500, "internal", "internal server error")


def _spec_for(exc: Exception) -> _ErrorSpec:
    return next((spec for cls, spec in _ERROR_TABLE.items() if isinstance(exc, cls)), _INTERNAL)


def _error_response(
    status: int, kind: str, message: str, headers: dict[str, str] | None = None
) -> JSONResponse:
    return JSONResponse(
        status_code=status, content={"error": {"kind": kind, "message": message}}, headers=headers
    )


def _handle_error(_: Request, exc: Exception) -> JSONResponse:
    spec = _spec_for(exc)
    if spec.message is None:
        return _error_response(spec.status, spec.kind, str(exc))
    if spec is not _INTERNAL:
        # Details for the operator only. Unexpected errors are not logged here:
        # the server re-raises them after responding and uvicorn logs the traceback.
        logger.warning("%s error: %s", spec.kind, exc)
    return _error_response(spec.status, spec.kind, spec.message)


class _GuardMiddleware:
    """Authentication, then the body-size cap, for everything under ``/v1`` but health.

    Pure ASGI on purpose: the token is checked before a single body byte is read
    (a ``422`` must never be an unauthenticated schema probe), and the body is
    buffered here under the cap so chunked uploads are bounded too. Precedence:
    401, 413, then the framework's 422.
    """

    def __init__(self, app: ASGIApp, *, api_token: str | None, max_body: int) -> None:
        self._app = app
        self._token = api_token.encode() if api_token is not None else None
        self._max_body = max_body

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        path = scope.get("path", "")
        if scope["type"] != "http" or not path.startswith("/v1/") or path == _HEALTH_PATH:
            await self._app(scope, receive, send)
            return
        headers = Headers(scope=scope)
        if self._token is not None and not self._authorized(headers.get("authorization", "")):
            response = _error_response(
                401, "auth", "missing or invalid API token", {"WWW-Authenticate": "Bearer"}
            )
            await response(scope, receive, send)
            return
        body = await self._read_body(headers, receive)
        if body is None:
            response = _error_response(
                413, "input", f"request body exceeds the {self._max_body}-byte limit"
            )
            await response(scope, receive, send)
            return
        replayed = False

        async def replay() -> Message:
            nonlocal replayed
            if not replayed:
                replayed = True
                return {"type": "http.request", "body": body, "more_body": False}
            return await receive()  # later calls see the client's disconnect

        await self._app(scope, replay, send)

    def _authorized(self, header: str) -> bool:
        assert self._token is not None
        parts = header.split(None, 1)
        presented = parts[1] if len(parts) == 2 and parts[0].casefold() == "bearer" else ""
        return hmac.compare_digest(presented.encode(), self._token)

    async def _read_body(self, headers: Headers, receive: Receive) -> bytes | None:
        """The whole body, or None when it exceeds the cap (declared or streamed)."""
        declared = headers.get("content-length", "")
        if declared.isdigit() and int(declared) > self._max_body:
            return None
        chunks: list[bytes] = []
        size = 0
        while True:
            message = await receive()
            if message["type"] != "http.request":
                return b"".join(chunks)  # client went away; the app will see it too
            chunk: bytes = message.get("body", b"")
            size += len(chunk)
            if size > self._max_body:
                return None
            chunks.append(chunk)
            if not message.get("more_body", False):
                return b"".join(chunks)


def _make_source(name: str) -> LineageSource:
    if name == "mock":
        return MockSource()
    host = os.environ.get("OMD_HOST")
    token = os.environ.get("OMD_TOKEN")
    if not host or not token:
        raise _CatalogNotConfigured
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
            _spec_for(exc).kind,
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
    if not any(handler.get_name() == _LOG_HANDLER_NAME for handler in logger.handlers):
        handler = logging.StreamHandler()
        handler.set_name(_LOG_HANDLER_NAME)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False  # a configured root logger must not print every line twice


def _configured_api_token() -> str | None:
    """The API token from the environment; unset means open, set-but-blank is refused."""
    raw = os.environ.get("SENSIFLOW_API_TOKEN")
    if raw is None:
        logger.warning(
            "SENSIFLOW_API_TOKEN is not set: /v1/report and /v1/check are OPEN to anyone "
            "who can reach this server. Set it, or restrict access at the network level."
        )
        return None
    if not raw.strip():
        # A blank token is always a mistake; running open would turn a typo into an exposure.
        raise SensiflowInputError(
            "SENSIFLOW_API_TOKEN is set but blank: set a real token, or unset it to run open"
        )
    return raw


def create_app() -> FastAPI:
    """Build the application. The API token is read here, once; catalog variables on first use."""
    _ensure_log_output()
    api_token = _configured_api_token()

    # With a token configured the schema is not served: an unauthenticated caller
    # gets nothing to probe (operators read it from an unauthenticated local run).
    locked = api_token is not None
    app = FastAPI(
        title="sensiflow",
        version=__version__,
        docs_url=None if locked else "/docs",
        redoc_url=None if locked else "/redoc",
        openapi_url=None if locked else "/openapi.json",
    )
    app.add_middleware(_GuardMiddleware, api_token=api_token, max_body=_MAX_BODY_BYTES)
    for exc_type in (*_ERROR_TABLE, Exception):
        app.add_exception_handler(exc_type, _handle_error)

    @app.get(_HEALTH_PATH)
    def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.post("/v1/report")
    def report(body: ReportRequest) -> Any:
        def work(selection: GraphSelection) -> tuple[Any, TraceResult, str]:
            graph = _make_source(body.source).build_graph(selection)
            result = trace(graph, dialect=body.dialect)
            return render_json(result), result, "report"

        return _logged("report", body, work)

    @app.post("/v1/check")
    def check(body: CheckRequest) -> Any:
        def work(selection: GraphSelection) -> tuple[Any, TraceResult, str]:
            graph = _make_source(body.source).build_graph(selection)
            result = trace(graph, dialect=body.dialect)
            outcome = evaluate_gate(
                result, fail_on=body.fail_on, min_confidence=body.min_confidence
            )
            return (
                render_check_json(result, outcome),
                result,
                "tripped" if outcome.tripped else "clean",
            )

        return _logged("check", body, work)

    return app

"""HTTP API hardening (ADR-0005 post-verification amendments).

Auth-before-body ordering, the body-size cap (declared and streamed), host-free
error bodies through the real connector, docs lockdown, schema parity.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
from collections.abc import Iterator
from functools import partial
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from starlette.applications import Starlette
from starlette.routing import Mount

from sensiflow import GraphSelection, SensiflowConnectionError
from sensiflow.server import create_app
from sensiflow.server.schemas import SelectionSpec
from sensiflow.sources import openmetadata

API_TOKEN = "fake-api-token-hardening"
AUTH = {"Authorization": f"Bearer {API_TOKEN}"}
JSON_HEADERS = {"content-type": "application/json"}
CAP = 1024 * 1024
CATALOG_HOST = "http://internal-catalog.example.test:8585"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("OMD_HOST", "OMD_TOKEN", "SENSIFLOW_API_TOKEN"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def authed(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    monkeypatch.setenv("SENSIFLOW_API_TOKEN", API_TOKEN)
    with TestClient(create_app(), raise_server_exceptions=False) as client:
        yield client


@pytest.fixture
def open_client() -> Iterator[TestClient]:
    with TestClient(create_app(), raise_server_exceptions=False) as client:
        yield client


def _padded(size: int) -> bytes:
    """A syntactically valid JSON body of exactly ``size`` bytes."""
    head = b'{"source": "mock", "dialect": "'
    tail = b'"}'
    return head + b"a" * (size - len(head) - len(tail)) + tail


# -- auth before body ----------------------------------------------------------------


def test_malformed_json_with_a_bad_token_is_401_not_422(authed: TestClient) -> None:
    response = authed.post("/v1/report", content=b"{nope", headers=JSON_HEADERS)
    assert response.status_code == 401
    assert response.json()["error"]["kind"] == "auth"


def test_oversized_body_with_a_bad_token_is_401_not_413(authed: TestClient) -> None:
    response = authed.post("/v1/report", content=_padded(CAP + 10), headers=JSON_HEADERS)
    assert response.status_code == 401


def test_unknown_v1_path_without_a_token_is_401(authed: TestClient) -> None:
    assert authed.post("/v1/propagate", json={}).status_code == 401


@pytest.mark.parametrize("scheme", ["bearer", "BEARER", "Bearer"])
def test_bearer_scheme_is_matched_case_insensitively(authed: TestClient, scheme: str) -> None:
    response = authed.post(
        "/v1/report", json={"source": "mock"}, headers={"Authorization": f"{scheme} {API_TOKEN}"}
    )
    assert response.status_code == 200


def test_bearer_scheme_tolerates_repeated_whitespace_but_the_token_is_exact(
    authed: TestClient,
) -> None:
    ok = authed.post(
        "/v1/report", json={"source": "mock"}, headers={"Authorization": f"Bearer   {API_TOKEN}"}
    )
    bad = authed.post(
        "/v1/report",
        json={"source": "mock"},
        headers={"Authorization": f"Bearer {API_TOKEN.upper()}"},
    )
    assert (ok.status_code, bad.status_code) == (200, 401)


def test_health_stays_open_and_unbuffered(authed: TestClient) -> None:
    assert authed.get("/v1/health").status_code == 200


# -- body cap ------------------------------------------------------------------------


def test_declared_oversized_body_is_413_structured(open_client: TestClient) -> None:
    response = open_client.post("/v1/report", content=_padded(CAP + 1), headers=JSON_HEADERS)
    assert response.status_code == 413
    assert response.json()["error"]["kind"] == "input"


def test_body_at_the_cap_is_accepted_by_the_guard(open_client: TestClient) -> None:
    response = open_client.post("/v1/report", content=_padded(CAP), headers=JSON_HEADERS)
    # Passes the cap; the unknown dialect then fails library validation: 400, not 413.
    assert response.status_code == 400


def test_streamed_chunked_body_is_capped_while_reading(open_client: TestClient) -> None:
    def chunks() -> Iterator[bytes]:
        yield b'{"source": "mock", "dialect": "'
        for _ in range(CAP // 65536 + 2):
            yield b"a" * 65536
        yield b'"}'

    response = open_client.post("/v1/report", content=chunks(), headers=JSON_HEADERS)
    assert response.status_code == 413


def test_streamed_small_body_still_works(open_client: TestClient) -> None:
    def chunks() -> Iterator[bytes]:
        yield b'{"source": '
        yield b'"mock"}'

    response = open_client.post("/v1/report", content=chunks(), headers=JSON_HEADERS)
    assert response.status_code == 200


def test_413_takes_precedence_over_422(open_client: TestClient) -> None:
    response = open_client.post("/v1/report", content=b"x" * (CAP + 1), headers=JSON_HEADERS)
    assert response.status_code == 413


def test_cap_applies_with_auth_enabled_and_a_valid_token(authed: TestClient) -> None:
    response = authed.post(
        "/v1/report", content=_padded(CAP + 1), headers={**JSON_HEADERS, **AUTH}
    )
    assert response.status_code == 413


# -- docs lockdown -------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_docs_are_disabled_when_a_token_is_configured(authed: TestClient, path: str) -> None:
    assert authed.get(path).status_code == 401  # the guard denies by default
    assert authed.get(path, headers=AUTH).status_code == 404  # and nothing is served behind it


def test_docs_are_served_without_a_token(open_client: TestClient) -> None:
    assert open_client.get("/docs").status_code == 200
    assert open_client.get("/openapi.json").status_code == 200


# -- error bodies never carry the catalog host -----------------------------------------


def _real_source_over(monkeypatch: pytest.MonkeyPatch, handler: Any) -> None:
    """Serve ``openmetadata`` requests through the real connector on a MockTransport."""
    monkeypatch.setenv("OMD_HOST", CATALOG_HOST)
    monkeypatch.setenv("OMD_TOKEN", "fake-omd-token-hardening")
    monkeypatch.setattr(
        openmetadata,
        "OpenMetadataSource",
        partial(openmetadata.OpenMetadataSource, transport=httpx.MockTransport(handler)),
    )


def test_unreachable_catalog_is_502_without_the_host(
    monkeypatch: pytest.MonkeyPatch, open_client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    def down(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom")

    _real_source_over(monkeypatch, down)
    response = open_client.post("/v1/report", json={"source": "openmetadata"})
    assert response.status_code == 502
    assert "internal-catalog" not in response.text
    assert "fake-omd-token" not in response.text
    assert "internal-catalog" in caplog.text  # operators keep the detail


def test_catalog_http_errors_are_502_without_the_host(
    monkeypatch: pytest.MonkeyPatch, open_client: TestClient
) -> None:
    _real_source_over(monkeypatch, lambda request: httpx.Response(401, json={}))
    response = open_client.post(
        "/v1/check", json={"source": "openmetadata", "fail_on": "HIGH"}
    )
    assert response.status_code == 502
    assert "internal-catalog" not in response.text


def test_from_seeds_without_seeds_is_400_without_the_host(
    monkeypatch: pytest.MonkeyPatch, open_client: TestClient
) -> None:
    _real_source_over(monkeypatch, lambda r: httpx.Response(200, json={"data": [], "paging": {}}))
    response = open_client.post(
        "/v1/report", json={"source": "openmetadata", "selection": {"from_seeds": True}}
    )
    assert response.status_code == 400
    assert "internal-catalog" not in response.text


def test_hostile_root_is_400_and_never_reaches_the_catalog(
    monkeypatch: pytest.MonkeyPatch, open_client: TestClient
) -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(404, json={})

    _real_source_over(monkeypatch, handler)
    response = open_client.post(
        "/v1/report",
        json={"source": "openmetadata", "selection": {"roots": ["a/../../admin"]}},
    )
    assert response.status_code == 400
    assert seen == []


def test_control_character_root_is_400(open_client: TestClient) -> None:
    response = open_client.post(
        "/v1/report", json={"source": "mock", "selection": {"roots": ["raw_customers\n"]}}
    )
    assert response.status_code == 400
    assert "control characters" in response.json()["error"]["message"]


# -- schema strictness ------------------------------------------------------------------


def test_integer_min_confidence_is_still_accepted(open_client: TestClient) -> None:
    response = open_client.post(
        "/v1/check", json={"source": "mock", "fail_on": "HIGH", "min_confidence": 1}
    )
    assert response.status_code == 200
    assert response.json()["min_confidence"] == 1.0


@pytest.mark.parametrize(
    "extra",
    [{"min_confidence": True}, {"selection": {"from_seeds": 1}}, {"selection": {"roots": "a"}}],
)
def test_strict_types_are_not_coerced(open_client: TestClient, extra: dict[str, Any]) -> None:
    body = {"source": "mock", "fail_on": "HIGH", **extra}
    assert open_client.post("/v1/check", json=body).status_code == 422


def test_selection_spec_mirrors_graph_selection_field_for_field() -> None:
    library = {f.name: f for f in dataclasses.fields(GraphSelection)}
    spec = SelectionSpec.model_fields
    assert set(spec) == set(library)
    defaults = GraphSelection()
    for name, field in spec.items():
        expected = getattr(defaults, name)
        actual = field.get_default(call_default_factory=True)
        assert tuple(actual) == expected if isinstance(actual, list) else actual == expected



def _asgi_post(
    app: Any, headers: list[tuple[bytes, bytes]], chunks: list[bytes], path: str = "/v1/report"
) -> tuple[int, list[bytes]]:
    """Drive the app at the raw ASGI level; returns the status and the unread chunks."""
    pending = list(reversed(chunks))
    sent: list[dict[str, Any]] = []

    async def receive() -> dict[str, Any]:
        if pending:
            return {"type": "http.request", "body": pending.pop(), "more_body": bool(pending)}
        return {"type": "http.disconnect"}

    async def send(message: dict[str, Any]) -> None:
        sent.append(message)

    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": [(b"content-type", b"application/json"), *headers],
        "client": ("127.0.0.1", 1),
        "server": ("testserver", 80),
    }
    asyncio.run(app(scope, receive, send))
    start = next(m for m in sent if m["type"] == "http.response.start")
    return int(start["status"]), pending


def test_cap_is_enforced_on_a_body_with_no_content_length_at_the_asgi_level() -> None:
    """Raw ASGI, no Content-Length header: the guard itself must count the bytes."""
    status, unread = _asgi_post(create_app(), [], [b"a" * 65536] * (CAP // 65536 + 1))
    assert status == 413
    assert unread == []  # the guard stopped reading only after exceeding the cap


@pytest.mark.parametrize(
    "declared",
    [b"\xc2\xb2", b"\xc2\xb9\xc2\xb2", b"9" * 5000, b"-5", b"1e9", b" ", b"0x10"],
)
def test_garbage_content_length_never_crashes_the_guard(declared: bytes) -> None:
    # Non-ASCII digits, absurdly long numbers and junk fall back to the streaming cap.
    ok_status, _ = _asgi_post(
        create_app(), [(b"content-length", declared)], [b'{"source": "mock"}']
    )
    assert ok_status == 200
    big_status, _ = _asgi_post(
        create_app(), [(b"content-length", declared)], [b"a" * 65536] * (CAP // 65536 + 1)
    )
    assert big_status == 413


# -- the guard judges the router's path, so a path prefix cannot bypass it ---------------


def _prefixed_clients(monkeypatch: pytest.MonkeyPatch) -> list[tuple[str, TestClient]]:
    monkeypatch.setenv("SENSIFLOW_API_TOKEN", API_TOKEN)
    mounted = Starlette(routes=[Mount("/prefix", create_app())])
    return [
        ("/api", TestClient(create_app(), root_path="/api", raise_server_exceptions=False)),
        ("/prefix", TestClient(mounted, raise_server_exceptions=False)),
    ]


def test_root_path_and_mount_prefixes_cannot_bypass_auth(monkeypatch: pytest.MonkeyPatch) -> None:
    for prefix, client in _prefixed_clients(monkeypatch):
        body = {"source": "mock"}
        assert client.post(f"{prefix}/v1/report", json=body).status_code == 401, prefix
        assert (
            client.post(f"{prefix}/v1/report", json=body, headers=AUTH).status_code == 200
        ), prefix
        assert client.get(f"{prefix}/v1/health").status_code == 200, prefix


def test_root_path_and_mount_prefixes_cannot_bypass_the_body_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for prefix, client in _prefixed_clients(monkeypatch):
        response = client.post(
            f"{prefix}/v1/report", content=_padded(CAP + 1), headers={**JSON_HEADERS, **AUTH}
        )
        assert response.status_code == 413, prefix


def test_prefixed_health_is_the_only_exemption_even_without_a_token() -> None:
    mounted = Starlette(routes=[Mount("/prefix", create_app())])
    with TestClient(mounted, raise_server_exceptions=False) as client:
        oversized = client.post(
            "/prefix/v1/report", content=_padded(CAP + 1), headers=JSON_HEADERS
        )
        assert oversized.status_code == 413
        assert client.get("/prefix/v1/health").status_code == 200


# -- misconfigured catalog host is a deployment fault -------------------------------------


@pytest.mark.parametrize(
    "host", ["catalog.example.test:8585", "http://user:hunter2@catalog.example.test:8585"]
)
def test_malformed_catalog_host_is_503_config_without_the_host(
    monkeypatch: pytest.MonkeyPatch,
    open_client: TestClient,
    caplog: pytest.LogCaptureFixture,
    host: str,
) -> None:
    monkeypatch.setenv("OMD_HOST", host)
    monkeypatch.setenv("OMD_TOKEN", "fake-omd-token-hardening")
    response = open_client.post("/v1/report", json={"source": "openmetadata"})
    assert response.status_code == 503
    assert response.json()["error"]["kind"] == "config"
    assert "catalog.example.test" not in response.text
    assert "hunter2" not in response.text
    assert "hunter2" not in caplog.text


# -- caller-supplied names stay out of the server log -------------------------------------


def test_failing_upstream_does_not_log_the_requested_root(
    monkeypatch: pytest.MonkeyPatch, open_client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    root = "sales_wh.secret_schema.customer_ledger"
    for status in (500, 404):
        _real_source_over(monkeypatch, lambda request, status=status: httpx.Response(status))
        with caplog.at_level(logging.DEBUG):
            response = open_client.post(
                "/v1/report", json={"source": "openmetadata", "selection": {"roots": [root]}}
            )
        assert response.status_code == 502
        assert "customer_ledger" not in caplog.text
    _real_source_over(monkeypatch, lambda request: httpx.Response(200, text="<html>"))
    open_client.post(
        "/v1/report", json={"source": "openmetadata", "selection": {"roots": [root]}}
    )
    assert "customer_ledger" not in caplog.text


def test_connector_errors_name_the_status_but_not_the_path() -> None:
    from sensiflow.sources.openmetadata import OpenMetadataSource

    source = OpenMetadataSource(
        CATALOG_HOST, "fake", transport=httpx.MockTransport(lambda r: httpx.Response(500))
    )
    with pytest.raises(SensiflowConnectionError) as excinfo:
        source.build_graph(GraphSelection(roots=("a.b",)))
    assert "500" in str(excinfo.value)
    assert "/tables" not in str(excinfo.value)
    assert "a.b" not in str(excinfo.value)

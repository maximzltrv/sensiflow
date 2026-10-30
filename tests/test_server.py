"""HTTP API tests (ADR-0005): in-process ASGI client, mock source, no network."""

from __future__ import annotations

import hmac
import json
import logging
import subprocess
import sys
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient

from sensiflow import (
    GraphSelection,
    SensiflowConnectionError,
    SensiflowDependencyError,
    SensiflowInputError,
    __version__,
    evaluate_gate,
    trace,
)
from sensiflow.report import render_check_json, render_json
from sensiflow.server import app as app_module
from sensiflow.server import create_app
from sensiflow.sources.mock import MockSource

FAKE_OMD_TOKEN = "fake-omd-token-0123456789"
FAKE_OMD_HOST = "http://catalog.example.test:8585"
API_TOKEN = "fake-api-token-abcdef"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("OMD_HOST", "OMD_TOKEN", "SENSIFLOW_API_TOKEN"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def client() -> Iterator[TestClient]:
    # Unhandled errors must surface as responses, as they do behind uvicorn.
    with TestClient(create_app(), raise_server_exceptions=False) as test_client:
        yield test_client


def _mock_document() -> dict[str, Any]:
    result = trace(MockSource().build_graph())
    document: dict[str, Any] = json.loads(json.dumps(render_json(result)))
    return document


def _stub_omd(monkeypatch: pytest.MonkeyPatch, exc: Exception) -> None:
    """Make the lazily imported OpenMetadata source raise ``exc`` on build_graph."""
    from sensiflow.sources import openmetadata

    class _Failing:
        def __init__(self, host: str, token: str) -> None:
            pass

        def build_graph(self, selection: GraphSelection | None = None) -> Any:
            raise exc

    monkeypatch.setenv("OMD_HOST", FAKE_OMD_HOST)
    monkeypatch.setenv("OMD_TOKEN", FAKE_OMD_TOKEN)
    monkeypatch.setattr(openmetadata, "OpenMetadataSource", _Failing)


# -- health -----------------------------------------------------------------


def test_health_reports_version(client: TestClient) -> None:
    response = client.get("/v1/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": __version__}


def test_health_never_touches_a_source(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(*_: Any, **__: Any) -> Any:
        raise AssertionError("health must not build a source")

    monkeypatch.setattr(app_module, "_make_source", boom)
    assert client.get("/v1/health").status_code == 200


def test_health_open_even_with_auth_enabled(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENSIFLOW_API_TOKEN", API_TOKEN)
    with TestClient(create_app()) as authed:
        assert authed.get("/v1/health").status_code == 200


# -- report / check ---------------------------------------------------------


def test_report_body_is_render_json_verbatim(client: TestClient) -> None:
    response = client.post("/v1/report", json={"source": "mock"})
    assert response.status_code == 200
    assert response.json() == _mock_document()


def test_report_accepts_selection_and_dialect(client: TestClient) -> None:
    response = client.post(
        "/v1/report",
        json={
            "source": "mock",
            "selection": {"roots": ["raw_customers"], "downstream_depth": 1},
            "dialect": "postgres",
        },
    )
    assert response.status_code == 200
    assert set(response.json()) == {"summary", "warnings", "nodes"}


def test_check_tripped_is_http_200(client: TestClient) -> None:
    response = client.post("/v1/check", json={"source": "mock", "fail_on": "HIGH"})
    assert response.status_code == 200
    body = response.json()
    assert body["tripped"] is True
    result = trace(MockSource().build_graph())
    expected = render_check_json(result, evaluate_gate(result, fail_on="HIGH"))
    assert body == json.loads(json.dumps(expected))


def test_check_clean_when_confidence_filters_every_finding(client: TestClient) -> None:
    # The mock's HIGH finding confidence is below 1.0, so min_confidence=1.0 suppresses it.
    response = client.post(
        "/v1/check", json={"source": "mock", "fail_on": "HIGH", "min_confidence": 1.0}
    )
    assert response.status_code == 200
    body = response.json()
    assert body["tripped"] is False
    assert body["min_confidence"] == 1.0
    assert body["suppressed"]


def test_check_min_confidence_defaults_to_zero(client: TestClient) -> None:
    body = client.post("/v1/check", json={"source": "mock", "fail_on": "LOW"}).json()
    assert body["min_confidence"] == 0.0


# -- status mapping -----------------------------------------------------------


def _assert_error(response: Any, status: int, kind: str) -> dict[str, Any]:
    assert response.status_code == status
    body: dict[str, Any] = response.json()
    assert set(body) == {"error"}
    assert set(body["error"]) == {"kind", "message"}
    assert body["error"]["kind"] == kind
    assert isinstance(body["error"]["message"], str)
    return body


def test_selection_validation_error_is_400(client: TestClient) -> None:
    response = client.post(
        "/v1/report",
        json={"source": "mock", "selection": {"roots": ["a"], "from_seeds": True}},
    )
    body = _assert_error(response, 400, "input")
    assert "mutually exclusive" in body["error"]["message"]


@pytest.mark.parametrize("fail_on", ["CRITICAL", "ORIGIN", "NONE", ""])
def test_invalid_fail_on_is_422(client: TestClient, fail_on: str) -> None:
    response = client.post("/v1/check", json={"source": "mock", "fail_on": fail_on})
    assert response.status_code == 422


@pytest.mark.parametrize("fail_on", ["high", "High", "HIGH"])
def test_fail_on_is_case_insensitive(client: TestClient, fail_on: str) -> None:
    response = client.post("/v1/check", json={"source": "mock", "fail_on": fail_on})
    assert response.status_code == 200
    assert response.json()["fail_on"] == "HIGH"


def test_invalid_min_confidence_is_400(client: TestClient) -> None:
    response = client.post(
        "/v1/check", json={"source": "mock", "fail_on": "HIGH", "min_confidence": 1.5}
    )
    _assert_error(response, 400, "input")


@pytest.mark.parametrize(
    ("path", "body"),
    [
        ("/v1/report", {}),
        ("/v1/report", {"source": "dbt"}),
        ("/v1/report", {"source": "mock", "selection": {"roots": "not-a-list"}}),
        ("/v1/check", {"source": "mock"}),
        ("/v1/check", {"source": "mock", "fail_on": "HIGH", "min_confidence": "high"}),
        ("/v1/report", {"source": "mock", "omd_token": "x"}),
        ("/v1/report", {"source": "mock", "omd_host": "http://internal.example.test"}),
        ("/v1/report", {"source": "mock", "selection": {"roots_file": "/etc/passwd"}}),
    ],
)
def test_malformed_body_is_native_422(client: TestClient, path: str, body: dict[str, Any]) -> None:
    response = client.post(path, json=body)
    assert response.status_code == 422
    assert "detail" in response.json()


def test_non_json_body_is_422(client: TestClient) -> None:
    response = client.post(
        "/v1/report", content=b"not json", headers={"content-type": "application/json"}
    )
    assert response.status_code == 422


def test_connection_error_is_502_with_a_fixed_message(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    detail = f"cannot reach OpenMetadata at {FAKE_OMD_HOST}: ConnectError"
    _stub_omd(monkeypatch, SensiflowConnectionError(detail))
    response = client.post("/v1/report", json={"source": "openmetadata"})
    body = _assert_error(response, 502, "connection")
    assert body["error"]["message"] == "the catalog could not be reached"
    assert FAKE_OMD_HOST not in response.text
    assert detail in caplog.text  # the operator still gets the full picture


def test_dependency_error_is_500(client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_omd(monkeypatch, SensiflowDependencyError("install the extra"))
    response = client.post("/v1/check", json={"source": "openmetadata", "fail_on": "HIGH"})
    body = _assert_error(response, 500, "dependency")
    assert "install the extra" not in response.text
    assert body["error"]["message"] == "the server is missing a required component"


def test_unexpected_error_is_generic_500_without_traceback(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _stub_omd(monkeypatch, RuntimeError("secret-internal-detail"))
    response = client.post("/v1/report", json={"source": "openmetadata"})
    body = _assert_error(response, 500, "internal")
    assert "secret-internal-detail" not in response.text
    assert "Traceback" not in response.text
    assert "RuntimeError" not in response.text
    assert body["error"]["message"] == "internal server error"
    # The traceback went to the server log instead.
    assert "secret-internal-detail" not in caplog.text  # uvicorn logs the traceback, once


def test_openmetadata_without_env_is_503_config_free_of_env_values(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OMD_HOST", FAKE_OMD_HOST)  # token missing: still unconfigured
    response = client.post("/v1/report", json={"source": "openmetadata"})
    body = _assert_error(response, 503, "config")
    assert FAKE_OMD_HOST not in response.text
    assert "OMD_" not in body["error"]["message"]


def test_openmetadata_bad_host_is_503_config(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OMD_HOST", "user:pw@catalog.example.test")
    monkeypatch.setenv("OMD_TOKEN", FAKE_OMD_TOKEN)
    response = client.post("/v1/report", json={"source": "openmetadata"})
    _assert_error(response, 503, "config")
    assert "pw@" not in response.text


def test_no_secret_appears_in_any_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENSIFLOW_API_TOKEN", API_TOKEN)
    _stub_omd(monkeypatch, RuntimeError(f"leaky {FAKE_OMD_TOKEN}"))
    auth = {"Authorization": f"Bearer {API_TOKEN}"}
    attempts: list[tuple[str, dict[str, Any], dict[str, str]]] = [
        ("/v1/report", {"source": "mock"}, auth),
        ("/v1/report", {"source": "openmetadata"}, auth),  # 500 internal
        ("/v1/report", {"source": "mock", "selection": {"roots": ["a"], "from_seeds": True}}, auth),
        ("/v1/check", {"source": "mock"}, auth),  # 422
        ("/v1/report", {"source": "mock"}, {"Authorization": "Bearer wrong"}),  # 401
        ("/v1/report", {"source": "mock"}, {}),  # 401
    ]
    with TestClient(create_app(), raise_server_exceptions=False) as client:
        for path, body, headers in attempts:
            response = client.post(path, json=body, headers=headers)
            for secret in (FAKE_OMD_TOKEN, API_TOKEN, FAKE_OMD_HOST):
                assert secret not in response.text
                assert secret not in str(response.headers)
        assert FAKE_OMD_TOKEN not in client.get("/openapi.json").text


# -- auth ---------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/v1/report", "/v1/check"])
def test_auth_enabled_rejects_missing_and_wrong_token(
    monkeypatch: pytest.MonkeyPatch, path: str
) -> None:
    monkeypatch.setenv("SENSIFLOW_API_TOKEN", API_TOKEN)
    body = {"source": "mock", **({"fail_on": "HIGH"} if path.endswith("check") else {})}
    with TestClient(create_app()) as authed:
        for headers in (
            {},
            {"Authorization": "Bearer wrong"},
            {"Authorization": f"Basic {API_TOKEN}"},
            {"Authorization": API_TOKEN},
            {"Authorization": "Bearer "},
        ):
            response = authed.post(path, json=body, headers=headers)
            _assert_error(response, 401, "auth")
            assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize("path", ["/v1/report", "/v1/check"])
def test_auth_enabled_accepts_correct_token(monkeypatch: pytest.MonkeyPatch, path: str) -> None:
    monkeypatch.setenv("SENSIFLOW_API_TOKEN", API_TOKEN)
    body = {"source": "mock", **({"fail_on": "HIGH"} if path.endswith("check") else {})}
    with TestClient(create_app()) as authed:
        response = authed.post(
            path,
            json=body,
            headers={"Authorization": f"Bearer {API_TOKEN}"},
        )
    assert response.status_code == 200


def test_auth_runs_before_body_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENSIFLOW_API_TOKEN", API_TOKEN)
    with TestClient(create_app()) as authed:
        # A malformed body without a token must not reveal schema details via 422.
        response = authed.post("/v1/report", json={})
    assert response.status_code == 401


def test_auth_comparison_is_constant_time(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENSIFLOW_API_TOKEN", API_TOKEN)
    calls: list[tuple[bytes, bytes]] = []
    real = hmac.compare_digest

    def spy(a: bytes, b: bytes) -> bool:
        calls.append((a, b))
        return bool(real(a, b))

    monkeypatch.setattr(hmac, "compare_digest", spy)
    with TestClient(create_app()) as authed:
        authed.post(
            "/v1/report",
            json={"source": "mock"},
            headers={"Authorization": f"Bearer {API_TOKEN}"},
        )
    assert calls == [(API_TOKEN.encode(), API_TOKEN.encode())]


def test_auth_unset_is_open_and_warns_at_startup(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="sensiflow.server"):
        app = create_app()
    assert any("SENSIFLOW_API_TOKEN" in r.getMessage() and "OPEN" in r.getMessage()
               for r in caplog.records)
    with TestClient(app) as open_client:
        assert open_client.post("/v1/report", json={"source": "mock"}).status_code == 200


def test_no_startup_warning_when_auth_enabled(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("SENSIFLOW_API_TOKEN", API_TOKEN)
    with caplog.at_level(logging.WARNING, logger="sensiflow.server"):
        create_app()
    assert not caplog.records


@pytest.mark.parametrize("blank", ["", " ", "\t\n  "])
def test_blank_api_token_refuses_to_start(monkeypatch: pytest.MonkeyPatch, blank: str) -> None:
    monkeypatch.setenv("SENSIFLOW_API_TOKEN", blank)
    with pytest.raises(SensiflowInputError, match="SENSIFLOW_API_TOKEN"):
        create_app()


# -- logging ------------------------------------------------------------------


def test_one_log_line_per_analysis_request_without_secrets(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setenv("SENSIFLOW_API_TOKEN", API_TOKEN)
    monkeypatch.setenv("OMD_TOKEN", FAKE_OMD_TOKEN)
    with TestClient(create_app()) as authed, caplog.at_level(logging.INFO, "sensiflow.server"):
        authed.get("/v1/health")
        authed.post(
            "/v1/check",
            json={"source": "mock", "fail_on": "HIGH", "selection": {"roots": ["raw_customers"]}},
            headers={"Authorization": f"Bearer {API_TOKEN}"},
        )
    messages = [r.getMessage() for r in caplog.records]
    assert len(messages) == 1
    line = messages[0]
    assert "check source=mock roots=1 patterns=0 from_seeds=False" in line
    assert "verdict=tripped" in line
    assert "nodes=" in line
    assert "duration=" in line
    assert API_TOKEN not in line
    assert FAKE_OMD_TOKEN not in line


def test_failed_request_logs_error_kind(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="sensiflow.server"):
        client.post(
            "/v1/report",
            json={"source": "mock", "selection": {"roots": ["a"], "from_seeds": True}},
        )
    lines = [r.getMessage() for r in caplog.records if r.name == "sensiflow.server"]
    assert len(lines) == 1
    assert "error=input" in lines[0]


# -- OpenAPI ------------------------------------------------------------------


def test_openapi_and_docs_remain_available(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    assert {"/v1/health", "/v1/report", "/v1/check"} <= set(schema["paths"])
    assert client.get("/docs").status_code == 200


# -- import hygiene -----------------------------------------------------------


def test_importing_the_library_does_not_load_the_server_layer() -> None:
    code = (
        "import sys, sensiflow, sensiflow.cli\n"
        "loaded = [m for m in ('sensiflow.server', 'fastapi', 'uvicorn', 'pydantic')"
        " if m in sys.modules]\n"
        "assert not loaded, loaded\n"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, check=False
    )
    assert completed.returncode == 0, completed.stderr


def test_create_app_is_idempotent_for_log_handlers() -> None:
    logger = logging.getLogger("sensiflow.server")

    def ours() -> list[logging.Handler]:
        return [h for h in logger.handlers if h.get_name() == "sensiflow.server.stderr"]

    create_app()
    create_app()
    assert len(ours()) == 1
    assert logger.propagate is False

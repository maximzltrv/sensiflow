"""QA supplemental tests for the HTTP API (ADR-0005).

Grey-box probes of what the spec promises beyond the developer's suite:
concurrency, error-path classification during the trace, auth edge cases,
schema strictness, transport-level rejections, cross-front-door agreement
(HTTP vs CLI), and the `serve` exit contract on a real bind failure.
In-process ASGI client and the mock source only; synthetic names only.
"""

from __future__ import annotations

import json
import logging
import socket
import subprocess
import sys
import threading
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import pytest
from fastapi.testclient import TestClient

from sensiflow import (
    GraphSelection,
    LineageGraph,
    Node,
    PiiTag,
    SensiflowError,
    SensiflowInputError,
    evaluate_gate,
    trace,
)
from sensiflow.cli import ExitCode, main
from sensiflow.report import render_check_json, render_json
from sensiflow.server import app as app_module
from sensiflow.server import create_app
from sensiflow.sources.base import LineageSource
from sensiflow.sources.mock import MockSource

API_TOKEN = "fake-api-token-qa-0123"
OTHER_TOKEN = "fake-api-token-qa-4567"

#: kinds the error body may carry: ADR-0005 §4's set plus the 401 "auth" kind.
ALLOWED_ERROR_KINDS = {"input", "connection", "dependency", "internal", "auth", "config"}


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("OMD_HOST", "OMD_TOKEN", "SENSIFLOW_API_TOKEN"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def client() -> Iterator[TestClient]:
    with TestClient(create_app(), raise_server_exceptions=False) as test_client:
        yield test_client


class _StaticSource:
    """A LineageSource returning a fixed graph (or raising a fixed error)."""

    def __init__(self, graph: LineageGraph | None = None, exc: Exception | None = None) -> None:
        self._graph = graph
        self._exc = exc

    def build_graph(self, selection: GraphSelection | None = None) -> LineageGraph:
        if self._exc is not None:
            raise self._exc
        assert self._graph is not None
        return self._graph


def _use_source(monkeypatch: pytest.MonkeyPatch, source: LineageSource) -> None:
    monkeypatch.setattr(app_module, "_make_source", lambda _name: source)


def _cyclic_graph() -> LineageGraph:
    return LineageGraph(
        nodes={
            "stg_alpha": Node(
                id="stg_alpha",
                name="stg_alpha",
                upstream=["stg_beta"],
                declared_pii={"email": PiiTag(category="email")},
            ),
            "stg_beta": Node(id="stg_beta", name="stg_beta", upstream=["stg_alpha"]),
        }
    )


def _roundtrip(document: Any) -> Any:
    return json.loads(json.dumps(document))


def _expected_check(fail_on: str, min_confidence: float = 0.0) -> Any:
    result = trace(MockSource().build_graph())
    outcome = evaluate_gate(result, fail_on=fail_on, min_confidence=min_confidence)  # type: ignore[arg-type]
    return _roundtrip(render_check_json(result, outcome))


def _assert_error(response: Any, status: int, kind: str) -> dict[str, Any]:
    assert response.status_code == status, response.text
    body: dict[str, Any] = response.json()
    assert body == {"error": {"kind": kind, "message": body["error"]["message"]}}
    assert isinstance(body["error"]["message"], str)
    return body


# -- concurrency (sync endpoints in the threadpool) ----------------------------


def test_two_requests_in_flight_at_once_get_their_own_answers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A barrier inside build_graph proves both requests overlap in the threadpool.
    barrier = threading.Barrier(2, timeout=10)

    class _Rendezvous:
        def build_graph(self, selection: GraphSelection | None = None) -> LineageGraph:
            barrier.wait()
            return MockSource().build_graph(selection)

    _use_source(monkeypatch, _Rendezvous())
    with TestClient(create_app()) as test_client, ThreadPoolExecutor(max_workers=2) as pool:
        report_future = pool.submit(test_client.post, "/v1/report", json={"source": "mock"})
        check_future = pool.submit(
            test_client.post, "/v1/check", json={"source": "mock", "fail_on": "HIGH"}
        )
        report_response = report_future.result(timeout=30)
        check_response = check_future.result(timeout=30)

    assert report_response.status_code == 200
    assert report_response.json() == _roundtrip(render_json(trace(MockSource().build_graph())))
    assert check_response.status_code == 200
    assert check_response.json() == _expected_check("HIGH")


def test_concurrent_mixed_policies_never_cross_talk() -> None:
    policies: list[tuple[str, float]] = [
        ("HIGH", 0.0),
        ("LOW", 0.0),
        ("HIGH", 1.0),
        ("MEDIUM", 0.5),
    ] * 4
    with TestClient(create_app()) as test_client, ThreadPoolExecutor(max_workers=8) as pool:
        futures = [
            pool.submit(
                test_client.post,
                "/v1/check",
                json={"source": "mock", "fail_on": fail_on, "min_confidence": conf},
            )
            for fail_on, conf in policies
        ]
        responses = [future.result(timeout=30) for future in futures]
    for (fail_on, conf), response in zip(policies, responses, strict=True):
        assert response.status_code == 200
        assert response.json() == _expected_check(fail_on, conf)


# -- error classification during the trace -------------------------------------


@pytest.mark.parametrize(
    ("path", "extra"), [("/v1/report", {}), ("/v1/check", {"fail_on": "HIGH"})]
)
def test_cycle_detected_during_trace_is_400_input(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    path: str,
    extra: dict[str, Any],
) -> None:
    _use_source(monkeypatch, _StaticSource(_cyclic_graph()))
    with (
        TestClient(create_app(), raise_server_exceptions=False) as test_client,
        caplog.at_level(logging.INFO, logger="sensiflow.server"),
    ):
        caplog.clear()  # drop the startup warning: only request lines count
        response = test_client.post(path, json={"source": "mock", **extra})
    body = _assert_error(response, 400, "input")
    assert "cycle" in body["error"]["message"]
    lines = [r.getMessage() for r in caplog.records if r.name == "sensiflow.server"]
    assert len(lines) == 1
    assert "error=input" in lines[0]


def test_input_error_raised_by_source_is_400_with_library_message(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    message = "root pattern 'mart_*' matched no tables"
    _use_source(monkeypatch, _StaticSource(exc=SensiflowInputError(message)))
    response = client.post(
        "/v1/check",
        json={"source": "mock", "fail_on": "HIGH", "selection": {"patterns": ["mart_*"]}},
    )
    body = _assert_error(response, 400, "input")
    assert body["error"]["message"] == message


def test_bare_sensiflow_error_is_generic_500_without_message(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    _use_source(monkeypatch, _StaticSource(exc=SensiflowError("base-class-internal-detail")))
    response = client.post("/v1/report", json={"source": "mock"})
    body = _assert_error(response, 500, "internal")
    assert "base-class-internal-detail" not in response.text
    assert body["error"]["message"] == "internal server error"


def test_server_keeps_serving_after_an_unexpected_error(
    monkeypatch: pytest.MonkeyPatch, client: TestClient
) -> None:
    calls = {"n": 0}

    class _FlakyOnce:
        def build_graph(self, selection: GraphSelection | None = None) -> LineageGraph:
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("first-call-boom")
            return MockSource().build_graph(selection)

    _use_source(monkeypatch, _FlakyOnce())
    assert client.post("/v1/report", json={"source": "mock"}).status_code == 500
    assert client.post("/v1/report", json={"source": "mock"}).status_code == 200


def test_every_error_body_uses_a_known_kind(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENSIFLOW_API_TOKEN", API_TOKEN)
    auth = {"Authorization": f"Bearer {API_TOKEN}"}
    with TestClient(create_app(), raise_server_exceptions=False) as test_client:
        responses = [
            test_client.post("/v1/report", json={"source": "mock"}),  # 401
            test_client.post(
                "/v1/check",
                json={"source": "mock", "fail_on": "HIGH", "min_confidence": 2.0},
                headers=auth,
            ),
            test_client.post("/v1/report", json={"source": "openmetadata"}, headers=auth),
        ]
        for exc in (RuntimeError("x"), SensiflowInputError("x")):
            _use_source(monkeypatch, _StaticSource(exc=exc))
            responses.append(test_client.post("/v1/report", json={"source": "mock"}, headers=auth))
    for response in responses:
        assert response.status_code >= 400
        assert response.json()["error"]["kind"] in ALLOWED_ERROR_KINDS


# -- auth edge cases --------------------------------------------------------------


@pytest.mark.parametrize(
    "header",
    [
        f"Bearer {API_TOKEN}x",  # token as a prefix of the presented value
        f"Bearer {API_TOKEN[:-1]}",  # presented value as a prefix of the token
        f"Bearer {API_TOKEN.upper()}",  # tokens are case-sensitive
        f"Bearer {OTHER_TOKEN}",
        f"Token {API_TOKEN}",
        f"{API_TOKEN} Bearer",
    ],
)
def test_near_miss_tokens_are_rejected(monkeypatch: pytest.MonkeyPatch, header: str) -> None:
    monkeypatch.setenv("SENSIFLOW_API_TOKEN", API_TOKEN)
    with TestClient(create_app()) as authed:
        response = authed.post(
            "/v1/check",
            json={"source": "mock", "fail_on": "HIGH"},
            headers={"Authorization": header},
        )
    _assert_error(response, 401, "auth")


def test_token_in_query_string_is_not_accepted(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENSIFLOW_API_TOKEN", API_TOKEN)
    with TestClient(create_app()) as authed:
        response = authed.post(f"/v1/report?token={API_TOKEN}", json={"source": "mock"})
    _assert_error(response, 401, "auth")


@pytest.mark.parametrize("blank", ["", "   "])
def test_blank_token_refuses_to_start_rather_than_opening_the_api(
    monkeypatch: pytest.MonkeyPatch, blank: str
) -> None:
    monkeypatch.setenv("SENSIFLOW_API_TOKEN", blank)
    with pytest.raises(SensiflowInputError):
        create_app()


def test_unset_token_warns_that_the_api_is_open(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="sensiflow.server"):
        create_app()
    assert any("OPEN" in r.getMessage() for r in caplog.records)


def test_health_ignores_a_wrong_token_header(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENSIFLOW_API_TOKEN", API_TOKEN)
    with TestClient(create_app()) as authed:
        response = authed.get("/v1/health", headers={"Authorization": "Bearer wrong"})
    assert response.status_code == 200


def test_api_token_is_bound_per_app_at_creation(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENSIFLOW_API_TOKEN", API_TOKEN)
    app_a = create_app()
    monkeypatch.setenv("SENSIFLOW_API_TOKEN", OTHER_TOKEN)
    app_b = create_app()
    monkeypatch.delenv("SENSIFLOW_API_TOKEN")  # later env changes do not reopen either app
    body = {"source": "mock"}
    with TestClient(app_a) as client_a, TestClient(app_b) as client_b:
        for test_client, good, bad in ((client_a, API_TOKEN, OTHER_TOKEN),
                                       (client_b, OTHER_TOKEN, API_TOKEN)):
            ok = test_client.post(
                "/v1/report", json=body, headers={"Authorization": f"Bearer {good}"}
            )
            assert ok.status_code == 200
            rejected = test_client.post(
                "/v1/report", json=body, headers={"Authorization": f"Bearer {bad}"}
            )
            assert rejected.status_code == 401
            assert test_client.post("/v1/report", json=body).status_code == 401


def test_invalid_json_without_token_is_401_and_leaks_no_schema(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("SENSIFLOW_API_TOKEN", API_TOKEN)
    with TestClient(create_app()) as authed:
        response = authed.post(
            "/v1/check", content=b"{not json", headers={"content-type": "application/json"}
        )
    _assert_error(response, 401, "auth")
    for field in ("source", "selection", "fail_on", "min_confidence", "dialect"):
        assert field not in response.text


def test_invalid_json_with_token_is_422(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENSIFLOW_API_TOKEN", API_TOKEN)
    with TestClient(create_app()) as authed:
        response = authed.post(
            "/v1/check",
            content=b"{not json",
            headers={"content-type": "application/json", "Authorization": f"Bearer {API_TOKEN}"},
        )
    assert response.status_code == 422


def test_bearer_scheme_is_case_insensitive(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SENSIFLOW_API_TOKEN", API_TOKEN)
    with TestClient(create_app()) as authed:
        response = authed.post(
            "/v1/report", json={"source": "mock"}, headers={"Authorization": f"bearer {API_TOKEN}"}
        )
    assert response.status_code == 200


# -- transport-level rejections are never 500 -------------------------------------


@pytest.mark.parametrize(
    ("content", "content_type"),
    [
        (b'{"source": "mock"}', "text/plain"),
        (b'{"source": "mock"}', None),
        (b"", "application/json"),
        (b"null", "application/json"),
        (b"[]", "application/json"),
        (b'"mock"', "application/json"),
    ],
)
def test_non_object_or_non_json_bodies_are_422(
    client: TestClient, content: bytes, content_type: str | None
) -> None:
    headers = {"content-type": content_type} if content_type else {}
    response = client.post("/v1/report", content=content, headers=headers)
    assert response.status_code == 422


@pytest.mark.parametrize(
    ("method", "path", "status"),
    [
        ("GET", "/v1/report", 405),
        ("GET", "/v1/check", 405),
        ("POST", "/v1/health", 405),
        ("PUT", "/v1/check", 405),
        ("GET", "/v1/propagate", 404),
        ("POST", "/v2/check", 404),
    ],
)
def test_wrong_method_or_path_is_4xx_not_500(
    client: TestClient, method: str, path: str, status: int
) -> None:
    response = client.request(method, path, json={"source": "mock", "fail_on": "HIGH"})
    assert response.status_code == status


def test_no_mutation_endpoint_is_published(client: TestClient) -> None:
    schema = client.get("/openapi.json").json()
    for path, operations in schema["paths"].items():
        assert path.startswith("/v1/")
        assert set(operations) <= {"get", "post"}
    assert set(schema["paths"]) == {"/v1/health", "/v1/report", "/v1/check"}


# -- schema strictness: no credentials, no paths, no dbt -----------------------------


@pytest.mark.parametrize(
    "body",
    [
        {"source": "mock", "fail_on": "HIGH", "omd_token": "x"},
        {"source": "mock", "fail_on": "HIGH", "omd_host": "http://catalog.example.test"},
        {"source": "mock", "fail_on": "HIGH", "dbt_manifest": "/srv/manifest.json"},
        {"source": "mock", "fail_on": "HIGH", "roots_file": "roots.yaml"},
        {"source": "mock", "fail_on": "HIGH", "selection": {"roots_file": "roots.yaml"}},
        {"source": "mock", "fail_on": "HIGH", "selection": {"token": "x"}},
        {"source": "dbt", "fail_on": "HIGH"},
        {"source": "MOCK", "fail_on": "HIGH"},
        {"source": "mock", "fail_on": "HIGH", "selection": None},
        {"source": "mock", "fail_on": "HIGH", "dialect": None},
        {"source": "mock", "fail_on": None},
        {"source": "mock", "fail_on": "HIGH", "selection": {"upstream_depth": 1.5}},
        {"source": "mock", "fail_on": "HIGH", "selection": {"roots": [1, 2]}},
    ],
)
def test_check_schema_rejects_out_of_contract_bodies(
    client: TestClient, body: dict[str, Any]
) -> None:
    response = client.post("/v1/check", json=body)
    assert response.status_code == 422


def test_boolean_min_confidence_is_rejected(client: TestClient) -> None:
    response = client.post(
        "/v1/check", json={"source": "mock", "fail_on": "HIGH", "min_confidence": True}
    )
    assert response.status_code == 422


@pytest.mark.parametrize("literal", [b"NaN", b"Infinity", b"-Infinity", b"-0.1", b"1.0001"])
def test_out_of_range_min_confidence_is_400_never_clean(client: TestClient, literal: bytes) -> None:
    content = b'{"source": "mock", "fail_on": "HIGH", "min_confidence": ' + literal + b"}"
    response = client.post(
        "/v1/check", content=content, headers={"content-type": "application/json"}
    )
    body = _assert_error(response, 400, "input")
    assert "min-confidence" in body["error"]["message"]


@pytest.mark.parametrize("fail_on", ["ORIGIN", "NONE", ""])
def test_non_threshold_fail_on_is_422(client: TestClient, fail_on: str) -> None:
    response = client.post("/v1/check", json={"source": "mock", "fail_on": fail_on})
    assert response.status_code == 422


@pytest.mark.parametrize(
    ("selection", "fragment"),
    [
        ({"roots": [""]}, "non-empty"),
        ({"roots": ["mart_*"]}, "use patterns"),
        ({"patterns": ["mart_orders"]}, "use roots"),
        ({"patterns": [""]}, "non-empty"),
        ({"upstream_depth": 2}, "depths require roots"),
        ({"roots": ["raw_customers"], "downstream_depth": -1}, ">= 0"),
        ({"patterns": ["raw_*"], "from_seeds": True}, "mutually exclusive"),
    ],
)
def test_selection_semantics_come_from_graph_selection(
    client: TestClient, selection: dict[str, Any], fragment: str
) -> None:
    response = client.post("/v1/report", json={"source": "mock", "selection": selection})
    body = _assert_error(response, 400, "input")
    assert fragment in body["error"]["message"]
    # Byte-identical message to the library's own validation.
    with pytest.raises(SensiflowInputError) as excinfo:
        GraphSelection(
            roots=tuple(selection.get("roots", ())),
            patterns=tuple(selection.get("patterns", ())),
            from_seeds=selection.get("from_seeds", False),
            upstream_depth=selection.get("upstream_depth"),
            downstream_depth=selection.get("downstream_depth"),
        )
    assert body["error"]["message"] == str(excinfo.value)


def test_selection_at_the_roots_cap_is_served_and_beyond_it_is_422(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    over = [f"stg_table_{i:05d}" for i in range(1001)]
    rejected = client.post("/v1/report", json={"source": "mock", "selection": {"roots": over}})
    assert rejected.status_code == 422
    patterns = [f"stg_{i}_*" for i in range(101)]
    rejected = client.post(
        "/v1/report", json={"source": "mock", "selection": {"patterns": patterns}}
    )
    assert rejected.status_code == 422
    roots = over[:1000]
    with caplog.at_level(logging.INFO, logger="sensiflow.server"):
        response = client.post("/v1/report", json={"source": "mock", "selection": {"roots": roots}})
    assert response.status_code == 200
    assert any("roots=1000" in r.getMessage() for r in caplog.records)


# -- cross-front-door agreement (HTTP vs CLI over the same library) ----------------


@pytest.mark.parametrize(
    ("fail_on", "min_confidence"), [("HIGH", 0.0), ("LOW", 0.0), ("HIGH", 1.0), ("MEDIUM", 0.5)]
)
def test_http_check_matches_cli_check_json(
    client: TestClient,
    capsys: pytest.CaptureFixture[str],
    fail_on: str,
    min_confidence: float,
) -> None:
    exit_code = main(
        [
            "check", "--source", "mock", "--fail-on", fail_on,
            "--min-confidence", str(min_confidence), "--format", "json",
        ]
    )
    cli_document = json.loads(capsys.readouterr().out)
    response = client.post(
        "/v1/check",
        json={"source": "mock", "fail_on": fail_on, "min_confidence": min_confidence},
    )
    assert response.status_code == 200
    assert response.json() == cli_document
    assert (exit_code == ExitCode.GATE_TRIPPED) == response.json()["tripped"]


def test_http_report_matches_cli_report_json(
    client: TestClient, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["report", "--source", "mock", "--format", "json", "--dialect", "postgres"]) == 0
    cli_document = json.loads(capsys.readouterr().out)
    response = client.post("/v1/report", json={"source": "mock", "dialect": "postgres"})
    assert response.json() == cli_document


# -- serve command: exit contract and parser isolation -----------------------------


def test_serve_bind_conflict_exits_3_never_1() -> None:
    # Real uvicorn on loopback: the port is taken, startup fails, nothing serves.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as blocker:
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        port = blocker.getsockname()[1]
        try:
            code: int | str | None = main(["serve", "--host", "127.0.0.1", "--port", str(port)])
        except SystemExit as exc:  # uvicorn exits on startup failure
            code = exc.code
    assert code == ExitCode.OPERATIONAL_ERROR


@pytest.mark.parametrize(
    "argv",
    [
        ["serve", "--source", "mock"],
        ["serve", "--fail-on", "HIGH"],
        ["serve", "--port", "eighty"],
        ["serve", "--omd-token", "x"],
    ],
)
def test_serve_rejects_foreign_flags_as_usage_error(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(argv)
    assert excinfo.value.code == ExitCode.INPUT_ERROR


def test_report_and_check_ignore_serve_flags(capsys: pytest.CaptureFixture[str]) -> None:
    # The serve subparser must not leak --host/--port into the analysis commands.
    with pytest.raises(SystemExit) as excinfo:
        main(["report", "--port", "8000"])
    assert excinfo.value.code == ExitCode.INPUT_ERROR
    capsys.readouterr()
    assert main(["check", "--fail-on", "high", "--format", "json"]) == ExitCode.GATE_TRIPPED


# -- logging stays in the server layer -----------------------------------------------


def test_core_library_creates_no_loggers() -> None:
    code = (
        "import logging, sensiflow, sensiflow.cli\n"
        "from sensiflow import trace\n"
        "from sensiflow.sources.mock import MockSource\n"
        "trace(MockSource().build_graph())\n"
        "names = [n for n in logging.Logger.manager.loggerDict if n.startswith('sensiflow')]\n"
        "assert not names, names\n"
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-c", code], capture_output=True, text=True, check=False
    )
    assert completed.returncode == 0, completed.stderr


def test_server_logger_handler_is_installed_once_across_many_apps() -> None:
    logger = logging.getLogger("sensiflow.server")
    for _ in range(5):
        create_app()
    ours = [h for h in logger.handlers if h.get_name() == "sensiflow.server.stderr"]
    assert len(ours) == 1

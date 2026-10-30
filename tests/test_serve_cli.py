"""`sensiflow serve` wiring (ADR-0005 §8): lazy import, exit contract, uvicorn call."""

from __future__ import annotations

import sys
from typing import Any

import pytest

from sensiflow.cli import ExitCode, main

_SERVER_STACK = ("sensiflow.server", "fastapi", "starlette", "pydantic")


def _hide_server_stack(monkeypatch: pytest.MonkeyPatch, missing: str) -> None:
    """Simulate an install without ``missing``: drop cached modules, block the import.

    The whole server stack is dropped from the module cache so the lazy import in
    ``serve`` really re-executes (a cached ``fastapi`` would mask a missing starlette).
    """
    for name in list(sys.modules):
        if any(name == root or name.startswith(f"{root}.") for root in _SERVER_STACK):
            monkeypatch.delitem(sys.modules, name)
    monkeypatch.setitem(sys.modules, missing, None)  # the import raises ModuleNotFoundError


@pytest.mark.parametrize("missing", ["fastapi", "uvicorn", "starlette", "pydantic"])
def test_serve_missing_extra_exits_3_with_hint(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], missing: str
) -> None:
    _hide_server_stack(monkeypatch, missing)
    assert main(["serve"]) == ExitCode.OPERATIONAL_ERROR
    err = capsys.readouterr().err
    assert "pip install 'sensiflow[server]'" in err
    assert "Traceback" not in err


def test_serve_does_not_mask_unrelated_import_errors(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    # A broken sensiflow module is a bug, not a missing extra: no install hint.
    _hide_server_stack(monkeypatch, "sensiflow.server.schemas")
    assert main(["serve"]) == ExitCode.OPERATIONAL_ERROR
    err = capsys.readouterr().err
    assert "pip install" not in err
    assert "Traceback" in err


def test_serve_blank_api_token_is_exit_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import uvicorn

    monkeypatch.setattr(uvicorn, "run", lambda *a, **k: pytest.fail("must not start serving"))
    for blank in ("", "   "):
        monkeypatch.setenv("SENSIFLOW_API_TOKEN", blank)
        assert main(["serve"]) == ExitCode.INPUT_ERROR
        assert "SENSIFLOW_API_TOKEN" in capsys.readouterr().err


def test_serve_runs_uvicorn_with_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    import uvicorn

    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.append({"app": app, **kw}))
    assert main(["serve"]) == ExitCode.OK
    assert len(calls) == 1
    assert calls[0]["host"] == "127.0.0.1"
    assert calls[0]["port"] == 8000
    assert calls[0]["app"].title == "sensiflow"
    assert set(calls[0]) == {"app", "host", "port"}  # single process: no workers/TLS


def test_serve_passes_host_and_port(monkeypatch: pytest.MonkeyPatch) -> None:
    import uvicorn

    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: calls.append(kw))
    assert main(["serve", "--host", "0.0.0.0", "--port", "9100"]) == ExitCode.OK
    assert calls == [{"host": "0.0.0.0", "port": 9100}]


def test_serve_unexpected_crash_is_exit_3(monkeypatch: pytest.MonkeyPatch) -> None:
    import uvicorn

    def boom(*_: Any, **__: Any) -> None:
        raise OSError("address in use")

    monkeypatch.setattr(uvicorn, "run", boom)
    assert main(["serve"]) == ExitCode.OPERATIONAL_ERROR

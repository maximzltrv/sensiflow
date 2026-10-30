"""`sensiflow serve` wiring (ADR-0005 §8): lazy import, exit contract, uvicorn call."""

from __future__ import annotations

import sys
from typing import Any

import pytest

from sensiflow.cli import ExitCode, main


@pytest.mark.parametrize("missing", ["sensiflow.server", "uvicorn"])
def test_serve_missing_extra_exits_3_with_hint(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], missing: str
) -> None:
    monkeypatch.setitem(sys.modules, missing, None)  # makes the import raise ImportError
    assert main(["serve"]) == ExitCode.OPERATIONAL_ERROR
    err = capsys.readouterr().err
    assert "pip install 'sensiflow[server]'" in err
    assert "Traceback" not in err


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

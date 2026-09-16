"""CLI integration tests: argv in -> rendered report on stdout, exit code out.

These exercise the full pipeline (mock source -> engine -> renderer -> stdout)
through the same entry point the `sensiflow` console script uses.
"""

from __future__ import annotations

import json

import pytest

from sensiflow.cli import main


def test_report_text_end_to_end(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["report", "--source", "mock"])
    out = capsys.readouterr().out

    assert exit_code == 0
    assert "7 nodes analyzed" in out
    # One line per risk level actually present on the mock graph.
    assert "[HIGH] mart_orders_enriched" in out
    assert "[MEDIUM] stg_customers" in out
    assert "[LOW] mart_customer_dump" in out
    assert "[ORIGIN] raw_customers" in out
    assert "[NONE] mart_daily_revenue" in out
    # Owners surface in the report — that is the "whose datamart" feature.
    assert "analytics@example.com" in out


def test_report_json_is_valid_and_complete(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["report", "--format", "json"])
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["summary"] == {"HIGH": 1, "MEDIUM": 2, "LOW": 1, "ORIGIN": 1, "NONE": 2}
    nodes = {node["node_id"]: node for node in payload["nodes"]}
    assert len(nodes) == 7
    assert nodes["mart_orders_enriched"]["max_risk"] == "HIGH"
    high_findings = nodes["mart_orders_enriched"]["findings"]
    assert any(f["column"] == "email" and f["risk"] == "HIGH" for f in high_findings)


def test_text_is_the_default_format(capsys: pytest.CaptureFixture[str]) -> None:
    main(["report"])
    out = capsys.readouterr().out
    assert out.startswith("sensiflow report")


def test_unknown_source_is_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["report", "--source", "dbt"])
    # argparse exits with code 2 on invalid choices; stderr names the argument.
    assert excinfo.value.code == 2
    assert "--source" in capsys.readouterr().err


def test_openmetadata_requires_credentials(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("OMD_HOST", raising=False)
    monkeypatch.delenv("OMD_TOKEN", raising=False)
    with pytest.raises(SystemExit) as excinfo:
        main(["report", "--source", "openmetadata"])
    assert excinfo.value.code == 2
    assert "OMD_HOST" in capsys.readouterr().err


def test_negative_depth_is_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["report", "--upstream-depth", "-1"])
    assert excinfo.value.code == 2
    assert "upstream-depth" in capsys.readouterr().err


def test_missing_command_is_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main([])
    assert excinfo.value.code == 2

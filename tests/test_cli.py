"""CLI integration tests: argv in -> rendered report on stdout, exit code out.

These exercise the full pipeline (mock source -> engine -> renderer -> stdout)
through the same entry point the `sensiflow` console script uses.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from sensiflow.cli import main
from sensiflow.exceptions import SensiflowConnectionError
from sensiflow.root_selectors import GraphSelection
from sensiflow.sources.mock import MockSource


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
    # Depth validation lives in GraphSelection (ADR-0002 amendment A4), so it
    # surfaces through the library error path; SensiflowInputError maps to
    # exit 2 in the ADR-0004 taxonomy, matching argparse's native usage errors.
    exit_code = main(["report", "--root", "raw_customers", "--upstream-depth", "-1"])
    err = capsys.readouterr().err
    assert exit_code == 2
    assert err.startswith("error:")
    assert "upstream-depth" in err


def test_missing_command_is_rejected(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main([])
    assert excinfo.value.code == 2


def test_roots_from_seeds_is_exclusive_with_root(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(["report", "--root", "raw_customers", "--roots-from-seeds"])
    err = capsys.readouterr().err
    assert exit_code == 2
    assert err.startswith("error:")
    assert "mutually exclusive" in err


def test_report_invalid_manifest_is_input_error(capsys: pytest.CaptureFixture[str]) -> None:
    # ADR-0004 realignment: report's input errors now exit 2, not 1.
    exit_code = main(["report", "--source", "dbt", "--dbt-manifest", "no/such/manifest.json"])
    err = capsys.readouterr().err
    assert exit_code == 2
    assert err.startswith("error:")


def test_report_operational_error_exits_3(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # ADR-0004 realignment: environmental failures exit 3, distinguishable
    # from input errors (2) so CI can decide whether a retry makes sense.
    def boom(self: MockSource, selection: GraphSelection | None = None) -> None:
        raise SensiflowConnectionError("catalog unreachable at http://localhost:8585")

    monkeypatch.setattr(MockSource, "build_graph", boom)
    exit_code = main(["report", "--source", "mock"])
    err = capsys.readouterr().err
    assert exit_code == 3
    assert err.startswith("error:")


def test_roots_file_may_be_given_at_most_once(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    roots_file = tmp_path / "roots.yaml"
    roots_file.write_text("version: 1\nroots:\n  - id: raw_customers\n")
    with pytest.raises(SystemExit) as excinfo:
        main(
            [
                "report",
                "--roots-file",
                str(roots_file),
                "--roots-file",
                str(roots_file),
            ]
        )
    assert excinfo.value.code == 2
    assert "at most once" in capsys.readouterr().err


def test_cli_rejects_host_with_embedded_credentials(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("OMD_TOKEN", raising=False)
    code = main(
        ["report", "--source", "openmetadata", "--omd-token", "tok_synthetic",
         "--omd-host", "http://svc_user:s3cret_pw@omd.test"]
    )
    captured = capsys.readouterr()
    assert code == 2
    assert "error: credentials embedded" in captured.err
    assert "svc_user" not in captured.err
    assert "s3cret_pw" not in captured.err
    assert captured.out == ""

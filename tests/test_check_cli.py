"""CLI integration tests for `sensiflow check` (ADR-0004).

All four exit codes are exercised offline: 0 (pass), 1 (gate tripped),
2 (usage/input error), 3 (operational error / unexpected crash). The mock
source covers the trip paths; a synthetic dbt manifest covers pass paths
(the mock graph always contains a HIGH node, so a clean pass needs a graph
built from different data).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from sensiflow.cli import ExitCode, main
from sensiflow.exceptions import SensiflowConnectionError, SensiflowDependencyError
from sensiflow.root_selectors import GraphSelection
from sensiflow.sources.mock import MockSource


def _write_manifest(tmp_path: Path, *, with_pii: bool) -> str:
    """A minimal synthetic dbt manifest: one source feeding one model."""
    email_column: dict[str, Any] = (
        {"email": {"meta": {"pii": True, "pii_category": "email"}}} if with_pii else {}
    )
    manifest = {
        "metadata": {"project_name": "demo_shop"},
        "nodes": {
            "model.demo_shop.stg_people": {
                "resource_type": "model",
                "name": "stg_people",
                "depends_on": {"nodes": ["source.demo_shop.crm.raw_people"]},
                "columns": {},
                "compiled_code": "SELECT person_id, email FROM raw_people",
            }
        },
        "sources": {
            "source.demo_shop.crm.raw_people": {
                "resource_type": "source",
                "name": "raw_people",
                "columns": email_column,
            }
        },
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    return str(path)


def test_exit_code_taxonomy_values_are_pinned() -> None:
    # The exit codes are a public CI contract (ADR-0004 §1): changing any of
    # these values is a major-version event.
    assert ExitCode.OK.value == 0
    assert ExitCode.GATE_TRIPPED.value == 1
    assert ExitCode.INPUT_ERROR.value == 2
    assert ExitCode.OPERATIONAL_ERROR.value == 3


# --- exit 1: gate tripped ----------------------------------------------------


def test_check_trips_on_mock_graph(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["check", "--source", "mock", "--fail-on", "HIGH"])
    out = capsys.readouterr().out
    assert exit_code == ExitCode.GATE_TRIPPED
    assert "result: FAIL — 1 node at or above HIGH" in out
    assert "mart_orders_enriched" in out


def test_check_fail_on_is_case_insensitive(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["check", "--fail-on", "high"])
    out = capsys.readouterr().out
    assert exit_code == 1
    assert "fail-on=HIGH" in out


def test_check_json_format_trip(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["check", "--fail-on", "HIGH", "--format", "json"])
    doc = json.loads(capsys.readouterr().out)
    assert exit_code == 1
    assert doc["tripped"] is True
    assert doc["fail_on"] == "HIGH"
    assert [n["node_id"] for n in doc["violations"]] == ["mart_orders_enriched"]


def test_check_dbt_manifest_with_pii_trips_at_medium(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    # The whole shared plumbing (source + root selectors) works for check too.
    manifest = _write_manifest(tmp_path, with_pii=True)
    exit_code = main(
        [
            "check",
            "--source",
            "dbt",
            "--dbt-manifest",
            manifest,
            "--roots-from-seeds",
            "--fail-on",
            "MEDIUM",
        ]
    )
    out = capsys.readouterr().out
    assert exit_code == 1
    assert "stg_people" in out


# --- exit 0: pass ------------------------------------------------------------


def test_check_clean_pass_no_pii(capsys: pytest.CaptureFixture[str], tmp_path: Path) -> None:
    manifest = _write_manifest(tmp_path, with_pii=False)
    exit_code = main(
        ["check", "--source", "dbt", "--dbt-manifest", manifest, "--fail-on", "LOW"]
    )
    out = capsys.readouterr().out
    assert exit_code == ExitCode.OK
    assert "result: PASS — no findings at or above LOW" in out
    # Warnings are displayed but do not affect the exit code (v1 decision).
    assert "warning: no PII seeds declared" in out


def test_check_passes_below_threshold_with_findings_present(
    capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    # The projected PII is MEDIUM; a HIGH gate passes while findings exist below it.
    manifest = _write_manifest(tmp_path, with_pii=True)
    exit_code = main(
        ["check", "--source", "dbt", "--dbt-manifest", manifest, "--fail-on", "HIGH"]
    )
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "result: PASS" in out
    assert "MEDIUM=1" in out


def test_check_min_confidence_pass_surfaces_suppressed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(["check", "--fail-on", "HIGH", "--min-confidence", "0.9"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "suppressed by --min-confidence 0.9 (not gating): 1 finding" in out
    assert "(1 suppressed below confidence)" in out


def test_check_min_confidence_json_pass(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(["check", "--fail-on", "HIGH", "--min-confidence", "0.9", "--format", "json"])
    doc = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert doc["tripped"] is False
    assert doc["min_confidence"] == 0.9
    assert len(doc["suppressed"]) == 1


# --- exit 2: usage / input errors ---------------------------------------------


def test_check_fail_on_is_required(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["check", "--source", "mock"])
    assert excinfo.value.code == 2
    assert "--fail-on" in capsys.readouterr().err


def test_check_rejects_unknown_fail_on(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["check", "--fail-on", "CRITICAL"])
    assert excinfo.value.code == 2
    assert "--fail-on" in capsys.readouterr().err


def test_check_rejects_non_numeric_min_confidence(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["check", "--fail-on", "HIGH", "--min-confidence", "very"])
    assert excinfo.value.code == 2


@pytest.mark.parametrize("bad", ["-0.1", "1.5"])
def test_check_out_of_range_min_confidence_exits_2(
    capsys: pytest.CaptureFixture[str], bad: str
) -> None:
    # Range validation lives in evaluate_gate (library), so it surfaces as a
    # SensiflowInputError mapped to exit 2 — not as an argparse error.
    exit_code = main(["check", "--fail-on", "HIGH", "--min-confidence", bad])
    err = capsys.readouterr().err
    assert exit_code == ExitCode.INPUT_ERROR
    assert err.startswith("error:")
    assert "min-confidence" in err


def test_check_missing_manifest_exits_2(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(
        ["check", "--source", "dbt", "--dbt-manifest", "no/such/manifest.json",
         "--fail-on", "HIGH"]
    )
    err = capsys.readouterr().err
    assert exit_code == 2
    assert err.startswith("error:")


def test_check_invalid_selector_exits_2(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = main(
        ["check", "--fail-on", "HIGH", "--root", "raw_customers", "--upstream-depth", "-1"]
    )
    err = capsys.readouterr().err
    assert exit_code == 2
    assert "upstream-depth" in err


# --- exit 3: operational errors -----------------------------------------------


@pytest.mark.parametrize(
    "exc",
    [
        SensiflowConnectionError("catalog unreachable at http://localhost:8585"),
        SensiflowDependencyError("install sensiflow[openmetadata] to use this source"),
    ],
)
def test_check_operational_errors_exit_3(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    exc: Exception,
) -> None:
    def boom(self: MockSource, selection: GraphSelection | None = None) -> None:
        raise exc

    monkeypatch.setattr(MockSource, "build_graph", boom)
    exit_code = main(["check", "--fail-on", "HIGH"])
    err = capsys.readouterr().err
    assert exit_code == ExitCode.OPERATIONAL_ERROR
    assert err.startswith("error:")


def test_check_unexpected_crash_exits_3_with_traceback(
    capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # Exit 1 is reserved for gate trips: a crash must never fake one, and the
    # full traceback must reach stderr for diagnosis.
    def boom(self: MockSource, selection: GraphSelection | None = None) -> None:
        raise RuntimeError("synthetic internal failure")

    monkeypatch.setattr(MockSource, "build_graph", boom)
    exit_code = main(["check", "--fail-on", "HIGH"])
    captured = capsys.readouterr()
    assert exit_code == 3
    assert "Traceback (most recent call last)" in captured.err
    assert "synthetic internal failure" in captured.err
    assert captured.out == ""

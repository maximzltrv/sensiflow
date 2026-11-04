"""QA supplemental tests for `propagate` write-back (ADR-0006).

Grey-box probes of what the spec promises and the public interfaces allow,
beyond the developer's own suites:

* plan/gate boundary parity (ADR-0004 A4 reused verbatim, §2);
* cross-connector classification consistency (OMD and dbt translate the same
  markup state into the same diff action, §3/§7);
* dbt edge inputs: malformed markers, shared properties files, traversal via
  symlinks, flow style, crash mid-apply, multi-level convergence (§4/§6);
* stale detection scoped to the traced subgraph through the CLI (§7);
* defects found in review, pinned as regression tests (the deferred BOM
  fidelity defect remains an ``xfail(strict=True)`` until it is fixed).

All project, model, column and host names are synthetic.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest
import yaml

from sensiflow import (
    ExistingTag,
    Finding,
    GateRisk,
    NodeResult,
    PiiTag,
    Risk,
    TagChange,
    TagPlan,
    TraceResult,
    WritebackDiff,
    apply_writeback,
    diff_writeback,
    evaluate_gate,
    plan_writeback,
    trace,
)
from sensiflow.cli import main
from sensiflow.sources.dbt import DbtSource
from tests.support import PREFIX, FakeOmd, actions, label, regenerate_manifest

PROJECT = "acme_demo"
SRC = f"source.{PROJECT}.crm.raw_people"
STG = f"model.{PROJECT}.stg_people"
JOINED = f"model.{PROJECT}.int_order_matches"
WIDE = f"model.{PROJECT}.wide_people"
WIDER = f"model.{PROJECT}.wider_people"
SIDE = f"model.{PROJECT}.side_people"
MARKER = "Sensiflow.Propagated"
OMD_STG = f"{PREFIX}.stg_customers"


# --- synthetic dbt project builder ---------------------------------------------------------------


def _model(name: str, sql: str, deps: Sequence[str], patch: str | None) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "resource_type": "model",
        "name": name,
        "package_name": PROJECT,
        "compiled_code": sql,
        "depends_on": {"nodes": list(deps)},
        "columns": {},
    }
    if patch is not None:
        raw["patch_path"] = f"{PROJECT}://{patch}"
    return raw


def make_project(
    root: Path,
    models: Mapping[str, tuple[str, Sequence[str], str | None]],
    files: Mapping[str, str | bytes],
) -> Path:
    """A dbt project: one PII source (email, phone) plus the given models and YAML files."""
    root.mkdir(parents=True, exist_ok=True)
    manifest = {
        "metadata": {"project_name": PROJECT},
        "sources": {
            SRC: {
                "resource_type": "source",
                "name": "raw_people",
                "package_name": PROJECT,
                "columns": {
                    "email": {"name": "email", "meta": {"pii": True, "pii_category": "email"}},
                    "phone": {"name": "phone", "meta": {"pii": True, "pii_category": "phone"}},
                },
            }
        },
        "nodes": {
            f"model.{PROJECT}.{name}": _model(name, sql, deps, patch)
            for name, (sql, deps, patch) in models.items()
        },
    }
    (root / "manifest.json").write_text(json.dumps(manifest))
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content)
    return root


def set_sql(root: Path, node_id: str, sql: str) -> None:
    path = root / "manifest.json"
    manifest = json.loads(path.read_text())
    manifest["nodes"][node_id]["compiled_code"] = sql
    path.write_text(json.dumps(manifest))


def dbt_diff(
    root: Path, min_risk: Risk = "LOW", min_confidence: float = 0.0
) -> tuple[DbtSource, WritebackDiff]:
    source = DbtSource(root / "manifest.json", root)
    plan = plan_writeback(
        trace(source.build_graph()), min_risk=min_risk, min_confidence=min_confidence
    )
    return source, diff_writeback(plan, source)


STG_ONLY = {"stg_people": ("SELECT person_key, email FROM raw_people", [SRC], "models/schema.yml")}
BASE_YML = "version: 2\nmodels:\n  - name: stg_people\n    columns:\n      - name: person_key\n"


# --- plan / gate boundary parity (ADR-0006 §2 reuses ADR-0004 A4 verbatim) ------------------------

_CONFIDENCES = (0.0, 0.3, 0.74994, 0.74995, 0.749949999, 0.75, 0.75004, 0.75005, 0.9999, 1.0)
_FLOORS = (0.0, 0.5, 0.7499, 0.74995, 0.75, 0.750049999, 0.75005, 1.0)


def _result_with(confidences: tuple[float, ...], risk: Risk) -> TraceResult:
    findings = {
        f"c{i}": Finding(f"c{i}", PiiTag("email"), risk, "test", conf, "origin")
        for i, conf in enumerate(confidences)
    }
    node = NodeResult("n", "n", [], False, findings)
    return TraceResult(nodes={"n": node})


@pytest.mark.parametrize("floor", _FLOORS)
@pytest.mark.parametrize("min_risk", ["LOW", "MEDIUM", "HIGH"])
@pytest.mark.parametrize("risk", ["ORIGIN", "LOW", "MEDIUM", "HIGH", "NONE"])
def test_plan_selection_is_exactly_the_gate_selection(
    floor: float, min_risk: GateRisk, risk: Risk
) -> None:
    # One confidence semantics across check and propagate: a finding is written
    # iff it would gate, and suppressed iff the gate would suppress it.
    result = _result_with(_CONFIDENCES, risk)
    plan = plan_writeback(result, min_risk=min_risk, min_confidence=floor)
    gate = evaluate_gate(result, fail_on=min_risk, min_confidence=floor)

    gate_suppressed = {f.column for _, f in gate.suppressed}
    gate_gating = {
        f.column
        for node in gate.violations
        for f in node.findings.values()
        if f.column not in gate_suppressed and f.risk == risk and risk not in ("ORIGIN", "NONE")
    }
    assert {c.column for c in plan.changes} == gate_gating
    assert {c.column for c in plan.suppressed} == gate_suppressed


# --- cross-connector consistency: same markup state, same action ---------------------------------

# Each state: (OMD tag labels on the column, dbt column `meta`). Managed dbt
# provenance matches the planned change exactly, so only the state differs.
_PROV = {"propagated": True, "risk": "MEDIUM", "confidence": 0.9, "origin": "origin.node"}
_STATES: dict[str, tuple[list[dict[str, str]], dict[str, Any] | None]] = {
    "none": ([], None),
    "human_sensitive": ([label("PII.Sensitive")], {"pii": True}),
    "human_non_sensitive": (
        [label("PII.NonSensitive")],
        {"pii": True, "pii_sensitive": False},
    ),
    "managed_sensitive": (
        [label("PII.Sensitive"), label(MARKER)],
        {"pii": True, "pii_sensitive": True, "sensiflow": _PROV},
    ),
    "managed_non_sensitive": (
        [label("PII.NonSensitive"), label(MARKER)],
        {"pii": True, "pii_sensitive": False, "sensiflow": _PROV},
    ),
}


def _plan_for(node_id: str, sensitive: bool) -> TagPlan:
    change = TagChange(
        node_id, "stg", "email", PiiTag("email", sensitive), "MEDIUM", 0.9, "origin.node"
    )
    return TagPlan("MEDIUM", 0.0, [change], [], traced_nodes={node_id: "stg"})


def _omd_action(tags: list[dict[str, str]], sensitive: bool) -> str:
    omd = FakeOmd()
    omd.column(OMD_STG, "email")["tags"] = tags
    diff = diff_writeback(_plan_for(OMD_STG, sensitive), omd.source())
    return diff.changes[0].action


def _dbt_action(tmp_path: Path, meta: dict[str, Any] | None, sensitive: bool) -> str:
    column: dict[str, Any] = {"name": "email"}
    if meta is not None:
        column["meta"] = meta
    document = {"version": 2, "models": [{"name": "stg_people", "columns": [column]}]}
    root = make_project(
        tmp_path / "proj", STG_ONLY, {"models/schema.yml": yaml.safe_dump(document)}
    )
    source = DbtSource(root / "manifest.json", root)
    diff = diff_writeback(_plan_for(STG, sensitive), source)
    return diff.changes[0].action


@pytest.mark.parametrize("sensitive", [True, False], ids=["derived_sensitive", "derived_non"])
@pytest.mark.parametrize("state", sorted(_STATES))
def test_omd_and_dbt_classify_the_same_markup_state_identically(
    tmp_path: Path, state: str, sensitive: bool
) -> None:
    tags, meta = _STATES[state]
    assert _omd_action(tags, sensitive) == _dbt_action(tmp_path, meta, sensitive)


def test_omd_confirmed_label_plus_marker_is_human_authority_but_still_does_not_seed() -> None:
    # ADR-0006 A1: a steward-confirmed (Manual/Confirmed) label next to the marker
    # is human-ratified: the diff treats it as human markup (never updated), while
    # seeding stays marker-only until the marker is removed. dbt has no label
    # state, so there the block alone decides: an accepted, documented asymmetry.
    omd = FakeOmd()
    confirmed = label("PII.NonSensitive") | {"labelType": "Manual", "state": "Confirmed"}
    omd.column(OMD_STG, "email")["tags"] = [confirmed, label(MARKER)]
    source = omd.source()
    assert source.read_markup([OMD_STG])[(OMD_STG, "email")].managed is False
    assert "email" not in source.build_graph().nodes[OMD_STG].declared_pii
    assert _omd_action([confirmed, label(MARKER)], True) == "conflict"
    assert _omd_action([confirmed, label(MARKER)], False) == "manual"


# --- dbt: malformed markers ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "marker",
    ["true", "[propagated]", "{propagated: 'true'}", "{propagated: 1}", "{propagated: false}", "~"],
)
def test_malformed_dbt_marker_is_not_managed_and_is_repaired_by_an_add(
    tmp_path: Path, marker: str
) -> None:
    yml = BASE_YML + f"      - name: email\n        meta:\n          sensiflow: {marker}\n"
    root = make_project(tmp_path / "proj", STG_ONLY, {"models/schema.yml": yml})
    source, diff = dbt_diff(root)
    assert actions(diff) == {(STG, "email"): "add"}

    result = apply_writeback(diff, source, confirm=True)
    assert not result.failed
    written = yaml.safe_load((root / "models/schema.yml").read_text())
    meta = written["models"][0]["columns"][1]["meta"]
    assert meta["sensiflow"]["propagated"] is True
    assert meta["pii"] is True

    _, rediff = dbt_diff(root)
    assert rediff.pending == []


@pytest.mark.parametrize("marker", ["true", "{propagated: 'yes'}"])
def test_malformed_dbt_marker_next_to_human_pii_leaves_the_file_untouched(
    tmp_path: Path, marker: str
) -> None:
    yml = BASE_YML + (
        f"      - name: email\n        meta:\n          pii: true\n          sensiflow: {marker}\n"
    )
    root = make_project(tmp_path / "proj", STG_ONLY, {"models/schema.yml": yml})
    before = (root / "models/schema.yml").read_bytes()
    source, diff = dbt_diff(root)
    assert actions(diff) == {(STG, "email"): "manual"}
    apply_writeback(diff, source, confirm=True)
    assert (root / "models/schema.yml").read_bytes() == before


# --- dbt: shared files, traversal, flow style ----------------------------------------------------


def test_two_models_sharing_one_properties_file_get_one_atomic_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    models = {
        "stg_people": ("SELECT person_key, email FROM raw_people", [SRC], "models/schema.yml"),
        "side_people": ("SELECT phone FROM raw_people", [SRC], "models/schema.yml"),
    }
    yml = BASE_YML + "  # side model\n  - name: side_people\n"
    root = make_project(tmp_path / "proj", models, {"models/schema.yml": yml})
    replaced: list[str] = []
    real_replace = os.replace

    def counting(src: str | Path, dst: str | Path) -> None:
        replaced.append(str(dst))
        real_replace(src, dst)

    monkeypatch.setattr("sensiflow.sources.dbt.os.replace", counting)
    source, diff = dbt_diff(root)
    result = apply_writeback(diff, source, confirm=True)

    assert {c.node_id for c in result.applied} == {STG, SIDE}
    assert len(replaced) == 1
    text = (root / "models/schema.yml").read_text()
    assert "# side model" in text
    document = yaml.safe_load(text)
    entries = {m["name"]: m for m in document["models"]}
    assert [c["name"] for c in entries["side_people"]["columns"]] == ["phone"]
    assert [c["name"] for c in entries["stg_people"]["columns"]] == ["person_key", "email"]


def test_symlinked_properties_file_pointing_outside_the_project_is_never_written(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "elsewhere" / "schema.yml"
    outside.parent.mkdir()
    outside.write_text(BASE_YML)
    root = make_project(tmp_path / "proj", STG_ONLY, {})
    (root / "models").mkdir()
    (root / "models" / "schema.yml").symlink_to(outside)

    source, diff = dbt_diff(root)
    assert set(actions(diff).values()) == {"unmatched"}
    assert "outside the project directory" in diff.changes[0].detail

    forged = TagChange(STG, "stg_people", "email", PiiTag("email"), "MEDIUM", 0.9, SRC)
    result = source.write_changes([forged])
    assert result.applied == []
    assert outside.read_text() == BASE_YML


def test_symlinked_models_directory_pointing_outside_is_unmatched(tmp_path: Path) -> None:
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "schema.yml").write_text(BASE_YML)
    root = make_project(tmp_path / "proj", STG_ONLY, {})
    (root / "models").symlink_to(outside, target_is_directory=True)
    _, diff = dbt_diff(root)
    assert set(actions(diff).values()) == {"unmatched"}


@pytest.mark.parametrize("patch", ["/etc/hosts", "../../../etc/hosts", "models/../../x.yml"])
def test_patch_path_without_package_prefix_cannot_escape(tmp_path: Path, patch: str) -> None:
    root = make_project(tmp_path / "proj", STG_ONLY, {"models/schema.yml": BASE_YML})
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["nodes"][STG]["patch_path"] = patch  # no "<pkg>://" prefix at all
    (root / "manifest.json").write_text(json.dumps(manifest))
    _, diff = dbt_diff(root)
    assert set(actions(diff).values()) == {"unmatched"}


def test_flow_style_columns_stay_valid_yaml_and_converge(tmp_path: Path) -> None:
    yml = (
        "version: 2\nmodels:\n  - name: stg_people\n"
        "    columns: [{name: person_key, description: key}, {name: email}]\n"
    )
    root = make_project(tmp_path / "proj", STG_ONLY, {"models/schema.yml": yml})
    source, diff = dbt_diff(root)
    assert not apply_writeback(diff, source, confirm=True).failed

    document = yaml.safe_load((root / "models/schema.yml").read_text())
    columns = document["models"][0]["columns"]
    assert columns[0] == {"name": "person_key", "description": "key"}
    assert columns[1]["meta"]["sensiflow"]["propagated"] is True
    _, rediff = dbt_diff(root)
    assert rediff.pending == []


# --- dbt: crash mid-apply, multi-level convergence, threshold interplay --------------------------


class _SimulatedCrash(BaseException):
    """Stands in for a SIGKILL / power loss between two file writes."""


def test_crash_between_file_writes_then_rerun_converges(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    models = {
        "stg_people": ("SELECT person_key, email FROM raw_people", [SRC], "models/a.yml"),
        "side_people": ("SELECT phone FROM raw_people", [SRC], "models/b.yml"),
    }
    files = {
        "models/a.yml": BASE_YML,
        "models/b.yml": "version: 2\nmodels:\n  - name: side_people\n",
    }
    root = make_project(tmp_path / "proj", models, files)
    real_replace = os.replace
    calls: list[str] = []

    def crash_on_second(src: str | Path, dst: str | Path) -> None:
        calls.append(str(dst))
        if len(calls) == 2:
            raise _SimulatedCrash
        real_replace(src, dst)

    monkeypatch.setattr("sensiflow.sources.dbt.os.replace", crash_on_second)
    source, diff = dbt_diff(root)
    with pytest.raises(_SimulatedCrash):
        apply_writeback(diff, source, confirm=True)
    monkeypatch.setattr("sensiflow.sources.dbt.os.replace", real_replace)

    # Exactly one file landed, the other is byte-identical, no temp file leaked.
    written = [
        p for p in (root / "models/a.yml", root / "models/b.yml") if "sensiflow" in p.read_text()
    ]
    assert len(written) == 1
    assert not list((root / "models").glob(".*.tmp"))

    source, rediff = dbt_diff(root)
    assert len(rediff.pending) == 1
    assert {c.action for c in rediff.changes} == {"add", "unchanged"}
    assert not apply_writeback(rediff, source, confirm=True).failed
    _, final = dbt_diff(root)
    assert final.pending == []


CHAIN = {
    "stg_people": ("SELECT person_key, email FROM raw_people", [SRC], "models/schema.yml"),
    "wide_people": ("SELECT * FROM stg_people", [STG], "models/schema.yml"),
    "wider_people": ("SELECT * FROM wide_people", [WIDE], "models/schema.yml"),
}
CHAIN_YML = BASE_YML + "  - name: wide_people\n  - name: wider_people\n"


@pytest.mark.parametrize("min_confidence", [0.0, 0.5, 0.65])
def test_multi_level_chain_converges_on_disk_under_min_confidence(
    tmp_path: Path, min_confidence: float
) -> None:
    # A propagated tag's node feeds another node, which feeds a third: after
    # `dbt parse` picks the markers up, nothing re-seeds and nothing is pending.
    root = make_project(tmp_path / "proj", CHAIN, {"models/schema.yml": CHAIN_YML})
    source = DbtSource(root / "manifest.json", root)
    before = trace(source.build_graph())
    plan = plan_writeback(before, min_risk="LOW", min_confidence=min_confidence)
    assert plan.changes  # something is written at every threshold here
    assert not apply_writeback(diff_writeback(plan, source), source, confirm=True).failed

    regenerate_manifest(root)
    source = DbtSource(root / "manifest.json", root)
    after = trace(source.build_graph())
    assert after == before
    replan = plan_writeback(after, min_risk="LOW", min_confidence=min_confidence)
    rediff = diff_writeback(replan, source)
    assert rediff.pending == []
    assert {c.column for c in replan.suppressed} == {c.column for c in plan.suppressed}

    # Lowering the threshold later adds exactly the previously suppressed findings.
    lowered = diff_writeback(plan_writeback(after, min_risk="LOW"), source)
    assert {(c.node_id, c.column) for c in lowered.pending} == {
        (c.node_id, c.column) for c in plan.suppressed
    }


def test_partial_apply_then_rerun_converges_without_touching_applied_files(
    tmp_path: Path,
) -> None:
    models = {
        "stg_people": ("SELECT person_key, email FROM raw_people", [SRC], "models/a.yml"),
        "side_people": ("SELECT phone FROM raw_people", [SRC], "models/b.yml"),
    }
    files = {
        "models/a.yml": BASE_YML,
        "models/b.yml": "version: 2\nmodels:\n  - name: side_people\n",
    }
    root = make_project(tmp_path / "proj", models, files)
    source, diff = dbt_diff(root)
    only_stg = WritebackDiff(diff.plan, [c for c in diff.changes if c.node_id == STG])
    assert not apply_writeback(only_stg, source, confirm=True).failed
    a_after_first = (root / "models/a.yml").read_bytes()

    source, rediff = dbt_diff(root)
    assert actions(rediff) == {(STG, "email"): "unchanged", (SIDE, "phone"): "add"}
    assert not apply_writeback(rediff, source, confirm=True).failed
    assert (root / "models/a.yml").read_bytes() == a_after_first


# --- empty plan, stale scoping (CLI) -------------------------------------------------------------


def test_empty_plan_apply_yes_is_exit_zero_and_touches_no_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root = make_project(tmp_path / "proj", STG_ONLY, {"models/schema.yml": BASE_YML})
    path = root / "models/schema.yml"
    before = (path.read_bytes(), path.stat().st_mtime_ns, sorted(os.listdir(path.parent)))
    argv = [
        "propagate", "--source", "dbt", "--dbt-manifest", str(root / "manifest.json"),
        "--dbt-project-dir", str(root), "--min-risk", "HIGH", "--apply", "--yes",
        "--format", "json",
    ]  # fmt: skip
    assert main(argv) == 0
    document = json.loads(capsys.readouterr().out)
    assert document["mode"] == "apply"
    assert document["changes"] == []
    assert document["applied"] == {"applied": [], "skipped": [], "failed": []}
    assert (path.read_bytes(), path.stat().st_mtime_ns, sorted(os.listdir(path.parent))) == before


def test_stale_detection_is_scoped_to_the_traced_subgraph_via_cli(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # side_people carries managed markup no finding supports; it is stale only
    # when traced. Rooting the run at stg_people (no downstream) must neither
    # report it nor touch it.
    models = {
        **STG_ONLY,
        "side_people": ("SELECT person_key FROM raw_people", [SRC], "models/schema.yml"),
    }
    managed = (
        "  - name: side_people\n    columns:\n      - name: legacy_col\n        meta:\n"
        "          pii: true\n          sensiflow: {propagated: true, risk: LOW,"
        " confidence: 0.5, origin: gone}\n"
    )
    root = make_project(tmp_path / "proj", models, {"models/schema.yml": BASE_YML + managed})
    base = [
        "propagate", "--source", "dbt", "--dbt-manifest", str(root / "manifest.json"),
        "--dbt-project-dir", str(root), "--min-risk", "LOW", "--format", "json",
    ]  # fmt: skip

    assert main([*base, "--root", "stg_people", "--downstream-depth", "0"]) == 0
    scoped = json.loads(capsys.readouterr().out)
    assert [(c["node_id"], c["column"], c["action"]) for c in scoped["changes"]] == [
        (STG, "email", "add")
    ]
    assert scoped["summary"]["stale"] == 0

    assert main(base) == 0
    full = json.loads(capsys.readouterr().out)
    stale = [c for c in full["changes"] if c["action"] == "stale"]
    assert [(c["node_id"], c["column"]) for c in stale] == [(SIDE, "legacy_col")]


# --- defects found in review (fixed in the ADR-0006 fix round; BOM stays pinned) ----------------


def test_dbt_human_not_pii_contradicts_a_non_sensitive_derivation(tmp_path: Path) -> None:
    yml = BASE_YML + "      - name: email\n        meta:\n          pii: false\n"
    root = make_project(tmp_path / "proj", STG_ONLY, {"models/schema.yml": yml})
    source = DbtSource(root / "manifest.json", root)
    diff = diff_writeback(_plan_for(STG, sensitive=False), source)
    assert diff.changes[0].action == "conflict"


def test_dbt_managed_category_drift_is_an_update(tmp_path: Path) -> None:
    models = {"stg_people": ("SELECT email AS contact FROM raw_people", [SRC], "models/schema.yml")}
    root = make_project(tmp_path / "proj", models, {"models/schema.yml": BASE_YML})
    source, diff = dbt_diff(root)
    assert not apply_writeback(diff, source, confirm=True).failed

    # The model now aliases a different PII column into the same output name:
    # same origin node, same risk, same confidence — only the category moved.
    set_sql(root, STG, "SELECT phone AS contact FROM raw_people")
    _, rediff = dbt_diff(root)
    change = rediff.changes[0]
    assert change.tag.category == "phone"
    assert change.action == "update"


def test_dbt_apply_preserves_crlf_line_endings(tmp_path: Path) -> None:
    crlf = BASE_YML.replace("\n", "\r\n").encode()
    root = make_project(tmp_path / "proj", STG_ONLY, {"models/schema.yml": crlf})
    source, diff = dbt_diff(root)
    assert not apply_writeback(diff, source, confirm=True).failed
    data = (root / "models/schema.yml").read_bytes()
    assert data.startswith(crlf.rstrip(b"\r\n"))
    assert b"\n" not in data.replace(b"\r\n", b"")


def test_dbt_apply_keeps_a_header_comment_above_the_document_start(tmp_path: Path) -> None:
    header = "# yaml-language-server: $schema=https://schemas.example.test/dbt.json\n---\n"
    root = make_project(tmp_path / "proj", STG_ONLY, {"models/schema.yml": header + BASE_YML})
    source, diff = dbt_diff(root)
    assert not apply_writeback(diff, source, confirm=True).failed
    assert (root / "models/schema.yml").read_text().startswith(header)


@pytest.mark.xfail(
    strict=True,
    reason="QA defect (minor): a UTF-8 BOM before '---' defeats explicit-start detection; "
    "both the BOM and the '---' are dropped on edit",
)
def test_dbt_apply_keeps_bom_and_document_start(tmp_path: Path) -> None:
    content = ("﻿---\n" + BASE_YML).encode("utf-8")
    root = make_project(tmp_path / "proj", STG_ONLY, {"models/schema.yml": content})
    source, diff = dbt_diff(root)
    assert not apply_writeback(diff, source, confirm=True).failed
    assert (root / "models/schema.yml").read_bytes().startswith("﻿---\n".encode())


def test_dbt_join_only_high_is_not_written_as_a_column(tmp_path: Path) -> None:
    models = {
        **STG_ONLY,
        "int_order_matches": (
            "SELECT o.order_key FROM orders o JOIN stg_people s ON o.email = s.email",
            [STG],
            "models/schema.yml",
        ),
    }
    yml = BASE_YML + "  - name: int_order_matches\n    columns:\n      - name: order_key\n"
    root = make_project(tmp_path / "proj", models, {"models/schema.yml": yml})
    _, diff = dbt_diff(root, min_risk="HIGH")
    joined = [c for c in diff.changes if c.node_id == JOINED]
    assert [(c.column, c.risk) for c in joined] == [("email", "HIGH")]
    assert joined[0].action == "unmatched"


def test_dbt_human_markup_appearing_after_the_diff_is_not_claimed(tmp_path: Path) -> None:
    root = make_project(
        tmp_path / "proj", STG_ONLY, {"models/schema.yml": BASE_YML + "      - name: email\n"}
    )
    source, diff = dbt_diff(root)
    assert actions(diff) == {(STG, "email"): "add"}
    path = root / "models/schema.yml"
    path.write_text(path.read_text() + "        meta:\n          pii: false\n")  # a human, now

    apply_writeback(diff, source, confirm=True)
    meta = yaml.safe_load(path.read_text())["models"][0]["columns"][1]["meta"]
    assert "sensiflow" not in meta
    assert meta == {"pii": False}


def test_dbt_nameless_column_entry_does_not_crash_the_diff(tmp_path: Path) -> None:
    yml = BASE_YML + "      - description: orphan\n        meta: {pii: true}\n"
    root = make_project(tmp_path / "proj", STG_ONLY, {"models/schema.yml": yml})
    _, diff = dbt_diff(root)
    assert (STG, "email") in actions(diff)


def test_dbt_duplicate_column_entries_converge(tmp_path: Path) -> None:
    stale_block = (
        "      - name: email\n        meta:\n          pii: true\n          pii_category: email\n"
        "          sensiflow: {propagated: true, risk: LOW, confidence: 0.1, origin: old}\n"
    )
    yml = BASE_YML + "      - name: email\n" + stale_block
    root = make_project(tmp_path / "proj", STG_ONLY, {"models/schema.yml": yml})
    source, diff = dbt_diff(root)
    assert not apply_writeback(diff, source, confirm=True).failed
    _, rediff = dbt_diff(root)
    assert rediff.pending == []


@pytest.mark.parametrize("column", ["on", "yes"])
def test_dbt_added_column_name_survives_a_yaml_1_1_reader(tmp_path: Path, column: str) -> None:
    models = {
        "stg_people": (f"SELECT email AS {column} FROM raw_people", [SRC], "models/schema.yml")
    }
    root = make_project(tmp_path / "proj", models, {"models/schema.yml": BASE_YML})
    source, diff = dbt_diff(root)
    assert not apply_writeback(diff, source, confirm=True).failed
    columns = yaml.safe_load((root / "models/schema.yml").read_text())["models"][0]["columns"]
    assert [c["name"] for c in columns] == ["person_key", column]


def test_dbt_unmatched_snippet_quotes_yaml_significant_names(tmp_path: Path) -> None:
    models = {"stg_people": ("SELECT email AS on FROM raw_people", [SRC], None)}
    root = make_project(tmp_path / "proj", models, {})
    _, diff = dbt_diff(root)
    snippet = diff.changes[0].detail.split("add manually:\n", 1)[1]
    assert yaml.safe_load(snippet)["models"][0]["columns"][0]["name"] == "on"


def test_dbt_marker_only_column_reads_as_managed_today(tmp_path: Path) -> None:
    # Characterization, not endorsement: a dbt marker block whose native `pii`
    # key was deleted reads as managed/unchanged, so the native markup is never
    # restored; OMD in the same state (marker, no PII label) re-adds the label.
    # Reported as a cross-connector inconsistency for the architect.
    yml = BASE_YML + (
        "      - name: email\n        meta:\n          sensiflow: {propagated: true, risk: MEDIUM,"
        " confidence: 0.9, origin: origin.node}\n"
    )
    root = make_project(tmp_path / "proj", STG_ONLY, {"models/schema.yml": yml})
    source = DbtSource(root / "manifest.json", root)
    assert diff_writeback(_plan_for(STG, True), source).changes[0].action == "unchanged"
    assert _omd_action([label(MARKER)], True) == "add"


def test_omd_existing_tag_carries_no_provenance_so_only_sensitivity_drives_update() -> None:
    # (b) in the brief: OMD leaves risk/confidence/origin None; a managed tag
    # must never flap to 'update' because of None-vs-value comparisons.
    omd = FakeOmd()
    omd.column(OMD_STG, "email")["tags"] = [label("PII.Sensitive"), label(MARKER)]
    markup = omd.source().read_markup([OMD_STG])[(OMD_STG, "email")]
    assert markup == ExistingTag(sensitive=True, managed=True)
    provenances: list[tuple[Risk, float, str]] = [
        ("LOW", 0.0, ""),
        ("HIGH", 1.0, "x.y.z"),
        ("MEDIUM", 0.12345, "o"),
    ]
    for risk, conf, origin in provenances:
        change = TagChange(OMD_STG, "stg", "email", PiiTag("email"), risk, conf, origin)
        plan = TagPlan("LOW", 0.0, [change], [], traced_nodes={OMD_STG: "stg"})
        assert diff_writeback(plan, omd.source()).changes[0].action == "unchanged"


def test_omd_update_replaces_the_managed_slot_and_spares_a_human_label_before_it() -> None:
    # ADR-0006 A1: the replace targets the Automated+Suggested label's own slot,
    # never "the first PII.* label" (which here is a human's).
    omd = FakeOmd()
    human = label("PII.Sensitive") | {"labelType": "Manual", "state": "Confirmed"}
    managed = label("PII.NonSensitive")
    omd.column(OMD_STG, "email")["tags"] = [human, managed, label(MARKER)]
    source = omd.source()
    plan = _plan_for(OMD_STG, sensitive=True)
    diff = diff_writeback(plan, source)
    assert diff.changes[0].action == "update"
    assert not apply_writeback(diff, source, confirm=True).failed
    tags = omd.column(OMD_STG, "email")["tags"]
    assert tags[0] == human
    assert tags[1]["tagFQN"] == "PII.Sensitive"
    assert diff_writeback(plan, source).pending == []

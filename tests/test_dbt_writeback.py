"""dbt write-back tests: properties-YAML round trips on a synthetic project.

tests/fixtures/dbt_project/ is a small clean-room dbt project whose YAML is
laid out with fidelity traps (comments, quoting styles, an anchor, flow
sequences, a block scalar, blank lines between models). Each test works on a
private copy under tmp_path. The manifest in the fixture is deliberately
stale against the YAML in places (human markup the manifest does not know),
which is what proves the YAML files, not the manifest, are the diff baseline.
"""

from __future__ import annotations

import difflib
import json
import os
import shutil
from pathlib import Path
from typing import Any

import pytest
import yaml

from sensiflow import (
    ApplyResult,
    ExistingTag,
    PiiTag,
    SensiflowDependencyError,
    SensiflowInputError,
    TagChange,
    WritebackDiff,
    apply_writeback,
    diff_writeback,
    plan_writeback,
    trace,
)
from sensiflow.cli import main
from sensiflow.sources import _dbt_yaml
from sensiflow.sources._dbt_yaml import PropertiesFile, detect_indent
from sensiflow.sources.dbt import DbtSource, _declared_pii

FIXTURE = Path(__file__).parent / "fixtures" / "dbt_project"
P = "demo_shop"
RAW = f"source.{P}.crm.raw_customers"
STG = f"model.{P}.stg_customers"
DIM = f"model.{P}.dim_customers"
DUMP = f"model.{P}.mart_customer_dump"
UNDOC = f"model.{P}.mart_undocumented"
PKG = "model.vendor_pkg.pkg_model"
STAGING_YML = "models/staging/schema.yml"
MARTS_YML = "models/marts/schema.yml"


@pytest.fixture
def project(tmp_path: Path) -> Path:
    target = tmp_path / "proj"
    shutil.copytree(FIXTURE, target)
    return target


def make_source(project: Path) -> DbtSource:
    return DbtSource(project / "manifest.json", project)


def run_diff(project: Path, min_risk: str = "LOW") -> tuple[DbtSource, WritebackDiff]:
    source = make_source(project)
    plan = plan_writeback(trace(source.build_graph()), min_risk=min_risk)  # type: ignore[arg-type]
    return source, diff_writeback(plan, source)


def actions(diff: WritebackDiff) -> dict[tuple[str, str], str]:
    return {(c.node_id, c.column): c.action for c in diff.changes}


def regenerate_manifest(project: Path) -> None:
    """Simulate `dbt parse`: refresh each model's column meta from the YAML files."""
    path = project / "manifest.json"
    manifest = json.loads(path.read_text())
    by_name = {n["name"]: n for n in manifest["nodes"].values()}
    for yml in (project / "models").rglob("*.yml"):
        for entry in (yaml.safe_load(yml.read_text()) or {}).get("models", []):
            node = by_name.get(entry["name"])
            if node is not None:
                node["columns"] = {
                    c["name"]: {
                        "name": c["name"],
                        "meta": c.get("meta") or {},
                        "tags": c.get("tags") or [],
                    }
                    for c in entry.get("columns") or []
                }
    path.write_text(json.dumps(manifest))


def removed_lines(before: str, after: str) -> list[str]:
    return [
        line[1:]
        for line in difflib.unified_diff(before.splitlines(), after.splitlines(), lineterm="", n=0)
        if line.startswith("-") and not line.startswith("---")
    ]


# --- diff against the YAML files -----------------------------------------------------------------


def test_dry_run_classifies_every_case_and_writes_nothing(project: Path) -> None:
    before = {p: p.read_bytes() for p in project.rglob("*") if p.is_file()}
    _, diff = run_diff(project)

    assert actions(diff) == {
        (STG, "email"): "add",
        (STG, "phone"): "add",
        (STG, "full_name"): "add",
        (DIM, "email"): "update",  # managed, provenance drifted
        (DIM, "full_name"): "add",  # column entry does not exist yet
        (DUMP, "email"): "conflict",  # human says not sensitive; manifest is stale about it
        (DUMP, "full_name"): "manual",  # human pii: true agrees
        (UNDOC, "email"): "unmatched",
        (PKG, "email"): "unmatched",
    }
    assert {p: p.read_bytes() for p in project.rglob("*") if p.is_file()} == before


def test_conflict_detail_names_the_human_tag_and_yaml_wins_over_a_stale_manifest(
    project: Path,
) -> None:
    source, diff = run_diff(project)
    manifest = json.loads((project / "manifest.json").read_text())
    assert manifest["nodes"][DUMP]["columns"] == {}  # the manifest knows nothing

    conflict = next(c for c in diff.changes if c.action == "conflict")
    assert "human-placed pii tag (non-sensitive)" in conflict.detail
    markup = source.read_markup([DUMP])
    assert markup[(DUMP, "email")] == ExistingTag(PiiTag("pii", sensitive=False), managed=False)
    assert markup[(DUMP, "full_name")].managed is False


def test_read_markup_returns_provenance_of_managed_columns(project: Path) -> None:
    markup = make_source(project).read_markup([DIM])
    assert markup[(DIM, "email")] == ExistingTag(
        PiiTag("email", sensitive=True),
        managed=True,
        risk="LOW",
        confidence=0.1,
        origin="old.origin",
    )
    assert (DIM, "segment") not in markup


def test_unmatched_carries_a_ready_to_paste_snippet(project: Path) -> None:
    _, diff = run_diff(project)
    by_node = {c.node_id: c for c in diff.changes if c.action == "unmatched"}
    assert "no properties-file entry" in by_node[UNDOC].detail
    assert "installed package 'vendor_pkg'" in by_node[PKG].detail

    snippet = by_node[UNDOC].detail.split("add manually:\n", 1)[1]
    parsed = yaml.safe_load(snippet)
    column = parsed["models"][0]["columns"][0]
    assert parsed["models"][0]["name"] == "mart_undocumented"
    assert column["name"] == "email"
    assert column["meta"]["pii"] is True
    assert column["meta"]["sensiflow"]["propagated"] is True
    assert column["meta"]["sensiflow"]["origin"] == RAW


def test_model_entry_missing_from_the_file_is_unmatched(project: Path) -> None:
    marts = project / MARTS_YML
    marts.write_text(marts.read_text().replace("name: mart_customer_dump", "name: renamed_dump"))
    _, diff = run_diff(project)
    unmatched = next(c for c in diff.changes if c.node_id == DUMP)
    assert unmatched.action == "unmatched"
    assert "no entry for the model in schema.yml" in unmatched.detail


@pytest.mark.parametrize("patch_path", ["demo_shop://../outside.yml", "demo_shop:///etc/hosts"])
def test_patch_path_escaping_the_project_is_unmatched(project: Path, patch_path: str) -> None:
    manifest = json.loads((project / "manifest.json").read_text())
    manifest["nodes"][STG]["patch_path"] = patch_path
    (project / "manifest.json").write_text(json.dumps(manifest))
    _, diff = run_diff(project)
    stg = [c for c in diff.changes if c.node_id == STG]
    assert {c.action for c in stg} == {"unmatched"}
    assert "outside the project directory" in stg[0].detail


def test_missing_properties_file_is_unmatched(project: Path) -> None:
    (project / STAGING_YML).unlink()
    _, diff = run_diff(project)
    assert {c.action for c in diff.changes if c.node_id == STG} == {"unmatched"}


def test_project_name_falls_back_to_dbt_project_yml(project: Path) -> None:
    manifest = json.loads((project / "manifest.json").read_text())
    del manifest["metadata"]
    (project / "manifest.json").write_text(json.dumps(manifest))
    _, diff = run_diff(project)
    assert actions(diff)[(STG, "email")] == "add"

    (project / "dbt_project.yml").unlink()
    with pytest.raises(SensiflowInputError, match="root dbt project name"):
        make_source(project).read_markup([STG])


# --- applying: round-trip fidelity ---------------------------------------------------------------


def test_apply_is_additive_in_staging_and_keeps_comments_quotes_and_anchor(project: Path) -> None:
    staging = project / STAGING_YML
    before = staging.read_text()
    source, diff = run_diff(project)
    result = apply_writeback(diff, source, confirm=True)
    assert not result.failed
    after = staging.read_text()

    assert removed_lines(before, after) == []  # pure insertions: nothing else moved
    for kept in (
        "# Staging models -- owned by the data platform team",
        'description: "Staged customers: one row per customer"   # keep the quotes',
        "description: 'Primary key'",
        "description: Customer email   # documented by hand",
        "tests: [not_null]",
        "      # phone is optional",
        "      - &phone_col",
        "# end of staging file",
    ):
        assert kept in after
    # blank line before the next model stays attached to the end of this one
    assert "origin: source.demo_shop.crm.raw_customers\n\n  - name: stg_unrelated" in after

    parsed = yaml.safe_load(after)
    columns = {c["name"]: c for c in parsed["models"][0]["columns"]}
    meta = columns["email"]["meta"]
    assert meta == {
        "pii": True,
        "pii_category": "email",
        "pii_sensitive": True,
        "sensiflow": {
            "propagated": True,
            "risk": "MEDIUM",
            "confidence": 0.9,
            "origin": RAW,
        },
    }
    assert columns["customer_id"].get("meta") is None  # untouched column


def test_apply_updates_managed_block_in_place_and_adds_missing_column_entry(
    project: Path,
) -> None:
    marts = project / MARTS_YML
    before = marts.read_text()
    source, diff = run_diff(project)
    apply_writeback(diff, source, confirm=True)
    after = marts.read_text()

    assert sorted(removed_lines(before, after)) == sorted(
        ["            risk: LOW", "            confidence: 0.1", "            origin: old.origin"]
    )
    assert (
        "sensiflow:   # written by a previous run" in after
    )  # comment on the owned block survives
    assert "owner: analytics" in after  # foreign meta keys survive
    parsed = yaml.safe_load(after)
    dim = {c["name"]: c for c in parsed["models"][0]["columns"]}
    assert dim["email"]["meta"]["sensiflow"]["confidence"] == 0.81
    assert dim["email"]["meta"]["sensiflow"]["risk"] == "MEDIUM"
    assert list(dim) == ["customer_id", "email", "segment", "full_name"]  # appended, not reordered
    assert dim["full_name"]["meta"]["pii_category"] == "name"
    assert "\n\n  - name: mart_customer_dump" in after  # blank line still separates the models


def test_human_markup_is_never_touched(project: Path) -> None:
    marts = project / MARTS_YML
    human_block = marts.read_text().split("  - name: mart_customer_dump")[1]
    source, diff = run_diff(project)
    apply_writeback(diff, source, confirm=True)
    assert marts.read_text().split("  - name: mart_customer_dump")[1] == human_block


def test_no_unmatched_node_gets_a_file_or_a_model_block(project: Path) -> None:
    files_before = {p for p in project.rglob("*") if p.is_file()}
    source, diff = run_diff(project)
    apply_writeback(diff, source, confirm=True)
    assert {p for p in project.rglob("*") if p.is_file()} == files_before  # no temp leftovers
    assert "mart_undocumented" not in (project / MARTS_YML).read_text()


def test_native_keys_are_only_written_when_absent(project: Path) -> None:
    staging = project / STAGING_YML
    text = staging.read_text().replace(
        "        tests: [not_null]\n",
        "        tests: [not_null]\n        meta:\n          pii_category: contact\n",
    )
    staging.write_text(text)
    source, diff = run_diff(project)
    apply_writeback(diff, source, confirm=True)
    meta = yaml.safe_load(staging.read_text())["models"][0]["columns"][1]["meta"]
    assert meta["pii_category"] == "contact"  # the human's native key is kept
    assert meta["pii"] is True  # the absent ones are filled in
    assert meta["sensiflow"]["propagated"] is True


def test_existing_column_is_matched_case_insensitively_without_duplicating(project: Path) -> None:
    staging = project / STAGING_YML
    staging.write_text(staging.read_text().replace("- name: email", "- name: Email"))
    source, diff = run_diff(project)
    apply_writeback(diff, source, confirm=True)
    names = [c["name"] for c in yaml.safe_load(staging.read_text())["models"][0]["columns"]]
    assert names == ["customer_id", "Email", "phone", "full_name"]


def test_model_without_a_columns_key_gets_one_and_keeps_the_blank_line() -> None:
    properties = PropertiesFile(
        "models:\n  - name: bare_model\n    description: no columns yet\n\n  - name: other\n"
    )
    properties.add_column(properties.find_entry("models", "bare_model"), "email")
    rendered = properties.render()
    assert "    description: no columns yet\n    columns:\n      - name: email\n" in rendered
    assert "\n\n  - name: other" in rendered


def test_a_null_meta_on_the_column_is_replaced(project: Path) -> None:
    staging = project / STAGING_YML
    staging.write_text(
        staging.read_text().replace(
            "        tests: [not_null]\n", "        tests: [not_null]\n        meta:\n"
        )
    )
    source, diff = run_diff(project)
    assert not apply_writeback(diff, source, confirm=True).failed
    columns = yaml.safe_load(staging.read_text())["models"][0]["columns"]
    assert columns[1]["meta"]["sensiflow"]["propagated"] is True


def test_explicit_document_start_and_zero_offset_style_are_preserved() -> None:
    text = "---\nversion: 2\nmodels:\n- name: m\n  columns:\n  - name: a\n  # tail comment\n"
    properties = PropertiesFile(text)
    column = properties.add_column(properties.find_entry("models", "m"), "b")
    rendered = properties.render()
    assert rendered.startswith("---\n")
    assert "\n- name: m\n  columns:\n  - name: a\n  - name: b" in rendered
    assert column["name"] == "b"
    assert rendered.rstrip().endswith("# tail comment")


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("models:\n  - name: a\n    columns:\n      - name: b\n", (2, 4, 2)),
        ("models:\n- name: a\n  columns:\n  - name: b\n", (2, 2, 0)),
        (
            "models:\n    - name: a\n      meta:\n          k: v\n      columns:\n"
            "          - name: b\n",
            (4, 6, 4),
        ),
        ("# only a comment\n", (2, 4, 2)),
        ("", (2, 4, 2)),
    ],
)
def test_detect_indent(text: str, expected: tuple[int, int, int]) -> None:
    assert detect_indent(text) == expected


def test_unused_anchor_survives_a_dump() -> None:
    text = "models:\n  - name: m\n    columns:\n      - &unused\n        name: a\n"
    assert "&unused" in PropertiesFile(text).render()


def test_aliases_survive_an_edit() -> None:
    text = (
        "models:\n  - name: m\n    meta: &shared\n      team: data\n    columns:\n"
        "      - name: a\n  - name: n\n    meta: *shared\n"
    )
    properties = PropertiesFile(text)
    properties.add_column(properties.find_entry("models", "m"), "b")
    rendered = properties.render()
    assert "meta: &shared" in rendered
    assert "meta: *shared" in rendered


# --- apply: failure isolation --------------------------------------------------------------------


def test_failed_atomic_replace_fails_only_that_file_and_leaves_it_intact(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staging = project / STAGING_YML
    original = staging.read_bytes()
    real_replace = os.replace

    def flaky(src: str | Path, dst: str | Path) -> None:
        if Path(dst).name == "schema.yml" and Path(dst).parent.name == "staging":
            raise OSError(28, "No space left on device")
        real_replace(src, dst)

    monkeypatch.setattr("sensiflow.sources.dbt.os.replace", flaky)
    source, diff = run_diff(project)
    result = apply_writeback(diff, source, confirm=True)

    assert {c.node_id for c, _ in result.failed} == {STG}
    assert all("cannot write schema.yml: No space left on device" in m for _, m in result.failed)
    assert {c.node_id for c in result.applied} == {DIM}
    assert staging.read_bytes() == original
    assert not list(staging.parent.glob(".*.tmp"))  # temp file cleaned up
    assert "sensiflow" in (project / MARTS_YML).read_text()  # the other file was written


def test_unparseable_file_at_write_time_fails_its_changes(project: Path) -> None:
    source, diff = run_diff(project)
    (project / STAGING_YML).write_text("models: [unclosed\n")
    result = apply_writeback(diff, source, confirm=True)
    assert {c.node_id for c, _ in result.failed} == {STG}
    assert {c.node_id for c in result.applied} == {DIM}


def test_entry_removed_between_diff_and_apply_is_skipped_and_reported(project: Path) -> None:
    source, diff = run_diff(project)
    staging = project / STAGING_YML
    staging.write_text(staging.read_text().replace("name: stg_customers", "name: stg_renamed"))
    result = apply_writeback(diff, source, confirm=True)
    assert all(
        m.startswith("skipped: entry vanished") for c, m in result.failed if c.node_id == STG
    )
    assert {c.node_id for c in result.applied} == {DIM}


def test_write_changes_for_unlocatable_nodes_reports_failure(project: Path) -> None:
    change = TagChange(UNDOC, "mart_undocumented", "email", PiiTag("email"), "MEDIUM", 0.7, RAW)
    result = make_source(project).write_changes([change])
    assert result.applied == []
    assert "cannot place" in result.failed[0][1]


def test_failed_write_in_one_file_still_converges_on_rerun(project: Path) -> None:
    source, diff = run_diff(project)
    (project / STAGING_YML).chmod(0o444)
    (project / STAGING_YML).parent.chmod(0o555)
    try:
        result = apply_writeback(diff, source, confirm=True)
    finally:
        (project / STAGING_YML).parent.chmod(0o755)
        (project / STAGING_YML).chmod(0o644)
    if os.geteuid() == 0:  # root ignores permission bits
        pytest.skip("permission bits are not enforced for root")
    assert {c.node_id for c, _ in result.failed} == {STG}
    _, rediff = run_diff(project)
    assert {c.node_id for c in rediff.pending} == {STG}


# --- convergence invariant (ADR-0006 §4) ---------------------------------------------------------


@pytest.mark.parametrize("min_risk", ["LOW", "MEDIUM"])
def test_convergence_on_disk(project: Path, min_risk: str) -> None:
    regenerate_manifest(project)  # manifest and YAML agree, as after a fresh `dbt parse`
    source = make_source(project)
    before = trace(source.build_graph())
    plan = plan_writeback(before, min_risk=min_risk)  # type: ignore[arg-type]
    result = apply_writeback(diff_writeback(plan, source), source, confirm=True)
    assert not result.failed
    assert result.applied

    regenerate_manifest(project)  # dbt parse again: the written markup is now in the manifest
    manifest = json.loads((project / "manifest.json").read_text())
    assert manifest["nodes"][STG]["columns"]["email"]["meta"]["sensiflow"]["propagated"] is True

    after = trace(make_source(project).build_graph())
    assert after == before  # marked columns did not re-seed: no ORIGIN inflation

    rediff = diff_writeback(plan_writeback(after, min_risk=min_risk), make_source(project))  # type: ignore[arg-type]
    assert rediff.pending == []

    snapshot = {p: p.read_bytes() for p in (project / "models").rglob("*.yml")}
    again = apply_writeback(rediff, make_source(project), confirm=True)
    assert again == ApplyResult(applied=[], failed=[])
    assert {p: p.read_bytes() for p in (project / "models").rglob("*.yml")} == snapshot


# --- requirements and reader-side exclusion ------------------------------------------------------


def test_write_back_requires_a_project_directory(project: Path) -> None:
    bare = DbtSource(project / "manifest.json")
    with pytest.raises(SensiflowInputError, match="--dbt-project-dir"):
        bare.read_markup([STG])
    with pytest.raises(SensiflowInputError, match="--dbt-project-dir"):
        bare.write_changes([])
    # lineage reading never needs the directory
    assert bare.build_graph().nodes


def test_missing_project_directory_is_an_input_error(project: Path) -> None:
    source = DbtSource(project / "manifest.json", project / "nope")
    with pytest.raises(SensiflowInputError, match="project directory not found"):
        source.find_unmatched([])


def test_unreadable_properties_file_is_an_input_error(project: Path) -> None:
    (project / STAGING_YML).write_bytes(b"\xff\xfe not utf-8")
    with pytest.raises(SensiflowInputError, match="cannot read properties file"):
        make_source(project).read_markup([STG])


def test_invalid_yaml_is_an_input_error_without_echoing_content(project: Path) -> None:
    (project / STAGING_YML).write_text("models: [unclosed secret-looking-value\n")
    with pytest.raises(SensiflowInputError) as excinfo:
        make_source(project).read_markup([STG])
    assert "not valid YAML" in str(excinfo.value)
    assert "secret-looking-value" not in str(excinfo.value)


def test_missing_ruamel_names_the_extra(monkeypatch: pytest.MonkeyPatch) -> None:
    def no_ruamel(name: str) -> Any:
        raise ImportError(name)

    with pytest.raises(SensiflowDependencyError, match=r"sensiflow\[dbt\]"):
        _dbt_yaml.require_ruamel(no_ruamel)


def column(**meta: Any) -> dict[str, Any]:
    return {"meta": meta}


def test_declared_pii_ignores_propagated_columns_but_reads_plain_pii() -> None:
    raw = {
        "columns": {
            "human": column(pii=True, pii_category="email"),
            "marked": column(pii=True, sensiflow={"propagated": True}),
            "marker_off": column(pii=True, sensiflow={"propagated": False}),
            "junk_marker": column(pii=True, sensiflow="yes"),
            "via_config": {
                "meta": {"pii": True},
                "config": {"meta": {"sensiflow": {"propagated": True}}},
            },
            "tagged_and_marked": {"tags": ["pii"], "meta": {"sensiflow": {"propagated": True}}},
        }
    }
    assert set(_declared_pii(raw)) == {"human", "marker_off", "junk_marker"}


@pytest.mark.parametrize(
    ("raw_column", "expected"),
    [
        ({"meta": {"pii": False}}, ExistingTag(PiiTag("pii", sensitive=False), managed=False)),
        ({"tags": ["pii:email"]}, ExistingTag(PiiTag("email"), managed=False)),
        ({"tags": ["pii"]}, ExistingTag(PiiTag("pii"), managed=False)),
        ({"meta": {"sensiflow": {"propagated": True}}}, ExistingTag(PiiTag("pii"), managed=True)),
        ({"meta": {"owner": "x"}, "tags": ["internal"]}, None),
    ],
)
def test_existing_tag_translation(raw_column: dict[str, Any], expected: ExistingTag | None) -> None:
    from sensiflow.sources.dbt import _existing_from_column

    assert _existing_from_column(raw_column) == expected


# --- CLI -----------------------------------------------------------------------------------------


def cli(project: Path, *extra: str, project_dir: Path | None = None) -> list[str]:
    return [
        "propagate", "--source", "dbt",
        "--dbt-manifest", str(project / "manifest.json"),
        "--dbt-project-dir", str(project_dir or project),
        "--min-risk", "low", *extra,
    ]  # fmt: skip


def test_cli_dry_run_reports_conflicts_with_exit_zero(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(cli(project)) == 0
    out = capsys.readouterr().out
    assert "CONFLICTS" in out
    assert "add manually:" in out
    assert "result: DRY-RUN" in out


def test_cli_dbt_without_project_dir_is_a_usage_error(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["propagate", "--source", "dbt", "--dbt-manifest", str(project / "manifest.json"),
              "--min-risk", "low"])  # fmt: skip
    assert excinfo.value.code == 2
    assert "--dbt-project-dir" in capsys.readouterr().err


def test_cli_missing_project_dir_path_is_exit_two(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(cli(project, project_dir=project / "nope"))
    assert code == 2
    assert "project directory not found" in capsys.readouterr().err


def test_cli_missing_ruamel_is_exit_three(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom() -> Any:
        raise SensiflowDependencyError("writing dbt markup requires the 'dbt' extra")

    monkeypatch.setattr(_dbt_yaml, "require_ruamel", boom)
    assert main(cli(project)) == 3
    assert "'dbt' extra" in capsys.readouterr().err


def test_cli_apply_cycle_writes_files_then_converges(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(cli(project, "--apply", "--yes")) == 0
    out = capsys.readouterr().out
    assert "result: APPLIED — 5 applied, 0 failed" in out
    assert main(cli(project, "--format", "json")) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["summary"]["add"] == 0
    assert payload["summary"]["update"] == 0
    assert payload["summary"]["unchanged"] == 5


def test_cli_apply_with_a_failed_file_is_exit_three(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def refuse(src: str | Path, dst: str | Path) -> None:
        raise OSError(13, "Permission denied")

    monkeypatch.setattr("sensiflow.sources.dbt.os.replace", refuse)
    assert main(cli(project, "--apply", "--yes")) == 3
    assert "Permission denied" in capsys.readouterr().out

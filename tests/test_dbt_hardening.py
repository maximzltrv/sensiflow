"""dbt write-back hardening (ADR-0006 A2-A7): hostile names, write allowlist, re-checks.

Every project, model and column name is synthetic. The shared fixture project
lives in tests/fixtures/dbt_project (see conftest ``project``).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from sensiflow import (
    ExistingTag,
    PiiTag,
    TagChange,
    TagPlan,
    apply_writeback,
    diff_writeback,
)
from sensiflow.cli import main
from sensiflow.sources._dbt_yaml import PropertiesFile
from sensiflow.sources.dbt import DbtSource, _yaml_snippet
from tests.support import make_source, run_diff

P = "demo_shop"
# Built with chr(): formatters and editors rewrite literal separators and bidi marks.
NEL, LS, PS, RLO = chr(0x85), chr(0x2028), chr(0x2029), chr(0x202E)
STG = f"model.{P}.stg_customers"
DIM = f"model.{P}.dim_customers"
UNDOC = f"model.{P}.mart_undocumented"
STAGING_YML = "models/staging/schema.yml"
MARTS_YML = "models/marts/schema.yml"


def change(column: str, *, node_id: str = STG, name: str = "stg_customers", **kw: Any) -> TagChange:
    return TagChange(node_id, name, column, PiiTag("email"), "MEDIUM", 0.9, "origin.node", **kw)


def plan_for(
    node_id: str, name: str, column: str, *, sensitive: bool, confidence: float = 0.9
) -> TagPlan:
    derived = TagChange(
        node_id, name, column, PiiTag("email", sensitive), "MEDIUM", confidence, "origin.node"
    )
    return TagPlan("LOW", 0.0, [derived], [], traced_nodes={node_id: name})


def set_patch_path(project: Path, node_id: str, patch_path: str) -> None:
    path = project / "manifest.json"
    manifest = json.loads(path.read_text())
    manifest["nodes"][node_id]["patch_path"] = patch_path
    path.write_text(json.dumps(manifest))


# --- snippets are serialized, never interpolated ---

NASTY_NAMES = [
    "a: b # c",
    'say "hi"',
    "back\\slash",
    "on",
    "é-ü",
    "emoji-\U0001f600",
    "- x",
    "{a: 1}",
]


@pytest.mark.parametrize("name", NASTY_NAMES)
def test_snippet_round_trips_hostile_names_as_data(name: str) -> None:
    snippet = _yaml_snippet("models", name, change(name))
    assert snippet is not None
    parsed = yaml.safe_load(snippet)
    assert parsed["models"][0]["name"] == name
    column = parsed["models"][0]["columns"][0]
    assert column["name"] == name
    assert set(column) == {"name", "meta"}  # the name could not inject keys
    assert set(column["meta"]) == {"pii", "pii_category", "pii_sensitive", "sensiflow"}
    assert column["meta"]["sensiflow"]["propagated"] is True


@pytest.mark.parametrize(
    "name", ["a\nb: injected", "a\rb", "a\x00b", "a\x85b", f"a{LS}b", f"a{PS}b", f"a{RLO}b"]
)
def test_snippet_is_refused_for_names_with_control_or_line_break_characters(name: str) -> None:
    assert _yaml_snippet("models", name, change("email")) is None
    assert _yaml_snippet("models", "m", change(name)) is None


def test_unmatched_detail_without_a_snippet_says_why(project: Path) -> None:
    detail = make_source(project).find_unmatched([change("e\nmail", node_id=UNDOC)])
    reason = detail[(UNDOC, "e\nmail")]
    assert "column or model name contains line breaks or control characters" in reason


# --- such names are never written ---


@pytest.mark.parametrize("column", ["a\nb", "a\x85b", f"a{LS}b", "a\x1bb", f"a{RLO}b"])
def test_unsafe_column_names_are_unmatched_in_the_diff_and_skipped_at_write(
    project: Path, column: str
) -> None:
    source = make_source(project)
    bad = change(column)
    assert "never written" in source.find_unmatched([bad])[(STG, column.lower())]
    before = (project / STAGING_YML).read_bytes()
    result = source.write_changes([bad])
    assert result.applied == [] and result.failed == []
    assert "never written" in result.skipped[0][1]
    assert (project / STAGING_YML).read_bytes() == before


# --- nothing absolute reaches messages ---


def _all_text(result: Any) -> str:
    return " | ".join(m for _, m in [*result.failed, *result.skipped])


def test_error_messages_carry_project_relative_paths_only(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, diff = run_diff(project)

    def refuse(src: str | Path, dst: str | Path) -> None:
        raise OSError(13, "Permission denied", str(dst))

    monkeypatch.setattr("sensiflow.sources.dbt.os.replace", refuse)
    result = apply_writeback(diff, source, confirm=True)
    text = _all_text(result)
    assert "cannot write models/" in text
    assert str(project) not in text


def test_read_errors_name_the_relative_path(project: Path) -> None:
    (project / STAGING_YML).write_text("models: [unclosed\n")
    with pytest.raises(Exception) as excinfo:
        make_source(project).read_markup([STG])
    assert "models/staging/schema.yml" in str(excinfo.value)
    assert str(project) not in str(excinfo.value)


def test_unreadable_file_at_apply_time_fails_with_a_relative_label(project: Path) -> None:
    source, diff = run_diff(project)
    (project / STAGING_YML).write_bytes(b"\xff\xfe\x00 not utf-8")
    result = apply_writeback(diff, source, confirm=True)
    assert {c.node_id for c, _ in result.failed} == {STG}
    assert str(project) not in _all_text(result)
    assert {c.node_id for c in result.applied} == {DIM}


# --- cyclic aliases do not hang the parser ---


def test_self_referencing_anchor_does_not_recurse_forever() -> None:
    text = "models:\n  - name: m\n    meta: &loop\n      self: *loop\n    columns: []\n"
    properties = PropertiesFile(text)
    assert properties.find_entry("models", "m") is not None


# --- only .yml/.yaml properties files inside the project, never dbt's own config ---


@pytest.mark.parametrize(
    ("patch_path", "reason"),
    [
        ("dbt_project.yml", "dbt configuration file"),
        ("profiles.yml", "dbt configuration file"),
        ("packages.yml", "dbt configuration file"),
        ("dependencies.yml", "dbt configuration file"),
        ("models/schema.json", "not a .yml/.yaml file"),
        ("models/schema.sql", "not a .yml/.yaml file"),
        ("target/schema.yml", "generated or VCS directory"),
        ("dbt_packages/x/schema.yml", "generated or VCS directory"),
        ("logs/schema.yml", "generated or VCS directory"),
        (".git/info/schema.yml", "generated or VCS directory"),
        ("models/target/schema.yml", "generated or VCS directory"),
    ],
)
def test_forbidden_write_targets_are_unmatched_and_untouched(
    project: Path, patch_path: str, reason: str
) -> None:
    target = project / patch_path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("models:\n  - name: stg_customers\n    columns: []\n")
    before = target.read_bytes()
    set_patch_path(project, STG, f"{P}://{patch_path}")
    source, diff = run_diff(project)
    stg = [c for c in diff.changes if c.node_id == STG]
    assert stg and {c.action for c in stg} == {"unmatched"}
    assert reason in stg[0].detail
    apply_writeback(diff, source, confirm=True)
    assert target.read_bytes() == before


@pytest.mark.parametrize("name", ["schema.YML", "schema.yaml", "schema.YAML"])
def test_yaml_suffix_matching_is_case_insensitive(project: Path, name: str) -> None:
    moved = project / "models" / "staging" / name
    (project / STAGING_YML).rename(moved)
    set_patch_path(project, STG, f"{P}://models/staging/{name}")
    _, diff = run_diff(project)
    assert {c.action for c in diff.changes if c.node_id == STG} == {"add"}


def test_a_symlink_to_a_forbidden_or_outside_file_is_not_followed(
    project: Path, tmp_path: Path
) -> None:
    outside = tmp_path / "outside.yml"
    outside.write_text("models: []\n")
    link = project / "models" / "link.yml"
    link.symlink_to(outside)
    set_patch_path(project, STG, f"{P}://models/link.yml")
    _, diff = run_diff(project)
    assert {c.action for c in diff.changes if c.node_id == STG} == {"unmatched"}
    assert outside.read_text() == "models: []\n"


# --- the result document survives any per-file failure ---


def test_value_errors_during_the_write_are_failures_not_crashes(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source, diff = run_diff(project)

    def boom(path: Path, text: str) -> None:
        raise ValueError("embedded null byte")

    monkeypatch.setattr("sensiflow.sources.dbt._atomic_write", boom)
    result = apply_writeback(diff, source, confirm=True)
    assert result.applied == []
    assert len(result.failed) == len(diff.pending)
    assert all("embedded null byte" in msg for _, msg in result.failed)


def test_cli_json_document_is_always_emitted_after_a_file_failure(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(path: Path, text: str) -> None:
        raise ValueError("embedded null byte")

    monkeypatch.setattr("sensiflow.sources.dbt._atomic_write", boom)
    argv = [
        "propagate", "--source", "dbt", "--dbt-manifest", str(project / "manifest.json"),
        "--dbt-project-dir", str(project), "--min-risk", "low", "--apply", "--yes",
        "--format", "json",
    ]  # fmt: skip
    assert main(argv) == 3
    document = json.loads(capsys.readouterr().out)
    assert document["applied"]["failed"]
    assert str(project) not in json.dumps(document)


# --- re-check against the freshly read file ---


def test_human_markup_appearing_after_the_diff_is_skipped_not_failed(project: Path) -> None:
    source, diff = run_diff(project)
    staging = project / STAGING_YML
    staging.write_text(
        staging.read_text().replace(
            "        tests: [not_null]\n", "        tests: [not_null]\n        meta: {pii: true}\n"
        )
    )
    result = apply_writeback(diff, source, confirm=True)
    assert result.failed == []
    skipped = {(c.node_id, c.column): msg for c, msg in result.skipped}
    assert skipped[(STG, "email")].startswith("skipped: re-check found manual")
    meta = yaml.safe_load(staging.read_text())["models"][0]["columns"][1]["meta"]
    assert meta == {"pii": True}
    assert {c.column for c in result.applied if c.node_id == STG} == {"phone", "full_name"}


def test_an_already_applied_change_is_skipped_as_unchanged_on_a_stale_diff(project: Path) -> None:
    source, diff = run_diff(project)
    assert not apply_writeback(diff, source, confirm=True).failed
    result = apply_writeback(diff, source, confirm=True)  # the same, now stale, diff
    assert result.applied == [] and result.failed == []
    assert all("re-check found unchanged" in msg for _, msg in result.skipped)
    assert len(result.skipped) == len(diff.pending)


def test_managed_downgrade_is_a_conflict_and_never_written(project: Path) -> None:
    yml = project / MARTS_YML
    plan = plan_for(DIM, "dim_customers", "email", sensitive=False, confidence=0.8)
    source = make_source(project)
    diff = diff_writeback(plan, source)
    assert diff.changes[0].action == "conflict"
    assert "downgrade withheld" in diff.changes[0].detail
    before = yml.read_bytes()
    apply_writeback(diff, source, confirm=True)
    assert yml.read_bytes() == before


# --- duplicates and nameless entries ---


def test_duplicate_column_entries_are_unmatched_with_a_resolve_manually_reason(
    project: Path,
) -> None:
    staging = project / STAGING_YML
    staging.write_text(
        staging.read_text().replace(
            "      - name: full_name\n", "      - name: full_name\n      - name: FULL_NAME\n"
        )
    )
    source, diff = run_diff(project)
    duplicate = next(c for c in diff.changes if c.column == "full_name" and c.node_id == STG)
    assert duplicate.action == "unmatched"
    assert "duplicate column entries" in duplicate.detail
    assert (STG, "full_name") not in source.read_markup([STG])
    before = staging.read_bytes()
    result = source.write_changes([change("full_name")])
    assert "duplicate column entries" in result.skipped[0][1]
    assert staging.read_bytes() == before


# --- line endings and headers ---


def test_crlf_files_stay_crlf_and_unrelated_lines_are_byte_identical(project: Path) -> None:
    staging = project / STAGING_YML
    original = staging.read_bytes().replace(b"\n", b"\r\n")
    staging.write_bytes(original)
    source, diff = run_diff(project)
    assert not apply_writeback(diff, source, confirm=True).failed
    data = staging.read_bytes()
    assert b"\n" not in data.replace(b"\r\n", b"")
    old_lines = original.split(b"\r\n")
    new_lines = data.split(b"\r\n")
    assert all(line in new_lines for line in old_lines)


@pytest.mark.parametrize(
    "header",
    [
        "# schema: https://example.test/dbt.json\n---\n",
        "\n\n# one\n\n# two\n---\n",
        "---\n",
        "# only a comment, no document start\n",
        "",
    ],
)
def test_headers_before_the_document_survive_an_edit(header: str) -> None:
    properties = PropertiesFile(header + "models:\n  - name: m\n    columns:\n      - name: a\n")
    properties.add_column(properties.find_entry("models", "m"), "b")
    assert properties.render().startswith(header)


def test_crlf_header_and_body_round_trip() -> None:
    text = "# c\r\n---\r\nmodels:\r\n  - name: m\r\n    columns: []\r\n"
    rendered = PropertiesFile(text).render()
    assert rendered == text


# --- YAML 1.1 ambiguity ---


@pytest.mark.parametrize(
    "word", ["on", "off", "yes", "no", "y", "n", "true", "null", "~", "1e3", "0x1f", "010"]
)
def test_ambiguous_scalars_are_force_quoted(word: str) -> None:
    properties = PropertiesFile("models: []\n")
    quoted = properties.scalar(word)
    assert quoted != word or isinstance(quoted, str)
    node = properties.new_map(name=quoted)
    properties.document["models"].append(node)
    loaded = yaml.safe_load(properties.render())
    assert loaded["models"][0]["name"] == word


@pytest.mark.parametrize("word", ["email", "full_name", "stg_customers", "x1"])
def test_ordinary_scalars_are_not_quoted(word: str) -> None:
    assert PropertiesFile("a: 1\n").scalar(word) == word


# --- the single column parser ---


def test_negative_declaration_in_the_yaml_never_seeds_even_through_the_manifest(
    project: Path,
) -> None:
    manifest_path = project / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["nodes"][STG]["columns"] = {"email": {"name": "email", "meta": {"pii": False}}}
    manifest_path.write_text(json.dumps(manifest))
    graph = DbtSource(manifest_path, project).build_graph()
    assert graph.nodes[STG].declared_pii == {}


def test_not_pii_in_the_yaml_conflicts_with_either_derivation(project: Path) -> None:
    staging = project / STAGING_YML
    staging.write_text(
        staging.read_text().replace(
            "        tests: [not_null]\n", "        tests: [not_null]\n        meta: {pii: false}\n"
        )
    )
    source = make_source(project)
    markup = source.read_markup([STG])[(STG, "email")]
    assert markup == ExistingTag(sensitive=False, managed=False, not_pii=True)
    for sensitive in (True, False):
        plan = plan_for(STG, "stg_customers", "email", sensitive=sensitive)
        assert diff_writeback(plan, source).changes[0].action == "conflict"

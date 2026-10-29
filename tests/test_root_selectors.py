"""Unit tests for the shared root-selection layer (ADR-0002 amendment).

Covers the GraphSelection validation matrix, the strict version-1 roots-file
schema, pattern resolution semantics, and the lazy PyYAML dependency guard
(monkeypatched import, same pattern as the httpx guard tests).
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from sensiflow import GraphSelection, SensiflowDependencyError, SensiflowInputError
from sensiflow.root_selectors import (
    _require_yaml,
    has_glob_chars,
    load_roots_file,
    resolve_patterns,
)

CANDIDATES = [
    ("demo.wh.crm.raw_customers", "raw_customers"),
    ("demo.wh.crm.raw_orders", "raw_orders"),
    ("demo.wh.crm.stg_customers", "stg_customers"),
    ("demo.wh.sales.dim_customers", "dim_customers"),
]


# --- GraphSelection: valid constructions ---------------------------------------


def test_defaults_mean_full_scan() -> None:
    selection = GraphSelection()
    assert selection.is_full_scan()
    assert selection.roots == () and selection.patterns == ()
    assert not selection.from_seeds
    assert selection.upstream_depth is None and selection.downstream_depth is None


def test_roots_patterns_and_depths_combine() -> None:
    selection = GraphSelection(
        roots=("demo.wh.crm.raw_customers",),
        patterns=("stg_*",),
        upstream_depth=0,
        downstream_depth=3,
    )
    assert not selection.is_full_scan()


def test_from_seeds_alone_allows_depths() -> None:
    # from_seeds is a selector, so depths have roots to measure from.
    selection = GraphSelection(from_seeds=True, upstream_depth=0)
    assert not selection.is_full_scan()


# --- GraphSelection: every violation --------------------------------------------


def test_from_seeds_excludes_roots() -> None:
    with pytest.raises(SensiflowInputError, match="mutually exclusive"):
        GraphSelection(from_seeds=True, roots=("raw_customers",))


def test_from_seeds_excludes_patterns() -> None:
    with pytest.raises(SensiflowInputError, match="mutually exclusive"):
        GraphSelection(from_seeds=True, patterns=("raw_*",))


def test_empty_root_rejected() -> None:
    with pytest.raises(SensiflowInputError, match="non-empty"):
        GraphSelection(roots=("",))


@pytest.mark.parametrize("root", ["raw_*", "raw_?", "raw_[ab]"])
def test_root_with_metacharacter_rejected(root: str) -> None:
    with pytest.raises(SensiflowInputError, match="use patterns"):
        GraphSelection(roots=(root,))


def test_empty_pattern_rejected() -> None:
    with pytest.raises(SensiflowInputError, match="non-empty"):
        GraphSelection(patterns=("",))


def test_pattern_without_metacharacter_rejected() -> None:
    with pytest.raises(SensiflowInputError, match="use roots"):
        GraphSelection(patterns=("raw_customers",))


@pytest.mark.parametrize("field", ["upstream_depth", "downstream_depth"])
def test_negative_depth_rejected(field: str) -> None:
    kwargs: dict[str, Any] = {field: -1}
    with pytest.raises(SensiflowInputError, match=">= 0"):
        GraphSelection(roots=("raw_customers",), **kwargs)


@pytest.mark.parametrize("field", ["upstream_depth", "downstream_depth"])
def test_depth_on_empty_selection_rejected(field: str) -> None:
    kwargs: dict[str, Any] = {field: 0}
    with pytest.raises(SensiflowInputError, match="depths require roots"):
        GraphSelection(**kwargs)


# --- resolve_patterns -----------------------------------------------------------


def test_pattern_matches_node_id() -> None:
    assert resolve_patterns(("demo.wh.crm.raw_*",), CANDIDATES) == [
        "demo.wh.crm.raw_customers",
        "demo.wh.crm.raw_orders",
    ]


def test_pattern_matches_bare_name() -> None:
    assert resolve_patterns(("dim_*",), CANDIDATES) == ["demo.wh.sales.dim_customers"]


def test_question_mark_and_class_metacharacters() -> None:
    assert resolve_patterns(("stg_?ustomers",), CANDIDATES) == ["demo.wh.crm.stg_customers"]
    assert resolve_patterns(("[sd]tg_customers",), CANDIDATES) == ["demo.wh.crm.stg_customers"]


def test_overlapping_patterns_deduplicate() -> None:
    resolved = resolve_patterns(("raw_*", "demo.wh.crm.*"), CANDIDATES)
    assert resolved == [
        "demo.wh.crm.raw_customers",
        "demo.wh.crm.raw_orders",
        "demo.wh.crm.stg_customers",
    ]


def test_matching_is_case_sensitive() -> None:
    with pytest.raises(SensiflowInputError, match="RAW_\\*"):
        resolve_patterns(("RAW_*",), CANDIDATES)


def test_zero_match_is_hard_error_even_among_matching_patterns() -> None:
    with pytest.raises(SensiflowInputError, match="'nothing_\\*' matched no tables"):
        resolve_patterns(("raw_*", "nothing_*"), CANDIDATES)


def test_has_glob_chars() -> None:
    assert has_glob_chars("raw_*") and has_glob_chars("x?") and has_glob_chars("[ab]")
    assert not has_glob_chars("demo.wh.crm.raw_customers")


# --- load_roots_file: happy path --------------------------------------------------


def write_roots(tmp_path: Path, content: str) -> Path:
    path = tmp_path / "roots.yaml"
    path.write_text(content)
    return path


def test_valid_file_maps_ids_and_patterns(tmp_path: Path) -> None:
    path = write_roots(
        tmp_path,
        """\
# team scoping baseline
version: 1
roots:
  - id: demo.wh.sales.orders
  - pattern: "demo.wh.crm.*"
  - pattern: "raw_*"
  - id: stg_customers
""",
    )
    selection = load_roots_file(path)
    assert selection.roots == ("demo.wh.sales.orders", "stg_customers")
    assert selection.patterns == ("demo.wh.crm.*", "raw_*")
    assert not selection.from_seeds
    assert selection.upstream_depth is None and selection.downstream_depth is None


# --- load_roots_file: every schema violation ---------------------------------------


def test_missing_file() -> None:
    with pytest.raises(SensiflowInputError, match="roots file not found"):
        load_roots_file("/nowhere/roots.yaml")


def test_unreadable_path(tmp_path: Path) -> None:
    # A directory is readable as a path but not as a file -> OSError branch.
    with pytest.raises(SensiflowInputError, match="cannot read roots file"):
        load_roots_file(tmp_path)


def test_invalid_yaml(tmp_path: Path) -> None:
    path = write_roots(tmp_path, "version: 1\nroots: [\n")
    with pytest.raises(SensiflowInputError, match="invalid YAML"):
        load_roots_file(path)


def test_top_level_not_a_mapping(tmp_path: Path) -> None:
    path = write_roots(tmp_path, "- id: a\n- id: b\n")
    with pytest.raises(SensiflowInputError, match="top level must be a mapping"):
        load_roots_file(path)


def test_unknown_top_level_key(tmp_path: Path) -> None:
    path = write_roots(tmp_path, "version: 1\nroots:\n  - id: a\nextra: 1\n")
    with pytest.raises(SensiflowInputError, match="unknown top-level key 'extra'"):
        load_roots_file(path)


def test_missing_version(tmp_path: Path) -> None:
    path = write_roots(tmp_path, "roots:\n  - id: a\n")
    with pytest.raises(SensiflowInputError, match="missing required key 'version'"):
        load_roots_file(path)


def test_missing_roots(tmp_path: Path) -> None:
    path = write_roots(tmp_path, "version: 1\n")
    with pytest.raises(SensiflowInputError, match="missing required key 'roots'"):
        load_roots_file(path)


@pytest.mark.parametrize("version", ["2", "'1'", "true"])
def test_unsupported_version(tmp_path: Path, version: str) -> None:
    path = write_roots(tmp_path, f"version: {version}\nroots:\n  - id: a\n")
    with pytest.raises(
        SensiflowInputError, match=r"unsupported roots-file version.*\(supported: 1\)"
    ):
        load_roots_file(path)


@pytest.mark.parametrize("roots", ["{}", "[]", "a string"])
def test_roots_must_be_a_non_empty_list(tmp_path: Path, roots: str) -> None:
    path = write_roots(tmp_path, f"version: 1\nroots: {roots}\n")
    with pytest.raises(SensiflowInputError, match="'roots' must be a non-empty list"):
        load_roots_file(path)


def test_entry_not_a_mapping(tmp_path: Path) -> None:
    path = write_roots(tmp_path, "version: 1\nroots:\n  - just_a_string\n")
    with pytest.raises(SensiflowInputError, match=r"roots\[0\] must be a mapping"):
        load_roots_file(path)


def test_entry_with_two_keys(tmp_path: Path) -> None:
    path = write_roots(tmp_path, "version: 1\nroots:\n  - id: a\n    pattern: 'b*'\n")
    with pytest.raises(SensiflowInputError, match="exactly one key"):
        load_roots_file(path)


def test_entry_with_unknown_key(tmp_path: Path) -> None:
    path = write_roots(tmp_path, "version: 1\nroots:\n  - name: a\n")
    with pytest.raises(SensiflowInputError, match="unknown entry key 'name'"):
        load_roots_file(path)


@pytest.mark.parametrize("value", ["1", "''", "[a]"])
def test_entry_value_must_be_non_empty_string(tmp_path: Path, value: str) -> None:
    # YAML "[a]" is a list, "1" an int, "''" an empty string — all rejected.
    path = write_roots(tmp_path, f"version: 1\nroots:\n  - id: {value}\n")
    with pytest.raises(SensiflowInputError, match="must be a non-empty string"):
        load_roots_file(path)


def test_id_with_glob_characters(tmp_path: Path) -> None:
    path = write_roots(tmp_path, "version: 1\nroots:\n  - id: 'raw_*'\n")
    with pytest.raises(SensiflowInputError, match=r"glob characters in 'id' entry.*use 'pattern'"):
        load_roots_file(path)


def test_pattern_without_glob_characters(tmp_path: Path) -> None:
    path = write_roots(tmp_path, "version: 1\nroots:\n  - pattern: raw_customers\n")
    with pytest.raises(
        SensiflowInputError, match=r"no glob characters in 'pattern' entry.*use 'id'"
    ):
        load_roots_file(path)


def test_violation_messages_name_the_file(tmp_path: Path) -> None:
    path = write_roots(tmp_path, "version: 2\nroots:\n  - id: a\n")
    with pytest.raises(SensiflowInputError, match=r"roots\.yaml"):
        load_roots_file(path)


def test_non_utf8_file_is_input_error(tmp_path: Path) -> None:
    path = tmp_path / "roots.yaml"
    path.write_bytes(b"version: 1\nroots:\n  - id: caf\xe9\n")  # latin-1 bytes
    with pytest.raises(SensiflowInputError, match="not valid UTF-8"):
        load_roots_file(path)


def test_invalid_yaml_message_never_leaks_file_contents(tmp_path: Path) -> None:
    # If the "YAML" is really a credentials file passed by mistake, the error
    # message must not echo its contents (MarkedYAMLError's str() would).
    sentinel = "sample_secret_sentinel_AKIA0000"
    path = write_roots(tmp_path, f"password: [{sentinel}\n")  # unclosed flow seq
    with pytest.raises(SensiflowInputError, match="invalid YAML") as excinfo:
        load_roots_file(path)
    message = str(excinfo.value)
    assert sentinel not in message
    assert "line" in message  # coordinates survive; contents do not


def test_file_over_the_size_cap_is_refused_before_parsing(tmp_path: Path) -> None:
    path = tmp_path / "roots.yaml"
    path.write_bytes(b"#" * (1024 * 1024 + 1))
    with pytest.raises(SensiflowInputError, match=r"1 MiB.*limit|limit.*1 MiB"):
        load_roots_file(path)


# --- lazy PyYAML dependency --------------------------------------------------------


def test_missing_pyyaml_raises_dependency_error() -> None:
    def failing_import(name: str) -> Any:
        raise ImportError(name)

    with pytest.raises(SensiflowDependencyError, match=r"sensiflow\[yaml\]"):
        _require_yaml(import_module=failing_import)


def test_safe_load_is_the_only_yaml_entry_point() -> None:
    # Heuristic grep guard, not a proof: substring matching over src/ to catch
    # a careless regression to PyYAML's unsafe constructors. `.load(` cannot
    # false-positive on `safe_load(` (that contains `_load(`, not `.load(`).
    src_root = Path(__file__).parent.parent / "src" / "sensiflow"
    sources = {path: path.read_text() for path in sorted(src_root.rglob("*.py"))}
    assert sources, "src/sensiflow not found — test layout changed?"

    loader_text = sources[src_root / "root_selectors.py"]
    assert "safe_load" in loader_text

    forbidden = (".load(", ".full_load(", ".unsafe_load(", "FullLoader", "UnsafeLoader")
    for path, text in sources.items():
        for token in forbidden:
            assert token not in text, f"{path}: forbidden YAML API {token!r}"

"""Shared root-selection layer for all lineage sources (ADR-0002 amendment A4).

Owns the :class:`GraphSelection` spec object, the roots-file loader, and the
pattern-matching rules, so connectors cannot drift apart. Like
``graph_scope``, this is source-adjacent infrastructure: the engine never
sees it.

The roots file needs PyYAML, shipped behind the ``yaml`` extra and imported
lazily — glob patterns and from-seeds selection pay no install step.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from types import ModuleType

from sensiflow.exceptions import SensiflowDependencyError, SensiflowInputError

#: fnmatch metacharacters; their presence classifies a value as a pattern.
_GLOB_CHARS = ("*", "?", "[")


def has_glob_chars(value: str) -> bool:
    """True when ``value`` contains an fnmatch metacharacter (``*``, ``?``, ``[``)."""
    return any(ch in value for ch in _GLOB_CHARS)


@dataclass(frozen=True)
class GraphSelection:
    """One graph-scoping request: which roots to walk from, and how far.

    ``GraphSelection()`` (all defaults) is valid and means "full scan",
    equivalent to passing ``None`` to ``build_graph``. Validation happens at
    construction so the CLI, the file loader, and library callers all fail
    early with the same messages.
    """

    roots: tuple[str, ...] = ()
    patterns: tuple[str, ...] = ()
    from_seeds: bool = False
    upstream_depth: int | None = None
    downstream_depth: int | None = None

    def __post_init__(self) -> None:
        if self.from_seeds and (self.roots or self.patterns):
            raise SensiflowInputError(
                "from-seeds root selection is mutually exclusive with "
                "explicit roots and patterns"
            )
        for root in self.roots:
            if not root:
                raise SensiflowInputError("root ids must be non-empty strings")
            if has_glob_chars(root):
                raise SensiflowInputError(
                    f"root {root!r} contains glob characters (*, ?, [) — use patterns"
                )
        for pattern in self.patterns:
            if not pattern:
                raise SensiflowInputError("root patterns must be non-empty strings")
            if not has_glob_chars(pattern):
                raise SensiflowInputError(
                    f"pattern {pattern!r} has no glob characters (*, ?, [) — use roots"
                )
        for label, depth in (
            ("upstream-depth", self.upstream_depth),
            ("downstream-depth", self.downstream_depth),
        ):
            if depth is not None and depth < 0:
                raise SensiflowInputError(f"{label} must be >= 0, got {depth}")
        if (
            self.upstream_depth is not None or self.downstream_depth is not None
        ) and self.is_full_scan():
            raise SensiflowInputError(
                "depths require roots: a full scan has no roots to measure hops from"
            )

    def is_full_scan(self) -> bool:
        """True when no selector is set — build the whole catalog."""
        return not (self.roots or self.patterns or self.from_seeds)


def resolve_patterns(
    patterns: Sequence[str], candidates: Iterable[tuple[str, str]]
) -> list[str]:
    """Resolve fnmatch patterns against ``(id, name)`` candidates to node ids.

    A pattern matches a candidate when it matches the node id or the bare
    name (case-sensitive, ``fnmatch.fnmatchcase``). Any pattern matching
    zero candidates is a hard error (ADR-0002 amendment A6) — even when
    other patterns did match. Ids are returned deduplicated, in candidate
    order per pattern.
    """
    pairs = list(candidates)
    resolved: list[str] = []
    seen: set[str] = set()
    for pattern in patterns:
        matched = [
            node_id
            for node_id, name in pairs
            if fnmatchcase(node_id, pattern) or fnmatchcase(name, pattern)
        ]
        if not matched:
            raise SensiflowInputError(f"root pattern {pattern!r} matched no tables")
        for node_id in matched:
            if node_id not in seen:
                seen.add(node_id)
                resolved.append(node_id)
    return resolved


# --- roots file (ADR-0002 amendment A3) ---------------------------------------


def _require_yaml(
    import_module: Callable[[str], ModuleType] = importlib.import_module,
) -> ModuleType:
    try:
        return import_module("yaml")
    except ImportError as exc:
        raise SensiflowDependencyError(
            "the roots file requires the 'yaml' extra: pip install 'sensiflow[yaml]'"
        ) from exc


def load_roots_file(path: str | Path) -> GraphSelection:
    """Load a version-1 roots file into a selection of roots and patterns.

    The schema is rigid on purpose (ADR-0002 amendment A3): exactly
    ``{version: 1, roots: [...]}`` where every entry is a single-key mapping,
    ``id: <exact node id>`` or ``pattern: <fnmatch glob>``. Every violation
    raises :class:`SensiflowInputError` naming the file and the problem.
    """
    yaml_mod = _require_yaml()
    file_path = Path(path)
    try:
        text = file_path.read_text()
    except FileNotFoundError:
        raise SensiflowInputError(f"roots file not found: {file_path}") from None
    except OSError as exc:
        raise SensiflowInputError(
            f"cannot read roots file {file_path}: {exc.strerror}"
        ) from None

    try:
        payload = yaml_mod.safe_load(text)
    except yaml_mod.YAMLError as exc:
        raise SensiflowInputError(
            f"roots file {file_path}: invalid YAML: {exc}"
        ) from None

    def fail(violation: str) -> SensiflowInputError:
        return SensiflowInputError(f"roots file {file_path}: {violation}")

    if not isinstance(payload, dict):
        raise fail("top level must be a mapping with keys 'version' and 'roots'")
    for key in payload:
        if key not in ("version", "roots"):
            raise fail(f"unknown top-level key {key!r} (allowed: 'version', 'roots')")
    if "version" not in payload:
        raise fail("missing required key 'version'")
    if "roots" not in payload:
        raise fail("missing required key 'roots'")

    version = payload["version"]
    # bool is an int subclass; `version: true` must not pass as 1.
    if not isinstance(version, int) or isinstance(version, bool) or version != 1:
        raise fail(f"unsupported roots-file version: {version!r} (supported: 1)")

    entries = payload["roots"]
    if not isinstance(entries, list) or not entries:
        raise fail("'roots' must be a non-empty list")

    roots: list[str] = []
    patterns: list[str] = []
    for index, entry in enumerate(entries):
        where = f"roots[{index}]"
        if not isinstance(entry, dict) or len(entry) != 1:
            raise fail(
                f"{where} must be a mapping with exactly one key, 'id' or 'pattern'"
            )
        key, value = next(iter(entry.items()))
        if key not in ("id", "pattern"):
            raise fail(f"{where}: unknown entry key {key!r} (allowed: 'id', 'pattern')")
        if not isinstance(value, str) or not value:
            raise fail(f"{where}: {key!r} must be a non-empty string")
        if key == "id":
            if has_glob_chars(value):
                raise fail(
                    f"{where}: glob characters in 'id' entry {value!r} — use 'pattern'"
                )
            roots.append(value)
        else:
            if not has_glob_chars(value):
                raise fail(
                    f"{where}: no glob characters in 'pattern' entry {value!r} — use 'id'"
                )
            patterns.append(value)

    return GraphSelection(roots=tuple(roots), patterns=tuple(patterns))

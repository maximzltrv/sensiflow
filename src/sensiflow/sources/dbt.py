"""dbt connector: builds a LineageGraph from a dbt ``manifest.json``.

Implements ADR-0003: standard-library-only parsing (no dbt-core, no extra),
defensive across manifest schema versions — a missing field means the feature
is absent, never a crash. The user brings a manifest produced by their own
``dbt compile`` / ``dbt build``; sensiflow never runs dbt.

PII seeds come from column annotations, two conventions (ADR-0003 §4):
``meta: {pii: true, pii_category: ..., pii_sensitive: ...}`` (primary) and
column tags ``pii`` / ``pii:<category>`` (secondary).
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sensiflow.exceptions import SensiflowInputError
from sensiflow.graph_scope import scope_graph
from sensiflow.model import RISK_RANK, LineageGraph, Node, PiiTag, Risk
from sensiflow.root_selectors import GraphSelection, resolve_patterns
from sensiflow.sources._dbt_yaml import PropertiesFile
from sensiflow.sources.base import ExistingTag
from sensiflow.writeback import ApplyResult, TagChange

#: resource kinds that become graph vertices; tests/macros/exposures are not data.
_INCLUDED_KINDS = frozenset({"model", "seed", "snapshot"})
_EDGE_PREFIXES = ("model.", "source.", "seed.", "snapshot.")

#: Properties-file section per resource kind that write-back can edit.
_SECTIONS = {"model": "models", "seed": "seeds", "snapshot": "snapshots"}

#: The managed block (ADR-0006 §4); the name and ``propagated`` key are a frozen contract.
MARKER_KEY = "sensiflow"


def _effective_meta(column: Any) -> dict[str, Any]:
    """A column's ``meta`` merged with ``config.meta`` (the latter wins), tolerant of junk."""
    merged: dict[str, Any] = {}
    config = column.get("config")
    for source in (column.get("meta"), config.get("meta") if isinstance(config, dict) else None):
        if isinstance(source, dict):
            merged.update(source)
    return merged


def _is_propagated(meta: dict[str, Any]) -> bool:
    """True when ``meta.sensiflow.propagated`` is true: tool-written markup."""
    block = meta.get(MARKER_KEY)
    return isinstance(block, dict) and block.get("propagated") is True


def _declared_pii(raw: dict[str, Any]) -> dict[str, PiiTag]:
    """Columns carrying PII annotations, except tool-propagated ones (ADR-0006 §4)."""
    declared: dict[str, PiiTag] = {}
    for column_name, column in (raw.get("columns") or {}).items():
        if _is_propagated(_effective_meta(column)):
            continue
        meta = column.get("meta") or {}
        if meta.get("pii") is True:
            declared[column_name] = PiiTag(
                category=str(meta.get("pii_category") or "pii"),
                sensitive=bool(meta.get("pii_sensitive", True)),
            )
            continue
        for tag in column.get("tags") or []:
            if not isinstance(tag, str):
                continue
            if tag == "pii":
                declared[column_name] = PiiTag(category="pii")
                break
            if tag.startswith("pii:") and len(tag) > 4:
                declared[column_name] = PiiTag(category=tag[4:])
                break
    return declared


def _owners(raw: dict[str, Any]) -> list[str]:
    meta = {**(raw.get("meta") or {}), **((raw.get("config") or {}).get("meta") or {})}
    owner = meta.get("owner")
    if isinstance(owner, str) and owner.strip():
        return [owner]
    if isinstance(owner, list):
        return [item for item in owner if isinstance(item, str) and item]
    group = raw.get("group")
    if isinstance(group, str) and group:
        return [group]
    return []


def _sql(raw: dict[str, Any]) -> str | None:
    for key in ("compiled_code", "raw_code"):
        code = raw.get(key)
        if isinstance(code, str) and code.strip():
            return code
    return None


def _node_from_manifest_entry(unique_id: str, raw: dict[str, Any]) -> Node:
    upstream = [
        dep
        for dep in (raw.get("depends_on") or {}).get("nodes") or []
        if isinstance(dep, str) and dep.startswith(_EDGE_PREFIXES)
    ]
    return Node(
        id=unique_id,
        name=raw.get("name") or unique_id.rsplit(".", 1)[-1],
        owners=_owners(raw),
        upstream=upstream,
        sql=_sql(raw),
        declared_pii=_declared_pii(raw),
    )


@dataclass(frozen=True)
class _Location:
    """Where a node's column markup lives: a properties file and its entry."""

    path: Path
    section: str
    name: str


def _as_risk(value: Any) -> Risk | None:
    return next((risk for risk in RISK_RANK if risk == value), None)


def _human_tag(column: Any, meta: dict[str, Any]) -> PiiTag | None:
    """PII declared without the marker: ``meta.pii`` (primary) or ``pii`` / ``pii:<cat>`` tags."""
    pii = meta.get("pii")
    if pii is True or pii is False:
        # An explicit human "not PII" has no PiiTag form; the closest honest
        # reading is non-sensitive, so a sensitive derivation conflicts with it.
        return PiiTag(
            category=str(meta.get("pii_category") or "pii"),
            sensitive=bool(meta.get("pii_sensitive", True)) and pii,
        )
    for tag in column.get("tags") or []:
        if tag == "pii":
            return PiiTag(category="pii")
        if isinstance(tag, str) and tag.startswith("pii:") and len(tag) > 4:
            return PiiTag(category=tag[4:])
    return None


def _existing_from_column(column: Any) -> ExistingTag | None:
    """One properties-file column entry in the neutral write-back shape."""
    meta = _effective_meta(column)
    if not _is_propagated(meta):
        tag = _human_tag(column, meta)
        return ExistingTag(tag=tag, managed=False) if tag is not None else None
    block = meta[MARKER_KEY]
    confidence = block.get("confidence")
    origin = block.get("origin")
    return ExistingTag(
        tag=PiiTag(
            category=str(meta.get("pii_category") or "pii"),
            sensitive=bool(meta.get("pii_sensitive", True)),
        ),
        managed=True,
        risk=_as_risk(block.get("risk")),
        confidence=float(confidence) if isinstance(confidence, int | float) else None,
        origin=origin if isinstance(origin, str) else None,
    )


def _yaml_snippet(section: str, model: str, change: TagChange) -> str:
    """A ready-to-paste properties entry for a change the tool cannot place itself."""
    return "\n".join(
        [
            f"{section}:",
            f"  - name: {model}",
            "    columns:",
            f"      - name: {change.column}",
            "        meta:",
            "          pii: true",
            f"          pii_category: {change.tag.category}",
            f"          pii_sensitive: {str(change.tag.sensitive).lower()}",
            f"          {MARKER_KEY}:",
            "            propagated: true",
            f"            risk: {change.risk}",
            f"            confidence: {round(change.confidence, 4)}",
            f"            origin: {change.origin_node}",
        ]
    )


def _apply_to_column(properties: PropertiesFile, column: Any, change: TagChange) -> None:
    """Write the dual markup: native keys plus the managed ``meta.sensiflow`` block.

    The tool owns and rewrites only ``meta.sensiflow``. Native keys are written
    only when absent — except on an already-managed column, whose natives the
    tool wrote and keeps in step with the block. New mappings are filled
    *before* they are attached, so trailing comments move onto their last leaf.
    """
    natives: dict[str, Any] = {
        "pii": True,
        "pii_category": change.tag.category,
        "pii_sensitive": change.tag.sensitive,
    }
    provenance: dict[str, Any] = {
        "propagated": True,
        "risk": change.risk,
        "confidence": round(change.confidence, 4),
        "origin": change.origin_node,
    }
    meta = column.get("meta")
    if not properties.is_map(meta):
        fresh = properties.new_map(**natives, **{MARKER_KEY: properties.new_map(**provenance)})
        properties.set_key(column, "meta", fresh)
        return
    managed = _is_propagated(meta)
    for key, value in natives.items():
        if managed or key not in meta:
            properties.set_key(meta, key, value)
    block = meta.get(MARKER_KEY)
    if properties.is_map(block):
        for key, value in provenance.items():
            properties.set_key(block, key, value)
    else:
        properties.set_key(meta, MARKER_KEY, properties.new_map(**provenance))


def _open(cache: dict[Path, PropertiesFile], path: Path) -> PropertiesFile:
    """Parse each properties file once per operation."""
    if path not in cache:
        try:
            cache[path] = PropertiesFile.read(path)
        except (OSError, UnicodeDecodeError) as exc:
            raise SensiflowInputError(f"cannot read properties file {path}: {exc}") from None
    return cache[path]


def _atomic_write(path: Path, text: str) -> None:
    """Render to a temp file in the same directory, then replace (atomic on POSIX)."""
    handle = tempfile.NamedTemporaryFile(  # noqa: SIM115 - closed explicitly below
        "w",
        encoding="utf-8",
        newline="",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    )
    try:
        with handle:
            handle.write(text)
        os.chmod(handle.name, path.stat().st_mode & 0o7777)
        os.replace(handle.name, path)
    except BaseException:
        Path(handle.name).unlink(missing_ok=True)
        raise


class DbtSource:
    """LineageSource over a local dbt manifest.json, and WritebackTarget over its project.

    Reading lineage is manifest-only and read-only. Write-back (ADR-0006 §6)
    additionally needs ``project_dir``: markup is read from and written to the
    properties YAML files — never the manifest, which is a build artifact and
    may be stale relative to the files.
    """

    def __init__(self, manifest_path: str | Path, project_dir: str | Path | None = None) -> None:
        self._path = Path(manifest_path)
        self._project_dir = Path(project_dir) if project_dir is not None else None

    def __repr__(self) -> str:
        return f"DbtSource(manifest_path={str(self._path)!r})"

    # -- WritebackTarget (ADR-0006 §3, §6) -------------------------------------

    def read_markup(self, node_ids: Sequence[str]) -> dict[tuple[str, str], ExistingTag]:
        """Column markup as it stands in the properties files (the manifest is not consulted)."""
        project_dir = self._require_project_dir()
        found, _ = self._locate(node_ids, project_dir)
        files: dict[Path, PropertiesFile] = {}
        markup: dict[tuple[str, str], ExistingTag] = {}
        for node_id, location in found.items():
            properties = _open(files, location.path)
            entry = properties.find_entry(location.section, location.name)
            if entry is None:
                continue
            for column in properties.columns(entry):
                existing = _existing_from_column(column)
                if existing is not None:
                    markup[(node_id, str(column["name"]).lower())] = existing
        return markup

    def find_unmatched(self, changes: Sequence[TagChange]) -> dict[tuple[str, str], str]:
        """Changes with no properties entry to edit, each with a ready-to-paste snippet."""
        project_dir = self._require_project_dir()
        node_ids = list(dict.fromkeys(c.node_id for c in changes))
        found, reasons = self._locate(node_ids, project_dir)
        files: dict[Path, PropertiesFile] = {}
        unmatched: dict[tuple[str, str], str] = {}
        for change in changes:
            key = (change.node_id, change.column.lower())
            location = found.get(change.node_id)
            if location is None:
                reason, section = reasons[change.node_id]
            else:
                properties = _open(files, location.path)
                if properties.find_entry(location.section, location.name) is not None:
                    continue
                reason = f"no entry for the model in {location.path.name}"
                section = location.section
            unmatched[key] = (
                f"{reason}; sensiflow does not create files or model blocks — "
                f"add manually:\n{_yaml_snippet(section, change.node_name, change)}"
            )
        return unmatched

    def write_changes(self, changes: Sequence[TagChange]) -> ApplyResult:
        """Patch the properties files in place; one atomic write per file.

        A file that cannot be read, parsed or replaced fails only its own
        changes. Changes whose entry vanished since the diff are skipped and
        reported in ``failed`` with a ``skipped:`` message.
        """
        project_dir = self._require_project_dir()
        found, reasons = self._locate(
            list(dict.fromkeys(c.node_id for c in changes)), project_dir
        )
        result = ApplyResult(applied=[], failed=[])
        by_file: dict[Path, list[tuple[TagChange, _Location]]] = {}
        for change in changes:
            location = found.get(change.node_id)
            if location is None:
                result.failed.append((change, f"cannot place: {reasons[change.node_id][0]}"))
            else:
                by_file.setdefault(location.path, []).append((change, location))
        for path, items in by_file.items():
            self._write_file(path, items, result)
        return result

    @staticmethod
    def _write_file(
        path: Path, items: list[tuple[TagChange, _Location]], result: ApplyResult
    ) -> None:
        applied: list[TagChange] = []
        skipped: list[tuple[TagChange, str]] = []
        try:
            properties = PropertiesFile.read(path)
            for change, location in items:
                entry = properties.find_entry(location.section, location.name)
                if entry is None:
                    skipped.append((change, f"skipped: entry vanished from {path.name}"))
                    continue
                column = properties.find_column(entry, change.column)
                if column is None:
                    column = properties.add_column(entry, change.column)
                _apply_to_column(properties, column, change)
                applied.append(change)
            if applied:
                _atomic_write(path, properties.render())
        except (OSError, SensiflowInputError) as exc:
            reason = exc.strerror if isinstance(exc, OSError) and exc.strerror else str(exc)
            skipped_changes = {id(c) for c, _ in skipped}
            result.failed.extend(skipped)
            result.failed.extend(
                (c, f"cannot write {path.name}: {reason}")
                for c, _ in items
                if id(c) not in skipped_changes
            )
            return
        result.failed.extend(skipped)
        result.applied.extend(applied)

    def _require_project_dir(self) -> Path:
        if self._project_dir is None:
            raise SensiflowInputError(
                "dbt write-back requires --dbt-project-dir: the properties files, "
                "not the manifest, are what gets read and edited"
            )
        if not self._project_dir.is_dir():
            raise SensiflowInputError(f"dbt project directory not found: {self._project_dir}")
        return self._project_dir

    def _locate(
        self, node_ids: Sequence[str], project_dir: Path
    ) -> tuple[dict[str, _Location], dict[str, tuple[str, str]]]:
        """Resolve nodes to their properties files via the manifest's ``patch_path``.

        Returns ``(located, {node_id: (reason, section)})`` for the nodes that
        cannot be placed: sources, installed-package nodes, and models without
        a properties entry or whose file is missing or outside the project.
        """
        manifest = self._load()
        nodes = manifest.get("nodes") or {}
        root = project_dir.resolve()
        project_name = self._project_name(manifest, root)
        found: dict[str, _Location] = {}
        reasons: dict[str, tuple[str, str]] = {}
        for node_id in node_ids:
            raw = nodes.get(node_id)
            if not isinstance(raw, dict) or raw.get("resource_type") not in _SECTIONS:
                reasons[node_id] = ("not a model, seed or snapshot of the project", "models")
                continue
            section = _SECTIONS[raw["resource_type"]]
            name = raw.get("name") or node_id.rsplit(".", 1)[-1]
            if raw.get("package_name") != project_name:
                reasons[node_id] = (
                    f"belongs to installed package {raw.get('package_name')!r}, not the root "
                    "project",
                    section,
                )
                continue
            patch_path = raw.get("patch_path")
            if not isinstance(patch_path, str) or not patch_path:
                reasons[node_id] = (
                    "no properties-file entry (patch_path) in the manifest",
                    section,
                )
                continue
            # patch_path is "<package>://<path relative to that package root>".
            _, sep, tail = patch_path.partition("://")
            resolved = (root / (tail if sep else patch_path)).resolve()
            if not resolved.is_relative_to(root):
                reasons[node_id] = ("patch_path points outside the project directory", section)
            elif not resolved.is_file():
                reasons[node_id] = (f"properties file {patch_path} not found on disk", section)
            else:
                found[node_id] = _Location(path=resolved, section=section, name=name)
        return found, reasons

    @staticmethod
    def _project_name(manifest: dict[str, Any], root: Path) -> str:
        name = (manifest.get("metadata") or {}).get("project_name")
        if isinstance(name, str) and name:
            return name
        project_file = root / "dbt_project.yml"
        if project_file.is_file():
            declared = PropertiesFile.read(project_file).document
            if isinstance(declared, dict) and isinstance(declared.get("name"), str):
                return str(declared["name"])
        raise SensiflowInputError(
            "cannot determine the root dbt project name: the manifest has no "
            "metadata.project_name and --dbt-project-dir has no readable dbt_project.yml"
        )

    def build_graph(self, selection: GraphSelection | None = None) -> LineageGraph:
        manifest = self._load()
        graph = self._graph_from_manifest(manifest)
        if selection is None or selection.is_full_scan():
            return graph
        return scope_graph(
            graph,
            self._resolve_selection(selection, graph),
            upstream_depth=selection.upstream_depth,
            downstream_depth=selection.downstream_depth,
        )

    @staticmethod
    def _resolve_selection(selection: GraphSelection, graph: LineageGraph) -> list[str]:
        """Resolve the selection to node ids, in memory (ADR-0002 amendment A5)."""
        if selection.from_seeds:
            seeded = sorted(
                node_id for node_id, node in graph.nodes.items() if node.declared_pii
            )
            if not seeded:
                raise SensiflowInputError(
                    "--roots-from-seeds found no PII-seeded models or sources in the "
                    "manifest; sensiflow needs declared PII markup to trace from "
                    "(ADR-0001 applicability precondition)"
                )
            return seeded
        resolved = [DbtSource._resolve_root(root, graph) for root in selection.roots]
        if selection.patterns:
            candidates = [(node_id, node.name) for node_id, node in graph.nodes.items()]
            resolved.extend(resolve_patterns(selection.patterns, candidates))
        # One node matched by several selectors appears once (A2).
        return list(dict.fromkeys(resolved))

    def _load(self) -> dict[str, Any]:
        try:
            # dbt writes manifest.json as UTF-8; anything else is not a manifest.
            text = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            raise SensiflowInputError(f"dbt manifest not found: {self._path}") from None
        except UnicodeDecodeError:
            raise SensiflowInputError(
                f"dbt manifest {self._path}: not valid UTF-8"
            ) from None
        except OSError as exc:
            raise SensiflowInputError(
                f"cannot read dbt manifest {self._path}: {exc.strerror}"
            ) from None
        try:
            manifest = json.loads(text)
        except ValueError:
            raise SensiflowInputError(
                f"{self._path} is not valid JSON — is it really a dbt manifest?"
            ) from None
        if not isinstance(manifest, dict) or (
            "nodes" not in manifest and "sources" not in manifest
        ):
            raise SensiflowInputError(
                f"{self._path} has neither 'nodes' nor 'sources' — "
                "not a dbt manifest.json"
            )
        return manifest

    @staticmethod
    def _graph_from_manifest(manifest: dict[str, Any]) -> LineageGraph:
        nodes: dict[str, Node] = {}
        for unique_id, raw in (manifest.get("nodes") or {}).items():
            if not isinstance(raw, dict):
                continue
            if raw.get("resource_type") not in _INCLUDED_KINDS:
                continue
            nodes[unique_id] = _node_from_manifest_entry(unique_id, raw)
        for unique_id, raw in (manifest.get("sources") or {}).items():
            if isinstance(raw, dict):
                nodes[unique_id] = _node_from_manifest_entry(unique_id, raw)
        return LineageGraph(nodes=nodes)

    @staticmethod
    def _resolve_root(root: str, graph: LineageGraph) -> str:
        """A root is a unique_id, or a bare model/source name if unambiguous."""
        if root in graph.nodes:
            return root
        matches = sorted(
            node_id for node_id, node in graph.nodes.items() if node.name == root
        )
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise SensiflowInputError(
                f"unknown root {root!r}: not a unique_id or a model/source name "
                "in the manifest"
            )
        raise SensiflowInputError(
            f"ambiguous root {root!r}: matches {', '.join(matches)} — "
            "use the full unique_id"
        )

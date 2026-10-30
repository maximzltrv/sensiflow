"""Round-trip YAML editing for dbt properties files (ADR-0006 §6).

The one place that touches ``ruamel.yaml``. It is imported lazily, so the
base install (and manifest reading) never needs it, and its incomplete type
hints stay behind this boundary: ruamel objects are plain ``Any`` here and
the rest of the connector only sees the small API below.

Round-trip fidelity is the contract: comments, key order, quoting and anchors
survive an edit, and the file's own indentation style is detected and reused
so untouched entries re-dump identically.
"""

from __future__ import annotations

import importlib
import io
import re
from collections.abc import Callable
from pathlib import Path
from types import ModuleType
from typing import Any

from sensiflow.exceptions import SensiflowDependencyError, SensiflowInputError

_DEFAULT_INDENT = (2, 4, 2)  # mapping, sequence, offset: the common dbt layout
_SIGNIFICANT = re.compile(r"^(?P<indent> *)(?P<rest>[^ #\n].*)$")


def require_ruamel(
    import_module: Callable[[str], ModuleType] = importlib.import_module,
) -> tuple[ModuleType, ModuleType]:
    """Return ``(ruamel.yaml, ruamel.yaml.comments)`` or raise with the install hint."""
    try:
        return import_module("ruamel.yaml"), import_module("ruamel.yaml.comments")
    except ImportError as exc:
        raise SensiflowDependencyError(
            "writing dbt markup requires the 'dbt' extra: pip install 'sensiflow[dbt]'"
        ) from exc


def detect_indent(text: str) -> tuple[int, int, int]:
    """Infer ``(mapping, sequence, offset)`` indentation from the file's first nestings."""
    mapping: int | None = None
    offset: int | None = None
    parent_indent: int | None = None  # indent of a bare ``key:`` line awaiting its child
    for line in text.splitlines():
        match = _SIGNIFICANT.match(line)
        if match is None:
            continue
        indent = len(match["indent"])
        rest = match["rest"]
        if parent_indent is not None and indent >= parent_indent:
            if rest.startswith("- "):
                if offset is None:
                    offset = indent - parent_indent
            elif mapping is None and indent > parent_indent:
                mapping = indent - parent_indent
        parent_indent = indent if rest.endswith(":") and not rest.startswith("- ") else None
        if mapping is not None and offset is not None:
            break
    mapping = mapping or _DEFAULT_INDENT[0]
    offset = _DEFAULT_INDENT[2] if offset is None else offset
    return mapping, offset + 2, offset


class PropertiesFile:
    """One parsed properties YAML file, editable in place and re-renderable."""

    def __init__(self, text: str) -> None:
        yaml_mod, comments_mod = require_ruamel()
        self._comments = comments_mod
        self._yaml: Any = yaml_mod.YAML(typ="rt")
        self._yaml.preserve_quotes = True
        self._yaml.width = 1 << 20  # never re-wrap long descriptions
        mapping, sequence, offset = detect_indent(text)
        self._yaml.indent(mapping=mapping, sequence=sequence, offset=offset)
        self._yaml.explicit_start = text.lstrip().startswith("---")
        try:
            self.document: Any = self._yaml.load(text)
        except yaml_mod.YAMLError as exc:
            # Parser messages quote file content; the error type is enough to act on.
            raise SensiflowInputError(f"not valid YAML ({type(exc).__name__})") from None
        if self.document is not None:
            self._pin_anchors(self.document)

    @classmethod
    def read(cls, path: Path) -> PropertiesFile:
        text = path.read_text(encoding="utf-8")
        try:
            return cls(text)
        except SensiflowInputError as exc:
            raise SensiflowInputError(f"{path}: {exc}") from None

    def render(self) -> str:
        buffer = io.StringIO()
        self._yaml.dump(self.document, buffer)
        return buffer.getvalue()

    # -- navigation -------------------------------------------------------------

    def find_entry(self, section: str, name: str) -> Any | None:
        """The ``name`` entry under top-level ``section`` (models / seeds / ...)."""
        if not self.is_map(self.document):
            return None
        for entry in _items(self.document.get(section)):
            if self.is_map(entry) and entry.get("name") == name:
                return entry
        return None

    def find_column(self, entry: Any, name: str) -> Any | None:
        for column in _items(entry.get("columns")):
            col_name = column.get("name") if self.is_map(column) else None
            if isinstance(col_name, str) and col_name.lower() == name.lower():
                return column
        return None

    def columns(self, entry: Any) -> list[Any]:
        return [c for c in _items(entry.get("columns")) if self.is_map(c)]

    def is_map(self, node: Any) -> bool:
        return isinstance(node, self._comments.CommentedMap)

    # -- editing ----------------------------------------------------------------

    def new_map(self, **items: Any) -> Any:
        node = self._comments.CommentedMap()
        for key, value in items.items():
            node[key] = value
        return node

    def add_column(self, entry: Any, name: str) -> Any:
        """Append a bare ``- name: <name>`` column entry, creating ``columns`` if needed."""
        column = self.new_map(name=name)
        columns = entry.get("columns")
        if isinstance(columns, self._comments.CommentedSeq):
            self._append_to_seq(columns, column)
        else:
            seq = self._comments.CommentedSeq()
            seq.append(column)
            if "columns" in entry:
                entry["columns"] = seq
            else:
                self.set_key(entry, "columns", seq)
        return column

    def set_key(self, node: Any, key: str, value: Any) -> None:
        """Set ``key``; a new key is appended and takes over the node's trailing comment.

        ruamel parks the blank lines / comments that follow a mapping on its
        last leaf; appending without moving them would wedge the new key
        between the old content and its trailing whitespace.
        """
        if key in node:
            node[key] = value
            return
        token = _take_trailing(node, self._comments)
        node[key] = value
        _give_trailing(node, token, self._comments)

    def _append_to_seq(self, seq: Any, item: Any) -> None:
        token = _take_trailing(seq, self._comments)
        seq.append(item)
        _give_trailing(seq, token, self._comments)

    def _pin_anchors(self, node: Any) -> None:
        """Keep anchors nothing aliases: ruamel would otherwise drop them on dump."""
        anchor = getattr(node, "yaml_anchor", lambda: None)()
        if anchor is not None:
            anchor.always_dump = True
        if isinstance(node, self._comments.CommentedMap):
            children = list(node.values())
        elif isinstance(node, self._comments.CommentedSeq):
            children = list(node)
        else:
            return
        for child in children:
            self._pin_anchors(child)


def _items(node: Any) -> list[Any]:
    return list(node) if isinstance(node, list) else []


def _last_slot(node: Any, comments: ModuleType) -> tuple[Any, Any] | None:
    """The deepest-last ``(container, key)`` of a node: where ruamel parks trailing comments."""
    while True:
        if isinstance(node, comments.CommentedMap) and len(node):
            key: Any = list(node.keys())[-1]
        elif isinstance(node, comments.CommentedSeq) and len(node):
            key = len(node) - 1
        else:
            return None
        child = node[key]
        if isinstance(child, comments.CommentedMap | comments.CommentedSeq) and len(child):
            node = child
            continue
        return node, key


def _slot_index(container: Any, comments: ModuleType) -> int:
    # Post-value comments live in slot 2 of a mapping item, slot 0 of a sequence item.
    return 2 if isinstance(container, comments.CommentedMap) else 0


def _take_trailing(node: Any, comments: ModuleType) -> Any | None:
    slot = _last_slot(node, comments)
    if slot is None:
        return None
    container, key = slot
    entry = container.ca.items.get(key)
    index = _slot_index(container, comments)
    if not entry or entry[index] is None:
        return None
    token = entry[index]
    entry[index] = None
    return token


def _give_trailing(node: Any, token: Any | None, comments: ModuleType) -> None:
    if token is None:
        return
    slot = _last_slot(node, comments)
    if slot is None:
        return
    container, key = slot
    entry = container.ca.items.setdefault(key, [None, None, None, None])
    entry[_slot_index(container, comments)] = token

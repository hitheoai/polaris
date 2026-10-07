"""Data shapes of the experimental code graph.

Everything here is plain data: ids, paths, line numbers, symbol names and digests. No source text
is ever stored. Records are immutable and `Graph.to_dict()` orders everything, so the same
repository state always serializes to the same bytes.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

GRAPH_FORMAT = "polaris.graph/0.1.0-experimental"
# Bump when extraction output for the same file text can change (it is part of every cache key).
EXTRACTOR_VERSION = "polaris-graph-extract/0.1.0"

MODULE_SUFFIX = "<module>"
# What an argument at a call site is, as far as the existing Python data-flow rules can tell.
ArgClass = Literal["constant", "request", "param", "sanitized", "unknown"]
EdgeStatus = Literal["resolved", "unresolved"]
# Unresolved reasons that only mean "this leaves the repository": a call into the standard library,
# an installed package or a builtin. They are reported, but they are not gaps in the graph.
EXTERNAL_REASONS = frozenset({"builtin", "stdlib", "third_party"})


@dataclass(frozen=True, slots=True)
class Limits:
    """Hard bounds. Hitting one never fails silently: it is listed in `Graph.incomplete`."""

    max_files: int = 20_000
    max_file_bytes: int = 1_000_000
    max_total_bytes: int = 256_000_000
    max_nodes: int = 500_000
    max_edges: int = 2_000_000

    def to_dict(self) -> dict[str, int]:
        return {
            "max_files": self.max_files, "max_file_bytes": self.max_file_bytes,
            "max_total_bytes": self.max_total_bytes, "max_nodes": self.max_nodes,
            "max_edges": self.max_edges,
        }


@dataclass(frozen=True, slots=True)
class Incomplete:
    """One reason the graph does not describe the whole repository."""

    reason: str
    path: str | None = None
    detail: str | None = None

    def to_dict(self) -> dict[str, Any]:
        item: dict[str, Any] = {"reason": self.reason}
        if self.path is not None:
            item["path"] = self.path
        if self.detail is not None:
            item["detail"] = self.detail
        return item


@dataclass(frozen=True, slots=True)
class ArgFact:
    """What one argument at a call site is made of. Never the argument's text."""

    kind: Literal["pos", "kw", "star", "dstar"]
    position: int | None
    keyword: str | None
    cls: ArgClass
    # Parameter names of the calling function the value derives from ("param"), and short
    # analyzer descriptions of request origins ("request input name", "request data (request.args)").
    params: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()
    reason: str | None = None
    # Upper-case names a "constant" depends on (resolved by the builder, then cleared).
    const_refs: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        item: dict[str, Any] = {"kind": self.kind, "cls": self.cls}
        if self.position is not None:
            item["position"] = self.position
        if self.keyword is not None:
            item["keyword"] = self.keyword
        if self.params:
            item["params"] = list(self.params)
        if self.sources:
            item["sources"] = list(self.sources)
        if self.reason is not None:
            item["reason"] = self.reason
        if self.const_refs:
            item["const_refs"] = list(self.const_refs)
        return item


@dataclass(frozen=True, slots=True)
class ParamFact:
    name: str
    kind: Literal["posonly", "pos", "kwonly", "vararg", "varkw"]
    default: Literal["none", "literal", "other"] = "none"

    def to_dict(self) -> dict[str, str]:
        return {"name": self.name, "kind": self.kind, "default": self.default}


@dataclass(frozen=True, slots=True)
class SinkFact:
    """A sink the existing flow rules found in a function whose argument derives from parameters."""

    kind: str
    line: int
    call: str
    params: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind, "line": self.line, "call": self.call, "params": list(self.params)}


@dataclass(frozen=True, slots=True)
class FileNode:
    path: str
    language: str
    digest: str
    status: str  # "ok" | "parse_error" | ...
    bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "language": self.language, "digest": self.digest,
                "status": self.status, "bytes": self.bytes}


@dataclass(frozen=True, slots=True)
class ImportEdge:
    importer: str
    line: int
    scope: str  # "" for module level, else the qualified name of the enclosing function
    kind: Literal["import", "from", "star"]
    module: str  # as written, relative imports keep their dots
    name: str  # imported name for `from` imports
    alias: str | None
    target: str | None  # the module's file (or namespace folder) when it was found
    status: EdgeStatus
    reason: str | None = None
    external: bool = False

    def to_dict(self) -> dict[str, Any]:
        item: dict[str, Any] = {
            "importer": self.importer, "line": self.line, "kind": self.kind, "module": self.module,
            "status": self.status,
        }
        if self.scope:
            item["scope"] = self.scope
        if self.name:
            item["name"] = self.name
        if self.alias:
            item["alias"] = self.alias
        if self.target is not None:
            item["target"] = self.target
        if self.reason is not None:
            item["reason"] = self.reason
        if self.external:
            item["external"] = True
        return item


@dataclass(frozen=True, slots=True)
class Definition:
    id: str
    path: str
    qualname: str
    kind: Literal["function", "method", "class"]
    is_async: bool
    line: int
    end_line: int
    parent: str | None  # id of the enclosing class or function
    params: tuple[ParamFact, ...] = ()
    decorators: tuple[str, ...] = ()
    bases: tuple[str, ...] = ()
    static: bool = False
    # The analyzer's own unit (top-level function or method), the only place its findings sit.
    analysis_unit: bool = False
    # How the existing analyzer recognizes request handlers (None when it does not).
    analyzer_entry: str | None = None
    sinks: tuple[SinkFact, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        item: dict[str, Any] = {
            "id": self.id, "path": self.path, "qualname": self.qualname, "kind": self.kind,
            "line": self.line, "end_line": self.end_line,
        }
        if self.is_async:
            item["async"] = True
        if self.parent is not None:
            item["parent"] = self.parent
        if self.params:
            item["params"] = [param.to_dict() for param in self.params]
        if self.decorators:
            item["decorators"] = list(self.decorators)
        if self.bases:
            item["bases"] = list(self.bases)
        if self.static:
            item["static"] = True
        if self.analysis_unit:
            item["analysis_unit"] = True
        if self.analyzer_entry is not None:
            item["analyzer_entry"] = self.analyzer_entry
        if self.sinks:
            item["sinks"] = [sink.to_dict() for sink in self.sinks]
        return item


@dataclass(frozen=True, slots=True)
class CallEdge:
    caller: str  # a definition id, or "<path>::<module>" for module-level code
    line: int
    column: int
    callee: str  # the dotted name as written, or "<expression>"
    status: EdgeStatus
    target: str | None = None  # definition id when resolved
    target_kind: Literal["function", "method", "constructor", "class"] | None = None
    reason: str | None = None
    external: bool = False
    bound_first: bool = False  # the target's first parameter is supplied implicitly (self/cls)
    via_star: bool = False
    opaque: tuple[str, ...] = ()  # decorators of the target that may change its arguments
    args: tuple[ArgFact, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        item: dict[str, Any] = {
            "caller": self.caller, "line": self.line, "column": self.column, "callee": self.callee,
            "status": self.status,
        }
        if self.target is not None:
            item["target"] = self.target
        if self.target_kind is not None:
            item["target_kind"] = self.target_kind
        if self.reason is not None:
            item["reason"] = self.reason
        if self.external:
            item["external"] = True
        if self.bound_first:
            item["bound_first"] = True
        if self.via_star:
            item["via_star"] = True
        if self.opaque:
            item["opaque"] = list(self.opaque)
        if self.args:
            item["args"] = [arg.to_dict() for arg in self.args]
        return item


@dataclass(frozen=True, slots=True)
class RefEdge:
    """A named function or class used as a value (callback, decorator, argument), not called."""

    source: str
    line: int
    target: str

    def to_dict(self) -> dict[str, Any]:
        return {"source": self.source, "line": self.line, "target": self.target}


@dataclass(frozen=True, slots=True)
class EntryPointNode:
    definition: str
    kind: str  # route | view_decorator | request_parameter (analyzer) | class_view (graph only)
    recognized_by: Literal["analyzer", "graph"]
    mutating: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"definition": self.definition, "kind": self.kind, "recognized_by": self.recognized_by,
                "mutating": self.mutating}


@dataclass(frozen=True, slots=True)
class ScriptImportEdge:
    """TypeScript / JavaScript import (the thin graph: files and specifiers, no definitions)."""

    importer: str
    line: int
    kind: Literal["import", "export_from", "require", "dynamic_import"]
    specifier: str
    target: str | None
    status: EdgeStatus
    reason: str | None = None
    external: bool = False

    def to_dict(self) -> dict[str, Any]:
        item: dict[str, Any] = {
            "importer": self.importer, "line": self.line, "kind": self.kind,
            "specifier": self.specifier, "status": self.status,
        }
        if self.target is not None:
            item["target"] = self.target
        if self.reason is not None:
            item["reason"] = self.reason
        if self.external:
            item["external"] = True
        return item


@dataclass(slots=True)
class Graph:
    """The built graph. Treat it as read-only; `digest` identifies its exact content."""

    limits: Limits
    files: tuple[FileNode, ...]
    imports: tuple[ImportEdge, ...]
    definitions: tuple[Definition, ...]
    calls: tuple[CallEdge, ...]
    refs: tuple[RefEdge, ...]
    entries: tuple[EntryPointNode, ...]
    script_imports: tuple[ScriptImportEdge, ...]
    incomplete: tuple[Incomplete, ...]
    stats: dict[str, Any]
    digest: str = ""
    _indexes: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": GRAPH_FORMAT,
            "extractor": EXTRACTOR_VERSION,
            "limits": self.limits.to_dict(),
            "complete": not self.incomplete,
            "incomplete": [item.to_dict() for item in self.incomplete],
            "stats": self.stats,
            "files": [item.to_dict() for item in self.files],
            "imports": [item.to_dict() for item in self.imports],
            "definitions": [item.to_dict() for item in self.definitions],
            "calls": [item.to_dict() for item in self.calls],
            "refs": [item.to_dict() for item in self.refs],
            "entry_points": [item.to_dict() for item in self.entries],
            "script_imports": [item.to_dict() for item in self.script_imports],
        }

    # ---- queries ----------------------------------------------------------------------------

    def _index(self, name: str) -> Any:
        found = self._indexes.get(name)
        if found is not None:
            return found
        if name == "definitions":
            found = {item.id: item for item in self.definitions}
        elif name == "by_path_symbol":
            found = {}
            for item in self.definitions:
                found.setdefault((item.path, item.qualname), []).append(item)
        elif name == "callers":
            found = {}
            for edge in self.calls:
                if edge.status == "resolved" and edge.target is not None:
                    found.setdefault(edge.target, []).append(edge)
        elif name == "refs":
            found = {}
            for ref in self.refs:
                found.setdefault(ref.target, []).append(ref)
        elif name == "entries":
            found = {item.definition: item for item in self.entries}
        elif name == "unresolved_names":
            found = {}
            for edge in self.calls:
                if edge.status == "unresolved" and not edge.external and edge.callee != "<expression>":
                    last = edge.callee.rsplit(".", 1)[-1]
                    found[last] = found.get(last, 0) + 1
                elif edge.status == "unresolved" and not edge.external:
                    found["<expression>"] = found.get("<expression>", 0) + 1
        else:
            raise KeyError(name)
        self._indexes[name] = found
        return found

    def definition(self, definition_id: str) -> Definition | None:
        result: Definition | None = self._index("definitions").get(definition_id)
        return result

    def definitions_at(self, path: str, symbol: str, line: int | None = None) -> list[Definition]:
        """Definitions named `symbol` in `path`; with `line`, only those whose span contains it."""
        found: list[Definition] = list(self._index("by_path_symbol").get((path, symbol), ()))
        if line is not None:
            found = [item for item in found if item.line <= line <= item.end_line]
        return found

    def callers(self, definition_id: str) -> list[CallEdge]:
        """Resolved call edges whose target is this definition."""
        return list(self._index("callers").get(definition_id, ()))

    def references(self, definition_id: str) -> list[RefEdge]:
        return list(self._index("refs").get(definition_id, ()))

    def entry_point(self, definition_id: str) -> EntryPointNode | None:
        result: EntryPointNode | None = self._index("entries").get(definition_id)
        return result

    def possible_unresolved_callers(self, name: str) -> int:
        """Unresolved in-repository-possible calls whose callee ends in `name`, plus calls through
        computed expressions (which could be anything)."""
        names = self._index("unresolved_names")
        return int(names.get(name, 0)) + int(names.get("<expression>", 0))

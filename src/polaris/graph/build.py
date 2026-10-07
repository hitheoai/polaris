"""Build the graph: limits, digest-keyed facts, cross-file name resolution, canonical output.

The rule that shapes this module: an edge is `resolved` only when the target follows from the
code without choosing between alternatives. A name that is bound more than once, a module name that
matches two files, a method that a subclass overrides, a receiver of unknown type, a star import
whose names cannot be listed: each becomes an `unresolved` edge with a reason. Calls that leave the
repository (builtins, the standard library, installed packages) are unresolved with an
`external` flag. They are listed, but they are not gaps.
"""

from __future__ import annotations

import builtins
import posixpath
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from typing import Any

from polaris.errors import PolarisInputError
from polaris.graph.jsimports import (
    SCRIPT_SUFFIXES,
    RawScriptImport,
    extract_script_imports,
    is_script_config,
    resolve_script_import,
)
from polaris.graph.model import (
    EXTERNAL_REASONS,
    EXTRACTOR_VERSION,
    MODULE_SUFFIX,
    ArgFact,
    CallEdge,
    Definition,
    EntryPointNode,
    FileNode,
    Graph,
    ImportEdge,
    Incomplete,
    Limits,
    RefEdge,
    ScriptImportEdge,
)
from polaris.graph.pyfacts import (
    FileFacts,
    RawCall,
    RawDef,
    RawImport,
    extract_python,
    module_name_parts,
)
from polaris.jsonio import canonical_bytes, digest_json, digest_text
from polaris.review.analyzers.python import AUTH_NAME, ROUTE_DECORATORS, VIEW_DECORATORS
from polaris.review.js.tsconfig import AliasConfig, config_paths_for, load_alias_config

BUILTIN_NAMES = frozenset(dir(builtins))
STDLIB = frozenset(getattr(sys, "stdlib_module_names", ()))
MAX_RESOLUTION_DEPTH = 40
# Decorators that do not change how a function is called (they register it or add metadata).
# Definitions that only describe a signature or an accessor of a name another definition implements.
STUB_DECORATORS = frozenset({"overload", "setter", "getter", "deleter"})
TRANSPARENT_DECORATORS = frozenset({
    "staticmethod", "classmethod", "abstractmethod", "lru_cache", "cache", "overload", "wraps",
    "cached_property", "final", "override",
})


@dataclass(frozen=True, slots=True)
class Tgt:
    """What a name resolves to. `kind` is def, class, module, namespace, const, other or unresolved."""

    kind: str
    path: str = ""
    qual: str = ""
    reason: str = ""
    external: bool = False
    via_star: bool = False


def _unresolved(reason: str, *, external: bool = False) -> Tgt:
    return Tgt("unresolved", reason=reason, external=external)


@dataclass(slots=True)
class DefRec:
    id: str
    path: str
    raw: RawDef
    stub: bool = False


class GraphCache:
    """Per-file facts keyed by (extractor version, file digest, path). In memory for the spike.

    A later persistent cache only needs to store `FileFacts` under the same key; nothing in the
    builder depends on how facts were obtained.
    """

    def __init__(self) -> None:
        self._python: dict[tuple[str, str, str], FileFacts] = {}
        self._scripts: dict[tuple[str, str, str], list[RawScriptImport]] = {}
        self.hits = 0
        self.misses = 0

    def python(self, path: str, digest: str, text: str) -> FileFacts:
        key = (EXTRACTOR_VERSION, digest, path)
        found = self._python.get(key)
        if found is not None:
            self.hits += 1
            return found
        self.misses += 1
        facts = extract_python(path, text)
        self._python[key] = facts
        return facts

    def script(self, path: str, digest: str, text: str) -> list[RawScriptImport]:
        key = (EXTRACTOR_VERSION, digest, path)
        found = self._scripts.get(key)
        if found is not None:
            self.hits += 1
            return found
        self.misses += 1
        extracted = extract_script_imports(path, text)
        self._scripts[key] = extracted
        return extracted

    def __len__(self) -> int:
        return len(self._python) + len(self._scripts)


def _language(path: str) -> str | None:
    if path.endswith(".py"):
        return "python"
    if path.endswith(SCRIPT_SUFFIXES):
        return "script"
    return None


def build_graph(
    files: Mapping[str, str], *, limits: Limits | None = None, skipped: Mapping[str, str] | None = None,
    cache: GraphCache | None = None, extra_incomplete: Iterable[Incomplete] = (),
) -> Graph:
    """Build the graph of `files` (repository-relative POSIX path -> text).

    `skipped` names files the caller could not read (path -> reason), so they stay visible as
    unanalyzed targets instead of looking like third-party code. `extra_incomplete` carries
    incompleteness the caller knows about (for example a folder listing that stopped early). The
    same inputs and limits always give the same graph.
    """
    limits = limits or Limits()
    cache = cache if cache is not None else GraphCache()
    skipped = dict(skipped or {})
    incomplete: list[Incomplete] = list(extra_incomplete)
    nodes_total = 0
    edges_total = 0
    bytes_total = 0
    stopped = False
    file_nodes: list[FileNode] = []
    py_facts: dict[str, FileFacts] = {}
    script_facts: dict[str, list[RawScriptImport]] = {}
    not_analyzed: dict[str, str] = {}
    all_py: set[str] = set()
    all_scripts: set[str] = set()

    for path in sorted(files):
        language = _language(path)
        if language == "python":
            all_py.add(path)
        elif language == "script":
            all_scripts.add(path)
    for path, reason in sorted(skipped.items()):
        language = _language(path)
        if language is None:
            continue
        (all_py if language == "python" else all_scripts).add(path)
        not_analyzed[path] = reason
        file_nodes.append(FileNode(path, language, "", reason, 0))
        incomplete.append(Incomplete(reason, path))

    analyzed = 0
    for path in sorted(files):
        language = _language(path)
        if language is None or path in not_analyzed:
            continue
        text = files[path]
        if stopped:
            not_analyzed[path] = "not_reached"
            continue
        if analyzed >= limits.max_files:
            incomplete.append(Incomplete("file_limit", path, f"limit {limits.max_files}"))
            stopped = True
            not_analyzed[path] = "file_limit"
            continue
        try:
            size = len(text.encode("utf-8"))
            digest = digest_text(text)
        except (UnicodeError, PolarisInputError):
            file_nodes.append(FileNode(path, language, "", "invalid_encoding", 0))
            incomplete.append(Incomplete("invalid_encoding", path))
            not_analyzed[path] = "invalid_encoding"
            continue
        if size > limits.max_file_bytes:
            file_nodes.append(FileNode(path, language, digest, "file_too_large", size))
            incomplete.append(Incomplete("file_too_large", path, f"{size} bytes"))
            not_analyzed[path] = "file_too_large"
            continue
        if bytes_total + size > limits.max_total_bytes:
            incomplete.append(Incomplete("total_bytes_limit", path, f"limit {limits.max_total_bytes}"))
            stopped = True
            not_analyzed[path] = "total_bytes_limit"
            continue
        if language == "python":
            facts = cache.python(path, digest, text)
            new_nodes = 1 + len(facts.defs)
            new_edges = len(facts.imports) + len(facts.calls) + len(facts.refs)
        else:
            raw = cache.script(path, digest, text)
            new_nodes, new_edges = 1, len(raw)
        if nodes_total + new_nodes > limits.max_nodes:
            incomplete.append(Incomplete("node_limit", path, f"limit {limits.max_nodes}"))
            stopped = True
            not_analyzed[path] = "node_limit"
            continue
        if edges_total + new_edges > limits.max_edges:
            incomplete.append(Incomplete("edge_limit", path, f"limit {limits.max_edges}"))
            stopped = True
            not_analyzed[path] = "edge_limit"
            continue
        nodes_total += new_nodes
        edges_total += new_edges
        bytes_total += size
        analyzed += 1
        if language == "python":
            status = facts.status
            if status != "ok":
                incomplete.append(Incomplete(status, path))
            else:
                py_facts[path] = facts
            file_nodes.append(FileNode(path, "python", digest, status, size))
            if status != "ok":
                not_analyzed[path] = status
        else:
            script_facts[path] = raw
            file_nodes.append(FileNode(path, "script", digest, "ok", size))

    resolver = _Resolver(py_facts, all_py, not_analyzed)
    imports, definitions, calls, refs, entries = resolver.build()
    script_edges = _script_edges(script_facts, all_scripts, files, not_analyzed)

    incomplete_sorted = tuple(sorted(
        incomplete, key=lambda item: (item.reason, item.path or "", item.detail or ""),
    ))
    stats = _stats(file_nodes, imports, definitions, calls, refs, entries, script_edges)
    graph = Graph(
        limits=limits, files=tuple(sorted(file_nodes, key=lambda item: item.path)), imports=imports,
        definitions=definitions, calls=calls, refs=refs, entries=entries, script_imports=script_edges,
        incomplete=incomplete_sorted, stats=stats,
    )
    graph.digest = digest_json(graph.to_dict())
    return graph


def graph_json(graph: Graph) -> bytes:
    """Canonical bytes of the graph with its digest: identical for identical repository state."""
    return canonical_bytes({"digest": graph.digest, **graph.to_dict()})


# ---- resolution -----------------------------------------------------------------------------


class _Resolver:
    def __init__(self, facts: dict[str, FileFacts], all_py: set[str], not_analyzed: dict[str, str]) -> None:
        self.facts = facts
        self.all_py = all_py
        self.not_analyzed = not_analyzed
        self.package_dirs = {posixpath.dirname(path) for path in all_py if posixpath.basename(path) == "__init__.py"}
        self.roots = self._roots()
        self.name_index: dict[str, set[str]] = {}
        self.dir_index: dict[str, set[str]] = {}
        self.all_dirs: set[str] = set()
        self._index_modules()
        # Definitions
        self.records: list[DefRec] = []
        self.by_qual: dict[tuple[str, str], list[DefRec]] = {}
        self.children: dict[tuple[str, str], dict[str, list[DefRec]]] = {}
        self._index_definitions()
        self._module_memo: dict[tuple[str, str], Tgt] = {}
        self._import_memo: dict[tuple[str, int], Tgt] = {}
        self._subclasses: dict[tuple[str, str], list[tuple[str, str]]] | None = None
        self._exports_memo: dict[str, frozenset[str] | None] = {}

    # ---- module index ---------------------------------------------------------------------

    def _roots(self) -> set[str]:
        roots = {""}
        for path in self.all_py:
            directory = posixpath.dirname(path)
            if directory in self.package_dirs:
                top = directory
                while top and top in self.package_dirs:
                    top = posixpath.dirname(top)
                roots.add(top)
        for conventional in ("src", "lib"):
            if conventional not in self.package_dirs and any(item.startswith(conventional + "/") for item in self.all_py):
                roots.add(conventional)
        return roots

    def _index_modules(self) -> None:
        for path in self.all_py:
            directory = posixpath.dirname(path)
            while True:
                self.all_dirs.add(directory)
                if not directory:
                    break
                directory = posixpath.dirname(directory)
            for root in self.roots:
                if root and not path.startswith(root + "/"):
                    continue
                relative = path[len(root) + 1:] if root else path
                dotted, _ = module_name_parts(relative)
                if dotted and all(part.isidentifier() for part in dotted.split(".")):
                    self.name_index.setdefault(dotted, set()).add(path)
        for directory in self.all_dirs:
            if not directory or directory in self.package_dirs:
                continue
            for root in self.roots:
                if directory == root or (root and not directory.startswith(root + "/")):
                    continue
                relative = directory[len(root) + 1:] if root else directory
                if all(part.isidentifier() for part in relative.split("/")):
                    self.dir_index.setdefault(relative.replace("/", "."), set()).add(directory)

    def _file_target(self, path: str) -> Tgt:
        if path in self.not_analyzed:
            return _unresolved("target_not_analyzed")
        return Tgt("module", path)

    def abs_module(self, importer: str, dotted: str) -> Tgt:
        candidates = set(self.name_index.get(dotted, ()))
        directory = posixpath.dirname(importer)
        sibling = ""
        if directory and directory not in self.package_dirs:
            # A script folder: its own folder is on the import path when a file there runs.
            sibling = directory + "/" + dotted.replace(".", "/")
            candidates.update(item for item in (sibling + ".py", sibling + "/__init__.py") if item in self.all_py)
        if len(candidates) == 1:
            return self._file_target(next(iter(candidates)))
        if len(candidates) > 1:
            return _unresolved("ambiguous_module")
        namespaces = set(self.dir_index.get(dotted, ()))
        if sibling and sibling in self.all_dirs and sibling not in self.package_dirs:
            namespaces.add(sibling)
        if len(namespaces) == 1:
            return Tgt("namespace", next(iter(namespaces)))
        if len(namespaces) > 1:
            return _unresolved("ambiguous_module")
        top = dotted.split(".")[0]
        if top in self.name_index or top in self.dir_index:
            return _unresolved("missing_submodule")
        if top in STDLIB:
            return _unresolved("stdlib", external=True)
        return _unresolved("third_party", external=True)

    def rel_module(self, importer: str, level: int, module: str) -> Tgt:
        base = posixpath.dirname(importer)
        for _ in range(level - 1):
            if not base:
                return _unresolved("relative_beyond_root")
            base = posixpath.dirname(base)
        if not base and "" not in self.package_dirs:
            # The repository root is not a package: there is nothing above the top package.
            return _unresolved("relative_beyond_root")
        if module:
            relative = posixpath.join(base, module.replace(".", "/"))
            found = [item for item in (relative + ".py", relative + "/__init__.py") if item in self.all_py]
        else:
            relative = base
            found = [relative + "/__init__.py" if relative else "__init__.py"]
            found = [item for item in found if item in self.all_py]
        if len(found) == 1:
            return self._file_target(found[0])
        if len(found) > 1:
            return _unresolved("ambiguous_module")
        if relative in self.all_dirs:
            return Tgt("namespace", relative)
        return _unresolved("relative_import_not_found")

    def from_module(self, importer: str, imp: RawImport) -> Tgt:
        if imp.level:
            return self.rel_module(importer, imp.level, imp.module)
        return self.abs_module(importer, imp.module)

    def child_module(self, directory: str, name: str) -> Tgt | None:
        found = [item for item in (posixpath.join(directory, name + ".py"), posixpath.join(directory, name, "__init__.py"))
                 if item in self.all_py]
        if len(found) == 1:
            return self._file_target(found[0])
        if len(found) > 1:
            return _unresolved("ambiguous_module")
        sub = posixpath.join(directory, name)
        if sub in self.all_dirs and sub not in self.package_dirs:
            return Tgt("namespace", sub)
        return None

    # ---- definitions ----------------------------------------------------------------------

    def _index_definitions(self) -> None:
        for path in sorted(self.facts):
            counts: dict[str, int] = {}
            for raw in self.facts[path].defs:
                counts[raw.qualname] = counts.get(raw.qualname, 0) + 1
            for raw in self.facts[path].defs:
                stub = any(name.rsplit(".", 1)[-1] in STUB_DECORATORS for name in raw.decorators)
                identity = f"{path}::{raw.qualname}"
                if counts[raw.qualname] > 1:
                    identity += f"@{raw.line}"
                record = DefRec(identity, path, raw, stub)
                self.records.append(record)
                if stub:
                    continue  # `@overload` signatures and property accessors never make a name ambiguous
                self.by_qual.setdefault((path, raw.qualname), []).append(record)
                if raw.parent is not None:
                    self.children.setdefault((path, raw.parent), {}).setdefault(
                        raw.qualname.rsplit(".", 1)[-1], []).append(record)

    def unique(self, path: str, qualname: str) -> DefRec | None:
        found = self.by_qual.get((path, qualname), [])
        return found[0] if len(found) == 1 else None

    # ---- names ----------------------------------------------------------------------------

    def module_name(self, path: str, name: str, stack: frozenset[tuple[str, str]] = frozenset()) -> Tgt:
        """What `name` means at the top level of the module `path`."""
        key = (path, name)
        if not stack and key in self._module_memo:
            return self._module_memo[key]
        result = self._module_name(path, name, stack)
        if not stack and result.reason != "import_cycle":
            self._module_memo[key] = result
        return result

    def _module_name(self, path: str, name: str, stack: frozenset[tuple[str, str]]) -> Tgt:
        key = (path, name)
        if key in stack:
            return _unresolved("import_cycle")
        if len(stack) > MAX_RESOLUTION_DEPTH:
            return _unresolved("reexport_depth_limit")
        facts = self.facts.get(path)
        if facts is None:
            return _unresolved("target_not_analyzed")
        inner = stack | {key}
        bindings = facts.bindings.get(name)
        if bindings:
            targets = [self._binding(path, name, item.kind, item.ref, inner) for item in bindings]
            first = targets[0]
            if all(item == first for item in targets):
                return first
            return _unresolved("rebound_name")
        return self._star_name(path, facts, name, inner)

    def _star_name(self, path: str, facts: FileFacts, name: str, stack: frozenset[tuple[str, str]]) -> Tgt:
        stars = [item for item in facts.imports if item.kind == "star" and item.scope == ""]
        if not stars:
            return _unresolved("unbound_name")
        found: list[Tgt] = []
        unknown = False
        for star in stars:
            module = self.from_module(path, star)
            if module.kind != "module":
                unknown = True
                continue
            exported = self.exports(module.path, frozenset())
            if exported is None:
                unknown = True
                continue
            if name in exported:
                target = self.module_name(module.path, name, stack)
                found.append(replace(target, via_star=True) if target.kind != "unresolved" else target)
        distinct = set(found)
        if len(distinct) == 1:
            return found[0]
        if len(distinct) > 1:
            return _unresolved("ambiguous_star_import")
        return _unresolved("star_import" if unknown else "unbound_name")

    def exports(self, path: str, visiting: frozenset[str]) -> frozenset[str] | None:
        """Names a star import of `path` binds, or None when they cannot be listed."""
        if not visiting and path in self._exports_memo:
            return self._exports_memo[path]
        result = self._exports(path, visiting)
        if not visiting:
            self._exports_memo[path] = result
        return result

    def _exports(self, path: str, visiting: frozenset[str]) -> frozenset[str] | None:
        facts = self.facts.get(path)
        if facts is None or path in visiting:
            return None
        if facts.all_names == "dynamic":
            return None
        if isinstance(facts.all_names, tuple):
            return frozenset(facts.all_names)
        names = {name for name in facts.bindings if not name.startswith("_")}
        for star in facts.imports:
            if star.kind != "star" or star.scope != "":
                continue
            module = self.from_module(path, star)
            if module.kind != "module":
                return None
            nested = self.exports(module.path, visiting | {path})
            if nested is None:
                return None
            names |= nested
        return frozenset(names)

    def _binding(self, path: str, name: str, kind: str, ref: Any, stack: frozenset[tuple[str, str]]) -> Tgt:
        if kind in ("def", "class"):
            records = self.by_qual.get((path, str(ref)), [])
            if len(records) != 1:
                return _unresolved("rebound_name")
            return Tgt("class" if kind == "class" else "def", path, str(ref))
        if kind == "import":
            return self.import_binding(path, int(ref), stack)
        if kind == "assign" and ref:
            return Tgt("const", path, name)
        return Tgt("other", path, name)

    def import_binding(self, path: str, index: int, stack: frozenset[tuple[str, str]] = frozenset()) -> Tgt:
        key = (path, index)
        if not stack and key in self._import_memo:
            return self._import_memo[key]
        facts = self.facts[path]
        imp = facts.imports[index]
        if imp.kind == "import":
            if imp.alias:
                result = self.abs_module(path, imp.module)
            else:
                result = self.abs_module(path, imp.module.split(".")[0])
        elif imp.kind == "from":
            module = self.from_module(path, imp)
            result = module if module.kind == "unresolved" else self.member(module, imp.name, stack)
        else:
            result = _unresolved("star_import")
        if not stack and result.reason != "import_cycle":
            self._import_memo[key] = result
        return result

    def member(self, module: Tgt, name: str, stack: frozenset[tuple[str, str]] = frozenset()) -> Tgt:
        """`module.name`: a name the module binds, else a submodule."""
        if module.kind == "module":
            found = self.module_name(module.path, name, stack)
            # `from pkg import sub` inside pkg/__init__.py (or a name only re-imported in a cycle):
            # Python falls back to importing the submodule.
            if found.kind == "unresolved" and found.reason in ("unbound_name", "import_cycle"):
                if posixpath.basename(module.path) == "__init__.py":
                    sub = self.child_module(posixpath.dirname(module.path), name)
                    if sub is not None:
                        return sub
                if found.reason == "import_cycle":
                    return found
                return _unresolved("symbol_not_found")
            return found
        if module.kind == "namespace":
            sub = self.child_module(module.path, name)
            return sub if sub is not None else _unresolved("symbol_not_found")
        return _unresolved("dynamic_receiver")

    def chain_at_module(self, path: str, chain: tuple[str, ...], stack: frozenset[tuple[str, str]] = frozenset()) -> Tgt:
        start = self.module_name(path, chain[0], stack)
        if start.kind == "unresolved" and start.reason == "unbound_name" and chain[0] in BUILTIN_NAMES:
            start = _unresolved("builtin", external=True)
        target, _ = self.walk(start, chain[1:], stack)
        return target

    def walk(self, start: Tgt, attrs: tuple[str, ...], stack: frozenset[tuple[str, str]] = frozenset()) -> tuple[Tgt, bool]:
        """Follow `.attr` steps. The flag says the last step looked a member up on a class."""
        current = start
        via_class = False
        for attr in attrs:
            if current.kind in ("module", "namespace"):
                current = self.member(current, attr, stack)
                via_class = False
            elif current.kind == "class":
                current = self.class_member(current, attr, frozenset())
                via_class = True
            elif current.kind == "unresolved":
                return current, False
            else:
                return _unresolved("dynamic_receiver"), False
            if current.kind == "unresolved":
                return current, False
        return current, via_class

    def class_member(self, cls: Tgt, name: str, seen: frozenset[tuple[str, str]]) -> Tgt:
        key = (cls.path, cls.qual)
        if key in seen or len(seen) > MAX_RESOLUTION_DEPTH:
            return _unresolved("cyclic_bases")
        own = self.children.get(key, {}).get(name)
        if own:
            if len(own) > 1:
                return _unresolved("rebound_name")
            record = own[0]
            return Tgt("class" if record.raw.kind == "class" else "def", record.path, record.raw.qualname)
        record_class = self.unique(cls.path, cls.qual)
        if record_class is None:
            return _unresolved("rebound_name")
        for base in record_class.raw.bases:
            if base is None:
                return _unresolved("unresolved_base")
            if base == ("object",):
                continue
            resolved = self.chain_at_module(cls.path, base)
            if resolved.kind != "class":
                return _unresolved("external_base" if resolved.external or resolved.reason == "builtin" else "unresolved_base",
                                   external=resolved.external)
            found = self.class_member(resolved, name, seen | {key})
            if found.kind != "unresolved" or found.reason != "attribute_not_found":
                return found
        return _unresolved("attribute_not_found")

    def subclasses(self) -> dict[tuple[str, str], list[tuple[str, str]]]:
        if self._subclasses is None:
            found: dict[tuple[str, str], list[tuple[str, str]]] = {}
            for record in self.records:
                if record.raw.kind != "class":
                    continue
                for base in record.raw.bases:
                    if base is None or base == ("object",):
                        continue
                    resolved = self.chain_at_module(record.path, base)
                    if resolved.kind == "class":
                        found.setdefault((resolved.path, resolved.qual), []).append((record.path, record.raw.qualname))
            self._subclasses = found
        return self._subclasses

    def overridden(self, cls: Tgt, name: str) -> bool:
        pending = list(self.subclasses().get((cls.path, cls.qual), ()))
        seen: set[tuple[str, str]] = set()
        while pending:
            key = pending.pop()
            if key in seen:
                continue
            seen.add(key)
            if name in self.children.get(key, {}):
                return True
            pending.extend(self.subclasses().get(key, ()))
        return False

    def literal_constant(self, path: str, name: str, depth: int = 0) -> bool:
        """`name` is bound exactly once, to a literal, and never rebound through `global`."""
        facts = self.facts.get(path)
        if facts is None or depth > MAX_RESOLUTION_DEPTH:
            return False
        bindings = facts.bindings.get(name, [])
        if len(bindings) != 1 or name in facts.global_names:
            return False
        binding = bindings[0]
        if binding.kind == "assign":
            return bool(binding.ref)
        if binding.kind == "import":
            target = self.import_binding(path, int(binding.ref))
            return target.kind == "const" and self.literal_constant(target.path, target.qual, depth + 1)
        return False

    # ---- output ---------------------------------------------------------------------------

    def build(self) -> tuple[tuple[ImportEdge, ...], tuple[Definition, ...], tuple[CallEdge, ...],
                             tuple[RefEdge, ...], tuple[EntryPointNode, ...]]:
        imports: list[ImportEdge] = []
        calls: list[CallEdge] = []
        refs: list[RefEdge] = []
        for path in sorted(self.facts):
            facts = self.facts[path]
            for index, imp in enumerate(facts.imports):
                imports.append(self._import_edge(path, index, imp))
            for raw_call in facts.calls:
                calls.append(self._call_edge(path, facts, raw_call))
            for raw_ref in facts.refs:
                edge = self._ref_edge(path, raw_ref)
                if edge is not None:
                    refs.append(edge)
        definitions = tuple(sorted((self._definition(record) for record in self.records),
                                   key=lambda item: (item.path, item.line, item.qualname, item.id)))
        entries = []
        for record in self.records:
            if record.raw.analyzer_entry is not None:
                entries.append(EntryPointNode(record.id, record.raw.analyzer_entry, "analyzer", record.raw.mutating))
            elif record.raw.class_view:
                entries.append(EntryPointNode(record.id, "class_view", "graph", False))
        imports.sort(key=lambda item: (item.importer, item.line, item.kind, item.module, item.name, item.alias or "", item.scope))
        calls.sort(key=lambda item: (item.caller, item.line, item.column, item.callee))
        refs.sort(key=lambda item: (item.source, item.line, item.target))
        entries.sort(key=lambda item: item.definition)
        return tuple(imports), definitions, tuple(calls), tuple(refs), tuple(entries)

    def _definition(self, record: DefRec) -> Definition:
        raw = record.raw
        parent: str | None = None
        if raw.parent is not None:
            parents = self.by_qual.get((record.path, raw.parent), [])
            parent = parents[0].id if parents else None
        return Definition(
            id=record.id, path=record.path, qualname=raw.qualname, kind=raw.kind,  # type: ignore[arg-type]
            is_async=raw.is_async, line=raw.line, end_line=raw.end_line, parent=parent, params=raw.params,
            decorators=raw.decorators,
            bases=tuple(".".join(base) if base else "<expression>" for base in raw.bases),
            static=raw.static, analysis_unit=raw.analysis_unit, analyzer_entry=raw.analyzer_entry, sinks=raw.sinks,
        )

    def _import_edge(self, path: str, index: int, imp: RawImport) -> ImportEdge:
        written = "." * imp.level + imp.module
        if imp.kind == "import":
            module = self.abs_module(path, imp.module)
            return ImportEdge(
                path, imp.line, imp.scope, "import", written, "", imp.alias,
                module.path if module.kind != "unresolved" else None,
                "resolved" if module.kind != "unresolved" else "unresolved",
                module.reason or None, module.external,
            )
        module = self.from_module(path, imp)
        if module.kind == "unresolved":
            return ImportEdge(path, imp.line, imp.scope, imp.kind, written, imp.name, imp.alias,  # type: ignore[arg-type]
                              None, "unresolved", module.reason, module.external)
        if imp.kind == "star":
            listed = module.kind == "module" and self.exports(module.path, frozenset()) is not None
            reason = None if listed else "star_import"
            return ImportEdge(path, imp.line, imp.scope, "star", written, "", None, module.path,
                              "resolved" if listed else "unresolved", reason)
        bound = self.import_binding(path, index)
        if bound.kind == "unresolved":
            return ImportEdge(path, imp.line, imp.scope, "from", written, imp.name, imp.alias, module.path,
                              "unresolved", bound.reason, bound.external)
        target = bound.path if bound.kind in ("module", "namespace") else module.path
        return ImportEdge(path, imp.line, imp.scope, "from", written, imp.name, imp.alias, target, "resolved")

    def _caller_id(self, path: str, caller: str) -> str:
        if caller == MODULE_SUFFIX:
            return f"{path}::{MODULE_SUFFIX}"
        records = self.by_qual.get((path, caller), [])
        return records[0].id if records else f"{path}::{caller}"

    def _arguments(self, path: str, args: tuple[ArgFact, ...]) -> tuple[ArgFact, ...]:
        result = []
        for arg in args:
            if arg.cls == "constant" and arg.const_refs:
                if all(self.literal_constant(path, name) for name in arg.const_refs):
                    arg = replace(arg, const_refs=())
                else:
                    arg = replace(arg, cls="unknown", const_refs=(), reason="constant_not_resolved")
            result.append(arg)
        return tuple(result)

    def _resolve(self, path: str, chain: tuple[str, ...], binding: tuple[str, Any]) -> tuple[Tgt, bool, bool]:
        """(target, looked up on a class, reached through `self`/`cls`)."""
        kind, ref = binding
        if kind == "local":
            return _unresolved("local_binding" if len(chain) == 1 else "dynamic_receiver"), False, False
        if kind == "self":
            class_qual, _ = ref
            if len(chain) != 2:
                return _unresolved("dynamic_receiver"), False, False
            cls = Tgt("class", path, class_qual)
            member = self.class_member(cls, chain[1], frozenset())
            if member.kind in ("def", "class") and self.overridden(cls, chain[1]):
                return _unresolved("overridden_in_subclass"), True, True
            return member, True, True
        if kind == "local_def":
            record = self.unique(path, str(ref))
            if record is None:
                return _unresolved("rebound_name"), False, False
            start = Tgt("class" if record.raw.kind == "class" else "def", path, record.raw.qualname)
        elif kind == "local_import":
            start = self.import_binding(path, int(ref))
        else:
            start = self.module_name(path, chain[0])
            if start.kind == "unresolved" and start.reason == "unbound_name" and chain[0] in BUILTIN_NAMES:
                start = _unresolved("builtin", external=True)
        target, via_class = self.walk(start, chain[1:])
        return target, via_class, False

    def _call_edge(self, path: str, facts: FileFacts, call: RawCall) -> CallEdge:
        caller = self._caller_id(path, call.caller)
        args = self._arguments(path, call.args)
        if call.chain is None:
            callee = f"<expr>.{call.last}" if call.last else "<expression>"
            reason = "dynamic_receiver" if call.last else "not_a_name"
            return CallEdge(caller, call.line, call.column, callee, "unresolved", reason=reason, args=args)
        callee = ".".join(call.chain)
        target, via_class, via_self = self._resolve(path, call.chain, call.binding)
        if target.kind == "unresolved":
            return CallEdge(caller, call.line, call.column, callee, "unresolved", reason=target.reason,
                            external=target.external or target.reason in EXTERNAL_REASONS, args=args)
        if target.kind == "def":
            record = self.unique(target.path, target.qual)
            if record is None:
                return CallEdge(caller, call.line, call.column, callee, "unresolved", reason="rebound_name", args=args)
            raw = record.raw
            names = raw.decorators
            classmethod_ = "classmethod" in names
            bound = (via_self and not raw.static) or (via_class and classmethod_)
            return CallEdge(
                caller, call.line, call.column, callee, "resolved", record.id,
                "method" if raw.kind == "method" else "function", bound_first=bound, via_star=target.via_star,
                opaque=_opaque(names), args=args,
            )
        if target.kind == "class":
            return self._constructor(caller, call, callee, target, args)
        reason = "module_not_callable" if target.kind in ("module", "namespace") else "assigned_value"
        return CallEdge(caller, call.line, call.column, callee, "unresolved", reason=reason, args=args)

    def _constructor(self, caller: str, call: RawCall, callee: str, target: Tgt, args: tuple[ArgFact, ...]) -> CallEdge:
        init = self.class_member(target, "__init__", frozenset())
        if init.kind == "def":
            record = self.unique(init.path, init.qual)
            if record is not None:
                return CallEdge(caller, call.line, call.column, callee, "resolved", record.id, "constructor",
                                bound_first=True, via_star=target.via_star, opaque=_opaque(record.raw.decorators), args=args)
        if init.kind == "unresolved" and init.reason == "attribute_not_found":
            record = self.unique(target.path, target.qual)
            if record is not None:
                return CallEdge(caller, call.line, call.column, callee, "resolved", record.id, "class",
                                via_star=target.via_star, opaque=_opaque(record.raw.decorators), args=args)
        reason = init.reason or "unresolved_base"
        return CallEdge(caller, call.line, call.column, callee, "unresolved", reason=reason,
                        external=init.external, args=args)

    def _ref_edge(self, path: str, ref: Any) -> RefEdge | None:
        target, _, _ = self._resolve(path, ref.chain, ref.binding)
        if target.kind not in ("def", "class"):
            return None
        record = self.unique(target.path, target.qual)
        if record is None:
            return None
        return RefEdge(self._caller_id(path, ref.source), ref.line, record.id)


def _opaque(decorators: tuple[str, ...]) -> tuple[str, ...]:
    result = []
    for name in decorators:
        last = name.split(".")[-1]
        if last in TRANSPARENT_DECORATORS or last in VIEW_DECORATORS or (last in ROUTE_DECORATORS and "." in name):
            continue
        if AUTH_NAME.search(name):
            continue
        result.append(name)
    return tuple(result)


# ---- TypeScript / JavaScript (the thin graph) -------------------------------------------------


def _script_edges(
    script_facts: dict[str, list[RawScriptImport]], all_scripts: set[str], files: Mapping[str, str],
    not_analyzed: dict[str, str],
) -> tuple[ScriptImportEdge, ...]:
    aliases: dict[str, AliasConfig] = {}

    def read(path: str) -> str | None:
        return files.get(path)

    for path in sorted(files):
        if is_script_config(path):
            loaded = load_alias_config(path, read)
            if loaded is not None:
                aliases[path] = loaded
    edges: list[ScriptImportEdge] = []
    known = {item for item in all_scripts if item not in not_analyzed}
    for path in sorted(script_facts):
        config = next((aliases[item] for item in config_paths_for(path) if item in aliases), None)
        for raw in script_facts[path]:
            target, status, reason, external = resolve_script_import(path, raw, known, all_scripts, config)
            edges.append(ScriptImportEdge(path, raw.line, raw.kind, raw.specifier, target, status, reason, external))  # type: ignore[arg-type]
    edges.sort(key=lambda item: (item.importer, item.line, item.kind, item.specifier))
    return tuple(edges)


# ---- statistics ---------------------------------------------------------------------------------


def _count(items: Any, key: Any) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = key(item)
        counts[value] = counts.get(value, 0) + 1
    return dict(sorted(counts.items()))


def _stats(
    files: list[FileNode], imports: tuple[ImportEdge, ...], definitions: tuple[Definition, ...],
    calls: tuple[CallEdge, ...], refs: tuple[RefEdge, ...], entries: tuple[EntryPointNode, ...],
    script_edges: tuple[ScriptImportEdge, ...],
) -> dict[str, Any]:
    """Counts only (no timings), so the digest does not depend on how fast a machine is."""
    unresolved_imports = [edge for edge in imports if edge.status == "unresolved"]
    unresolved_calls = [edge for edge in calls if edge.status == "unresolved"]
    internal_calls = [edge for edge in unresolved_calls if not edge.external]
    internal_imports = [edge for edge in unresolved_imports if not edge.external]
    resolved_calls = len(calls) - len(unresolved_calls)
    edges = len(imports) + len(calls) + len(refs) + len(script_edges)
    unresolved_total = len(unresolved_imports) + len(unresolved_calls) + sum(
        1 for edge in script_edges if edge.status == "unresolved")
    internal_total = len(internal_imports) + len(internal_calls) + sum(
        1 for edge in script_edges if edge.status == "unresolved" and not edge.external)
    considered = len(imports) + len(calls) + len(script_edges)

    def ratio(numerator: int, denominator: int) -> float | None:
        return round(numerator / denominator, 4) if denominator else None

    return {
        "files": _count(files, lambda item: f"{item.language}:{item.status}"),
        "nodes": len(files) + len(definitions),
        "definitions": _count(definitions, lambda item: item.kind),
        "edges": edges,
        "imports": {
            "total": len(imports), "unresolved": len(unresolved_imports), "unresolved_external": len(unresolved_imports) - len(internal_imports),
            "unresolved_reasons": _count(unresolved_imports, lambda item: item.reason or ""),
        },
        "calls": {
            "total": len(calls), "resolved": resolved_calls, "unresolved": len(unresolved_calls),
            "unresolved_external": len(unresolved_calls) - len(internal_calls),
            "unresolved_reasons": _count(unresolved_calls, lambda item: item.reason or ""),
            "in_repo_resolution_rate": ratio(resolved_calls, resolved_calls + len(internal_calls)),
        },
        "refs": len(refs),
        "entry_points": {
            "total": len(entries), "by_source": _count(entries, lambda item: item.recognized_by),
            "by_kind": _count(entries, lambda item: item.kind),
        },
        "script_imports": {
            "total": len(script_edges),
            "unresolved": sum(1 for edge in script_edges if edge.status == "unresolved"),
            "unresolved_reasons": _count([e for e in script_edges if e.status == "unresolved"], lambda item: item.reason or ""),
        },
        "unresolved_edge_ratio": ratio(unresolved_total, considered),
        "unresolved_non_external_ratio": ratio(internal_total, considered),
        "sinks_with_parameter_origins": sum(len(item.sinks) for item in definitions),
    }

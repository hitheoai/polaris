"""The thin TypeScript / JavaScript graph for the spike: which file imports which file.

Only import specifiers are read (static `import`, `export ... from`, `require("x")`, `import("x")`).
Relative specifiers and `tsconfig`/`jsconfig` path aliases are resolved to files inside the
repository with the review analyzer's own alias reader; bare package names, Node built-ins and
asset files are recorded as external, and a computed specifier is an explicit unresolved edge.
There are no definitions or call edges for these languages yet.
"""

from __future__ import annotations

import posixpath
from dataclasses import dataclass
from typing import Any

from polaris.review.js.tsconfig import AliasConfig

SCRIPT_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts")
RESOLVE_EXTENSIONS = SCRIPT_SUFFIXES
CONFIG_NAMES = ("tsconfig.json", "jsconfig.json")
NODE_BUILTINS = frozenset({
    "assert", "async_hooks", "buffer", "child_process", "cluster", "console", "constants", "crypto", "dgram",
    "diagnostics_channel", "dns", "domain", "events", "fs", "fs/promises", "http", "http2", "https", "inspector",
    "module", "net", "os", "path", "path/posix", "perf_hooks", "process", "punycode", "querystring", "readline",
    "repl", "stream", "stream/promises", "string_decoder", "sys", "timers", "timers/promises", "tls",
    "trace_events", "tty", "url", "util", "v8", "vm", "wasi", "worker_threads", "zlib",
})


@dataclass(slots=True)
class RawScriptImport:
    line: int
    kind: str  # import | export_from | require | dynamic_import
    specifier: str  # "" when the specifier is computed


def is_script_config(path: str) -> bool:
    return posixpath.basename(path) in CONFIG_NAMES


def _string(node: Any) -> str | None:
    if node is None:
        return None
    if node.type == "string":
        return "".join(
            (child.text or b"").decode("utf-8", "replace")
            for child in node.named_children if child.type in ("string_fragment", "escape_sequence")
        )
    if node.type == "template_string" and not any(child.type == "template_substitution" for child in node.named_children):
        return "".join(
            (child.text or b"").decode("utf-8", "replace")
            for child in node.named_children if child.type in ("string_fragment", "escape_sequence")
        )
    return None


def extract_script_imports(path: str, text: str) -> list[RawScriptImport]:
    """Import specifiers of one file. A file that does not parse cleanly still yields what was found."""
    from tree_sitter import Parser

    from polaris.review.js.engine import _language, grammar_for

    tree = Parser(_language(grammar_for(path))).parse(text.encode("utf-8"))
    found: list[RawScriptImport] = []
    stack = [tree.root_node]
    while stack:
        node = stack.pop()
        kind = node.type
        line = int(node.start_point[0]) + 1
        if kind == "import_statement":
            source = node.child_by_field_name("source")
            if source is None:
                for child in node.named_children:
                    if child.type == "import_require_clause":
                        source = child.child_by_field_name("source")
            found.append(RawScriptImport(line, "import", _string(source) or ""))
            continue
        if kind == "export_statement":
            source = node.child_by_field_name("source")
            if source is not None:
                found.append(RawScriptImport(line, "export_from", _string(source) or ""))
                continue
        elif kind == "call_expression":
            function = node.child_by_field_name("function")
            arguments = node.child_by_field_name("arguments")
            name = (function.text or b"").decode("utf-8", "replace") if function is not None else ""
            if function is not None and (function.type == "import" or name == "require") and arguments is not None:
                first = next(iter(arguments.named_children), None)
                found.append(RawScriptImport(
                    line, "dynamic_import" if function.type == "import" else "require", _string(first) or "",
                ))
        stack.extend(reversed(node.children))
    found.sort(key=lambda item: (item.line, item.kind, item.specifier))
    return found


def _matches_paths(config: AliasConfig, specifier: str) -> bool:
    """Does the specifier match a `compilerOptions.paths` pattern (not only the baseUrl fallback)?"""
    for pattern, _ in config.paths:
        prefix, star, suffix = pattern.partition("*")
        if not star:
            if pattern == specifier:
                return True
        elif len(specifier) >= len(prefix) + len(suffix) and specifier.startswith(prefix) and specifier.endswith(suffix):
            return True
    return False


def _lookup(base: str, scripts: set[str]) -> str | None:
    if base in scripts:
        return base
    for extension in RESOLVE_EXTENSIONS:
        for candidate in (base + extension, f"{base}/index{extension}"):
            if candidate in scripts:
                return candidate
    stem, extension = posixpath.splitext(base)
    if extension in (".js", ".jsx", ".mjs", ".cjs"):
        for replacement in (".ts", ".tsx", ".mts", ".cts"):
            if stem + replacement in scripts:
                return stem + replacement
    return None


def resolve_script_import(
    importer: str, raw: RawScriptImport, known: set[str], all_scripts: set[str], config: AliasConfig | None,
) -> tuple[str | None, str, str | None, bool]:
    """(target file, status, reason, external) for one import."""
    specifier = raw.specifier.removeprefix("node:") if raw.specifier.startswith("node:") else raw.specifier
    if not raw.specifier:
        return None, "unresolved", "dynamic_specifier", False
    if raw.specifier.startswith("node:") or specifier in NODE_BUILTINS:
        return None, "unresolved", "node_builtin", True
    if specifier.startswith("/"):
        return None, "unresolved", "absolute_path", False
    candidates: list[str]
    if specifier.startswith("."):
        candidates = [posixpath.normpath(posixpath.join(posixpath.dirname(importer), specifier))]
        extension = posixpath.splitext(specifier)[1]
        if extension and extension not in SCRIPT_SUFFIXES and _lookup(candidates[0], all_scripts) is None:
            return None, "unresolved", "non_script_file", True
        missing = "relative_import_not_found"
    else:
        candidates = config.candidates(specifier) if config is not None else []
        if not candidates:
            return None, "unresolved", "external_package", True
        missing = "alias_target_not_found" if config is not None and _matches_paths(config, specifier) else "external_package"
    for candidate in candidates:
        found = _lookup(candidate, all_scripts)
        if found is not None:
            if found in known:
                return found, "resolved", None, False
            return None, "unresolved", "target_not_analyzed", False
    return None, "unresolved", missing, missing == "external_package"

"""Built-in Rust analyzer: tree-sitter syntax trees, function-local data flow, never compiled or run.

Entry points are Tauri commands (arguments come from the webview), axum/actix/rocket request
extractors and CLI arguments. Sinks: process execution (`Command::new` chains), SQL built with
`format!`, filesystem paths, outbound HTTP, secrets in output macros and disabled TLS checks.
"""

from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from polaris.jsonio import digest_json
from polaris.review import catalog, secrets
from polaris.review.analyzers.base import AnalysisInput, AnalyzerResult, language_for_path
from polaris.review.analyzers.evidence import make_finding, step
from polaris.review.models import (
    AnalyzerCapability,
    CheckCoverage,
    CoverageStatus,
    SourceFile,
    WorkflowFinding,
)

ANALYZER_ID = "polaris-rust"
VERSION = "polaris-rust/0.1.0"
CHECKS = ("command_injection", "sql_injection", "path_traversal", "ssrf", "secret_exposure",
          "unsafe_security_configuration")
LIMITATIONS = [
    "Function-local data flow; macros other than format!/println!/log macros are opaque.",
    "Entry points: #[tauri::command], axum/actix/rocket extractors and std::env::args.",
    "XSS, open redirect, code injection, authorization and crypto checks are not implemented for Rust yet.",
]
# axum/actix extractors. The generic forms only: a plain `&Path`/`PathBuf` is std::path, not input.
EXTRACTOR = re.compile(r"\b(Query|Path|Json|Form|TypedHeader)\s*<|\b(Multipart|RawQuery|HttpRequest|RawForm)\b")
NOT_INPUT = re.compile(r"\b(State|AppHandle|Window|WebviewWindow|Webview|Extension|Data|Pool|DbConn|Arc|Mutex|Sender|Config)\b")
ROUTE_ATTRIBUTE = re.compile(r"^#\[(tauri::command|command|get|post|put|patch|delete|route|actix_web::(get|post|put|delete|patch)|rocket::(get|post|put|delete|patch))\b")
SHELLS = frozenset({"sh", "bash", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"})
OPTION_PROGRAMS = frozenset({"git", "ssh", "scp", "rsync", "curl", "wget", "tar", "zip", "unzip", "find", "ffmpeg",
                             "convert", "magick", "npm", "npx", "docker", "kubectl", "psql", "mysql", "sqlite3", "gpg"})
FS_FUNCTIONS = frozenset({
    "read", "read_to_string", "write", "remove_file", "remove_dir", "remove_dir_all", "create_dir",
    "create_dir_all", "copy", "rename", "read_dir", "metadata", "open", "create", "hard_link", "symlink",
})
SQL_FUNCTIONS = frozenset({"query", "query_as", "query_scalar", "execute", "prepare", "sql_query", "query_row",
                           "batch_execute", "simple_query", "query_one", "query_opt"})
SQL_KEYWORDS = re.compile(r"(?i)\b(select|insert|update|delete|from|where|values|join|into|order\s+by)\b")
OUTPUT_MACROS = frozenset({"println", "eprintln", "print", "eprint", "info", "warn", "error", "debug", "trace", "dbg"})
PROPAGATE = frozenset({
    "to_string", "clone", "as_str", "trim", "to_owned", "into", "unwrap", "expect", "unwrap_or", "unwrap_or_default",
    "as_ref", "borrow", "join", "to_lowercase", "to_uppercase", "replace", "as_path", "display", "to_str",
    "to_string_lossy", "into_inner", "get", "nth", "next", "collect", "concat", "push_str",
})
SECRET_ENV = re.compile(r"(?i)(secret|token|password|passwd|private|api_?key|access_?key|credential)")


@dataclass
class RValue:
    origins: list[tuple[str, int, str]] = field(default_factory=list)  # (kind, line, label)
    literal: str | None = None
    kind: str = "unknown"            # command, format, literal, path
    program: str | None = None
    program_origins: list[tuple[str, int, str]] = field(default_factory=list)
    args: list[RValue] = field(default_factory=list)
    text: str = ""
    sql_text: str = ""

    @property
    def tainted(self) -> bool:
        return bool(self.origins)


@dataclass(frozen=True)
class RHit:
    check: str
    rule_id: str
    line: int
    sink: str
    origins: tuple[tuple[str, int, str], ...]
    symbol: str


@lru_cache(maxsize=1)
def _language() -> Any:
    import tree_sitter_rust
    from tree_sitter import Language

    return Language(tree_sitter_rust.language())


def _text(node: Any) -> str:
    return node.text.decode("utf-8", "replace") if node is not None and node.text is not None else ""


def _named(node: Any) -> list[Any]:
    return [child for child in node.named_children if child.type not in ("line_comment", "block_comment")]


def _line(node: Any) -> int:
    return int(node.start_point[0]) + 1


def _string(node: Any) -> str | None:
    if node is None:
        return None
    if node.type == "string_literal":
        return "".join(_text(child) for child in node.named_children if child.type in ("string_content", "escape_sequence"))
    if node.type == "raw_string_literal":
        return re.sub(r'^r#*"|"#*$', "", _text(node))
    if node.type == "reference_expression":
        inner = node.child_by_field_name("value")
        return _string(inner)
    return None


def _rules() -> None:
    rs = "polaris.rust."
    catalog.rule(rs + "command_injection.executable", "command_injection", "Program chosen by input",
                 "Untrusted input chooses which program Command::new runs.",
                 "Map the input to a fixed allowlist of programs instead of running it.", severity="critical")
    catalog.rule(rs + "command_injection.shell", "command_injection", "Shell command built from input",
                 "Untrusted input reaches a `sh -c` style shell command.",
                 "Run the program directly with .arg()/.args() and no shell, and validate the values.", severity="critical")
    catalog.rule(rs + "command_injection.argument_injection", "command_injection", "Argument injection",
                 "An untrusted value is passed where the program can read it as an option.",
                 "Add .arg(\"--\") before user-supplied arguments and reject values starting with \"-\".",
                 severity="medium", cwe="CWE-88")
    catalog.rule(rs + "sql_injection", "sql_injection", "SQL built with format!",
                 "Untrusted input is formatted into SQL text.",
                 "Use bind parameters (sqlx::query(\"... WHERE id = $1\").bind(id), rusqlite params![]) instead of format!.")
    catalog.rule(rs + "path_traversal", "path_traversal", "File path built from input",
                 "Untrusted input chooses a filesystem path.",
                 "Join onto a fixed base, canonicalize, and reject results that don't start with the base directory.")
    catalog.rule(rs + "ssrf", "ssrf", "Request to a user-controlled URL",
                 "The program requests a URL derived from untrusted input.",
                 "Parse with url::Url and check the host against an allowlist before requesting.")
    catalog.rule(rs + "secret_exposure.output", "secret_exposure", "Secret written to output",
                 "A secret-named environment value is printed or logged.", "Never print or log credentials.")
    catalog.rule(rs + "secret_exposure.hardcoded", "secret_exposure", "Hardcoded credential",
                 "A credential appears to be hardcoded in source.",
                 "Load it from the environment or a secret manager and rotate the exposed key.")
    catalog.rule(rs + "tls_disabled", "unsafe_security_configuration", "TLS verification disabled",
                 "Certificate or hostname verification is disabled on an HTTP client.",
                 "Remove danger_accept_invalid_certs/hostnames and configure the correct root certificates.")


_rules()


def grammar_available() -> bool:
    try:
        _language()
        return True
    except (ImportError, OSError, ValueError, AttributeError, TypeError):
        return False


def capability() -> AnalyzerCapability:
    available = grammar_available()
    return AnalyzerCapability(
        analyzer_id=ANALYZER_ID, availability="available" if available else "unavailable",
        version=VERSION, expected_version=VERSION, rule_pack_version=VERSION,
        rule_pack_digest=digest_json({"version": VERSION, "rules": sorted(r for r in catalog.RULES if r.startswith("polaris.rust."))}),
        languages=["rust"], checks=list(CHECKS),
        provenance="Original Polaris tree-sitter rules (tree-sitter-rust: MIT)", license="Apache-2.0",
        reason="builtin_in_process" if available else "tree_sitter_unavailable", limitations=list(LIMITATIONS),
    )


class _Function:
    def __init__(self, file: _File, node: Any, symbol: str, entry: bool) -> None:
        self.file = file
        self.node = node
        self.symbol = symbol
        self.entry = entry
        self.env: dict[str, RValue] = {}
        self.hits: list[RHit] = []

    def run(self) -> None:
        params = self.node.child_by_field_name("parameters")
        for param in _named(params) if params is not None else []:
            if param.type != "parameter":
                continue
            pattern = param.child_by_field_name("pattern")
            kind = param.child_by_field_name("type")
            type_text = _text(kind)
            tainted = self.entry and not NOT_INPUT.search(type_text) or bool(EXTRACTOR.search(type_text))
            if NOT_INPUT.search(type_text):
                tainted = False
            value = RValue(origins=[("request", _line(param), _text(pattern) or "argument")] if tainted else [],
                           text=_text(pattern))
            self._bind(pattern, value)
        body = self.node.child_by_field_name("body")
        if body is not None:
            self._block(body)

    def _bind(self, pattern: Any, value: RValue) -> None:
        if pattern is None:
            return
        if pattern.type == "identifier":
            self.env[_text(pattern)] = value
        elif pattern.type in ("tuple_struct_pattern", "tuple_pattern", "struct_pattern", "mut_pattern",
                              "ref_pattern", "reference_pattern"):
            for child in _named(pattern):
                if child.type in ("identifier", "tuple_struct_pattern", "tuple_pattern", "struct_pattern",
                                  "mut_pattern", "field_pattern", "ref_pattern", "shorthand_field_identifier"):
                    if child.type == "identifier" and child == pattern.child_by_field_name("type"):
                        continue
                    self._bind(child, RValue(origins=list(value.origins), text=_text(child)))
        elif pattern.type == "field_pattern":
            inner = pattern.child_by_field_name("pattern")
            if inner is not None:
                self._bind(inner, value)
            else:
                for child in _named(pattern):
                    if child.type == "shorthand_field_identifier":
                        self.env[_text(child)] = value
        elif pattern.type == "shorthand_field_identifier":
            self.env[_text(pattern)] = value

    def _block(self, node: Any) -> None:
        for child in _named(node):
            if child.type == "let_declaration":
                value_node = child.child_by_field_name("value")
                value = self.ev(value_node) if value_node is not None else RValue()
                self._bind(child.child_by_field_name("pattern"), value)
            else:
                self.ev(child)

    def ev(self, node: Any) -> RValue:
        if node is None:
            return RValue()
        kind = node.type
        if kind == "identifier":
            return self.env.get(_text(node), RValue(text=_text(node)))
        if kind in ("string_literal", "raw_string_literal"):
            value = _string(node) or ""
            return RValue(literal=value, kind="literal", text=_text(node), sql_text=value)
        if kind in ("reference_expression", "unary_expression", "parenthesized_expression", "try_expression",
                    "await_expression", "type_cast_expression"):
            inner = node.child_by_field_name("value") or next(iter(_named(node)), None)
            return self.ev(inner)
        if kind == "field_expression":
            base = self.ev(node.child_by_field_name("value"))
            return RValue(origins=list(base.origins), text=_text(node))
        if kind == "index_expression":
            # params["cmd"] carries the container's origin; a tainted index into a fixed table doesn't.
            parts = _named(node)
            container = self.ev(parts[0]) if parts else RValue()
            for part in parts[1:]:
                self.ev(part)
            return RValue(origins=list(container.origins), text=_text(node)[:80])
        if kind == "macro_invocation":
            return self._macro(node)
        if kind == "call_expression":
            return self._call(node)
        if kind in ("block", "unsafe_block", "async_block"):
            self._block(node if kind == "block" else next(iter(_named(node)), node))
            return RValue()
        if kind in ("if_expression", "match_expression", "while_expression", "loop_expression", "for_expression"):
            for child in _named(node):
                if child.type in ("block",):
                    self._block(child)
                elif child.type == "match_block":
                    for arm in _named(child):
                        for part in _named(arm):
                            self.ev(part)
                elif child.type == "else_clause":
                    for part in _named(child):
                        self.ev(part)
                else:
                    self.ev(child)
            return RValue()
        if kind == "assignment_expression":
            left = node.child_by_field_name("left")
            assigned = self.ev(node.child_by_field_name("right"))
            if left is not None and left.type == "identifier":
                self.env[_text(left)] = assigned
            return assigned
        if kind == "expression_statement":
            for child in _named(node):
                self.ev(child)
            return RValue()
        if kind == "binary_expression":
            left = self.ev(node.child_by_field_name("left"))
            right = self.ev(node.child_by_field_name("right"))
            return RValue(origins=left.origins + right.origins, text=_text(node), sql_text=left.sql_text + right.sql_text)
        if kind in ("array_expression", "tuple_expression"):
            items = [self.ev(child) for child in _named(node)]
            return RValue(origins=[origin for item in items for origin in item.origins], kind="array", args=items,
                          text=_text(node)[:80])
        for child in _named(node):
            self.ev(child)
        return RValue(text=_text(node)[:80])

    def _macro(self, node: Any) -> RValue:
        macro = node.child_by_field_name("macro")
        name = _text(macro).split("::")[-1]
        tree = next((child for child in _named(node) if child.type == "token_tree"), None)
        origins: list[tuple[str, int, str]] = []
        literal_parts: list[str] = []
        secret: list[tuple[str, int, str]] = []
        if tree is not None:
            for token in self._tokens(tree):
                if token.type == "identifier" and _text(token) in self.env:
                    origins.extend(self.env[_text(token)].origins)
                elif token.type == "string_literal":
                    literal_parts.append(_string(token) or "")
            joined = _text(tree)
            for match in re.finditer(r"env::var\(\s*\"([A-Z0-9_]+)\"", joined):
                if SECRET_ENV.search(match.group(1)):
                    secret.append(("secret_env", _line(node), f"env::var(\"{match.group(1)}\")"))
            for token in self._tokens(tree):
                if token.type == "identifier" and _text(token) in self.env:
                    secret.extend(origin for origin in self.env[_text(token)].origins if origin[0] == "secret_env")
        if name in OUTPUT_MACROS and secret:
            self.hits.append(RHit("secret_exposure", "polaris.rust.secret_exposure.output", _line(node), f"{name}!(…)",
                                  tuple(secret[:2]), self.symbol))
        return RValue(origins=[origin for origin in origins if origin[0] != "secret_env"], kind="format",
                      text=_text(node)[:120], sql_text=" ? ".join(literal_parts))

    def _tokens(self, node: Any) -> list[Any]:
        found: list[Any] = []
        stack = [node]
        while stack and len(found) < 2_000:
            current = stack.pop()
            for child in current.children:
                if child.type == "token_tree":
                    stack.append(child)
                else:
                    found.append(child)
        return found

    def _call(self, node: Any) -> RValue:
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        args = [self.ev(item) for item in _named(arguments)] if arguments is not None else []
        name = _text(function)
        line = _line(node)
        if function is not None and function.type == "field_expression":
            receiver = self.ev(function.child_by_field_name("value"))
            method = _text(function.child_by_field_name("field"))
            return self._method(receiver, method, args, node, line)
        last = name.split("::")[-1]
        if name.endswith("Command::new") and args:
            self._program_hit(args[0], line)
            return RValue(kind="command", program=args[0].literal, program_origins=list(args[0].origins),
                          text=_text(node)[:80])
        if name in ("std::env::var", "env::var") and args and args[0].literal and SECRET_ENV.search(args[0].literal):
            return RValue(origins=[("secret_env", line, f"env::var(\"{args[0].literal}\")")], text=name)
        if name in ("std::env::args", "env::args"):
            return RValue(origins=[("argv", line, "env::args()")], text=name)
        if (name.startswith(("std::fs::", "fs::", "tokio::fs::")) or name.endswith(("File::open", "File::create"))) and last in FS_FUNCTIONS and args:
            self._hit("path_traversal", "polaris.rust.path_traversal", args[0], line, f"{name}(path)")
            if last in ("copy", "rename", "hard_link", "symlink") and len(args) > 1:
                self._hit("path_traversal", "polaris.rust.path_traversal", args[1], line, f"{name}(…, path)")
        if last in SQL_FUNCTIONS and args and args[0].kind == "format" and len(SQL_KEYWORDS.findall(args[0].sql_text)) >= 2:
            self._hit("sql_injection", "polaris.rust.sql_injection", args[0], line, f"{name}(sql)")
        if name in ("reqwest::get", "reqwest::blocking::get") and args:
            self._ssrf(args[0], line, name)
        if name.endswith(("PathBuf::from", "Path::new")) and args:
            return RValue(origins=list(args[0].origins), kind="path", text=_text(node)[:80])
        return RValue(origins=[origin for arg in args for origin in arg.origins] if last in ("from", "new", "format") else [],
                      text=_text(node)[:80])

    def _program_hit(self, program: RValue, line: int) -> None:
        if program.tainted:
            self._hit("command_injection", "polaris.rust.command_injection.executable", program, line, "Command::new(program)")

    def _method(self, receiver: RValue, method: str, args: list[RValue], node: Any, line: int) -> RValue:
        if receiver.kind == "command":
            if method == "arg" and args:
                return self._command_arg(receiver, [args[0]], line)
            if method == "args" and args:
                items = args[0].args if args[0].args else [args[0]]
                return self._command_arg(receiver, items, line)
            return receiver
        if method in ("danger_accept_invalid_certs", "danger_accept_invalid_hostnames") and args and args[0].text == "true":
            self.hits.append(RHit("unsafe_security_configuration", "polaris.rust.tls_disabled", line,
                                  f".{method}(true)", (), self.symbol))
        if method in ("get", "post", "put", "patch", "delete", "request") and args and self._http_receiver(node):
            self._ssrf(args[-1] if method == "request" else args[0], line, f".{method}(url)")
        if method in SQL_FUNCTIONS and args and args[0].kind == "format" and len(SQL_KEYWORDS.findall(args[0].sql_text)) >= 2:
            self._hit("sql_injection", "polaris.rust.sql_injection", args[0], line, f".{method}(sql)")
        if method in ("join", "push", "with_file_name") and receiver.kind == "path":
            return RValue(origins=receiver.origins + [o for a in args for o in a.origins], kind="path", text=receiver.text)
        if method in PROPAGATE:
            return RValue(origins=list(receiver.origins), kind=receiver.kind if receiver.kind == "path" else "unknown",
                          text=receiver.text, literal=receiver.literal)
        return RValue(text=receiver.text)

    def _http_receiver(self, node: Any) -> bool:
        function = node.child_by_field_name("function")
        receiver = _text(function.child_by_field_name("value")) if function is not None else ""
        return bool(re.search(r"(?i)(client|reqwest|http)", receiver))

    def _command_arg(self, command: RValue, items: list[RValue], line: int) -> RValue:
        args = [*command.args, *items]
        program = posixpath.basename(command.program or "")
        if program in SHELLS:
            shell_flag = any(item.literal in ("-c", "/C", "/c", "-Command") for item in command.args)
            for item in items:
                if shell_flag and item.tainted:
                    self._hit("command_injection", "polaris.rust.command_injection.shell", item, line, f"{program} -c …")
        elif program in OPTION_PROGRAMS and not any(item.literal == "--" for item in command.args):
            for item in items:
                if item.literal == "--":
                    break
                if item.tainted:
                    self._hit("command_injection", "polaris.rust.command_injection.argument_injection", item, line,
                              f"{program} argument")
                    break
        return RValue(kind="command", program=command.program, program_origins=command.program_origins, args=args,
                      text=command.text)

    def _ssrf(self, value: RValue, line: int, label: str) -> None:
        prefix = value.literal or ""
        if value.kind == "format":
            prefix = value.sql_text.split(" ? ")[0]
        if re.match(r"^https?://[^/?#\s]+[/?#]", prefix):
            return
        self._hit("ssrf", "polaris.rust.ssrf", value, line, label)

    def _hit(self, check: str, rule_id: str, value: RValue, line: int, sink: str) -> None:
        real = [origin for origin in value.origins if origin[0] in ("request", "argv")]
        if real:
            self.hits.append(RHit(check, rule_id, line, sink, tuple(real[:2]), self.symbol))


class _File:
    def __init__(self, source: SourceFile) -> None:
        from tree_sitter import Parser

        self.source = source
        self.tree = Parser(_language()).parse((source.after or "").encode("utf-8"))
        self.root = self.tree.root_node

    def functions(self) -> list[tuple[Any, str, bool]]:
        found: list[tuple[Any, str, bool]] = []
        stack: list[tuple[Any, str]] = [(self.root, "")]
        while stack:
            node, prefix = stack.pop()
            previous_attributes: list[str] = []
            for child in _named(node):
                if child.type == "attribute_item":
                    previous_attributes.append(_text(child))
                    continue
                if child.type == "function_item":
                    name = _text(child.child_by_field_name("name"))
                    entry = any(ROUTE_ATTRIBUTE.match(item) for item in previous_attributes)
                    found.append((child, prefix + name, entry))
                elif child.type in ("impl_item", "mod_item"):
                    body = child.child_by_field_name("body")
                    label = _text(child.child_by_field_name("type") or child.child_by_field_name("name"))
                    if body is not None:
                        stack.append((body, f"{label}::" if label else prefix))
                previous_attributes = []
        return found


class RustAnalyzer:
    analyzer_id = ANALYZER_ID

    def analyze(self, request: AnalysisInput) -> AnalyzerResult:
        checks = [check for check in request.checks if check in CHECKS]
        findings: list[WorkflowFinding] = []
        coverage: list[CheckCoverage] = []
        evidence = request.config.evidence
        available = grammar_available()
        for source in request.sources:
            if language_for_path(source.path) != "rust" or source.role != "review" or source.after is None or source.skip:
                continue
            if not available:
                coverage.extend(CheckCoverage(path=source.path, language="rust", check_id=check, analyzer_id=ANALYZER_ID,
                                              status="not_checked", reason="tree_sitter_unavailable") for check in checks)
                continue
            status: CoverageStatus = "checked"
            reason = "builtin_rules_completed"
            try:
                parsed = _File(source)
                hits: list[RHit] = []
                for node, symbol, entry in parsed.functions():
                    function = _Function(parsed, node, symbol, entry)
                    function.run()
                    hits.extend(function.hits)
                if parsed.root.has_error:
                    reason = "partial_parse_tolerated"
            except (RecursionError, MemoryError, ValueError):
                status, reason, hits = "partial", "analysis_error", []
            seen: set[tuple[int, str]] = set()
            for hit in hits:
                if hit.check not in checks or (hit.line, hit.rule_id) in seen:
                    continue
                seen.add((hit.line, hit.rule_id))
                info = catalog.RULES[hit.rule_id]
                first = hit.origins[0] if hit.origins else None
                argv_only = bool(hit.origins) and all(origin[0] == "argv" for origin in hit.origins)
                trace = [step("source", line, f"{label} ({'command-line argument' if kind == 'argv' else 'secret environment value' if kind == 'secret_env' else 'request input'})")
                         for kind, line, label in hit.origins[:2]] + [step("sink", hit.line, hit.sink)]
                message = info.message + (f" {first[2]} (line {first[1]}) reaches {hit.sink}." if first else f" ({hit.sink})")
                findings.append(make_finding(
                    analyzer_id=ANALYZER_ID, analyzer_version=VERSION, source=source, check_id=hit.check,
                    rule_id=hit.rule_id, result="flagged", start_line=hit.line, symbol=hit.symbol, message=message,
                    severity="medium" if argv_only else None, confidence="medium" if argv_only else "high",
                    trace=trace, evidence=evidence, reason="tainted_flow" if hit.origins else "pattern_match",
                ))
            if "secret_exposure" in checks:
                for match in secrets.scan(source.after):
                    findings.append(make_finding(
                        analyzer_id=ANALYZER_ID, analyzer_version=VERSION, source=source, check_id="secret_exposure",
                        rule_id="polaris.rust.secret_exposure.hardcoded", result="flagged", start_line=match.line,
                        message=f"A credential appears to be hardcoded in source ({match.label}, {match.masked}).",
                        severity=match.severity, trace=[step("sink", match.line, match.label)], evidence=evidence,
                        reason="pattern_match",
                    ))
            coverage.extend(CheckCoverage(path=source.path, language="rust", check_id=check, analyzer_id=ANALYZER_ID,
                                          status=status, reason=reason) for check in checks)
        return AnalyzerResult(findings=tuple(findings), coverage=tuple(coverage), capability=capability())

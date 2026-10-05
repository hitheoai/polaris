"""Built-in Python analyzer for the workflow: AST data flow and patterns, no model inference.

Request handlers (Flask/FastAPI/Django/Starlette routes) are entry points: their arguments are
client input. Other functions treat parameters as caller-supplied, so a dangerous use of one
asks for its call sites instead of being flagged blindly.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

from polaris.jsonio import digest_json, digest_text
from polaris.review import catalog, secrets
from polaris.review.analyzers.base import AnalysisInput, AnalyzerResult, language_for_path
from polaris.review.analyzers.evidence import insert_edit, make_finding, step
from polaris.review.dataflow import (
    WEB_KINDS,
    FlowFacts,
    Sink,
    analyze,
    dotted,
    has_candidate_call,
    module_http_clients,
    module_imports,
)
from polaris.review.extract import CodeUnit, units_from_source
from polaris.review.models import (
    AnalyzerCapability,
    CheckCoverage,
    CoverageStatus,
    SourceFile,
    TraceStep,
    WorkflowFinding,
)
from polaris.review.rules import rule_verdict, web_verdict

ANALYZER_ID = "polaris-python"
VERSION = "polaris-python-rules/0.2.0"
SUPPORTED_CHECKS = (
    "sql_injection", "command_injection", "code_injection", "xss", "ssrf", "open_redirect",
    "path_traversal", "secret_exposure", "missing_authorization", "insecure_auth_crypto",
    "unsafe_security_configuration",
)
LIMITATIONS = [
    "Function-local data flow; request handlers' arguments are client input, other parameters need their call sites.",
    "Allowlist checks (`if x not in ALLOWED: raise`, `assert x in ALLOWED`, fullmatch) and known sanitizers are recognized.",
    "Calls into unknown functions hide value origins; such cases are reported as needing context, not as clean.",
    "missing_authorization recognizes common auth decorators, FastAPI Depends(...) guards and guard calls.",
    "No model is loaded, called, downloaded, or used as a fallback.",
]
KIND_FOR_CHECK = {"ssrf": "ssrf", "open_redirect": "redirect", "xss": "xss", "path_traversal": "path",
                  "code_injection": "code", "secret_exposure": "secret"}
ROUTE_DECORATORS = frozenset({"route", "get", "post", "put", "patch", "delete", "api_route", "websocket", "head", "options"})
VIEW_DECORATORS = frozenset({"api_view", "require_http_methods", "require_POST", "require_GET", "require_safe", "csrf_exempt"})
MUTATING_DECORATORS = frozenset({"post", "put", "patch", "delete"})
AUTH_NAME = re.compile(
    r"(?i)(login_required|jwt_required|permission_required|permission_classes|user_passes_test|staff_member_required|"
    r"requires?_(auth|login|user|admin|role|permission|scope)|auth_required|token_required|admin_required|"
    r"roles?_(required|accepted)|authenticated|protected|verify_(token|api_key|user|auth|signature|webhook)|"
    r"api_key_required|get_current_(active_)?(user|account|admin|principal)|current_user|authenticate|authorize|"
    r"check_(auth|permission|access|admin|owner)|ensure_(auth|user|admin|permission)|is_(authenticated|admin|owner|staff)|"
    r"has_(permission|perm|role|access)|validate_(token|api_key|session|signature)|HTTPBearer|OAuth2PasswordBearer|APIKeyHeader)"
)
DB_RECEIVER = re.compile(r"(?i)(^|\.)(db|session|cursor|conn|connection|objects|collection|table|repo|repository|client|bucket|engine|supabase|firestore|redis|s3|dynamodb)(\.|$)")
UNAMBIGUOUS_WRITES = frozenset({
    "commit", "bulk_create", "bulk_update", "insert_one", "insert_many", "update_one", "update_many",
    "delete_one", "delete_many", "put_item", "delete_item", "update_item", "put_object", "delete_object",
    "get_or_create", "update_or_create",
})
WRITE_METHODS = frozenset({"add", "delete", "save", "create", "update", "remove", "insert", "upsert", "merge", "execute", "executemany"})
READ_METHODS = frozenset({"query", "filter", "get", "all", "first", "find", "find_one", "fetchall", "fetchone", "select", "scan", "get_item"})
WRITE_SQL = re.compile(r"(?i)^\s*(insert|update|delete|drop|alter|create|truncate|grant)\b")
SECURITY_NAME = re.compile(r"(?i)(token|secret|nonce|otp|password|passwd|salt|session|csrf|reset|invite|api_?key|verification|signature|passcode)")
SESSION_COOKIE = re.compile(r"(?i)(session|token|auth|sid|jwt|refresh|remember)")
TEST_PATH = re.compile(r"(?i)(^|/)(tests?|testing|fixtures?|examples?|conftest\.py$)|(^|/)test_[^/]+\.py$|_test\.py$")

GUIDANCE = {
    "untrusted_value_in_sql_text": "Use placeholders and pass values separately, e.g. "
                                   "cursor.execute(\"SELECT * FROM t WHERE id = %s\", (user_id,)).",
    "identifier": "Placeholders can't bind table or column names. Map the input to a fixed allowlist "
                  "(e.g. COLUMNS = {\"name\": \"name\", \"date\": \"created_at\"}) and format only the mapped constant.",
    "query_supplied_by_caller": "The whole query comes from the caller: make sure every caller passes fixed SQL text "
                                "and sends values as parameters.",
    "untrusted_executable": "Don't let input choose the program: map allowed choices to fixed executables.",
    "executable_supplied_by_caller": "The program to run is chosen by the caller: check every call site passes a fixed, allowlisted program.",
    "untrusted_value_in_shell_command": "Don't build shell commands: pass an argument list without shell=True, "
                                        "e.g. subprocess.run([\"convert\", src, dst], check=True).",
    "command_supplied_by_caller": "The whole command comes from the caller: check every call site passes a fixed argument list.",
    "untrusted_command_split": "Splitting an untrusted string still lets it choose the program and options; build the list yourself.",
    "untrusted_option_argument": "Put \"--\" before user-supplied arguments so they can't be read as options "
                                 "(git clone -- <url> <dir>), and reject values starting with \"-\" or unexpected URL schemes.",
}
WEB_GUIDANCE = {
    "ssrf": "Keep scheme and host fixed, or parse with urllib.parse.urlsplit and check the hostname against an allowlist before requesting.",
    "open_redirect": "Only redirect to relative paths starting with a single \"/\" or to an allowlist (e.g. url_has_allowed_host_and_scheme in Django).",
    "xss": "Don't mark untrusted input as safe HTML; let the template engine escape it, or sanitize with bleach/nh3 first.",
    "path_traversal": "Resolve against a fixed base (Path(BASE, name).resolve()) and reject results outside BASE "
                      "(use is_relative_to), or use werkzeug.utils.secure_filename / send_from_directory.",
    "code_injection": "Never evaluate or unpickle untrusted data; use json, yaml.safe_load, ast.literal_eval or a fixed dispatch table.",
    "secret_exposure": "Never print, log or return credentials; log a fixed redaction instead.",
}
VERIFY = {
    "sql_injection": "Is the SQL text fixed in every caller, with values passed as parameters?",
    "command_injection": "Does every caller pass a fixed program and argument list?",
    "ssrf": "Is the URL's host fixed or allowlisted in every caller?",
    "open_redirect": "Is the destination a relative path or allowlisted in every caller?",
    "xss": "Is the HTML trusted or sanitized in every caller?",
    "path_traversal": "Is the path confined to a fixed base folder in every caller?",
    "code_injection": "Can this value ever come from users or the network?",
}


def capability() -> AnalyzerCapability:
    root = Path(__file__).parent.parent
    material = {
        name: digest_text((root / name).read_text(encoding="utf-8"))
        for name in ("rules.py", "dataflow.py", "extract.py", "analyzers/python.py")
    }
    return AnalyzerCapability(
        analyzer_id=ANALYZER_ID, availability="available", version=VERSION, expected_version=VERSION,
        rule_pack_version=VERSION, rule_pack_digest=digest_json(material),
        languages=["python"], checks=list(SUPPORTED_CHECKS), provenance="Original Polaris Python AST rules",
        license="Apache-2.0", reason="builtin", limitations=list(LIMITATIONS),
    )


def _rules() -> None:
    py = "polaris.python."
    catalog.rule(py + "sql_injection", "sql_injection", "SQL text built from input",
                 "Untrusted input is built into SQL text.", GUIDANCE["untrusted_value_in_sql_text"])
    catalog.rule(py + "command_injection", "command_injection", "Unsafe process execution",
                 "Untrusted input reaches a shell command or chooses the program.", GUIDANCE["untrusted_value_in_shell_command"])
    catalog.rule(py + "argument_injection", "command_injection", "Argument injection",
                 "An untrusted value is passed where the program can read it as an option.",
                 GUIDANCE["untrusted_option_argument"], severity="medium", cwe="CWE-88")
    for check, title in (("ssrf", "Request to a user-controlled URL"), ("open_redirect", "Redirect to a user-controlled destination"),
                         ("xss", "Untrusted input marked as safe HTML"), ("path_traversal", "File path built from input"),
                         ("code_injection", "Untrusted data evaluated or deserialized"),
                         ("secret_exposure", "Secret written to logs or a response")):
        catalog.rule(py + check, check, title, catalog.CHECKS[check].summary, WEB_GUIDANCE[check])
    catalog.rule(py + "secret_exposure.hardcoded", "secret_exposure", "Hardcoded credential",
                 "A credential appears to be hardcoded in source.",
                 "Move it to a server-side environment variable or secret manager and rotate the exposed key.")
    catalog.rule(py + "tls_disabled", "unsafe_security_configuration", "TLS verification disabled",
                 "Certificate verification is turned off.", "Remove verify=False / unverified contexts and configure the right CA bundle.")
    catalog.rule(py + "debug_enabled", "unsafe_security_configuration", "Debug server enabled",
                 "The Flask/Werkzeug debugger is enabled; it allows remote code execution if reachable.",
                 "Never run with debug=True outside local development; read it from an environment flag defaulting to False.")
    catalog.rule(py + "cors_credentials", "unsafe_security_configuration", "Credentialed CORS for any origin",
                 "CORS allows credentials for any origin.", "Allow credentials only for an explicit list of trusted origins.",
                 severity="medium", cwe="CWE-942")
    catalog.rule(py + "cookie_flags", "unsafe_security_configuration", "Session cookie without httponly/secure",
                 "A session cookie is set with httponly or secure disabled.", "Set httponly=True, secure=True and samesite='Lax'.",
                 severity="medium", cwe="CWE-1004")
    catalog.rule(py + "weak_random", "insecure_auth_crypto", "Predictable security token",
                 "The random module is used to create a security-sensitive value.",
                 "Use secrets.token_urlsafe(), secrets.token_hex() or secrets.choice() for tokens and codes.", cwe="CWE-338")
    catalog.rule(py + "weak_password_hash", "insecure_auth_crypto", "Weak password hash",
                 "A password is hashed with a fast hash (MD5/SHA-1/SHA-256).",
                 "Use bcrypt, scrypt, argon2 (argon2-cffi) or hashlib.scrypt with a per-user salt.", severity="high", cwe="CWE-916")
    catalog.rule(py + "jwt_unverified", "insecure_auth_crypto", "JWT signature not verified",
                 "A JWT is decoded without verifying its signature (or with the 'none' algorithm).",
                 "Call jwt.decode(token, key, algorithms=[\"HS256\"]) with verification enabled.", severity="high", cwe="CWE-347")
    catalog.rule(py + "missing_authorization", "missing_authorization", "Route without an auth check",
                 "This route changes or reads data without an authentication/authorization check.",
                 "Add your auth decorator/dependency (login_required, Depends(get_current_user), ...) or list the route "
                 "under [workflow].public_routes in .polaris.toml if it is intentionally public.")


_rules()


def _decorator_names(node: ast.AST) -> list[str]:
    names: list[str] = []
    for decorator in getattr(node, "decorator_list", []):
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = dotted(target, {}) or ""
        names.append(name)
    return names


def _entry_kind(node: ast.AST, path: str) -> tuple[bool, bool]:
    """(is request handler, uses a mutating HTTP method)."""
    if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return False, False
    mutating = False
    entry = False
    for decorator in node.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = dotted(target, {}) or ""
        last = name.split(".")[-1]
        if last in ROUTE_DECORATORS and "." in name:
            entry = True
            mutating = mutating or last in MUTATING_DECORATORS
            if isinstance(decorator, ast.Call):
                for keyword in decorator.keywords:
                    if keyword.arg == "methods" and any(
                        isinstance(item, ast.Constant) and str(item.value).upper() in ("POST", "PUT", "PATCH", "DELETE")
                        for item in ast.walk(keyword.value)
                    ):
                        mutating = True
        elif last in VIEW_DECORATORS:
            entry = True
            mutating = mutating or last in ("require_POST",)
    params = [argument.arg for argument in node.args.args]
    if not entry and params[:1] == ["request"] and path.endswith(("views.py", "api.py", "routes.py")):
        entry = True
    return entry, mutating


def _guarded(node: ast.AST) -> bool:
    for name in _decorator_names(node):
        if AUTH_NAME.search(name):
            return True
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        defaults = [*node.args.defaults, *[item for item in node.args.kw_defaults if item is not None]]
        for default in defaults:
            if isinstance(default, ast.Call) and (dotted(default.func, {}) or "").split(".")[-1] in ("Depends", "Security"):
                if AUTH_NAME.search(ast.unparse(default)):
                    return True
        for annotation in [argument.annotation for argument in node.args.args if argument.annotation is not None]:
            if AUTH_NAME.search(ast.unparse(annotation)):
                return True
    for child in ast.walk(node):
        if isinstance(child, ast.Call) and AUTH_NAME.search((dotted(child.func, {}) or "").split(".")[-1]):
            return True
        if isinstance(child, ast.Attribute) and child.attr in ("is_authenticated", "is_staff", "is_superuser", "has_perm"):
            return True
        if isinstance(child, ast.Name) and child.id == "current_user":
            return True
    return False


def _data_operations(node: ast.AST) -> tuple[list[tuple[int, str]], list[tuple[int, str]]]:
    writes: list[tuple[int, str]] = []
    reads: list[tuple[int, str]] = []
    for child in ast.walk(node):
        if not isinstance(child, ast.Call) or not isinstance(child.func, ast.Attribute):
            continue
        name = dotted(child.func, {}) or child.func.attr
        method = child.func.attr
        receiver = name.rsplit(".", 1)[0] if "." in name else ""
        if method in UNAMBIGUOUS_WRITES:
            writes.append((child.lineno, name))
        elif method in WRITE_METHODS and DB_RECEIVER.search(receiver):
            if method in ("execute", "executemany"):
                first = child.args[0] if child.args else None
                if isinstance(first, ast.Constant) and isinstance(first.value, str) and WRITE_SQL.search(first.value):
                    writes.append((child.lineno, name))
                elif isinstance(first, ast.Constant):
                    reads.append((child.lineno, name))
            else:
                writes.append((child.lineno, name))
        elif method in READ_METHODS and DB_RECEIVER.search(receiver):
            reads.append((child.lineno, name))
    return writes, reads


def _call_sites(tree: ast.Module, symbol: str, path: str) -> list[str]:
    name = symbol.split(".")[-1]
    sites = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            target = node.func.attr if isinstance(node.func, ast.Attribute) else node.func.id if isinstance(node.func, ast.Name) else None
            if target == name:
                sites.append(f"{path}:{node.lineno}")
    return sites[:8]


def _origin_line(facts: FlowFacts, label: str, fallback: int) -> int:
    for entry in facts.sources:
        if entry.startswith(label) and "(line " in entry:
            try:
                return int(entry.rsplit("(line ", 1)[1].rstrip(")"))
            except ValueError:
                return fallback
    return fallback


class PythonAnalyzer:
    analyzer_id = ANALYZER_ID

    def analyze(self, request: AnalysisInput) -> AnalyzerResult:
        findings: list[WorkflowFinding] = []
        coverage: list[CheckCoverage] = []
        checks = [check for check in request.checks if check in SUPPORTED_CHECKS]
        config = request.config
        remaining_units = config.max_units
        for source in request.sources:
            if language_for_path(source.path) != "python" or not checks or source.role != "review":
                continue
            reason = source.skip
            status: CoverageStatus = "not_checked"
            if reason is None and source.after is None:
                reason = "missing_source"
            if reason is None and source.after is not None:
                if len(source.after) > config.max_file_bytes:
                    reason = "file_too_large"
                else:
                    try:
                        if len(source.after.encode("utf-8")) > config.max_file_bytes:
                            reason = "file_too_large"
                    except UnicodeError:
                        reason = "invalid_encoding"
            if reason is None and source.after is not None:
                units, reason = units_from_source(source.path, source.after)
                tree = ast.parse(source.after) if reason is None else None
                if reason is None and tree is not None:
                    status = "checked"
                    if len(units) > remaining_units:
                        reason, status = "unit_limit", "partial"
                    selected = units[:remaining_units]
                    remaining_units = max(0, remaining_units - len(selected))
                    clients = module_http_clients(tree, module_imports(tree))
                    for unit in selected:
                        try:
                            if sum(1 for _ in ast.walk(unit.node)) > 100_000:
                                reason, status = "ast_node_limit", "partial"
                                continue
                            findings.extend(self._unit(source, tree, unit, checks, config.evidence,
                                                       config.project.public_routes, clients))
                        except (RecursionError, MemoryError, ValueError):
                            reason, status = "analysis_error", "partial"
                    findings.extend(self._patterns(source, tree, checks, config.evidence))
                    if len(findings) >= config.max_findings:
                        reason, status = "result_limit", "partial"
                    if not source.context_complete:
                        reason, status = "incomplete_source_context", "partial"
            coverage.extend(
                CheckCoverage(path=source.path, language="python", check_id=check, analyzer_id=ANALYZER_ID,
                              status=status, reason=reason or "python_rules_completed")
                for check in checks
            )
        unique: dict[tuple[str, int, str, str], WorkflowFinding] = {}
        for finding in findings:
            unique.setdefault((finding.path, finding.start_line, finding.check_id, finding.rule_id), finding)
        return AnalyzerResult(findings=tuple(unique.values())[: config.max_findings], coverage=tuple(coverage),
                              capability=capability())

    # ---- per function ----------------------------------------------------------------------

    def _unit(self, source: SourceFile, tree: ast.Module, unit: CodeUnit, checks: list[str], evidence: str,
              public_routes: list[str], clients: frozenset[str] = frozenset()) -> list[WorkflowFinding]:
        findings: list[WorkflowFinding] = []
        entry, mutating = _entry_kind(unit.node, source.path)
        if has_candidate_call(unit.node, unit.imports, web=True, clients=clients):
            facts = analyze(unit.node, unit.imports, entry=entry, web=True, clients=clients)
            for check in ("sql_injection", "command_injection"):
                if check in checks:
                    result, reason, sink = rule_verdict(check, facts)
                    if result != "ok" and sink is not None:
                        findings.append(self._legacy_finding(source, tree, unit, facts, check, result, reason, sink, evidence))
            for check, kind in KIND_FOR_CHECK.items():
                if check not in checks:
                    continue
                for sink in facts.sinks:
                    if sink.kind != kind:
                        continue
                    result, reason = web_verdict(check, sink)
                    if result != "ok":
                        findings.append(self._web_finding(source, tree, unit, facts, check, result, reason, sink, evidence))
        if "missing_authorization" in checks and entry and not _guarded(unit.node):
            import fnmatch

            if not any(fnmatch.fnmatchcase(source.path, pattern) for pattern in public_routes):
                writes, reads = _data_operations(unit.node)
                if writes or reads:
                    line, operation = (writes or reads)[0]
                    result = "flagged" if writes else "needs_context"
                    findings.append(make_finding(
                        analyzer_id=ANALYZER_ID, analyzer_version=VERSION, source=source,
                        check_id="missing_authorization", rule_id="polaris.python.missing_authorization",
                        result=result, start_line=unit.start_line, end_line=unit.end_line, symbol=unit.symbol,
                        message=f"The route {unit.symbol}() {'changes' if writes else 'reads'} data ({operation}, line {line}) "
                                "without an auth decorator, dependency or guard call.",
                        severity="high" if writes else "medium", confidence="medium" if writes else "low",
                        trace=[step("source", unit.start_line, f"{unit.symbol}() route"), step("sink", line, operation)],
                        verify=None if writes else "Is this route intentionally public? If not, add your auth check; "
                                                   "otherwise list it under [workflow].public_routes.",
                        evidence=evidence, reason="unguarded_write" if writes else "unguarded_read",
                    ))
        return findings

    def _trace(self, facts: FlowFacts, sink: Sink, unit: CodeUnit) -> list[TraceStep]:
        steps: list[TraceStep] = []
        for origin in sink.origins[:2]:
            label = origin
            line = _origin_line(facts, origin, unit.start_line)
            steps.append(step("source", line, label))
        steps.append(step("sink", sink.line, f"{sink.call}(…)"))
        return steps

    def _legacy_finding(self, source: SourceFile, tree: ast.Module, unit: CodeUnit, facts: FlowFacts, check: str,
                        result: str, reason: str, sink: Sink, evidence: str) -> WorkflowFinding:
        argument_injection = reason == "untrusted_option_argument"
        rule_id = "polaris.python.argument_injection" if argument_injection else f"polaris.python.{check}"
        guidance = GUIDANCE["identifier"] if (
            check == "sql_injection" and sink.argument is not None and sink.argument.identifier_position
        ) else GUIDANCE.get(reason)
        origins = [origin for origin in sink.origins if not origin.startswith("parameter ")]
        argv_only = bool(origins) and all(origin.startswith("command-line") for origin in origins)
        edit = None
        if argument_injection and sink.edit_column >= 0:
            edit = insert_edit(source, sink.edit_line, sink.edit_column, '"--", ',
                               "\"--\" stops the value from being parsed as an option.")
        described = sink.argument.text if sink.argument is not None else "a value"
        message = {
            "flagged": f"{catalog.check_title(check)}: {described} reaches {sink.call}().",
            "needs_context": f"{catalog.check_title(check)} depends on the caller: {described} reaches {sink.call}().",
        }.get(result, f"{catalog.check_title(check)} at {sink.call}().")
        return make_finding(
            analyzer_id=ANALYZER_ID, analyzer_version=VERSION, source=source, check_id=check, rule_id=rule_id,
            result=result, start_line=sink.line, symbol=unit.symbol, message=message, guidance=guidance,
            reason=reason, severity="medium" if argv_only or argument_injection else None,
            confidence="high" if result == "flagged" else "low", trace=self._trace(facts, sink, unit),
            suggested_edit=edit, verify=VERIFY.get(check) if result == "needs_context" else None,
            call_sites=_call_sites(tree, unit.symbol, source.path) if result == "needs_context" else (),
            evidence=evidence, details=["Original Python flow rule matched."],
        )

    def _web_finding(self, source: SourceFile, tree: ast.Module, unit: CodeUnit, facts: FlowFacts, check: str,
                     result: str, reason: str, sink: Sink, evidence: str) -> WorkflowFinding:
        origins = [origin for origin in sink.origins if not origin.startswith("parameter ")]
        argv_only = bool(origins) and all(origin.startswith(("command-line", "input()")) for origin in origins)
        first = origins[0] if origins else (sink.origins[0] if sink.origins else "a value")
        message = (f"{catalog.RULES['polaris.python.' + check].title}: {first} reaches {sink.call}()."
                   if result == "flagged" else
                   f"{catalog.check_title(check)} depends on the caller: {first} reaches {sink.call}().")
        return make_finding(
            analyzer_id=ANALYZER_ID, analyzer_version=VERSION, source=source, check_id=check,
            rule_id=f"polaris.python.{check}", result=result, start_line=sink.line, symbol=unit.symbol,
            message=message, reason=reason, severity="medium" if argv_only else None,
            confidence="high" if result == "flagged" else "low", trace=self._trace(facts, sink, unit),
            verify=VERIFY.get(check) if result == "needs_context" else None,
            call_sites=_call_sites(tree, unit.symbol, source.path) if result == "needs_context" else (),
            evidence=evidence,
        )

    # ---- patterns ----------------------------------------------------------------------------

    def _patterns(self, source: SourceFile, tree: ast.Module, checks: list[str], evidence: str) -> list[WorkflowFinding]:
        found: list[tuple[str, str, int, str, str]] = []  # check, rule, line, label, symbol
        fixtures: list[tuple[int, str]] = []  # credential-shaped values in test files (line, label)
        text = source.after or ""
        test_path = bool(TEST_PATH.search(source.path))
        secret_rule = "polaris.python.secret_exposure.hardcoded"
        if "secret_exposure" in checks:
            for match in secrets.scan(text):
                label = f"{match.label} ({match.masked})"
                if test_path:
                    # Test fixtures are usually fake credentials (often testing a redactor or scanner).
                    fixtures.append((match.line, label))
                else:
                    found.append(("secret_exposure", secret_rule, match.line, label, "<module>"))
        imports = module_imports(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                name = dotted(node.func, imports) or ""
                keywords = {keyword.arg: keyword.value for keyword in node.keywords if keyword.arg}
                last = name.split(".")[-1]
                verify = keywords.get("verify")
                if verify is not None and isinstance(verify, ast.Constant) and verify.value is False and not test_path and (
                        name.split(".")[0] in ("requests", "httpx", "aiohttp") or last in ("Client", "AsyncClient", "Session")):
                    found.append(("unsafe_security_configuration", "polaris.python.tls_disabled", node.lineno, f"{name}(verify=False)", "<module>"))
                if name in ("ssl._create_unverified_context", "ssl._create_stdlib_context") and not test_path:
                    found.append(("unsafe_security_configuration", "polaris.python.tls_disabled", node.lineno, name, "<module>"))
                debug = keywords.get("debug")
                if last == "run" and isinstance(debug, ast.Constant) and debug.value is True and isinstance(node.func, ast.Attribute):
                    found.append(("unsafe_security_configuration", "polaris.python.debug_enabled", node.lineno, "app.run(debug=True)", "<module>"))
                if last == "CORS" and isinstance(keywords.get("supports_credentials"), ast.Constant) and \
                        getattr(keywords.get("supports_credentials"), "value", False) is True and (
                        "origins" not in keywords or "*" in ast.unparse(keywords["origins"])):
                    found.append(("unsafe_security_configuration", "polaris.python.cors_credentials", node.lineno, "CORS(..., supports_credentials=True)", "<module>"))
                if last == "set_cookie" and node.args and isinstance(node.args[0], ast.Constant) and SESSION_COOKIE.search(str(node.args[0].value)):
                    for flag in ("httponly", "secure"):
                        value = keywords.get(flag)
                        if isinstance(value, ast.Constant) and value.value is False:
                            found.append(("unsafe_security_configuration", "polaris.python.cookie_flags", node.lineno,
                                          f"set_cookie('{str(node.args[0].value)}', {flag}=False)", "<module>"))
                            break
                if name.startswith("random.") and last in ("random", "randint", "choice", "choices", "getrandbits", "randrange", "sample") and not test_path:
                    parent_names = self._assigned_names(tree, node)
                    if any(SECURITY_NAME.search(item) for item in parent_names):
                        found.append(("insecure_auth_crypto", "polaris.python.weak_random", node.lineno, f"{name}() for {parent_names[0]}", "<module>"))
                if name in ("hashlib.md5", "hashlib.sha1", "hashlib.sha256") and re.search(r"(?i)(password|passwd|pwd)", ast.unparse(node)):
                    found.append(("insecure_auth_crypto", "polaris.python.weak_password_hash", node.lineno, f"{name}(password)", "<module>"))
                if name == "jwt.decode":
                    options = keywords.get("options")
                    algorithms = keywords.get("algorithms")
                    unverified = (isinstance(keywords.get("verify"), ast.Constant) and getattr(keywords.get("verify"), "value", True) is False) or (
                        options is not None and re.search(r"verify_signature['\"]\s*:\s*False", ast.unparse(options)) is not None)
                    if unverified or (algorithms is not None and "none" in ast.unparse(algorithms).lower()):
                        found.append(("insecure_auth_crypto", "polaris.python.jwt_unverified", node.lineno, "jwt.decode without verification", "<module>"))
            elif isinstance(node, ast.Assign) and not test_path:
                target = ast.unparse(node.targets[0]) if node.targets else ""
                if target.endswith("verify_mode") and "CERT_NONE" in ast.unparse(node.value):
                    found.append(("unsafe_security_configuration", "polaris.python.tls_disabled", node.lineno, "verify_mode = CERT_NONE", "<module>"))
                if target.endswith("check_hostname") and isinstance(node.value, ast.Constant) and node.value.value is False:
                    found.append(("unsafe_security_configuration", "polaris.python.tls_disabled", node.lineno, "check_hostname = False", "<module>"))
        results = [
            make_finding(
                analyzer_id=ANALYZER_ID, analyzer_version=VERSION, source=source, check_id="secret_exposure",
                rule_id=secret_rule, result="needs_context", start_line=line, symbol="<module>",
                message=f"{catalog.RULES[secret_rule].message} ({label} in a test file; confirm it is a fake fixture)",
                severity="medium", confidence="low", trace=[step("sink", line, label)], evidence=evidence,
                reason="test_fixture_credential",
                verify="Is this a fake test credential? If it is real, rotate it and load it from the environment instead.",
            )
            for line, label in fixtures
        ]
        for check, rule_id, line, label, symbol in found:
            if check not in checks:
                continue
            results.append(make_finding(
                analyzer_id=ANALYZER_ID, analyzer_version=VERSION, source=source, check_id=check, rule_id=rule_id,
                result="flagged", start_line=line, symbol=symbol,
                message=f"{catalog.RULES[rule_id].message} ({label})",
                severity="critical" if "Stripe live" in label or "private key" in label else None,
                confidence="medium" if test_path else "high", trace=[step("sink", line, label)],
                evidence=evidence, reason="pattern_match",
            ))
        return results

    @staticmethod
    def _assigned_names(tree: ast.Module, call: ast.Call) -> list[str]:
        names: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                value = node.value
                if value is not None and any(child is call for child in ast.walk(value)):
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    names.extend(ast.unparse(target) for target in targets)
            elif isinstance(node, ast.keyword) and any(child is call for child in ast.walk(node.value)) and node.arg:
                names.append(node.arg)
            elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
                    isinstance(child, ast.Return) and child.value is not None and any(item is call for item in ast.walk(child.value))
                    for child in ast.walk(node)):
                names.append(node.name)
        return names


__all__ = ["ANALYZER_ID", "SUPPORTED_CHECKS", "PythonAnalyzer", "capability", "WEB_KINDS"]

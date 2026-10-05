"""Configuration and crypto patterns that don't need data flow: explicit, local, high-signal."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from typing import Any

from polaris.review import secrets
from polaris.review.js.engine import (
    JsFile,
    _language,
    grammar_for,
    iter_nodes,
    line_of,
    named,
    string_value,
    txt,
    unwrap,
)

SECURITY_NAME = re.compile(
    r"(?i)(token|secret|nonce|otp|password|passwd|salt|session|csrf|xsrf|reset|invite|api_?key|"
    r"access_?key|secret_?key|verification|verify|auth|signature|magic_?link|one_?time|passcode|pin_?code)"
)
NOT_SECURITY_NAME = re.compile(r"(?i)(color|colour|style|anim|delay|jitter|retry|backoff|sample|shuffle|offset)")
SESSION_COOKIE = re.compile(r"(?i)(session|token|auth|sid|jwt|refresh|remember|login)")
PUBLIC_SECRET = re.compile(r"NEXT_PUBLIC_[A-Z0-9_]+")
PUBLIC_SECRET_WORDS = re.compile(r"(SECRET|PRIVATE|SERVICE_ROLE|ACCESS_TOKEN|API_KEY|APIKEY|PASSWORD|_TOKEN$|ADMIN_KEY|WEBHOOK|SIGNING)")
# Values designed to ship to browsers (publishable keys, map tokens, referrer-restricted Google
# browser keys) and settings that only look secret (PRIVATE_MODE_ENABLED, TOKEN_TTL).
PUBLIC_OK_WORDS = re.compile(
    r"(PUBLISHABLE|ANON|PUBLIC_KEY|SITE_KEY|CLIENT_ID|DSN|MEASUREMENT|_URL|_ID$|MAPS_API_KEY|FIREBASE_API_KEY|POSTHOG|"
    r"SENTRY|RECAPTCHA|TURNSTILE|ALGOLIA_SEARCH|MAPBOX|PICKER|GOOGLE_\w*API_KEY|_ENABLED$|_DISABLED$|_MODE$|_FLAG$|"
    r"_TTL$|_VERSION$|^NEXT_PUBLIC_ENABLE_)"
)
TEST_PATH = re.compile(r"(?i)(^|/)(__tests__|tests?|spec|fixtures?|mocks?|examples?|e2e|stories)(/|$)|\.(test|spec|stories)\.")
SCAN_TYPES = ("pair", "assignment_expression", "object", "call_expression")


@lru_cache(maxsize=4)
def _scan_query(grammar: str) -> Any:
    from tree_sitter import Query

    return Query(_language(grammar), "[" + " ".join(f"({kind})" for kind in SCAN_TYPES) + "] @node")


def _scan_nodes(file: JsFile) -> list[Any]:
    """The nodes these rules inspect, in document order; tree-sitter selects them natively
    instead of visiting every node in Python."""
    try:
        from tree_sitter import QueryCursor

        captured = QueryCursor(_scan_query(grammar_for(file.path))).captures(file.root).get("node", [])
    except (ImportError, AttributeError, TypeError, ValueError):
        return [node for node in iter_nodes(file.root) if node.type in SCAN_TYPES]
    return sorted(captured, key=lambda node: (node.start_byte, -node.end_byte))


@dataclass(frozen=True)
class PatternHit:
    check: str
    rule_id: str
    line: int
    label: str
    symbol: str = "<module>"
    result: str = "flagged"
    detail: str = ""
    replace_old: str = ""
    replace_new: str = ""
    severity: str | None = None
    confidence: str = "high"


def _enclosing_names(node: Any, depth: int = 7) -> list[str]:
    names: list[str] = []
    current = node.parent
    while current is not None and depth > 0:
        kind = current.type
        if kind == "variable_declarator":
            target = current.child_by_field_name("name")
            if target is not None:
                names.append(txt(target))
        elif kind in ("assignment_expression", "augmented_assignment_expression"):
            target = current.child_by_field_name("left")
            if target is not None:
                names.append(txt(target))
        elif kind == "pair":
            key = current.child_by_field_name("key")
            if key is not None:
                names.append(txt(key))
        elif kind == "jsx_attribute":
            parts = named(current)
            if parts:
                names.append(txt(parts[0]))
        elif kind in ("function_declaration", "method_definition"):
            name = current.child_by_field_name("name")
            if name is not None:
                names.append(txt(name))
            break
        elif kind == "arrow_function":
            parent = current.parent
            if parent is not None and parent.type == "variable_declarator":
                name = parent.child_by_field_name("name")
                if name is not None:
                    names.append(txt(name))
            break
        current = current.parent
        depth -= 1
    return names


def _statement_text(node: Any) -> str:
    current = node
    while current.parent is not None and current.type not in (
        "expression_statement", "lexical_declaration", "variable_declaration", "return_statement",
    ):
        current = current.parent
    return txt(current)[:2_000]


def _pairs(node: Any) -> dict[str, Any]:
    found: dict[str, Any] = {}
    for item in named(node):
        if item.type == "pair":
            key = item.child_by_field_name("key")
            value = item.child_by_field_name("value")
            if key is not None and value is not None:
                found[string_value(key) or txt(key)] = unwrap(value)
    return found


def scan(file: JsFile) -> list[PatternHit]:
    hits: list[PatternHit] = []
    text = file.text
    test_path = bool(TEST_PATH.search(file.path))
    for match in secrets.scan(text):
        if test_path:
            # Test fixtures are usually fake credentials (often testing a redactor or scanner).
            hits.append(PatternHit(
                "secret_exposure", "polaris.js.secret_exposure.hardcoded", match.line,
                f"{match.label} in a test file ({match.masked}); confirm it is a fake fixture", detail=match.kind,
                severity="medium", result="needs_context", confidence="low",
            ))
            continue
        hits.append(PatternHit(
            "secret_exposure", "polaris.js.secret_exposure.hardcoded", match.line,
            f"{match.label} ({match.masked})", detail=match.kind, severity=match.severity,
            confidence="medium" if match.confidence != "high" else "high",
        ))
    reported_public: set[str] = set()
    for number, line in enumerate(text.splitlines(), start=1):
        for name in PUBLIC_SECRET.findall(line):
            if name in reported_public:
                continue
            if PUBLIC_SECRET_WORDS.search(name) and not PUBLIC_OK_WORDS.search(name):
                reported_public.add(name)
                hits.append(PatternHit("secret_exposure", "polaris.js.secret_exposure.public_env", number, name,
                                       detail="next_public_secret"))
    has_verify = bool(re.search(r"\b(jwt\.verify|jwtVerify|verify\s*\()", text))
    # Have I Been Pwned's k-anonymity range API requires SHA-1 of the password by design.
    pwned_lookup = "pwnedpasswords" in text
    for node in _scan_nodes(file):
        kind = node.type
        if kind == "pair":
            key = node.child_by_field_name("key")
            value = node.child_by_field_name("value")
            if key is not None and value is not None and (string_value(key) or txt(key)) == "rejectUnauthorized" \
                    and txt(value) == "false" and not test_path:
                old = re.sub(r"\s+", " ", txt(node))
                hits.append(PatternHit("unsafe_security_configuration", "polaris.js.unsafe_security_configuration.tls_disabled",
                                       line_of(node), "rejectUnauthorized: false", replace_old=old,
                                       replace_new=old.replace("false", "true")))
        elif kind == "assignment_expression":
            left = txt(node.child_by_field_name("left") or node)
            right = node.child_by_field_name("right")
            if "NODE_TLS_REJECT_UNAUTHORIZED" in left and right is not None and (string_value(right) == "0" or txt(right) == "0"):
                hits.append(PatternHit("unsafe_security_configuration", "polaris.js.unsafe_security_configuration.tls_disabled",
                                       line_of(node), "NODE_TLS_REJECT_UNAUTHORIZED = 0"))
        elif kind == "object":
            pairs = _pairs(node)
            origin = pairs.get("origin")
            credentials = pairs.get("credentials")
            if origin is not None and credentials is not None and txt(credentials) == "true" and (
                    string_value(origin) == "*" or txt(origin) == "true"):
                hits.append(PatternHit("unsafe_security_configuration",
                                       "polaris.js.unsafe_security_configuration.cors_credentials", line_of(node),
                                       "cors({ origin: '*', credentials: true })"))
            allow_origin = next((value for key, value in pairs.items() if key.lower() == "access-control-allow-origin"), None)
            allow_credentials = next((value for key, value in pairs.items()
                                      if key.lower() == "access-control-allow-credentials"), None)
            if allow_origin is not None and allow_credentials is not None and (
                    string_value(allow_credentials) == "true" or txt(allow_credentials) == "true") and (
                    string_value(allow_origin) == "*" or "origin" in txt(allow_origin).lower()):
                hits.append(PatternHit("unsafe_security_configuration",
                                       "polaris.js.unsafe_security_configuration.cors_credentials", line_of(node),
                                       "Access-Control-Allow-Credentials with a wildcard/reflected origin"))
        elif kind == "call_expression":
            function = node.child_by_field_name("function")
            name = file.callee(function) or ""
            last = name.split(".")[-1]
            arguments = node.child_by_field_name("arguments")
            args = named(arguments) if arguments is not None and arguments.type == "arguments" else []
            if name == "Math.random":
                names = _enclosing_names(node)
                if any(SECURITY_NAME.search(item) and not NOT_SECURITY_NAME.search(item) for item in names) and not test_path:
                    hits.append(PatternHit("insecure_auth_crypto", "polaris.js.insecure_auth_crypto.weak_random",
                                           line_of(node), f"Math.random() for {next(item for item in names if SECURITY_NAME.search(item))}"))
            elif last == "createHash" and args and (string_value(args[0]) or "").lower() in ("md5", "sha1", "sha256", "sha-1"):
                hibp = pwned_lookup and (string_value(args[0]) or "").lower() in ("sha1", "sha-1")
                if re.search(r"(?i)(password|passwd|pwd)", _statement_text(node)) and not hibp:
                    hits.append(PatternHit("insecure_auth_crypto", "polaris.js.insecure_auth_crypto.weak_password_hash",
                                           line_of(node), f"createHash('{string_value(args[0])}') on a password"))
            elif last in ("createCipher", "createDecipher") and ("crypto" in name or name == last):
                hits.append(PatternHit("insecure_auth_crypto", "polaris.js.insecure_auth_crypto.weak_cipher",
                                       line_of(node), f"crypto.{last}() (deprecated, no IV)"))
            elif last in ("createCipheriv", "createDecipheriv") and args and "ecb" in (string_value(args[0]) or "").lower():
                hits.append(PatternHit("insecure_auth_crypto", "polaris.js.insecure_auth_crypto.weak_cipher",
                                       line_of(node), f"{string_value(args[0])} (ECB mode)"))
            elif last == "verify" and ("jwt" in name.lower() or "jsonwebtoken" in name) and len(args) >= 3:
                options = unwrap(args[2])
                if options is not None and options.type == "object":
                    algorithms = _pairs(options).get("algorithms")
                    if algorithms is not None and re.search(r"['\"]none['\"]", txt(algorithms), re.IGNORECASE):
                        hits.append(PatternHit("insecure_auth_crypto", "polaris.js.insecure_auth_crypto.jwt_none",
                                               line_of(node), "jwt.verify(..., { algorithms: ['none'] })"))
            elif last == "decode" and ("jwt" in name.lower() or "jsonwebtoken" in name or "jose" in name) and not has_verify:
                hits.append(PatternHit("insecure_auth_crypto", "polaris.js.insecure_auth_crypto.jwt_decode",
                                       line_of(node), f"{name}()", result="needs_context", confidence="low"))
            elif last in ("set", "cookie", "setCookie") and len(args) >= 3 and (
                    "cookies" in name or name.split(".")[0] in ("res", "response", "reply", "ctx", "c")):
                cookie = string_value(args[0]) or ""
                options = unwrap(args[2])
                if SESSION_COOKIE.search(cookie) and options is not None and options.type == "object":
                    pairs = _pairs(options)
                    for flag in ("httpOnly", "secure"):
                        value = pairs.get(flag)
                        if value is not None and txt(value) == "false":
                            hits.append(PatternHit("unsafe_security_configuration",
                                                   "polaris.js.unsafe_security_configuration.cookie_flags", line_of(node),
                                                   f"cookie '{cookie}' with {flag}: false"))
                            break
    return hits

"""Original Polaris rules, Apache-2.0. No Semgrep Registry rules are bundled or fetched.

This is a deliberately narrow pattern pack, not a general security qualification. JSON is
also YAML; serializing this module's data avoids a runtime YAML dependency/resource loader.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from polaris.jsonio import canonical_bytes, digest_json
from polaris.review.analyzers.identity import RUNTIME_VERSION
from polaris.review.models import Language

SEMGREP_VERSION = RUNTIME_VERSION
RULE_PACK_VERSION = "polaris-original/0.1.0"
PYTHON_EXTRA_CHECKS = ("secret_exposure", "path_traversal", "unsafe_security_configuration")
JS_CHECKS = ("sql_injection", "command_injection", *PYTHON_EXTRA_CHECKS)


@dataclass(frozen=True)
class RuleDescription:
    check_id: str
    languages: tuple[Language, ...]
    title: str
    message: str
    guidance: str


DESCRIPTIONS: dict[str, RuleDescription] = {
    "polaris.js.sql-text": RuleDescription(
        "sql_injection", ("javascript", "typescript"), "SQL injection",
        "An untrusted value reaches SQL text in a query/execute/raw-style call.",
        "Keep SQL text fixed; pass data as separate bound parameters and allowlist identifiers.",
    ),
    "polaris.js.shell-command": RuleDescription(
        "command_injection", ("javascript", "typescript"), "Command injection",
        "An untrusted value reaches a Node child_process shell command.",
        "Use a fixed executable with an argument array and shell disabled; validate arguments.",
    ),
    "polaris.js.shell-spawn": RuleDescription(
        "command_injection", ("javascript", "typescript"), "Command injection",
        "Untrusted executable or arguments reach Node spawn with shell explicitly enabled.",
        "Disable the shell and keep the executable fixed; validate and delimit path arguments.",
    ),
    "polaris.js.secret-output": RuleDescription(
        "secret_exposure", ("javascript", "typescript"), "Secret exposure",
        "A secret-named environment value reaches logging or an HTTP response.",
        "Keep credentials server-side and remove them from logs and responses; use a fixed redaction.",
    ),
    "polaris.js.path-input": RuleDescription(
        "path_traversal", ("javascript", "typescript"), "Path traversal",
        "An untrusted value reaches a filesystem path or sendFile-style sink.",
        "Resolve against an approved base and verify containment after normalization; reject escapes.",
    ),
    "polaris.js.tls-disabled": RuleDescription(
        "unsafe_security_configuration", ("javascript", "typescript"),
        "Unsafe security configuration",
        "TLS peer-verification is explicitly disabled by an environment setting or client option.",
        "Keep certificate verification enabled and configure the correct trusted CA instead.",
    ),
    "polaris.python.secret-output": RuleDescription(
        "secret_exposure", ("python",), "Secret exposure",
        "A secret-named environment value reaches printing, logging, or a JSON response.",
        "Do not include credentials in responses or logs; use a fixed redaction.",
    ),
    "polaris.python.path-input": RuleDescription(
        "path_traversal", ("python",), "Path traversal",
        "An untrusted value reaches an open/send_file-style path.",
        "Validate resolved paths against an approved base and reject traversal and symlink escapes.",
    ),
    "polaris.python.tls-disabled": RuleDescription(
        "unsafe_security_configuration", ("python",), "Unsafe security configuration",
        "An HTTP request disables certificate verification or creates an unverified TLS context.",
        "Use certificate verification and the intended CA trust store.",
    ),
}


def _node_sinks(
    modules: tuple[str, ...], methods: tuple[str, ...], arguments: str, focus: str | None,
) -> list[dict[str, Any]]:
    """Recognize explicit imports/requires; do not label an arbitrary object's .exec as Node."""
    sinks: list[dict[str, Any]] = []
    for module in modules:
        for method in methods:
            object_imports = [
                {"pattern-inside": f'const $MODULE = require("{module}");\n...'},
                {"pattern-inside": f'import * as $MODULE from "{module}";\n...'},
                {"pattern-inside": f'import $MODULE from "{module}";\n...'},
            ]
            named_imports = [
                {"pattern-inside": f'import {{ {method} as $CALL }} from "{module}";\n...'},
                {"pattern-inside": f'const {{ {method}: $CALL }} = require("{module}");\n...'},
            ]
            shorthand_imports = [
                {"pattern-inside": f'import {{ {method} }} from "{module}";\n...'},
                {"pattern-inside": f'const {{ {method} }} = require("{module}");\n...'},
            ]
            for imports, call in (
                (object_imports, f"$MODULE.{method}({arguments})"),
                (named_imports, f"$CALL({arguments})"),
                (shorthand_imports, f"{method}({arguments})"),
            ):
                patterns: list[dict[str, Any]] = [
                    {"pattern-either": imports}, {"pattern": call},
                ]
                if focus:
                    patterns.append({"focus-metavariable": focus})
                sinks.append({"patterns": patterns})
            direct: list[dict[str, Any]] = [
                {"pattern": f'require("{module}").{method}({arguments})'}
            ]
            if focus:
                direct.append({"focus-metavariable": focus})
            sinks.append({"patterns": direct})
    return sinks


JS_SOURCES: list[dict[str, Any]] = [
    {"patterns": [
        {"pattern-inside": "function $FUNCTION(..., $PARAMETER, ...) { ... }"},
        {"focus-metavariable": "$PARAMETER"},
    ]},
    {"patterns": [
        {"pattern-inside": "(..., $PARAMETER, ...) => { ... }"},
        {"focus-metavariable": "$PARAMETER"},
    ]},
    *({"pattern": value} for value in (
        "$REQUEST.query", "$REQUEST.body", "$REQUEST.params", "$REQUEST.headers",
        "process.argv", "process.env", "$REQUEST.json()", "$REQUEST.text()",
    )),
]
PYTHON_SOURCES: list[dict[str, Any]] = [
    {"patterns": [
        {"pattern-inside": "def $FUNCTION(..., $PARAMETER, ...):\n    ..."},
        {"focus-metavariable": "$PARAMETER"},
    ]},
    *({"pattern": value} for value in (
        "input(...)", "sys.argv", "os.environ", "os.getenv(...)",
        "$REQUEST.args.get(...)", "$REQUEST.form.get(...)", "$REQUEST.GET.get(...)",
    )),
]
SECRET_NAME = "(?i).*(?:secret|token|password|passwd|api_?key|private_?key).*"


def _rule(rule_id: str, **body: Any) -> dict[str, Any]:
    description = DESCRIPTIONS[rule_id]
    return {
        "id": rule_id,
        "languages": list(description.languages),
        "severity": "WARNING",
        "message": description.message,
        "metadata": {
            "license": "Apache-2.0", "author": "Polaris",
            "polaris_check": description.check_id,
            "polaris_rule_pack": RULE_PACK_VERSION,
        },
        **body,
    }


RULES: tuple[dict[str, Any], ...] = (
    _rule(
        "polaris.js.sql-text", mode="taint",
        **{
            "pattern-sources": JS_SOURCES,
            "pattern-sinks": [
                {"patterns": [
                    {"pattern-either": [{"pattern": value} for value in (
                        "$DB.query($SQL, ...)", "$DB.execute($SQL, ...)",
                        "$DB.raw($SQL, ...)", "$DB.$queryRawUnsafe($SQL, ...)",
                        "$DB.$executeRawUnsafe($SQL, ...)",
                    )]},
                    {"focus-metavariable": "$SQL"},
                ]},
            ],
        },
    ),
    _rule(
        "polaris.js.shell-command", mode="taint",
        **{
            "pattern-sources": JS_SOURCES,
            "pattern-sinks": _node_sinks(
                ("child_process", "node:child_process"), ("exec", "execSync"),
                "$COMMAND, ...", "$COMMAND",
            ),
        },
    ),
    _rule(
        "polaris.js.shell-spawn", mode="taint",
        **{
            "pattern-sources": JS_SOURCES,
            "pattern-sinks": _node_sinks(
                ("child_process", "node:child_process"), ("spawn", "spawnSync"),
                "$COMMAND, $ARGS, { ..., shell: true, ... }", None,
            ),
        },
    ),
    _rule(
        "polaris.js.secret-output", mode="taint",
        **{
            "pattern-sources": [
                {"patterns": [
                    {"pattern": "process.env.$NAME"},
                    {"metavariable-regex": {"metavariable": "$NAME", "regex": SECRET_NAME}},
                ], "exact": True},
                {"patterns": [
                    {"pattern": "process.env[$NAME]"},
                    {"metavariable-regex": {"metavariable": "$NAME", "regex": SECRET_NAME}},
                ], "exact": True},
            ],
            "pattern-sinks": [{"pattern": value} for value in (
                "console.log(...)", "console.info(...)", "console.warn(...)",
                "console.error(...)", "console.debug(...)", "$RESPONSE.json(...)",
                "$RESPONSE.send(...)", "$RESPONSE.end(...)", "Response.json(...)",
                "new Response(...)",
            )],
        },
    ),
    _rule(
        "polaris.js.path-input", mode="taint",
        **{
            "pattern-sources": JS_SOURCES,
            "pattern-sinks": [
                *_node_sinks(
                    ("fs", "node:fs", "fs/promises", "node:fs/promises"),
                    ("readFile", "readFileSync", "writeFile", "writeFileSync",
                     "createReadStream", "createWriteStream", "unlink", "unlinkSync"),
                    "$PATH, ...", "$PATH",
                ),
                {"patterns": [
                    {"pattern": "$RESPONSE.sendFile($PATH, ...)"},
                    {"focus-metavariable": "$PATH"},
                ]},
            ],
        },
    ),
    _rule(
        "polaris.js.tls-disabled",
        **{"pattern-either": [{"pattern": value} for value in (
            'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"',
            "process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0",
            "new $CLIENT({ ..., rejectUnauthorized: false, ... })",
            "tls.connect({ ..., rejectUnauthorized: false, ... })",
            "https.request({ ..., rejectUnauthorized: false, ... }, ...)",
        )]},
    ),
    _rule(
        "polaris.python.secret-output", mode="taint",
        **{
            "pattern-sources": [
                {"patterns": [
                    {"pattern-either": [{"pattern": value} for value in (
                        "os.environ[$NAME]", "os.environ.get($NAME, ...)", "os.getenv($NAME, ...)",
                    )]},
                    {"metavariable-regex": {"metavariable": "$NAME", "regex": SECRET_NAME}},
                ], "exact": True},
            ],
            "pattern-sinks": [{"pattern": value} for value in (
                "print(...)", "$LOGGER.info(...)", "$LOGGER.warning(...)",
                "$LOGGER.error(...)", "$LOGGER.debug(...)", "flask.jsonify(...)",
            )],
        },
    ),
    _rule(
        "polaris.python.path-input", mode="taint",
        **{
            "pattern-sources": PYTHON_SOURCES,
            "pattern-sinks": [
                {"patterns": [
                    {"pattern-either": [{"pattern": value} for value in (
                        "open($PATH, ...)", "io.open($PATH, ...)",
                        "flask.send_file($PATH, ...)",
                    )]},
                    {"focus-metavariable": "$PATH"},
                ]},
            ],
        },
    ),
    _rule(
        "polaris.python.tls-disabled",
        **{"pattern-either": [
            {"patterns": [
                {"pattern": "requests.$METHOD(..., verify=False, ...)"},
                {"metavariable-regex": {
                    "metavariable": "$METHOD", "regex": "^(get|post|put|patch|delete|head|request)$",
                }},
            ]},
            {"pattern": "ssl._create_unverified_context(...)"},
            {"pattern": "httpx.Client(..., verify=False, ...)"},
            {"pattern": "httpx.AsyncClient(..., verify=False, ...)"},
        ]},
    ),
)
RULE_PACK_DIGEST = digest_json({"version": RULE_PACK_VERSION, "rules": RULES})


def rule_pack_bytes(checks: set[str], languages: set[Language]) -> bytes:
    selected = [
        rule for rule in RULES
        if DESCRIPTIONS[rule["id"]].check_id in checks
        and languages.intersection(DESCRIPTIONS[rule["id"]].languages)
    ]
    return canonical_bytes({"rules": selected})

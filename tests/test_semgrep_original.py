"""Opt-in real-engine software fixtures, not an accuracy benchmark.

Set POLARIS_TEST_SEMGREP to the explicitly trusted exact managed 1.178.0+theovex.1 environment.
Nothing is installed/downloaded by these tests, and all source input is synthetic.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from analysis_fixtures import (
    COMMAND_BAD,
    COMMAND_GOOD,
    PATH_BAD,
    PATH_GOOD,
    PYTHON_COMMAND_BAD,
    PYTHON_COMMAND_GOOD,
    PYTHON_PATH_BAD,
    PYTHON_SECRET_BAD,
    PYTHON_TLS_BAD,
    SECRET_BAD,
    SECRET_GOOD,
    SPAWN_BAD,
    SQL_BAD,
    SQL_GOOD,
    TLS_BAD,
    TLS_GOOD,
)

from polaris.review.analyzers import AnalysisRuntime
from polaris.review.engine import WorkflowReviewer
from polaris.review.models import SourceFile, WorkflowReviewConfig


@pytest.fixture
def real_runtime(tmp_path, monkeypatch):
    executable = os.environ.get("POLARIS_TEST_SEMGREP")
    if not executable:
        pytest.skip("real Semgrep tests require explicit POLARIS_TEST_SEMGREP")
    assert Path(executable).is_absolute() and Path(executable).is_file()
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("POLARIS_HOME", str(tmp_path))
    monkeypatch.setenv("HF_HUB_OFFLINE", "1")
    monkeypatch.setenv("TRANSFORMERS_OFFLINE", "1")
    monkeypatch.delenv("POLARIS_MODEL", raising=False)
    return AnalysisRuntime(semgrep_executable=executable)


def test_original_rules_positive_negative_js_ts_jsx_tsx_python(real_runtime):
    cases = {
        "sql.bad.ts": (SQL_BAD, {"sql_injection"}),
        "sql.good.ts": (SQL_GOOD, set()),
        "command.bad.js": (COMMAND_BAD, {"command_injection"}),
        "command.shorthand.bad.js": (
            COMMAND_BAD.replace("exec as execute", "exec").replace('execute("printf "', 'exec("printf "'),
            {"command_injection"},
        ),
        "command.require.bad.js": (
            COMMAND_BAD.replace('import { exec as execute } from "node:child_process";',
                                'const { exec } = require("node:child_process");')
            .replace('execute("printf "', 'exec("printf "'),
            {"command_injection"},
        ),
        "command.good.js": (COMMAND_GOOD, set()),
        "spawn.bad.ts": (SPAWN_BAD, {"command_injection"}),
        "secret.bad.ts": (SECRET_BAD, {"secret_exposure"}),
        "secret.good.ts": (SECRET_GOOD, set()),
        "path.bad.js": (PATH_BAD, {"path_traversal"}),
        "path.good.js": (PATH_GOOD, set()),
        "tls.bad.js": (TLS_BAD, {"unsafe_security_configuration"}),
        "tls.good.js": (TLS_GOOD, set()),
        "component.bad.jsx": (SECRET_BAD + "export const Component = () => <div />;\n", {"secret_exposure"}),
        "component.bad.tsx": (SECRET_BAD + "export const Component = () => <div />;\n", {"secret_exposure"}),
        "module.bad.mts": (SQL_BAD, {"sql_injection"}),
        "python_command_bad.py": (PYTHON_COMMAND_BAD, {"command_injection"}),
        "python_command_good.py": (PYTHON_COMMAND_GOOD, set()),
        "python_secret_bad.py": (PYTHON_SECRET_BAD, {"secret_exposure"}),
        "python_path_bad.py": (PYTHON_PATH_BAD, {"path_traversal"}),
        "python_tls_bad.py": (PYTHON_TLS_BAD, {"unsafe_security_configuration"}),
        "comment-cannot-suppress.js": (COMMAND_BAD.replace('execute("printf " + req.query.message);',
                                                              'execute("printf " + req.query.message); // nosemgrep'),
                                       {"command_injection"}),
    }
    report = WorkflowReviewer(runtime=real_runtime).review_sources([
        SourceFile(path, code) for path, (code, _) in cases.items()
    ])
    incomplete = [(entry.path, entry.check_id, entry.reason) for entry in report.coverage.entries
                  if entry.required and entry.status != "checked"]
    assert report.coverage.complete, incomplete
    for path, (_, expected) in cases.items():
        actual = {finding.check_id for finding in report.findings if finding.path == path}
        assert actual == expected, (path, actual, expected)
    assert all(finding.evidence_digest.startswith("sha256:") for finding in report.findings)


def test_real_parse_failure_is_incomplete_not_clean(real_runtime):
    report = WorkflowReviewer(
        runtime=real_runtime, config=WorkflowReviewConfig(checks=["sql_injection"]),
    ).review_snippet("export function broken( {\n db.query('SELECT ' + request.query.name);\n", path="broken.ts")
    assert not report.coverage.complete
    assert any(entry.required and entry.status != "checked" for entry in report.coverage.entries)

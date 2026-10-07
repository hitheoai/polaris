"""First-wave codemods for `polaris fix`: yaml.load, SQL parameters and Node TLS checks.

Every codemod has positive cases, cases it must refuse, a CRLF case, an unparseable-file case and an
end-to-end case through `build_plan`. Source in these fixtures is data that is parsed, never executed.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from polaris.integrations.forge.verify import MEMORY_ONLY
from polaris.refactor import codemods
from polaris.refactor.apply import apply_fix
from polaris.refactor.generators import deterministic
from polaris.refactor.plan import build_plan
from polaris.review.models import WorkflowReviewConfig
from polaris.workflow.service import review_workspace_detailed

GIT_ENV = {"PATH": os.defpath, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}


def make_project(tmp_path: Path, files: dict[str, str], name: str = "project") -> Path:
    root = (tmp_path / name).resolve()
    root.mkdir()
    subprocess.run(["/usr/bin/git", "--no-pager", "init", "-q", str(root)], check=True,
                   env={**GIT_ENV, "HOME": str(tmp_path)})
    for path, text in files.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text)
    return root


def plan_for(root: Path):
    review = review_workspace_detailed(root, paths=[root], config=WorkflowReviewConfig(), runtime=MEMORY_ONLY)
    return build_plan(root, review, deterministic())


def applied_text(path: str, text: str, tmp_path: Path, expected_rule: str, codemod_name: str, label: str = "") -> str:
    """Plan the fix for `text`, check it was a verified codemod fix, apply it and return the new file."""
    project = make_project(tmp_path, {path: text}, name=f"e2e_{codemod_name}_{label}")
    plan = plan_for(project)
    items = [item for item in plan.items if item.rule_id == expected_rule]
    assert len(items) == 1, [(item.rule_id, item.status, item.reason) for item in plan.items]
    item = items[0]
    assert item.status == "verified", (item.status, item.reason, item.attempts)
    assert item.origin == "codemod" and item.attempts[-1].name == codemod_name
    outcome = apply_fix(project, item.proposal, approved_digest=item.proposal_digest, config=WorkflowReviewConfig(),
                        runtime=MEMORY_ONLY, known=item.known)
    assert (outcome.applied, outcome.verified) == (True, True), outcome
    return (project / path).read_text()


def crlf(text: str) -> str:
    return text.replace("\n", "\r\n")


# ---- yaml.load -> yaml.safe_load ---------------------------------------------------------------

YAML_RULE = "polaris.python.code_injection"
YAML_HANDLER = (
    "import yaml\n"
    "from flask import Flask, request\n\n"
    "app = Flask(__name__)\n\n\n"
    "@app.route('/c', methods=['POST'])\n"
    "def conf():\n"
    "    {line}\n"
    "    return str(data)\n"
)


def yaml_source(line: str) -> str:
    return YAML_HANDLER.format(line=line)


@pytest.mark.parametrize(("line", "fixed"), [
    ("data = yaml.load(request.data)", "data = yaml.safe_load(request.data)"),
    ("data = yaml.load(request.data, Loader=yaml.Loader)", "data = yaml.safe_load(request.data)"),
    ("data = yaml.load(request.data, Loader=yaml.UnsafeLoader)", "data = yaml.safe_load(request.data)"),
    ("data = yaml.load(request.data, Loader=yaml.FullLoader)", "data = yaml.safe_load(request.data)"),
    ("data = yaml.load(request.data, yaml.Loader)", "data = yaml.safe_load(request.data)"),
    ("data = yaml.load(request.data, Loader = yaml.Loader,)", "data = yaml.safe_load(request.data,)"),
    ("data = yaml.load(stream=request.data)", None),  # a keyword stream is not the plain form
    ("data = yaml.unsafe_load(request.data)", "data = yaml.safe_load(request.data)"),
    ("data = list(yaml.load_all(request.data, Loader=yaml.Loader))", "data = list(yaml.safe_load_all(request.data))"),
    ("data = list(yaml.unsafe_load_all(request.data))", "data = list(yaml.safe_load_all(request.data))"),
    ("data = yaml.load(request.get_data().decode(), Loader=yaml.Loader)",
     "data = yaml.safe_load(request.get_data().decode())"),  # the stream expression is kept exactly
])
def test_yaml_load_becomes_safe_load_and_only_the_loader_changes(line, fixed):
    text = yaml_source(line)
    fix = codemods.yaml_safe_load(text, 9)
    if fixed is None:
        assert fix is None
        return
    assert fix and fix.name == "yaml_safe_load" and fix.text == yaml_source(fixed)
    assert "Python" in fix.rationale and "did not run your code" in fix.rationale


def test_yaml_codemod_follows_the_module_alias_and_multiline_calls():
    aliased = YAML_HANDLER.replace("import yaml\n", "import yaml as y\n").format(
        line="data = y.load(request.data, Loader=y.Loader)")
    assert codemods.yaml_safe_load(aliased, 9).text.splitlines()[8] == "    data = y.safe_load(request.data)"
    spread = yaml_source("data = yaml.load(\n        request.data,\n        Loader=yaml.Loader,\n    )")
    fixed = codemods.yaml_safe_load(spread, 9)
    assert fixed and "yaml.safe_load(\n        request.data,\n    )" in fixed.text
    from_import = YAML_HANDLER.replace("import yaml\n", "import yaml\nfrom yaml import Loader\n").format(
        line="data = yaml.load(request.data, Loader=Loader)")
    assert codemods.yaml_safe_load(from_import, 10).text.splitlines()[9] == "    data = yaml.safe_load(request.data)"


@pytest.mark.parametrize("line", [
    "data = yaml.load(request.data, Loader=yaml.SafeLoader)",  # already safe
    "data = yaml.load(request.data, Loader=yaml.BaseLoader)",  # builds only strings: not the same result
    "data = yaml.load(request.data, Loader=yaml.CLoader)",  # a different (C) parser, not just a safer one
    "data = yaml.load(request.data, Loader=loader_class)",  # not a known loader
    "data = yaml.load(request.data, Loader=yaml.Loader, other=1)",  # an extra argument
    "data = yaml.load(request.data, yaml.Loader, extra)",  # an extra argument
    "data = yaml.load(*parts)",  # arguments the call builds
    "data = yaml.load(request.data, **options)",
    "data = yaml.load((request.data), Loader=yaml.Loader)",  # parenthesized: not the plain form
    "data = yaml.load(request.data, Loader=yaml.Loader  # trusted)\n    )",  # a comment sits in the call
    "data = yaml.load(request.data, Loader=yaml.Loader) or yaml.load(request.args, Loader=yaml.Loader)",  # two calls
    "data = yaml.unsafe_load(request.data, Loader=yaml.Loader)",  # unsafe_load takes no Loader
    "data = yaml.safe_load(request.data)",  # nothing to fix
    "data = other.load(request.data, Loader=yaml.Loader)",  # not the yaml module
])
def test_yaml_codemod_declines_what_it_cannot_prove(line):
    assert codemods.yaml_safe_load(yaml_source(line), 9) is None


def test_yaml_codemod_declines_when_the_names_are_not_pyyaml():
    wrong_module = YAML_HANDLER.replace("import yaml\n", "import ruamel.yaml as yaml\n").format(
        line="data = yaml.load(request.data, Loader=yaml.Loader)")
    assert codemods.yaml_safe_load(wrong_module, 9) is None
    rebound = YAML_HANDLER.replace("def conf():\n", "def conf(yaml=None):\n").format(
        line="data = yaml.load(request.data, Loader=yaml.Loader)")
    assert codemods.yaml_safe_load(rebound, 9) is None
    reassigned = "import yaml\nyaml = make_yaml()\n\n\ndef conf(body):\n    return yaml.load(body)\n"
    assert codemods.yaml_safe_load(reassigned, 6) is None
    bare = YAML_HANDLER.replace("import yaml\n", "from yaml import load, Loader\n").format(
        line="data = load(request.data, Loader=Loader)")
    assert codemods.yaml_safe_load(bare, 9) is None  # the safe function would need a new import
    shadowed_loader = YAML_HANDLER.replace("import yaml\n", "import yaml\nfrom elsewhere import Loader\n").format(
        line="data = yaml.load(request.data, Loader=Loader)")
    assert codemods.yaml_safe_load(shadowed_loader, 10) is None


def test_yaml_codemod_declines_windows_line_endings_and_unparseable_files():
    text = yaml_source("data = yaml.load(request.data, Loader=yaml.Loader)")
    assert codemods.yaml_safe_load(crlf(text), 9) is None
    assert codemods.yaml_safe_load("import yaml\ndef (:\n    yaml.load(x)\n", 3) is None
    assert codemods.yaml_safe_load(text, 99) is None  # no call on that line


def test_yaml_safe_load_is_registered_for_the_code_injection_rule():
    assert codemods.yaml_safe_load in codemods.CODEMODS["polaris.python.code_injection"]


def test_yaml_fix_is_verified_and_applied_end_to_end(tmp_path):
    text = yaml_source("data = yaml.load(request.data, Loader=yaml.Loader)")
    result = applied_text(tmp_path=tmp_path, path="conf.py", text=text, expected_rule=YAML_RULE,
                          codemod_name="yaml_safe_load")
    assert result == yaml_source("data = yaml.safe_load(request.data)")


def test_a_yaml_fix_is_not_offered_when_other_code_evaluation_stays_on_the_line(tmp_path):
    text = yaml_source("data = [yaml.load(request.data, Loader=yaml.Loader), eval(request.args['x'])]")
    plan = plan_for(make_project(tmp_path, {"conf.py": text}))
    item = next(item for item in plan.items if item.rule_id == YAML_RULE)
    assert item.status == "rejected" and item.proposal is None


# ---- SQL parameters ----------------------------------------------------------------------------

SQL_RULE = "polaris.python.sql_injection"
SQLITE_FILE = "import sqlite3\n\n\ndef find(conn, name, uid, age, row, ids, table, col, n):\n    cur = conn.cursor()\n    {line}\n    return cur.fetchall()\n"
SQL_LINE = 6


def sqlite_source(line: str, header: str = "import sqlite3\n") -> str:
    return SQLITE_FILE.replace("import sqlite3\n", header, 1).format(line=line)


def sql_fix(line: str, header: str = "import sqlite3\n"):
    # The statement sits on line 6 of the one-line header version; more imports push it down.
    return codemods_sql().sql_parameters(sqlite_source(line, header), SQL_LINE + header.count("\n") - 1)


def codemods_sql():
    from polaris.refactor import sql_params

    return sql_params


@pytest.mark.parametrize(("line", "fixed"), [
    # concatenation, quoted and unquoted
    ("cur.execute(\"SELECT * FROM t WHERE name = '\" + name + \"'\")",
     "cur.execute(\"SELECT * FROM t WHERE name = ?\", (name,))"),
    ("cur.execute(\"SELECT * FROM t WHERE id = \" + uid)", "cur.execute(\"SELECT * FROM t WHERE id = ?\", (uid,))"),
    ("cur.execute(\"SELECT * FROM t WHERE name = '\" + name + \"' AND age > \" + age)",
     "cur.execute(\"SELECT * FROM t WHERE name = ? AND age > ?\", (name, age))"),
    # f-strings
    ("cur.execute(f\"SELECT * FROM t WHERE name = '{name}'\")", "cur.execute(\"SELECT * FROM t WHERE name = ?\", (name,))"),
    ("cur.execute(f\"SELECT * FROM t WHERE name = '{name}' AND age >= {age}\")",
     "cur.execute(\"SELECT * FROM t WHERE name = ? AND age >= ?\", (name, age))"),
    # % formatting and .format()
    ("cur.execute(\"SELECT * FROM t WHERE name = '%s'\" % name)", "cur.execute(\"SELECT * FROM t WHERE name = ?\", (name,))"),
    ("cur.execute(\"SELECT * FROM t WHERE name = '%s' AND age < %s\" % (name, age))",
     "cur.execute(\"SELECT * FROM t WHERE name = ? AND age < ?\", (name, age))"),
    ("cur.execute(\"SELECT * FROM t WHERE id = {}\".format(uid))", "cur.execute(\"SELECT * FROM t WHERE id = ?\", (uid,))"),
    ("cur.execute(\"SELECT * FROM t WHERE name = '{}' AND id <> {}\".format(name, uid))",
     "cur.execute(\"SELECT * FROM t WHERE name = ? AND id <> ?\", (name, uid))"),
    # INSERT and UPDATE and DELETE
    ("cur.execute(\"INSERT INTO t (a, b) VALUES ('\" + name + \"', \" + uid + \")\")",
     "cur.execute(\"INSERT INTO t (a, b) VALUES (?, ?)\", (name, uid))"),
    ("cur.execute(f\"INSERT INTO t (a, b, c) VALUES ('{name}', 1, '{age}')\")",
     "cur.execute(\"INSERT INTO t (a, b, c) VALUES (?, 1, ?)\", (name, age))"),
    ("cur.execute(\"UPDATE t SET name = '\" + name + \"' WHERE id = \" + uid)",
     "cur.execute(\"UPDATE t SET name = ? WHERE id = ?\", (name, uid))"),
    ("cur.execute(f\"DELETE FROM t WHERE id = {uid}\")", "cur.execute(\"DELETE FROM t WHERE id = ?\", (uid,))"),
    # attributes, constant subscripts, other receivers, fixed text with quotes of its own
    ("cur.execute(\"SELECT * FROM t WHERE name = '\" + row['name'] + \"'\")",
     "cur.execute(\"SELECT * FROM t WHERE name = ?\", (row['name'],))"),
    ("cur.execute(\"SELECT * FROM t WHERE name = '\" + row.name + \"' AND id = \" + row[0])",
     "cur.execute(\"SELECT * FROM t WHERE name = ? AND id = ?\", (row.name, row[0]))"),
    ("conn.execute(f\"SELECT * FROM t WHERE id = {uid}\")", "conn.execute(\"SELECT * FROM t WHERE id = ?\", (uid,))"),
    ("conn.cursor().execute(f\"SELECT * FROM t WHERE id = {uid}\")",
     "conn.cursor().execute(\"SELECT * FROM t WHERE id = ?\", (uid,))"),
    ("cur.execute(\"SELECT * FROM t WHERE kind = 'user' AND name = '\" + name + \"'\")",
     "cur.execute(\"SELECT * FROM t WHERE kind = 'user' AND name = ?\", (name,))"),
    ("cur.execute(\"SELECT * FROM t WHERE tag LIKE 'a%' AND name = '\" + name + \"'\")",
     "cur.execute(\"SELECT * FROM t WHERE tag LIKE 'a%' AND name = ?\", (name,))"),  # a whole literal with % is fine for ?
    ("cur.execute(\"select * from t where name = '\" + name + \"'\")", "cur.execute(\"select * from t where name = ?\", (name,))"),
    ("cur.execute(\n        \"SELECT * FROM t WHERE name = '\" + name + \"'\"\n    )",
     "cur.execute(\n        \"SELECT * FROM t WHERE name = ?\", (name,)\n    )"),
    ("cur.execute(\"SELECT * FROM t WHERE name = '\" + name + \"'\",)", "cur.execute(\"SELECT * FROM t WHERE name = ?\", (name,),)"),
])
def test_sql_values_move_into_parameters_without_changing_the_query(line, fixed):
    fix = sql_fix(line)
    assert fix is not None, line
    assert fix.name == "sql_parameters" and fix.text == sqlite_source(fixed)
    assert "SQL injection" in fix.rationale and "did not run your code" in fix.rationale


@pytest.mark.parametrize(("header", "marker"), [
    ("import psycopg2\n", "%s"), ("import psycopg\n", "%s"), ("import pymysql\n", "%s"), ("import MySQLdb\n", "%s"),
    ("import mysql.connector\n", "%s"), ("from mysql import connector\n", "%s"),
    ("import psycopg2\nimport psycopg2.extras\nimport pymysql\n", "%s"),  # several drivers that agree
    ("from sqlite3 import connect\n", "?"), ("import sqlite3 as db\n", "?"),
])
def test_the_placeholder_style_follows_the_driver_the_file_imports(header, marker):
    fix = sql_fix("cur.execute(\"SELECT * FROM t WHERE name = '\" + name + \"' AND id = \" + uid)", header)
    assert fix is not None
    assert fix.text == sqlite_source(f"cur.execute(\"SELECT * FROM t WHERE name = {marker} AND id = {marker}\", (name, uid))",
                                     header)


@pytest.mark.parametrize("line", [
    # not the plain "value in value position" shape
    "cur.execute(\"SELECT * FROM t WHERE name LIKE '%\" + name + \"%'\")",  # wildcards around the value
    "cur.execute(\"SELECT * FROM t WHERE name LIKE '\" + name + \"'\")",  # LIKE is not a comparison operator we model
    "cur.execute(\"SELECT * FROM t WHERE name = 'x\" + name + \"'\")",  # only part of the string literal
    "cur.execute(\"SELECT * FROM t WHERE name = '\" + name + \"y'\")",
    "cur.execute(\"SELECT * FROM t WHERE name = '\" + name)",  # the closing quote is missing
    "cur.execute(\"SELECT * FROM t WHERE name = \" + name + \"'\")",  # a stray closing quote
    "cur.execute(\"SELECT * FROM t WHERE a = '\" + name + uid + \"'\")",  # two values in one literal
    "cur.execute(\"SELECT * FROM t WHERE a = \" + name + uid)",  # two values with no text between
    "cur.execute(\"SELECT * FROM t WHERE id IN (\" + name + \")\")",  # an IN list
    "cur.execute(\"SELECT * FROM t WHERE id IN ('\" + name + \"')\")",
    "cur.execute(\"SELECT * FROM \" + table)",  # an identifier
    "cur.execute(\"SELECT * FROM t WHERE \" + col + \" = 1\")",
    "cur.execute(\"SELECT * FROM t ORDER BY \" + col)",
    "cur.execute(\"SELECT * FROM t ORDER BY '\" + col + \"'\")",  # SQLite reads a quoted name as an identifier here
    "cur.execute(\"SELECT * FROM '\" + table + \"'\")",
    "cur.execute(\"SELECT * FROM t LIMIT \" + n)",  # a string bound to LIMIT is an error in some drivers
    "cur.execute(\"SELECT * FROM t WHERE id BETWEEN 1 AND \" + uid)",
    "cur.execute(\"SELECT * FROM t WHERE id = \" + uid + \"abc\")",  # text glued to the value
    "cur.execute(\"SELECT * FROM t WHERE id = \" + uid + \".5\")",
    # values that are not plain
    "cur.execute(\"SELECT * FROM t WHERE name = '\" + name.strip() + \"'\")",
    "cur.execute(\"SELECT * FROM t WHERE id = \" + str(uid))",
    "cur.execute(f\"SELECT * FROM t WHERE id = {uid + 1}\")",
    "cur.execute(f\"SELECT * FROM t WHERE id = {uid!r}\")",
    "cur.execute(f\"SELECT * FROM t WHERE id = {uid:>5}\")",
    "cur.execute(f\"SELECT * FROM t WHERE id = {row[0:1]}\")",
    "cur.execute(\"SELECT * FROM t WHERE id = {0}\".format(uid))",  # numbered fields
    "cur.execute(\"SELECT * FROM t WHERE id = {uid}\".format(uid=uid))",
    "cur.execute(\"SELECT * FROM t WHERE id = %d\" % uid)",  # another conversion
    "cur.execute(\"SELECT * FROM t WHERE id = %(uid)s\" % {'uid': uid})",
    "cur.execute(\"SELECT * FROM t WHERE id = %s AND x = 100%%\" % uid)",
    "cur.execute(\"SELECT * FROM t WHERE id = %s AND x = %s\" % (uid,))",  # the count is wrong
    "cur.execute(\"SELECT * FROM t WHERE id = %s\" % (uid, age))",
    "cur.execute(\"SELECT * FROM t WHERE id = %s\" % uid + \" AND x = 1\")",  # mixed forms
    "cur.execute(\"SELECT * FROM t WHERE id = \" + COND)",  # a module constant is not a value
    "cur.execute(BASE + \" WHERE id = \" + uid)",
    "cur.execute(\"SELECT * FROM t WHERE id = \" + 5)",
    "cur.execute(\"SELECT * FROM t WHERE id = \" + uid + \" AND x = \" + ids[0:2])",
    # text that is misread once parameters are used, or that the codemod does not model
    "cur.execute('SELECT \"a\" FROM t WHERE id = ' + uid)",
    "cur.execute(\"SELECT * FROM t WHERE a = 'it''s' AND id = \" + uid)",
    "cur.execute(\"SELECT * FROM t WHERE a = '\\\\' AND id = \" + uid)",
    "cur.execute(\"SELECT * FROM t WHERE id = \" + uid + \"; DROP TABLE t\")",
    "cur.execute(\"SELECT * FROM t WHERE id = \" + uid + \" -- c\")",
    "cur.execute(\"SELECT * FROM t /* c */ WHERE id = \" + uid)",
    "cur.execute(\"SELECT * FROM t WHERE a = ? AND id = \" + uid)",  # already has a placeholder
    "cur.execute(\"SELECT * FROM t WHERE a = :a AND id = \" + uid)",
    "cur.execute(\"SELECT * FROM t WHERE a = $1 AND id = \" + uid)",
    "cur.execute(\"SELECT * FROM t WHERE data @> 'x' AND id = \" + uid)",
    "cur.execute(\"\"\"SELECT *\n    FROM t WHERE id = \"\"\" + uid)",  # a multi-line query
    "cur.execute(\"CREATE TABLE t (a TEXT DEFAULT '\" + name + \"')\")",  # parameters are not allowed in DDL
    "cur.execute(\"PRAGMA user_version = \" + uid)",
    "cur.execute(\"\" + uid)",
    # the shape of the call
    "cur.execute(\"SELECT * FROM t WHERE id = \" + uid, (age,))",  # parameters already passed
    "cur.execute(sql=\"SELECT * FROM t WHERE id = \" + uid)",
    "cur.execute(*parts)",
    "cur.executemany(\"INSERT INTO t VALUES (\" + uid + \")\", [])",
    "cur.executescript(\"SELECT * FROM t WHERE id = \" + uid)",
    "get_cursor().execute(\"SELECT * FROM t WHERE id = \" + uid)",  # a receiver we can't see
    "conn.cursor(row_factory).execute(\"SELECT * FROM t WHERE id = \" + uid)",
    "cur.execute((\"SELECT * FROM t WHERE id = \" + uid))",  # extra parentheses
    "cur.execute(\"SELECT * FROM t WHERE id = \" + uid  # trusted\n    )",
    "cur.execute(\"SELECT * FROM t WHERE id = \" + uid); cur.execute(\"SELECT * FROM t WHERE id = \" + age)",
])
def test_sql_codemod_declines_what_it_cannot_prove(line):
    assert sql_fix(line) is None, line


def test_sql_codemod_declines_a_percent_sign_when_the_driver_uses_percent_placeholders():
    line = "cur.execute(\"SELECT * FROM t WHERE tag LIKE 'a%' AND name = '\" + name + \"'\")"
    assert sql_fix(line) is not None  # sqlite's ? is not affected by a % in the text
    assert sql_fix(line, "import psycopg2\n") is None  # a lone % would need escaping as %%


@pytest.mark.parametrize("header", [
    "",  # no driver imported: the placeholder style is unknown
    "import sqlite3\nimport psycopg2\n",  # two styles
    "import sqlite3\nimport sqlalchemy\n",  # a library with other bind syntax
    "import sqlite3\nfrom django.db import connection\n",
    "import psycopg2\nimport asyncpg\n",
    "import sqlite3\nimport pandas as pd\n",
    "import asyncpg\n",  # not a style this codemod knows
    "import mysql\n",
    "from . import sqlite3\n",
])
def test_sql_codemod_declines_when_the_placeholder_style_is_not_certain(header):
    assert sql_fix("cur.execute(\"SELECT * FROM t WHERE id = \" + uid)", header) is None


def test_sql_codemod_declines_windows_line_endings_and_unparseable_files():
    text = sqlite_source("cur.execute(\"SELECT * FROM t WHERE id = \" + uid)")
    assert codemods_sql().sql_parameters(crlf(text), SQL_LINE) is None
    assert codemods_sql().sql_parameters("import sqlite3\ndef (:\n    cur.execute('x' + y)\n", 3) is None
    assert codemods_sql().sql_parameters(text, 99) is None


def test_sql_parameters_is_registered_for_the_sql_injection_rule():
    from polaris.refactor import sql_params

    assert sql_params.sql_parameters in codemods.CODEMODS[SQL_RULE]


@pytest.mark.parametrize(("header", "line", "fixed", "name"), [
    ("import sqlite3\n", "cur.execute(\"SELECT * FROM t WHERE name = '\" + name + \"'\")",
     "cur.execute(\"SELECT * FROM t WHERE name = ?\", (name,))", "sqlite"),
    ("import psycopg2\n", "cur.execute(\"SELECT * FROM t WHERE name = '%s'\" % name)",
     "cur.execute(\"SELECT * FROM t WHERE name = %s\", (name,))", "psycopg"),
    ("import pymysql\n", "cur.execute(f\"UPDATE t SET name = '{name}' WHERE id = {uid}\")",
     "cur.execute(\"UPDATE t SET name = %s WHERE id = %s\", (name, uid))", "mysql"),
    ("import sqlite3\n", "cur.execute(\n        \"SELECT * FROM t WHERE name = '{}'\".format(name)\n    )",
     "cur.execute(\n        \"SELECT * FROM t WHERE name = ?\", (name,)\n    )", "multiline"),
])
def test_sql_fix_is_verified_and_applied_end_to_end(tmp_path, header, line, fixed, name):
    result = applied_text(path="db.py", text=sqlite_source(line, header), tmp_path=tmp_path, expected_rule=SQL_RULE,
                          codemod_name="sql_parameters", label=name)
    assert result == sqlite_source(fixed, header)


# ---- Node TLS checks ---------------------------------------------------------------------------

TLS_RULE = "polaris.js.unsafe_security_configuration.tls_disabled"


def js_reject(text: str, line: int):
    from polaris.refactor import js_tls

    return js_tls.reject_unauthorized_true(text, line)


def js_env(text: str, line: int):
    from polaris.refactor import js_tls

    return js_tls.node_tls_unset(text, line)


AGENT = "const https = require('https');\nconst agent = new https.Agent({PAIR});\nmodule.exports = agent;\n"


@pytest.mark.parametrize(("pair", "fixed"), [
    (" rejectUnauthorized: false ", " rejectUnauthorized: true "),
    (" rejectUnauthorized  :  false ", " rejectUnauthorized  :  true "),  # the spacing is kept
    (" keepAlive: true, rejectUnauthorized: false", " keepAlive: true, rejectUnauthorized: true"),
    (" 'rejectUnauthorized': false ", " 'rejectUnauthorized': true "),
    (' "rejectUnauthorized": false ', ' "rejectUnauthorized": true '),
])
def test_reject_unauthorized_false_becomes_true_and_only_the_literal_changes(pair, fixed):
    fix = js_reject(AGENT.replace("PAIR", pair), 2)
    assert fix and fix.name == "tls_reject_unauthorized_true" and fix.text == AGENT.replace("PAIR", fixed)
    assert "did not run your code" in fix.rationale and "ca option" in fix.rationale


def test_reject_unauthorized_handles_multiline_objects_and_typescript():
    spread = "const https = require('https');\nconst agent = new https.Agent({\n  keepAlive: true,\n  rejectUnauthorized: false,\n});\n"
    fixed = js_reject(spread, 4)
    assert fixed and fixed.text == spread.replace("rejectUnauthorized: false", "rejectUnauthorized: true")
    typed = ("import https from 'https';\n"
             "export const agent: https.Agent = new https.Agent({ rejectUnauthorized: false } as https.AgentOptions);\n")
    assert js_reject(typed, 2).text == typed.replace("false", "true")  # type syntax needs the TypeScript grammar
    jsx = "const view = <Secure agent={new Agent({ rejectUnauthorized: false })} />;\n"
    assert js_reject(jsx, 1).text == jsx.replace("false", "true")  # and JSX the JavaScript one


@pytest.mark.parametrize("pair", [
    " rejectUnauthorized: !!insecure ",  # not the bare literal
    " rejectUnauthorized: (false) ",
    " rejectUnauthorized: process.env.STRICT === '1' ",
    " rejectUnauthorized: true ",  # nothing to fix
    " ['rejectUnauthorized']: false ",  # a computed key
    " 'reject\\u0055nauthorized': false ",  # a key that is not spelled out
    " rejectUnauthorized: false }, { rejectUnauthorized: false ",  # two on one line
    " requestCert: false ",
])
def test_reject_unauthorized_codemod_declines_what_it_cannot_prove(pair):
    assert js_reject(AGENT.replace("PAIR", pair), 2) is None


def test_reject_unauthorized_codemod_ignores_patterns_and_types():
    assert js_reject("const { rejectUnauthorized = false } = options;\n", 1) is None  # a default, not a pair
    assert js_reject("type Options = { rejectUnauthorized: false };\n", 1) is None  # a type, not a value
    assert js_reject(AGENT.replace("PAIR", " rejectUnauthorized: false "), 3) is None  # wrong line


def test_node_tls_codemods_decline_windows_line_endings_and_unparseable_files():
    text = AGENT.replace("PAIR", " rejectUnauthorized: false ")
    assert js_reject(crlf(text), 2) is None
    assert js_reject("const agent = new Agent({ rejectUnauthorized: false ;\n", 1) is None
    env = "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\nmodule.exports = 1;\n"
    assert js_env(crlf(env), 1) is None
    assert js_env("process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\nfunction (\n", 1) is None


@pytest.mark.parametrize("statement", [
    "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';",
    'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";',
    "process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;",
    "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'",  # no semicolon
    "process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';",
    'process.env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0";',
    "process.env.NODE_TLS_REJECT_UNAUTHORIZED =\n  '0';",  # spread over two lines
])
def test_the_statement_that_disables_node_tls_checks_is_removed(statement):
    text = f"const https = require('https');\n{statement}\nmodule.exports = https;\n"
    fix = js_env(text, 2)
    assert fix and fix.name == "tls_env_check_restored"
    assert fix.text == "const https = require('https');\nmodule.exports = https;\n"
    assert "NODE_EXTRA_CA_CERTS" in fix.rationale and "did not run your code" in fix.rationale


def test_the_statement_is_removed_inside_blocks_and_typescript_keeping_the_other_lines():
    block = ("export function setup(): void {\n  if (process.env.DEV) {\n"
             "    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n    console.log('dev');\n  }\n}\n")
    fixed = js_env(block, 3)
    assert fixed and fixed.text == ("export function setup(): void {\n  if (process.env.DEV) {\n"
                                    "    console.log('dev');\n  }\n}\n")
    alone = "if (process.env.DEV) {\n  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n}\n"
    assert js_env(alone, 2).text == "if (process.env.DEV) {\n}\n"  # an empty block is still valid
    last = "const a = 1;\nprocess.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';"  # no newline at the end of the file
    assert js_env(last, 2).text == "const a = 1;\n"


@pytest.mark.parametrize(("source", "line"), [
    ("if (process.env.DEV) process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\nrun();\n", 1),  # an unbraced if
    ("const a = process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\nrun(a);\n", 1),  # a chained assignment
    ("const f = () => process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\nf();\n", 1),  # an arrow body
    ("setup(), process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\nrun();\n", 1),  # a sequence
    ("process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; // dev only\nrun();\n", 1),  # a comment on the line
    ("setup(); process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\nrun();\n", 1),  # other code on the line
    ("process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0'; run();\n", 1),
    ("process.env.NODE_TLS_REJECT_UNAUTHORIZED = '1';\nrun();\n", 1),  # another value
    ("process.env.NODE_TLS_REJECT_UNAUTHORIZED = value;\nrun();\n", 1),
    ("process.env.NODE_TLS_REJECT_UNAUTHORIZED = '00';\nrun();\n", 1),
    ("env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\nrun();\n", 1),  # not process.env
    ("process.env.OTHER = '0';\nrun();\n", 1),
    ("switch (mode) {\n  case 'dev':\n    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n    break;\n}\n", 3),
    ("function f() {\n  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n  'use strict';\n}\n", 2),  # a directive appears
    ("const a = b\nprocess.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n(run)()\n", 2),  # the next line would join the last
    ("process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n", 7),  # wrong line
])
def test_node_tls_removal_declines_what_it_cannot_prove(source, line):
    assert js_env(source, line) is None, source


def test_both_node_tls_codemods_are_registered_for_the_tls_rule():
    from polaris.refactor import js_tls

    assert codemods.CODEMODS[TLS_RULE] == (js_tls.reject_unauthorized_true, js_tls.node_tls_unset)


@pytest.mark.parametrize(("path", "text", "codemod", "expected"), [
    # The rule's own one-line edit handles the plain spelling, so this uses one it can't match.
    ("agent.js", AGENT.replace("PAIR", " rejectUnauthorized  :  false "), "tls_reject_unauthorized_true",
     AGENT.replace("PAIR", " rejectUnauthorized  :  true ")),
    ("setup.ts", "export function setup(): void {\n  process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\n  run();\n}\n"
     "\nfunction run(): void {}\n", "tls_env_check_restored",
     "export function setup(): void {\n  run();\n}\n\nfunction run(): void {}\n"),
    ("setup.js", "process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';\nconst https = require('https');\nmodule.exports = https;\n",
     "tls_env_check_restored", "const https = require('https');\nmodule.exports = https;\n"),
])
def test_node_tls_fixes_are_verified_and_applied_end_to_end(tmp_path, path, text, codemod, expected):
    assert applied_text(path=path, text=text, tmp_path=tmp_path, expected_rule=TLS_RULE, codemod_name=codemod,
                        label=path.replace(".", "_")) == expected


# ---- GitHub Actions: env: indirection ----------------------------------------------------------

GHA_RULE = "polaris.gha.workflow_injection.run"
WORKFLOW = (
    "name: triage\n"
    "on:\n"
    "  issues:\n"
    "    types: [opened]\n"
    "jobs:\n"
    "  triage:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "{steps}"
)
SCRIPT_LINE = 11  # the first script line when a step is `- name: Greet` + `run: |`


def workflow(steps: str) -> str:
    return WORKFLOW.format(steps=steps)


def named_step(script: str, extra: str = "") -> str:
    body = "".join(f"          {row}\n" for row in script.split("\n"))
    return f"      - name: Greet\n{extra}        run: |\n{body}"


def gha_env(text: str, line: int):
    from polaris.refactor import gha_env

    return gha_env.env_indirection(text, line)


@pytest.mark.parametrize(("script", "fixed_script", "variable"), [
    ('echo "New issue: ${{ github.event.issue.title }}"', 'echo "New issue: ${ISSUE_TITLE}"', "ISSUE_TITLE"),
    ("echo ${{ github.event.issue.title }}", 'echo "$ISSUE_TITLE"', "ISSUE_TITLE"),
    ("echo '${{ github.event.issue.title }}'", "echo ''\"$ISSUE_TITLE\"''", "ISSUE_TITLE"),
    ("TITLE=${{ github.event.issue.title }}", 'TITLE="$ISSUE_TITLE"', "ISSUE_TITLE"),
    ("echo pre${{ github.event.issue.title }}post", 'echo pre"$ISSUE_TITLE"post', "ISSUE_TITLE"),
    ('echo "${{ github.event.comment.body }}"', 'echo "${COMMENT_BODY}"', "COMMENT_BODY"),
    ('echo "${{ github.event.issue.body }}" | wc -c', 'echo "${ISSUE_BODY}" | wc -c', "ISSUE_BODY"),
    ('git checkout "${{ github.head_ref }}"', 'git checkout "${HEAD_REF}"', "HEAD_REF"),
    ('echo "${{github.event.issue.title}}"', 'echo "${ISSUE_TITLE}"', "ISSUE_TITLE"),
])
def test_an_untrusted_expression_moves_into_env_with_matching_quotes(script, fixed_script, variable):
    original = "${{" + script.split("${{", 1)[1].split("}}", 1)[0] + "}}"  # copied exactly as written
    text = workflow(named_step(script))
    fix = gha_env(text, SCRIPT_LINE)
    assert fix is not None, script
    assert fix.name == "gha_env_indirection" and "did not run your workflow" in fix.rationale
    assert fix.text == workflow(
        f"      - name: Greet\n        env:\n          {variable}: {original}\n        run: |\n          {fixed_script}\n")


def test_other_script_lines_are_kept_and_env_goes_next_to_existing_keys():
    script = "set -eu\necho start\necho \"${{ github.event.issue.title }}\"\necho done"
    fix = gha_env(workflow(named_step(script)), SCRIPT_LINE + 2)
    assert fix and fix.text == workflow(
        "      - name: Greet\n        env:\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n        run: |\n"
        "          set -eu\n          echo start\n          echo \"${ISSUE_TITLE}\"\n          echo done\n")


def test_an_existing_env_block_gets_the_new_variable_added():
    extra = "        env:\n          TOKEN_NAME: abc\n"
    fix = gha_env(workflow(named_step('echo "${{ github.event.issue.title }}"', extra)), SCRIPT_LINE + 2)
    assert fix and fix.text == workflow(
        "      - name: Greet\n        env:\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n"
        "          TOKEN_NAME: abc\n        run: |\n          echo \"${ISSUE_TITLE}\"\n")


def test_a_run_key_that_shares_the_dash_line_gets_env_below_the_script():
    steps = "      - run: |\n          echo \"${{ github.event.issue.title }}\"\n          echo done\n      - run: echo next\n"
    fix = gha_env(workflow(steps), 10)
    assert fix and fix.text == workflow(
        "      - run: |\n          echo \"${ISSUE_TITLE}\"\n          echo done\n        env:\n"
        "          ISSUE_TITLE: ${{ github.event.issue.title }}\n      - run: echo next\n")
    last = "      - run: |\n          echo \"${{ github.event.issue.title }}\"\n"
    assert gha_env(workflow(last), 10).text == workflow(
        "      - run: |\n          echo \"${ISSUE_TITLE}\"\n        env:\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n")


@pytest.mark.parametrize("script", [
    'echo "$(echo ${{ github.event.issue.title }})"',  # inside a command substitution
    "echo `echo ${{ github.event.issue.title }}`",
    "cat <<EOF\n${{ github.event.issue.title }}\nEOF",  # inside a heredoc
    "echo hi # ${{ github.event.issue.title }}",  # in a comment
    "echo \\${{ github.event.issue.title }}",  # after an escape
    'echo "${{ github.event.issue.title }}" "${{ github.event.issue.body }}"',  # two expressions on a line
    'echo "${{ toJSON(github.event.issue) }}"',  # not a plain property path
    'echo "${{ github.event.issue.title || \'x\' }}"',
    'echo "${{ format(\'{0}\', github.event.issue.title) }}"',
    'echo "${{ github.sha }}"',  # not untrusted
    'echo "${{ github.event.issue.number }}"',
    'echo "${{ env.TITLE }}"',
    'echo "${{ secrets.TOKEN }}"',
])
def test_env_indirection_declines_what_it_cannot_prove(script):
    text = workflow(named_step(script))
    # try every script line so a refusal is not just a wrong line number
    assert all(gha_env(text, number) is None for number in range(SCRIPT_LINE - 2, SCRIPT_LINE + 6))


def test_env_indirection_declines_other_steps_and_shells():
    plain = 'echo "${{ github.event.issue.title }}"'
    windows = WORKFLOW.replace("ubuntu-latest", "windows-latest").format(steps=named_step(plain))
    assert gha_env(windows, SCRIPT_LINE) is None  # PowerShell by default
    powershell = workflow(named_step(plain, "        shell: pwsh\n"))
    assert gha_env(powershell, SCRIPT_LINE + 1) is None
    unknown_runner = WORKFLOW.replace("ubuntu-latest", "self-hosted").format(steps=named_step(plain))
    assert gha_env(unknown_runner, SCRIPT_LINE) is None  # the shell is not known
    explicit = workflow(named_step(plain, "        shell: bash\n"))
    assert gha_env(explicit, SCRIPT_LINE + 1) is not None
    folded = workflow("      - name: Greet\n        run: >\n          echo \"${{ github.event.issue.title }}\"\n")
    assert gha_env(folded, 11) is None  # not a literal block
    one_line = workflow("      - name: Greet\n        run: echo \"${{ github.event.issue.title }}\"\n")
    assert gha_env(one_line, 10) is None
    keep = workflow("      - name: Greet\n        run: |+\n          echo \"${{ github.event.issue.title }}\"\n\n")
    assert gha_env(keep, 11) is None
    github_script = workflow("      - uses: actions/github-script@v7\n        with:\n          script: |\n"
                             "            console.log('${{ github.event.issue.title }}')\n")
    assert gha_env(github_script, 12) is None  # not a run: script


def test_env_indirection_declines_name_collisions_and_flow_env():
    plain = 'echo "${{ github.event.issue.title }}"'
    taken = workflow(named_step(plain, "        env:\n          issue_title: other\n"))
    assert gha_env(taken, SCRIPT_LINE + 2) is None
    job_env = WORKFLOW.replace("    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    env:\n      ISSUE_TITLE: x\n")
    assert gha_env(job_env.format(steps=named_step(plain)), SCRIPT_LINE + 2) is None
    mentioned = workflow(named_step('echo "$ISSUE_TITLE ${{ github.event.issue.title }}"'))
    assert gha_env(mentioned, SCRIPT_LINE) is None
    flow = workflow(named_step(plain, "        env: {OTHER: x}\n"))
    assert gha_env(flow, SCRIPT_LINE + 1) is None


def test_env_indirection_declines_shared_steps_windows_line_endings_tabs_and_broken_yaml():
    shared = workflow("      - &greet\n        run: |\n          echo \"${{ github.event.issue.title }}\"\n      - *greet\n")
    assert all(gha_env(shared, number) is None for number in range(8, 16))
    text = workflow(named_step('echo "${{ github.event.issue.title }}"'))
    assert gha_env(crlf(text), SCRIPT_LINE) is None
    assert gha_env(text.replace("    types: [opened]", "\ttypes: [opened]"), SCRIPT_LINE) is None
    assert gha_env("on: [\nrun: |\n", 2) is None
    assert gha_env(text, 99) is None


def test_env_indirection_is_registered_for_the_run_injection_rule():
    from polaris.refactor import gha_env as module

    assert module.env_indirection in codemods.CODEMODS[GHA_RULE]


@pytest.mark.parametrize(("steps", "expected"), [
    (named_step('echo "New issue: ${{ github.event.issue.title }}"'),
     "      - name: Greet\n        env:\n          ISSUE_TITLE: ${{ github.event.issue.title }}\n        run: |\n"
     "          echo \"New issue: ${ISSUE_TITLE}\"\n"),
    ("      - run: |\n          echo ${{ github.event.issue.body }}\n",
     "      - run: |\n          echo \"$ISSUE_BODY\"\n        env:\n          ISSUE_BODY: ${{ github.event.issue.body }}\n"),
])
def test_env_indirection_is_verified_and_applied_end_to_end(tmp_path, steps, expected):
    result = applied_text(path=".github/workflows/triage.yml", text=workflow(steps), tmp_path=tmp_path,
                          expected_rule=GHA_RULE, codemod_name="gha_env_indirection", label=str(len(steps)))
    assert result == workflow(expected)

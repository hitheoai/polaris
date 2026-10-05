"""Rule and analyzer behavior found by the hand-written benchmark challenge set."""

from __future__ import annotations

import pytest

from polaris.review.dataflow import analyze
from polaris.review.extract import units_from_source
from polaris.review.rules import rule_result


def verdict(code: str, check: str) -> str:
    units, reason = units_from_source("example.py", code)
    assert reason is None
    results = [rule_result(check, analyze(unit.node, unit.imports))[0] for unit in units if unit.kind == "function"]
    assert len(results) == 1
    return results[0]


@pytest.mark.parametrize("call", ["subprocess.run(step.command, shell=True)", "subprocess.run(step.command)",
                                  "os.system(job['command'])"])
def test_whole_command_from_a_parameter_needs_context(call):
    code = f"import os\nimport subprocess\n\n\ndef execute_step(step, job):\n    {call}\n"
    assert verdict(code, "command_injection") == "needs_context"


def test_whole_command_from_request_data_is_flagged():
    code = ("import subprocess\nfrom flask import request\n\n\ndef run():\n"
            "    subprocess.run(request.form['cmd'], shell=True)\n")
    assert verdict(code, "command_injection") == "flagged"


def test_whole_query_from_a_parameter_needs_context():
    code = "def run(cursor, job):\n    cursor.execute(job.sql)\n"
    assert verdict(code, "sql_injection") == "needs_context"


def test_placeholder_join_is_not_tainted():
    code = ("def delete(db, ids):\n    marks = ','.join('?' for _ in ids)\n"
            "    db.execute(f'DELETE FROM users WHERE id IN ({marks})', ids)\n")
    assert verdict(code, "sql_injection") == "ok"


def test_value_join_is_still_flagged():
    code = ("def delete(db, ids):\n    marks = ','.join(str(i) for i in ids)\n"
            "    db.execute(f'DELETE FROM users WHERE id IN ({marks})')\n")
    assert verdict(code, "sql_injection") == "flagged"


def test_asyncpg_fetch_with_sql_is_checked():
    code = ("async def audit(conn, actor):\n"
            "    return await conn.fetch(f\"SELECT * FROM audit_log WHERE actor = '{actor}'\")\n")
    assert verdict(code, "sql_injection") == "flagged"
    safe = "async def audit(conn, actor):\n    return await conn.fetchrow('SELECT * FROM audit_log WHERE actor = $1', actor)\n"
    assert verdict(safe, "sql_injection") == "ok"


def test_query_builder_execute_without_sql_is_not_a_sql_call():
    code = ("def store(client, row):\n    return client.table('messages').insert(row).execute()\n\n\n"
            "def latest(client, room):\n    return client.table('rooms').select('*').eq('name', room).limit(1).execute()\n")
    units, _ = units_from_source("example.py", code)
    assert all(not analyze(unit.node, unit.imports).sinks for unit in units)
    raw = "def run(cursor, **options):\n    cursor.execute(**options)\n"
    assert verdict(raw, "sql_injection") == "needs_context"


def test_shutil_which_with_a_fixed_name_is_a_fixed_program():
    code = ("import shutil\nimport subprocess\n\n\ndef containers(host):\n"
            "    binary = shutil.which('docker')\n"
            "    return subprocess.run([binary, '--host', host, 'ps'], capture_output=True)\n")
    assert verdict(code, "command_injection") == "ok"
    chosen = ("import shutil\nimport subprocess\n\n\ndef version(tool):\n"
              "    return subprocess.run([shutil.which(tool), '--version'])\n")
    # The caller chooses the program: like a caller-supplied command, this needs the call sites.
    assert verdict(chosen, "command_injection") == "needs_context"


def test_http_fetch_is_not_sql():
    code = "async def load(client, item_id):\n    return await client.fetch(f'https://api.example.com/items/{item_id}')\n"
    units, _ = units_from_source("example.py", code)
    facts = analyze(units[0].node, units[0].imports)
    assert not facts.sinks

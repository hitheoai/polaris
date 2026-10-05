"""Reconstruction of the 16-function Python evaluation (9 vulnerable, 7 safe) reported for 0.3.x.

The original functions weren't shared; these follow the reported categories exactly: SQL built
with f-strings, %, .format() and joining (including SQLAlchemy text() and Flask request input),
shell=True, os.system and os.popen, the missed `git clone` without `--`; safe parameterized
queries, fixed command lists, shlex.quote, module constants and an allowlisted table name.
Two extra cases pin the label consistency issue (caller-supplied whole command vs program).
"""

from harness import Case

H = "import os\nimport shlex\nimport subprocess\nimport sqlite3\nfrom flask import Flask, request\nfrom sqlalchemy import text\n\napp = Flask(__name__)\n\n"


def py(name: str, check: str, expect: str, body: str, line: int | None = None, note: str = "") -> Case:
    return Case(id=f"eval-{name}", check=check, expect=expect, files={"app/handlers.py": H + body},  # type: ignore[arg-type]
                line=line, language="python", split="evaluator", note=note)


CASES = [
    # --- vulnerable (9)
    py("sql-fstring-flask", "sql_injection", "flagged",
       "@app.get('/users')\ndef users():\n    db = sqlite3.connect('app.db')\n    name = request.args['name']\n"
       "    return db.execute(f\"SELECT * FROM users WHERE name = '{name}'\").fetchall()\n", 14),
    py("sql-percent", "sql_injection", "flagged",
       "def find_order(db, order_id):\n    return db.execute(\"SELECT * FROM orders WHERE id = %s\" % order_id)\n", 11),
    py("sql-format", "sql_injection", "flagged",
       "def find_user(cursor, email):\n    cursor.execute(\"SELECT * FROM users WHERE email = '{}'\".format(email))\n", 11),
    py("sql-join", "sql_injection", "flagged",
       "def search(cursor, term):\n    query = \"SELECT * FROM items WHERE title LIKE '%\" + term + \"%'\"\n    cursor.execute(query)\n", 12),
    py("sql-sqlalchemy-text", "sql_injection", "flagged",
       "@app.post('/report')\ndef report():\n    engine = app.config['ENGINE']\n    region = request.form['region']\n"
       "    with engine.connect() as connection:\n        return connection.execute(text(f\"SELECT * FROM sales WHERE region = '{region}'\")).all()\n", 15),
    py("cmd-shell-true", "command_injection", "flagged",
       "def archive(folder):\n    subprocess.run(f\"tar czf backup.tgz {folder}\", shell=True, check=True)\n", 11),
    py("cmd-os-system", "command_injection", "flagged",
       "@app.post('/ping')\ndef ping():\n    host = request.form['host']\n    os.system('ping -c 1 ' + host)\n    return 'ok'\n", 13),
    py("cmd-os-popen", "command_injection", "flagged",
       "def disk_usage(path):\n    return os.popen('du -sh ' + path).read()\n", 11),
    py("cmd-git-clone-no-separator", "command_injection", "flagged",
       "@app.post('/import')\ndef import_repo():\n    repo_url = request.json['repo_url']\n"
       "    subprocess.run(['git', 'clone', repo_url, '/srv/imports/repo'], check=True)\n    return 'ok'\n", 13,
       note="Option injection: --upload-pack=... without a -- separator (missed by 0.3.x)."),
    # --- safe (7)
    py("safe-sql-parameterized", "sql_injection", "none",
       "def find_user(cursor, email):\n    cursor.execute('SELECT * FROM users WHERE email = ?', (email,))\n"),
    py("safe-sql-parameterized-named", "sql_injection", "none",
       "@app.get('/orders')\ndef orders():\n    db = sqlite3.connect('app.db')\n"
       "    return db.execute('SELECT * FROM orders WHERE status = :status', {'status': request.args['status']}).fetchall()\n"),
    py("safe-cmd-fixed-list", "command_injection", "none",
       "def list_files():\n    return subprocess.run(['ls', '-la', '/srv/data'], capture_output=True, check=True).stdout\n"),
    py("safe-cmd-shlex-quote", "command_injection", "none",
       "def archive(folder):\n    subprocess.run(f\"tar czf backup.tgz {shlex.quote(folder)}\", shell=True, check=True)\n"),
    py("safe-sql-module-constant", "sql_injection", "none",
       "ACTIVE_USERS = 'SELECT id, email FROM users WHERE active = 1'\n\n\ndef active_users(cursor):\n"
       "    cursor.execute(ACTIVE_USERS)\n    return cursor.fetchall()\n"),
    py("safe-sql-allowlisted-table", "sql_injection", "none",
       "ALLOWED_TABLES = {'orders', 'invoices', 'customers'}\n\n\ndef count_rows(cursor, table):\n"
       "    if table not in ALLOWED_TABLES:\n        raise ValueError('unknown table')\n"
       "    cursor.execute(f'SELECT COUNT(*) FROM {table}')\n    return cursor.fetchone()[0]\n",
       note="False alarm in 0.3.x: the allowlist check wasn't recognized."),
    py("safe-cmd-git-clone-separator", "command_injection", "none",
       "@app.post('/import')\ndef import_repo():\n    repo_url = request.json['repo_url']\n"
       "    subprocess.run(['git', 'clone', '--', repo_url, '/srv/imports/repo'], check=True)\n    return 'ok'\n"),
    # --- label consistency: both caller-supplied shapes need caller context (0.3.x disagreed)
    py("context-whole-command", "command_injection", "needs_context",
       "def run_command(command):\n    return subprocess.run(command, check=True)\n"),
    py("context-program-in-list", "command_injection", "needs_context",
       "def run_tool(program, path):\n    return subprocess.run([program, path], check=True)\n"),
]

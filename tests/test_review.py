"""Review engine tests. Scripted and tiny random models exercise software only, never quality."""

import ast
import json
import subprocess
import textwrap

import pytest
from review_helpers import ScriptedBackend

from polaris.engine import Assessor
from polaris.review import (
    ReviewCache,
    ReviewConfig,
    Reviewer,
    SourceFile,
    load_config,
    to_sarif,
    to_text,
)
from polaris.review.config import ConfigError
from polaris.review.dataflow import analyze, module_imports
from polaris.review.engine import read_text
from polaris.review.extract import parse_unified_diff, units_from_source
from polaris.review.format import build_request
from polaris.review.git import sources_from_git
from polaris.review.rules import rule_result

HEADER = "import os, shlex, subprocess\nfrom flask import request\n\n"


def facts_for(code, name=None):
    tree = ast.parse(HEADER + textwrap.dedent(code))
    node = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and (name is None or n.name == name))
    return analyze(node, module_imports(tree))


@pytest.mark.parametrize(
    ("code", "check", "expected"),
    [
        ("def f(db, name):\n    db.execute(f\"SELECT * FROM t WHERE n = '{name}'\")\n", "sql_injection", "flagged"),
        ("def f(db, name):\n    db.execute('SELECT * FROM t WHERE n = ?', (name,))\n", "sql_injection", "ok"),
        ("def f(db, c):\n    q = 'SELECT id FROM t ORDER BY ' + c\n    db.execute(q)\n", "sql_injection", "flagged"),
        ("def f(db):\n    db.execute(build_query())\n", "sql_injection", "needs_context"),
        ("def f(db, sql):\n    db.execute(sql)\n", "sql_injection", "needs_context"),
        ("def f(db, n):\n    db.execute(f'SELECT * FROM t LIMIT {int(n)}')\n", "sql_injection", "ok"),
        ("def f(db):\n    term = request.args.get('q')\n    db.execute('SELECT ' + term)\n", "sql_injection", "flagged"),
        ("def f(p):\n    subprocess.run(['tar', '-czf', 'x.tgz', '--', p])\n", "command_injection", "ok"),
        ("def f(h):\n    os.system('ping -c 1 ' + h)\n", "command_injection", "flagged"),
        ("def f(h):\n    subprocess.run('ping ' + shlex.quote(h), shell=True)\n", "command_injection", "ok"),
        # A caller-chosen program is judged like a caller-supplied command: it needs the call sites.
        ("def f(tool, a):\n    subprocess.run([tool, a])\n", "command_injection", "needs_context"),
        ("def f(tool, a):\n    subprocess.run([request.args['tool'], a])\n", "command_injection", "flagged"),
        ("def f(url, dest):\n    subprocess.run(['git', 'clone', url, dest])\n", "command_injection", "flagged"),
        ("def f(url, dest):\n    subprocess.run(['git', 'clone', '--', url, dest])\n", "command_injection", "ok"),
        ("def f(cmd):\n    subprocess.run(cmd, shell=True)\n", "command_injection", "needs_context"),
        ("def f():\n    subprocess.run(CMD, shell=True)\n", "command_injection", "ok"),
    ],
)
def test_rule_baseline_reads_facts(code, check, expected):
    assert rule_result(check, facts_for(code))[0] == expected


@pytest.mark.parametrize(
    ("code", "check", "expected"),
    [
        ("def f(db):\n    db.execute(f'SELECT * FROM t WHERE x = {get_filter()}')\n", "sql_injection", "needs_context"),
        ("def f(db):\n    v = get_filter()\n    db.execute(f'SELECT * FROM t WHERE x = {v}')\n", "sql_injection", "needs_context"),
        ("def f(self, db):\n    db.execute(f'SELECT * FROM {self.table}')\n", "sql_injection", "needs_context"),
        ("def f(db, sort):\n    col = SORTS.get(sort, 'id')\n    db.execute(f'SELECT * FROM t ORDER BY {col}')\n", "sql_injection", "ok"),
        ("def f(db, payload):\n    db.execute('SELECT ' + payload.name)\n", "sql_injection", "flagged"),
        ("def main(parser):\n    args = parser.parse_args()\n    os.system('rm -rf ' + args.path)\n", "command_injection", "flagged"),
        ("def f(cmd):\n    subprocess.run(['sh', '-c', cmd])\n", "command_injection", "flagged"),
        ("def f(cmd):\n    shell = 'bash'\n    subprocess.run([shell, '-c', 'echo ' + cmd])\n", "command_injection", "flagged"),
        ("def f():\n    subprocess.run(['sh', '-c', 'make clean'])\n", "command_injection", "ok"),
        ("def f(db, name):\n    db.execute(USER_TEMPLATE % name)\n", "sql_injection", "flagged"),
        ("def f(db):\n    data = request.get_json()\n    clauses = []\n    for key in data:\n        clauses.append(f'{key} = ?')\n"
         "    db.execute('SELECT * FROM t WHERE ' + ' AND '.join(clauses))\n", "sql_injection", "flagged"),
        ("def f(db, t):\n    q = sql.SQL('SELECT * FROM {}').format(sql.Identifier(t))\n    db.execute(q)\n",
         "sql_injection", "ok"),
    ],
)
def test_visibility_lookups_argparse_and_shell_lists(code, check, expected):
    assert rule_result(check, facts_for(code))[0] == expected


def test_short_literals_appear_in_notes_for_commands():
    notes = facts_for("def f(url):\n    subprocess.run(['git', 'clone', url])\n").render()
    assert "string literal 'git'" in notes and "parameter url (untrusted)" in notes


def test_notes_are_facts_not_verdicts():
    notes = facts_for("def f(db, name):\n    db.execute(f\"SELECT {name}\")\n").render()
    assert "f-string using name (untrusted)" in notes and "Separate parameters: no" in notes
    assert not any(word in notes.lower() for word in ("vulnerab", "unsafe", "is safe", "injection"))


def test_later_sanitization_never_masks_an_earlier_call():
    code = "def f(db, name):\n    db.execute(f'SELECT {name}')\n    name = int(name)\n    db.execute(f'SELECT {name}')\n"
    facts = facts_for(code)
    assert [bool(sink.argument.tainted) for sink in facts.sinks] == [True, False]
    assert rule_result("sql_injection", facts)[0] == "flagged"


def test_git_diff_changed_lines_new_deleted_and_deletion_only():
    diff = textwrap.dedent("""\
        diff --git a/app.py b/app.py
        index 1..2 100644
        --- a/app.py
        +++ b/app.py
        @@ -2,2 +2,3 @@ def f():
             keep = 1
        -    old = 2
        +    new = 2
        +    more = 3
        @@ -10,2 +11,0 @@
        -gone = 1
        -gone2 = 2
        diff --git a/new.py b/new.py
        new file mode 100644
        --- /dev/null
        +++ b/new.py
        @@ -0,0 +1,2 @@
        +def g():
        +    pass
        diff --git a/old.py b/old.py
        deleted file mode 100644
        --- a/old.py
        +++ /dev/null
        @@ -1 +0,0 @@
        -x = 1
        """)
    files = {(item.old_path, item.new_path): item for item in parse_unified_diff(diff)}
    assert files[("app.py", "app.py")].changed_lines == {3, 4, 11}
    assert files[(None, "new.py")].changed_lines == {1, 2}
    assert ("old.py", None) in files


def test_plain_multi_file_diff_does_not_misread_deleted_dash_lines():
    diff = "--- a/one.py\n+++ b/one.py\n@@ -1,2 +1,2 @@\n--- not a header\n+x = 1\n keep\n--- a/two.py\n+++ b/two.py\n@@ -5 +5 @@\n-a\n+b\n"
    files = parse_unified_diff(diff)
    assert [(item.new_path, sorted(item.changed_lines)) for item in files] == [("one.py", [1]), ("two.py", [5])]


def test_units_cover_methods_decorators_and_scripts_with_before_matching():
    after = textwrap.dedent("""\
        import os
        class Repo:
            @cached
            def load(self, key):
                return self.db.execute(key)
        def helper():
            def inner():
                os.system("ls")
            inner()
        os.system("echo start")
        """)
    before = after.replace('"ls"', '"pwd"')
    units, reason = units_from_source("repo.py", after, before_text=before)
    assert reason is None
    by_symbol = {unit.symbol: unit for unit in units}
    assert set(by_symbol) == {"Repo.load", "helper", "<module>"}
    assert by_symbol["Repo.load"].start_line == 3 and by_symbol["Repo.load"].source.startswith("@cached")
    assert by_symbol["helper"].before is not None and by_symbol["Repo.load"].before is None
    touched, _ = units_from_source("repo.py", after, changed_lines=frozenset({8}))
    assert [unit.symbol for unit in touched] == ["helper"]
    assert units_from_source("bad.py", "def (:\n")[1] == "parse_error"


BATCH_CODE = HEADER + "\n".join(
    f"def f{i}(db, v):\n    # {marker}\n    return db.execute(f'SELECT {{v}}')\n"
    for i, marker in enumerate(["RISKY"] * 12 + ["UNSURE"] * 5 + ["NOCONTEXT"] * 4 + ["safe"] * 9)
) + "\ndef quiet(x):\n    return x + 1\n"


def test_model_path_maps_every_result_and_batches_by_sixteen():
    backend = ScriptedBackend()
    report = Reviewer(backend).review_snippet(BATCH_CODE, path="svc/db.py")
    assert report.summary.results == {"flagged": 12, "ok": 9 + 2 + 30, "needs_context": 4, "uncertain": 5}
    assert report.summary.units_prefiltered == 1 and report.summary.units_assessed == 30
    assert max(backend.batches) <= 16 and sum(backend.batches) == 30
    flagged = [f for f in report.findings if f.result == "flagged"]
    assert all(f.risk > 0.99 and f.threshold == 0.5 and f.guidance and f.request_digest for f in flagged)
    assert all(f.details and "SQL execution" in f.details[0] for f in flagged)
    assert report.findings[0].result == "flagged" and report.exit_code() == 1
    assert "Experimental model" in " ".join(report.notices)


def test_too_long_and_errors_are_reported_never_passed():
    code = HEADER + "def big(db, v):\n    # TOOLONG\n    db.execute('SELECT ' + v)\n"
    report = Reviewer(ScriptedBackend()).review_snippet(code)
    assert [f.result for f in report.findings] == ["too_large"]
    assert report.exit_code() == 0 and report.exit_code(frozenset({"flagged", "too_large"})) == 1


def test_cache_skips_unchanged_functions(tmp_path):
    backend, cache = ScriptedBackend(), ReviewCache(tmp_path / "cache.sqlite")
    first = Reviewer(backend, cache=cache).review_snippet(BATCH_CODE)
    calls = sum(backend.batches)
    second = Reviewer(backend, cache=cache).review_snippet(BATCH_CODE)
    assert sum(backend.batches) == calls and second.summary.cache_hits == 30
    assert [f.model_dump(exclude={"message"}) for f in first.findings] == [
        f.model_dump(exclude={"message"}) for f in second.findings
    ]
    cache.close()


def test_assess_many_matches_assess_and_isolates_failures():
    backend = ScriptedBackend()
    units, _ = units_from_source("a.py", BATCH_CODE)
    requests = []
    for unit in units[:6]:
        facts = analyze(unit.node, unit.imports)
        requests.append(build_request(path=unit.path, symbol=unit.symbol, start_line=unit.start_line,
                                      source=unit.source, before=None, facts=facts,
                                      checks=["sql_injection"], policy=["Parameters are untrusted."],
                                      policy_source="default"))
    assessor = Assessor(backend, allow_experimental=True)
    batched = assessor.assess_many([*requests, {"contract_version": "polaris.assessment/0.1.0"}])
    assert batched[-1].kind == "error" and batched[-1].code == "invalid_input"
    for request, response in zip(requests, batched, strict=False):
        assert response == assessor.assess(request)
    assert Assessor(None).assess_many(requests[:1])[0].code == "model_unavailable"


def test_repository_configuration(tmp_path):
    (tmp_path / ".polaris.toml").write_text(
        '[review]\npolicy = ["Only admins call these scripts."]\nflag_threshold = 1\nexclude = ["legacy/**"]\n'
    )
    config, origin = load_config(tmp_path)
    assert config.policy_source == "repository" and config.flag_threshold == 1.0
    assert "legacy/**" in config.exclude and "**/migrations/**" in config.exclude and origin.endswith(".polaris.toml")
    (tmp_path / ".polaris.toml").unlink()
    (tmp_path / "pyproject.toml").write_text('[tool.polaris.review]\nchecks = ["sql_injection"]\n')
    assert load_config(tmp_path)[0].checks == ["sql_injection"]
    (tmp_path / "pyproject.toml").write_text('[tool.polaris.review]\nsurprise = true\n')
    with pytest.raises(ConfigError):
        load_config(tmp_path)
    assert load_config(None)[0].policy_source == "default"


def test_sarif_and_text_outputs():
    report = Reviewer(ScriptedBackend()).review_snippet(BATCH_CODE, path="svc/db.py")
    sarif = to_sarif(report)
    run = sarif["runs"][0]
    assert sarif["version"] == "2.1.0" and {r["id"] for r in run["tool"]["driver"]["rules"]} == {
        "polaris/sql_injection", "polaris/command_injection"}
    levels = {result["level"] for result in run["results"]}
    assert levels == {"error", "warning"}
    location = run["results"][0]["locations"][0]["physicalLocation"]
    assert location["artifactLocation"]["uri"] == "svc/db.py" and location["region"]["startLine"] >= 1
    assert all(result["partialFingerprints"]["polarisFinding/v1"] for result in run["results"])
    json.dumps(sarif)
    text = to_text(report)
    assert "FLAGGED" in text and "Summary: 12 flagged" in text and "\033[" not in text


def test_rules_engine_needs_no_model():
    report = Reviewer(engine="rules").review_snippet(HEADER + "def f(h):\n    os.system('ping ' + h)\n")
    assert [f.result for f in report.findings] == ["flagged"] and report.model.engine == "rules"
    with pytest.raises(Exception, match="local model bundle"):
        Reviewer(None)


def test_read_text_rejects_traversal_symlinks_and_large_files(tmp_path):
    (tmp_path / "ok.py").write_text("x = 1\n")
    (tmp_path / "big.py").write_text("x" * 5000)
    (tmp_path / "link.py").symlink_to(tmp_path / "ok.py")
    assert read_text(tmp_path, "ok.py", 1000) == "x = 1\n"
    assert read_text(tmp_path, "../ok.py", 1000) is None
    assert read_text(tmp_path, str(tmp_path / "ok.py"), 1000) is None
    assert read_text(tmp_path, "link.py", 1000) is None
    assert read_text(tmp_path, "big.py", 1000) is None


def test_scan_prunes_environment_folders_and_counts_skips(tmp_path):
    (tmp_path / "app").mkdir()
    (tmp_path / "app" / "views.py").write_text(HEADER + "def f(h):\n    os.system('ping ' + h)\n")
    (tmp_path / "app" / "broken.py").write_text("def (:\n")
    (tmp_path / ".venv" / "lib").mkdir(parents=True)
    (tmp_path / ".venv" / "lib" / "dep.py").write_text("import os\nos.system(input())\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.py").write_text("import os\nos.system(input())\n")
    report = Reviewer(engine="rules").review_paths([tmp_path], root=tmp_path)
    assert [f.path for f in report.findings] == ["app/views.py"]
    assert report.summary.files_skipped == {"parse_error": 1}


def test_diff_without_repository_reviews_hunks_with_real_line_numbers():
    diff = "--- a/svc.py\n+++ b/svc.py\n@@ -40,2 +40,3 @@\n def run(host):\n-    pass\n+    import os\n+    os.system('ping ' + host)\n"
    report = Reviewer(engine="rules").review_diff(diff)
    assert report.findings and report.findings[0].start_line == 40
    assert any("diff hunks only" in notice for notice in report.notices)


def _git(root, *args):
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t",
                        "GIT_COMMITTER_EMAIL": "t@example.invalid", "HOME": str(root), "PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"})


def test_git_sources_for_worktree_staged_and_untracked(tmp_path):
    _git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "svc.py").write_text(HEADER + "def run(h):\n    subprocess.run(['ping', h])\n\n\ndef other():\n    return 1\n")
    _git(tmp_path, "add", "svc.py")
    _git(tmp_path, "commit", "-q", "-m", "base")
    (tmp_path / "svc.py").write_text(HEADER + "def run(h):\n    os.system('ping ' + h)\n\n\ndef other():\n    return 1\n")
    (tmp_path / "fresh.py").write_text(HEADER + "def g(db, v):\n    db.execute('SELECT ' + v)\n")
    sources = {source.path: source for source in sources_from_git(tmp_path)}
    assert set(sources) == {"svc.py", "fresh.py"}
    assert sources["svc.py"].before and "subprocess.run" in sources["svc.py"].before
    assert sources["svc.py"].changed_lines == frozenset({5}) and sources["fresh.py"].changed_lines is None
    report = Reviewer(engine="rules").review_sources(sources.values())
    assert {(f.path, f.symbol) for f in report.findings} == {("svc.py", "run"), ("fresh.py", "g")}
    assert sources_from_git(tmp_path, staged=True) == []
    _git(tmp_path, "add", "svc.py")
    staged = sources_from_git(tmp_path, staged=True)
    assert [s.path for s in staged] == ["svc.py"] and "os.system" in staged[0].after


def test_source_file_skip_reasons_are_counted():
    report = Reviewer(engine="rules").review_sources([
        SourceFile("a.js", "x"), SourceFile("gone.py", None, skip="deleted"),
        SourceFile("bin.py", "a\0b"), SourceFile("migrations/0001.py", "import os\nos.system(input())\n"),
    ])
    assert report.summary.files_skipped == {"binary": 1, "deleted": 1, "excluded": 1, "not_python": 1}


def test_configured_threshold_changes_only_the_flag_line():
    report = Reviewer(ScriptedBackend(), config=ReviewConfig(flag_threshold=0.99999999)).review_snippet(BATCH_CODE)
    assert report.summary.results.get("flagged", 0) == 0


def test_cli_review_and_scan_outputs_and_exit_codes(tmp_path, capsys, monkeypatch):
    from polaris.cli import main

    (tmp_path / "app.py").write_text(HEADER + "def f(h):\n    os.system('ping ' + h)\n")
    base = ["--engine", "rules", "--root", str(tmp_path)]
    assert main(["review", "--files", str(tmp_path / "app.py"), *base, "--format", "json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["format"] == "polaris.review/0.1.0" and report["summary"]["results"]["flagged"] == 1
    assert main(["scan", str(tmp_path), *base, "--quiet", "--fail-on", "none"]) == 0
    assert "FLAGGED" in capsys.readouterr().out
    output = tmp_path / "report.sarif"
    output.write_text("old")
    assert main(["scan", str(tmp_path), *base, "--quiet", "--format", "sarif", "--output", str(output)]) == 1
    assert json.loads(output.read_text())["version"] == "2.1.0"
    assert main(["scan", str(tmp_path), *base, "--fail-on", "surprise"]) == 2
    monkeypatch.setenv("POLARIS_HOME", str(tmp_path / "empty-home"))
    monkeypatch.delenv("POLARIS_MODEL", raising=False)
    assert main(["scan", str(tmp_path), "--root", str(tmp_path), "--engine", "model"]) == 3
    assert "No Polaris model found" in capsys.readouterr().err
    # The default hybrid engine still reviews with the rules when no model is installed.
    assert main(["scan", str(tmp_path), "--root", str(tmp_path), "--quiet"]) == 1
    assert "No Polaris model is installed" in capsys.readouterr().out


@pytest.mark.ml
def test_real_tiny_bundle_reviews_end_to_end(tmp_path):
    pytest.importorskip("torch")
    pytest.importorskip("transformers")
    from ml_helpers import make_tiny_bundle

    from polaris.runtime import LocalBackend

    backend = LocalBackend(make_tiny_bundle(tmp_path / "tiny"), device="cpu", allow_experimental=True)
    report = Reviewer(backend).review_snippet(BATCH_CODE)
    assert report.summary.units_assessed == 30 and report.summary.results.get("error", 0) == 0
    assert report.model.model_version == "tiny-random-unit-test" and report.summary.results["flagged"] == 30

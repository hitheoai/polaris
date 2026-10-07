"""`polaris fix`: every fix is checked before it is shown, and nothing is written without approval.

Source is fixture data that is parsed, never executed.
"""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from polaris.cli import main
from polaris.engineering import EngineeringError, parse_proposal
from polaris.integrations.forge.verify import MEMORY_ONLY, Reverifier, apply_edit, verify_edits
from polaris.refactor import codemods
from polaris.refactor.apply import apply_fix
from polaris.refactor.cli import _apply
from polaris.refactor.gates import scope_problem
from polaris.refactor.generators import Candidate, SuggestedEdit, deterministic
from polaris.refactor.models import FixItem
from polaris.refactor.plan import build_plan
from polaris.refactor.render import clean, diff_lines
from polaris.review.models import WorkflowReviewConfig
from polaris.workflow.service import review_workspace_detailed

ROOT = Path(__file__).resolve().parents[1]
PING = 'import os\n\n\ndef ping(host):\n    os.system("ping -c 1 " + host)\n'
PING_FIXED = 'import os\nimport subprocess\n\n\ndef ping(host):\n    subprocess.run(["ping", "-c", "1", host])\n'
FETCH = "import requests\n\n\ndef get(url):\n    return requests.get(url, verify=False)\n"
WEB = 'from flask import Flask\n\napp = Flask(__name__)\n\nif __name__ == "__main__":\n    app.run(debug=True)\n'
CLEAN = "def add(a, b):\n    return a + b\n"
GIT_LOG = 'import subprocess\n\n\ndef log(branch):\n    subprocess.run(["git", "log", branch])\n'
SQL = 'def search(db, name):\n    return db.execute("SELECT * FROM people WHERE name = " + name)\n'
GIT_ENV = {"PATH": os.defpath, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}


def make_project(tmp_path: Path, files: dict[str, str], name: str = "project") -> Path:
    root = (tmp_path / name).resolve()
    root.mkdir()
    env = {**GIT_ENV, "HOME": str(tmp_path)}
    subprocess.run(["/usr/bin/git", "--no-pager", "init", "-q", str(root)], check=True, env=env)
    for path, text in files.items():
        (root / path).write_text(text)
    return root


@pytest.fixture
def project(tmp_path):
    return make_project(tmp_path, {"ping.py": PING, "fetch.py": FETCH, "web.py": WEB})


def review_of(root: Path):
    return review_workspace_detailed(root, paths=[root], config=WorkflowReviewConfig(), runtime=MEMORY_ONLY)


def plan_for(root: Path, generators=None, **options):
    return build_plan(root, review_of(root), generators or deterministic(), **options)


def finding_in(review, path: str):
    return next(item for item in review.envelope.review.findings if item.path == path and item.result == "flagged")


class Fixed:
    """A test generator that returns whatever replacement it was given."""

    origin = "codemod"

    def __init__(self, replacement: str, path: str | None = None):
        self.replacement, self.path = replacement, path

    def __call__(self, finding, text):
        return Candidate(self.path or finding.path, self.replacement, "codemod", "test_fix", "A test fix.")


# ---- codemods ----------------------------------------------------------------------------------


def test_os_system_becomes_an_argument_list_and_gets_its_import():
    fix = codemods.command_as_list(PING, 5)
    assert fix and fix.text == PING_FIXED and fix.name == "command_as_list"


def test_the_import_goes_after_the_docstring_and_leading_imports_and_is_not_repeated():
    docstring = '"""Tools."""\n\n\ndef ping(host):\n    os.system("ping " + host)\n'
    assert codemods.command_as_list(docstring, 5).text.splitlines()[:2] == ['"""Tools."""', "import subprocess"]
    already = "import subprocess\nimport os\n\n\ndef ping(host):\n    os.system(f\"ping {host}\")\n"
    fixed = codemods.command_as_list(already, 6)
    assert fixed.text.count("import subprocess") == 1 and 'subprocess.run(["ping", str(host)])' in fixed.text


def test_subprocess_shell_calls_keep_their_other_arguments():
    text = 'import subprocess\n\n\ndef ping(host):\n    subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)\n'
    fixed = codemods.command_as_list(text, 5)
    assert fixed and fixed.text.splitlines()[-1] == (
        '    subprocess.run(["ping", "-c", "1", str(host)], capture_output=True)')
    attribute = 'import os\n\n\ndef run(self):\n    os.system("ls -l " + self.path)\n'
    assert 'subprocess.run(["ls", "-l", self.path])' in codemods.command_as_list(attribute, 5).text


@pytest.mark.parametrize("line", [
    'os.system("bash -c " + command)',  # a shell
    'os.system("git log " + ref)',  # a program that reads options from its arguments
    'result = os.system("ping " + host)',  # its return value is used
    'os.system("echo hi; " + value)',  # shell syntax in the fixed text
    'os.system(command + " -c 1")',  # the program is not fixed
    'os.system("ping " + host.strip())',  # not a plain name
    'os.system("ping %s" % host)',  # another way to build the string
    'os.system("a " + x); os.system("b " + y)',  # two calls on one line
    'subprocess.run("ping " + host, shell=False)',  # no shell to remove
])
def test_command_codemod_declines_what_it_cannot_prove_equivalent(line):
    text = f"import os\nimport subprocess\n\n\ndef f(host, command, ref, value, x, y):\n    {line}\n"
    assert codemods.command_as_list(text, 6) is None


def test_codemods_decline_windows_line_endings_and_unparseable_files():
    assert codemods.command_as_list(PING.replace("\n", "\r\n"), 5) is None
    assert codemods.tls_verification_on("def (:\n", 1) is None


def test_tls_and_debug_codemods_change_only_the_literal():
    assert codemods.tls_verification_on(FETCH, 5).text == FETCH.replace("verify=False", "verify=True")
    spread = "import requests\n\n\ndef get(url):\n    return requests.get(\n        url,\n        verify=False,\n    )\n"
    assert codemods.tls_verification_on(spread, 5).text == spread.replace("verify=False", "verify=True")
    assert codemods.debug_off(WEB, 6).text == WEB.replace("debug=True", "debug=False")
    assert codemods.debug_off("run(debug=True)\n", 1) is None  # not a method call
    assert codemods.tls_verification_on("get(url, verify=flag)\n", 1) is None
    twice = "a.get(x, verify=False); b.get(y, verify=False)\n"
    assert codemods.tls_verification_on(twice, 1) is None


# ---- gates -------------------------------------------------------------------------------------


def make_finding(root, files, name):
    return finding_in(review_of(make_project(root, files, name)), next(iter(files)))


def test_the_scope_lock_keeps_fixes_near_the_problem(tmp_path):
    finding = make_finding(tmp_path, {"ping.py": PING}, "scope")
    assert scope_problem(PING, PING_FIXED, finding) is None  # the fix and its import
    far = PING + "\n" * 100 + "x = 1\n"
    assert scope_problem(far, far.replace("x = 1", "x = 2"), finding) == "change_outside_scope"
    assert scope_problem(PING, PING, finding) == "no_change"
    assert scope_problem(PING, PING + "".join(f"y{i} = {i}\n" for i in range(80)), finding) == "change_too_large"
    # The exemption for imports only matters far from the finding, so put the finding far down the file.
    deep = "import os\n" + "\n" * 100 + "def ping(host):\n    os.system(\"ping -c 1 \" + host)\n"
    deep_finding = make_finding(tmp_path, {"deep.py": deep}, "deep")
    plain = deep.replace("import os\n", "import os\nimport subprocess\n", 1)
    assert scope_problem(deep, plain, deep_finding) is None  # a plain import far from the finding is fine
    for line in ("import shutil as s; s.rmtree('/')", "from os import system; system('x')", "    import json",
                 "import json\nimport yaml\n__import__('os')"):
        sneaky = deep.replace("import os\n", f"import os\n{line}\n", 1)
        assert scope_problem(deep, sneaky, deep_finding) == "change_outside_scope", line


def test_a_fix_may_not_drop_a_value_the_flagged_call_used(tmp_path):
    finding = make_finding(tmp_path, {"db.py": SQL}, "drops")
    kept = SQL.replace('"SELECT * FROM people WHERE name = " + name', '"SELECT * FROM people WHERE name = ?", (name,)')
    dropped = SQL.replace('"SELECT * FROM people WHERE name = " + name', '"SELECT * FROM people WHERE name = %s"')
    assert scope_problem(SQL, kept, finding) is None
    assert scope_problem(SQL, dropped, finding) == "fix_drops_a_value"
    # An f-string that loses its name, a name that survives only as a substring, and a deleted call.
    assert scope_problem(SQL, SQL.replace(' + name', ' + "x"'), finding) == "fix_drops_a_value"
    assert scope_problem(SQL, SQL.replace(' + name', ' + username'), finding) == "fix_drops_a_value"
    assert scope_problem(SQL, "def search(db, name):\n    return None\n", finding) == "fix_drops_a_value"
    # What it leaves alone: a file that doesn't parse (the re-review reports that), an untouched call.
    assert scope_problem(SQL, "def (:\n", finding) is None
    assert scope_problem(SQL, "import json\n" + SQL, finding) is None


def test_the_dropped_value_check_reads_only_the_calls_own_arguments():
    from polaris.refactor.gates import argument_names

    text = "x = db.execute('q' + str(a), (b, c.d), k=e[f])\n"
    assert argument_names(text, 1) == {"a", "b", "c", "e", "f"}  # not db, execute, str or the names k
    assert argument_names(text, 2) == set() and argument_names("def (:\n", 1) == set()


def test_codemod_fixes_keep_the_values_they_were_given():
    for codemod, text, line in ((codemods.command_as_list, PING, 5), (codemods.tls_verification_on, FETCH, 5)):
        assert codemod(text, line)  # these still pass the gate; see the plan tests for the end-to-end path


# ---- the shared re-verifier --------------------------------------------------------------------


def test_the_reverifier_judges_whole_file_replacements(tmp_path):
    root = make_project(tmp_path, {"ping.py": PING})
    review = review_of(root)
    finding = finding_in(review, "ping.py")
    checker = Reverifier(review)
    assert checker.verify(finding, PING_FIXED).status == "verified"
    assert checker.verify(finding, "# note\n" + PING).status == "still_detected"
    assert checker.verify(finding, PING).reason == "no_change"
    extra = ('import requests\nimport subprocess\n\n\ndef ping(host):\n    subprocess.run(["ping", "-c", "1", host])\n'
             "\n\ndef get(url):\n    return requests.get(url, verify=False)\n")
    assert checker.verify(finding, extra).status == "adds_findings"
    assert checker.verify(finding, "def (:\n").status == "inconclusive"  # a syntax error is not a fix


def test_lines_that_move_because_a_fix_added_an_import_are_not_new_findings(tmp_path):
    both = PING + "\n\ndef again(host):\n    os.system(\"ping -c 2 \" + host)\n"
    review = review_of(make_project(tmp_path, {"both.py": both}))
    first = min((item for item in review.envelope.review.findings if item.result == "flagged"),
                key=lambda item: item.start_line)
    fixed = codemods.command_as_list(both, first.start_line)
    assert fixed and fixed.text.count("import subprocess") == 1  # one line added above the second problem
    assert Reverifier(review).verify(first, fixed.text).status == "verified"
    # ...but a problem that really is new is still caught, wherever it sits.
    worse = fixed.text + "\n\ndef get(url):\n    import requests\n    return requests.get(url, verify=False)\n"
    assert Reverifier(review).verify(first, worse).status == "adds_findings"


def test_the_reverifier_declines_windows_line_endings(tmp_path):
    root = make_project(tmp_path, {})
    (root / "ping.py").write_bytes(PING.replace("\n", "\r\n").encode())
    review = review_of(root)
    finding = finding_in(review, "ping.py")
    assert Reverifier(review).verify(finding, PING_FIXED).reason == "carriage_returns"


def test_one_line_suggested_edits_still_verify_as_before(tmp_path):
    root = make_project(tmp_path, {"log.py": GIT_LOG})
    review = review_of(root)
    finding = finding_in(review, "log.py")
    assert finding.suggested_edit is not None
    old = verify_edits(review, [finding])[finding.finding_id]
    new = Reverifier(review).verify(finding, apply_edit(
        GIT_LOG, finding.suggested_edit.line, finding.suggested_edit.original, finding.suggested_edit.replacement))
    assert old.status == new.status == "verified"
    candidate = SuggestedEdit()(finding, GIT_LOG)
    assert candidate and candidate.origin == "suggested_edit" and '"--", branch' in candidate.replacement


# ---- the plan ----------------------------------------------------------------------------------


def test_a_plan_has_a_checked_fix_for_each_problem_and_writes_nothing(project):
    before = {path.name: path.read_text() for path in project.glob("*.py")}
    plan = plan_for(project)
    assert plan.status == "fixes_ready" and plan.counts.verified == 3 and plan.counts.flagged == 3
    assert {item.origin for item in plan.items} == {"codemod"} and plan.behavioral_tests == "not_run"
    assert {path.name: path.read_text() for path in project.glob("*.py")} == before
    for item in plan.items:
        assert item.status == "verified" and item.proposal and item.proposal_digest
        proposal = parse_proposal(item.proposal)
        assert proposal.proposal_digest == item.proposal_digest
        assert proposal.verification_commands == () and proposal.origin == "host_candidate"
    assert [item.attempts[-1].status for item in plan.items] == ["verified"] * 3


def test_one_fix_per_file_per_run_and_a_limit(tmp_path):
    root = make_project(tmp_path, {"both.py": PING + "\n\ndef again(host):\n    os.system(\"ping -c 2 \" + host)\n"})
    plan = plan_for(root)
    assert [item.status for item in plan.items] == ["verified", "deferred"]
    assert plan.items[1].reason == "another_fix_to_this_file_comes_first" and plan.notes
    many = make_project(tmp_path, {"a.py": PING, "b.py": FETCH, "c.py": WEB}, "many")
    limited = plan_for(many, limit=1)
    assert [item.status for item in limited.items] == ["verified", "deferred", "deferred"]
    assert {item.reason for item in limited.items[1:]} == {"fix_limit_reached"}
    with pytest.raises(ValueError):
        plan_for(many, limit=0)


def test_problems_without_a_fix_are_reported_not_hidden(tmp_path):
    plan = plan_for(make_project(tmp_path, {"db.py": SQL}))
    assert plan.status == "no_fixes" and plan.counts.no_candidate == 1
    assert plan.items[0].reason == "no_generator_has_a_fix" and plan.items[0].proposal is None
    assert plan_for(make_project(tmp_path, {"ok.py": CLEAN}, "ok")).status == "nothing_to_fix"


def test_a_candidate_that_does_not_pass_every_check_is_rejected_with_its_reason(tmp_path):
    root = make_project(tmp_path, {"ping.py": PING + "\n" * 100 + "x = 1\n"})
    far = PING + "\n" * 100 + "x = 2\n"
    cases = [
        (Fixed("# note\n" + PING + "\n" * 100 + "x = 1\n"), "finding_still_detected"),
        (Fixed(far), "change_outside_scope"),
        (Fixed(PING_FIXED, path="other.py"), "edits_another_file"),
        (Fixed(PING + "\n" * 100 + "x = 1\n"), "no_change"),
    ]
    for generator, reason in cases:
        plan = plan_for(root, [generator])
        item = plan.items[0]
        assert item.status == "rejected" and item.reason == reason, reason
        assert item.proposal is None and item.attempts[-1].status == "rejected"


def test_the_first_generator_that_passes_wins_and_failures_are_recorded(tmp_path):
    root = make_project(tmp_path, {"ping.py": PING})
    plan = plan_for(root, [Fixed("# note\n" + PING), *deterministic()])
    item = plan.items[0]
    assert item.status == "verified" and item.origin == "codemod"
    assert [attempt.status for attempt in item.attempts] == ["rejected", "verified"]
    assert item.attempts[0].reason == "finding_still_detected"


def test_summaries_leave_out_source_and_diffs(project):
    plan = plan_for(project)
    text = plan.summary().model_dump_json()
    assert "replacement" not in text and "diff" not in text and "subprocess" not in text
    assert plan.items[0].proposal and plan.summary().items[0].proposal_digest == plan.items[0].proposal_digest


# ---- applying ----------------------------------------------------------------------------------


def applied(root, item):
    return apply_fix(root, item.proposal, approved_digest=item.proposal_digest, config=WorkflowReviewConfig(),
                     runtime=MEMORY_ONLY, known=item.known)


def test_an_approved_fix_is_written_and_confirmed_by_a_fresh_check(tmp_path):
    root = make_project(tmp_path, {"ping.py": PING})
    item = plan_for(root).items[0]
    outcome = applied(root, item)
    assert (outcome.applied, outcome.verified, outcome.reason) == (True, True, "no_longer_detected")
    assert (root / "ping.py").read_text() == PING_FIXED
    assert plan_for(root).status == "nothing_to_fix"


def test_a_fix_is_confirmed_when_the_file_has_other_open_notes_that_were_already_there(tmp_path):
    root = make_project(tmp_path, {"fetch.py": FETCH})
    item = plan_for(root).items[0]
    assert item.known  # the SSRF note on `requests.get(url)` was there before the fix
    outcome = applied(root, item)
    assert (outcome.applied, outcome.verified) == (True, True)
    # Without the baseline the same fix is applied but cannot be called confirmed.
    other = make_project(tmp_path, {"fetch.py": FETCH}, "other")
    plain = plan_for(other).items[0]
    unconfirmed = apply_fix(other, plain.proposal, approved_digest=plain.proposal_digest,
                            config=WorkflowReviewConfig(), runtime=MEMORY_ONLY)
    assert (unconfirmed.applied, unconfirmed.verified, unconfirmed.reason) == (True, False, "not_confirmed")


def test_the_baseline_is_never_written_to_json(project):
    plan = plan_for(project)
    assert any(item.known for item in plan.items)
    assert "known" not in plan.model_dump_json() and "known" not in json.dumps(plan.model_dump(mode="json"))


def test_a_fix_is_refused_when_the_digest_differs_or_the_files_moved_on(tmp_path):
    root = make_project(tmp_path, {"ping.py": PING})
    item = plan_for(root).items[0]
    wrong = apply_fix(root, item.proposal, approved_digest="sha256:" + "0" * 64, config=WorkflowReviewConfig(),
                      runtime=MEMORY_ONLY)
    assert (wrong.applied, wrong.reason) == (False, "proposal_mismatch") and (root / "ping.py").read_text() == PING
    edited = PING + "# someone else's edit\n"
    (root / "ping.py").write_text(edited)
    stale = applied(root, item)
    assert not stale.applied and stale.reason.startswith("stale") and (root / "ping.py").read_text() == edited


def test_a_tampered_proposal_is_refused(tmp_path):
    root = make_project(tmp_path, {"ping.py": PING})
    item = plan_for(root).items[0]
    tampered = {**item.proposal, "rationale": "Delete everything."}
    outcome = apply_fix(root, tampered, approved_digest=item.proposal_digest, config=WorkflowReviewConfig(),
                        runtime=MEMORY_ONLY)
    assert not outcome.applied and (root / "ping.py").read_text() == PING
    with pytest.raises(EngineeringError):
        parse_proposal(tampered)


# ---- rendering ---------------------------------------------------------------------------------


def test_text_from_the_repository_cannot_reach_the_terminal_as_control_codes():
    item = FixItem(finding_id="f", path="a.py", line=1, rule_id="r", title="t", status="verified", reason="x",
                   proposal={"diff": "@@ -1 +1 @@\n-\x1b[31mred\x1b[0m\n+\tgood \u202e\n"})
    shown = "\n".join(diff_lines(item))
    assert "\x1b" not in shown and "\u202e" not in shown and "\t" not in shown and "good" in shown
    assert clean("a\x07b\x00c") == "a\ufffdb\ufffdc"


# ---- the command -------------------------------------------------------------------------------


def run(root: Path, *args: str) -> int:
    return main(["fix", "--root", str(root), "--all", *args])


def test_the_command_shows_checked_fixes_and_changes_nothing(project, capsys):
    before = {path.name: path.read_text() for path in project.glob("*.py")}
    assert run(project) == 1
    out = capsys.readouterr().out
    assert "Polaris can fix 3 of 3 problems" in out and "polaris fix --approve sha256:" in out
    assert "subprocess.run" in out and "Your tests were not run" in out
    assert {path.name: path.read_text() for path in project.glob("*.py")} == before


def test_nothing_to_fix_exits_zero(tmp_path, capsys):
    assert run(make_project(tmp_path, {"ok.py": CLEAN})) == 0
    assert "Nothing to fix now." in capsys.readouterr().out


def test_json_output_names_the_fixes_without_source(project, capsys):
    assert run(project, "--json") == 1
    data = json.loads(capsys.readouterr().out)
    assert data["format"] == "polaris.fix-plan/0.1.0" and data["counts"]["verified"] == 3
    assert all(item["proposal"] is None and item["proposal_digest"] for item in data["items"])
    assert "subprocess" not in json.dumps(data)


def test_output_is_a_new_private_file_with_the_proposals(project, tmp_path, capsys):
    target = tmp_path / "plan.json"
    assert run(project, "--output", str(target)) == 1
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    saved = json.loads(target.read_text())
    assert all(parse_proposal(item["proposal"]) for item in saved["items"])
    raw = target.read_bytes()
    capsys.readouterr()
    assert run(project, "--output", str(target)) == 2 and target.read_bytes() == raw
    assert "couldn't write --output" in capsys.readouterr().err


def test_approving_a_digest_applies_exactly_that_fix(project, capsys):
    plan = plan_for(project)
    ping = next(item for item in plan.items if item.path == "ping.py")
    assert run(project, "--approve", ping.proposal_digest) == 1  # the other two problems remain
    out = capsys.readouterr().out
    assert "Fixed ping.py:5" in out
    assert (project / "ping.py").read_text() == PING_FIXED
    assert (project / "fetch.py").read_text() == FETCH and (project / "web.py").read_text() == WEB
    codes = []
    for path in ("fetch.py", "web.py"):
        digest = next(item for item in plan_for(project).items if item.path == path).proposal_digest
        codes.append(run(project, "--approve", digest))
    assert codes == [1, 0]  # applied and confirmed each time; 0 once nothing is left
    assert plan_for(project).status == "nothing_to_fix"
    assert "Polaris couldn't confirm" not in capsys.readouterr().err


def test_an_unknown_digest_changes_nothing(project, capsys):
    assert run(project, "--approve", "sha256:" + "0" * 64) == 2
    assert "None of the fixes Polaris found has that digest" in capsys.readouterr().err
    assert (project / "ping.py").read_text() == PING


def test_apply_needs_a_terminal(project, capsys):
    assert run(project, "--apply") == 2
    assert "needs a terminal" in capsys.readouterr().err and (project / "ping.py").read_text() == PING


def test_interactive_apply_applies_only_what_is_approved(project, monkeypatch, capsys):
    plan = plan_for(project)
    answers = iter([False, True, False])
    monkeypatch.setattr("polaris.refactor.cli._ask", lambda question: next(answers))
    code = _apply(project, [item for item in plan.items if item.status == "verified"], SimpleNamespace(apply=True))
    texts = {path.name: path.read_text() for path in project.glob("*.py")}
    changed = [name for name, text in texts.items() if text not in (PING, FETCH, WEB)]
    assert len(changed) == 1 and code == 1  # one fix applied and confirmed; two were left
    captured = capsys.readouterr()
    assert captured.out.count("Left as it is.") == 2 and "couldn't confirm" not in captured.err


def test_a_folder_without_git_is_refused(tmp_path, capsys):
    folder = tmp_path / "plain"
    folder.mkdir()
    (folder / "ping.py").write_text(PING)
    assert main(["fix", "--root", str(folder), "--all"]) == 2
    assert "needs a Git project" in capsys.readouterr().err and (folder / "ping.py").read_text() == PING


def test_a_bad_limit_is_refused(project, capsys):
    assert run(project, "--limit", "0") == 2
    assert "--limit" in capsys.readouterr().err


def test_fix_is_listed_next_to_check_and_the_public_wheel_ships_it(capsys):
    with pytest.raises(SystemExit) as stop:
        main(["--help"])
    assert stop.value.code == 0
    out = capsys.readouterr().out
    assert out.index("check") < out.index("fix")
    spec = importlib.util.spec_from_file_location("build_public_wheel", ROOT / "scripts" / "build_public_wheel.py")
    assert spec and spec.loader
    builder = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(builder)
    assert "refactor" in builder.PUBLIC and "refactor/cli.py" in builder.REQUIRED

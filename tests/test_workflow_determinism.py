"""What makes two reviews 'the same', and a clear error for a project reached through a link."""

from __future__ import annotations

import json
import os
import subprocess

from polaris.cli import main
from polaris.review.models import SourceFile
from polaris.workflow.service import _envelope, review_supplied

SOURCES = [SourceFile("app.py", 'import os\n\n\ndef ping(host):\n    os.system("ping -c 1 " + host)\n')]


def test_the_report_id_does_not_depend_on_how_long_the_review_took():
    first = review_supplied(SOURCES)
    slower = first.review.model_copy(update={
        "summary": first.review.summary.model_copy(update={"elapsed_ms": first.review.summary.elapsed_ms + 12_345.0})})
    again = _envelope(slower, first.snapshot, SOURCES, first.context)
    assert again.review.summary.elapsed_ms != first.review.summary.elapsed_ms
    assert again.report_id == first.report_id
    assert review_supplied(SOURCES).report_id == first.report_id


def test_the_report_id_still_changes_when_the_review_does():
    other = [SourceFile("app.py", "def ping(host):\n    return host\n")]
    assert review_supplied(other).report_id != review_supplied(SOURCES).report_id


def test_a_project_reached_through_a_symbolic_link_is_explained(tmp_path, capsys):
    real = tmp_path / "real"
    real.mkdir()
    env = {"PATH": os.defpath, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "HOME": str(tmp_path)}
    subprocess.run(["/usr/bin/git", "init", "-q", str(real)], check=True, env=env)
    (real / "a.py").write_text("x = 1\n")
    (tmp_path / "link").symlink_to(real)
    assert main(["workflow", "review", "--root", str(tmp_path / "link"), "--files", str(real / "a.py"),
                 "--format", "json"]) == 2
    error = json.loads(capsys.readouterr().out)
    assert error["code"] == "path_is_symlink" and "real path" in error["message"]
    assert str(tmp_path) not in error["message"]  # no path from the machine is echoed
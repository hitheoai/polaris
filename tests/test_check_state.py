"""`polaris check` remembers the last check: what was fixed, what is new, what is still open.

Records hold hex item ids only, live in Git's private admin folder, and never break a check.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from integration_helpers import isolated_home_fixture, repository_fixture  # noqa: F401

from polaris.check import state
from polaris.check.model import CHECK_FORMAT
from polaris.check.runner import CheckRequest, run_check
from polaris.integrations.freshness import state_directory

RISKY_RUN = ("import subprocess\nimport sys\n\n\ndef run(name):\n    subprocess.run('echo ' + name, shell=True)\n\n\n"
             "def main():\n    run(sys.argv[1])\n")
SAFE_RUN = ("import subprocess\nimport sys\n\n\ndef run(name):\n    subprocess.run(['echo', '--', name])\n\n\n"
            "def main():\n    run(sys.argv[1])\n")
RISKY_PING = ("import os\nimport sys\n\n\ndef ping(host):\n    os.system('ping -c 1 ' + host)\n\n\n"
              "def main():\n    ping(sys.argv[1])\n")


def check_json(capsys: pytest.CaptureFixture[str], *argv: str) -> tuple[int, dict[str, Any]]:
    from polaris.cli import main

    code = main(["check", "--json", *argv])
    return code, json.loads(capsys.readouterr().out)


def test_state_round_trip_bounds_and_odd_records(repository: Path) -> None:
    key = state.scope_key("changes")
    assert state.load_previous(repository, key) is None
    state.save(repository, key, ["b" * 24, "a" * 24, "a" * 24, "not-hex!", "DEADBEEF00"])
    assert state.load_previous(repository, key) == ["a" * 24, "b" * 24]
    record = state_directory(repository) / "check" / "changes.json"
    data = json.loads(record.read_text())
    # Hex ids only: no paths, messages or source.
    assert data == {"format": state.STATE_FORMAT, "key": "changes", "ids": ["a" * 24, "b" * 24]}
    assert record.stat().st_mode & 0o777 == 0o600
    # Keys that aren't ours never name a file.
    for odd in ("../escape", "changes/../x", "", "Changes", "range-zz"):
        state.save(repository, odd, ["a" * 24])
        assert state.load_previous(repository, odd) is None
    assert sorted(path.name for path in record.parent.iterdir()) == ["changes.json"]
    # Too many items to compare: remembered as not comparable, never as a wrong diff.
    state.save(repository, key, [f"{index:024x}" for index in range(state.MAX_IDS + 1)])
    assert json.loads(record.read_text())["ids"] is None and state.load_previous(repository, key) is None
    for content in (b"{not json", b'{"format": "other", "key": "changes", "ids": []}',
                    b'{"format": "polaris.check-state/1", "key": "project", "ids": []}',
                    b'{"format": "polaris.check-state/1", "key": "changes", "ids": ["zz"]}',
                    b"[]", b"x" * (state.MAX_BYTES + 1)):
        record.write_bytes(content)
        assert state.load_previous(repository, key) is None


def test_state_never_follows_links_or_raises(repository: Path, tmp_path: Path) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    folder = state_directory(repository)
    folder.mkdir(parents=True)
    (folder / "check").symlink_to(outside, target_is_directory=True)
    state.save(repository, "changes", ["a" * 24])
    assert state.load_previous(repository, "changes") is None and not list(outside.iterdir())
    plain = tmp_path / "plain"
    plain.mkdir()
    state.save(plain, "changes", ["a" * 24])  # no Git: nowhere to remember, and no error
    assert state.load_previous(plain, "changes") is None and not list(plain.iterdir())


def test_since_last_check_across_separate_runs(repository: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (repository / "run.py").write_text(RISKY_RUN)
    (repository / "ping.py").write_text(RISKY_PING)
    code, first = check_json(capsys, "--root", str(repository))
    assert code == 1 and first["format"] == CHECK_FORMAT and first["scope"] == "changes"
    assert first["since_last_check"] is None and first["counts"]["fix_now"] == 2
    ids = {item["where"]["file"]: item["id"] for item in first["items"]}
    (repository / "run.py").write_text(SAFE_RUN)  # the user fixes one problem
    code, second = check_json(capsys, "--root", str(repository))
    assert code == 1 and second["counts"]["fix_now"] == 1
    assert second["since_last_check"] == {"fixed": [ids["run.py"]], "new": [], "still_open": [ids["ping.py"]]}
    (repository / "more.py").write_text(RISKY_RUN.replace("def run", "def again").replace("run(sys", "again(sys"))
    code, third = check_json(capsys, "--root", str(repository))
    since = third["since_last_check"]
    assert since["fixed"] == [] and since["still_open"] == [ids["ping.py"]] and len(since["new"]) == 1
    (repository / "ping.py").unlink()
    (repository / "more.py").unlink()
    code, clear = check_json(capsys, "--root", str(repository))
    assert code == 0 and clear["status"] == "clear"
    assert clear["since_last_check"]["new"] == [] and len(clear["since_last_check"]["fixed"]) == 2
    # The text output says the same in plain words.
    from polaris.cli import main

    (repository / "ping.py").write_text(RISKY_PING)
    assert main(["check", "--plain", "--root", str(repository)]) == 1
    assert "Since your last check: 0 fixed \u00b7 1 new \u00b7 0 still open" in capsys.readouterr().out


def test_remember_false_leaves_no_record(repository: Path) -> None:
    (repository / "ping.py").write_text(RISKY_PING)
    run_check(CheckRequest(root=repository, remember=False, verify_fixes=False))
    assert not (state_directory(repository) / "check").exists()

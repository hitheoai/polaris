"""Synthetic Git fixtures; no commands/configuration from a real project are executed."""

import os
import subprocess

import pytest


@pytest.fixture(name="isolated_home")
def isolated_home_fixture(tmp_path, monkeypatch):
    home = (tmp_path / "home").resolve()
    home.mkdir()
    for name in ("POLARIS_MODEL", "POLARIS_API_KEY", "POLARIS_API_URL", "POLARIS_AGENT_HOOK_ACTIVE",
                 "GIT_DIR", "GIT_WORK_TREE", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT"):
        monkeypatch.delenv(name, raising=False)
    for key, value in {
        "HOME": str(home), "POLARIS_HOME": str(home / ".polaris"),
        "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": str(home / ".gitconfig"),
    }.items():
        monkeypatch.setenv(key, value)
    return home


def git(root, *args):
    result = subprocess.run(
        ["git", "--no-pager", "-c", "core.fsmonitor=false", "-C", str(root), *args],
        check=True, capture_output=True, text=True,
        env={**os.environ, "GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
             "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid"},
    )
    return result.stdout


@pytest.fixture(name="repository")
def repository_fixture(tmp_path, isolated_home):
    root = (tmp_path / "repository").resolve()
    root.mkdir()
    git(root, "init", "-q", "-b", "main")
    (root / "main.py").write_text("def add(a, b):\n    return a + b\n")
    (root / "package-lock.json").write_text('{"lockfileVersion":3}\n')
    git(root, "add", ".")
    git(root, "commit", "-qm", "synthetic fixture")
    return root

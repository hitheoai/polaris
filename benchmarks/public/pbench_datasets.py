"""Dataset adapters for the public benchmark.

Every adapter is pinned by an exact commit hash and a content digest, fetches on demand into a
cache folder OUTSIDE the repository, verifies what it fetched against its pins, and never
commits or vendors the data. The only network use is `git fetch` of the pinned public commits.

Cache folder: `--cache`, else the `POLARIS_BENCH_CACHE` environment variable, else
`/tmp/polaris-bench-cache`.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pbench_core import Weakness, tree_digest, verify_pin

DEFAULT_CACHE = "/tmp/polaris-bench-cache"  # noqa: S108  (a cache folder, never source)
CACHE_VARIABLE = "POLARIS_BENCH_CACHE"
ALLOWED_HOSTS = ("https://github.com/",)
GIT_TIMEOUT_SECONDS = 300


class DatasetUnavailable(RuntimeError):
    """The dataset cannot be fetched (network, removed repository, disabled adapter)."""


def cache_root(override: str | os.PathLike[str] | None = None) -> Path:
    """The cache folder, fully resolved: Polaris refuses a review root reached through a symlink,
    and `/tmp` is one on macOS."""
    return Path(override or os.environ.get(CACHE_VARIABLE) or DEFAULT_CACHE).expanduser().resolve()


def git_environment(home: Path) -> dict[str, str]:
    """A minimal, non-interactive Git environment: no prompts, no user config, no hooks, no LFS."""
    return {
        "PATH": os.environ.get("PATH", os.defpath), "HOME": str(home), "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "true",
        "GIT_LFS_SKIP_SMUDGE": "1", "LC_ALL": "C",
    }


def run_git(args: list[str], cwd: Path, home: Path, *, timeout: float = GIT_TIMEOUT_SECONDS) -> str:
    git = shutil.which("git")
    if git is None:
        raise DatasetUnavailable("git is not on PATH")
    command = [git, "--no-pager", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
               "-c", "protocol.allow=never", "-c", "protocol.https.allow=always", *args]
    try:
        done = subprocess.run(command, cwd=cwd, env=git_environment(home), capture_output=True, text=True,
                              timeout=timeout, check=False)
    except subprocess.TimeoutExpired as problem:
        raise DatasetUnavailable(f"git {args[0]} timed out after {timeout:.0f}s") from problem
    if done.returncode != 0:
        message = (done.stderr or done.stdout).strip().splitlines()[-1:] or ["failed"]
        raise DatasetUnavailable(f"git {args[0]} failed: {message[0][:200]}")
    return done.stdout


def fetch_commit(url: str, commit: str, destination: Path, home: Path, *, blobless: bool = False) -> None:
    """Fetch exactly `commit` (depth 1) into `destination`, creating the repository if needed."""
    if not url.startswith(ALLOWED_HOSTS):
        raise DatasetUnavailable("only https://github.com/ repositories are fetched")
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("a full 40-character commit hash is required")
    destination.mkdir(parents=True, exist_ok=True)
    if not (destination / ".git").exists():
        run_git(["init", "-q"], destination, home)
        run_git(["remote", "add", "origin", url], destination, home)
    have = subprocess.run([shutil.which("git") or "git", "cat-file", "-e", f"{commit}^{{commit}}"], cwd=destination,
                          env=git_environment(home), capture_output=True, check=False).returncode == 0
    if not have:
        run_git(["fetch", "-q", "--depth", "1", *(["--filter=blob:none"] if blobless else []), "origin", commit],
                destination, home)


def checkout(repository: Path, commit: str, home: Path) -> None:
    """Check out `commit` detached and remove anything untracked; verify the result."""
    run_git(["checkout", "-q", "--detach", "-f", commit], repository, home)
    run_git(["clean", "-fdxq"], repository, home)
    head = run_git(["rev-parse", "HEAD"], repository, home).strip()
    verify_pin(head, commit, "checked-out commit")


# ---------------------------------------------------------------------------------------------
# OpenSSF CVE Benchmark

OSSF_URL = "https://github.com/ossf-cve-benchmark/ossf-cve-benchmark.git"
OSSF_COMMIT = "91c59fd54b2b768c0f310bb0027d2ac59cdf74d4"
# sha256 over the sorted (CVEs/<name>.json, sha256 of its bytes) pairs at OSSF_COMMIT.
OSSF_CVES_DIGEST = "43a31b752f7a462542f63645946215e2b0ee9092e2177148a438e72a7dd4974b"
OSSF_LICENCE = "MIT (Copyright GitHub, Inc.); only results are published, no dataset content"


@dataclass(frozen=True)
class CveCase:
    id: str
    repository: str
    pre_commit: str
    post_commit: str
    weaknesses: tuple[Weakness, ...]
    cwes: tuple[str, ...] = ()

    @property
    def files(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(item.file for item in self.weaknesses))


def parse_cve_entry(entry: Mapping[str, Any]) -> CveCase:
    """A `CveCase` from one CVE Benchmark JSON entry; ValueError names the reason it is unusable."""
    cve = entry.get("CVE")
    repository = entry.get("repository")
    if not isinstance(cve, str) or not isinstance(repository, str):
        raise ValueError("entry has no CVE id or repository")
    if entry.get("state") != "PUBLISHED":
        raise ValueError(f"state is {entry.get('state')!r}, not PUBLISHED")
    if not repository.startswith(ALLOWED_HOSTS):
        raise ValueError("repository is not on github.com")
    pre = (entry.get("prePatch") or {})
    post = (entry.get("postPatch") or {})
    pre_commit, post_commit = pre.get("commit"), post.get("commit")
    for label, value in (("prePatch", pre_commit), ("postPatch", post_commit)):
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{40}", value):
            raise ValueError(f"{label} has no full commit hash")
    weaknesses: list[Weakness] = []
    for item in pre.get("weaknesses") or ():
        location = item.get("location") or {}
        file, line = location.get("file"), location.get("line")
        if isinstance(file, str) and isinstance(line, int) and file and not file.startswith(("/", "..")) \
                and ".." not in file.split("/"):
            weaknesses.append(Weakness(file=file, line=line, explanation=str(item.get("explanation", ""))))
    if not weaknesses:
        raise ValueError("no weakness with a file and line")
    return CveCase(id=cve, repository=repository, pre_commit=str(pre_commit), post_commit=str(post_commit),
                   weaknesses=tuple(weaknesses), cwes=tuple(str(c) for c in entry.get("CWEs") or ()))


def select_cases(entries: Iterable[tuple[str, Mapping[str, Any]]], limit: int,
                 fetch: Callable[[CveCase], None]) -> tuple[list[CveCase], list[dict[str, str]]]:
    """The first `limit` usable cases in file-name order whose commits `fetch` retrieves cleanly.

    Selection depends only on the sorted names, the entries' content and whether the commits can
    be fetched; every skipped entry is returned with its reason so the report can show it.
    """
    chosen: list[CveCase] = []
    skipped: list[dict[str, str]] = []
    for name, entry in sorted(entries, key=lambda pair: pair[0]):
        if len(chosen) >= limit:
            break
        try:
            case = parse_cve_entry(entry)
        except ValueError as problem:
            skipped.append({"id": name.removesuffix(".json"), "reason": f"unusable label: {problem}"})
            continue
        try:
            fetch(case)
        except DatasetUnavailable as problem:
            skipped.append({"id": case.id, "reason": f"not fetched: {problem}"})
            continue
        chosen.append(case)
    return chosen, skipped


@dataclass
class OssfCveDataset:
    cache: Path
    id: str = "ossf-cve-benchmark"
    enabled: bool = True
    home: Path = field(init=False)

    def __post_init__(self) -> None:
        self.home = self.cache / "home"
        self.home.mkdir(parents=True, exist_ok=True)

    @property
    def labels_dir(self) -> Path:
        return self.cache / "datasets" / "ossf-cve-benchmark"

    def fetch_labels(self) -> dict[str, dict[str, Any]]:
        """Fetch the labels at the pinned commit and verify their content digest."""
        import json

        fetch_commit(OSSF_URL, OSSF_COMMIT, self.labels_dir, self.home)
        checkout(self.labels_dir, OSSF_COMMIT, self.home)
        files = {f"CVEs/{path.name}": path.read_bytes() for path in sorted((self.labels_dir / "CVEs").glob("*.json"))}
        verify_pin(tree_digest(files), OSSF_CVES_DIGEST, "OpenSSF CVE Benchmark CVEs/*.json digest")
        return {name.split("/", 1)[1]: json.loads(content) for name, content in files.items()}

    def repository_dir(self, case: CveCase) -> Path:
        return self.cache / "repos" / case.id

    def fetch_case(self, case: CveCase) -> Path:
        """Fetch both revisions of one case (depth 1 each); DatasetUnavailable if either is gone."""
        repository = self.repository_dir(case)
        for commit in (case.pre_commit, case.post_commit):
            fetch_commit(case.repository, commit, repository, self.home)
        return repository

    def describe(self) -> dict[str, Any]:
        return {"id": self.id, "status": "used", "licence": OSSF_LICENCE, "source": OSSF_URL.removesuffix(".git"),
                "commit": OSSF_COMMIT, "content_digest": OSSF_CVES_DIGEST,
                "note": "Labels (CVEs/*.json) only. The code under test comes from each CVE's own public repository "
                        "at the labelled commits and keeps that repository's licence; none of it is redistributed."}


# ---------------------------------------------------------------------------------------------
# GitHub Actions workflow fixtures (zizmor's own test data)

ZIZMOR_URL = "https://github.com/zizmorcore/zizmor.git"
ZIZMOR_COMMIT = "99a054ed9283c90abdd2d5b9fb5101d27dde9783"  # tag v1.30.1
ZIZMOR_VERSION = "1.30.1"
ZIZMOR_FIXTURE_DIR = "crates/zizmor/tests/integration/test-data"
# sha256 over the sorted (flattened workflow name, sha256) pairs of the fixtures selected below.
ZIZMOR_FIXTURES_DIGEST = "86be495fb322cefb28a293c2c3783e8b37747a6e86c62296cc4549595d9960a6"
ZIZMOR_LICENCE = ("MIT (repository LICENSE at the pinned commit); fixtures are not audited one by one for "
                  "third-party origin, so only counts and fixture names are published, never fixture content")

_ON = re.compile(r"(?m)^(?:on|\"on\"|'on'|true)\s*:")
_JOBS = re.compile(r"(?m)^jobs\s*:")


def looks_like_workflow(text: str) -> bool:
    """A GitHub Actions workflow has top-level `on` and `jobs` keys (composite actions do not)."""
    return bool(_ON.search(text) and _JOBS.search(text))


def flatten_name(relative: str) -> str:
    """`a/b c.yml` becomes `a__b_c.yml`, a name that is safe as one workflow file name."""
    return re.sub(r"[^A-Za-z0-9._-]", "_", relative.replace("/", "__"))


def select_fixtures(files: Mapping[str, bytes]) -> dict[str, bytes]:
    """Workflow fixtures from `{relative path: bytes}`, keyed by their flattened file names."""
    chosen: dict[str, bytes] = {}
    for relative, content in sorted(files.items()):
        if not relative.endswith((".yml", ".yaml")):
            continue
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if looks_like_workflow(text):
            chosen[flatten_name(relative)] = content
    return chosen


@dataclass
class ZizmorFixtures:
    cache: Path
    id: str = "github-actions-fixtures"
    enabled: bool = True
    home: Path = field(init=False)

    def __post_init__(self) -> None:
        self.home = self.cache / "home"
        self.home.mkdir(parents=True, exist_ok=True)

    @property
    def source_dir(self) -> Path:
        return self.cache / "datasets" / "zizmor-source"

    @property
    def project_dir(self) -> Path:
        return self.cache / "datasets" / "zizmor-fixture-project"

    def fetch(self) -> dict[str, bytes]:
        """Fetch the pinned fixtures, verify their digest and build a Git project of workflows."""
        fetch_commit(ZIZMOR_URL, ZIZMOR_COMMIT, self.source_dir, self.home, blobless=True)
        run_git(["sparse-checkout", "set", "--no-cone", f"/{ZIZMOR_FIXTURE_DIR}/", "/LICENSE"], self.source_dir, self.home)
        checkout(self.source_dir, ZIZMOR_COMMIT, self.home)
        base = self.source_dir / ZIZMOR_FIXTURE_DIR
        files = {path.relative_to(base).as_posix(): path.read_bytes() for path in sorted(base.rglob("*"))
                 if path.is_file() and not path.is_symlink()}
        fixtures = select_fixtures(files)
        verify_pin(tree_digest(fixtures), ZIZMOR_FIXTURES_DIGEST, "zizmor fixture workflows digest")
        self.build_project(fixtures)
        return fixtures

    def build_project(self, fixtures: Mapping[str, bytes]) -> Path:
        """A fresh Git project holding each fixture as `.github/workflows/<flat name>`."""
        if self.project_dir.exists():
            shutil.rmtree(self.project_dir)
        workflows = self.project_dir / ".github" / "workflows"
        workflows.mkdir(parents=True)
        for name, content in fixtures.items():
            (workflows / name).write_bytes(content)
        run_git(["init", "-q"], self.project_dir, self.home)
        run_git(["add", "-A"], self.project_dir, self.home)
        run_git(["-c", "user.name=bench", "-c", "user.email=bench@localhost", "commit", "-q", "-m", "fixtures"],
                self.project_dir, self.home)
        return self.project_dir

    def describe(self) -> dict[str, Any]:
        return {"id": self.id, "status": "used", "licence": ZIZMOR_LICENCE, "source": ZIZMOR_URL.removesuffix(".git"),
                "commit": ZIZMOR_COMMIT, "content_digest": ZIZMOR_FIXTURES_DIGEST,
                "note": "Workflow files under the repository's integration test data (tag v1.30.1). They have no "
                        "labels of their own in a machine-readable form, so this dataset measures agreement "
                        "between tools, not accuracy."}


# ---------------------------------------------------------------------------------------------
# OWASP Benchmark for Python: disabled on purpose

OWASP_PYTHON_REASON = (
    "The OWASP Benchmark for Python is licensed under the GPL. Polaris neither fetches nor vendors "
    "it, so no result here depends on it. Enabling this adapter would need a decision about "
    "whether running Polaris over GPL files and publishing the scores is acceptable."
)


@dataclass
class OwaspPythonStub:
    """A documented, disabled adapter: it fetches nothing and cannot be enabled by a flag."""

    id: str = "owasp-benchmark-python"
    enabled: bool = False
    reason: str = OWASP_PYTHON_REASON

    def fetch(self) -> None:
        raise DatasetUnavailable(self.reason)

    def describe(self) -> dict[str, Any]:
        return {"id": self.id, "status": "disabled", "licence": "GPL", "source": "https://owasp.org/",
                "note": self.reason}



"""Build the public `theovex-polaris` wheel (and, with --sdist, its source archive).

It holds the reviewer, CLI, API server, MCP server, editor setup and model tools. Polaris Lab
and the training pipeline stay private to TheoVex and are left out; the CLI hides their
commands when they're missing. The source archive is built from the same public files, for
PyPI and the Homebrew formula.

    uv run python scripts/build_public_wheel.py [--out-dir dist/public] [--sdist]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# Top-level parts of src/polaris that never ship publicly.
PRIVATE = frozenset({
    "lab", "training.py", "trainer.py", "synthetic.py", "posttraining.py", "evaluation.py",
    "exporting.py", "checkpoints.py", "metrics.py",
})
EXTRAS = ("model", "api", "mcp", "tui")
PUBLIC = frozenset({
    "__init__.py", "__main__.py", "account_cli.py", "api", "artifacts.py", "benchmark.py",
    "calibration.py", "cli.py", "client.py", "contract.py", "data.py", "engine.py", "engineering",
    "errors.py", "fixtures.py", "graph", "install.py", "integrations", "jsonio.py", "mcp", "model.py",
    "model_cli.py", "onboarding", "preprocessing.py", "py.typed", "registry.py", "remote.py",
    "review", "runtime.py", "selftest.py", "tui", "workflow", "check", "refactor",
})
# The analyzer has its own exact graph and is not installed through public extras.
COMBINED_EXTRAS = ("model", "api", "mcp", "tui")
REQUIRED = ("cli.py", "review/engine.py", "api/app.py", "mcp/server.py", "install.py", "selftest.py",
            "remote.py", "account_cli.py", "client.py", "py.typed",
            "onboarding/cli.py", "onboarding/__main__.py", "onboarding/auth.py",
            "onboarding/installation.py", "onboarding/lifecycle.py", "onboarding/sources.py",
            "workflow/service.py", "workflow/cli.py", "workflow/mcp.py", "workflow/api.py",
            "tui/cli.py", "tui/app.py", "tui/view.py", "tui/simple/__init__.py",
            "check/cli.py", "check/model.py", "check/build.py", "check/runner.py", "check/output.py",
            "check/state.py", "check/brand.py", "check/brand_site.py",
            "refactor/cli.py", "refactor/plan.py", "refactor/apply.py", "refactor/generators.py",
            "refactor/codemods.py", "refactor/gates.py", "refactor/models.py", "refactor/render.py",
            "refactor/ai.py", "refactor/aiconfig.py",
            "graph/__init__.py", "graph/build.py", "graph/model.py", "graph/pyfacts.py", "graph/callers.py",
            "engineering/models.py", "engineering/apply.py", "engineering/generation.py",
            "integrations/freshness.py", "integrations/hooks.py", "integrations/doctor.py",
            "review/capabilities.py", "review/analyzers/semgrep.py", "review/analyzers/rule_pack.py",
            "review/analyzers/identity.py", "review/analyzers/analyzer-contract.json")

PYPROJECT = """\
[build-system]
requires = ["hatchling>=1.26,<2"]
build-backend = "hatchling.build"

[project]
name = "theovex-polaris"
version = "{version}"
description = "Polaris by TheoVex: security review, bounded repair proposals, and action assessment for engineering agents."
readme = "README.md"
requires-python = "{requires_python}"
license = "Apache-2.0"
license-files = ["LICENSE", "NOTICE"]
dependencies = {dependencies}
keywords = ["security", "code-review", "sql-injection", "command-injection", "mcp"]
classifiers = [
    "Development Status :: 4 - Beta",
    "Intended Audience :: Developers",
    "Programming Language :: Python :: 3",
    "Topic :: Security",
    "Topic :: Software Development :: Quality Assurance",
]

[project.optional-dependencies]
{extras}
all = {all_extras}

[project.scripts]
polaris = "polaris.cli:main"
theo = "polaris.onboarding.cli:main"

[project.urls]
Homepage = "https://polaris.theovex.com"
Documentation = "https://polaris.theovex.com/docs"
Source = "https://github.com/hitheoai/polaris"
Issues = "https://github.com/hitheoai/polaris/issues"
Changelog = "https://github.com/hitheoai/polaris/blob/main/CHANGELOG.md"

[tool.hatch.build.targets.wheel]
packages = ["src/polaris"]
"""


def _ignore(directory: str, names: list[str]) -> set[str]:
    skipped = {name for name in names if name == "__pycache__" or name.endswith((".pyc", ".pyo"))}
    if Path(directory).resolve() == (ROOT / "src" / "polaris").resolve():
        skipped |= set(names) - PUBLIC
    return skipped


def package_files(names: list[str]) -> dict[str, str]:
    """Archive entries inside the `polaris` package, keyed by their path within it.

    Works for wheels (`polaris/cli.py`) and source archives
    (`theovex_polaris-0.2.0/src/polaris/cli.py`).
    """
    found = {}
    for name in names:
        parts = name.split("/")
        for index, part in enumerate(parts[:-1]):
            if part == "polaris" and (index == 0 or parts[index - 1] == "src"):
                found["/".join(parts[index + 1:])] = name
                break
    return found


def check_contents(names: list[str], label: str) -> None:
    """Refuse an archive that holds private files or lacks the public essentials."""
    files = package_files(names)
    leaked = sorted(entry for inner, entry in files.items() if inner.split("/")[0] in PRIVATE)
    if leaked:
        raise SystemExit(f"private files in the public {label}: {leaked}")
    unapproved = sorted(entry for inner, entry in files.items() if inner.split("/")[0] not in PUBLIC)
    if unapproved:
        raise SystemExit(f"unapproved files in the public {label}: {unapproved}")
    for required in REQUIRED:
        if required not in files:
            raise SystemExit(f"public {label} is missing polaris/{required}")


def build(out_dir: Path, *, sdist: bool = False) -> dict[str, object]:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    optional = project["optional-dependencies"]
    extras = "\n".join(f"{name} = {json.dumps(optional[name])}" for name in EXTRAS)
    combined = sorted({item for name in COMBINED_EXTRAS for item in optional[name]})
    out_dir = Path(os.path.abspath(out_dir.expanduser()))
    if any(path.is_symlink() for path in (out_dir, *out_dir.parents)):
        raise ValueError("Public output must not traverse symlinks.")
    if out_dir.exists() or out_dir.is_relative_to(ROOT / "src"):
        raise ValueError("Public output must be a new immutable directory outside source inputs.")
    if any(path.is_symlink() for path in (ROOT / "src/polaris").rglob("*")):
        raise ValueError("Public source must not contain symlinks.")
    out_dir.mkdir(parents=True, mode=0o700)
    with tempfile.TemporaryDirectory(prefix="polaris-public-") as temporary:
        stage = Path(temporary)
        shutil.copytree(ROOT / "src" / "polaris", stage / "src" / "polaris", ignore=_ignore)
        for name in ("LICENSE", "NOTICE"):
            shutil.copy2(ROOT / name, stage / name)
        shutil.copy2(ROOT / "packaging" / "README.md", stage / "README.md")
        (stage / "pyproject.toml").write_text(PYPROJECT.format(
            version=project["version"], requires_python=project["requires-python"],
            dependencies=json.dumps(project["dependencies"]), extras=extras,
            all_extras=json.dumps(combined),
        ), encoding="utf-8")
        kinds = ["--wheel", "--sdist"] if sdist else ["--wheel"]
        subprocess.run(["uv", "build", *kinds, "--out-dir", str(out_dir), str(stage)], check=True)
    wheel = out_dir / f"theovex_polaris-{project['version']}-py3-none-any.whl"
    with zipfile.ZipFile(wheel) as archive:
        names = archive.namelist()
    check_contents(names, "wheel")
    result: dict[str, object] = {"wheel": str(wheel), "files": len(names), "bytes": wheel.stat().st_size,
                                 "version": project["version"]}
    if sdist:
        source = out_dir / f"theovex_polaris-{project['version']}.tar.gz"
        with tarfile.open(source) as archive:
            check_contents(archive.getnames(), "source archive")
        result |= {"sdist": str(source), "sdist_bytes": source.stat().st_size}
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out-dir", type=Path, default=ROOT / "dist" / "public")
    parser.add_argument("--sdist", action="store_true", help="Also build the source archive.")
    args = parser.parse_args()
    result = build(args.out_dir.absolute(), sdist=args.sdist)
    json.dump(result, sys.stdout, indent=2)
    print()


if __name__ == "__main__":
    main()

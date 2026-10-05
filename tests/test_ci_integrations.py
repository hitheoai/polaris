from __future__ import annotations

import importlib.util
import json
import re
import shlex
import subprocess
from pathlib import Path

import pytest

from polaris import cli

yaml = pytest.importorskip("yaml")
ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
RISKY = '''import os


def ping(host):
    os.system("ping -c 1 " + host)
'''


def _parse(command: str) -> object:
    words = shlex.split(command)
    assert words[0] == "polaris"
    return cli.parser().parse_args(words[1:])


def _polaris_lines(script: str) -> list[str]:
    """Polaris command lines in a shell script, with shell variables replaced by sample values."""
    joined = re.sub(r"\\\n\s*", " ", script)
    lines = []
    for line in joined.splitlines():
        line = line.strip()
        if line.startswith("polaris review"):
            line = re.sub(r'"\$\{[a-z_]+\[@\]\}"', "", line)  # bash arrays, checked separately
            line = re.sub(r"\$\{?([A-Z_]+)\}?", lambda m: {"POLARIS_ENGINE": "model", "POLARIS_NO_MODEL": "fail",
                                                           "POLARIS_FAIL_ON": "flagged",
                                                           "POLARIS_MODEL_SOURCE": "remote"}.get(m.group(1), "x"),
                          line)
            lines.append(line)
    return lines


def test_pre_commit_hooks_are_valid_commands():
    hooks = yaml.safe_load((ROOT / ".pre-commit-hooks.yaml").read_text())
    assert {hook["id"] for hook in hooks} == {"polaris-review", "polaris-review-rules", "polaris-workflow"}
    for hook in hooks:
        assert hook["language"] == "system" and hook["pass_filenames"] is False
        if hook["id"] == "polaris-workflow":
            words = shlex.split(hook["entry"])
            assert words[:4] == ["python", "-I", "-m", "polaris"]
            args = cli.parser().parse_args(words[4:])
            assert args.command == "workflow" and args.workflow_command == "review"
            assert args.staged and args.require_complete
            assert hook["always_run"] is True and hook["require_serial"] is True
            assert "types" not in hook, "unsupported changed files must remain visible"
        else:
            assert hook["types"] == ["python"]
            args = _parse(hook["entry"])
            assert args.command == "review" and args.staged


def test_gitlab_template_commands_parse():
    template = yaml.safe_load((ROOT / "ci" / "gitlab" / "polaris.gitlab-ci.yml").read_text())
    job = template["polaris-review"]
    assert job["artifacts"]["reports"]["codequality"] == "gl-code-quality-report.json"
    lines = [line for entry in job["script"] for line in _polaris_lines(entry)]
    assert len(lines) == 2
    formats = {_parse(line).format for line in lines}
    assert formats == {"codequality", "text"}
    assert all(_parse(line).model_source == "remote" for line in lines)
    assert "POLARIS_API_KEY" not in job["variables"], "a template default would hide the project's secret"
    setup = "\n".join(job["before_script"])
    assert '[ -z "${POLARIS_API_KEY:-}" ]' in setup and "theovex-polaris[model]" in setup


def _run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], *extra: str):
    (tmp_path / "app.py").write_text(RISKY)
    monkeypatch.setenv("POLARIS_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("POLARIS_MODEL", raising=False)
    monkeypatch.chdir(tmp_path)
    code = cli.main(["review", "--files", "app.py", "--root", str(tmp_path), *extra])
    return code, capsys.readouterr()


def test_no_model_skip_passes_with_a_warning(tmp_path, monkeypatch, capsys):
    code, out = _run(tmp_path, monkeypatch, capsys, "--engine", "model", "--no-model", "skip")
    assert code == 0
    assert "NOT reviewed" in out.err


def test_no_model_fail_is_the_default_for_the_model_engine(tmp_path, monkeypatch, capsys):
    code, out = _run(tmp_path, monkeypatch, capsys, "--engine", "model")
    assert code == 3


def test_the_default_hybrid_engine_reviews_with_rules_when_no_model_is_installed(tmp_path, monkeypatch, capsys):
    code, out = _run(tmp_path, monkeypatch, capsys, "--format", "json")
    assert code == 1
    report = json.loads(out.out)
    assert report["model"]["engine"] == "rules"
    assert any("No Polaris model is installed" in notice for notice in report["notices"])


def test_no_model_rules_falls_back(tmp_path, monkeypatch, capsys):
    code, out = _run(tmp_path, monkeypatch, capsys, "--engine", "model", "--no-model", "rules", "--format", "json")
    assert code == 1
    report = json.loads(out.out)
    assert report["model"]["engine"] == "rules"
    assert "static rules instead" in out.err


def test_codequality_output(tmp_path, monkeypatch, capsys):
    code, out = _run(tmp_path, monkeypatch, capsys, "--engine", "rules", "--format", "codequality")
    assert code == 1
    issues = json.loads(out.out)
    assert len(issues) == 1
    issue = issues[0]
    assert issue["check_name"] == "polaris/command_injection"
    assert issue["severity"] == "critical"
    assert issue["location"] == {"path": "app.py", "lines": {"begin": 4, "end": 5}}
    assert issue["fingerprint"]


def test_public_cli_hides_private_commands(monkeypatch):
    private = {"polaris.lab", "polaris.training", "polaris.posttraining", "polaris.evaluation", "polaris.exporting"}
    monkeypatch.setattr(cli, "available", lambda module: module not in private)
    choices = set(cli.parser()._subparsers._group_actions[0].choices)  # type: ignore[union-attr]
    assert not choices & {"lab", "train", "calibrate", "evaluate", "export-candidate"}
    assert {"review", "scan", "model", "serve", "mcp", "setup", "assess", "login", "logout", "whoami"} <= choices


def test_public_wheel_filter_drops_only_private_modules():
    spec = importlib.util.spec_from_file_location("build_public_wheel", ROOT / "scripts" / "build_public_wheel.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    package = ROOT / "src" / "polaris"
    # Named explicitly: a public checkout has no private modules to list.
    names = sorted({path.name for path in package.iterdir()} | {"lab", "training.py", "synthetic.py", "evaluation.py"})
    skipped = module._ignore(str(package), names)
    assert {"lab", "training.py", "synthetic.py", "evaluation.py"} <= skipped
    assert not skipped & {"cli.py", "review", "api", "mcp", "runtime.py", "selftest.py", "install.py"}
    assert module._ignore(str(package / "review"), ["metrics.py", "engine.py"]) == set()
    assert "unapproved-private-module.py" in module._ignore(str(package), ["unapproved-private-module.py"])


@pytest.mark.skipif(subprocess.run(["git", "--version"], capture_output=True).returncode != 0, reason="needs git")
def test_staged_review_in_a_repository(tmp_path, monkeypatch, capsys):
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    (tmp_path / "app.py").write_text(RISKY)
    subprocess.run(["git", "-C", str(tmp_path), "add", "app.py"], check=True)
    monkeypatch.chdir(tmp_path)
    code = cli.main(["review", "--staged", "--engine", "rules", "--format", "json"])
    report = json.loads(capsys.readouterr().out)
    assert code == 1
    assert report["summary"]["results"]["flagged"] == 1


def _build_module():
    spec = importlib.util.spec_from_file_location("build_public_wheel", ROOT / "scripts" / "build_public_wheel.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _workflow(name: str) -> dict:
    workflow = yaml.safe_load((WORKFLOWS / name).read_text())
    workflow["on"] = workflow.pop(True, workflow.get("on"))  # YAML 1.1 reads the key `on` as true
    return workflow


def _steps(job: dict, action: str) -> list[dict]:
    return [step for step in job["steps"] if step.get("uses", "").startswith(action + "@")]


def test_public_archives_are_checked_in_wheel_and_source_layouts():
    module = _build_module()
    wheel = [f"polaris/{name}" for name in module.REQUIRED]
    source = [f"theovex_polaris-0.2.0/src/{name}" for name in wheel] + ["theovex_polaris-0.2.0/README.md"]
    module.check_contents(wheel, "wheel")
    module.check_contents(source, "source archive")
    with pytest.raises(SystemExit, match="private files"):
        module.check_contents([*source, "theovex_polaris-0.2.0/src/polaris/lab/app.py"], "source archive")
    with pytest.raises(SystemExit, match="missing polaris/remote.py"):
        module.check_contents([name for name in wheel if name != "polaris/remote.py"], "wheel")


def _check_workflow_hygiene(name: str) -> None:
    """No stored secrets, least privilege per job, pinned actions, no `${{ }}` in scripts."""
    assert "secrets." not in (WORKFLOWS / name).read_text(), "workflows use OIDC and the job token, never stored secrets"
    workflow = _workflow(name)
    assert workflow["permissions"] == {}
    for job_name, job in workflow["jobs"].items():
        assert isinstance(job.get("permissions"), dict), f"{job_name} must declare its permissions"
        for step in job["steps"]:
            if "uses" in step:
                assert PINNED.match(step["uses"]), f"{job_name}: {step['uses']} isn't pinned to a commit"
            if "run" in step:
                assert "${{" not in step["run"], f"{job_name}: {step.get('name')} interpolates into its script"
        for step in _steps(job, "actions/checkout"):
            assert step["with"]["persist-credentials"] is False


@pytest.mark.parametrize("name", ["release.yml", "ci.yml"])
def test_workflows_are_pinned_least_privilege_and_never_interpolate_into_scripts(name):
    _check_workflow_hygiene(name)


def test_the_public_ci_runs_the_same_checks_as_this_repository():
    # packaging/public-ci.yml becomes the public repository's .github/workflows/ci.yml.
    public = yaml.safe_load((ROOT / "packaging" / "public-ci.yml").read_text())
    public["on"] = public.pop(True)
    ours = _workflow("ci.yml")
    for key in ("on", "permissions", "concurrency"):
        assert public[key] == ours[key], key
    assert set(public["jobs"]) == {"test"} and public["jobs"]["test"] == ours["jobs"]["test"]


def test_the_public_release_template_is_the_release_workflow():
    # packaging/public-release.yml becomes the public repository's .github/workflows/release.yml.
    assert (ROOT / "packaging" / "public-release.yml").read_bytes() == (WORKFLOWS / "release.yml").read_bytes()


def test_pypi_publishing_uses_trusted_publishing_from_a_gated_job():
    release = _workflow("release.yml")
    assert set(release["on"]) == {"workflow_dispatch"}
    assert release["on"]["workflow_dispatch"]["inputs"]["approve_publication"]["default"] is False
    jobs = release["jobs"]
    assert "inputs.approve_publication" in jobs["build"]["if"]
    assert "!github.event.repository.private" in jobs["build"]["if"]
    assert "github.repository == vars.PUBLIC_RELEASE_REPOSITORY" in jobs["build"]["if"]
    assert "refs/tags/v" in jobs["build"]["if"]
    assert jobs["build"]["environment"] == "release-approval"
    assert jobs["build"]["permissions"] == {"contents": "read"}
    build = "\n".join(step.get("run", "") for step in jobs["build"]["steps"])
    assert "scripts/build_public_wheel.py --out-dir dist --sdist" in build
    smoke = re.search(r"/tmp/smoke/bin/(polaris scan [^|\n]+?)\s*\|\|", build)
    assert smoke and _parse(smoke.group(1)).engine == "rules"
    pypi = jobs["pypi"]
    assert pypi["environment"]["name"] == "pypi" and pypi["needs"] == "build"
    assert pypi["permissions"] == {"id-token": "write"}
    assert [step["uses"].split("@")[0] for step in pypi["steps"]] == ["actions/download-artifact",
                                                                     "pypa/gh-action-pypi-publish"]
    publish = _steps(pypi, "pypa/gh-action-pypi-publish")[0].get("with") or {}
    assert not {"user", "password"} & set(publish), "Trusted Publishing needs no credentials"
    assert publish.get("attestations", True) is not False
    sign = jobs["sign"]
    assert sign["environment"] == "release-approval"
    assert _steps(sign, "sigstore/gh-action-sigstore-python") and _steps(sign, "actions/attest-build-provenance")
    assert [name for name, job in jobs.items() if job["permissions"].get("id-token")] == ["pypi", "sign"]


def test_homebrew_formula_requires_generated_pins_and_separate_offline_runtimes():
    formula = (ROOT / "packaging" / "homebrew" / "polaris.rb").read_text()
    assert "scripts/build_homebrew_formula.py" in formula and "@@GENERATOR_GUARD@@" in formula
    assert '%w[app analyzer]' in formula and "import mcp" in formula
    assert '"--require-hashes", "--no-build"' in formula and '"--offline"' in formula
    assert "deny_network_access!" in formula and '"analyzerRuntime" => "not_checked"' in formula
    assert "virtualenv_install_with_resources" not in formula and "depends_on \"python@" not in formula
    assert 'polaris_command = Shellwords.escape((bin/"polaris").to_s)' in formula
    assert 'theo_command = Shellwords.escape((bin/"theo").to_s)' in formula
    assert "#{bin}/" not in formula.split("  test do\n", 1)[1]
    command = re.search(r'"#\{polaris_command\} ([^"]+)"\s*\\\s*\n\s*"([^"]+)", 1', formula)
    assert command
    args = _parse("polaris " + "".join(command.groups()))
    assert args.command == "scan" and args.engine == "rules"
    assert args.model_source == "local"
    assert "Shellwords.escape(testpath.to_s)" in str(args.root)
    assert args.format == "json"
    assert "scan safe.py --root" in formula
    assert 'summary.fetch("units_assessed")' in formula
    assert 'summary.fetch("files_reviewed")' in formula
    assert 'finding.fetch("check_id") == "command_injection"' in formula
    assert 'safe.fetch("summary").fetch("results").fetch("ok")' in formula


@pytest.mark.parametrize("path", ["packaging/public-release.yml", ".github/workflows/macos-release-readiness.yml"])
def test_new_release_workflows_require_manual_protected_approval_and_pinned_actions(path):
    raw = (ROOT / path).read_text()
    workflow = yaml.safe_load(raw)
    triggers = workflow.get("on", workflow.get(True))
    assert set(triggers) == {"workflow_dispatch"} and workflow["permissions"] == {}
    assert "secrets." not in raw
    for job in workflow["jobs"].values():
        assert job["environment"]
        assert isinstance(job["permissions"], dict)
        for step in job["steps"]:
            if "uses" in step:
                assert PINNED.fullmatch(step["uses"])
            if "run" in step:
                assert "${{" not in step["run"]
    first = next(iter(workflow["jobs"].values()))
    assert "inputs.approve_" in first["if"] and "github.repository == vars." in first["if"]
    if path.startswith("packaging/"):
        assert "!github.event.repository.private" in first["if"]
        assert workflow["jobs"]["pypi"]["permissions"] == {"id-token": "write"}
    else:
        assert first["permissions"] == {"contents": "read", "actions": "read"}
        assert "self-hosted" in first["runs-on"] and "ARM64" in first["runs-on"]
        assert "attest-build-provenance" not in raw and "pypi-publish" not in raw

"""Local regression handoff: synthetic private installations, never installed user runtimes."""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from polaris import __version__
from polaris.integrations._safe import IntegrationProblem
from polaris.onboarding import (
    MINIMUM_MACOS,
    RELEASE_ID,
    SIGNED_RELEASE_ID,
    cli,
    installation,
    lifecycle,
)
from polaris.onboarding.errors import OnboardingProblem
from polaris.review.analyzers import identity
from polaris.workflow import cli as workflow_cli
from polaris.workflow import host as workflow_host

REFUSALS = (OnboardingProblem, IntegrationProblem, OSError, ValueError)


@pytest.mark.parametrize("entrypoint", ["polaris", "theo"])
@pytest.mark.parametrize("option", ["--version", "--help"])
def test_both_commands_have_projectless_version_and_help(entrypoint, option, isolated_account, monkeypatch, capsys):
    from polaris.cli import main as polaris_main

    monkeypatch.chdir(isolated_account)
    with pytest.raises(SystemExit) as result:
        (polaris_main if entrypoint == "polaris" else cli.main)([option])
    assert result.value.code == 0
    captured = capsys.readouterr()
    assert not captured.err
    assert (__version__ if option == "--version" else "usage:") in captured.out


def private_directory(path):
    if not path.exists():
        private_directory(path.parent)
        path.mkdir(mode=0o700)
    return path


def write(path, value, mode=0o600):
    private_directory(path.parent)
    path.write_bytes(value.encode() if isinstance(value, str) else value)
    path.chmod(mode)
    return path


def write_json(path, value):
    return write(path, json.dumps(value, sort_keys=True, indent=2) + "\n")


def fingerprint(root):
    """Include directory modes and never traverse links; ignore read/access timestamps."""
    result = {".": ("directory", stat.S_IMODE(root.lstat().st_mode))}
    for parent, directories, files in os.walk(root, followlinks=False):
        for name in sorted([*directories, *files]):
            path = Path(parent) / name
            info = path.lstat()
            relative = path.relative_to(root).as_posix()
            mode = stat.S_IMODE(info.st_mode)
            if stat.S_ISLNK(info.st_mode):
                result[relative] = ("link", os.readlink(path))
            elif stat.S_ISDIR(info.st_mode):
                result[relative] = ("directory", mode)
            elif stat.S_ISREG(info.st_mode):
                result[relative] = ("file", mode, hashlib.sha256(path.read_bytes()).hexdigest())
            else:
                result[relative] = ("special", info.st_mode)
    return result


@pytest.fixture(autouse=True)
def isolated_account(tmp_path, monkeypatch):
    old_umask = os.umask(0o077)
    home = private_directory(tmp_path / "account")
    temporary = private_directory(tmp_path / "temp")
    for name in (
        "POLARIS_API_KEY", "POLARIS_API_URL", "POLARIS_MODEL", "SEMGREP_APP_TOKEN",
        "PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "THEO_PREFIX", "HOMEBREW_PREFIX",
    ):
        monkeypatch.delenv(name, raising=False)
    for name, value in {
        "HOME": home,
        "USERPROFILE": home,
        "TMPDIR": temporary,
        "POLARIS_HOME": home / ".polaris",
        "XDG_CONFIG_HOME": home / ".config",
        "XDG_CACHE_HOME": home / ".cache",
    }.items():
        monkeypatch.setenv(name, str(value))
    monkeypatch.setenv("HF_HUB_OFFLINE", "1")
    monkeypatch.setenv("TRANSFORMERS_OFFLINE", "1")

    def no_execution(*args, **kwargs):
        pytest.fail("A fixture executable, project command, or external process was invoked.")

    monkeypatch.setattr(subprocess, "Popen", no_execution)
    monkeypatch.setattr(subprocess, "run", no_execution)
    monkeypatch.setattr(os, "system", no_execution)
    monkeypatch.setattr("polaris.remote.load_credentials", no_execution)
    monkeypatch.setattr(cli, "activate", no_execution)
    try:
        yield home
    finally:
        os.umask(old_umask)


@pytest.fixture
def managed(tmp_path, isolated_account, monkeypatch):
    made = []

    def create(manager="standalone", *, keg_suffix="", release_id=RELEASE_ID):
        base = private_directory(tmp_path / f"fixture-{len(made)}")
        if manager == "standalone":
            prefix = private_directory(base / "prefix")
            root = private_directory(prefix / "releases" / release_id)
            write_json(prefix / "owner.json", {"format": "polaris.theo-prefix/1", "uid": os.getuid()})
            write(prefix / "install.lock", b"")
        else:
            prefix = private_directory(base / "brew/Cellar/polaris" / f"{__version__}{keg_suffix}")
            root = private_directory(prefix / "libexec")
        app = private_directory(root / "app")
        module = write(app / "polaris/onboarding/installation.py", "# Non-executable fixture data.\n")
        runtime = write(root / "python/bin/python3.11", "fixture interpreter; never executed\n", 0o700)
        semgrep = write(root / "analyzer/bin/semgrep", "fixture analyzer; never executed\n", 0o700)
        manifest = {
            "format": "polaris.theo-bundle/1",
            "id": release_id,
            "version": __version__,
            "platform": "macos-arm64",
            "minimumMacOS": MINIMUM_MACOS,
            "availability": "unpublished",
            "environments": {
                "app": {"theovex-polaris": __version__, "mcp": "2.2.0", "tomlkit": "0.13.3"},
                "analyzer": {name: pin["version"] for name, pin in identity.contract()["packages"].items()},
            },
            "runtimes": {"python": {"version": "3.11.16"}},
            "analyzerIdentity": identity.manifest_identity(),
        }
        manifest_path = write_json(root / "manifest.json", manifest)
        receipt = {
            "format": "polaris.theo-install/2",
            "release": release_id,
            "version": __version__,
            "platform": "macos-arm64",
            "status": "installed",
            "manager": manager,
            "packageValidated": True,
            "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            "analyzerRuntime": "not_checked",
        }
        receipt_path = write_json(root / "install-receipt.json", receipt)
        monkeypatch.setattr(sys, "prefix", str(app))
        monkeypatch.setattr(installation, "__file__", str(module))
        current = None
        if manager == "standalone":
            launchers = {
                name: write(prefix / "bin" / name, f"# {name} fixture; never executed\n", 0o700)
                for name in ("theo", "polaris")
            }
            current = {
                "format": "polaris.theo-current/2",
                "release": release_id,
                "launchers": {
                    name: hashlib.sha256(path.read_bytes()).hexdigest()
                    for name, path in launchers.items()
                },
            }
            write_json(prefix / "current.json", current)
            installation.seal_uninstall_inventory()
        fixture = SimpleNamespace(
            base=base, prefix=prefix, root=root, app=app, module=module,
            runtime=runtime, semgrep=semgrep, receipt=receipt,
            receipt_path=receipt_path, manifest=manifest,
            manifest_path=manifest_path, current=current,
        )
        made.append(fixture)
        return fixture

    yield create
    # A read-only-directory mutation must not make pytest's disposable cleanup fail.
    for fixture in made:
        if fixture.root.exists() and not fixture.root.is_symlink():
            fixture.root.chmod(0o700)


@pytest.mark.parametrize("manager,keg_suffix", [
    ("standalone", ""), ("homebrew", ""), ("homebrew", "_1"),
])
def test_discovery_is_bound_to_the_running_module_and_matching_receipt(managed, manager, keg_suffix):
    fixture = managed(manager, keg_suffix=keg_suffix)
    before = fingerprint(fixture.base)
    observed = installation.managed_installation()
    assert observed["status"] == "managed" and observed["manager"] == manager
    assert observed["root"] == str(fixture.root) and observed["prefix"] == str(fixture.prefix)
    assert observed["release"] == RELEASE_ID and observed["version"] == __version__
    assert observed["minimum_macos"] == MINIMUM_MACOS
    assert observed["package_validated"] is True and observed["host_verified"] is False
    assert installation.analyzer() == fixture.semgrep
    assert fingerprint(fixture.base) == before


@pytest.mark.parametrize("manager", ["standalone", "homebrew"])
def test_signed_revision_binds_its_own_receipts_and_never_adopts_unsigned_identity(managed, manager):
    fixture = managed(manager, release_id=SIGNED_RELEASE_ID)
    assert installation.managed_installation()["release"] == SIGNED_RELEASE_ID
    if manager == "standalone":
        receipt = json.loads((fixture.root / "uninstall-files.json").read_bytes())
        assert receipt["release"] == SIGNED_RELEASE_ID
        assert lifecycle.uninstall()["release"] == SIGNED_RELEASE_ID
        assert lifecycle.uninstall(confirm=True)["status"] == "runtime_removed"
    else:
        write_json(fixture.receipt_path, {**fixture.receipt, "release": RELEASE_ID})
        with pytest.raises(OnboardingProblem):
            installation.managed_installation()


def test_homebrew_opt_link_resolves_to_owned_versioned_keg(managed, monkeypatch):
    fixture = managed("homebrew")
    opt = fixture.base / "brew/opt/polaris"
    private_directory(opt.parent)
    opt.symlink_to(fixture.prefix, target_is_directory=True)
    monkeypatch.setattr(sys, "prefix", str(opt / "libexec/app"))
    monkeypatch.setattr(installation, "__file__", str(opt / "libexec/app/polaris/onboarding/installation.py"))
    assert installation.managed_installation()["root"] == str(fixture.root)
    assert installation.analyzer() == fixture.semgrep


@pytest.mark.parametrize("variant", ["foreign-module", "module-symlink", "wrong-app-name", "wrong-keg"])
def test_discovery_refuses_module_or_layout_binding_mismatch(managed, monkeypatch, variant):
    fixture = managed("homebrew" if variant == "wrong-keg" else "standalone")
    if variant == "foreign-module":
        foreign = write(fixture.base / "other/installation.py", "# unrelated fixture\n")
        monkeypatch.setattr(installation, "__file__", str(foreign))
    elif variant == "module-symlink":
        foreign = write(fixture.base / "other/installation.py", "# unrelated fixture\n")
        fixture.module.unlink()
        fixture.module.symlink_to(foreign)
    elif variant == "wrong-app-name":
        alternate = fixture.app.with_name("other-app")
        fixture.app.rename(alternate)
        monkeypatch.setattr(sys, "prefix", str(alternate))
        monkeypatch.setattr(installation, "__file__", str(alternate / "polaris/onboarding/installation.py"))
    else:
        alternate = fixture.prefix.with_name("999.0.0")
        fixture.prefix.rename(alternate)
        monkeypatch.setattr(sys, "prefix", str(alternate / "libexec/app"))
        monkeypatch.setattr(installation, "__file__", str(alternate / "libexec/app/polaris/onboarding/installation.py"))
    before = fingerprint(fixture.base)
    with pytest.raises(OnboardingProblem) as caught:
        installation.managed_installation()
    assert caught.value.code == "invalid_installation"
    assert fingerprint(fixture.base) == before


@pytest.mark.parametrize("field,value", [
    ("format", "polaris.theo-install/1"),
    ("release", "theo-wrong-fixture"),
    ("version", "999.0.0"),
    ("platform", "macos-x86_64"),
    ("status", "partial"),
    ("manager", "unknown"),
    ("packageValidated", False),
    ("packageValidated", 1),
    ("manifest_sha256", "0" * 63),
    ("manifest_sha256", "0" * 64),
])
def test_discovery_rejects_receipt_changes_without_writes(managed, field, value):
    fixture = managed()
    write_json(fixture.receipt_path, {**fixture.receipt, field: value})
    before = fingerprint(fixture.base)
    with pytest.raises(OnboardingProblem):
        installation.managed_installation()
    assert fingerprint(fixture.base) == before


@pytest.mark.parametrize("field,value", [
    ("format", "polaris.theo-bundle/99"),
    ("id", "theo-other-fixture"),
    ("version", "999.0.0"),
    ("platform", "macos-x86_64"),
    ("minimumMacOS", "11.0"),
    ("minimumMacOS", None),
])
def test_manifest_identity_is_checked_even_when_receipt_digest_matches(managed, field, value):
    fixture = managed()
    write_json(fixture.manifest_path, {**fixture.manifest, field: value})
    write_json(fixture.receipt_path, {
        **fixture.receipt,
        "manifest_sha256": hashlib.sha256(fixture.manifest_path.read_bytes()).hexdigest(),
    })
    before = fingerprint(fixture.base)
    with pytest.raises(OnboardingProblem):
        installation.managed_installation()
    assert fingerprint(fixture.base) == before


@pytest.mark.parametrize("manager", ["standalone", "homebrew"])
@pytest.mark.parametrize("target", ["receipt", "manifest", "root", "app", "analyzer", "analyzer-bin", "executable"])
def test_discovery_refuses_writable_receipts_and_runtime_paths(managed, manager, target):
    fixture = managed(manager)
    path = {
        "receipt": fixture.receipt_path,
        "manifest": fixture.manifest_path,
        "root": fixture.root,
        "app": fixture.app,
        "analyzer": fixture.semgrep.parent.parent,
        "analyzer-bin": fixture.semgrep.parent,
        "executable": fixture.semgrep,
    }[target]
    path.chmod(stat.S_IMODE(path.stat().st_mode) | 0o022)
    before = fingerprint(fixture.base)
    with pytest.raises(OnboardingProblem):
        installation.analyzer()
    assert fingerprint(fixture.base) == before


@pytest.mark.parametrize("target", ["receipt", "manifest", "executable", "analyzer-bin"])
def test_discovery_refuses_receipt_or_analyzer_symlinks(managed, target):
    fixture = managed()
    path = {
        "receipt": fixture.receipt_path,
        "manifest": fixture.manifest_path,
        "executable": fixture.semgrep,
        "analyzer-bin": fixture.semgrep.parent,
    }[target]
    moved = fixture.base / "symlink-target"
    path.rename(moved)
    path.symlink_to(moved, target_is_directory=moved.is_dir())
    before = fingerprint(fixture.base)
    with pytest.raises(REFUSALS):
        installation.analyzer()
    assert fingerprint(fixture.base) == before


def test_missing_or_nonexecutable_analyzer_does_not_become_available(managed):
    fixture = managed()
    fixture.semgrep.chmod(0o600)
    with pytest.raises(IntegrationProblem):
        installation.analyzer()
    fixture.semgrep.unlink()
    with pytest.raises(REFUSALS):
        installation.analyzer()


def test_path_project_and_environment_hints_cannot_select_a_managed_runtime(managed, tmp_path, monkeypatch):
    fixture = managed()
    project = private_directory(tmp_path / "project")
    shutil.copyfile(fixture.receipt_path, project / "install-receipt.json")
    shutil.copyfile(fixture.manifest_path, project / "manifest.json")
    unowned_python = private_directory(tmp_path / "unmanaged-python")
    monkeypatch.setattr(sys, "prefix", str(unowned_python))
    monkeypatch.chdir(project)
    for name, value in {
        "PATH": fixture.semgrep.parent,
        "POLARIS_HOME": fixture.root,
        "POLARIS_SEMGREP": fixture.semgrep,
        "THEO_PREFIX": fixture.prefix,
        "HOMEBREW_PREFIX": fixture.prefix,
        "VIRTUAL_ENV": fixture.app,
        "PYTHONPATH": fixture.app,
    }.items():
        monkeypatch.setenv(name, str(value))
    monkeypatch.setattr(shutil, "which", lambda *a, **kw: pytest.fail("Searched ambient PATH."))
    before = fingerprint(tmp_path)
    assert installation.managed_installation() == {
        "status": "unmanaged", "version": __version__, "manager": "python",
    }
    assert installation.analyzer() is None
    assert fingerprint(tmp_path) == before


@pytest.mark.parametrize("surface", ["cli", "host"])
@pytest.mark.parametrize("external,explicit,requested", [
    (True, False, False), (True, False, True), (True, True, True), (False, False, True), (False, True, False),
])
def test_explicit_and_disabled_analyzer_settings_take_precedence(
    monkeypatch, tmp_path, surface, external, explicit, requested,
):
    discovered, selected = tmp_path / "managed-semgrep", tmp_path / "explicit-semgrep"
    calls = []

    def discover():
        calls.append(True)
        return discovered

    monkeypatch.setattr(installation, "analyzer", discover)
    value = selected if explicit else None
    if surface == "cli":
        arguments = argparse.Namespace(
            checks=None, include=None, exclude=None, semgrep=value, with_semgrep=requested,
            no_external_analyzers=not external, guard_policy=None,
        )
        _, runtime, _ = workflow_cli.analysis_settings(arguments)
    else:
        runtime, _, _ = workflow_host.host_settings(semgrep=value, external=external, managed_semgrep=requested)
    # Semgrep is opt-in: the managed install is only looked up when explicitly requested.
    expected = selected if explicit else discovered if external and requested else None
    assert runtime.semgrep_executable == (str(expected) if expected else None)
    assert runtime.allow_external_analyzers is external
    assert runtime.allow_temporary_source_files is external
    assert len(calls) == int(external and requested and not explicit)


def test_host_configuration_refuses_relative_explicit_analyzers():
    with pytest.raises(ValueError, match="invalid trusted host configuration"):
        workflow_host.host_settings(semgrep=Path("project/semgrep"), external=True)


def test_discovery_errors_are_visible_not_an_unmanaged_fallback(monkeypatch, capsys):
    def invalid():
        raise OnboardingProblem("invalid_installation", "Synthetic installation problem.")

    monkeypatch.setattr(installation, "analyzer", invalid)
    with pytest.raises(ValueError, match="invalid trusted host configuration"):
        workflow_host.host_settings(external=True, managed_semgrep=True)
    arguments = argparse.Namespace(
        workflow_command="capabilities", checks=None, include=None, exclude=None,
        semgrep=None, with_semgrep=True, no_external_analyzers=False, guard_policy=None, output=None,
    )
    assert workflow_cli.run(arguments) == 2
    assert json.loads(capsys.readouterr().out)["code"] == "workflow_unavailable"


@pytest.mark.parametrize("manager", ["standalone", "homebrew", "python"])
def test_installation_diagnostics_need_no_project_host_credentials_or_probes(
    managed, tmp_path, isolated_account, monkeypatch, capsys, manager,
):
    if manager == "python":
        monkeypatch.setattr(sys, "prefix", str(private_directory(tmp_path / "python-env")))
    else:
        managed(manager)
    monkeypatch.chdir(isolated_account)
    monkeypatch.setattr(cli.storage, "project_root", lambda *a: pytest.fail("Required a project."))
    monkeypatch.setattr(cli, "choose_host", lambda *a: pytest.fail("Required a coding host."))
    monkeypatch.setattr(cli, "_configure", lambda *a, **kw: pytest.fail("Configured a project."))
    before = fingerprint(tmp_path)
    assert cli.main(["installation", "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["command"] == "installation" and report["manager"] == manager
    assert report["network_used"] is False and not report.get("host_verified", False)
    assert bool(report["analyzer"]) is (manager != "python")
    assert fingerprint(tmp_path) == before


@pytest.mark.parametrize("content", ["{", "[]", "null"])
def test_malformed_installation_receipts_are_safe_cli_errors(managed, capsys, content):
    fixture = managed()
    write(fixture.receipt_path, content)
    before = fingerprint(fixture.base)
    assert cli.main(["installation", "--json"]) == 2
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report["status"] == "error" and report["host_verified"] is False
    assert not captured.err and str(fixture.root) not in captured.out
    assert fingerprint(fixture.base) == before


@pytest.mark.parametrize("manager", ["homebrew", "python"])
@pytest.mark.parametrize("confirm", [False, True])
def test_nonstandalone_uninstall_delegates_without_any_mutation(managed, tmp_path, monkeypatch, manager, confirm):
    if manager == "python":
        monkeypatch.setattr(sys, "prefix", str(private_directory(tmp_path / "python-env")))
    else:
        managed(manager)
    before = fingerprint(tmp_path)
    report = lifecycle.uninstall(confirm=confirm)
    assert report["status"] == "package_manager_owned" and report["manager"] == manager
    assert report["changed"] is False
    if manager == "homebrew":
        assert "brew uninstall polaris" in report["next_action"]
    assert fingerprint(tmp_path) == before


def test_standalone_uninstall_is_preview_until_explicit_confirmation(managed):
    fixture = managed()
    before = fingerprint(fixture.base)
    report = lifecycle.uninstall()
    assert report["status"] == "removal_preview" and report["changed"] is False
    assert set(report["commands"]) == {str(fixture.prefix / "bin" / name) for name in ("theo", "polaris")}
    assert fingerprint(fixture.base) == before
    removed = lifecycle.uninstall(confirm=True)
    assert removed["status"] == "runtime_removed" and removed["changed"] is True
    assert not fixture.root.exists()
    assert not (fixture.prefix / "current.json").exists()
    assert not any((fixture.prefix / "bin").iterdir())
    assert (fixture.prefix / "owner.json").exists()
    assert (fixture.prefix / "install.lock").exists()
    after = fingerprint(fixture.base)
    assert lifecycle.uninstall(confirm=True)["changed"] is False
    assert fingerprint(fixture.base) == after


@pytest.mark.parametrize("mutation", [
    "runtime-content", "runtime-mode", "unknown-file", "unknown-directory",
    "launcher-content", "launcher-mode", "root-mode",
    "missing-launcher", "current-manifest", "removal-receipt",
])
def test_preexisting_changes_refuse_uninstall_before_any_owned_write(managed, mutation):
    fixture = managed()
    if mutation == "runtime-content":
        write(fixture.runtime, "changed fixture\n", 0o700)
    elif mutation == "runtime-mode":
        fixture.runtime.chmod(0o500)
    elif mutation == "unknown-file":
        write(fixture.root / "user-notes.txt", "retain unrelated notes\n")
    elif mutation == "unknown-directory":
        private_directory(fixture.root / "user-empty-directory")
    elif mutation == "launcher-content":
        write(fixture.prefix / "bin/theo", "# user-edited fixture\n", 0o700)
    elif mutation == "launcher-mode":
        (fixture.prefix / "bin/theo").chmod(0o500)
    elif mutation == "root-mode":
        fixture.root.chmod(0o500)
    elif mutation == "missing-launcher":
        (fixture.prefix / "bin/polaris").unlink()
    elif mutation == "current-manifest":
        write_json(fixture.prefix / "current.json", {**fixture.current, "format": "wrong"})
    else:
        write_json(fixture.root / "uninstall-files.json", {"format": "wrong", "files": {}})
    before = fingerprint(fixture.base)
    with pytest.raises(REFUSALS):
        lifecycle.uninstall(confirm=True)
    assert fingerprint(fixture.base) == before


@pytest.mark.parametrize("target", ["current.json", "install.lock", "bin/theo", "releases-receipt"])
def test_uninstall_preflight_does_not_follow_replaced_receipt_lock_or_command_links(managed, target):
    fixture = managed()
    path = (fixture.root / "uninstall-files.json" if target == "releases-receipt"
            else fixture.prefix / target)
    saved = fixture.base / "saved-target"
    path.rename(saved)
    path.symlink_to(saved)
    before = fingerprint(fixture.base)
    with pytest.raises(REFUSALS):
        lifecycle.uninstall(confirm=True)
    assert fingerprint(fixture.base) == before


def test_confirmed_removal_preserves_user_state_older_releases_and_all_excluded_scratch(
    managed, isolated_account,
):
    fixture = managed()
    retained = [
        write(isolated_account / "project/app.py", "# synthetic user project\n"),
        write(isolated_account / "project/.mcp.json", '{"unrelated": true}\n'),
        write(isolated_account / ".polaris/credentials.json", '{"fixture": "not-a-credential"}\n'),
        write(isolated_account / ".zprofile", "# synthetic profile\n"),
        write(fixture.prefix / "state/projects/receipt.json", '{"fixture": true}\n'),
        write(fixture.prefix / "profile-backups/profile", "# synthetic backup\n"),
        write(fixture.prefix / "releases/theo-previous-fixture/retained.txt", "not executable old code\n"),
        write(fixture.prefix / "bin/unrelated", "# unrelated command fixture\n"),
        write(fixture.root / "installer-home/user-file", "retained scratch\n"),
        write(fixture.root / "tmp/user-file", "retained scratch\n"),
        write(fixture.root / "uv-cache/user-file", "retained scratch\n"),
        write(fixture.root / ".interrupted-app-fixture/user-file", "retained interruption\n"),
        write(fixture.app / ".interrupted-nested-fixture/user-file", "retained nested interruption\n"),
    ]
    before = {path: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode)) for path in retained}
    assert lifecycle.uninstall(confirm=True)["status"] == "runtime_removed"
    assert {path: (path.read_bytes(), stat.S_IMODE(path.stat().st_mode)) for path in retained} == before
    assert not fixture.runtime.exists() and not fixture.module.exists() and not fixture.semgrep.exists()
    assert not fixture.receipt_path.exists()
    assert (fixture.prefix / "owner.json").exists() and (fixture.prefix / "install.lock").exists()


def test_removing_inactive_release_preserves_current_commands_and_selection(managed):
    fixture = managed()
    write_json(fixture.prefix / "current.json", {**fixture.current, "release": "theo-other-fixture"})
    paths = [fixture.prefix / "current.json", fixture.prefix / "bin/theo", fixture.prefix / "bin/polaris"]
    before = {path: path.read_bytes() for path in paths}
    report = lifecycle.uninstall(confirm=True)
    assert report["commands"] == [] and report["status"] == "runtime_removed"
    assert {path: path.read_bytes() for path in paths} == before


@pytest.mark.parametrize("home_scope", ["prefix", "descendant", "aliased-prefix", "aliased-descendant"])
def test_uninstall_refuses_canonical_home_and_its_ancestor(managed, monkeypatch, home_scope):
    fixture = managed()
    home = fixture.prefix
    if "descendant" in home_scope:
        home = private_directory(fixture.prefix / "account-child")
    if home_scope.startswith("aliased-"):
        alias = fixture.base / "home-alias"
        alias.symlink_to(home, target_is_directory=True)
        home = alias
    monkeypatch.setenv("HOME", str(home))
    before = fingerprint(fixture.base)
    with pytest.raises(OnboardingProblem) as caught:
        lifecycle.uninstall(confirm=True)
    assert caught.value.code == "unsafe_prefix"
    assert fingerprint(fixture.base) == before


def test_uninstall_respects_existing_installation_lock(managed):
    fixture = managed()
    before = fingerprint(fixture.base)
    with (fixture.prefix / "install.lock").open("rb") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(OnboardingProblem) as caught:
            lifecycle.uninstall(confirm=True)
        assert caught.value.code == "installation_busy"
    assert fingerprint(fixture.base) == before


def test_directory_symlink_swap_during_removal_never_touches_external_content(managed, monkeypatch):
    fixture = managed()
    external = private_directory(fixture.base / "external")
    write(external / "precious.txt", "synthetic content outside the release\n")
    external_before = fingerprint(external)
    moved = fixture.root / ".interrupted-app-race"
    original_remove = lifecycle._remove_entry
    swapped = []

    def swap(parent, name, relative, record, entries, children):
        if relative == "app" and not swapped:
            fixture.app.rename(moved)
            fixture.app.symlink_to(external, target_is_directory=True)
            swapped.append(True)
        return original_remove(parent, name, relative, record, entries, children)

    monkeypatch.setattr(lifecycle, "_remove_entry", swap)
    with pytest.raises(OnboardingProblem) as caught:
        lifecycle.uninstall(confirm=True)
    assert caught.value.code == "removal_stopped" and swapped
    assert fingerprint(external) == external_before
    assert (moved / "polaris/onboarding/installation.py").read_text() == "# Non-executable fixture data.\n"


def test_launcher_parent_symlink_swap_stops_before_runtime_or_external_deletion(managed, monkeypatch):
    fixture = managed()
    external = private_directory(fixture.base / "external-bin")
    write(external / "theo", "unrelated external command fixture\n", 0o700)
    external_before = fingerprint(external)
    runtime_before = fingerprint(fixture.root)
    original_unlink = lifecycle.checked_unlink
    moved = fixture.prefix / "preserved-original-bin"
    swapped = []

    def swap(path, expected):
        if not swapped:
            (fixture.prefix / "bin").rename(moved)
            (fixture.prefix / "bin").symlink_to(external, target_is_directory=True)
            swapped.append(True)
        return original_unlink(path, expected)

    monkeypatch.setattr(lifecycle, "checked_unlink", swap)
    with pytest.raises(OnboardingProblem) as caught:
        lifecycle.uninstall(confirm=True)
    assert caught.value.code == "removal_stopped" and swapped
    assert fingerprint(external) == external_before
    assert fingerprint(fixture.root) == runtime_before
    assert (moved / "theo").exists() and (moved / "polaris").exists()

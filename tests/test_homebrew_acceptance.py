"""Offline harness tests; no Homebrew installation, gem download, or formula execution."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import shutil
import signal
import ssl
import subprocess
import sys
import time
from pathlib import Path

import pytest

from polaris.review.analyzers import identity

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "homebrew_acceptance_test", ROOT / "scripts/verify_homebrew_release.py",
)
assert SPEC and SPEC.loader
verifier = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(verifier)


def sha(content):
    return hashlib.sha256(content).hexdigest()


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    for key in list(os.environ):
        if key.startswith("HOMEBREW_"):
            monkeypatch.delenv(key)
    root = tmp_path.resolve() / "owned"
    root.mkdir(mode=0o700)
    for name in verifier.DIRECTORIES:
        (root / name).mkdir(mode=0o700)
    verifier.write_json(root / "workspace.json", {
        "format": "polaris.homebrew-workspace/1", "root": str(root), "prefix": str(root / "prefix"),
        "uid": os.getuid(), "homebrew_revision": verifier.HOMEBREW_REVISION,
    })
    verifier.write_new(root / "curlrc", b'proto = "=file"\nproto-redir = "=file"\n')
    return verifier.Workspace(root)


def lock_fixture():
    versions = verifier.GEM_VERSIONS
    return ("GEM\n  remote: https://rubygems.org/\n  specs:\n"
            + "".join(f"    {name} ({version})\n" for name, version in versions.items())
            + "\nCHECKSUMS\n"
            + "".join(f"  {name} ({version}) sha256={sha(name.encode())}\n"
                      for name, version in versions.items())).encode()


def test_only_the_eleven_frozen_gems_are_selected():
    content = lock_fixture()
    pins = verifier.locked_gems(content, expected_hash=sha(content))
    assert len(pins) == 11
    assert {item["name"]: item["version"] for item in pins} == verifier.GEM_VERSIONS
    assert all(item["url"] == f'https://rubygems.org/downloads/{item["filename"]}' for item in pins)


@pytest.mark.parametrize("mutation", ["digest", "source", "version", "missing-checksum"])
def test_lock_changes_are_rejected(mutation):
    content = lock_fixture()
    expected = sha(content)
    if mutation == "digest":
        content += b"\n"
    elif mutation == "source":
        content = content.replace(b"https://rubygems.org/", b"https://unapproved.invalid/")
        expected = sha(content)
    elif mutation == "version":
        content = content.replace(b"minitest (6.0.6)", b"minitest (6.0.7)")
        expected = sha(content)
    else:
        content = content.replace(f"  minitest (6.0.6) sha256={sha(b'minitest')}\n".encode(), b"")
        expected = sha(content)
    with pytest.raises(ValueError):
        verifier.locked_gems(content, expected_hash=expected)


@pytest.mark.parametrize("path", ["relative", "/tmp/../outside", "/tmp/line\nbreak"])
def test_ambiguous_paths_are_refused(path):
    with pytest.raises(ValueError):
        verifier.safe_path(Path(path))


def test_source_and_parent_symlinks_are_refused(tmp_path):
    root = tmp_path.resolve()
    source = root / "file"
    source.write_bytes(b"safe")
    alias = root / "alias"
    alias.symlink_to(source)
    with pytest.raises(ValueError, match="symlink"):
        verifier.file_pin(alias)
    directory = root / "directory"
    directory.mkdir()
    parent_alias = root / "linked-parent"
    parent_alias.symlink_to(directory, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        verifier.write_new(parent_alias / "output", b"must not write")
    assert list(directory.iterdir()) == []


def test_exclusive_writes_cannot_replace_user_data(tmp_path):
    path = tmp_path.resolve() / "retained"
    verifier.write_new(path, b"original")
    with pytest.raises(FileExistsError):
        verifier.write_new(path, b"replacement")
    assert path.read_bytes() == b"original"
    assert path.stat().st_mode & 0o777 == 0o600


def test_pin_rejects_nonregular_and_oversized_files(tmp_path):
    root = tmp_path.resolve()
    fifo = root / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match="bounded regular"):
        verifier.file_pin(fifo)
    regular = root / "large"
    regular.write_bytes(b"0123456789")
    with pytest.raises(ValueError, match="bounded regular"):
        verifier.file_pin(regular, limit=9)
    with pytest.raises(ValueError, match="SHA256"):
        verifier.verify_pin(regular, sha(b"different"))


def test_wrong_prefix_marker_is_rejected(workspace):
    path = workspace.root / "workspace.json"
    marker = json.loads(path.read_bytes())
    marker["prefix"] = "/opt/homebrew"
    path.write_text(json.dumps(marker))
    with pytest.raises(ValueError, match="marker"):
        workspace.check()


def test_live_prefix_symlink_is_rejected(workspace):
    workspace.prefix.symlink_to("/opt/homebrew", target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        workspace.check()


@pytest.mark.parametrize("mutation", ["revision", "tracked-code"])
def test_changed_homebrew_source_is_rejected(workspace, monkeypatch, mutation):
    (workspace.prefix / ".git").mkdir(parents=True)
    commands = []

    def inspect(command, **kwargs):
        commands.append(command)
        assert kwargs["env"]["GIT_NO_REPLACE_OBJECTS"] == "1"
        assert kwargs["env"]["GIT_NO_LAZY_FETCH"] == "1"
        if "rev-parse" in command:
            revision = "0" * 40 if mutation == "revision" else verifier.HOMEBREW_REVISION
            return subprocess.CompletedProcess(command, 0, stdout=revision + "\n")
        assert "--no-ext-diff" in command and "--no-textconv" in command and "--quiet" in command
        raise subprocess.CalledProcessError(1, command)

    monkeypatch.setattr(subprocess, "run", inspect)
    with pytest.raises((ValueError, subprocess.CalledProcessError)):
        workspace.verify_homebrew()
    assert len(commands) == (1 if mutation == "revision" else 2)


@pytest.fixture
def external_temp_parent(workspace, monkeypatch):
    parent = workspace.root.parent / "system-temp"
    parent.mkdir(mode=0o700)
    monkeypatch.setattr(verifier, "system_temporary_directory", lambda: parent)
    monkeypatch.setattr(verifier, "has_git_ancestor", lambda path: False)
    monkeypatch.setattr(verifier, "ensure_unconfined", lambda: None)
    return parent


def test_external_test_temp_is_fresh_owned_and_narrowly_bound(workspace, external_temp_parent):
    workspace.isolate_test_temp()
    marker = json.loads((workspace.root / "workspace.json").read_bytes())
    record = marker["externalTestTemp"]
    temporary = Path(record["identity"]["path"])
    assert temporary.parent == external_temp_parent
    assert record["identity"] == verifier.directory_identity(temporary)
    assert list(temporary.iterdir()) == [temporary / ".polaris-homebrew-test-workspace.json"]
    env = workspace.environment()
    assert env["HOMEBREW_TEMP"] == env["TMPDIR"] == str(temporary)
    assert env["TMP"] == env["TEMP"] == str(workspace.root / "tmp")
    assert env["HOME"] == str(workspace.root / "home")
    binding = json.loads(next(workspace.root.glob("test-temp-binding-*.json")).read_bytes())
    assert "externalTestTemp" not in binding["previousMarker"]
    assert binding["freshMkdtemp"] is True
    with pytest.raises(ValueError, match="already bound"):
        workspace.isolate_test_temp()


@pytest.mark.parametrize("mutation", ["replacement", "symlink", "mode", "ownership", "ancestor"])
def test_external_test_temp_tampering_is_rejected(workspace, external_temp_parent, monkeypatch, mutation):
    workspace.isolate_test_temp()
    marker = json.loads((workspace.root / "workspace.json").read_bytes())
    temporary = Path(marker["externalTestTemp"]["identity"]["path"])
    if mutation in ("replacement", "symlink"):
        retained = external_temp_parent / "retained-original"
        temporary.rename(retained)
        if mutation == "replacement":
            temporary.mkdir(mode=0o700)
        else:
            temporary.symlink_to(retained, target_is_directory=True)
    elif mutation == "mode":
        temporary.chmod(0o755)
    elif mutation == "ownership":
        (temporary / ".polaris-homebrew-test-workspace.json").write_bytes(b"changed")
    else:
        monkeypatch.setattr(verifier, "has_git_ancestor", lambda path: True)
    with pytest.raises(ValueError):
        workspace.check()


def test_external_temp_inside_a_checkout_is_refused_before_creation(
    workspace, external_temp_parent, monkeypatch,
):
    monkeypatch.setattr(verifier, "has_git_ancestor", lambda path: True)
    with pytest.raises(ValueError, match="inside a Git"):
        workspace.isolate_test_temp()
    assert list(external_temp_parent.iterdir()) == []
    assert "externalTestTemp" not in json.loads((workspace.root / "workspace.json").read_bytes())


@pytest.mark.parametrize("key", ["HOMEBREW_TESTS", "HOMEBREW_AVOID_NESTED_SANDBOXING",
                                 "HOMEBREW_NO_REQUIRE_TAP_TRUST",
                                 "HOMEBREW_AUTOMATICALLY_SET_NO_INSTALL_FROM_API"])
def test_inherited_semantic_bypasses_are_rejected(workspace, monkeypatch, key):
    monkeypatch.setenv(key, "1")
    with pytest.raises(ValueError, match="inherited"):
        workspace.environment()


def test_environment_keeps_safety_and_no_credentials(workspace, monkeypatch):
    monkeypatch.setenv("SYNTHETIC_SECRET", "must-not-propagate")
    monkeypatch.setenv("HOMEBREW_FORBIDDEN_TAPS", "unapproved/example")
    env = workspace.environment()
    assert "SYNTHETIC_SECRET" not in env
    assert env["HOMEBREW_FORBIDDEN_TAPS"] == "unapproved/example"
    assert env["HOME"] == str(workspace.root / "home")
    assert env["HOMEBREW_CACHE"] == str(workspace.root / "cache/homebrew")
    assert env["HOMEBREW_NO_AUTO_UPDATE"] == env["HOMEBREW_NO_AUTOREMOVE"] == "1"
    assert "HOMEBREW_NO_INSTALL_FROM_API" not in env
    assert "HOMEBREW_NO_REQUIRE_TAP_TRUST" not in env
    assert "HOMEBREW_TESTS" not in env


def test_redirects_fail_without_echoing_the_destination():
    with pytest.raises(ValueError) as error:
        verifier.NoRedirect().redirect_request(None, None, 302, "", {}, "https://secret.invalid/token")
    assert "secret" not in str(error.value)


def test_download_deadline_interrupts_and_restores_signal_state():
    before = signal.getsignal(signal.SIGALRM)
    started = time.monotonic()
    with pytest.raises(TimeoutError, match="time bound"), verifier.download_deadline(0.02):
        time.sleep(2)
    assert time.monotonic() - started < 1
    assert signal.getsignal(signal.SIGALRM) == before
    assert signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0)


def test_download_deadline_will_not_replace_an_existing_alarm(monkeypatch):
    monkeypatch.setattr(signal, "getitimer", lambda timer: (10.0, 0.0))
    with pytest.raises(ValueError, match="existing alarm"), verifier.download_deadline():
        pytest.fail("The existing alarm was ignored.")


def make_candidate(root, version="0.3.3", *, mode="local-file"):
    root.mkdir()
    release = f"theo-{version}-macos-arm64-r1"
    manifest = {
        "format": "polaris.theo-bundle/1", "id": release, "version": version, "platform": "macos-arm64",
        "environments": {
            "app": {"theovex-polaris": version, "mcp": "2.2.0", "tomlkit": "0.13.3"},
            "analyzer": {name: pin["version"] for name, pin in identity.contract()["packages"].items()},
        },
        "runtimes": {"python": {"version": "3.11.16"}},
        "analyzerIdentity": identity.manifest_identity(),
    }
    raw_manifest = json.dumps(manifest).encode()
    (root / "manifest.json").write_bytes(raw_manifest)
    manifest_sha = sha(raw_manifest)
    archive = root / f"{release}-homebrew.tar.gz"
    archive.write_bytes(f"An inert {version} archive fixture, never executed.".encode())
    archive_sha = sha(archive.read_bytes())
    url = (archive.as_uri() if mode == "local-file"
           else f"https://approved.invalid/releases/{release}/{archive.name}")
    formula = root / "polaris.rb"
    formula.write_text(
        f'class Polaris < Formula\n  url "{url}"\n'
        f'  version "{version}"\n  sha256 "{archive_sha}"\n'
        f'  THEO_RELEASE = "{release}".freeze\n'
        f'  THEO_MANIFEST_SHA256 = "{manifest_sha}".freeze\n  deny_network_access!\nend\n',
    )
    formula_sha = sha(formula.read_bytes())
    metadata = {
        "format": "polaris.homebrew-release/1", "mode": mode, "availability": "unpublished",
        "publicationPerformed": False, "platform": "macos-arm64", "version": version, "release": release,
        "formula": {"sha256": formula_sha, "bytes": formula.stat().st_size},
        "artifact": {"name": archive.name, "sha256": archive_sha,
                     "bytes": archive.stat().st_size, "url": url},
        "manifest": {"sha256": manifest_sha},
    }
    (root / "homebrew.json").write_text(json.dumps(metadata))
    return formula, formula_sha, archive_sha, metadata


@pytest.fixture
def candidate(tmp_path):
    return make_candidate(tmp_path.resolve() / "candidate")


def test_explicit_candidate_pins_are_version_independent(candidate):
    formula, formula_sha, archive_sha, _ = candidate
    result = verifier.inspect_candidate(formula, formula_sha, archive_sha)
    assert result["version"] == "0.3.3"
    assert result["formula_sha256"] == formula_sha
    assert result["archive_sha256"] == archive_sha


@pytest.mark.parametrize("mutation", ["formula", "archive", "url", "name", "version",
                                     "published", "metadata-formula-sha"])
def test_tampered_candidate_is_refused(candidate, mutation):
    formula, formula_sha, archive_sha, metadata = candidate
    if mutation == "formula":
        formula.write_text(formula.read_text() + "# Changed\n")
    elif mutation == "archive":
        (formula.parent / metadata["artifact"]["name"]).write_bytes(b"changed")
    elif mutation == "url":
        metadata["artifact"]["url"] = "https://unapproved.invalid/release.tar.gz"
    elif mutation == "name":
        metadata["artifact"]["name"] = "../outside"
    elif mutation == "version":
        metadata["version"] = "../../outside"
    elif mutation == "published":
        metadata["publicationPerformed"] = True
    else:
        metadata["formula"]["sha256"] = sha(b"different")
    (formula.parent / "homebrew.json").write_text(json.dumps(metadata))
    with pytest.raises(ValueError):
        verifier.inspect_candidate(formula, formula_sha, archive_sha)


def test_runtime_inventory_detects_bytes_modes_and_added_files(tmp_path):
    root = tmp_path.resolve() / "runtime"
    root.mkdir()
    path = root / "encodings.pyc"
    path.write_bytes(b"original")
    before = verifier.tree_inventory(root)
    path.write_bytes(b"changed")
    assert verifier.tree_inventory(root) != before
    path.write_bytes(b"original")
    path.chmod(0o700)
    assert verifier.tree_inventory(root) != before
    path.chmod(before[path.name]["mode"])
    assert verifier.tree_inventory(root) == before
    (root / "new.pyc").write_bytes(b"new")
    assert verifier.tree_inventory(root) != before


def test_inventory_allows_owned_venv_links_but_refuses_escape(tmp_path):
    root = tmp_path.resolve() / "runtime"
    root.mkdir()
    binary = root / "python"
    binary.write_bytes(b"not executable")
    (root / "venv-python").symlink_to(binary)
    assert verifier.tree_inventory(root)["venv-python"]["link"] == str(binary)
    outside = tmp_path.resolve() / "outside"
    outside.write_bytes(b"outside")
    (root / "escape").symlink_to(outside)
    with pytest.raises(ValueError, match="escapes"):
        verifier.tree_inventory(root)


def test_preservation_verification_never_recreates_removed_files(workspace):
    workspace.fixture(create=True)
    sentinel = workspace.root / "home/unrelated-preservation.fixture"
    sentinel.unlink()
    with pytest.raises(FileNotFoundError):
        workspace.fixture()
    assert not sentinel.exists()


def complete_review():
    return {
        "format": "polaris.workflow/0.1.0", "status": "complete", "snapshot": {"fresh": True},
        "changes": [{"path": name} for name in ("app.py", "app.js")],
        "review": {
            "coverage": {"complete": True, "files_analyzed": 2, "entries": [
                {"path": name, "check_id": "command_injection", "status": "checked"}
                for name in ("app.py", "app.js")
            ]},
            "findings": [{"path": name, "check_id": "command_injection", "result": "flagged"}
                         for name in ("app.py", "app.js")],
        },
    }


def test_review_requires_fresh_complete_nonempty_two_language_analysis():
    report = complete_review()
    verifier.validate_review(report)
    report["review"]["findings"] = []
    with pytest.raises(ValueError, match="nonempty"):
        verifier.validate_review(report)


@pytest.mark.parametrize("mutation", ["stale", "missing-file", "partial", "unchecked"])
def test_incomplete_reviews_cannot_pass(mutation):
    report = complete_review()
    if mutation == "stale":
        report["snapshot"]["fresh"] = False
    elif mutation == "missing-file":
        report["changes"].pop()
    elif mutation == "partial":
        report["review"]["coverage"]["complete"] = False
    else:
        report["review"]["coverage"]["entries"][0]["status"] = "not_checked"
    with pytest.raises(ValueError):
        verifier.validate_review(report)


def test_command_receipts_retain_real_nonzero_exit(workspace):
    output, path = workspace.run("fixture-failure", [sys.executable, "-I", "-B", "-c",
                                                    "print('fixture'); raise SystemExit(3)"],
                                 accepted=(3,))
    assert output.strip() == "fixture"
    assert json.loads((path / "command.json").read_bytes())["returncode"] == 3
    with pytest.raises(ValueError, match="failed"):
        workspace.run("fixture-failure", [sys.executable, "-I", "-B", "-c", "raise SystemExit(3)"])


def test_output_bound_stops_a_run_and_preserves_failure(workspace, monkeypatch):
    monkeypatch.setattr(verifier, "MAX_LOG", 100)
    with pytest.raises(ValueError, match="output bound"):
        workspace.run("too-much-output", [sys.executable, "-I", "-B", "-c",
                                          "import time; print('x'*1000, flush=True); time.sleep(30)"])
    receipts = list((workspace.root / "results").glob("*/command.json"))
    assert len(receipts) == 1
    assert json.loads(receipts[0].read_bytes())["error"] == "ValueError"


def test_timeout_cleans_up_a_detached_descendant(workspace):
    program = (
        "import subprocess,sys,time\n"
        "child=subprocess.Popen([sys.executable,'-I','-B','-c','import time; time.sleep(30)'],"
        "start_new_session=True)\n"
        "print(child.pid,flush=True)\n"
        "time.sleep(30)\n"
    )
    with pytest.raises(ValueError, match="time bound"):
        workspace.run("timeout", [sys.executable, "-I", "-B", "-c", program], timeout=1.5)
    stdout = next((workspace.root / "results").glob("*/stdout.log"))
    child = int(stdout.read_text())
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        result = subprocess.run(["/bin/ps", "-p", str(child), "-o", "stat="],
                                capture_output=True, text=True, check=False)
        if result.returncode != 0 or result.stdout.strip().startswith("Z"):
            break
        time.sleep(0.05)
    else:
        pytest.fail("Detached owned descendant survived the bounded command.")


@pytest.mark.parametrize("failure", [False, True])
def test_genuine_test_keeps_normal_arguments_and_records_failure(workspace, candidate, monkeypatch, failure):
    formula, formula_sha, archive_sha, _ = candidate
    staged = verifier.inspect_candidate(formula, formula_sha, archive_sha)
    stage = workspace.root / "stages/test"
    stage.mkdir()
    staged["stage"] = str(stage)
    commands = []
    monkeypatch.setattr(verifier, "ensure_unconfined", lambda: None)
    monkeypatch.setattr(verifier, "tree_inventory", lambda root: {"fixture": {"sha256": "unchanged"}})
    monkeypatch.setattr(workspace, "verify_homebrew", lambda: None)
    monkeypatch.setattr(workspace, "verify_gems", lambda: None)
    monkeypatch.setattr(workspace, "fixture", lambda: None)
    monkeypatch.setattr(workspace, "staged", lambda: staged)

    def capture(*args, **kwargs):
        commands.append(args)
        if failure:
            raise ValueError("Genuine test failed.")
        return "", stage

    monkeypatch.setattr(workspace, "brew_run", capture)
    if failure:
        with pytest.raises(ValueError, match="Genuine test failed"):
            workspace.lifecycle("test")
    else:
        workspace.lifecycle("test")
    assert commands == [("genuine-brew-test", "test", verifier.FORMULA)]
    record = json.loads(next(stage.glob("test-*.json")).read_bytes())
    assert record["runtimeInventoryUnchanged"] is True
    assert record["passed"] is not failure
    assert record.get("genuineBrewTestPassed", False) is not failure


def test_cli_argument_error_does_not_echo_supplied_values():
    result = subprocess.run(
        [sys.executable, "-I", "-B", str(ROOT / "scripts/verify_homebrew_release.py"),
         "--unknown=synthetic-do-not-echo"], capture_output=True, text=True, check=False,
    )
    assert result.returncode != 0
    assert "synthetic-do-not-echo" not in result.stdout + result.stderr


@pytest.fixture
def mock_brew(workspace, monkeypatch):
    commands = []
    monkeypatch.setattr(verifier, "ensure_unconfined", lambda: None)
    monkeypatch.setattr(workspace, "verify_homebrew", lambda: None)
    monkeypatch.setattr(workspace, "verify_gems", lambda: None)
    monkeypatch.setattr(workspace, "fixture", lambda **kwargs: None)
    workspace.tap_formula.parent.mkdir(parents=True)

    def capture(*args, **kwargs):
        commands.append(args)
        if args[0] == "https-cache-binding":
            cached = list((workspace.root / "cache/homebrew/downloads").glob("*--*.tar.gz"))
            assert len(cached) == 1
            return str(cached[0]) + "\n", workspace.root / "results"
        return "", workspace.root / "results"

    monkeypatch.setattr(workspace, "brew_run", capture)
    return commands


def install_inert_keg(workspace, candidate):
    keg = workspace.prefix / "Cellar/polaris" / candidate["version"]
    for name in ("bin", ".brew", "libexec"):
        (keg / name).mkdir(parents=True)
    formula = Path(candidate["formula"])
    (keg / ".brew/polaris.rb").write_bytes(formula.read_bytes())
    (keg / "libexec/manifest.json").write_bytes((formula.parent / "manifest.json").read_bytes())
    (keg / "libexec/runtime.fixture").write_bytes(b"Inert runtime bytes, never executed.\n")
    verifier.write_json(keg / "libexec/install-receipt.json", {
        "manager": "homebrew", "status": "installed", "version": candidate["version"],
        "release": candidate["release"], "manifest_sha256": candidate["manifest_sha256"],
        "packageValidated": True,
    })
    for name in ("polaris", "theo"):
        (keg / "bin" / name).write_bytes(b"Inert launcher, never executed.\n")
    for relative, target in {
        "bin/polaris": keg / "bin/polaris", "bin/theo": keg / "bin/theo",
        "opt/polaris": keg, "var/homebrew/linked/polaris": keg,
    }.items():
        path = workspace.prefix / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        if os.path.lexists(path):
            assert path.is_symlink()
            path.unlink()
        path.symlink_to(target)
    return keg


@pytest.fixture
def upgrade_pair(workspace, tmp_path, mock_brew):
    old = make_candidate(tmp_path.resolve() / "old", "0.3.1")
    new = make_candidate(tmp_path.resolve() / "new", "0.3.2")
    workspace.stage(*old[:3])
    previous = workspace.staged()
    install_inert_keg(workspace, previous)
    before = workspace.runtime_snapshot(previous)
    workspace.stage(*new[:3], upgrading=True)
    staged = workspace.staged()
    assert staged["upgradeFrom"]["candidate"] == previous
    assert workspace.runtime_snapshot(previous) == before
    mock_brew.clear()
    return previous, staged


@pytest.mark.parametrize("version", ["0.3.0", "0.3.1"])
def test_same_version_and_downgrade_are_refused_before_staging(
    workspace, tmp_path, mock_brew, version,
):
    old = make_candidate(tmp_path.resolve() / "old", "0.3.1")
    rejected = make_candidate(tmp_path.resolve() / "rejected", version)
    workspace.stage(*old[:3])
    previous = workspace.staged()
    install_inert_keg(workspace, previous)
    mock_brew.clear()
    with pytest.raises(ValueError, match="strictly newer"):
        workspace.stage(*rejected[:3], upgrading=True)
    assert workspace.staged() == previous
    assert workspace.tap_formula.read_bytes() == old[0].read_bytes()
    assert mock_brew == []
    assert len(list((workspace.root / "stages").iterdir())) == 1


@pytest.mark.parametrize("mutation", ["not-installed", "wrong-formula", "wrong-manifest", "extra-keg"])
def test_upgrade_staging_requires_exact_installed_prior_candidate(
    workspace, tmp_path, mock_brew, mutation,
):
    old = make_candidate(tmp_path.resolve() / "old", "0.3.1")
    new = make_candidate(tmp_path.resolve() / "new", "0.3.2")
    workspace.stage(*old[:3])
    previous = workspace.staged()
    if mutation != "not-installed":
        keg = install_inert_keg(workspace, previous)
        if mutation == "wrong-formula":
            (keg / ".brew/polaris.rb").write_bytes(b"wrong")
        elif mutation == "wrong-manifest":
            (keg / "libexec/manifest.json").write_bytes(b"wrong")
        else:
            (keg.parent / "0.3.0").mkdir()
    mock_brew.clear()
    with pytest.raises(ValueError):
        workspace.stage(*new[:3], upgrading=True)
    assert workspace.staged() == previous
    assert mock_brew == []


@pytest.mark.parametrize("relative", [
    "bin/polaris", "bin/theo", "opt/polaris", "var/homebrew/linked/polaris",
])
@pytest.mark.parametrize("kind", ["file", "outside-symlink", "dangling-symlink"])
def test_upgrade_refuses_command_collisions_without_force_or_mutation(
    workspace, upgrade_pair, mock_brew, relative, kind,
):
    previous, candidate = upgrade_pair
    before = workspace.runtime_snapshot(previous)
    command = workspace.prefix / relative
    command.unlink()
    unrelated = workspace.root / "unrelated-command"
    unrelated.write_bytes(b"Preserve this unrelated command.\n")
    if kind == "file":
        command.write_bytes(unrelated.read_bytes())
    else:
        command.symlink_to(unrelated if kind == "outside-symlink" else workspace.root / "absent-command")
    with pytest.raises((ValueError, FileNotFoundError)):
        workspace.lifecycle("upgrade")
    assert mock_brew == []
    assert workspace.runtime_snapshot(previous) == before
    assert unrelated.read_bytes() == b"Preserve this unrelated command.\n"
    if kind == "file":
        assert command.read_bytes() == unrelated.read_bytes()
    else:
        assert command.is_symlink()
    record = verifier.read_json(next(Path(candidate["stage"]).glob("upgrade-*.json")))
    assert record["passed"] is False and record["previousRuntimeUnchanged"] is True


@pytest.mark.parametrize("result", ["success", "failure", "no-op", "mutates-old", "wrong-links"])
def test_upgrade_calls_real_command_shape_and_requires_observed_transition(
    workspace, upgrade_pair, monkeypatch, result,
):
    previous, candidate = upgrade_pair
    commands = []

    def capture(*args, **kwargs):
        commands.append(args)
        if result == "failure":
            raise ValueError("Genuine upgrade failed.")
        if result != "no-op":
            install_inert_keg(workspace, candidate)
        if result == "mutates-old":
            (workspace.prefix / "Cellar/polaris" / previous["version"] / "libexec/runtime.fixture").write_bytes(b"changed")
        if result == "wrong-links":
            path = workspace.prefix / "bin/theo"
            path.unlink()
            path.symlink_to(workspace.prefix / "Cellar/polaris" / previous["version"] / "bin/theo")
        return "", workspace.root / "results"

    monkeypatch.setattr(workspace, "brew_run", capture)
    if result == "success":
        workspace.lifecycle("upgrade")
    else:
        with pytest.raises(ValueError):
            workspace.lifecycle("upgrade")
    assert commands == [("genuine-brew-upgrade", "upgrade", "--formula", verifier.FORMULA)]
    record = verifier.read_json(next(Path(candidate["stage"]).glob("upgrade-*.json")))
    assert record["passed"] is (result == "success")
    assert record["previousRuntimeUnchanged"] is (result != "mutates-old")
    assert record.get("genuineBrewUpgradePassed", False) is (result == "success")


def test_fresh_install_cannot_be_reported_as_upgrade(workspace, candidate, mock_brew):
    workspace.stage(*candidate[:3])
    mock_brew.clear()
    with pytest.raises(ValueError, match="explicitly staged previous"):
        workspace.lifecycle("upgrade")
    assert mock_brew == []


@pytest.mark.parametrize("mutation", ["snapshot", "old-launcher", "old-runtime", "new-already-installed"])
def test_changed_upgrade_prerequisites_fail_before_brew(
    workspace, upgrade_pair, mock_brew, mutation,
):
    previous, candidate = upgrade_pair
    old = workspace.prefix / "Cellar/polaris" / previous["version"]
    if mutation == "snapshot":
        (Path(candidate["stage"]) / "previous-runtime.json").write_bytes(b"{}")
    elif mutation == "old-launcher":
        (old / "bin/theo").write_bytes(b"changed")
    elif mutation == "old-runtime":
        (old / "libexec/runtime.fixture").write_bytes(b"changed")
    else:
        install_inert_keg(workspace, candidate)
    with pytest.raises(ValueError):
        workspace.lifecycle("upgrade")
    assert mock_brew == []
    assert verifier.read_json(next(Path(candidate["stage"]).glob("upgrade-*.json")))["passed"] is False


def test_ordinary_upgraded_uninstall_retains_old_runtime(workspace, upgrade_pair, monkeypatch):
    previous, candidate = upgrade_pair
    new_keg = install_inert_keg(workspace, candidate)
    before = workspace.runtime_snapshot(previous)
    commands = []

    def uninstall(*args, **kwargs):
        commands.append(args)
        for relative in ("bin/polaris", "bin/theo", "opt/polaris", "var/homebrew/linked/polaris"):
            (workspace.prefix / relative).unlink()
        shutil.rmtree(new_keg)
        return "", workspace.root / "results"

    monkeypatch.setattr(workspace, "brew_run", uninstall)
    workspace.lifecycle("uninstall")
    assert commands == [("uninstall", "uninstall", "--formula", verifier.FORMULA)]
    assert workspace.runtime_snapshot(previous) == before
    assert workspace.installed_versions() == [previous["version"]]
    receipt = verifier.read_json(next(Path(candidate["stage"]).glob("uninstall-*.json")))
    assert receipt["allKegsRemoved"] is False
    assert receipt["previousRuntimeRetainedUnchanged"] is True
    assert receipt["kegAndLinksRemoved"] is True


def test_semgrep_expected_identity_comes_from_pinned_manifest(candidate):
    formula, formula_sha, archive_sha, _ = candidate
    inspected = verifier.inspect_candidate(formula, formula_sha, archive_sha)
    assert verifier.expected_semgrep(formula.parent / "manifest.json", inspected) == identity.manifest_identity()
    (formula.parent / "manifest.json").write_bytes(b"changed")
    with pytest.raises(ValueError, match="SHA256"):
        verifier.expected_semgrep(formula.parent / "manifest.json", inspected)


@pytest.mark.parametrize("mutation", ["wrong-release", "wrong-version", "wrong-platform", "missing", "unstable"])
def test_semgrep_manifest_identity_and_pin_are_not_optional(candidate, mutation):
    formula, formula_sha, archive_sha, _ = candidate
    inspected = verifier.inspect_candidate(formula, formula_sha, archive_sha)
    path = formula.parent / "manifest.json"
    manifest = json.loads(path.read_bytes())
    if mutation == "missing":
        del manifest["environments"]["analyzer"]["semgrep"]
    elif mutation == "unstable":
        manifest["environments"]["analyzer"]["semgrep"] = "latest"
    else:
        key = {"wrong-release": "id", "wrong-version": "version", "wrong-platform": "platform"}[mutation]
        manifest[key] = "different"
    path.write_text(json.dumps(manifest))
    inspected["manifest_sha256"] = sha(path.read_bytes())
    with pytest.raises((ValueError, KeyError)):
        verifier.expected_semgrep(path, inspected)


@pytest.fixture
def https_candidate(tmp_path):
    return make_candidate(tmp_path.resolve() / "https-candidate", mode="https-origin")


def https_arguments(candidate):
    formula, _, _, metadata = candidate
    return {"approved_https_url": metadata["artifact"]["url"],
            "metadata_sha256": sha((formula.parent / "homebrew.json").read_bytes())}


class MockHTTPSResponse(io.BytesIO):
    def __init__(self, content, url, *, status=200, headers=None):
        super().__init__(content)
        self.url = url
        self.status = status
        self.headers = {} if headers is None else headers

    def geturl(self):
        return self.url


def mock_https(monkeypatch, candidate, *, content=None, url=None, status=200, headers=None, error=None):
    formula, _, _, metadata = candidate
    if content is None:
        content = (formula.parent / metadata["artifact"]["name"]).read_bytes()
    requests = []

    def build(*handlers):
        assert len(handlers) == 3
        assert isinstance(handlers[0], verifier.urllib.request.ProxyHandler) and handlers[0].proxies == {}
        assert isinstance(handlers[1], verifier.NoRedirect)
        context = handlers[2]._context
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        assert context.minimum_version >= ssl.TLSVersion.TLSv1_2

        class Opener:
            def open(self, request, *, timeout):
                requests.append(request)
                assert timeout == 30
                assert request.full_url == metadata["artifact"]["url"]
                assert request.get_header("Accept-encoding") == "identity"
                assert not request.has_header("Authorization") and not request.has_header("Cookie")
                if error:
                    raise error
                return MockHTTPSResponse(content, url or request.full_url, status=status, headers=headers)

        return Opener()

    monkeypatch.setattr(verifier.urllib.request, "build_opener", build)
    return requests


def test_https_acquisition_keeps_exact_formula_and_bounded_separate_receipt(
    workspace, https_candidate, monkeypatch,
):
    requests = mock_https(monkeypatch, https_candidate)
    formula, formula_sha, archive_sha, metadata = https_candidate
    original = formula.read_bytes()
    receipt_path = workspace.fetch_candidate(formula, formula_sha, archive_sha, **https_arguments(https_candidate))
    assert len(requests) == 1 and formula.read_bytes() == original
    receipt = verifier.read_json(receipt_path)
    assert receipt["passed"] is True and receipt["quarantineVerified"] is False
    assert receipt["definition"]["artifact_url"] == metadata["artifact"]["url"]
    assert receipt["artifact"]["sha256"] == archive_sha
    acquired = workspace.acquired_candidate(receipt_path, receipt["definition"])
    assert acquired["archive"] == str(receipt_path.parent / metadata["artifact"]["name"])
    assert Path(acquired["archive"]) != formula.parent / metadata["artifact"]["name"]


@pytest.mark.parametrize("missing", ["url", "metadata-pin"])
def test_https_approval_cannot_be_inferred_from_metadata(https_candidate, missing):
    arguments = https_arguments(https_candidate)
    del arguments["approved_https_url" if missing == "url" else "metadata_sha256"]
    with pytest.raises(ValueError, match="explicit URL approval"):
        verifier.inspect_formula(*https_candidate[:3], **arguments)


@pytest.mark.parametrize("mutation", [
    "http", "credentials", "query", "fragment", "wrong-host", "wrong-path", "trailing-query",
    "backslash", "newline", "bad-port",
])
def test_https_approval_rejects_unsafe_or_nonexact_urls(https_candidate, mutation):
    arguments = https_arguments(https_candidate)
    url = arguments["approved_https_url"]
    changes = {
        "http": url.replace("https:", "http:"), "credentials": url.replace("https://", "https://name:secret@"),
        "query": url + "?token=secret", "fragment": url + "#secret",
        "wrong-host": url.replace("approved.invalid", "different.invalid"),
        "wrong-path": url.replace("/releases/", "/unapproved/"), "trailing-query": url + "?",
        "backslash": url.replace("/releases/", "\\releases/"), "newline": url + "\n",
        "bad-port": url.replace("approved.invalid", "approved.invalid:99999"),
    }
    arguments["approved_https_url"] = changes[mutation]
    with pytest.raises(ValueError) as caught:
        verifier.inspect_formula(*https_candidate[:3], **arguments)
    assert "secret" not in str(caught.value)


@pytest.mark.parametrize("mutation", [
    "redirect", "status", "truncated", "oversized", "digest", "content-length", "encoding", "tls", "timeout",
])
def test_failed_https_acquisition_is_retained_and_cannot_be_staged(
    workspace, https_candidate, monkeypatch, mutation,
):
    formula, formula_sha, archive_sha, metadata = https_candidate
    content = (formula.parent / metadata["artifact"]["name"]).read_bytes()
    options = {
        "redirect": {"url": "https://unapproved.invalid/redirect"},
        "status": {"status": 302}, "truncated": {"content": content[:-1]},
        "oversized": {"content": content + b"x"}, "digest": {"content": b"x" * len(content)},
        "content-length": {"headers": {"Content-Length": str(len(content) + 1)}},
        "encoding": {"headers": {"Content-Encoding": "gzip"}},
        "tls": {"error": ssl.SSLError("Synthetic TLS refusal")},
        "timeout": {"error": TimeoutError("Synthetic timeout")},
    }
    mock_https(monkeypatch, https_candidate, **options[mutation])
    with pytest.raises((ValueError, OSError)):
        workspace.fetch_candidate(formula, formula_sha, archive_sha, **https_arguments(https_candidate))
    receipts = list((workspace.root / "downloads").glob("https-*/acquisition.json"))
    assert len(receipts) == 1
    receipt = verifier.read_json(receipts[0])
    assert receipt["passed"] is False and "error" in receipt
    assert not (receipts[0].parent / metadata["artifact"]["name"]).exists()
    with pytest.raises(ValueError, match="unsuccessful"):
        workspace.acquired_candidate(receipts[0], receipt["definition"])
    assert not (workspace.root / "staged.json").exists()


def test_local_archive_cannot_replace_https_acquisition(workspace, https_candidate, mock_brew):
    with pytest.raises(ValueError, match="separate successful acquisition"):
        workspace.stage(*https_candidate[:3], **https_arguments(https_candidate))
    assert mock_brew == []
    assert not workspace.tap_formula.exists()


def test_https_stage_preserves_url_and_file_only_transport(
    workspace, https_candidate, mock_brew, monkeypatch,
):
    mock_https(monkeypatch, https_candidate)
    formula = https_candidate[0]
    receipt = workspace.fetch_candidate(*https_candidate[:3], **https_arguments(https_candidate))
    workspace.stage(*https_candidate[:3], **https_arguments(https_candidate), https_receipt=receipt)
    staged = workspace.staged()
    assert workspace.tap_formula.read_bytes() == formula.read_bytes()
    assert staged["mode"] == "https-origin" and staged["https_receipt_sha256"] == sha(receipt.read_bytes())
    assert mock_brew == [("trust-formula", "trust", "--formula", verifier.FORMULA),
                         ("https-cache-binding", "--cache", "--formula", verifier.FORMULA)]
    cache_record = verifier.read_json(Path(staged["stage"]) / "https-cache.json")
    assert cache_record["homebrewTransport"] == "file-only"
    assert cache_record["publicDeliveryVerified"] is False
    assert Path(cache_record["archive"]).read_bytes() == Path(staged["archive"]).read_bytes()
    assert (workspace.root / "curlrc").read_bytes() == b'proto = "=file"\nproto-redir = "=file"\n'


@pytest.mark.parametrize("mutation", ["metadata", "receipt", "download", "cache", "cache-alias", "transport"])
def test_staged_https_pin_and_cache_mutations_fail_closed(
    workspace, https_candidate, mock_brew, monkeypatch, mutation,
):
    mock_https(monkeypatch, https_candidate)
    receipt = workspace.fetch_candidate(*https_candidate[:3], **https_arguments(https_candidate))
    workspace.stage(*https_candidate[:3], **https_arguments(https_candidate), https_receipt=receipt)
    staged = workspace.staged()
    target = Path(verifier.read_json(Path(staged["stage"]) / "https-cache.json")["archive"])
    if mutation == "metadata":
        path = https_candidate[0].parent / "homebrew.json"
        path.write_bytes(path.read_bytes() + b"\n")
    elif mutation == "receipt":
        receipt.write_bytes(receipt.read_bytes() + b"\n")
    elif mutation == "download":
        Path(staged["archive"]).write_bytes(b"changed")
    elif mutation == "cache":
        target.write_bytes(b"changed")
    elif mutation == "cache-alias":
        token = sha(staged["artifact_url"].encode())
        (target.parent / f"{token}--different.tar.gz").write_bytes(b"changed")
    else:
        (workspace.root / "curlrc").write_bytes(b'proto = "=https,file"\n')
    with pytest.raises(ValueError):
        workspace.staged()


def test_https_receipt_cannot_be_replayed_for_another_candidate(
    workspace, https_candidate, monkeypatch, tmp_path,
):
    mock_https(monkeypatch, https_candidate)
    receipt = workspace.fetch_candidate(*https_candidate[:3], **https_arguments(https_candidate))
    other = make_candidate(tmp_path.resolve() / "other-https", version="0.3.4", mode="https-origin")
    definition = verifier.inspect_formula(*other[:3], **https_arguments(other))
    with pytest.raises(ValueError, match="another candidate"):
        workspace.acquired_candidate(receipt, definition)
